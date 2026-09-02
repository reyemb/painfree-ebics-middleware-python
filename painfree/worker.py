"""The upload worker: the process that holds the keys and talks to banks.

The API accepts a payment, validates it, builds the ``pain.001`` and stops;
this claims that order, opens the connection's private keys, drives the
engine's ``UploadTransaction`` through initialisation, transfer and receipt
over real HTTP, and records what the bank said.

**It is a separate process, and that is the point.** The three in-process
mechanisms state honestly what they cannot do: stop a request handler that
deliberately reads ``os.environ`` and rebuilds the custody key. The answer is
not a fourth check in the same process -- it is that the API process does not
have the secret. ``PAINFREE_ROLE=api`` refuses to start if it does,
``PAINFREE_ROLE=worker`` refuses to start if it does not, and production
refuses ``combined`` outright (:mod:`painfree.config`). What is left in the API
process is AES-256-GCM ciphertext under a key it has no input to derive.

**Nothing here can run inside a request.** :func:`painfree.custody.worker_context`
is entered around every claim, and it raises if there is a request context above
it. That is belt and braces given the process split, and it stays because it is
what makes the boundary visible in review rather than in a deployment manifest.

**One order at a time, claimed by the database.** Two workers is the ordinary
deployment, and a double claim is a double payment, so the claim is an atomic
conditional ``UPDATE`` in :mod:`painfree.queue` rather than a read followed by a
write. This module never decides who owns an order; it asks and is told.

**Retrying is not recovering.** Recovery inside one transaction --
``EBICS_TX_RECOVERY_SYNC``, a rewound segment cursor -- belongs to the engine and
happens without this module knowing. A retry is the other thing: a fresh EBICS
transaction after a failed attempt, carrying the **same** ``MsgId`` and the same
bytes, because the document was built once at accept time and is stored. That is
what makes a retry safe: the bank deduplicates on ``MsgId``, and this service
has no path that builds a second message for one order.

Every exchange is logged with the order type, the transaction phase, the segment
number and the bank's return code and report text, correlated by ``order_id``.
The return code is the first field an operator reads when a bank refuses
something, and it is logged for the exchanges that succeed too -- otherwise the
successful case is the one with no evidence.
"""

from __future__ import annotations

import os
import platform
import threading
import uuid
from dataclasses import dataclass

from sqlalchemy import Engine

from painfree import custody, ebics3
from painfree.attempts import Attempt, service_for_attempt
from painfree.audit import AuditLog
from painfree.config import Settings
from painfree.connections import BankConnection, ConnectionRegistry
from painfree.errors import ServiceError
from painfree.keyring import KeyCustodian, Keyring
from painfree.logging import bind, get_logger
from painfree.orders import OrderState, PaymentOrder
from painfree.queue import ClaimedOrder, OrderQueue
from painfree.sealing import CustodyKey
from painfree.transport import BankTransport, TransportError

log = get_logger("painfree.worker")

#: How long an idle worker waits before asking for work again. Short enough
#: that a payment submitted now is on its way in seconds, long enough that an
#: idle deployment is not a query per millisecond.
POLL_INTERVAL = 2.0

#: The BTF service a Swiss `pain.001` upload is announced under, for an order
#: that has no attempt row -- one accepted before `0015_payment_schemes`
#: existed. ``MCT`` is the Swiss Payment Standards multi-currency credit
#: transfer and the scope is ``CH``, which is what every such order was in fact
#: uploaded under.
#:
#: **A live order does not come through here.** The BTF is stored on the
#: attempt beside the document it announces, and the worker reads it off that
#: row; per-bank configuration is :class:`painfree.schemes.SchemeProfiles` on
#: the connection, whose own defaults are these two values.
DEFAULT_SERVICE_NAME = "MCT"
DEFAULT_SCOPE = "CH"

#: How long shutdown waits for the download thread to finish what it is doing.
#: Long enough for a receipt exchange with a slow bank, short enough that a
#: container stop does not become a container kill.
SHUTDOWN_GRACE = 30.0


class UploadFailed(ServiceError):
    """The upload did not reach a terminal EBICS state and is worth retrying."""

    status_code = 502
    code = "upload_failed"


@dataclass(frozen=True, slots=True)
class UploadResult:
    """What one completed upload attempt is worth recording."""

    order_id: str
    state: OrderState
    bank_order_id: str | None = None
    return_code: str | None = None
    report_text: str | None = None
    exchanges: int = 0
    segments: int = 0


def service_for(message_type: str, *, name: str = DEFAULT_SERVICE_NAME,
                scope: str | None = DEFAULT_SCOPE) -> ebics3.Service:
    """The BTF for one ISO 20022 message type, e.g. ``pain.001.001.09``.

    ``MsgName`` and its version are read off the message type rather than
    configured beside it: they are two halves of one fact, and a service whose
    ``MsgName`` disagrees with the document it carries is refused by the bank
    with a code that does not say so.
    """
    parts = message_type.split(".")
    if len(parts) < 4:
        raise UploadFailed(
            f"{message_type!r} is not an ISO 20022 message type; a BTF cannot "
            f"be derived from it")
    return ebics3.Service(name=name, scope=scope,
                          msg_name=".".join(parts[:2]), msg_version=parts[3])


def new_worker_id() -> str:
    """Host, pid and a nonce. All three, because all three are asked for.

    The host and pid are what an operator greps for when one worker is
    misbehaving; the nonce is what keeps two workers apart after a restart
    reused a pid.
    """
    return f"{platform.node()[:24]}:{os.getpid()}:{uuid.uuid4().hex[:8]}"[:64]


class UploadWorker:
    """Claims queued orders and uploads them. Built once per process.

    Construction opens no keys but does build a :class:`KeyCustodian`, which
    refuses to exist on a request-handling path -- so a worker assembled inside
    a handler fails at construction rather than at the first signature.
    """

    __slots__ = ("_engine", "_queue", "_registry", "_keyring", "_custodian",
                 "_worker_id", "_timeout", "_user_agent")

    def __init__(self, engine: Engine, custody_key: CustodyKey, *,
                 audit: AuditLog | None = None, worker_id: str | None = None,
                 timeout: float | None = None,
                 user_agent: str | None = None) -> None:
        audit = audit or AuditLog(engine)
        self._engine = engine
        self._queue = OrderQueue(engine, audit)
        self._registry = ConnectionRegistry(engine, audit)
        self._keyring = Keyring(engine)
        self._custodian = KeyCustodian(engine, audit, custody_key)
        self._worker_id = worker_id or new_worker_id()
        self._timeout = timeout
        self._user_agent = user_agent

    @property
    def worker_id(self) -> str:
        return self._worker_id

    @property
    def custody_key_id(self) -> str:
        """Which custody key this worker holds. A hash; safe to log."""
        return self._custodian.key_id

    # --- the loop ----------------------------------------------------------

    def run_once(self) -> UploadResult | None:
        """Claim one order and see it to a recorded outcome. ``None`` if idle."""
        with custody.worker_context():
            claimed = self._queue.claim(worker_id=self._worker_id)
            if claimed is None:
                return None
            with bind(order_id=claimed.order_id,
                      connection_id=claimed.connection_id,
                      job_id=self._worker_id):
                return self._deliver(claimed)

    def run_forever(self, *, stop: threading.Event | None = None,
                    poll_interval: float = POLL_INTERVAL) -> None:
        """Claim, upload, repeat, until ``stop`` is set.

        The loop never dies of one order. An unexpected exception is logged
        with its trace and the loop continues, because a worker that exits on
        the first surprise stops every *other* payment as well; the order that
        caused it is already back in the queue or in a terminal state, and
        :mod:`painfree.queue` is what stops it being retried for ever.
        """
        stop = stop or threading.Event()
        log.info("worker.started", worker_id=self._worker_id,
                 custody_key_id=self.custody_key_id,
                 poll_interval_s=poll_interval)
        while not stop.is_set():
            try:
                result = self.run_once()
            except Exception:
                log.exception("worker.iteration_failed",
                              worker_id=self._worker_id)
                result = None
            if result is None:
                stop.wait(poll_interval)
        log.info("worker.stopped", worker_id=self._worker_id)

    # --- one order ---------------------------------------------------------

    def _deliver(self, claimed: ClaimedOrder) -> UploadResult:
        """Upload one claimed order and record the outcome, whatever it is.

        Every branch ends in a queue write. An order that is claimed and never
        settled is an order that waits for its lease to expire, which is a
        payment delayed by fifteen minutes for no reason.
        """
        try:
            result = self._upload(claimed)
        except ebics3.BankRefusedError as exc:
            # The exchange worked and the answer was no. Whether that is final
            # is the engine's classification, not a guess made here.
            log.warning("ebics.refused", return_code=exc.return_code,
                        return_code_name=exc.name, report_text=exc.report_text,
                        retryable=exc.retryable, attempt=claimed.attempts)
            if exc.retryable:
                state = self._queue.retry_later(
                    claimed.order_id, attempts=claimed.attempts,
                    reason=f"bank returned {exc.return_code}",
                    return_code=exc.return_code, report_text=exc.report_text)
            elif self._fell_back(claimed, exc):
                # The bank said instant could not be used, said it definitively,
                # and said it before it had taken anything. The order is back on
                # the queue carrying the *reserve* message that was built and
                # validated at accept time. This is the only call site of
                # `fall_back` in the service.
                state = OrderState.ACCEPTED
            else:
                state = self._queue.refused(
                    claimed.order_id, return_code=exc.return_code,
                    report_text=exc.report_text, name=exc.name,
                    request=getattr(exc, "request", None))
            return UploadResult(claimed.order_id, state,
                                return_code=exc.return_code,
                                report_text=exc.report_text)
        except TransportError as exc:
            # Logged where it is caught, with the trace and with the one fact
            # that distinguishes "the bank never saw it" from "we do not know".
            log.exception("ebics.transport_failed", sent=exc.sent,
                          status=exc.status, attempt=claimed.attempts)
            state = self._queue.retry_later(
                claimed.order_id, attempts=claimed.attempts, reason=str(exc))
            return UploadResult(claimed.order_id, state)
        except Exception as exc:
            # A protocol error, a missing key, a connection that vanished. The
            # order goes back rather than being left claimed; the trace is what
            # the operator gets.
            log.exception("worker.upload_failed", attempt=claimed.attempts)
            state = self._queue.retry_later(
                claimed.order_id, attempts=claimed.attempts,
                reason=f"{type(exc).__name__}: {exc}")
            return UploadResult(claimed.order_id, state)

        state = self._queue.submitted(
            claimed.order_id, bank_order_id=result.bank_order_id,
            return_code=result.return_code, report_text=result.report_text)
        log.info("ebics.upload_completed", bank_order_id=result.bank_order_id,
                 exchanges=result.exchanges, segments=result.segments,
                 return_code=result.return_code)
        return UploadResult(claimed.order_id, state,
                            bank_order_id=result.bank_order_id,
                            return_code=result.return_code,
                            report_text=result.report_text,
                            exchanges=result.exchanges,
                            segments=result.segments)

    def _announcement(self, order: PaymentOrder, attempt: Attempt | None,
                      connection: BankConnection
                      ) -> tuple[ebics3.Service, bytes, str]:
        """The BTF, the bytes and the ``MsgId`` -- from one row, or from none.

        The point of returning all three together is that they cannot be
        computed apart. A BTF claiming instant over a document that does not
        claim it is refused by the bank with a code that will not explain
        itself, so the announcement is read off the same row as the message it
        announces.

        An order with no attempt row was accepted before that row existed. It
        is a normal credit transfer by construction -- ``payment_order.scheme``
        defaults to ``normal`` and nothing else could have written it -- so its
        BTF comes from the connection's normal profile, which resolves to the
        module defaults for a connection nobody has configured. That is the
        same triplet it would have been uploaded under before schemes existed.
        """
        if attempt is not None:
            return (service_for_attempt(attempt, order.message_type),
                    attempt.document, attempt.msg_id)
        profile = connection.schemes.profile(order.scheme)
        service = service_for(order.message_type, name=profile.service_name,
                              scope=profile.scope)
        return service, order.document, order.msg_id

    def _fell_back(self, claimed: ClaimedOrder,
                   exc: ebics3.BankRefusedError) -> bool:
        """Ask the queue to promote the reserve attempt. Never decides itself.

        Reached from exactly one place: a **parsed, definitive** refusal from
        the bank. Every other way an attempt can end -- a timeout, a dropped
        connection, a response that would not parse, an unexpected exception --
        goes to :meth:`OrderQueue.retry_later`, which cannot promote anything.
        An outcome this service does not understand is not a refusal, and
        treating it as one is how a payment goes out twice.

        The conditions are the queue's, checked against the database in the
        statement that acts on them, so this method contributes nothing but the
        connection's own configuration.
        """
        profiles = self._registry.get(claimed.connection_id).schemes
        return self._queue.fall_back(
            claimed, profiles=profiles, return_code=exc.return_code,
            report_text=exc.report_text, name=exc.name) is not None

    def _upload(self, claimed: ClaimedOrder) -> UploadResult:
        """Drive one ``BTU`` from initialisation to the last segment."""
        order = claimed.order
        connection = self._registry.get(order.connection_id)
        if not connection.initialised:
            # A connection that lost its initialisation between accept and
            # upload. Not retryable in any useful sense, but the queue's
            # ceiling handles it and refusing here would need a fourth state.
            raise UploadFailed(
                f"connection {connection.connection_id!r} is at "
                f"{connection.key_state.value} and cannot upload")

        keys = self._open_keys(connection)
        transport = self._transport(connection)
        attempt = self._queue.attempts.live(order.order_id)
        service, document, msg_id = self._announcement(order, attempt,
                                                       connection)

        # The pipeline runs over the *stored* document. It is the message that
        # was validated at accept time and it carries the `MsgId` a retry has
        # to reuse; rebuilding it here from a newer builder would be a
        # different message under the same order id.
        secured = ebics3.secure_order_data(
            document, signature_key=keys.signature,
            bank_encryption_key=keys.bank.encryption,
            partner_id=connection.partner_id, user_id=connection.user_id)
        transaction = ebics3.UploadTransaction.prepare(
            document, secured, connection.context,
            authentication_key=keys.authentication)
        # Responses are verified against the bank's X002 key. The keyring only
        # holds one if `HPB` delivered it *and* it matched the bank's letter.
        transaction.bank_authentication_key = keys.bank.authentication

        log.info("ebics.upload_started", order_type="BTU",
                 msg_id=msg_id, service_name=service.name,
                 service_option=service.option, scope=service.scope,
                 msg_name=service.msg_name, msg_version=service.msg_version,
                 scheme=order.scheme.value,
                 requested_scheme=order.requested_scheme.value,
                 payment_type_information=(attempt.payment_type
                                           if attempt else None),
                 segments=transaction.num_segments,
                 bytes=len(document), attempt=claimed.attempts,
                 reopens_transaction=claimed.reopens)

        request = transaction.initialisation_request(
            service, bank_authentication_key=keys.bank.authentication,
            bank_encryption_key=keys.bank.encryption,
            file_name=f"{msg_id}.xml")
        exchanges = self._exchange(transaction, request, transport, order)

        # Persisted before a single segment goes out: the `TransactionID` is
        # the only handle on an open transaction.
        self._queue.opened(order.order_id,
                           transaction_id=transaction.transaction_id,
                           bank_order_id=transaction.order_id)

        while (request := transaction.next_request()) is not None:
            exchanges = self._exchange(transaction, request, transport, order,
                                       exchanges)

        if transaction.phase is not ebics3.Phase.DONE:
            raise UploadFailed(
                f"the upload stopped in {transaction.phase.value} after "
                f"{exchanges} exchanges")
        return UploadResult(order.order_id, OrderState.SUBMITTED,
                            bank_order_id=transaction.order_id,
                            return_code=ebics3.EBICS_OK,
                            report_text=None, exchanges=exchanges,
                            segments=transaction.num_segments)

    def _exchange(self, transaction: ebics3.UploadTransaction,
                  request, transport: BankTransport, order: PaymentOrder,
                  exchanges: int = 0) -> int:
        """One request, one response, one log line -- in that order.

        The response is parsed and logged *before* it is fed to the engine,
        because feeding it is what raises on a refusal: log afterwards and the
        one exchange an operator most needs to see is the one with no line.
        """
        body = ebics3.serialize_request(request)
        raw = transport.post(body)
        root = ebics3.parse_xml(raw)
        parsed = ebics3.parse_response(root)
        exchanges += 1

        status = parsed.status
        code = status.decisive
        log.info(
            "ebics.exchange", order_type="BTU", msg_id=order.msg_id,
            phase=parsed.transaction_phase or transaction.phase.value,
            segment_number=parsed.segment_number,
            num_segments=transaction.num_segments,
            transaction_id=parsed.transaction_id,
            bank_order_id=parsed.order_id,
            header_return_code=parsed.header_return_code,
            body_return_code=parsed.body_return_code,
            return_code_name=code.name if code else None,
            report_text=parsed.report_text,
            request_bytes=len(body), exchange=exchanges,
        )
        try:
            transaction.feed(root)
        except ebics3.BankRefusedError as refusal:
            # The one place the refused document is still in hand. It is
            # attached rather than stored here because this method knows
            # nothing about orders, and the handler that records the refusal
            # already has the row.
            refusal.request = body
            raise
        return exchanges

    # --- the parts that need the custody key -------------------------------

    def _open_keys(self, connection: BankConnection) -> "_Keys":
        """The three keys one upload needs. The only decryption in this module."""
        connection_id = connection.connection_id
        signature_version = self._keyring.signature_version(connection_id)
        return _Keys(
            signature=self._custodian.open(connection_id, signature_version),
            authentication=self._custodian.open(connection_id,
                                                ebics3.KeyVersion.X002),
            bank=self._keyring.bank_keys(connection_id),
        )

    def _transport(self, connection: BankConnection) -> BankTransport:
        if self._timeout is None:
            return BankTransport(connection.host_url,
                                 user_agent=self._user_agent)
        return BankTransport(connection.host_url, timeout=self._timeout,
                             user_agent=self._user_agent)


@dataclass(frozen=True, slots=True)
class _Keys:
    """What one upload holds open: two of ours, two of the bank's."""

    signature: ebics3.EbicsKey
    authentication: ebics3.EbicsKey
    bank: ebics3.BankKeys


def build_worker(settings: Settings, engine: Engine, **kwargs) -> UploadWorker:
    """A worker from a resolved configuration, with the role checked first.

    The check is here rather than only in :class:`~painfree.config.Settings` so
    that a caller assembling a worker in code -- a test, a future scheduler --
    hits the same refusal as one starting the process from an environment.
    """
    if not settings.role.uploads:
        raise ValueError(
            f"PAINFREE_ROLE is {settings.role.value}; this process does not "
            f"upload orders and holds no custody key")
    kwargs.setdefault("user_agent", settings.ebics_user_agent)
    return UploadWorker(engine, settings.custody_key(), **kwargs)


def run_worker(settings: Settings, *, stop: threading.Event | None = None) -> int:
    """``python -m painfree worker``: migrate if asked, then claim until stopped.

    Three kinds of loop in one process. Uploads and downloads need the same private keys
    and the same custody boundary, so splitting them across two deployments
    would double the number of places the secret has to be, for no gain --
    The custody boundary is about keeping the API process out, not about how
    many kinds of work the worker does. They run in separate threads because
    the two cadences are different by an order of magnitude: a payment waits
    seconds, a statement download runs for minutes and must not hold a payment
    up while it does. The webhook dispatcher joins them for the same reason it
    needs the same custody key: a signature is made with a secret sealed under
    it (:mod:`painfree.dispatcher`).
    """
    from painfree import wrapping
    from painfree.db import build_engine, migrate
    from painfree.dispatcher import DISPATCH_THREADS, WebhookDispatcher
    from painfree.downloader import DownloadWorker
    from painfree.initialiser import KeyWorker

    log.info("worker.starting", version=settings.version,
             git_sha=settings.git_sha, config=settings.redacted())
    engine = build_engine(settings)
    stop = stop or threading.Event()
    threads: list[threading.Thread] = []
    try:
        if settings.migrate_on_startup:
            migrate(engine)
        worker = build_worker(settings, engine)
        downloader = DownloadWorker(engine, settings.custody_key(),
                                    worker_id=worker.worker_id)
        AuditLog(engine).record(
            "worker.started",
            detail={"worker_id": worker.worker_id,
                    "custody_key_id": worker.custody_key_id,
                    "version": settings.version,
                    "environment": settings.environment.value,
                    "dialect": settings.dialect},
        )
        # Published before any dispatch thread starts, and before the API can
        # need it: it is the public half of the keypair a webhook signing
        # secret is sealed to, and the API process -- which holds no custody
        # key -- cannot derive it for itself. Idempotent, so every worker start
        # republishes the same bytes.
        wrapping.publish(engine, settings.custody_key())
        dispatcher = WebhookDispatcher(engine, settings.custody_key(),
                                       worker_id=worker.worker_id)
        # The fourth loop, and the one an operator is watching in real time:
        # every key operation the console offers is a row this thread claims.
        # It is here rather than in its own process for the same reason the
        # downloader is -- it needs the same custody key, and a second
        # deployment holding the secret would be a second place to lose it.
        keys = KeyWorker(engine, settings.custody_key(),
                         worker_id=worker.worker_id)
        threads.append(threading.Thread(target=downloader.run_forever,
                                        kwargs={"stop": stop},
                                        name="painfree-downloader", daemon=True))
        threads.append(threading.Thread(target=keys.run_forever,
                                        kwargs={"stop": stop},
                                        name="painfree-keys", daemon=True))
        # Several dispatch threads, because one consumer taking thirty seconds
        # must not be the reason another consumer waits. They claim from one
        # table and the claim is atomic, so more threads is more parallelism
        # across *subscriptions* and never two attempts at one event.
        threads.extend(
            threading.Thread(target=dispatcher.run_forever,
                             kwargs={"stop": stop},
                             name=f"painfree-webhooks-{number}", daemon=True)
            for number in range(DISPATCH_THREADS))
        for thread in threads:
            thread.start()
        worker.run_forever(stop=stop)
    except Exception:
        log.exception("worker.start_failed")
        raise
    finally:
        stop.set()
        for thread in threads:
            # Joined rather than abandoned: a download thread killed mid-receipt
            # leaves a transaction open at the bank, which is the one thing the
            # receipt phase exists to close, and a dispatch thread killed
            # mid-POST leaves a claim to expire before the event moves again.
            thread.join(timeout=SHUTDOWN_GRACE)
        engine.dispose()
    return 0


__all__ = ["DEFAULT_SCOPE", "DEFAULT_SERVICE_NAME", "POLL_INTERVAL",
           "SHUTDOWN_GRACE",
           "UploadFailed", "UploadResult", "UploadWorker", "build_worker",
           "new_worker_id", "run_worker", "service_for"]
