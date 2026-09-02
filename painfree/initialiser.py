"""The worker loop that performs what the console asked for.

:mod:`painfree.keyjobs` is the request; this is the fulfilment. It runs in the
worker process, holds the custody key, and is the only thing that turns a
button press in a browser into `INI`, `HIA`, `HPB` or a minted key.

**Why this exists at all.** The console cannot do any of it. The API process is
refused the custody secret at startup, and every one of these operations needs
a private key: `INI` and `HIA` register keys this service has to hold, `HPB`
arrives encrypted to our own `E002` half, and minting or renewing writes sealed
material. Rather than widen the boundary for a UI, the UI asks.

**The bank's keys are staged, never accepted, here.** `fetch_hpb` decrypts the
response, parses the bank's two keys and writes them as `pending` -- unusable
by anything -- and stops. What turns them into keys this service will encrypt a
payment file to is a *separate* job carrying two fingerprints a human read off
the bank's letter. There is no code path in this module that trusts a key
because it arrived.

Every exchange is logged with the step, the bank's return code and its report
text, correlated by ``job_id`` and ``connection_id``, exactly as an upload is.
"""

from __future__ import annotations

import threading
from typing import Any, Callable

from sqlalchemy import Engine

from painfree import custody, ebics3
from painfree.audit import Actor, AuditLog
from painfree.config import Settings
from painfree.catalogue import Catalogue
from painfree.connections import BankConnection, ConnectionRegistry
from painfree.errors import ConflictError
from painfree.keyjobs import JobState, KeyAction, KeyJob, KeyJobQueue
from painfree.keyring import KeyCustodian, Keyring
from painfree.keyjobs import ALLOWED_FROM
from painfree.logging import bind, get_logger
from painfree.sealing import CustodyKey
from painfree.transport import BankTransport

log = get_logger("painfree.initialiser")

#: How long an idle key worker waits before asking for work again. An operator
#: is watching this one, so it polls faster than the payment loop.
POLL_INTERVAL = 1.0

DEFAULT_COUNTRY = "CH"


class KeyWorker:
    """Claims key jobs and performs them. Built once per worker process."""

    __slots__ = ("_engine", "_queue", "_registry", "_keyring", "_custodian",
                 "_worker_id", "_timeout", "_user_agent", "_catalogue")

    def __init__(self, engine: Engine, custody_key: CustodyKey, *,
                 audit: AuditLog | None = None, worker_id: str | None = None,
                 timeout: float | None = None,
                 user_agent: str | None = None) -> None:
        audit = audit or AuditLog(engine)
        self._engine = engine
        self._queue = KeyJobQueue(engine, audit)
        self._registry = ConnectionRegistry(engine, audit)
        self._keyring = Keyring(engine)
        self._catalogue = Catalogue(engine)
        # Refuses to exist on a request-handling path, so a console that grew a
        # shortcut into this class fails at construction rather than at the
        # first decryption.
        self._custodian = KeyCustodian(engine, audit, custody_key)
        self._worker_id = worker_id or "keys"
        self._timeout = timeout
        self._user_agent = user_agent

    @property
    def worker_id(self) -> str:
        return self._worker_id

    # --- the loop ----------------------------------------------------------

    def run_once(self) -> KeyJob | None:
        """Claim one job and see it to a recorded outcome. ``None`` if idle."""
        with custody.worker_context():
            job = self._queue.claim(worker_id=self._worker_id)
            if job is None:
                return None
            with bind(connection_id=job.connection_id, job_id=job.job_id):
                return self._perform(job)

    def run_forever(self, *, stop: threading.Event | None = None,
                    poll_interval: float = POLL_INTERVAL) -> None:
        stop = stop or threading.Event()
        log.info("keyworker.started", worker_id=self._worker_id,
                 poll_interval_s=poll_interval)
        while not stop.is_set():
            try:
                performed = self.run_once()
            except Exception:
                # One malformed job must not stop every other connection's
                # lifecycle. The job itself is already settled or will be
                # reclaimed once; the ceiling in `keyjobs` stops a loop.
                log.exception("keyworker.iteration_failed",
                              worker_id=self._worker_id)
                performed = None
            if performed is None:
                stop.wait(poll_interval)
        log.info("keyworker.stopped", worker_id=self._worker_id)

    # --- one job -----------------------------------------------------------

    def _perform(self, job: KeyJob) -> KeyJob:
        """Run one job and record the outcome, whatever it is."""
        try:
            connection = self._registry.get(job.connection_id)
            allowed = ALLOWED_FROM[job.action]
            if connection.key_state not in allowed:
                # The row may be minutes old, and something else may have moved
                # the connection since. The state machine is the authority.
                raise ebics3.RequestError(
                    f"{job.action.value} is not available while the connection "
                    f"is at {connection.key_state.value}")
            result = _ACTIONS[job.action](self, job, connection)
        except ebics3.BankRefusedError as exc:
            log.warning("ebics.refused", step=job.action.value,
                        return_code=exc.return_code, return_code_name=exc.name,
                        report_text=exc.report_text)
            return self._queue.failed(
                job, reason=f"the bank refused {job.action.value}: {exc}",
                return_code=exc.return_code, report_text=exc.report_text)
        except Exception as exc:
            # Logged where it is caught, with the trace, and converted into an
            # outcome the operator reads on the screen they clicked from.
            log.exception("keyjob.failed", action=job.action.value)
            return self._queue.failed(
                job, reason=f"{type(exc).__name__}: {exc}")
        return self._queue.succeeded(job, result=result.get("result", {}),
                                     return_code=result.get("return_code"),
                                     report_text=result.get("report_text"))

    # --- the actions -------------------------------------------------------

    def _create_keys(self, job: KeyJob, connection: BankConnection) -> dict[str, Any]:
        """Mint the subscriber's three keys and seal the private halves."""
        subject = ebics3.subject_name(
            str(job.params.get("common_name") or connection.user_id),
            job.params.get("organisation") or connection.partner_id,
            job.params.get("country") or DEFAULT_COUNTRY)
        created = self._custodian.create_subscriber_keys(
            connection.connection_id, subject=subject)
        return {"result": {"fingerprints": {version: key.fingerprint_hex
                                            for version, key in created.items()}}}

    def _send_ini(self, job: KeyJob, connection: BankConnection) -> dict[str, Any]:
        return self._registration(connection, ebics3.Step.INI)

    def _send_hia(self, job: KeyJob, connection: BankConnection) -> dict[str, Any]:
        return self._registration(connection, ebics3.Step.HIA)

    def _registration(self, connection: BankConnection,
                      step: ebics3.Step) -> dict[str, Any]:
        """One unsecured registration exchange, then persist what it achieved.

        Persisted after the exchange rather than at the end of the walk: the
        failure this prevents is `INI` succeeding, `HIA` failing, and a second
        attempt re-sending `INI` with a key the bank has already accepted --
        which a bank answers with `EBICS_INVALID_USER_STATE` and a support call.
        """
        initialisation = self._custodian.resume_initialisation(
            connection.connection_id)
        if initialisation.next_step is not step:
            raise ebics3.RequestError(
                f"the connection's next outstanding step is "
                f"{getattr(initialisation.next_step, 'value', 'none')}, "
                f"not {step.value}")
        parsed = self._exchange(connection, initialisation, step)
        self._custodian.save_initialisation(connection.connection_id,
                                            initialisation)
        return {"result": {"step": step.value, "order_id": parsed.order_id},
                "return_code": parsed.header_return_code,
                "report_text": parsed.report_text}

    def _fetch_hpb(self, job: KeyJob, connection: BankConnection) -> dict[str, Any]:
        """Ask the bank for its keys and stage them. Nothing is trusted here.

        A fresh state machine rather than the persisted one, because `HPB` is
        repeatable and a connection that is already `ready` has no outstanding
        step -- asking the resumed machine for the next request would get
        ``None``. What is reused is the part that matters: the same private
        `E002` half opens the response either way.
        """
        initialisation = self._custodian.resume_initialisation(
            connection.connection_id)
        initialisation.bank_keys = None
        initialisation.bank_fingerprints = None
        parsed = self._exchange(connection, initialisation, ebics3.Step.HPB)
        fingerprints = self._custodian.stage_bank_keys(
            connection.connection_id, initialisation.bank_keys)
        if connection.key_state is ebics3.KeyState.KEYS_SENT:
            # `bank_keys_received` is not `ready`: a connection whose operator
            # has not yet checked the letter is visibly unfinished rather than
            # quietly usable. A connection that was already `ready` keeps the
            # keys it trusts until these are compared.
            self._registry.save_progress(connection.connection_id,
                                         initialisation)
        return {"result": {"step": "HPB", "staged_fingerprints": fingerprints,
                           "digest": connection.letter_digest.value,
                           "trusted": False},
                "return_code": parsed.header_return_code,
                "report_text": parsed.report_text}

    def _fetch_catalogue(self, job: KeyJob,
                         connection: BankConnection) -> dict[str, Any]:
        """Ask the bank what it publishes, and store the answer verbatim.

        An ordinary three-phase download -- the same one a statement takes --
        opened with an administrative order type instead of a BTF. It is here
        rather than in :mod:`painfree.downloader` because it is a thing an
        operator asks for and watches, not a thing a schedule does; and it is a
        key job rather than a console action because the response is encrypted
        to our own ``E002`` half, which the API process cannot open.

        Nothing fetched here is trusted for anything. It is written to
        :mod:`painfree.catalogue` and read by a page. A bank that publishes an
        upload this service is not configured for does not thereby become
        configured for it -- the comparison is shown to a person, who decides.
        """
        order_type = str(job.params.get("order_type") or "HTD").upper()
        if order_type not in ebics3.ADMIN_DOWNLOADS:
            raise ConflictError(
                f"{order_type!r} is not a catalogue this service fetches; it "
                f"knows {', '.join(sorted(ebics3.ADMIN_DOWNLOADS))}")

        authentication = self._custodian.open(connection.connection_id,
                                              ebics3.KeyVersion.X002)
        encryption = self._custodian.open(connection.connection_id,
                                          ebics3.KeyVersion.E002)
        bank = self._keyring.bank_keys(connection.connection_id)
        transaction = ebics3.DownloadTransaction(
            context=connection.context, authentication_key=authentication,
            encryption_key=encryption,
            bank_authentication_key=bank.authentication)
        transport = self._transport(connection)

        request = transaction.admin_initialisation_request(
            order_type, bank_authentication_key=bank.authentication,
            bank_encryption_key=bank.encryption)
        exchanges = 1
        parsed = self._download_exchange(transaction, request, transport,
                                         order_type, exchanges)
        while transaction.phase is ebics3.Phase.TRANSFER:
            following = transaction.next_request()
            if following is None:  # pragma: no cover - the engine's job
                break
            exchanges += 1
            parsed = self._download_exchange(transaction, following, transport,
                                             order_type, exchanges)

        if not transaction.segments:
            # A bank with nothing to say here is a bank that answered. It is
            # not an error and it is not a catalogue, so nothing is stored --
            # storing an empty one would read as *this bank offers nothing*.
            return {"result": {"order_type": order_type, "stored": False,
                               "reason": "the bank returned no order data"},
                    "return_code": parsed.header_return_code,
                    "report_text": parsed.report_text}

        document = transaction.order_data
        entry = self._catalogue.record(
            connection.connection_id, order_type, document=document,
            return_code=parsed.header_return_code,
            report_text=parsed.report_text)

        acknowledged = False
        if transaction.phase is ebics3.Phase.RECEIPT:
            exchanges += 1
            # After the row is written, for the same reason a statement
            # acknowledges after ingest: the two orderings differ by whether a
            # crash loses what the bank believes it delivered.
            parsed = self._download_exchange(
                transaction, transaction.next_request(), transport,
                order_type, exchanges)
            acknowledged = transaction.phase is ebics3.Phase.DONE

        return {"result": {"order_type": order_type, "stored": True,
                           "readable": entry.summary is not None,
                           "bytes": len(document),
                           "acknowledged": acknowledged,
                           "exchanges": exchanges},
                "return_code": parsed.header_return_code,
                "report_text": parsed.report_text}

    def _download_exchange(self, transaction, request, transport,
                           order_type: str, exchange: int):
        """One request, one response, one log line -- in that order.

        Parsed and logged before it is fed to the engine, because feeding it is
        what raises on a refusal, and the exchange an operator most needs to
        read is the one that failed.
        """
        body = ebics3.serialize_request(request)
        raw = transport.post(body)
        root = ebics3.parse_xml(raw)
        parsed = ebics3.parse_response(root)
        code = parsed.status.decisive
        log.info("ebics.exchange", order_type=order_type,
                 phase=parsed.transaction_phase or transaction.phase.value,
                 segment_number=parsed.segment_number,
                 num_segments=parsed.num_segments or transaction.num_segments,
                 transaction_id=parsed.transaction_id,
                 header_return_code=parsed.header_return_code,
                 body_return_code=parsed.body_return_code,
                 return_code_name=code.name if code else None,
                 report_text=parsed.report_text,
                 request_bytes=len(body), exchange=exchange)
        transaction.feed(root)
        return parsed

    def _transport(self, connection: BankConnection) -> BankTransport:
        if self._timeout is None:
            return BankTransport(connection.host_url,
                                 user_agent=self._user_agent)
        return BankTransport(connection.host_url, timeout=self._timeout,
                             user_agent=self._user_agent)

    def _confirm_bank_keys(self, job: KeyJob,

                           connection: BankConnection) -> dict[str, Any]:
        """Compare the staged keys against what the operator read off the letter."""
        updated = self._custodian.confirm_bank_keys(
            connection.connection_id,
            authentication=str(job.params.get("authentication") or ""),
            encryption=str(job.params.get("encryption") or ""),
            actor=Actor(job.requested_by_type, job.requested_by_id))
        return {"result": {"key_state": updated.key_state.value,
                           "fingerprints": updated.bank_fingerprints}}

    def _decline_bank_keys(self, job: KeyJob,
                           connection: BankConnection) -> dict[str, Any]:
        declined = self._custodian.decline_bank_keys(
            connection.connection_id,
            reason=str(job.params.get("reason") or "no reason given"),
            actor=Actor(job.requested_by_type, job.requested_by_id))
        after = self._registry.get(connection.connection_id)
        return {"result": {"declined": [key.fingerprint for key in declined],
                           "key_state": after.key_state.value,
                           "initialised": after.initialised}}

    def _renew_key(self, job: KeyJob, connection: BankConnection) -> dict[str, Any]:
        """Mint the next generation of one key. The bank is not told here.

        Registering the replacement is another `INI` or `HIA`, which is another
        job. The keyring only makes the new key exist without losing the one
        the bank still has on file.
        """
        subject = ebics3.subject_name(
            str(job.params.get("common_name") or connection.user_id),
            job.params.get("organisation") or connection.partner_id,
            job.params.get("country") or DEFAULT_COUNTRY)
        version = ebics3.KeyVersion.parse(str(job.params.get("version")))
        key = self._custodian.renew(connection.connection_id, version,
                                    subject=subject)
        return {"result": {"key_version": key.version.value,
                           "fingerprint": key.fingerprint_hex,
                           "registered_with_bank": False}}

    def _suspend_keys(self, job: KeyJob,
                      connection: BankConnection) -> dict[str, Any]:
        raw = job.params.get("version")
        suspended = self._custodian.suspend(
            connection.connection_id,
            version=ebics3.KeyVersion.parse(str(raw)) if raw else None,
            reason=str(job.params.get("reason") or "no reason given"))
        return {"result": {"suspended": [
            {"key_version": key.version.value, "generation": key.generation,
             "fingerprint": key.fingerprint} for key in suspended]}}

    # --- the wire ----------------------------------------------------------

    def _exchange(self, connection: BankConnection,
                  initialisation: ebics3.Initialisation,
                  step: ebics3.Step) -> ebics3.BankResponse:
        """One request, one response, one log line -- in that order.

        The response is parsed and logged *before* it is fed to the state
        machine, because feeding it is what raises on a refusal: log afterwards
        and the one exchange an operator most needs to see is the one with no
        line.
        """
        request = initialisation.next_request()
        body = ebics3.serialize_request(request)
        transport = (
            BankTransport(connection.host_url, user_agent=self._user_agent)
            if self._timeout is None else
            BankTransport(connection.host_url, timeout=self._timeout,
                          user_agent=self._user_agent))
        raw = transport.post(body)
        root = ebics3.parse_xml(raw)
        parsed = ebics3.parse_response(root)
        code = parsed.status.decisive
        log.info("ebics.exchange", order_type=step.value,
                 phase="KeyManagement",
                 header_return_code=parsed.header_return_code,
                 body_return_code=parsed.body_return_code,
                 return_code_name=code.name if code else None,
                 report_text=parsed.report_text,
                 bank_order_id=parsed.order_id, request_bytes=len(body))
        initialisation.feed(root)
        return parsed


#: Action to method. A dict rather than ``getattr`` so an action name that no
#: method implements is a ``KeyError`` at dispatch and not a silent no-op.
_ACTIONS: dict[KeyAction, Callable[..., dict[str, Any]]] = {
    KeyAction.create_keys: KeyWorker._create_keys,
    KeyAction.send_ini: KeyWorker._send_ini,
    KeyAction.send_hia: KeyWorker._send_hia,
    KeyAction.fetch_hpb: KeyWorker._fetch_hpb,
    KeyAction.fetch_catalogue: KeyWorker._fetch_catalogue,
    KeyAction.confirm_bank_keys: KeyWorker._confirm_bank_keys,
    KeyAction.decline_bank_keys: KeyWorker._decline_bank_keys,
    KeyAction.renew_key: KeyWorker._renew_key,
    KeyAction.suspend_keys: KeyWorker._suspend_keys,
}


def build_key_worker(settings: Settings, engine: Engine, **kwargs) -> KeyWorker:
    """A key worker from a resolved configuration, with the role checked first."""
    if not settings.role.uploads:
        raise ValueError(
            f"PAINFREE_ROLE is {settings.role.value}; this process performs no "
            f"key operations and holds no custody key")
    kwargs.setdefault("user_agent", settings.ebics_user_agent)
    return KeyWorker(engine, settings.custody_key(), **kwargs)


__all__ = ["DEFAULT_COUNTRY", "JobState", "KeyWorker", "POLL_INTERVAL",
           "build_key_worker"]
