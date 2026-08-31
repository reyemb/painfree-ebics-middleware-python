"""The download worker: fetch a statement, store it, and only then acknowledge.

The other direction of the upload worker. A scheduler row comes due, this
claims it, opens the connection's private keys, drives the engine's
``DownloadTransaction`` through initialisation, transfer and **receipt** over
real HTTP, and turns what came back into rows.

**It runs in the worker process, because it needs the keys.** A download is
decrypted with our own `E002` private half -- the bank encrypts the transaction
key to it -- so it belongs on the same side of the custody boundary as the
upload worker and for the same reason. The API process cannot do this and is
not asked to.

**The receipt is not a formality.** EBICS marks downloaded data as delivered
only when the client acknowledges it; a transaction left open means the bank
offers the same statement again on the next run, for ever. Skipping the receipt
does not fail, which is what makes it dangerous -- it quietly turns a scheduled
download into a duplicate machine.

**Storing happens before acknowledging, and that ordering is the design.**
The reassembled documents are normalised and written, and only then does the
receipt go out. Crash in between and the bank re-serves, which the ingestion
constraint makes a no-op; acknowledge first and crash and the statement is gone,
because the bank has been told it was delivered. One of the two failure modes is
recoverable and the other is not, so the recoverable one is chosen.

**Nothing to download is not a failure.** `EBICS_NO_DOWNLOAD_DATA_AVAILABLE`
(`090005`) is what a scheduled download finds most of the time, and the engine
classifies it as a completed transaction rather than an error. It ends the run
as ``empty``: no exception, no alert, no retry, and the schedule goes back to
its ordinary cadence.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from sqlalchemy import Engine

from painfree import custody, ebics3
from painfree.audit import AuditLog
from painfree.config import Settings
from painfree.connections import BankConnection, ConnectionRegistry
from painfree.errors import ServiceError
from painfree.keyring import KeyCustodian, Keyring
from painfree.logging import bind, get_logger
from painfree.schedule import (COMPLETE, EMPTY, FAILED, REFUSED, ClaimedSchedule,
                               DownloadSchedules)
from painfree.sealing import CustodyKey
from painfree.statements import IngestResult, StatementStore, unpack
from painfree.transport import BankTransport, TransportError
from painfree.worker import new_worker_id

log = get_logger("painfree.downloader")

#: How long an idle download worker waits before asking for work again. Longer
#: than the upload worker's: a payment waiting two seconds matters to a caller,
#: a statement waiting fifteen does not.
POLL_INTERVAL = 15.0


class DownloadFailed(ServiceError):
    """The download did not reach a terminal EBICS state."""

    status_code = 502
    code = "download_failed"


@dataclass(frozen=True, slots=True)
class DownloadResult:
    """What one download attempt is worth recording."""

    run_id: str
    schedule_id: str
    state: str
    return_code: str | None = None
    report_text: str | None = None
    acknowledged: bool = False
    segments: int = 0
    byte_count: int = 0
    documents: int = 0
    statements: int = 0
    duplicates: int = 0
    transaction_id: str | None = None
    statement_ids: tuple[str, ...] = ()


class DownloadWorker:
    """Claims due schedules and downloads them. Built once per process."""

    __slots__ = ("_engine", "_schedules", "_registry", "_keyring", "_custodian",
                 "_statements", "_worker_id", "_timeout")

    def __init__(self, engine: Engine, custody_key: CustodyKey, *,
                 audit: AuditLog | None = None, worker_id: str | None = None,
                 timeout: float | None = None) -> None:
        audit = audit or AuditLog(engine)
        self._engine = engine
        self._schedules = DownloadSchedules(engine, audit)
        self._registry = ConnectionRegistry(engine, audit)
        self._keyring = Keyring(engine)
        self._custodian = KeyCustodian(engine, audit, custody_key)
        self._statements = StatementStore(engine, audit)
        self._worker_id = worker_id or new_worker_id()
        self._timeout = timeout

    @property
    def worker_id(self) -> str:
        return self._worker_id

    @property
    def schedules(self) -> DownloadSchedules:
        """The schedule store, so a caller can register one without a second."""
        return self._schedules

    # --- the loop ----------------------------------------------------------

    def run_once(self) -> DownloadResult | None:
        """Claim one due schedule and see it to a recorded outcome."""
        with custody.worker_context():
            claimed = self._schedules.claim(worker_id=self._worker_id)
            if claimed is None:
                return None
            with bind(connection_id=claimed.connection_id, job_id=claimed.run_id):
                return self._run(claimed)

    def run_forever(self, *, stop: threading.Event | None = None,
                    poll_interval: float = POLL_INTERVAL) -> None:
        """Claim, download, repeat, until ``stop`` is set."""
        stop = stop or threading.Event()
        log.info("downloader.started", worker_id=self._worker_id,
                 poll_interval_s=poll_interval)
        while not stop.is_set():
            try:
                result = self.run_once()
            except Exception:
                log.exception("downloader.iteration_failed",
                              worker_id=self._worker_id)
                result = None
            if result is None:
                stop.wait(poll_interval)
        log.info("downloader.stopped", worker_id=self._worker_id)

    # --- one schedule ------------------------------------------------------

    def _run(self, claimed: ClaimedSchedule) -> DownloadResult:
        """Download one claimed schedule and close its run, whatever happens.

        Every branch ends in one call to ``finished``. A run left open is a
        schedule that waits for its lease to expire, which is a statement
        delayed by fifteen minutes for nothing.
        """
        error: str | None = None
        try:
            result = self._download(claimed)
        except ebics3.BankRefusedError as exc:
            # The exchange worked and the answer was no. `090005` never gets
            # here: the engine classifies it as a completed transaction and not
            # as a refusal, which is what keeps an empty download off this path.
            log.warning("ebics.refused", order_type="BTD",
                        return_code=exc.return_code, return_code_name=exc.name,
                        report_text=exc.report_text, retryable=exc.retryable)
            result = DownloadResult(claimed.run_id, claimed.schedule_id, REFUSED,
                                    return_code=exc.return_code,
                                    report_text=exc.report_text)
        except TransportError as exc:
            # Logged where it is caught, with the trace and with the one fact
            # that separates "the bank never saw it" from "we do not know".
            log.exception("ebics.transport_failed", order_type="BTD",
                          sent=exc.sent, status=exc.status)
            result = DownloadResult(claimed.run_id, claimed.schedule_id, FAILED)
            error = str(exc)
        except Exception as exc:
            log.exception("downloader.download_failed")
            result = DownloadResult(claimed.run_id, claimed.schedule_id, FAILED)
            error = f"{type(exc).__name__}: {exc}"

        self._schedules.finished(
            claimed, state=result.state, return_code=result.return_code,
            report_text=result.report_text, acknowledged=result.acknowledged,
            transaction_id=result.transaction_id, segments=result.segments,
            byte_count=result.byte_count, documents=result.documents,
            statements=result.statements, duplicates=result.duplicates,
            error=error)
        return result

    def _download(self, claimed: ClaimedSchedule) -> DownloadResult:
        """Drive one ``BTD`` from initialisation to the receipt."""
        schedule = claimed.schedule
        connection = self._registry.get(schedule.connection_id)
        if not connection.initialised:
            raise DownloadFailed(
                f"connection {connection.connection_id!r} is at "
                f"{connection.key_state.value} and cannot download")

        keys = self._open_keys(connection)
        transport = self._transport(connection)
        service = schedule.service
        transaction = ebics3.DownloadTransaction(
            context=connection.context, authentication_key=keys.authentication,
            encryption_key=keys.encryption,
            bank_authentication_key=keys.bank.authentication)

        date_range = (None if claimed.window_start is None
                      else (claimed.window_start, claimed.window_end))
        log.info("ebics.download_started", order_type="BTD",
                 schedule_id=schedule.schedule_id, service_name=service.name,
                 msg_name=service.msg_name, msg_version=service.msg_version,
                 container=service.container, window_start=claimed.window_start,
                 window_end=claimed.window_end)

        request = transaction.initialisation_request(
            service, bank_authentication_key=keys.bank.authentication,
            bank_encryption_key=keys.bank.encryption, date_range=date_range)
        exchanges = 1
        response = self._exchange(transaction, request, transport, exchanges)
        # Written as soon as the bank assigns it: a run whose transaction is
        # still open at the bank is one an operator has to be able to name.
        self._schedules.opened(claimed.run_id,
                               transaction_id=transaction.transaction_id)

        while transaction.phase is ebics3.Phase.TRANSFER:
            request = transaction.next_request()
            if request is None:  # pragma: no cover -- the state machine's job
                break
            exchanges += 1
            response = self._exchange(transaction, request, transport, exchanges)

        if not transaction.segments:
            # The ordinary case for a scheduled download: the bank had nothing
            # for this window. Not an error, not an alert, not a retry --
            # `090005` is a completed transaction.
            log.info("ebics.download_empty", order_type="BTD",
                     schedule_id=schedule.schedule_id,
                     return_code=response.header_return_code,
                     report_text=response.report_text, exchanges=exchanges,
                     reason="the bank had no data available for this window")
            return DownloadResult(
                claimed.run_id, schedule.schedule_id, EMPTY,
                return_code=response.header_return_code,
                report_text=response.report_text,
                transaction_id=transaction.transaction_id)

        order_data = transaction.order_data
        documents = unpack(order_data)
        # Stored *before* the receipt goes out. See the module docstring: one
        # of the two orderings loses a statement on a crash.
        ingested = self._ingest(claimed, documents)

        acknowledged = False
        if transaction.phase is ebics3.Phase.RECEIPT:
            exchanges += 1
            response = self._exchange(transaction, transaction.next_request(),
                                      transport, exchanges)
            acknowledged = transaction.phase is ebics3.Phase.DONE

        log.info("ebics.download_completed", order_type="BTD",
                 schedule_id=schedule.schedule_id,
                 transaction_id=transaction.transaction_id,
                 segments=len(transaction.segments), bytes=len(order_data),
                 documents=len(documents), statements=ingested.statements,
                 stored=ingested.stored, duplicates=ingested.duplicates,
                 unreadable=ingested.unreadable,
                 acknowledged=acknowledged,
                 return_code=response.header_return_code, exchanges=exchanges)
        if not acknowledged:
            # Its own line, because the data is safe and the bank still
            # believes it was never delivered -- so the next run gets it again.
            log.warning("ebics.download_unacknowledged",
                        schedule_id=schedule.schedule_id,
                        transaction_id=transaction.transaction_id,
                        phase=transaction.phase.value)
        return DownloadResult(
            claimed.run_id, schedule.schedule_id, COMPLETE,
            return_code=response.header_return_code,
            report_text=response.report_text, acknowledged=acknowledged,
            transaction_id=transaction.transaction_id,
            segments=len(transaction.segments), byte_count=len(order_data),
            documents=len(documents), statements=ingested.statements,
            duplicates=ingested.duplicates,
            statement_ids=tuple(ingested.statement_ids))

    def _ingest(self, claimed: ClaimedSchedule, documents: list[bytes]) -> IngestResult:
        return self._statements.ingest(claimed.connection_id, documents,
                                       run_id=claimed.run_id)

    def _exchange(self, transaction: ebics3.DownloadTransaction, request,
                  transport: BankTransport, exchange: int) -> ebics3.BankResponse:
        """One request, one response, one log line -- in that order.

        The response is parsed and logged *before* it is fed to the engine,
        because feeding it is what raises on a refusal: log afterwards and the
        one exchange an operator most needs to see is the one with no line.
        """
        body = ebics3.serialize_request(request)
        raw = transport.post(body)
        root = ebics3.parse_xml(raw)
        parsed = ebics3.parse_response(root)

        code = parsed.status.decisive
        log.info(
            "ebics.exchange", order_type="BTD",
            phase=parsed.transaction_phase or transaction.phase.value,
            segment_number=parsed.segment_number,
            num_segments=parsed.num_segments or transaction.num_segments,
            transaction_id=parsed.transaction_id,
            header_return_code=parsed.header_return_code,
            body_return_code=parsed.body_return_code,
            return_code_name=code.name if code else None,
            report_text=parsed.report_text,
            request_bytes=len(body), exchange=exchange,
        )
        transaction.feed(root)
        return parsed

    # --- the parts that need the custody key -------------------------------

    def _open_keys(self, connection: BankConnection) -> "_Keys":
        """The keys one download needs: ours to sign and to decrypt with.

        No signature key. A download signs nothing -- there is no order data
        going out to put an electronic signature on -- so the `A006` half stays
        sealed, which is the one that authorises money movement.
        """
        connection_id = connection.connection_id
        return _Keys(
            authentication=self._custodian.open(connection_id,
                                                ebics3.KeyVersion.X002),
            encryption=self._custodian.open(connection_id,
                                            ebics3.KeyVersion.E002),
            bank=self._keyring.bank_keys(connection_id),
        )

    def _transport(self, connection: BankConnection) -> BankTransport:
        if self._timeout is None:
            return BankTransport(connection.host_url)
        return BankTransport(connection.host_url, timeout=self._timeout)


@dataclass(frozen=True, slots=True)
class _Keys:
    """What one download holds open: two of ours, two of the bank's."""

    authentication: ebics3.EbicsKey
    encryption: ebics3.EbicsKey
    bank: ebics3.BankKeys


def build_downloader(settings: Settings, engine: Engine, **kwargs) -> DownloadWorker:
    """A download worker from a resolved configuration, role checked first."""
    if not settings.role.downloads:
        raise ValueError(
            f"PAINFREE_ROLE is {settings.role.value}; this process does not "
            f"download and holds no custody key")
    return DownloadWorker(engine, settings.custody_key(), **kwargs)


__all__ = ["POLL_INTERVAL", "DownloadFailed", "DownloadResult", "DownloadWorker",
           "build_downloader"]
