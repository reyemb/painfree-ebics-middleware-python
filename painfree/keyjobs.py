"""Key-lifecycle work the console asks for and the worker performs.

The operator console runs inside the API process. That process cannot open a
private key -- it is refused the custody secret at startup -- and every step of
an EBICS key lifecycle needs one: `INI` and `HIA` register keys this service
has to hold, `HPB` arrives encrypted to our own `E002` half, and minting,
renewing or suspending a key writes sealed material.

So the console does not perform key operations. It **requests** them, and this
module is the request. A browser click appends a row; a worker claims it, does
the work with the custody key it alone holds, and writes back what happened.
There is no path from a session cookie to a decryption, and the absence is
structural rather than checked.

Two classes, split exactly like :mod:`painfree.orders` and
:mod:`painfree.queue`:

:class:`KeyJobStore`
    The request path's view. Enqueue, read one, list a connection's history.
    It writes nothing but ``key_job`` rows and needs no key at all.

:class:`KeyJobQueue`
    The worker's view. The atomic claim, and the two ways a job ends.

**A job is not retried on its own.** A payment is retried because nobody is
watching; a key operation was asked for by a named human who is looking at the
screen. A failure is therefore reported, not re-attempted -- the operator reads
the bank's return code and decides. The one exception is a worker that died
holding a claim: the lease expires, the job is claimed once more, and a second
death fails it rather than looping.
"""

from __future__ import annotations

import datetime as _dt
import enum
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Engine, and_, or_, select

from painfree import ebics3
from painfree.audit import FAILURE, Actor, AuditLog, SYSTEM_ACTOR
from painfree.errors import ConflictError, NotFoundError
from painfree.logging import bind, get_logger
from painfree.schema import key_job

log = get_logger("painfree.keyjobs")

JOB_ID_PREFIX = "kjb_"

#: How long a claim is good for before another worker may take the job over.
#: Shorter than a payment's, because a key exchange is one HTTP round trip and
#: not a multi-segment upload.
CLAIM_LEASE = _dt.timedelta(minutes=5)

#: A job is claimed at most twice: once normally, once after a worker died
#: holding it. Beyond that it is failed rather than retried -- see the module
#: docstring.
MAX_ATTEMPTS = 2

MAX_ERROR_LENGTH = 512


class KeyAction(str, enum.Enum):
    """What the console can ask the worker to do to a connection's keys."""

    create_keys = "create_keys"
    """Mint the subscriber's A006, X002 and E002 keys and seal the private halves."""

    send_ini = "send_ini"
    """Register the signature key with the bank. Unsecured, and irreversible."""

    send_hia = "send_hia"
    """Register the authentication and encryption keys. Likewise."""

    fetch_hpb = "fetch_hpb"
    """Ask the bank for its keys. They are **staged**, not trusted -- see below."""

    fetch_catalogue = "fetch_catalogue"
    """Ask the bank what it publishes: ``HAA``, ``HTD`` or ``HPD``.

    Named in ``params["order_type"]``. It is a key job for the same reason
    ``fetch_hpb`` is -- the answer arrives encrypted to our own ``E002`` half,
    which only the worker can open -- and not because it is dangerous. Nothing
    it fetches is secret, nothing it writes is trusted for anything, and it can
    be asked for as often as somebody likes.
    """

    confirm_bank_keys = "confirm_bank_keys"

    """Compare the staged keys against the fingerprints on the bank's letter.

    The whole trust decision: the H005 key-management response carries no
    signature, so this comparison is the only control there is. The operator
    supplies both values; nothing is defaulted.
    """

    decline_bank_keys = "decline_bank_keys"
    """Discard staged bank keys the operator would not vouch for.

    A first-class outcome rather than "close the tab". Declining leaves the
    connection at ``bank_keys_received`` -- visibly unfinished, and unable to
    submit anything -- and writes an audit row saying who refused what.
    """

    renew_key = "renew_key"
    """Mint the next generation of one key. The old one is superseded, not lost."""

    suspend_keys = "suspend_keys"
    """Take a key -- or the whole subscriber -- out of service, with a reason."""


class JobState(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"

    @property
    def terminal(self) -> bool:
        return self in (JobState.DONE, JobState.FAILED)


#: Which key states each action may be asked for. Checked when the job is
#: enqueued so the console refuses immediately, and again by the worker when it
#: claims -- the row may be minutes old by then, and the state machine is the
#: authority either way.
ALLOWED_FROM: dict[KeyAction, tuple[ebics3.KeyState, ...]] = {
    KeyAction.create_keys: (ebics3.KeyState.CREATED,),
    # INI before HIA, although the protocol allows either order. The engine's
    # state machine hands out the request for whichever step is outstanding, so
    # a console that offered both at once would post an `INI` document under a
    # button labelled `HIA`. One order, and `hia_sent` without `ini_sent` is
    # simply a state this console cannot reach.
    KeyAction.send_ini: (ebics3.KeyState.CREATED,),
    KeyAction.send_hia: (ebics3.KeyState.INI_SENT,),
    # `HPB` is repeatable by design -- the letter was lost, or the bank rolled
    # its keys -- so it is offered from every state that has both registrations
    # behind it, `ready` included.
    KeyAction.fetch_hpb: (ebics3.KeyState.KEYS_SENT,
                          ebics3.KeyState.BANK_KEYS_RECEIVED,
                          ebics3.KeyState.READY),
    # A catalogue can be asked for from the moment the bank will answer a
    # signed request at all, which is once both registrations are behind us.
    # It is offered from `ready` too, and repeatedly: a bank changing what it
    # accepts is exactly the event this exists to notice.
    KeyAction.fetch_catalogue: (ebics3.KeyState.KEYS_SENT,
                                ebics3.KeyState.BANK_KEYS_RECEIVED,
                                ebics3.KeyState.READY),
    KeyAction.confirm_bank_keys: (ebics3.KeyState.BANK_KEYS_RECEIVED,

                                  ebics3.KeyState.READY),
    KeyAction.decline_bank_keys: (ebics3.KeyState.BANK_KEYS_RECEIVED,
                                  ebics3.KeyState.READY),
    KeyAction.renew_key: (ebics3.KeyState.KEYS_SENT,
                          ebics3.KeyState.BANK_KEYS_RECEIVED,
                          ebics3.KeyState.READY),
    KeyAction.suspend_keys: tuple(ebics3.KeyState),
}


@dataclass(frozen=True, slots=True)
class KeyJob:
    """One requested operation, and what became of it."""

    job_id: str
    connection_id: str
    action: KeyAction
    params: dict[str, Any]
    state: JobState
    requested_by_type: str
    requested_by_id: str
    worker_id: str | None
    attempts: int
    result: dict[str, Any] | None
    return_code: str | None
    report_text: str | None
    last_error: str | None
    created_at: _dt.datetime
    updated_at: _dt.datetime
    finished_at: _dt.datetime | None

    @property
    def pending(self) -> bool:
        return not self.state.terminal

    def as_response(self) -> dict[str, Any]:
        """What a screen shows. Never a parameter that is not the operator's own."""
        return {"job_id": self.job_id, "connection_id": self.connection_id,
                "action": self.action.value, "state": self.state.value,
                "requested_by": self.requested_by_id,
                "result": self.result, "return_code": self.return_code,
                "report_text": self.report_text, "last_error": self.last_error,
                "created_at": self.created_at.isoformat(),
                "finished_at": (self.finished_at.isoformat()
                                if self.finished_at else None)}


class KeyJobStore:
    """The console's view: ask for work, then read what happened."""

    __slots__ = ("_engine", "_audit")

    def __init__(self, engine: Engine, audit: AuditLog | None = None) -> None:
        self._engine = engine
        self._audit = audit or AuditLog(engine)

    def request(self, connection_id: str, action: KeyAction | str, *,
                key_state: ebics3.KeyState, params: dict[str, Any] | None = None,
                actor: Actor = SYSTEM_ACTOR) -> KeyJob:
        """Append one request, or refuse it. No key is touched on this path."""
        action = KeyAction(action)
        allowed = ALLOWED_FROM[action]
        if key_state not in allowed:
            raise ConflictError(
                f"{action.value} cannot be asked for while connection "
                f"{connection_id!r} is at {key_state.value}",
                detail={"key_state": key_state.value,
                        "allowed_from": [state.value for state in allowed]})
        outstanding = self.outstanding(connection_id)
        if outstanding is not None:
            # Two key exchanges in flight for one subscriber is how a bank ends
            # up with two INI registrations and an EBICS_INVALID_USER_STATE.
            raise ConflictError(
                f"connection {connection_id!r} already has a {outstanding.action.value} "
                f"job in flight; wait for it to finish",
                detail={"job_id": outstanding.job_id,
                        "action": outstanding.action.value})

        job_id = f"{JOB_ID_PREFIX}{uuid.uuid4().hex}"
        now = _dt.datetime.now(_dt.timezone.utc)
        with self._engine.begin() as connection:
            connection.execute(key_job.insert().values(
                job_id=job_id, connection_id=connection_id,
                action=action.value, params=params or {},
                state=JobState.QUEUED.value,
                requested_by_type=actor.type, requested_by_id=actor.id,
                worker_id=None, claimed_at=None, attempts=0,
                result=None, return_code=None, report_text=None,
                last_error=None, created_at=now, updated_at=now,
                finished_at=None))
        with bind(connection_id=connection_id, job_id=job_id):
            self._audit.record(
                "key.job_requested", actor=actor, connection_id=connection_id,
                job_id=job_id,
                detail={"action": action.value,
                        "key_state": key_state.value,
                        # The operator's own input, and it is public material:
                        # a fingerprint read off a letter, a suspension reason.
                        "params": params or {}})
            log.info("keyjob.requested", action=action.value,
                     key_state=key_state.value, requested_by=actor.id)
        return self.get(job_id)

    # --- reading -----------------------------------------------------------

    def get(self, job_id: str) -> KeyJob:
        with self._engine.connect() as connection:
            row = connection.execute(
                select(key_job).where(key_job.c.job_id == job_id)
            ).mappings().one_or_none()
        if row is None:
            raise NotFoundError(f"no such key job: {job_id!r}")
        return _from_row(row)

    def history(self, connection_id: str, limit: int = 25) -> list[KeyJob]:
        """This connection's jobs, newest first."""
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(key_job)
                .where(key_job.c.connection_id == connection_id)
                .order_by(key_job.c.seq.desc()).limit(limit)).mappings().all()
        return [_from_row(row) for row in rows]

    def outstanding(self, connection_id: str) -> KeyJob | None:
        """The job this connection is waiting on, if any."""
        with self._engine.connect() as connection:
            row = connection.execute(
                select(key_job)
                .where(key_job.c.connection_id == connection_id,
                       key_job.c.state.in_((JobState.QUEUED.value,
                                            JobState.RUNNING.value)))
                .order_by(key_job.c.seq).limit(1)).mappings().one_or_none()
        return None if row is None else _from_row(row)


class KeyJobQueue:
    """The worker's view: claim one job, then say how it went."""

    __slots__ = ("_engine", "_audit")

    def __init__(self, engine: Engine, audit: AuditLog | None = None) -> None:
        self._engine = engine
        self._audit = audit or AuditLog(engine)

    def claim(self, *, worker_id: str, now: _dt.datetime | None = None,
              lease: _dt.timedelta = CLAIM_LEASE) -> KeyJob | None:
        """Take the oldest claimable job, atomically. ``None`` if there is none.

        The same single conditional ``UPDATE`` as :mod:`painfree.queue`, for the
        same reason: two workers polling one table is the ordinary deployment,
        and two workers driving one `INI` would register a key twice.
        """
        now = now or _dt.datetime.now(_dt.timezone.utc)
        expired = now - lease
        candidate = (
            select(key_job.c.seq)
            .where(or_(
                key_job.c.state == JobState.QUEUED.value,
                and_(key_job.c.state == JobState.RUNNING.value,
                     key_job.c.claimed_at.is_not(None),
                     key_job.c.claimed_at < expired,
                     key_job.c.attempts < MAX_ATTEMPTS),
            ))
            .order_by(key_job.c.seq).limit(1))
        if self._engine.dialect.name == "postgresql":
            candidate = candidate.with_for_update(skip_locked=True)

        statement = (key_job.update()
                     .where(key_job.c.seq == candidate.scalar_subquery())
                     .values(state=JobState.RUNNING.value, worker_id=worker_id,
                             claimed_at=now, attempts=key_job.c.attempts + 1,
                             updated_at=now)
                     .returning(*key_job.c))
        with self._engine.begin() as connection:
            row = connection.execute(statement).mappings().one_or_none()
        if row is None:
            return None
        job = _from_row(row)
        with bind(connection_id=job.connection_id, job_id=job.job_id):
            if job.attempts > 1:
                log.warning("keyjob.reclaimed", action=job.action.value,
                            worker_id=worker_id, attempt=job.attempts,
                            reason="a worker was claimed to be running this job "
                                   "and its lease expired")
            log.info("keyjob.claimed", action=job.action.value,
                     worker_id=worker_id, attempt=job.attempts)
        return job

    def succeeded(self, job: KeyJob, *, result: dict[str, Any],
                  return_code: str | None = None,
                  report_text: str | None = None) -> KeyJob:
        return self._settle(job, JobState.DONE, result=result,
                            return_code=return_code, report_text=report_text,
                            last_error=None)

    def failed(self, job: KeyJob, *, reason: str,
               result: dict[str, Any] | None = None,
               return_code: str | None = None,
               report_text: str | None = None) -> KeyJob:
        return self._settle(job, JobState.FAILED, result=result,
                            return_code=return_code, report_text=report_text,
                            last_error=_short(reason))

    def _settle(self, job: KeyJob, state: JobState, *,
                result: dict[str, Any] | None, return_code: str | None,
                report_text: str | None, last_error: str | None) -> KeyJob:
        now = _dt.datetime.now(_dt.timezone.utc)
        with self._engine.begin() as connection:
            connection.execute(
                key_job.update().where(key_job.c.job_id == job.job_id)
                .values(state=state.value, worker_id=None, claimed_at=None,
                        result=result, return_code=return_code,
                        report_text=report_text, last_error=last_error,
                        updated_at=now, finished_at=now))
        with bind(connection_id=job.connection_id, job_id=job.job_id):
            self._audit.record(
                "key.job_finished",
                actor=Actor(job.requested_by_type, job.requested_by_id),
                outcome=FAILURE if state is JobState.FAILED else "success",
                connection_id=job.connection_id, job_id=job.job_id,
                # `job_state`, not `state`: `state` is a redacted field name
                # (`painfree.logging.SENSITIVE_FIELDS`), so a bare one showed an
                # operator `***` where the job's outcome should be. The same
                # rename made in the order writers and in the downloader;
                # `tests/test_service_audit_actions.py` now fails the next one
                # rather than waiting for someone to notice it.
                detail={"action": job.action.value, "job_state": state.value,
                        "result": result, "return_code": return_code,
                        "report_text": report_text, "error": last_error})
            log.info("keyjob.finished", action=job.action.value,
                     job_state=state.value, return_code=return_code,
                     report_text=report_text, error=last_error)
        with self._engine.connect() as connection:
            row = connection.execute(
                select(key_job).where(key_job.c.job_id == job.job_id)
            ).mappings().one()
        return _from_row(row)


def _short(reason: str) -> str:
    reason = " ".join(str(reason).split())
    return reason if len(reason) <= MAX_ERROR_LENGTH else (
        reason[:MAX_ERROR_LENGTH - 1] + "…")


def _from_row(row: Any) -> KeyJob:
    return KeyJob(
        job_id=row["job_id"], connection_id=row["connection_id"],
        action=KeyAction(row["action"]), params=row["params"] or {},
        state=JobState(row["state"]),
        requested_by_type=row["requested_by_type"],
        requested_by_id=row["requested_by_id"], worker_id=row["worker_id"],
        attempts=row["attempts"], result=row["result"],
        return_code=row["return_code"], report_text=row["report_text"],
        last_error=row["last_error"], created_at=row["created_at"],
        updated_at=row["updated_at"], finished_at=row["finished_at"])


__all__ = ["ALLOWED_FROM", "CLAIM_LEASE", "JOB_ID_PREFIX", "JobState",
           "KeyAction", "KeyJob", "KeyJobQueue", "KeyJobStore", "MAX_ATTEMPTS"]
