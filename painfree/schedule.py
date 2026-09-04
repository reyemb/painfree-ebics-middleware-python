"""Periodic download jobs: when the next one is due, and who owns it.

The scheduler's whole state is one table. There is no in-process timer wheel and
no cron *daemon*, because both of those forget: a process that restarts at 03:00
with its schedule in memory has no idea what it was meant to do at 02:55.
``download_schedule.due_at`` is a row, so a scheduler that comes back finds one
overdue schedule -- **one**, not one per interval it slept through. Missing a
window is a gap an operator can see and re-run; firing 288 catch-up downloads
because a container was restarted is a stampede at the bank's end.

A schedule may nonetheless be *written* as a cron expression
(``download_schedule.cron``), and that changes none of the above: the expression
is consulted once, when a finished run computes the next ``due_at``, and the row
is still the only state. A restart still finds one overdue schedule and not the
history it slept through (:mod:`painfree.cron`).

**Two schedulers must not both fetch the same window.** The same reasoning as
:mod:`painfree.queue`, and the same mechanism: the claim is a single conditional
``UPDATE`` whose subquery picks the candidate and whose ``RETURNING`` hands back
the row it took, with ``FOR UPDATE SKIP LOCKED`` on PostgreSQL so several
schedulers take *different* schedules rather than queueing behind one. A
read-then-write cannot do it -- both readers see "due", both fetch, and the bank
serves one statement twice, of which one copy is then never acknowledged.

``claimed_at`` is a lease, for the same reason the upload queue's is: a
scheduler that dies mid-download would otherwise strand a schedule for ever.

**The cadence does not stampede either.** ``due_at`` is set from the moment a
run *finished* plus the cadence plus a jitter of up to
:data:`JITTER_FRACTION` of it. Without the jitter every schedule registered in
the same deployment drifts into lockstep and the bank sees all of them at once,
every hour, for ever.

**The window is the point of the ledger.** ``fetched_through`` advances only
when a run finished -- with data or with the bank saying it had none. A run that
failed leaves it where it was, so the next run asks for the same window again;
and every attempt, successful or not, leaves a ``download_run`` row saying what
it asked for and how it ended. A statement that never arrived is then a row an
operator can find, not an absence they have to infer.
"""

from __future__ import annotations

import datetime as _dt
import random
import uuid
from dataclasses import dataclass
from typing import Any, Sequence

from sqlalchemy import Engine, and_, func, or_, select
from sqlalchemy.exc import IntegrityError

from painfree import cron as cron_module
from painfree import ebics3
from painfree.audit import (FAILURE, SUCCESS, SYSTEM_ACTOR, Actor,
                            AuditLog)
from painfree.errors import ConflictError, NotFoundError
from painfree.logging import bind, get_logger
from painfree.schema import download_run, download_schedule

log = get_logger("painfree.schedule")

SCHEDULE_ID_PREFIX = "dsc_"
RUN_ID_PREFIX = "run_"

#: How long a claim is good for. A statement download of a hundred segments
#: from a slow bank is minutes, not hours; a scheduler that has been silent for
#: this long is not coming back.
CLAIM_LEASE = _dt.timedelta(minutes=15)

#: How much of the cadence the next due time is spread over. Enough that a
#: hundred hourly schedules registered in one deployment stop arriving in one
#: second, small enough that "every hour" still means every hour.
JITTER_FRACTION = 0.1

#: How soon a schedule is retried after a run that did not finish. Capped by
#: the cadence, because retrying more often than the schedule itself runs would
#: turn one broken connection into the busiest thing in the deployment.
RETRY_AFTER = _dt.timedelta(minutes=5)

#: The shortest cadence a schedule may have. A download is a multi-exchange
#: conversation with a bank and every bank has a fair-use limit; a schedule
#: that runs every second is a mistake, not a configuration.
MIN_CADENCE = _dt.timedelta(seconds=30)

MAX_ERROR_LENGTH = 512

#: What an operator may change about a schedule after it exists. Its id and its
#: connection are not here: those are its identity, and a schedule pointed at a
#: different bank is a different schedule with one bank's window ledger.
#: ``fetched_through`` is not here either -- rewinding it is
#: :meth:`DownloadSchedules.refetch`, which says so in the ledger.
MUTABLE = frozenset({"service_name", "msg_name", "msg_version", "msg_variant",
                     "scope", "service_option", "container", "cadence_seconds",
                     "cron", "window_days", "description", "enabled"})

#: The BTF columns, in the order the engine's ``Service`` takes them. Kept in
#: one place so a change validated on registration is validated identically on
#: an edit rather than by a second reading of the same rules.
BTF_COLUMNS = ("service_name", "msg_name", "msg_version", "msg_variant",
               "scope", "service_option", "container")

#: How a run ended. `empty` is a *success*: `EBICS_NO_DOWNLOAD_DATA_AVAILABLE`
#: means the bank had nothing to send, which is what most scheduled downloads
#: find most of the time.
RUNNING = "running"
COMPLETE = "complete"
EMPTY = "empty"
REFUSED = "refused"
FAILED = "failed"

#: The two outcomes that mean the bank answered for the window it was asked
#: about, and the window may therefore move on.
FINISHED = (COMPLETE, EMPTY)


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


@dataclass(frozen=True, slots=True)
class Schedule:
    """One periodic download, as the rest of the service sees it."""

    schedule_id: str
    connection_id: str
    service_name: str
    msg_name: str
    msg_version: str | None
    msg_variant: str | None
    scope: str | None
    service_option: str | None
    container: str | None
    cadence: _dt.timedelta
    enabled: bool
    window_days: int | None
    fetched_through: str | None
    #: A five-field cron expression, or `None` when the cadence decides. Set,
    #: it is what picks the next run; the cadence still caps the retry after a
    #: run that did not finish.
    cron: str | None
    due_at: _dt.datetime
    description: str | None = None
    worker_id: str | None = None
    claimed_at: _dt.datetime | None = None
    last_run_at: _dt.datetime | None = None
    last_return_code: str | None = None
    last_error: str | None = None
    run_requested_by: str | None = None

    @property
    def service(self) -> ebics3.Service:
        """The BTF this schedule asks for, validated by the engine's own rules."""
        return ebics3.Service(
            name=self.service_name, msg_name=self.msg_name, scope=self.scope,
            option=self.service_option, container=self.container,
            msg_variant=self.msg_variant, msg_version=self.msg_version)

    @property
    def label(self) -> str:
        """What a log line calls this schedule: the BTF, in one field."""
        version = f".{self.msg_version}" if self.msg_version else ""
        return f"{self.service_name}/{self.msg_name}{version}"

    def window(self, today: _dt.date | None = None) -> tuple[str | None, str | None]:
        """The `DateRange` this run asks for, or ``(None, None)`` for none.

        A schedule with no ``window_days`` sends no ``DateRange`` at all, which
        is the ordinary EBICS model: the bank serves what it has pending and the
        *receipt* is what stops it being served again. A schedule that does have
        one asks from the day after the high-water mark, so a window that failed
        is asked for again rather than skipped.
        """
        if self.window_days is None:
            return None, None
        today = today or utcnow().date()
        if self.fetched_through:
            start = _dt.date.fromisoformat(self.fetched_through) + _dt.timedelta(days=1)
        else:
            start = today - _dt.timedelta(days=self.window_days)
        return min(start, today).isoformat(), today.isoformat()

    def ledger(self, today: _dt.date | None = None) -> "Window":
        """What this schedule has covered, and what it has not."""
        start, end = self.window(today)
        return Window(dated=self.window_days is not None,
                      covered_through=self.fetched_through,
                      pending_start=start, pending_end=end)

    @property
    def running(self) -> bool:
        """Is a worker holding this schedule right now?"""
        return self.claimed_at is not None

    @property
    def health(self) -> str:
        """The one word an operator reads first.

        Whether the last return code was a failure is asked of the *engine's*
        table (``ebics3.lookup``) rather than of a list written out beside it:
        `090005` is `EBICS_NO_DOWNLOAD_DATA_AVAILABLE`, which the table
        classifies as a completed transaction, so a run that found nothing
        leaves the schedule ``healthy``. A console with its own list of benign
        codes is a console that can eventually call a normal empty download a
        failure, and the word an operator has to be able to trust is
        ``failing``.
        """
        if not self.enabled:
            return "paused"
        code = ebics3.lookup(self.last_return_code)
        if self.last_error or (code is not None and not code.is_benign):
            return "failing"
        if self.last_run_at is None:
            return "untried"
        return "healthy"

    def as_response(self, today: _dt.date | None = None) -> dict[str, Any]:
        """The JSON one schedule is, in the REST contract's shape."""
        return {
            "schedule_id": self.schedule_id,
            "connection_id": self.connection_id,
            "description": self.description,
            "service": {"service_name": self.service_name,
                        "msg_name": self.msg_name,
                        "msg_version": self.msg_version,
                        "msg_variant": self.msg_variant,
                        "scope": self.scope,
                        "service_option": self.service_option,
                        "container": self.container},
            "label": self.label,
            "cadence_seconds": int(self.cadence.total_seconds()),
            "cron": self.cron,
            "enabled": self.enabled,
            "health": self.health,
            "running": self.running,
            "window_days": self.window_days,
            "window": self.ledger(today).as_response(),
            "due_at": self.due_at.isoformat(),
            "last_run_at": (self.last_run_at.isoformat()
                            if self.last_run_at else None),
            "last_return_code": self.last_return_code,
            "last_error": self.last_error,
            "run_requested_by": self.run_requested_by,
        }


@dataclass(frozen=True, slots=True)
class Window:
    """What one schedule has covered and what it has not, on a given day.

    Derived, never stored: it is :attr:`Schedule.fetched_through` and
    :meth:`Schedule.window` read together, in the one place that names what the
    pair *means*. A console and an API that each computed "how far behind is
    this" would eventually disagree about a gap, which is the one number an
    operator opens the page for.
    """

    #: Whether this schedule sends a ``DateRange`` at all. False means the bank
    #: serves what it has pending and the receipt is what stops a re-serve --
    #: there is no window to be behind on, and saying "0 days" would be a lie.
    dated: bool
    #: The high-water mark: the last day the bank has answered for.
    covered_through: str | None
    #: The window the next run will ask for.
    pending_start: str | None
    pending_end: str | None

    @property
    def days_pending(self) -> int:
        """Days the next run will ask for, today included. `0` when undated."""
        if not (self.pending_start and self.pending_end):
            return 0
        return (_dt.date.fromisoformat(self.pending_end)
                - _dt.date.fromisoformat(self.pending_start)).days + 1

    @property
    def days_behind(self) -> int:
        """Days older than today that are still outstanding.

        Today is always pending -- the day is not over -- so it is not a gap.
        Anything before it is: those are days the bank has been asked about and
        has not answered for, or has not been asked about at all.
        """
        return max(0, self.days_pending - 1)

    @property
    def share_behind(self) -> int:
        """How much of the window the next run asks for is already overdue, 0-100.

        The one number a picture of coverage needs. Today is always in the
        pending window and is never a gap, so a schedule that is up to date has
        a window of one day and nothing overdue in it; one twelve days behind
        has thirteen, of which twelve are. A band drawn to this reads *how much
        of what we are about to ask for should already have been answered*,
        which is the question, and it stays honest for an undated schedule by
        being zero rather than by guessing at a span.
        """
        if not self.behind:
            # A schedule that has never fetched anything is not behind, however
            # wide the window it is about to ask for -- the same rule
            # :attr:`behind` states, and this has to agree with it or a picture
            # drawn from the two contradicts itself.
            return 0
        total = self.days_pending
        return round(self.days_behind * 100 / total) if total else 0

    @property
    def behind(self) -> bool:
        """Are there days the bank answered *past* and has not answered for?

        A schedule that has never fetched anything is **not** behind, however
        long its first window is: asking for the last seven days on a first run
        is the window doing its job, not a gap. Requiring a high-water mark is
        what keeps the amber panel on the list page meaning something -- a
        console that flagged every newly registered schedule would train an
        operator to scroll past the one that is genuinely stuck.
        """
        return self.covered_through is not None and self.days_behind > 0

    def as_response(self) -> dict[str, Any]:
        return {"dated": self.dated, "covered_through": self.covered_through,
                "pending_start": self.pending_start,
                "pending_end": self.pending_end,
                "days_pending": self.days_pending,
                "days_behind": self.days_behind, "behind": self.behind}


@dataclass(frozen=True, slots=True)
class ClaimedSchedule:
    """One schedule this worker now owns, and the run row opened for it."""

    schedule: Schedule
    run_id: str
    worker_id: str
    window_start: str | None
    window_end: str | None

    @property
    def schedule_id(self) -> str:
        return self.schedule.schedule_id

    @property
    def connection_id(self) -> str:
        return self.schedule.connection_id


def _validated_cron(expression: str | None) -> str | None:
    """The expression as it will be stored, or a refusal naming what is wrong.

    Validated here rather than at the form, so the API and the console cannot
    disagree about what this service will act on, and so a row can only ever
    hold an expression the scheduler can read.
    """
    text = (expression or "").strip()
    if not text:
        return None
    return cron_module.parse(text).expression


class DownloadSchedules:
    """Reads and writes ``download_schedule`` and ``download_run``.

    Holds no keys and opens no sockets, which is why it is a module of its own:
    the claim is the part that has to be right under concurrency, and it is
    reviewable without reading a line of EBICS.
    """

    __slots__ = ("_engine", "_audit", "_random")

    def __init__(self, engine: Engine, audit: AuditLog | None = None,
                 jitter: random.Random | None = None) -> None:
        self._engine = engine
        self._audit = audit or AuditLog(engine)
        self._random = jitter or random.Random()

    # --- registration ------------------------------------------------------

    def register(self, connection_id: str, *, service_name: str, msg_name: str,
                 cadence: _dt.timedelta, msg_version: str | None = None,
                 msg_variant: str | None = None, scope: str | None = None,
                 service_option: str | None = None, container: str | None = None,
                 window_days: int | None = None, enabled: bool = True,
                 cron: str | None = None,
                 description: str | None = None, actor: Actor | None = None,
                 due_at: _dt.datetime | None = None) -> Schedule:
        """Add one periodic download.

        The BTF is taken rather than guessed. Which service a bank publishes for
        statements is per-bank configuration -- `EOP`, `STM`, something else --
        and a wrong `ServiceName` is answered with `EBICS_INVALID_ORDER_PARAMS`
        rather than with a local error, which is the failure the
        validate-before-the-bank rule exists to avoid. So it is registered, not
        inferred.
        """
        if cadence < MIN_CADENCE:
            raise ConflictError(
                f"a cadence of {cadence} is shorter than the {MIN_CADENCE} "
                f"minimum; a download is a conversation with a bank")
        # Raises `RequestError` for a BTF the bank's schema would refuse.
        ebics3.Service(name=service_name, msg_name=msg_name, scope=scope,
                       option=service_option, container=container,
                       msg_variant=msg_variant, msg_version=msg_version)

        now = utcnow()
        schedule_id = SCHEDULE_ID_PREFIX + uuid.uuid4().hex
        values = {
            "schedule_id": schedule_id, "connection_id": connection_id,
            "service_name": service_name, "scope": scope,
            "service_option": service_option, "container": container,
            "msg_name": msg_name, "msg_variant": msg_variant,
            "msg_version": msg_version,
            "cadence_seconds": int(cadence.total_seconds()),
            "cron": _validated_cron(cron),
            "enabled": enabled, "window_days": window_days,
            "fetched_through": None, "due_at": due_at or now,
            "created_at": now, "updated_at": now,
        }
        values["description"] = description
        try:
            with self._engine.begin() as connection:
                connection.execute(download_schedule.insert().values(**values))
        except IntegrityError:
            # `uq_download_schedule_btf`. This is the idempotency of this
            # endpoint and it is a constraint rather than a check: a repeated
            # registration of the same BTF for the same connection cannot
            # become two schedules asking one bank for one statement on two
            # cadences, whichever process issued it.
            existing = self._by_btf(connection_id, service_name, msg_name,
                                    msg_version)
            log.warning("download_schedule.duplicate",
                        connection_id=connection_id,
                        service=f"{service_name}/{msg_name}",
                        schedule_id=existing.schedule_id if existing else None)
            raise ConflictError(
                f"connection {connection_id!r} already has a schedule for "
                f"{service_name}/{msg_name}"
                + (f" ({existing.schedule_id})" if existing else ""),
                detail={"schedule_id": existing.schedule_id} if existing else None,
            ) from None
        schedule = self.get(schedule_id)
        with bind(connection_id=connection_id):
            self._audit.record(
                "download_schedule.registered", connection_id=connection_id,
                actor=actor or SYSTEM_ACTOR,
                detail={"schedule_id": schedule_id, "service": schedule.label,
                        "cadence_seconds": values["cadence_seconds"],
                        "window_days": window_days, "enabled": enabled},
            )
        return schedule

    def _by_btf(self, connection_id: str, service_name: str, msg_name: str,
                msg_version: str | None) -> Schedule | None:
        """The row the unique constraint refused to duplicate."""
        with self._engine.connect() as connection:
            row = connection.execute(
                select(download_schedule).where(and_(
                    download_schedule.c.connection_id == connection_id,
                    download_schedule.c.service_name == service_name,
                    download_schedule.c.msg_name == msg_name,
                    download_schedule.c.msg_version.is_(msg_version)
                    if msg_version is None
                    else download_schedule.c.msg_version == msg_version,
                ))).mappings().one_or_none()
        return _from_row(row) if row else None

    def get(self, schedule_id: str) -> Schedule:
        with self._engine.connect() as connection:
            row = connection.execute(
                select(download_schedule)
                .where(download_schedule.c.schedule_id == schedule_id)
            ).mappings().one_or_none()
        if row is None:
            raise NotFoundError(f"no such download schedule: {schedule_id!r}")
        return _from_row(row)

    def all(self, connection_id: str | None = None,
            connection_ids: Sequence[str] | None = None) -> list[Schedule]:
        """Schedules, narrowed by the filter and by what the caller may see."""
        query = select(download_schedule).order_by(download_schedule.c.seq)
        if connection_id is not None:
            query = query.where(download_schedule.c.connection_id == connection_id)
        if connection_ids is not None:
            # What this caller holds a grant on.
            query = query.where(
                download_schedule.c.connection_id.in_(list(connection_ids)))
        with self._engine.connect() as connection:
            return [_from_row(row) for row in connection.execute(query).mappings()]

    def set_enabled(self, schedule_id: str, enabled: bool,
                    actor: Actor | None = None) -> Schedule:
        """Stop or restart one schedule without losing its window."""
        return self.update(schedule_id, actor=actor, enabled=enabled)

    def update(self, schedule_id: str, *, actor: Actor | None = None,
               **changes: Any) -> Schedule:
        """Change what an operator may change, validating what the bank will see.

        The BTF is re-validated **against the merged row**, not against the
        fields that arrived: an edit that changes only ``msg_version`` still has
        to produce a `BTF` the bank's schema accepts, and validating the change
        alone would pass a combination that fails hours later as
        `EBICS_INVALID_ORDER_PARAMS`.

        The window ledger is deliberately untouched. Changing a cadence or a
        description says nothing about which days have been fetched, and an edit
        that silently reset the high-water mark would re-ask a bank for a month.
        """
        unknown = set(changes) - MUTABLE
        if unknown:
            raise ConflictError(
                "a download schedule has no such field: "
                + ", ".join(sorted(unknown)))
        current = self.get(schedule_id)
        if not changes:
            return current

        if "cron" in changes:
            changes["cron"] = _validated_cron(changes["cron"])
        cadence_seconds = changes.get("cadence_seconds")
        if cadence_seconds is not None and (
                _dt.timedelta(seconds=int(cadence_seconds)) < MIN_CADENCE):
            raise ConflictError(
                f"a cadence of {cadence_seconds}s is shorter than the "
                f"{int(MIN_CADENCE.total_seconds())}s minimum; a download is a "
                f"conversation with a bank")
        window_days = changes.get("window_days")
        if window_days is not None and int(window_days) < 1:
            raise ConflictError(
                "a window of fewer than one day asks the bank for nothing; "
                "leave it empty to send no DateRange at all")

        merged = {column: changes.get(column, getattr(current, column))
                  for column in BTF_COLUMNS}
        # Raises `RequestError` for a BTF the bank's schema would refuse.
        ebics3.Service(name=merged["service_name"], msg_name=merged["msg_name"],
                       scope=merged["scope"], option=merged["service_option"],
                       container=merged["container"],
                       msg_variant=merged["msg_variant"],
                       msg_version=merged["msg_version"])

        self._write(schedule_id, **changes)
        schedule = self.get(schedule_id)
        with bind(connection_id=schedule.connection_id):
            self._audit.record(
                "download_schedule.updated",
                connection_id=schedule.connection_id,
                actor=actor or SYSTEM_ACTOR,
                detail={"schedule_id": schedule_id, "service": schedule.label,
                        "changed": sorted(changes)})
            log.info("download_schedule.updated", schedule_id=schedule_id,
                     service=schedule.label, changed=sorted(changes),
                     enabled=schedule.enabled)
        return schedule

    def delete(self, schedule_id: str, actor: Actor | None = None) -> int:
        """Remove one schedule and its run ledger. Returns the runs dropped.

        The statements it fetched are **not** removed. They are the point of
        having had the schedule, they are referenced by order pages and
        reconciliation, and `statement.run_id` is a plain column precisely so
        that dropping a schedule cannot cascade into payment records.
        """
        schedule = self.get(schedule_id)
        with self._engine.begin() as connection:
            runs = connection.execute(
                select(func.count()).select_from(download_run)
                .where(download_run.c.schedule_id == schedule_id)).scalar_one()
            connection.execute(download_schedule.delete()
                               .where(download_schedule.c.schedule_id == schedule_id))
        with bind(connection_id=schedule.connection_id):
            self._audit.record(
                "download_schedule.deleted",
                connection_id=schedule.connection_id,
                actor=actor or SYSTEM_ACTOR,
                detail={"schedule_id": schedule_id, "service": schedule.label,
                        "runs_dropped": runs,
                        "fetched_through": schedule.fetched_through})
            log.warning("download_schedule.deleted", schedule_id=schedule_id,
                        service=schedule.label, runs_dropped=runs,
                        fetched_through=schedule.fetched_through,
                        reason="an operator removed the schedule; the "
                               "statements it fetched are kept")
        return runs

    # --- asking for a run out of band --------------------------------------

    def run_now(self, schedule_id: str, *, requested_by: str,
                actor: Actor | None = None,
                now: _dt.datetime | None = None) -> Schedule:
        """Make this schedule due immediately. The **worker** runs it.

        Nothing is downloaded here: this process holds no custody key and a
        download decrypts with the connection's `E002` private half, so the only
        thing a surface can do is move the row's ``due_at`` and let the download
        worker claim it on its next poll. That is the same shape as a key job
        and as a webhook ping: queued, not sent.

        Who asked is recorded on the row and copied onto the run the claim
        opens, because a run that reports duplicates means one thing when the
        cadence caused it and the opposite when a human asked for a window back.
        """
        schedule = self._claimable(schedule_id, "run")
        now = now or utcnow()
        self._write(schedule_id, due_at=now, run_requested_by=requested_by)
        return self._requested(schedule, "download_schedule.run_requested",
                               actor, requested_by,
                               detail={"due_at": now.isoformat()})

    def refetch(self, schedule_id: str, *, since: _dt.date, requested_by: str,
                actor: Actor | None = None,
                now: _dt.datetime | None = None) -> Schedule:
        """Ask the bank again for every day from ``since``, and run at once.

        Implemented by rewinding the high-water mark rather than by a second
        mechanism, so the next window is computed by exactly the code every
        ordinary run uses: ``fetched_through`` goes back to the day *before*
        ``since``, and :meth:`Schedule.window` therefore asks from ``since`` to
        today.

        **Re-fetching is safe because ingestion is keyed on the document.** A
        statement the bank serves twice hits
        `uq_statement_connection_id_document_key` and is counted as a duplicate
        rather than stored again (:mod:`painfree.statements`) -- which is the
        same constraint that already absorbs an unacknowledged download being
        re-served, so this adds no second guarantee to keep true.

        The rewind is not free and the docstring says so rather than the code
        implying otherwise: if the re-fetch run then *fails*, the mark stays
        rewound and the next ordinary run asks for the whole widened window.
        That is the safe direction -- it re-asks rather than skips -- but it is
        a wider request than the operator asked for.
        """
        schedule = self._claimable(schedule_id, "re-fetch")
        if schedule.window_days is None:
            raise ConflictError(
                f"schedule {schedule_id!r} sends no DateRange, so there is no "
                f"window to re-fetch; the bank serves what it has pending and "
                f"the receipt is what stops it being served twice")
        now = now or utcnow()
        today = now.date()
        if since > today:
            raise ConflictError(
                f"{since.isoformat()} is in the future; a window can only be "
                f"re-fetched up to today ({today.isoformat()})")
        mark = (since - _dt.timedelta(days=1)).isoformat()
        self._write(schedule_id, fetched_through=mark, due_at=now,
                    run_requested_by=requested_by)
        return self._requested(
            schedule, "download_schedule.refetch_requested", actor,
            requested_by,
            detail={"since": since.isoformat(), "until": today.isoformat(),
                    "fetched_through_before": schedule.fetched_through,
                    "fetched_through_after": mark})

    def _claimable(self, schedule_id: str, what: str) -> Schedule:
        """The schedule, if a worker could take it now. Refuses with the reason.

        A disabled schedule is refused rather than run once: `enabled` is what
        the claim filters on, so a surface that pretended otherwise would set
        ``due_at`` on a row nothing will ever pick up and report success.
        """
        schedule = self.get(schedule_id)
        if not schedule.enabled:
            raise ConflictError(
                f"schedule {schedule_id!r} is disabled, so no worker will claim "
                f"it; enable it first, then {what} it")
        if schedule.running:
            raise ConflictError(
                f"schedule {schedule_id!r} is already running on worker "
                f"{schedule.worker_id!r}; wait for that run to finish")
        return schedule

    def _requested(self, schedule: Schedule, action: str, actor: Actor | None,
                   requested_by: str, *, detail: dict[str, Any]) -> Schedule:
        detail = {"schedule_id": schedule.schedule_id,
                  "service": schedule.label, "requested_by": requested_by,
                  **detail}
        with bind(connection_id=schedule.connection_id):
            self._audit.record(action, connection_id=schedule.connection_id,
                               actor=actor or SYSTEM_ACTOR, detail=detail)
            log.info(action, **detail)
        return self.get(schedule.schedule_id)

    # --- claiming ----------------------------------------------------------

    def claim(self, *, worker_id: str, now: _dt.datetime | None = None,
              lease: _dt.timedelta = CLAIM_LEASE) -> ClaimedSchedule | None:
        """Take the most overdue claimable schedule, atomically.

        One statement, for the reason in the module docstring. The run row is
        opened straight afterwards so that every claim has a ledger entry --
        including the ones that end in a crash, which are exactly the ones an
        operator goes looking for.
        """
        now = now or utcnow()
        expired = now - lease
        statement = (
            download_schedule.update()
            .where(download_schedule.c.seq
                   == self._candidate(now, expired).scalar_subquery())
            .values(worker_id=worker_id, claimed_at=now, updated_at=now)
            .returning(*download_schedule.c)
        )
        with self._engine.begin() as connection:
            row = connection.execute(statement).mappings().one_or_none()
        if row is None:
            return None

        schedule = _from_row(row)
        window_start, window_end = schedule.window(now.date())
        run_id = self._open_run(schedule, worker_id, window_start, window_end, now)
        with bind(connection_id=schedule.connection_id, job_id=run_id):
            if row["claimed_at"] is not None and row["worker_id"] != worker_id:
                log.warning(
                    "download.reclaimed", schedule_id=schedule.schedule_id,
                    previous_worker_id=row["worker_id"],
                    reason="the previous claim's lease expired; the bank may "
                           "serve the same data again, which the receipt and "
                           "the ingestion constraint both cover")
            log.info("download.claimed", schedule_id=schedule.schedule_id,
                     worker_id=worker_id, service=schedule.label,
                     window_start=window_start, window_end=window_end,
                     fetched_through=schedule.fetched_through)
        return ClaimedSchedule(schedule=schedule, run_id=run_id,
                               worker_id=worker_id, window_start=window_start,
                               window_end=window_end)

    def _candidate(self, now: _dt.datetime, expired: _dt.datetime):
        """The one row a claim will try to take, locked where the backend can."""
        query = (
            select(download_schedule.c.seq)
            .where(and_(
                download_schedule.c.enabled.is_(True),
                or_(
                    # Due, and nobody holds it.
                    and_(download_schedule.c.claimed_at.is_(None),
                         download_schedule.c.due_at <= now),
                    # Held by a scheduler that has not been heard from since.
                    and_(download_schedule.c.claimed_at.is_not(None),
                         download_schedule.c.claimed_at < expired),
                ),
            ))
            # Most overdue first, so a backlog drains oldest-first rather than
            # letting one schedule starve behind a busier one.
            .order_by(download_schedule.c.due_at, download_schedule.c.seq)
            .limit(1)
        )
        if self._engine.dialect.name == "postgresql":
            query = query.with_for_update(skip_locked=True)
        return query

    # --- outcomes ----------------------------------------------------------

    def finished(self, claimed: ClaimedSchedule, *, state: str,
                 return_code: str | None = None, report_text: str | None = None,
                 transaction_id: str | None = None,
                 bank_order_id: str | None = None, acknowledged: bool = False,
                 segments: int = 0, byte_count: int = 0, documents: int = 0,
                 statements: int = 0, duplicates: int = 0,
                 error: str | None = None,
                 now: _dt.datetime | None = None) -> None:
        """Close the run and release the claim, whatever happened.

        The window advances only for :data:`FINISHED` -- a completed download or
        a bank that had nothing to send. Anything else leaves ``fetched_through``
        where it was, which is what makes the missed window the next run's job
        rather than a hole nobody notices.
        """
        now = now or utcnow()
        schedule = claimed.schedule
        moved_on = state in FINISHED
        with self._engine.begin() as connection:
            connection.execute(
                download_run.update()
                .where(download_run.c.run_id == claimed.run_id)
                .values(state=state, finished_at=now, return_code=return_code,
                        report_text=_short(report_text) if report_text else None,
                        transaction_id=transaction_id, bank_order_id=bank_order_id,
                        acknowledged=acknowledged, segments=segments,
                        bytes=byte_count, documents=documents,
                        statements=statements, duplicates=duplicates,
                        last_error=_short(error) if error else None))
            connection.execute(
                download_schedule.update()
                .where(download_schedule.c.schedule_id == schedule.schedule_id)
                .values(worker_id=None, claimed_at=None, last_run_at=now,
                        last_return_code=return_code,
                        last_error=_short(error) if error else None,
                        updated_at=now,
                        due_at=self._next_due(schedule, now, moved_on),
                        **({"fetched_through": claimed.window_end or now.date().isoformat()}
                           if moved_on else {})))

        with bind(connection_id=schedule.connection_id, job_id=claimed.run_id):
            self._audit.record(
                "download.finished", connection_id=schedule.connection_id,
                outcome=SUCCESS if moved_on else FAILURE,
                # `run_state`, not `state`: `state` is a redacted field name
                # (`painfree.logging.SENSITIVE_FIELDS`), so a bare one would
                # show an operator `***` where the run's outcome should be.
                # The same rename made in the order writers.
                detail={"schedule_id": schedule.schedule_id, "run_id": claimed.run_id,
                        "service": schedule.label, "run_state": state,
                        "return_code": return_code, "report_text": report_text,
                        "documents": documents, "statements": statements,
                        "duplicates": duplicates,
                        "acknowledged": acknowledged,
                        "window_start": claimed.window_start,
                        "window_end": claimed.window_end},
            )
            emit = log.info if moved_on else log.warning
            emit("download.finished", schedule_id=schedule.schedule_id,
                 service=schedule.label, run_state=state, return_code=return_code,
                 report_text=report_text, acknowledged=acknowledged,
                 segments=segments, bytes=byte_count, documents=documents,
                 statements=statements, duplicates=duplicates,
                 window_start=claimed.window_start,
                 window_end=claimed.window_end,
                 fetched_through_advanced=moved_on, error=error)

    def opened(self, run_id: str, *, transaction_id: str | None) -> None:
        """Persist the `TransactionID` the moment the bank assigns it.

        A download that stops mid-transfer leaves a transaction open at the
        bank's end, and the id is the only name it has. Written before the
        first segment is asked for, so the run that crashed still says which
        transaction it was.
        """
        with self._engine.begin() as connection:
            connection.execute(
                download_run.update()
                .where(download_run.c.run_id == run_id)
                .values(transaction_id=transaction_id))

    def runs(self, schedule_id: str, limit: int = 50) -> list[dict[str, Any]]:
        """The ledger for one schedule, newest first."""
        with self._engine.connect() as connection:
            return [dict(row) for row in connection.execute(
                select(download_run)
                .where(download_run.c.schedule_id == schedule_id)
                .order_by(download_run.c.seq.desc()).limit(limit)).mappings()]

    def last_run(self, schedule_id: str) -> dict[str, Any] | None:
        """The most recent attempt, or ``None`` if it has never run."""
        rows = self.runs(schedule_id, limit=1)
        return rows[0] if rows else None

    def unfinished_runs(self, schedule_id: str,
                        limit: int = 50) -> list[dict[str, Any]]:
        """Runs that did not move the window: what a gap is actually made of.

        A `refused` or `failed` run asked the bank for days it did not get, and
        the high-water mark stayed where it was. Listing them is what turns
        "this schedule is four days behind" into four rows naming the window
        each attempt asked for and what the bank said.
        """
        with self._engine.connect() as connection:
            return [dict(row) for row in connection.execute(
                select(download_run)
                .where(and_(download_run.c.schedule_id == schedule_id,
                            download_run.c.state.notin_(
                                (RUNNING,) + tuple(FINISHED))))
                .order_by(download_run.c.seq.desc()).limit(limit)).mappings()]

    # --- storage -----------------------------------------------------------

    def _open_run(self, schedule: Schedule, worker_id: str,
                  window_start: str | None, window_end: str | None,
                  now: _dt.datetime) -> str:
        """Open the ledger row, and move an out-of-band request onto it.

        ``run_requested_by`` is consumed here rather than in the claim's own
        ``UPDATE`` because that statement's ``RETURNING`` would hand back the
        value it had just cleared. Doing it in the same transaction as the
        insert is safe: the schedule is claimed by the time this runs, and a
        surface refuses to request a run on a claimed schedule.
        """
        run_id = RUN_ID_PREFIX + uuid.uuid4().hex
        with self._engine.begin() as connection:
            connection.execute(download_run.insert().values(
                run_id=run_id, schedule_id=schedule.schedule_id,
                connection_id=schedule.connection_id, worker_id=worker_id,
                state=RUNNING, window_start=window_start, window_end=window_end,
                requested_by=schedule.run_requested_by, started_at=now))
            if schedule.run_requested_by is not None:
                connection.execute(
                    download_schedule.update()
                    .where(download_schedule.c.schedule_id == schedule.schedule_id)
                    .values(run_requested_by=None))
        return run_id

    def _next_due(self, schedule: Schedule, now: _dt.datetime,
                  finished: bool) -> _dt.datetime:
        """When this schedule may run again.

        From *now*, not from the previous due time: catching up on a cadence
        missed while the process was down would send the bank a burst of
        downloads for the same data.
        """
        if not finished:
            return now + min(schedule.cadence, RETRY_AFTER)
        if schedule.cron:
            # A time, not a rate: the next matching minute, and no jitter. The
            # jitter exists so a hundred hourly schedules stop arriving in one
            # second; an operator who wrote `0 8 * * *` asked for 08:00 and
            # moving it by minutes to spread load would be answering a question
            # they did not ask.
            try:
                return cron_module.parse(schedule.cron).next_after(now)
            except cron_module.CronError:
                # Stored expressions are validated on the way in, so this is a
                # row edited underneath the service. Fall back to the cadence
                # rather than stranding the schedule, and say so.
                log.error("schedule.cron_unreadable",
                          schedule_id=schedule.schedule_id, cron=schedule.cron)
        spread = schedule.cadence.total_seconds() * JITTER_FRACTION
        return now + schedule.cadence + _dt.timedelta(
            seconds=self._random.uniform(-spread, spread))

    def _write(self, schedule_id: str, **values: Any) -> None:
        values.setdefault("updated_at", utcnow())
        with self._engine.begin() as connection:
            connection.execute(
                download_schedule.update()
                .where(download_schedule.c.schedule_id == schedule_id)
                .values(**values))


def _from_row(row) -> Schedule:
    return Schedule(
        schedule_id=row["schedule_id"], connection_id=row["connection_id"],
        service_name=row["service_name"], msg_name=row["msg_name"],
        msg_version=row["msg_version"], msg_variant=row["msg_variant"],
        scope=row["scope"], service_option=row["service_option"],
        container=row["container"],
        cadence=_dt.timedelta(seconds=row["cadence_seconds"]),
        cron=row["cron"],
        enabled=bool(row["enabled"]), window_days=row["window_days"],
        fetched_through=row["fetched_through"], due_at=row["due_at"],
        description=row["description"],
        worker_id=row["worker_id"], claimed_at=row["claimed_at"],
        last_run_at=row["last_run_at"],
        last_return_code=row["last_return_code"], last_error=row["last_error"],
        run_requested_by=row["run_requested_by"])


def _short(reason: str) -> str:
    reason = " ".join(str(reason).split())
    return reason if len(reason) <= MAX_ERROR_LENGTH else (
        reason[:MAX_ERROR_LENGTH - 1] + "…")


def run_response(row: dict[str, Any]) -> dict[str, Any]:
    """One ``download_run`` as JSON. The ledger's shape, in one place.

    ``empty`` is a state and not an error, and it is returned as one: the
    contract has no `success` boolean to be wrong about, and a consumer that
    wants "did the bank answer" asks whether the state is in ``FINISHED``.
    """
    return {
        "run_id": row["run_id"], "schedule_id": row["schedule_id"],
        "state": row["state"], "finished": row["state"] in FINISHED,
        "window_start": row["window_start"], "window_end": row["window_end"],
        "return_code": row["return_code"], "report_text": row["report_text"],
        "acknowledged": bool(row["acknowledged"]),
        "segments": row["segments"], "bytes": row["bytes"],
        "documents": row["documents"], "statements": row["statements"],
        "duplicates": row["duplicates"], "last_error": row["last_error"],
        "requested_by": row["requested_by"],
        "transaction_id": row["transaction_id"],
        "started_at": row["started_at"].isoformat() if row["started_at"] else None,
        "finished_at": (row["finished_at"].isoformat()
                        if row["finished_at"] else None),
    }


__all__ = ["BTF_COLUMNS", "CLAIM_LEASE", "COMPLETE", "EMPTY", "FAILED",
           "FINISHED", "JITTER_FRACTION", "MIN_CADENCE", "MUTABLE", "REFUSED",
           "RETRY_AFTER", "RUNNING", "ClaimedSchedule", "DownloadSchedules",
           "Schedule", "Window", "run_response", "utcnow"]
