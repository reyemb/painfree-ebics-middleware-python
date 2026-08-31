"""The audit log: one chokepoint, append-only.

Who did what, and how it went. Two properties are what make it worth having:

**One writer.** Every audit row in this service is written by
:meth:`AuditLog.record` and nowhere else. Scattered ``INSERT INTO audit_log``
call sites drift -- one forgets the actor, one forgets the request id, one
writes the payment amount into the detail -- and the drift is only discovered
when someone needs the trail. There is deliberately no update and no delete: the
module exposes no way to amend a row, so "append-only" is a property of the
surface rather than a promise in a comment.

**It is also the event source.** Every webhook this service sends is an audit
row: :func:`painfree.webhooks.fan_out` runs inside the transaction below, so an
event owed to a consumer is written with the fact it reports rather than after
it. That is what makes at-least-once delivery mean something -- there is no
window in which a payment is rejected and nothing was recorded to tell anyone.
It also means the redaction below applies to webhook payloads, which is a
property worth having twice.

**The same redaction as the log stream.** The detail column goes through
:func:`painfree.logging.redact` before it is stored. An audit trail is read by
more people than a log stream is; it is the last place a token or a payment
payload should end up.

Recording is also *logged*, on the same line shape and with the same correlation
ids, so an event can be found in ``docker logs`` before anyone opens a database
client.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from dataclasses import dataclass
from typing import Any, Sequence

from sqlalchemy import Engine, select

from painfree.logging import CORRELATION_FIELDS, context, get_logger, redact
from painfree.schema import audit_log
from painfree.webhooks import fan_out

log = get_logger("painfree.audit")

SUCCESS = "success"
FAILURE = "failure"

#: What the service does on its own behalf -- startup, scheduled work, a worker
#: step. Human and machine callers arrive with an identity; until then this is
#: the only actor there is, and saying so is better than writing "unknown" and
#: pretending the column is already populated.
SYSTEM = "system"


@dataclass(frozen=True, slots=True)
class Actor:
    """Who did the thing. ``type`` is coarse, ``id`` is exact."""

    type: str = SYSTEM
    id: str = SYSTEM

    def __post_init__(self) -> None:
        if not self.type or not self.id:
            raise ValueError("an audit actor needs both a type and an id")


SYSTEM_ACTOR = Actor(SYSTEM, SYSTEM)


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """A row as it was written. Returned so a caller can quote the ``event_id``."""

    event_id: str
    action: str
    outcome: str
    occurred_at: _dt.datetime


class AuditLog:
    """The only writer of ``audit_log``."""

    __slots__ = ("_engine",)

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def record(
        self,
        action: str,
        *,
        actor: Actor = SYSTEM_ACTOR,
        outcome: str = SUCCESS,
        detail: dict[str, Any] | None = None,
        **correlation: Any,
    ) -> AuditEvent:
        """Append one event, and log it.

        Correlation ids default to whatever is bound in the current logging
        context, so a request handler that already bound ``request_id`` does not
        repeat it -- and cannot forget it.
        """
        unknown = set(correlation) - set(CORRELATION_FIELDS)
        if unknown:
            raise ValueError(
                "unknown correlation fields: " + ", ".join(sorted(unknown))
            )
        if outcome not in (SUCCESS, FAILURE):
            raise ValueError(f"outcome must be {SUCCESS!r} or {FAILURE!r}")

        bound = context()
        ids = {
            name: correlation.get(name, bound.get(name))
            for name in CORRELATION_FIELDS
        }
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            action=action,
            outcome=outcome,
            occurred_at=_dt.datetime.now(_dt.timezone.utc),
        )
        safe_detail = redact(detail or {})

        try:
            with self._engine.begin() as connection:
                connection.execute(
                    audit_log.insert().values(
                        event_id=event.event_id,
                        occurred_at=event.occurred_at,
                        actor_type=actor.type,
                        actor_id=actor.id,
                        action=action,
                        outcome=outcome,
                        detail=safe_detail,
                        **ids,
                    )
                )
                # In the same transaction, on purpose: an event a consumer is
                # owed is part of the record, not a consequence of it: the row
                # that says a payment was rejected and the row that owes that
                # fact to a webhook commit together, so there is no instant in
                # which one exists without the other. Most actions are not
                # events and this costs a dict lookup.
                fan_out(connection, event_id=event.event_id, action=action,
                        occurred_at=event.occurred_at, ids=ids,
                        detail=safe_detail)
        except Exception:
            # Logged here, where it is caught, then re-raised: a caller that
            # wanted an audit trail must not be told the write succeeded.
            log.exception("audit.write_failed", action=action, outcome=outcome, **ids)
            raise

        log.info(
            "audit.recorded",
            action=action,
            outcome=outcome,
            event_id=event.event_id,
            actor_type=actor.type,
            actor_id=actor.id,
            detail=safe_detail or None,
            **ids,
        )
        return event

    def recent(self, limit: int = 50, *, connection_id: str | None = None,
               connection_ids: Sequence[str] | None = None,
               order_id: str | None = None,
               action_prefix: str | None = None) -> list[dict[str, Any]]:
        """The newest events first, optionally narrowed to one thing's trail."""
        return self.search(limit=limit, connection_id=connection_id,
                           connection_ids=connection_ids,
                           order_id=order_id, action_prefix=action_prefix)

    def search(self, *, limit: int = 50, connection_id: str | None = None,
               connection_ids: Sequence[str] | None = None,
               order_id: str | None = None, job_id: str | None = None,
               request_id: str | None = None,
               idempotency_key: str | None = None,
               actor_id: str | None = None, action: str | None = None,
               action_prefix: str | None = None, outcome: str | None = None,
               since: _dt.datetime | None = None,
               until: _dt.datetime | None = None,
               before_seq: int | None = None) -> list[dict[str, Any]]:
        """The newest events first, narrowed to the question being asked.

        The scope is demanded at the surfaces, which is where a caller exists to
        demand it of (:data:`painfree.identity.Scope.audit_read`). What *is*
        decided here is which rows a caller may be shown at all.

        **``connection_ids`` restricts to those connections and excludes every
        row that names none.** The trail spans the deployment, and rows with a
        `NULL` `connection_id` are the ones that span it: the service starting,
        somebody signing in, a grant being made. Those name subjects a member
        was never told about, so a member does not see them -- the same rule
        that keeps a member off another connection's orders. Rows *for* a
        connection they hold they do see, including who else was granted it,
        which is the accountability that makes a shared bank connection
        reviewable by the people sharing it.

        Every filter is an equality on an indexed column or a prefix on
        ``action``, because "what happened to this order" and "what did this
        person do" are the two questions the trail is actually asked, and
        answering either by fetching everything and discarding most of it stops
        working at the first busy connection.

        ``before_seq`` pages by the append sequence rather than by an offset:
        rows arrive while an operator reads, and an offset would show them a row
        twice and skip another. ``seq`` is monotonic, so paging by it is stable
        against concurrent writes.
        """
        statement = select(audit_log).order_by(audit_log.c.seq.desc())
        equals = {
            audit_log.c.connection_id: connection_id,
            audit_log.c.order_id: order_id,
            audit_log.c.job_id: job_id,
            audit_log.c.request_id: request_id,
            audit_log.c.idempotency_key: idempotency_key,
            audit_log.c.actor_id: actor_id,
            audit_log.c.action: action,
            audit_log.c.outcome: outcome,
        }
        for column, value in equals.items():
            if value:
                statement = statement.where(column == value)
        if connection_ids is not None:
            # `.in_()` alone would also drop the `NULL` rows, and it is written
            # out so that the exclusion is a decision on the page rather than a
            # property of SQL's three-valued logic that a later reader has to
            # rediscover.
            statement = statement.where(
                audit_log.c.connection_id.isnot(None),
                audit_log.c.connection_id.in_(list(connection_ids)))
        if action_prefix:
            statement = statement.where(
                audit_log.c.action.like(f"{action_prefix}%"))
        if since is not None:
            statement = statement.where(audit_log.c.occurred_at >= since)
        if until is not None:
            statement = statement.where(audit_log.c.occurred_at <= until)
        if before_seq is not None:
            statement = statement.where(audit_log.c.seq < before_seq)
        with self._engine.connect() as connection:
            return [dict(row) for row in
                    connection.execute(statement.limit(limit)).mappings()]

    def actions(self, connection_ids: Sequence[str] | None = None
                ) -> list[str]:
        """The action names this deployment has actually written.

        Read out of the table rather than out of a list in the code: a filter
        offering an action nothing ever wrote is a filter that returns nothing
        and teaches an operator to distrust the page, and a list in the code is
        one more thing to forget to extend.

        Narrowed by ``connection_ids`` for the same reason :meth:`search` is: a
        dropdown built from every row is a dropdown that tells a member which
        actions happened on banks they cannot see.
        """
        return self._distinct(audit_log.c.action,
                              connection_ids=connection_ids)

    def actors(self, limit: int = 200,
               connection_ids: Sequence[str] | None = None) -> list[str]:
        """Who appears in the trail. Same reasoning as :meth:`actions`.

        This one matters more than the action list: an unfiltered version hands
        a member the subject of every colleague who ever used the deployment,
        off a page that shows them none of those colleagues' rows.
        """
        return self._distinct(audit_log.c.actor_id, limit=limit,
                              connection_ids=connection_ids)

    def _distinct(self, column: Any, limit: int | None = None,
                  connection_ids: Sequence[str] | None = None) -> list[str]:
        statement = select(column).distinct().order_by(column)
        if connection_ids is not None:
            statement = statement.where(
                audit_log.c.connection_id.isnot(None),
                audit_log.c.connection_id.in_(list(connection_ids)))
        if limit is not None:
            statement = statement.limit(limit)
        with self._engine.connect() as connection:
            return [value for (value,) in connection.execute(statement)
                    if value]


__all__ = ["Actor", "AuditEvent", "AuditLog", "FAILURE", "SUCCESS", "SYSTEM",
           "SYSTEM_ACTOR"]
