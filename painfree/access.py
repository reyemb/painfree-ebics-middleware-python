"""Who was granted which connection, and the one check that enforces it.

:mod:`painfree.identity` is the model -- what a level carries, what an admin is.
This module is the two things that model needs to be true of a running service:
the **store** the grants live in, and the **guard** every route that names a
connection calls.

**One guard, one rule.** :func:`require` is the only function that decides
whether a caller may touch a connection, and every surface calls it: `/v1`, the
console, and the object-level checks that run after a row is loaded. Two
implementations of "may this person see this bank" would eventually be two
answers, and the one that is wrong is the one nobody re-reads.

**A connection a caller holds no grant on does not exist.** :func:`require`
raises `404` in that case and `403` only when the caller holds the connection
and not the privilege. The distinction is deliberate and is the difference
between two refusals that say different things:

- `403 missing_scopes: ["payments:submit"]` tells a `viewer` on their own bank
  exactly what to ask for, which is the refusal an operator has to be able to
  act on.
- `404` tells a caller nothing about a connection they were never given --
  including whether it exists, which order ids are real, and how many banks
  this deployment talks to. An id in a URL is a guess until the service
  confirms it.

**There is a second kind of grant, and it names no connection.** An *oversight*
grant is deployment-wide and read-only: :func:`visible` says yes to every
connection for its holder, including to ``None``, and the scope check that
follows is what refuses every write. That ordering is the whole of it --
oversight widens what may be *seen* and nothing else, because
:data:`painfree.identity.OVERSIGHT_SCOPES` contains no scope that does
anything.

**The filter and the guard are the same fact, applied twice.** A list endpoint
narrows its query with :meth:`Principal.visible_connections`; a detail endpoint
loads the row and calls :func:`require` with the connection the row names. The
second is not a fallback for the first -- an object-level check is the only
thing that stops a member reaching another connection's order by *guessing its
id* on a route they legitimately hold, because the route-level scope check has
already passed by then.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from sqlalchemy import Engine, delete, func, insert, select, update

from painfree.audit import Actor, AuditLog
from painfree.errors import ConflictError, ForbiddenError, NotFoundError
from painfree.identity import (OVERSIGHT_SCOPES, Level, Principal,
                               Scope)
from painfree.logging import get_logger
from painfree.schema import (bank_connection, connection_grant,
                            oversight_grant, user_session)

log = get_logger("painfree.access")

#: How many known subjects the users page lists. A deployment with more people
#: than this needs a search box, which is a page problem rather than a model
#: one; the cap is here so the query cannot become the slow one on the console.
SUBJECT_PAGE = 500


@dataclass(frozen=True, slots=True)
class Grant:
    """One subject's access to one connection."""

    grant_id: str
    subject: str
    connection_id: str
    level: Level
    granted_by: str
    created_at: _dt.datetime
    updated_at: _dt.datetime

    def scopes(self) -> list[str]:
        """What this grant carries, read out of the model rather than restated."""
        from painfree.identity import LEVEL_SCOPES

        return sorted(scope.value for scope in LEVEL_SCOPES[self.level])

    def as_response(self) -> dict[str, Any]:
        return {"grant_id": self.grant_id, "subject": self.subject,
                "connection_id": self.connection_id, "level": self.level.value,
                "granted_by": self.granted_by,
                "scopes": self.scopes(),
                "created_at": self.created_at.isoformat(),
                "updated_at": self.updated_at.isoformat()}


@dataclass(frozen=True, slots=True)
class OversightGrant:
    """One subject's deployment-wide read-only reach.

    No connection and no level, because it has neither: see
    :data:`painfree.schema.oversight_grant` for why those columns are absent
    rather than nullable.
    """

    grant_id: str
    subject: str
    granted_by: str
    created_at: _dt.datetime

    def scopes(self) -> list[str]:
        """What it carries, read out of the model rather than restated here."""
        return sorted(scope.value for scope in OVERSIGHT_SCOPES)

    def as_response(self) -> dict[str, Any]:
        return {"grant_id": self.grant_id, "subject": self.subject,
                "granted_by": self.granted_by, "scopes": self.scopes(),
                "created_at": self.created_at.isoformat()}


@dataclass(frozen=True, slots=True)
class Reach:
    """Everything this deployment holds about what one subject may touch.

    Both halves in one value because both are read on **every** request and a
    caller that fetched one and forgot the other would be a caller with half an
    answer -- which, for the half that is oversight, is a reviewer whose access
    silently stopped working.
    """

    grants: tuple[tuple[str, Level], ...] = ()
    oversight: bool = False


@dataclass(frozen=True, slots=True)
class KnownSubject:
    """Somebody this deployment has seen or granted something to.

    Deliberately not a user record. There is no user table: a subject is known
    because it signed in or because it holds a grant, and both of those are
    facts this service already had. Inventing a third would be a second
    identity store to keep in step with the provider.
    """

    subject: str
    display_name: str | None
    last_seen_at: _dt.datetime | None
    grants: tuple[Grant, ...]
    #: Holds deployment-wide read-only oversight. On the same row as the grants
    #: because "who can see everything" is the question an administrator is
    #: answering when they read this list, and a second page to cross-reference
    #: is a page nobody reads.
    oversight: bool = False

    def as_response(self) -> dict[str, Any]:
        return {"subject": self.subject, "display_name": self.display_name,
                "last_seen_at": (self.last_seen_at.isoformat()
                                 if self.last_seen_at else None),
                "oversight": self.oversight,
                "grants": [grant.as_response() for grant in self.grants]}


class Grants:
    """The grant table, read on every request and written only by an admin."""

    def __init__(self, engine: Engine, audit: AuditLog | None = None) -> None:
        self._engine = engine
        self._audit = audit

    # --- reading ------------------------------------------------------------

    def reach_for(self, subject: str) -> Reach:
        """Everything this subject holds, read on one connection.

        The one call :mod:`painfree.authn` makes per request, and the only way
        to ask this question -- there is deliberately no method that returns the
        per-connection grants alone, because a caller that used it and forgot
        oversight would build a reviewer whose access had silently stopped
        working. Two indexed selects on one round trip.

        Per request rather than per session on purpose: a grant copied into a
        session row would keep working until the person next signed in, which is
        not what anybody means by revoking access to a bank account.
        """
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(connection_grant.c.connection_id,
                       connection_grant.c.level)
                .where(connection_grant.c.subject == subject)
                .order_by(connection_grant.c.connection_id)).all()
            watching = connection.execute(
                select(oversight_grant.c.grant_id)
                .where(oversight_grant.c.subject == subject)).one_or_none()
        return Reach(
            grants=tuple((connection_id, Level(level))
                         for connection_id, level in rows),
            oversight=watching is not None)

    def oversight_all(self) -> list[OversightGrant]:
        """Everyone holding deployment-wide read, oldest first."""
        with self._engine.connect() as connection:
            return [_from_oversight_row(row) for row in connection.execute(
                select(oversight_grant).order_by(oversight_grant.c.subject)
            ).mappings()]

    def oversight_get(self, subject: str) -> OversightGrant | None:
        with self._engine.connect() as connection:
            row = connection.execute(
                select(oversight_grant).where(
                    oversight_grant.c.subject == subject)).mappings(
                        ).one_or_none()
        return _from_oversight_row(row) if row else None

    def get(self, subject: str, connection_id: str) -> Grant | None:
        with self._engine.connect() as connection:
            row = connection.execute(
                select(connection_grant).where(
                    connection_grant.c.subject == subject,
                    connection_grant.c.connection_id == connection_id)
            ).mappings().one_or_none()
        return _from_row(row) if row else None

    def all(self, *, subject: str | None = None,
            connection_id: str | None = None) -> list[Grant]:
        query = select(connection_grant).order_by(
            connection_grant.c.subject, connection_grant.c.connection_id)
        if subject:
            query = query.where(connection_grant.c.subject == subject)
        if connection_id:
            query = query.where(
                connection_grant.c.connection_id == connection_id)
        with self._engine.connect() as connection:
            return [_from_row(row) for row
                    in connection.execute(query).mappings()]

    def subjects(self, limit: int = SUBJECT_PAGE) -> list[KnownSubject]:
        """Everyone this deployment knows about, with what they hold.

        The union of facts it already had: a subject that has signed in has a
        `user_session` row, and a subject that was granted something has a
        `connection_grant` or an `oversight_grant` row. A person who was granted
        access and has not yet signed in appears here with no display name,
        which is what an administrator needs to see -- otherwise granting to a
        new colleague looks like it did nothing.
        """
        held: dict[str, list[Grant]] = {}
        for grant in self.all():
            held.setdefault(grant.subject, []).append(grant)
        seen: dict[str, tuple[str | None, _dt.datetime | None]] = {}
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(user_session.c.subject,
                       func.max(user_session.c.last_seen_at).label("last"))
                .group_by(user_session.c.subject)
                .order_by(func.max(user_session.c.last_seen_at).desc())
                .limit(limit)).all()
            names = dict(connection.execute(
                select(user_session.c.subject, user_session.c.display_name)
                .where(user_session.c.display_name.isnot(None))).all())
        for subject, last in rows:
            seen[subject] = (names.get(subject), last)
        watching = {row.subject for row in self.oversight_all()}
        for subject in set(held) | watching:
            seen.setdefault(subject, (names.get(subject), None))
        return [KnownSubject(subject=subject, display_name=name,
                             last_seen_at=last,
                             grants=tuple(held.get(subject, ())),
                             oversight=subject in watching)
                for subject, (name, last) in sorted(seen.items())][:limit]

    # --- writing ------------------------------------------------------------

    def grant(self, subject: str, connection_id: str, level: Level, *,
              actor: Actor) -> Grant:
        """Give ``subject`` this level on this connection, or change the level.

        Granting the same pair twice is an update rather than a second row --
        the unique constraint says so -- and both write the same audit action
        with the level that is now in force. An administrator raising somebody
        from `viewer` to `operator` and one granting for the first time are the
        same decision seen twice, and a reader of the trail should not have to
        know which it was to see who can now move money.
        """
        subject = subject.strip()
        if not subject:
            raise ConflictError("a grant needs a subject")
        now = _dt.datetime.now(_dt.timezone.utc)
        with self._engine.begin() as connection:
            exists = connection.execute(
                select(bank_connection.c.connection_id).where(
                    bank_connection.c.connection_id == connection_id)
            ).one_or_none()
            if exists is None:
                raise NotFoundError(
                    f"no such bank connection: {connection_id!r}")
            existing = connection.execute(
                select(connection_grant).where(
                    connection_grant.c.subject == subject,
                    connection_grant.c.connection_id == connection_id)
            ).mappings().one_or_none()
            if existing is None:
                grant_id = f"grn_{uuid.uuid4().hex[:24]}"
                connection.execute(insert(connection_grant).values(
                    grant_id=grant_id, subject=subject,
                    connection_id=connection_id, level=level.value,
                    granted_by=actor.id, created_at=now, updated_at=now))
                previous = None
            else:
                grant_id = existing["grant_id"]
                previous = existing["level"]
                connection.execute(update(connection_grant).where(
                    connection_grant.c.grant_id == grant_id).values(
                        level=level.value, granted_by=actor.id, updated_at=now))
        # `grant_level`, not `level`: the structured logger takes `level` as
        # the severity, and an audit detail goes through the same redaction and
        # the same field names as a log line. The same class of collision that
        # `state` was renamed out of, caught the same way -- by the call
        # failing.
        self._record("access.granted", actor, subject, connection_id,
                     grant_level=level.value, previous_level=previous)
        log.info("access.granted", subject=subject,
                 connection_id=connection_id, grant_level=level.value,
                 previous_level=previous, granted_by=actor.id)
        granted = self.get(subject, connection_id)
        assert granted is not None  # written in the transaction above
        return granted

    def revoke(self, subject: str, connection_id: str, *,
               actor: Actor) -> bool:
        """Take the grant away. ``False`` if there was none to take.

        It takes effect on the next request, not the next sign-in: the grants a
        `Principal` carries are read per request, so the session the revoked
        person is holding stops working without anybody restarting anything.
        """
        with self._engine.begin() as connection:
            existing = connection.execute(
                select(connection_grant.c.level).where(
                    connection_grant.c.subject == subject,
                    connection_grant.c.connection_id == connection_id)
            ).one_or_none()
            if existing is None:
                return False
            connection.execute(delete(connection_grant).where(
                connection_grant.c.subject == subject,
                connection_grant.c.connection_id == connection_id))
        self._record("access.revoked", actor, subject, connection_id,
                     grant_level=existing[0])
        log.info("access.revoked", subject=subject,
                 connection_id=connection_id, grant_level=existing[0],
                 revoked_by=actor.id)
        return True

    def grant_oversight(self, subject: str, *,
                        actor: Actor) -> OversightGrant:
        """Give ``subject`` deployment-wide read. Issuing twice is one row.

        Idempotent by subject, like a per-connection grant is idempotent by the
        pair: there is nothing to change -- oversight is held or it is not --
        so a second issue is the same decision and returns the same row rather
        than a `409` an administrator has to interpret.
        """
        subject = subject.strip()
        if not subject:
            raise ConflictError("a grant needs a subject")
        existing = self.oversight_get(subject)
        if existing is not None:
            return existing
        now = _dt.datetime.now(_dt.timezone.utc)
        with self._engine.begin() as connection:
            connection.execute(insert(oversight_grant).values(
                grant_id=f"ovs_{uuid.uuid4().hex[:24]}", subject=subject,
                granted_by=actor.id, created_at=now))
        # `connection_id=None`, which is the row itself saying what the grant
        # is: a decision about the whole deployment. A member reading the trail
        # of a bank they hold is not shown it, for the same reason they are not
        # shown a sign-in.
        self._record_deployment(
            "access.oversight_granted", actor, subject,
            scopes=sorted(scope.value for scope in OVERSIGHT_SCOPES))
        log.info("access.oversight_granted", subject=subject,
                 granted_by=actor.id)
        issued = self.oversight_get(subject)
        assert issued is not None  # written in the transaction above
        return issued

    def revoke_oversight(self, subject: str, *, actor: Actor) -> bool:
        """Take it away. ``False`` if there was none to take.

        Effective on the reviewer's next request, not their next sign-in: the
        oversight flag is read out of this table on every one of them, in the
        same round trip as the per-connection grants (:meth:`reach_for`).
        """
        with self._engine.begin() as connection:
            existing = connection.execute(
                select(oversight_grant.c.grant_id).where(
                    oversight_grant.c.subject == subject)).one_or_none()
            if existing is None:
                return False
            connection.execute(delete(oversight_grant).where(
                oversight_grant.c.subject == subject))
        self._record_deployment("access.oversight_revoked", actor, subject)
        log.info("access.oversight_revoked", subject=subject,
                 revoked_by=actor.id)
        return True

    def _record_deployment(self, action: str, actor: Actor, subject: str,
                           **detail: Any) -> None:
        """An audit row for a decision that names no connection.

        The same shape as :meth:`_record` and deliberately a different method:
        passing ``connection_id=None`` into the per-connection one would have
        worked and would have made "this grant is about the deployment" a
        parameter value rather than a call site anybody can grep for.
        """
        if self._audit is None:  # pragma: no cover - the app always wires one
            return
        self._audit.record(action, actor=actor, connection_id=None,
                           detail={"subject": subject, **detail})

    def _record(self, action: str, actor: Actor, subject: str,
                connection_id: str, **detail: Any) -> None:
        """One audit row per decision about who may touch a bank connection.

        ``subject`` is in the detail rather than in ``actor_id``: the actor is
        the administrator who decided, and the trail's question is *who did
        this*, not *who it was done to*.
        """
        if self._audit is None:  # pragma: no cover - the app always wires one
            return
        self._audit.record(action, actor=actor, connection_id=connection_id,
                           detail={"subject": subject, **detail})


def _from_oversight_row(row: Any) -> OversightGrant:
    return OversightGrant(grant_id=row["grant_id"], subject=row["subject"],
                          granted_by=row["granted_by"],
                          created_at=row["created_at"])


def _from_row(row: Any) -> Grant:
    return Grant(grant_id=row["grant_id"], subject=row["subject"],
                 connection_id=row["connection_id"],
                 level=Level(row["level"]), granted_by=row["granted_by"],
                 created_at=row["created_at"], updated_at=row["updated_at"])


# --- the guard --------------------------------------------------------------

def visible(principal: Principal, connection_id: str | None) -> bool:
    """May this caller be told that this connection exists?

    ``None`` is the thing that belongs to no connection -- a deployment-wide
    audit row, a webhook subscription that receives every connection's events.
    An `admin` sees those, and so does an oversight holder, whose whole purpose
    is reviewing them.

    Being visible is not being actionable: what follows this in :func:`require`
    is the scope check, and no scope an oversight grant carries does anything.
    """
    if principal.admin or principal.oversight:
        return True
    if connection_id is None:
        return False
    return principal.level_on(connection_id) is not None


def require(principal: Principal, connection_id: str | None,
            *scopes: Scope, what: str = "resource") -> None:
    """The check. `404` if the connection is not theirs, `403` if the level is.

    ``what`` names the thing in the `404`, so a caller who mistyped their own
    connection id reads *no such order* rather than a sentence about access
    control -- the two are indistinguishable to them by design, and the message
    should not hint at which it was.
    """
    if not visible(principal, connection_id):
        log.warning("access.refused", subject=principal.subject,
                    connection_id=connection_id, kind=what,
                    reason="the caller holds no grant on this connection",
                    scopes=sorted(scope.value for scope in scopes))
        raise NotFoundError(f"no such {what}")
    missing = [scope for scope in scopes
               if not principal.may(scope, connection_id)]
    if missing:
        names = sorted(scope.value for scope in missing)
        log.warning("access.forbidden", subject=principal.subject,
                    connection_id=connection_id, kind=what, missing=names)
        raise ForbiddenError(
            "the caller does not hold the privilege this needs on this "
            "connection",
            detail={"missing_scopes": names, "connection_id": connection_id,
                    "held_scopes": sorted(
                        scope.value for scope
                        in principal.scopes_on(connection_id or ""))})


def restrict(principal: Principal,
             requested: str | None = None) -> tuple[Sequence[str] | None, bool]:
    """What a list query should be narrowed to, and whether it can return rows.

    Returns ``(connection_ids, possible)``. ``connection_ids`` of ``None``
    means *do not filter* and is only ever the answer for an `admin`;
    ``possible`` is ``False`` when the caller asked for a connection they do
    not hold, which is an empty list rather than a `403` -- a filter naming
    somebody else's bank should answer the same way as a filter naming a bank
    that does not exist.
    """
    allowed = principal.visible_connections()
    if requested:
        if allowed is not None and requested not in allowed:
            return (), False
        return [requested], True
    if allowed is None:
        return None, True
    return list(allowed), bool(allowed)


def held(principal: Principal, connections: Iterable[Any]) -> list[Any]:
    """Filter already-loaded connection rows to the ones this caller holds.

    For the two places a query cannot be narrowed usefully -- a form's dropdown
    and a filter's option list -- where the rows are few and already in hand.
    """
    allowed = principal.visible_connections()
    if allowed is None:
        return list(connections)
    return [row for row in connections if row.connection_id in allowed]


__all__ = ["Grant", "Grants", "KnownSubject", "OversightGrant", "Reach",
           "SUBJECT_PAGE", "held", "require", "restrict", "visible"]
