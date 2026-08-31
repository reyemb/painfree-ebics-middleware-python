"""Who a caller is, and what that lets them do.

This module is the authorisation model and nothing else: no HTTP, no tokens, no
provider. It answers one question -- given a set of claims a trusted issuer put
its signature on, and the grants this deployment holds for that subject, which
operations may this caller perform on which bank connection -- and it answers it
the same way for a browser session and for a machine bearer token, because two
answers would eventually be two different answers.

**Privileges are scopes, and scopes are named after operations.** Not after
tables and not after routes: ``payments:submit`` is a privilege because moving
money is a thing one is allowed or not allowed to do, and ``payments:read`` is a
*different* privilege because knowing what was paid is a different thing. A
model that collapses them is a model in which read access to an order history
is write access to the account.

**Identity comes from the provider; access comes from here.** There are two
roles. ``admin`` does everything everywhere and is the only role that may grant
access; ``member`` may sign in and holds *nothing* until an administrator grants
it a connection. A member with no grants has a working login and an empty
console, and that is the intended state rather than a fault. The provider's
roles claim decides only which of the two a caller is. Everything else is a
**grant**: a row in this deployment's own database naming a subject, a
connection, and a level.

**A grant is levelled, and it applies to one connection.** ``viewer`` carries
the read scopes on that connection; ``operator`` adds submitting a payment,
replaying one, and managing that connection's download schedule. Keeping those
separable is the point of levelling them at all -- "can see this bank" and "can
move money at this bank" are not one permission, for the same reason
``payments:read`` and ``payments:submit`` are not one scope.

**One grant names no connection at all, and it is read-only.** An *oversight*
grant carries every read scope on every connection, and the audit rows that name
none -- the sign-ins, the service starts, the grants. It carries **no write
scope**, and the definition is mechanical rather than a list somebody maintains:
:data:`OVERSIGHT_SCOPES` is every scope whose name ends in ``:read``, so a
privilege that does anything falls outside it by construction. It is not a
third role: it is a row in this deployment's database, issued and revoked by an
`admin`, exactly like a per-connection grant, and it carries no grant
management -- which is why grant management is not a scope.

**Two scopes are held by no level, only by ``admin``.** ``connections:write``
is the key lifecycle, which is the authority to register this deployment's keys
with a bank; ``webhooks:manage`` decides that a URL outside the deployment
receives payment events. Neither is an operation on a connection so much as a
decision about what the deployment *is*, so no grant carries them and no member
can reach them -- which is why a member cannot create the connection-less
webhook subscription that would receive every connection's events. That path is
closed by there being no rule to get wrong, rather than by a check that could
be forgotten.

**Roles grant, scopes narrow.** A role is what the identity provider *granted*;
the ``scope`` claim is what the client *asked for*. Those are not the same fact
and this service never confuses them: the effective privilege is what the role
and the grants allow, intersected with the requested scopes when the token
carries any. That direction is deliberate -- a `scope` claim is under the
influence of whoever requested the token, and a service that reads privilege out
of it is a service whose authorisation model lives in its clients. Narrowing can
only ever take privilege away, and it narrows the per-connection sets too.

**An unknown role name grants no administration, never guessed at.** A provider
that starts sending ``payments-admin`` makes nobody an administrator here until
someone maps it. The holder is an ordinary member, which is to say they hold
whatever they were granted and nothing more. The alternative -- a default
administrator, or a substring match on the claim -- is how a directory group
created for something else becomes the ability to move money.
"""

from __future__ import annotations

import datetime as _dt
import enum
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from painfree.audit import Actor


class Scope(str, enum.Enum):
    """One privilege. The unit an endpoint is protected with."""

    connections_read = "connections:read"
    """List bank connections and their key state."""

    connections_write = "connections:write"
    """Register a connection and drive its initialisation, including every key
    job: `INI`, `HIA`, `HPB`, renewal and suspension.

    **No grant level carries it.** A grant says what a person may do with a bank
    connection; this scope is the authority to decide that this deployment *has*
    one, and to register the keys that authorise money movement against it.
    Widening the set of people who can do that is a decision about the
    deployment, not about a connection, so it stays with `admin`.
    """

    payments_read = "payments:read"
    """Read an order back: its state, the bank's return code, its report text."""

    payments_submit = "payments:submit"
    """Submit a payment instruction. The one that moves money."""

    statements_read = "statements:read"
    """Read normalised `camt` documents. Reserved for the statements endpoint."""

    orders_replay = "orders:replay"
    """Re-enqueue a failed order. Reserved for the replay endpoint.

    Carried by the `operator` level for the same reason `payments:submit` is:
    a replay re-sends a document this caller could have submitted in the first
    place, under the same `MsgId` the bank deduplicates on. Handing it to
    `viewer` would make "can see this bank" into "can cause a bank exchange".
    """

    audit_read = "audit:read"
    """Read the audit log -- who did what, and to which connection.

    Carried by both grant levels and **scoped to the connections the caller
    holds**. A member reading another connection's trail would be reading who
    paid whom at a bank they were never given; a member who cannot read their
    own connection's history has a page that answers nothing. Rows that name no
    connection -- the service starting, a sign-in, a grant being made -- span
    the whole deployment and are reached by an `admin` and by an **oversight**
    grant, which is read-only across the whole deployment.
    """

    webhooks_read = "webhooks:read"
    """See which endpoints receive this service's events, and their health.

    Split from `connections:read` rather than folded into it: the list of
    webhook endpoints is the list of *external systems this service pushes
    payment events to*, and being allowed to look at a bank connection is not
    by itself being told where the money news goes. So the `operator` level
    carries it and `viewer` does not. A member sees only the subscriptions
    scoped to a connection they hold -- never a connection-less one, which by
    definition belongs to the whole deployment, unless they hold **oversight**:
    reviewing where this deployment's payment events are forwarded is exactly
    what read-only oversight is for.
    """

    webhooks_manage = "webhooks:manage"
    """Register, edit, pause, rotate, test and delete a webhook subscription.

    Deliberately not implied by `payments:submit`. Submitting a payment moves
    money this service already has a mandate for; registering a webhook decides
    that a third party receives every subsequent payment event -- an order id,
    an idempotency key, a bank status -- at a URL of the registrant's choosing.
    That is an administrative decision about data leaving the deployment, not a
    payments operation, so it was `administrator` alone and it is now `admin`
    alone: **no grant level carries it.** A subscription may name no
    connection, in which case it receives every connection's payment events;
    handing this scope to a member holding one connection would put that
    subscription one field away from them.
    """

    schedules_read = "schedules:read"
    """See which bank services this deployment polls, how far each window got,
    and how the last run ended.

    Carried by both grant levels including `viewer`, unlike `webhooks:read`.
    The asymmetry is deliberate: a webhook endpoint is an *external* system
    this service pushes payment events to, while a download schedule is
    configuration of a connection the holder can already see, producing
    statements they can already read.
    """

    schedules_manage = "schedules:manage"
    """Create, edit, pause, delete, run now, and re-fetch a window.

    Carried by the `operator` level, which is where this parts company with
    `webhooks:manage`. A schedule creates no new recipient and moves no money:
    it pulls data in, under a mandate the connection already has. Re-fetching a
    window the bank never answered for is exactly what the operator who was
    paged about a missing statement has to do, and a privilege the person on
    call cannot hold is a privilege that gets shared.
    """


class Role(str, enum.Enum):
    """What a provider's claim makes a caller. Two names, and only two.

    ``admin`` is everything, everywhere, and is the only role that may grant
    access. ``member`` is everyone else who can sign in: a working login, and
    nothing visible until an administrator grants a connection.

    There is no third name, and adding one would be a decision rather than a
    convenience. The four-role model this replaces put the whole deployment
    behind one word in a token; the difference in reach between two people who
    both need to look at a bank is now which banks they were granted, which is
    data this deployment owns and can revoke.

    Deployment-wide read-only oversight is **not** the third name it would have
    been under the old model: it is a grant, for the same reason and by the same
    argument. An oversight holder's role here is `member`.
    """

    admin = "admin"
    member = "member"


#: Claim values that make a caller an administrator. ``administrator`` is the
#: name the first role model used and is still accepted: the identity provider
#: is not migrated by a database migration, so a deployment whose directory
#: still sends the old word must not lose its administrators on upgrade.
ADMIN_ROLE_NAMES = frozenset({"admin", "administrator"})

#: Claim values the four-role model used that are **not** administration.
#: Recognised so they are not logged as unmapped noise on every request; they
#: make the holder a member, which is to say they decide nothing on their own.
#:
#: **``auditor`` is in this set and stays in it.** The oversight grant gives
#: the reach that word used to mean a home again, and mapping the claim onto it
#: would be the obvious next line -- and would hand deployment-wide read of
#: every bank's payment history to anybody whose directory still sends the old
#: word, on the morning of an upgrade, without a decision being taken. An
#: oversight grant is issued per person by an administrator, or it is not
#: issued.
LEGACY_MEMBER_ROLE_NAMES = frozenset({"member", "operator", "viewer", "auditor"})

#: Every role name this deployment understands. Anything else is logged.
KNOWN_ROLE_NAMES = ADMIN_ROLE_NAMES | LEGACY_MEMBER_ROLE_NAMES


class Level(str, enum.Enum):
    """How much a grant carries, on the one connection it names.

    Two levels, and the split between them is the whole reason a grant is
    levelled rather than a boolean: *may see this bank* and *may move money at
    this bank* are separate answers, and a model that collapses them is a model
    where read access to an account is payment access to it.

    **Oversight is not a third level here, deliberately.** A level is something
    a grant names a connection with, so an `oversight` member of this enum would
    be grantable *on one bank* -- a shape that means nothing -- and would appear
    in every level dropdown the console draws. Deployment-wide read is a grant
    of its own kind, with no connection column to fill in.
    """

    viewer = "viewer"
    operator = "operator"


_VIEWER = frozenset({Scope.connections_read, Scope.payments_read,
                     Scope.statements_read, Scope.schedules_read,
                     Scope.audit_read})

#: What each level carries **on the connection its grant names**, and nothing
#: anywhere else. One table, so "who may move money at this bank" is something
#: to read rather than to search for.
#:
#: `connections:write` and `webhooks:manage` appear in neither row. That is the
#: `admin`-only set, and it is an absence rather than a rule: a member cannot
#: create the connection-less webhook subscription that would receive every
#: connection's payment events, because a member cannot create a subscription
#: at all.
LEVEL_SCOPES: Mapping[Level, frozenset[Scope]] = {
    Level.viewer: _VIEWER,
    # `webhooks:read` and `schedules:manage` are on this level because the
    # person who is paged when an endpoint parks or a statement does not arrive
    # is the operator on that connection. Neither creates a recipient outside
    # the deployment.
    Level.operator: _VIEWER | {Scope.payments_submit, Scope.orders_replay,
                               Scope.webhooks_read, Scope.schedules_manage},
}

#: What `admin` holds, everywhere. Every scope there is, by construction: a
#: scope defined and granted to nobody is a route nobody can reach.
ADMIN_SCOPES: frozenset[Scope] = frozenset(Scope)

#: What an **oversight** grant carries, on every connection and on the rows that
#: name none. Derived from the names rather than listed, and that is the whole
#: safety property: a scope belongs to this set **iff** it is called ``:read``.
#:
#: The alternative -- a hand-kept tuple of the six read scopes -- is a tuple
#: somebody extends by one line while adding a privilege, at which point a
#: read-only reviewer can move money. Here a new privilege has to be *named*
#: ``something:read`` to be included, and every write scope this model has is
#: named for what it does: `:write`, `:submit`, `:replay`, `:manage`. The naming
#: convention was already load-bearing (see the module docstring); this makes it
#: enforceable, and `tests/test_service_oversight.py` pins the resulting set
#: against every write scope by name so the derivation cannot drift quietly.
OVERSIGHT_SCOPES: frozenset[Scope] = frozenset(
    scope for scope in Scope if scope.value.endswith(":read"))

#: Everything an oversight grant does **not** carry. Named so the negative is a
#: value a test can enumerate rather than a sentence in a docstring.
WRITE_SCOPES: frozenset[Scope] = frozenset(Scope) - OVERSIGHT_SCOPES

#: Kept because the developer page and the API contract are generated from it.
#: Global scopes per role: an `admin` holds all of them everywhere, and a
#: `member` holds none of them globally -- what a member holds is per
#: connection and is in :data:`LEVEL_SCOPES`.
ROLE_SCOPES: Mapping[Role, frozenset[Scope]] = {
    Role.admin: ADMIN_SCOPES,
    Role.member: frozenset(),
}


def role_for(roles: Iterable[str]) -> Role:
    """Which of the two roles these claim values make a caller.

    Any recognised administrator name wins; everything else, including a claim
    this deployment has no mapping for and an absent claim entirely, is a
    member. That is not a default privilege -- a member holds nothing until it
    is granted a connection -- so the failure mode of an unmapped role is an
    empty console rather than an unearned one.
    """
    return Role.admin if any(name in ADMIN_ROLE_NAMES
                             for name in roles) else Role.member


#: How a caller proved who they are. Recorded on every audit row, because
#: "the operator submitted it in the browser" and "a machine client submitted it
#: with a bearer token" are different facts about the same payment.
BEARER = "bearer"
SESSION = "session"
DEVELOPMENT = "development"
#: An HTTP Basic credential checked against this deployment's own accounts. A
#: separate name from `session` because it is a separate fact: the credential
#: arrived on *this* request rather than having been exchanged for a session
#: once. What it grants is identical -- the role and the grants decide, and
#: this constant reaches no further than the audit column.
BASIC = "basic"

#: The `actor_type` each method writes into the audit log. `basic` writes
#: `user`: the caller is a person or a machine holding a password this
#: deployment issued, and telling that apart from a browser session on the trail
#: is what the `method` on the principal is for.
ACTOR_TYPES = {BEARER: "client", SESSION: "user", DEVELOPMENT: "developer",
               BASIC: "user"}

#: The `issuer` of an identity this deployment vouched for itself. It is not a
#: URL and is not meant to look like one: no provider was consulted, and a value
#: shaped like an issuer URL would invite somebody to compare it with one.
LOCAL_ISSUER = "painfree-local"


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated caller, and what it may do to which connection.

    Built once per request, by :mod:`painfree.authn`, from claims that have
    already been verified and grants read out of the database *on that request*.
    Nothing downstream re-derives privilege -- if :meth:`may` says no, the caller
    does not have it.

    **Grants are read per request and never copied into the session.** A session
    row would make a revocation take effect whenever the person next signed in,
    which is not what anybody means by revoking access to a bank account. The
    cost is one indexed lookup per request; the property bought is that
    :meth:`may` answers with the state of the database now.
    """

    subject: str
    issuer: str
    method: str
    #: What this caller holds *somewhere*: every scope any of its grants
    #: carries, or every scope there is when it is an `admin`. This is what a
    #: route-level check asks about -- "may this caller list orders at all" --
    #: and it is never the whole answer for a route that names a connection.
    scopes: frozenset[Scope]
    roles: tuple[str, ...] = ()
    #: The provider said this caller administers the deployment.
    admin: bool = False
    #: One entry per connection this caller was granted, with its level.
    #: Empty for an admin, whose reach is not expressed as grants, and empty
    #: for a member nobody has granted anything -- which is a working login
    #: with an empty console rather than a fault.
    grants: tuple[tuple[str, Level], ...] = ()
    #: This caller holds a deployment-wide **oversight** grant: every read
    #: scope, on every connection and on the rows that name none, and nothing
    #: else. Not a role -- the role is still `member` -- and not a level,
    #: because it names no connection to be a level *of*. Reset to ``False``
    #: for an `admin`, whose reach is not expressed as grants either.
    oversight: bool = False
    token_id: str | None = None
    expires_at: _dt.datetime | None = None
    display_name: str | None = None

    def has(self, scope: Scope) -> bool:
        """Does this caller hold ``scope`` anywhere at all?

        The route-level question. A member with `payments:submit` on one
        connection answers ``True`` here and must still be asked :meth:`may`
        before a payment is accepted for a *particular* connection.
        """
        return scope in self.scopes

    def may(self, scope: Scope, connection_id: str | None) -> bool:
        """Does this caller hold ``scope`` **on this connection**?

        The only question that decides anything about a connection's data.
        ``connection_id`` of ``None`` means the thing being asked about belongs
        to no connection -- a deployment-wide audit row, a webhook subscription
        that receives every connection's events. An `admin` reaches those, and
        so does an oversight holder for a **read** scope and for no other.
        """
        if self.admin:
            return scope in self.scopes
        if self.oversight and scope in OVERSIGHT_SCOPES:
            # Deployment-wide, ``connection_id`` of ``None`` included: the rows
            # that name no connection are precisely what oversight exists to
            # review. ``self.scopes`` is the already-narrowed set, so a token
            # that asked for less still gets less.
            return scope in self.scopes
        if connection_id is None:
            return False
        return scope in self.scopes_on(connection_id)

    def level_on(self, connection_id: str) -> Level | None:
        """The level this caller was granted on one connection, if any."""
        for granted, level in self.grants:
            if granted == connection_id:
                return level
        return None

    def scopes_on(self, connection_id: str) -> frozenset[Scope]:
        """Everything this caller may do to one connection.

        An `admin` holds the whole model on every connection; a member holds
        what its grant's level carries, narrowed by the token's `scope` claim
        exactly as the global set is -- narrowing takes privilege away and must
        not be escapable by naming a connection.

        An oversight grant adds the read scopes on **every** connection, and
        the union is a union rather than a replacement: somebody who reviews the
        whole deployment and also operates one bank holds both, and neither
        answer should quietly swallow the other.
        """
        if self.admin:
            return self.scopes
        held: frozenset[Scope] = frozenset()
        if self.oversight:
            held |= OVERSIGHT_SCOPES & self.scopes
        level = self.level_on(connection_id)
        if level is not None:
            held |= frozenset(LEVEL_SCOPES[level]) & self.scopes
        return held

    def visible_connections(self) -> tuple[str, ...] | None:
        """Which connections this caller may be shown, or ``None`` for all.

        ``None`` means *do not filter* and is the answer for an `admin` and for
        an oversight holder; it is deliberately not "the empty restriction",
        because a list method that confused an unrestricted admin with a member
        holding nothing would show every bank to the person who was granted
        none. Unfiltered is not unprivileged: what an oversight holder may then
        *do* with each row is still decided scope by scope, and every write one
        is outside :data:`OVERSIGHT_SCOPES`.
        """
        if self.admin or self.oversight:
            return None
        return tuple(connection_id for connection_id, _ in self.grants)

    def actor(self) -> Actor:
        """The audit actor. ``subject`` is the provider's, verbatim."""
        return Actor(ACTOR_TYPES.get(self.method, self.method), self.subject)

    def as_response(self) -> dict[str, Any]:
        """What ``GET /auth/me`` returns. Never a token, never a session id."""
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "method": self.method,
            "roles": list(self.roles),
            "role": Role.admin.value if self.admin else Role.member.value,
            # Reported beside the role and not as one: a reader of this document
            # has to be able to tell "reviews the whole deployment" from "runs
            # it", and a third role name would have hidden the difference.
            "oversight": self.oversight,
            "scopes": sorted(scope.value for scope in self.scopes),
            "grants": [{"connection_id": connection_id, "level": level.value,
                        "scopes": sorted(s.value for s
                                         in self.scopes_on(connection_id))}
                       for connection_id, level in self.grants],
            "display_name": self.display_name,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


def build_principal(*, subject: str, issuer: str, method: str,
                    roles: Iterable[str],
                    grants: Iterable[tuple[str, Level]] = (),
                    oversight: bool = False,
                    requested: Iterable[str] | None = None,
                    token_id: str | None = None,
                    expires_at: _dt.datetime | None = None,
                    display_name: str | None = None) -> Principal:
    """The one place a :class:`Principal` is assembled.

    One function rather than three constructions in :mod:`painfree.authn`,
    because a bearer token, a browser session and the development header have
    to produce identical privilege for identical inputs -- three call sites are
    three chances for one of them to be a little more permissive.

    ``requested`` is the token's `scope` claim when it carries one. It
    intersects, never adds: see the module docstring for why that direction.
    Oversight is narrowed by it like everything else -- it is added before the
    intersection, so a token that asked for `payments:read` alone gets a
    reviewer who can read payments and not statements.
    """
    names = tuple(roles)
    role = role_for(names)
    held = sorted(set(grants), key=lambda pair: pair[0])
    if role is Role.admin:
        granted = ADMIN_SCOPES
        held = []
        # An admin already holds everything everywhere. Reporting an oversight
        # row for them as well would make `/auth/me` answer the same question
        # twice, and the second answer is the one that goes stale -- the same
        # reason `grants` is emptied here.
        oversight = False
    else:
        granted = frozenset().union(
            *(LEVEL_SCOPES[level] for _, level in held)) if held else frozenset()
        if oversight:
            granted |= OVERSIGHT_SCOPES
    if requested is not None:
        granted &= {Scope(name) for name in requested if name in _SCOPE_VALUES}
    return Principal(subject=subject, issuer=issuer, method=method,
                     scopes=frozenset(granted), roles=names,
                     admin=role is Role.admin, grants=tuple(held),
                     oversight=oversight,
                     token_id=token_id, expires_at=expires_at,
                     display_name=display_name)


def scopes_for(roles: Iterable[str]) -> frozenset[Scope]:
    """The **global** scopes these role names grant: everything, or nothing.

    An administrator name grants the whole model everywhere. Anything else
    grants nothing globally, which is not the same as nothing at all -- what a
    member holds comes from its grants, one connection at a time, and is in
    :meth:`Principal.scopes_on`.
    """
    return ROLE_SCOPES[role_for(roles)]


def unknown_roles(roles: Iterable[str]) -> tuple[str, ...]:
    """Role names this service has no mapping for. Logged, so a misconfigured
    provider is visible in the stream rather than as a mysterious empty console.

    An unmapped name is not an error and does not refuse the caller: they are a
    member, and a member with no grants sees nothing. The line in the log is
    what turns "the console is empty" into "the directory group is not the one
    this deployment calls admin".
    """
    return tuple(name for name in roles if name not in KNOWN_ROLE_NAMES)


def effective_scopes(roles: Iterable[str],
                     requested: Iterable[str] | None) -> frozenset[Scope]:
    """Granted globally, then narrowed. See the module docstring for the order."""
    granted = scopes_for(roles)
    if requested is None:
        return granted
    asked = {Scope(name) for name in requested if name in _SCOPE_VALUES}
    return frozenset(granted & asked)


_SCOPE_VALUES = {scope.value for scope in Scope}


def claim_at(claims: Mapping[str, Any], path: str) -> Any:
    """Read a claim by a dotted path, so ``realm_access.roles`` works.

    Providers do not agree on where they put roles: some use a top-level claim,
    Keycloak nests them under ``realm_access``. One dotted string in the
    configuration is cheaper than a mapping layer, and it fails to ``None``
    rather than raising -- a token without the claim is a token with no roles,
    which is a caller with no privileges.
    """
    current: Any = claims
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def string_list(value: Any) -> tuple[str, ...]:
    """Normalise a claim that may be a list, or a space- or comma-separated string.

    ``scope`` is space-separated by RFC 8693; ``roles`` is a JSON array almost
    everywhere and a comma-separated string in a few places. Accepting all three
    shapes here means no call site has to ask which provider it is talking to.
    """
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(part for part in value.replace(",", " ").split() if part)
    if isinstance(value, (list, tuple)):
        return tuple(str(part) for part in value if str(part))
    return ()


__all__ = ["ACTOR_TYPES", "ADMIN_ROLE_NAMES", "ADMIN_SCOPES", "BASIC", "BEARER",
           "DEVELOPMENT", "KNOWN_ROLE_NAMES", "LEGACY_MEMBER_ROLE_NAMES",
           "LOCAL_ISSUER",
           "LEVEL_SCOPES", "Level", "OVERSIGHT_SCOPES", "Principal",
           "ROLE_SCOPES", "Role", "SESSION", "Scope", "WRITE_SCOPES",
           "build_principal", "claim_at", "effective_scopes", "role_for",
           "scopes_for", "string_list", "unknown_roles"]
