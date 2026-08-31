"""The routes that decide who may use this deployment, and how they prove it.

Split out of :mod:`painfree.api` when that module reached the repository's
1 000-line cap, along the seam the access model already draws: the endpoints
below are not operations *on* a bank connection, they are decisions about the
deployment that owns them. Nothing about the grant and oversight routes changed
in the move.

Three surfaces, and they answer three different questions:

- **Who may touch which bank** -- `/v1/grants`, per connection and levelled.
- **Who may read the whole deployment** -- `/v1/oversight`, the grant that names
  no connection and carries no write scope.
- **Who may sign in at all** -- `/v1/accounts` and `/v1/lockouts`, which exist
  only because a deployment may have no identity provider to answer that
  question. They are managed in every mode, so a deployment can be prepared
  before it is switched over, and they authenticate nobody unless
  ``PAINFREE_AUTH_MODE`` is ``basic``.

**Every route here is `admin` alone, and not by a scope.** There is no
`grants:manage` and no `accounts:manage` in :class:`painfree.identity.Scope`,
deliberately: a scope is something a grant can carry, and a member holding that
grant could grant themselves the rest. :func:`_administrator` is a dependency of
its own, and the developer page reads the role off it the way it reads scopes
off ``requires(...)``.

The account routes never accept, return, log or echo a password. The request
bodies carry it as a :class:`~pydantic.SecretStr`, so a validation error, a
``repr`` and a traceback all render it as asterisks rather than as itself; the
responses are built from :class:`painfree.accounts.Account`, which has no field
that could hold one.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from painfree.access import Grants
from painfree.accounts import MINIMUM_PASSWORD_LENGTH, Accounts
from painfree.authn import principal_of
from painfree.errors import ForbiddenError, NotFoundError
from painfree.identity import Level, Principal, Role
from painfree.logging import get_logger

log = get_logger("painfree.access_api")

router = APIRouter(prefix="/v1")


# --- access grants ----------------------------------------------------------
#
# The routes that decide who may touch a bank connection, and therefore who may
# move money at one. Every one of them is `admin` alone: `Scope.connections_write`
# is the closest existing privilege and it is already the key lifecycle, so a
# grant route carrying it would be coherent -- and it would also mean that the
# ability to register a connection's keys is the ability to hand somebody else
# `payments:submit` on it. It is not the same decision, so the check is not a
# scope at all: :func:`_administrator` refuses anybody who is not an `admin`,
# which is what grant management is.

class GrantRequest(BaseModel):
    """Give one subject one level on one connection.

    ``extra="forbid"``, like every other write body here: a misspelled `level`
    silently defaulting would be somebody quietly given the wrong access to a
    bank account.
    """

    model_config = ConfigDict(extra="forbid")

    subject: Annotated[str, Field(min_length=1, max_length=255)]
    connection_id: Annotated[str, Field(min_length=1, max_length=64)]
    level: Level


class GrantChange(BaseModel):
    """Change an existing grant's level. The pair is in the path."""

    model_config = ConfigDict(extra="forbid")

    level: Level


def _administrator(request: Request) -> Principal:
    """Refuse anybody who is not an `admin`. The whole check, in one place."""
    principal = principal_of(request)
    if not principal.admin:
        log.warning("access.grant_refused", subject=principal.subject,
                    path=request.url.path, roles=list(principal.roles),
                    reason="granting access to a bank connection is admin only")
        raise ForbiddenError(
            "granting and revoking access is reserved to an administrator",
            detail={"required_role": Role.admin.value,
                    "role": Role.member.value})
    return principal


# Read by the developer page the same way `requires(...)` records its scopes.
# Without it the page reports these routes as reachable by any authenticated
# caller, which is false and is the exact failure that page exists to prevent
# -- it was reported that way once, in a browser, before this line.
_administrator.required_role = Role.admin.value  # type: ignore[attr-defined]


def _grants(request: Request) -> Grants:
    return request.app.state.grants


@router.get("/grants", tags=["access"], summary="Who may touch which connection")
def list_grants(request: Request, subject: str | None = None,
                connection_id: str | None = None,
                principal: Principal = Depends(_administrator),
                ) -> dict[str, Any]:
    """Every grant, optionally narrowed to one subject or one connection.

    The two questions an administrator actually asks -- *what can this person
    reach* and *who can reach this bank* -- are the two filters, because a flat
    list that has to be read twice to answer either is a list nobody audits.
    """
    return {"grants": [grant.as_response() for grant
                       in _grants(request).all(subject=subject,
                                               connection_id=connection_id)]}


@router.get("/grants/subjects", tags=["access"], summary="Known subjects")
def list_subjects(request: Request,
                  principal: Principal = Depends(_administrator),
                  ) -> dict[str, Any]:
    """Everyone this deployment has seen sign in or has granted something to.

    Not a user directory: there is no user table. A subject appears here
    because it has a session row or a grant row, which are facts this service
    already had rather than a second copy of the provider's.
    """
    return {"subjects": [row.as_response() for row
                         in _grants(request).subjects()]}


@router.put("/grants", status_code=201, tags=["access"],
            summary="Grant a subject access to one connection")
def create_grant(body: GrantRequest, request: Request,
                 principal: Principal = Depends(_administrator),
                 ) -> dict[str, Any]:
    """Grant, or change the level of an existing grant. Idempotent by identity.

    `PUT` rather than `POST` because the pair *(subject, connection)* is the
    identity and the constraint already says so: sending this twice leaves one
    grant at the level asked for, which is what an administrator meant both
    times. There is no `Idempotency-Key` for the same reason a schedule has
    none -- a retry cannot produce a second anything.
    """
    grant = _grants(request).grant(body.subject, body.connection_id,
                                   body.level, actor=principal.actor())
    return grant.as_response()


@router.patch("/grants/{subject}/{connection_id}", tags=["access"],
              summary="Change a grant's level")
def change_grant(subject: str, connection_id: str, body: GrantChange,
                 request: Request,
                 principal: Principal = Depends(_administrator),
                 ) -> dict[str, Any]:
    """Raise or lower one grant. `404` when there is none to change.

    Distinct from `PUT /v1/grants`, which would create one: an administrator
    who meant to *change* somebody's level and mistyped the subject should be
    told so rather than quietly given a new person with access to a bank.
    """
    store = _grants(request)
    if store.get(subject, connection_id) is None:
        raise NotFoundError(
            f"{subject!r} holds no grant on {connection_id!r}")
    return store.grant(subject, connection_id, body.level,
                       actor=principal.actor()).as_response()


@router.delete("/grants/{subject}/{connection_id}", tags=["access"],
               summary="Revoke a grant")
def revoke_grant(subject: str, connection_id: str, request: Request,
                 principal: Principal = Depends(_administrator),
                 ) -> dict[str, Any]:
    """Take the access away. It stops working on the caller's **next request**.

    Not the next sign-in: a `Principal` reads its grants from this table on
    every request, so the session the revoked person is holding open stops
    reaching the connection without anybody restarting a process.
    """
    if not _grants(request).revoke(subject, connection_id,
                                   actor=principal.actor()):
        raise NotFoundError(f"{subject!r} holds no grant on {connection_id!r}")
    return {"subject": subject, "connection_id": connection_id,
            "revoked": True}


# --- deployment-wide oversight ----------------------------------------------
#
# The same `admin`-alone check as the grant routes above, and for the same
# reason at one more remove: these routes hand out the ability to read every
# bank connection in the deployment, so a privilege that conferred them would be
# a privilege whose holder could widen their own reach. `_administrator` is
# therefore what guards them, exactly as it guards granting -- which is what
# makes the escalation this grant exists to avoid unreachable rather than
# checked for.

class OversightRequest(BaseModel):
    """Give one subject deployment-wide read. There is nothing else to say.

    No `level` and no `connection_id`: an oversight grant has neither, and a
    body that accepted either would be a body somebody could be surprised by.
    """

    model_config = ConfigDict(extra="forbid")

    subject: Annotated[str, Field(min_length=1, max_length=255)]


@router.get("/oversight", tags=["access"],
            summary="Who reviews the whole deployment")
def list_oversight(request: Request,
                   principal: Principal = Depends(_administrator),
                   ) -> dict[str, Any]:
    """Everyone holding read-only oversight, and what it carries.

    The `scopes` on each row are read out of the model rather than restated, so
    this answers *what can these people see* rather than *what were they given*
    -- one question, one source.
    """
    return {"oversight": [row.as_response() for row
                          in _grants(request).oversight_all()]}


@router.put("/oversight", status_code=201, tags=["access"],
            summary="Grant deployment-wide read-only oversight")
def create_oversight(body: OversightRequest, request: Request,
                     principal: Principal = Depends(_administrator),
                     ) -> dict[str, Any]:
    """Issue it. Idempotent by subject: it is held or it is not.

    `PUT` for the reason `PUT /v1/grants` is one -- the subject *is* the
    identity -- and with no `Idempotency-Key` for the reason that route has
    none: a retry cannot produce a second anything.
    """
    return _grants(request).grant_oversight(
        body.subject, actor=principal.actor()).as_response()


@router.delete("/oversight/{subject}", tags=["access"],
               summary="Revoke deployment-wide oversight")
def revoke_oversight(subject: str, request: Request,
                     principal: Principal = Depends(_administrator),
                     ) -> dict[str, Any]:
    """Take it away, effective on the reviewer's **next request**.

    Not their next sign-in: the flag is read out of the table on every request
    alongside the per-connection grants.
    """
    if not _grants(request).revoke_oversight(subject,
                                             actor=principal.actor()):
        raise NotFoundError(f"{subject!r} holds no oversight grant")
    return {"subject": subject, "revoked": True}


# --- local accounts ---------------------------------------------------------
#
# Who may sign in at all, for a deployment whose answer to that is not an
# identity provider. Managed in every mode rather than only in `basic`, so a
# deployment can be prepared before it is switched over and so an administrator
# locked out of a provider outage has somewhere to look; what decides whether a
# password is *accepted* is `PAINFREE_AUTH_MODE`, checked in
# `painfree.authn.Authenticator.resolve` and nowhere near these routes.
#
# `admin` alone, for the same reason grant management is: creating an
# administrator account is granting administration, one step removed, and a
# scope that could do it is a scope a grant could carry.

class AccountRequest(BaseModel):
    """Create one account.

    ``password`` is a :class:`~pydantic.SecretStr`, which is what makes a
    validation failure, a ``repr`` of this model and any traceback that carries
    one render it as asterisks. The `422` handler in :mod:`painfree.app` already
    drops pydantic's ``input`` from what it reports; this is the second of the
    two, because one of them is a control somebody could refactor away.
    """

    model_config = ConfigDict(extra="forbid")

    subject: Annotated[str, Field(min_length=1, max_length=255)]
    password: Annotated[SecretStr, Field(min_length=MINIMUM_PASSWORD_LENGTH)]
    role: Role = Role.member
    display_name: Annotated[str | None, Field(default=None, max_length=255)]


class AccountChange(BaseModel):
    """Change what an account is. Not what its password is -- that is its own route.

    Every field is optional and ``None`` means *leave it alone*, so a `PATCH`
    that names only ``disabled`` cannot silently demote somebody by omitting
    their role.
    """

    model_config = ConfigDict(extra="forbid")

    role: Role | None = None
    display_name: Annotated[str | None, Field(default=None, max_length=255)]
    disabled: bool | None = None


class PasswordChange(BaseModel):
    """Set an account's password. One field, and it is a secret."""

    model_config = ConfigDict(extra="forbid")

    password: Annotated[SecretStr, Field(min_length=MINIMUM_PASSWORD_LENGTH)]


def _accounts(request: Request) -> Accounts:
    return request.app.state.accounts


@router.get("/accounts", tags=["access"], summary="Local accounts")
def list_accounts(request: Request,
                  principal: Principal = Depends(_administrator)
                  ) -> dict[str, Any]:
    """Every local account. No hash, no password, and no field that holds one."""
    return {"accounts": [account.as_response()
                         for account in _accounts(request).all()],
            "auth_mode": request.app.state.settings.auth_mode.value}


@router.put("/accounts", status_code=201, tags=["access"],
            summary="Create a local account")
def create_account(body: AccountRequest, request: Request,
                   principal: Principal = Depends(_administrator)
                   ) -> dict[str, Any]:
    """Add one. A name that already exists is a `409`, never a silent replacement.

    A `PUT` that overwrote an existing account would put "reset a colleague's
    password" one typo away from "create a colleague"; changing one is
    ``POST /v1/accounts/{subject}/password`` and is a different decision.
    """
    account = _accounts(request).create(
        body.subject, body.password.get_secret_value(), role=body.role,
        display_name=body.display_name, actor=principal.actor())
    return account.as_response()


@router.patch("/accounts/{subject}", tags=["access"],
              summary="Change an account's role or suspend it")
def change_account(subject: str, body: AccountChange, request: Request,
                   principal: Principal = Depends(_administrator)
                   ) -> dict[str, Any]:
    """Role, display name, suspension. Grants are untouched by all three."""
    account = _accounts(request).change(
        subject, role=body.role, display_name=body.display_name,
        disabled=body.disabled, actor=principal.actor())
    return account.as_response()


@router.post("/accounts/{subject}/password", tags=["access"],
             summary="Set an account's password")
def set_account_password(subject: str, body: PasswordChange, request: Request,
                         principal: Principal = Depends(_administrator)
                         ) -> dict[str, Any]:
    """Replace it. Every session the old password established stays valid.

    Deliberately: a session is a separate credential with its own revocation,
    and a password change that silently signed somebody out of four browsers
    would be a password change doing two things. Revoking sessions is the
    session store's job and has its own lever.
    """
    account = _accounts(request).set_password(
        subject, body.password.get_secret_value(), actor=principal.actor())
    return account.as_response()


@router.delete("/accounts/{subject}", tags=["access"],
               summary="Delete a local account")
def delete_account(subject: str, request: Request,
                   principal: Principal = Depends(_administrator)
                   ) -> dict[str, Any]:
    """Remove it. **The subject's grants survive**, and the response says so.

    A grant names a subject, and the same subject may arrive again from an
    identity provider tomorrow. A delete that cascaded through four bank
    connections would be a decision taken by a button labelled *delete
    account*, so this one is not that button: revoking access is
    ``/v1/grants``, which is one screen away and says what it does.
    """
    if not _accounts(request).delete(subject, actor=principal.actor()):
        raise NotFoundError(f"no account named {subject!r}")
    return {"subject": subject, "deleted": True,
            "grants_retained": True}


@router.get("/lockouts", tags=["access"],
            summary="Accounts and sources being throttled")
def list_lockouts(request: Request, only_locked: bool = False,
                  principal: Principal = Depends(_administrator)
                  ) -> dict[str, Any]:
    """Who is being throttled, and how far along each counter is.

    Reading this is also what purges the counters whose window has passed --
    the table only grows while somebody is guessing, and the throttle is what
    bounds that, so a scheduled job for it would be a job that runs for nothing
    on every deployment nobody is attacking.
    """
    store = _accounts(request)
    store.purge_lockouts()
    return {"lockouts": [row.as_response()
                         for row in store.lockouts(only_locked=only_locked)]}


@router.delete("/lockouts/{scope}/{value}", tags=["access"],
               summary="Clear one lockout")
def clear_lockout(scope: str, value: str, request: Request,
                  principal: Principal = Depends(_administrator)
                  ) -> dict[str, Any]:
    """The lever that matters. ``scope`` is `subject` or `source`.

    The counter goes with the lock, so the next mistyped password starts from
    one rather than re-locking immediately. A lockout nobody holds is a `404`
    and not a silent success, for the same reason revoking a grant nobody holds
    is.
    """
    if not _accounts(request).clear_lockout(scope, value,
                                            actor=principal.actor()):
        raise NotFoundError(
            f"no lockout is recorded for that {scope}")
    return {"scope": scope, "value": value, "cleared": True}


__all__ = ["AccountChange", "AccountRequest", "GrantChange", "GrantRequest",
           "OversightRequest", "PasswordChange", "router"]
