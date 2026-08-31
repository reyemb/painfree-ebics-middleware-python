"""The two console pages that are about the deployment rather than its work.

Split out of :mod:`painfree.ui.views` when that module reached the repository's
1 000-line cap. The line the split follows is what the page is *about*: the
others show what this deployment did with a bank, these two show the deployment
itself -- who did what across it, and how a machine reaches its API.

Neither is changed by being here, except that the audit page is now scoped to
the connections its reader holds.
"""

from __future__ import annotations

import datetime as _dt

from fastapi import APIRouter, Depends, Request

from painfree import access, accounts, identity
from painfree.authn import PUBLIC_PATHS, requires
from painfree.errors import ConflictError
from painfree.identity import Principal, Scope
from painfree.ui import reference
from painfree.ui.rendering import audit_links, may_for, render
from painfree.ui.views import PREFIX, _registry

router = APIRouter(prefix=PREFIX, tags=["console"], include_in_schema=False)


# --- the audit trail --------------------------------------------------------
#
# `audit:read`, which both grant levels carry -- **for the connections the
# caller holds, and no others**. It was once a global privilege held by two of
# four roles; it is per connection now, and the reasoning changed with the
# model. A member who may see a bank's orders and statements is not learning
# anything new from that bank's trail, and a page they cannot open makes them
# ask an administrator what happened on their own connection. What they must
# not see is another connection's trail, or the rows that name no connection at
# all -- a sign-in, a service start, a grant -- since those name colleagues
# this deployment never told them about.
#
# The filtering is in `AuditLog.search`, not here: an unfiltered query whose
# rows are dropped afterwards is a page that silently returns short.

#: How many rows one page shows, and the cap on what a caller may ask for.
AUDIT_PAGE = 50
MAX_AUDIT_PAGE = 200


@router.get("/audit")
def audit(request: Request, connection_id: str = "", actor_id: str = "",
          action: str = "", outcome: str = "", order_id: str = "",
          since: str = "", until: str = "", before: int = 0,
          limit: int = AUDIT_PAGE,
          principal: Principal = Depends(requires(Scope.audit_read))):
    """Who did what, filtered, with every row linked to what it happened to."""
    log_ = request.app.state.audit
    window = (_day(since, "the start date"), _day(until, "the end date"))
    allowed, possible = access.restrict(principal, connection_id or None)
    rows = [] if not possible else log_.search(
        limit=max(1, min(limit, MAX_AUDIT_PAGE)) + 1,
        connection_ids=allowed, actor_id=actor_id or None,
        action=action or None, outcome=outcome or None,
        order_id=order_id or None, since=window[0],
        # Inclusive of the whole named day: an operator typing today's date and
        # seeing none of today's events would reasonably conclude the page is
        # broken.
        until=window[1] + _dt.timedelta(days=1) - _dt.timedelta(microseconds=1)
        if window[1] else None,
        before_seq=before or None)
    page = rows[:max(1, min(limit, MAX_AUDIT_PAGE))]
    return render(
        request, "audit.html", events=page,
        links={row["event_id"]: audit_links(row, may_for(principal))
               for row in page},
        actions=log_.actions(allowed), actors=log_.actors(
            connection_ids=allowed),
        connections=access.held(principal, _registry(request).all()),
        filters={"connection_id": connection_id, "actor_id": actor_id,
                 "action": action, "outcome": outcome, "order_id": order_id,
                 "since": since, "until": until},
        # A cursor, not an offset: rows arrive while the page is read, and an
        # offset would show one twice and skip another (`AuditLog.search`).
        older=page[-1]["seq"] if len(rows) > len(page) else None)


def _day(value: str, label: str) -> _dt.datetime | None:
    """``2026-08-30`` as midnight UTC, or a `409` naming the field."""
    if not value.strip():
        return None
    try:
        parsed = _dt.date.fromisoformat(value.strip())
    except ValueError:
        raise ConflictError(
            f"{label} must be a date such as 2026-08-30") from None
    return _dt.datetime.combine(parsed, _dt.time.min, _dt.timezone.utc)


# --- the API, and how a machine reaches it ----------------------------------

@router.get("/api")
def api_reference(request: Request,
                  principal: Principal = Depends(requires())):
    """The developer page. Authenticated, and deliberately privilege-free.

    Every other page here demands a scope. This one demands none, because the
    question it exists to answer is *why was I refused* -- and the caller
    asking it is the caller who holds nothing. A page about privileges that is
    itself behind a privilege leaves that person with a redirect loop and no
    way to find out what they would have needed.

    It reveals nothing a caller could not already learn: their own claims,
    which the provider issued to them, and the deployment's scope model, which
    is in this repository. No secret and no other caller's identity appears.
    """
    settings = request.app.state.settings
    return render(
        request, "api.html",
        documents=reference.OPENAPI_DOCUMENTS,
        scopes=reference.scope_catalogue(principal),
        roles=reference.role_catalogue(),
        grant_levels=reference.level_catalogue(),
        oversight_scopes=reference.oversight_catalogue(),
        routes=reference.protected_routes(request.app, PUBLIC_PATHS),
        unscoped=reference.unprotected(request.app, PUBLIC_PATHS),
        me=principal.as_response(),
        unmapped=identity.unknown_roles(principal.roles),
        auth_mode=settings.auth_mode.value,
        # Derived when it is not set, so the page says *why* it is what it is.
        # The same sentence the startup line carries.
        auth_mode_reason=settings.auth_mode_reason,
        password_hashing=(
            f"Argon2id, m={accounts.ARGON2_MEMORY_KIB // 1024} MiB, "
            f"t={accounts.ARGON2_TIME_COST}, p={accounts.ARGON2_PARALLELISM}"),
        provider={"issuer": settings.oidc_issuer,
                  "audience": settings.audience,
                  "client_id": settings.oidc_client_id,
                  "roles_claim": settings.oidc_roles_claim,
                  "scope_claim": settings.oidc_scope_claim},
        base_url=str(request.base_url).rstrip("/"))


__all__ = ["AUDIT_PAGE", "MAX_AUDIT_PAGE", "router"]
