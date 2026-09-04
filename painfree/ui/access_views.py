"""The console pages that decide who may touch which bank connection.

Three screens, and they exist because the model they operate has two ways of
being read and an administrator needs both:

- **Who is there** -- ``/ui/access`` lists every subject this deployment knows
  with the connections it holds, which is the question asked when somebody
  joins or leaves.
- **What can this person reach** -- ``/ui/access/{subject}`` is one person's
  grants, and where a grant is made or taken away.
- **Who can reach this bank** -- ``/ui/connections/{id}/access`` is the same
  rows read the other way, on the connection's own page, which is the question
  asked during a review of one account.

The third is not a duplicate of the second. A grant table has two natural
readings and an administrator who can only take one of them ends up exporting
rows into a spreadsheet to answer the other.

**Every one of these routes is `admin` alone**, and not by a scope. There is no
`grants:manage` in :class:`painfree.identity.Scope`, deliberately: a scope is
something a grant can carry, and a privilege that could be granted to a member
would let the holder grant themselves the rest. Granting is the one capability
the model does not express as a scope, which is what keeps it out of reach of
everything the model can hand out.

**Deployment-wide oversight is issued from these same screens**, because it is
the same decision read at a different width: *who may look at this*. It is a
grant with no connection to choose, so it has no dropdown -- a checkbox-shaped
decision, confirmed like a revocation is, and shown on the subject list beside
the per-connection grants so that "who can see every bank" is answerable by
reading one page.

**Deleting a connection is not here.** Revoking somebody's access and removing a
bank connection are different decisions and the second one has no page at all
yet; a revoke that quietly cascaded would be the wrong surprise on this screen.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from painfree.access import Grants
from painfree.access_api import _administrator
from painfree.config import AuthMode
from painfree.errors import ConflictError, NotFoundError
from painfree.identity import OVERSIGHT_SCOPES, Level, Principal
from painfree.logging import bind
from painfree.ui.rendering import render
from painfree.ui.views import PREFIX, _registry, form_data

router = APIRouter(prefix=PREFIX, tags=["console"], include_in_schema=False)


def _grants(request: Request) -> Grants:
    return request.app.state.grants


def _see(path: str) -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def _level(form: dict[str, str]) -> Level:
    """The level off a form, or a `409` naming what was sent.

    Never a default. A form that silently fell back to `viewer` would grant
    less than an administrator asked for, and one that fell back to `operator`
    would grant somebody the ability to move money because a select was
    mis-named.
    """
    raw = (form.get("level") or "").strip()
    try:
        return Level(raw)
    except ValueError:
        raise ConflictError(
            f"{raw!r} is not an access level; choose "
            f"{' or '.join(level.value for level in Level)}") from None


def _subject(form: dict[str, str]) -> str:
    value = (form.get("subject") or "").strip()
    if not value:
        raise ConflictError("the subject is required")
    return value


@router.get("/access")
def access_index(request: Request,
                 principal: Principal = Depends(_administrator)):
    """Everyone this deployment knows, and what each of them holds.

    A subject appears here because it signed in or because it was granted
    something. Somebody granted access who has not yet signed in shows with no
    display name and no last-seen -- which is the row an administrator needs to
    see, or granting to a new colleague looks like it did nothing.
    """
    store = _grants(request)
    subjects = store.subjects()
    # How each person signs in. A grant is inert without a way to use it, and
    # the two facts live in tables nothing joined: `basic_account` holds the
    # local passwords and the grant tables hold the privilege, so a grant
    # nobody can use looked exactly like a working one.
    mode = request.app.state.settings.auth_mode
    local = {row.subject for row in request.app.state.accounts.all()}
    return render(request, "access.html", subjects=subjects,
                  connections=_registry(request).all(),
                  levels=[level.value for level in Level],
                  password_holders=local, auth_mode=mode.value,
                  # The number an administrator opens this page to check.
                  # `operator` is the level that carries `payments:submit`.
                  movers=sum(1 for row in subjects
                             if any(grant.level is Level.operator
                                    for grant in row.grants)),
                  # A person who can never sign in is the state this page could
                  # not show at all, and under `basic` it is the ordinary
                  # consequence of granting before the account exists.
                  stranded=[row.subject for row in subjects
                            if mode is AuthMode.basic
                            and row.subject not in local
                            and (row.grants or row.oversight)],
                  oversight=[row for row in subjects if row.oversight],
                  # Holding oversight is holding something, so a reviewer is
                  # not "signed in, holding no grant" -- listing them there
                  # would tell an administrator to grant somebody who already
                  # reads every bank in the deployment.
                  ungranted=[row for row in subjects
                             if not row.grants and not row.oversight])


@router.get("/access/{subject}")
def access_subject(request: Request, subject: str,
                   granted: str = "", revoked: str = "",
                   principal: Principal = Depends(_administrator)):
    """One person: every connection they hold, and the form that changes it."""
    store = _grants(request)
    held = store.all(subject=subject)
    connections = _registry(request).all()
    taken = {grant.connection_id for grant in held}
    return render(request, "access_subject.html", subject=subject,
                  grants=held, connections=connections,
                  available=[row for row in connections
                             if row.connection_id not in taken],
                  levels=[level.value for level in Level],
                  oversight=store.oversight_get(subject),
                  oversight_scopes=sorted(scope.value
                                          for scope in OVERSIGHT_SCOPES),
                  granted=granted or None, revoked=revoked or None)


@router.post("/access/{subject}")
def save_subject_grant(
    request: Request, subject: str,
    principal: Principal = Depends(_administrator),
    form: dict[str, str] = Depends(form_data),
):
    """Grant a connection to this person, or change the level of one they hold."""
    connection_id = (form.get("connection_id") or "").strip()
    if not connection_id:
        raise ConflictError("choose a connection to grant")
    with bind(connection_id=connection_id):
        _grants(request).grant(subject, connection_id, _level(form),
                               actor=principal.actor())
    return _see(f"{PREFIX}/access/{subject}?granted={connection_id}")


@router.post("/access/{subject}/revoke")
def revoke_subject_grant(
    request: Request, subject: str,
    principal: Principal = Depends(_administrator),
    form: dict[str, str] = Depends(form_data),
):
    """Take one connection away from this person. It stops working immediately.

    Not on their next sign-in: grants are read from the table on every request,
    so the session they have open now stops reaching the connection before they
    finish reading the page they are on.
    """
    connection_id = (form.get("connection_id") or "").strip()
    if (form.get("confirm") or "").strip() != "revoke":
        raise ConflictError("the revocation was not confirmed")
    with bind(connection_id=connection_id):
        if not _grants(request).revoke(subject, connection_id,
                                       actor=principal.actor()):
            raise NotFoundError(
                f"{subject!r} holds no grant on {connection_id!r}")
    return _see(f"{PREFIX}/access/{subject}?revoked={connection_id}")


@router.post("/access/{subject}/oversight")
def grant_oversight(
    request: Request, subject: str,
    principal: Principal = Depends(_administrator),
    form: dict[str, str] = Depends(form_data),
):
    """Give this subject read-only reach over the whole deployment.

    Confirmed like a revocation is, and for the mirror-image reason: this is
    the one grant whose blast radius is every bank connection at once, so it
    should not be one mis-aimed click. What it hands over is read and nothing
    else -- every scope in it is named `:read` -- but *every* connection's
    payment history is still every connection's payment history.
    """
    if (form.get("confirm") or "").strip() != "oversight":
        raise ConflictError("the oversight grant was not confirmed")
    _grants(request).grant_oversight(subject, actor=principal.actor())
    return _see(f"{PREFIX}/access/{subject}?granted=oversight")


@router.post("/access/{subject}/oversight/revoke")
def revoke_oversight(
    request: Request, subject: str,
    principal: Principal = Depends(_administrator),
    form: dict[str, str] = Depends(form_data),
):
    """Take it away. Effective on their next request, like every revocation."""
    if (form.get("confirm") or "").strip() != "revoke":
        raise ConflictError("the revocation was not confirmed")
    if not _grants(request).revoke_oversight(subject,
                                             actor=principal.actor()):
        raise NotFoundError(f"{subject!r} holds no oversight grant")
    return _see(f"{PREFIX}/access/{subject}?revoked=oversight")


@router.get("/connections/{connection_id}/access")
def connection_access(request: Request, connection_id: str,
                      granted: str = "", revoked: str = "",
                      principal: Principal = Depends(_administrator)):
    """Who can reach this bank, and at what level. The other reading of the table."""
    with bind(connection_id=connection_id):
        connection = _registry(request).get(connection_id)
        return render(request, "connection_access.html", connection=connection,
                      grants=_grants(request).all(connection_id=connection_id),
                      subjects=_grants(request).subjects(),
                      levels=[level.value for level in Level],
                      granted=granted or None, revoked=revoked or None)


@router.post("/connections/{connection_id}/access")
def save_connection_grant(
    request: Request, connection_id: str,
    principal: Principal = Depends(_administrator),
    form: dict[str, str] = Depends(form_data),
):
    """Grant this connection to a subject, typed or chosen.

    Typed as well as chosen, because the person being granted access may never
    have signed in: a deployment that could only grant to somebody already in
    its session table could never onboard anybody.
    """
    with bind(connection_id=connection_id):
        subject = _subject(form)
        _grants(request).grant(subject, connection_id, _level(form),
                               actor=principal.actor())
    return _see(f"{PREFIX}/connections/{connection_id}/access?granted={subject}")


@router.post("/connections/{connection_id}/access/revoke")
def revoke_connection_grant(
    request: Request, connection_id: str,
    principal: Principal = Depends(_administrator),
    form: dict[str, str] = Depends(form_data),
):
    """Take this connection away from one subject."""
    subject = _subject(form)
    if (form.get("confirm") or "").strip() != "revoke":
        raise ConflictError("the revocation was not confirmed")
    with bind(connection_id=connection_id):
        if not _grants(request).revoke(subject, connection_id,
                                       actor=principal.actor()):
            raise NotFoundError(
                f"{subject!r} holds no grant on {connection_id!r}")
    return _see(f"{PREFIX}/connections/{connection_id}/access?revoked={subject}")


__all__ = ["router"]
