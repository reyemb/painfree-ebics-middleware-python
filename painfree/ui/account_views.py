"""The console page for a deployment that issues its own credentials.

One screen, and it exists because of what would otherwise be true: in a
deployment with no identity provider, this console is the only operator surface
there is, and every account decision would have to be made with `curl` against
`/v1/accounts`. A console that can hand out `payments:submit` on a bank
connection but cannot create the account that holds it is a console that is
honest about half of the model.

**`admin` alone, and not by a scope.** The same :func:`_administrator`
dependency that guards granting, for the same reason: creating an administrator
account *is* granting administration, one step removed, so a scope that could do
it is a scope a grant could carry and a member could grant themselves.

**Under an identity provider it gets out of the way.** Where a provider is
configured, accounts are that provider's to manage, and a console offering a
second place to make them offers a credential this process would refuse: a
password is only accepted in ``basic`` mode. So the navigation entry is hidden
and creating an account is refused, both with one exception -- accounts that
already exist stay listed and stay removable, because a deployment that moved
*onto* a provider has leftovers to clear and hiding them would be hiding the
only screen that can.

The other direction, preparing accounts before moving *off* a provider, is the
CLI's: ``python -m painfree create-admin`` works in every mode and is already
the only way the first account is ever made.

**Nothing on this page can read a password back.** The table is built from
:class:`painfree.accounts.Account`, which has no field for one, and the two
forms that set one send it and are answered with a redirect -- so it is not in
the page that comes back and not in the URL that is bookmarked.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from painfree.accounts import MINIMUM_PASSWORD_LENGTH, Accounts
from painfree.config import AuthMode
from painfree.access_api import _administrator
from painfree.errors import ConflictError, NotFoundError
from painfree.identity import Principal, Role
from painfree.ui.rendering import render
from painfree.ui.views import PREFIX, form_data

router = APIRouter(prefix=PREFIX, tags=["console"], include_in_schema=False)


def _accounts(request: Request) -> Accounts:
    return request.app.state.accounts


def _see() -> RedirectResponse:
    """Back to the page, after every write. `303`, so a reload does not repeat it.

    It matters more here than elsewhere: the two forms that carry a password
    would otherwise be resubmitted by a refresh, and a browser that offers to
    resend a form containing a credential is a browser holding it in a place
    nobody expects.
    """
    return RedirectResponse(f"{PREFIX}/accounts", status_code=303)


@router.get("/accounts")
def accounts_page(request: Request,
                  principal: Principal = Depends(_administrator)):
    """Who may sign in, who is currently locked out, and both levers."""
    store = _accounts(request)
    store.purge_lockouts()
    return render(
        request, "accounts.html",
        accounts=store.all(),
        lockouts=store.lockouts(),
        roles=[role.value for role in Role],
        minimum_password_length=MINIMUM_PASSWORD_LENGTH,
        auth_mode=request.app.state.settings.auth_mode.value)


@router.post("/accounts")
def create_account(request: Request,
                   form: dict = Depends(form_data),
                   principal: Principal = Depends(_administrator)):
    """Add an account. The role is read explicitly and never defaulted.

    A select that silently fell back would be somebody made an administrator by
    a mis-named field, which is the same problem a silently defaulted grant
    level would be, and has the same answer.
    """
    if request.app.state.settings.auth_mode is AuthMode.oidc:
        # The account would be real, stored, and unable to sign in: this
        # process accepts one kind of credential and this is not it. Refused
        # rather than created, because a credential that authenticates nobody
        # is worse than no credential -- somebody is holding it and waiting.
        raise ConflictError(
            "this deployment authenticates against an identity provider, so "
            "accounts are made there; one made here could not sign in. To "
            "prepare for moving off the provider, use `python -m painfree "
            "create-admin`, which works in every mode.")
    _accounts(request).create(
        (form.get("subject") or "").strip(),
        form.get("password") or "",
        role=_role(form),
        display_name=(form.get("display_name") or "").strip() or None,
        actor=principal.actor())
    return _see()


@router.post("/accounts/{subject}/password")
def set_password(subject: str, request: Request,
                 form: dict = Depends(form_data),
                 principal: Principal = Depends(_administrator)):
    _accounts(request).set_password(subject, form.get("password") or "",
                                    actor=principal.actor())
    return _see()


@router.post("/accounts/{subject}/role")
def change_role(subject: str, request: Request,
                form: dict = Depends(form_data),
                principal: Principal = Depends(_administrator)):
    _accounts(request).change(subject, role=_role(form),
                              actor=principal.actor())
    return _see()


@router.post("/accounts/{subject}/suspend")
def suspend(subject: str, request: Request,
            form: dict = Depends(form_data),
            principal: Principal = Depends(_administrator)):
    """Stop a login without touching what the subject was granted.

    The two are separate decisions on purpose: somebody on leave should stop
    being able to sign in without an administrator having to reconstruct four
    connection grants when they come back.
    """
    _accounts(request).change(
        subject, disabled=(form.get("disabled") or "").lower() == "true",
        actor=principal.actor())
    return _see()


@router.post("/accounts/{subject}/delete")
def delete_account(subject: str, request: Request,
                   form: dict = Depends(form_data),
                   principal: Principal = Depends(_administrator)):
    """Remove the account. **Not the grants** -- the page says so beside it."""
    if (form.get("confirm") or "") != "delete":
        raise ConflictError("that form did not confirm the deletion")
    if not _accounts(request).delete(subject, actor=principal.actor()):
        raise NotFoundError(f"no account named {subject!r}")
    return _see()


@router.post("/accounts/lockouts/{scope}/{value}/clear")
def clear_lockout(scope: str, value: str, request: Request,
                  form: dict = Depends(form_data),
                  principal: Principal = Depends(_administrator)):
    """The lever an administrator reaches for when somebody is locked out now."""
    if (form.get("confirm") or "") != "clear":
        raise ConflictError("that form did not confirm clearing the lockout")
    if not _accounts(request).clear_lockout(scope, value,
                                            actor=principal.actor()):
        raise NotFoundError(f"no lockout is recorded for that {scope}")
    return _see()


def _role(form: dict) -> Role:
    """The role off a form, or a `409` naming what was sent. Never a default."""
    raw = (form.get("role") or "").strip()
    try:
        return Role(raw)
    except ValueError:
        raise ConflictError(
            f"{raw!r} is not a role; choose "
            f"{' or '.join(role.value for role in Role)}") from None


__all__ = ["router"]
