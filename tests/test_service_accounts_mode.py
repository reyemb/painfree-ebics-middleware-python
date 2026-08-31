"""Where local accounts are this deployment's business, and where they are not.

A password is accepted in exactly one mode. So under an identity provider an
account created in this console would be stored, real, and refused at sign-in --
a credential somebody is holding and waiting on. The console gets out of the
way instead: no navigation entry, no form, and a refusal if the route is posted
to directly.

The exception is the one that makes it safe. A deployment that moved *onto* a
provider still has whatever it issued before, and this screen is the only place
that can remove it, so accounts that already exist stay listed and the entry
stays visible until they are gone.

The other direction, preparing accounts before moving *off* a provider, belongs
to `python -m painfree create-admin`, which works in every mode and is already
the only way a first account is ever made.
"""

from __future__ import annotations

from contextlib import contextmanager

from fastapi.testclient import TestClient

from conftest import dev_credentials
from painfree import db
from painfree.accounts import Accounts
from painfree.app import create_app
from painfree.audit import Actor, AuditLog
from painfree.config import AuthMode
from painfree.identity import Role

CLI = Actor(type="cli", id="tests")


@contextmanager
def _console(settings, *, mode: str, accounts: bool = False):
    """A console whose *configured* mode is `mode`, still reachable by a test.

    The mode is set **after** the application has started, which is the same
    shape as the plaintext-hop test: assert the state after validation rather
    than lying to `load_settings`. Swapping it before startup would build the
    authenticator in that mode too, and the development header this drives the
    console with would be refused -- which is correct, and not what is under
    test here.
    """
    engine = db.build_engine(settings)
    db.migrate(engine)
    if accounts:
        Accounts(engine, AuditLog(engine)).create(
            "leftover", "a-long-enough-password", role=Role.member, actor=CLI)
    app = create_app(settings)
    try:
        with TestClient(app, headers=dev_credentials()) as client:
            app.state.settings = settings.model_copy(
                update={"auth_mode": AuthMode(mode)})
            yield client, engine
    finally:
        engine.dispose()


def test_the_entry_is_hidden_under_a_provider(settings):
    """Nothing to manage here: the provider manages them."""
    with _console(settings, mode="oidc") as (client, engine):
        page = client.get("/ui/connections")

    assert "/ui/accounts" not in page.text


def test_the_entry_stays_while_there_are_leftovers_to_clear(settings):
    """A deployment that moved onto a provider still has what it issued before."""
    with _console(settings, mode="oidc", accounts=True) as (client, engine):
        page = client.get("/ui/connections")

    assert "/ui/accounts" in page.text


def test_the_entry_is_shown_when_this_deployment_authenticates(settings):
    """With no provider this console is the only operator surface there is."""
    with _console(settings, mode="basic") as (client, engine):
        page = client.get("/ui/connections")

    assert "/ui/accounts" in page.text


def test_creating_one_under_a_provider_is_refused(settings):
    """It would be stored, real, and unable to sign in. Refused, not created."""
    with _console(settings, mode="oidc") as (client, engine):
        response = client.post("/ui/accounts", data={
            "subject": "someone", "password": "a-long-enough-password",
            "role": "member"})

        assert response.status_code == 409
        assert "create-admin" in response.text
        # And nothing was written.
        assert Accounts(engine).all() == []


def test_the_page_says_who_owns_them(settings):
    """The form is gone and the reason is in its place, not left to be guessed."""
    with _console(settings, mode="oidc", accounts=True) as (client, engine):
        page = client.get("/ui/accounts")

    assert page.status_code == 200
    assert "identity provider" in page.text
    # The leftover is still removable, which is the reason the page is reachable.
    assert "leftover" in page.text
