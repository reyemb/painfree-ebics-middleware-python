"""Proving the deployment: which mode, over what, with which first account.

The three things the ``basic`` mode had to decide before a password is ever
verified, and the one it had to decide after.

**Which mode.** One credential and never two, resolved once at startup, derived
only in production and only when it was not set. The table in
`painfree/config.py` is asserted row by row, in both directions: a checkout is
unchanged, a production deployment with a provider gets `oidc`, one without gets
`basic`, and a password offered to a process configured for a provider is
refused.

**Over what.** A production process serving HTTP in the `basic` mode does not
start unless the deployment states that TLS terminates in front of it, and a
request the proxy reports as plaintext is refused with its credential unread.

**With which first account.** None. The migration writes no rows, nothing
bootstraps one on a first request, and the fourteen credential pairs a scanner
tries first are each refused on a freshly migrated deployment. The first
administrator is created by `python -m painfree create-admin`, run here the way
a person runs it.

**And afterwards, the browser.** The console signs in through a form and carries
a session cookie, which is what makes signing out of it work; the API keeps pure
Basic, where there is no logout to get wrong. The one case that leaves -- a
browser that cached a credential from a native dialog -- is exercised rather than
described.
"""

from __future__ import annotations

import io
import logging
import sys

import pytest
from fastapi.testclient import TestClient

import basic_world
from basic_world import (BROWSER, EVERY_PASSWORD, MALLORY, NOBODY, ROOT,
                         ROOT_PASSWORD, WATCHER, basic, root)
from basic_world import accounts_of as _accounts
from basic_world import settings_for as _basic_settings
from conftest import PRODUCTION_OIDC, dev_credentials
from painfree import authn, db
from painfree.accounts import MINIMUM_PASSWORD_LENGTH
from painfree.app import create_app
from painfree.audit import Actor
from painfree.config import (ConfigurationError, Environment, load_settings)
from painfree.identity import Role
from painfree.schema import basic_account


@pytest.fixture
def world(sqlite_url):
    """Two banks and four password-holding identities. See `basic_world`."""
    yield from basic_world.build(sqlite_url)


# --- nothing is bootstrapped for anybody ------------------------------------

#: What an appliance that shipped a default credential would accept. None of
#: these is a guess about painfree: they are the pairs a scanner tries first.
DEFAULT_CREDENTIALS = (
    ("admin", "admin"), ("admin", "password"), ("admin", ""),
    ("administrator", "administrator"), ("root", "root"), ("root", "toor"),
    ("painfree", "painfree"), ("painfree", "changeme"), ("user", "user"),
    ("operator", "operator"), ("developer", "developer"),
    ("admin", "painfree"), ("guest", "guest"), ("test", "test"),
)


def test_a_migrated_deployment_has_no_account_at_all(sqlite_url):
    """The table is created empty and stays empty until a person acts.

    A default credential is not a convenience with a caveat in the
    documentation. It is a published password, present on every installation
    that has not been hardened, which on the first day is all of them.
    """
    settings = _basic_settings(sqlite_url)
    engine = db.build_engine(settings)
    assert db.migrate(engine) == "0017_bank_catalogue"
    from sqlalchemy import select

    with engine.connect() as connection:
        assert connection.execute(select(basic_account)).all() == []
    app = create_app(settings)
    with TestClient(app) as client:
        assert _accounts(app).count() == 0
        for name, password in DEFAULT_CREDENTIALS:
            response = client.get("/auth/me", headers=basic(name, password))
            assert response.status_code == 401, \
                f"{name}/{password} was accepted on a fresh deployment"
        # And the console says what is wrong rather than rejecting silently.
        page = client.get("/auth/login", headers=BROWSER)
        assert page.status_code == 200
        assert "create-admin" in page.text
    engine.dispose()


def test_the_bootstrap_command_creates_the_first_administrator(sqlite_url,
                                                               monkeypatch):
    """`python -m painfree create-admin`, run as a person would run it."""
    from painfree.__main__ import main

    monkeypatch.setenv("PAINFREE_DATABASE_URL", sqlite_url)
    monkeypatch.setenv("PAINFREE_AUTH_MODE", "basic")
    assert main(["migrate"]) == 0

    monkeypatch.setattr(sys, "stdin", io.StringIO("first-admin-password-here\n"))
    assert main(["create-admin", "alice", "--display-name", "Alice"]) == 0

    settings = load_settings()
    app = create_app(settings)
    with TestClient(app) as client:
        me = client.get("/auth/me",
                        headers=basic("alice", "first-admin-password-here"))
        assert me.status_code == 200
        assert me.json()["role"] == "admin"
        assert me.json()["display_name"] == "Alice"

    # A second run refuses rather than resetting the password of an account
    # that already exists.
    monkeypatch.setattr(sys, "stdin", io.StringIO("some-other-password-x\n"))
    assert main(["create-admin", "alice"]) == 2
    # And a password the policy refuses never reaches the database.
    monkeypatch.setattr(sys, "stdin", io.StringIO("short\n"))
    assert main(["create-admin", "bob"]) == 2
    # `set-password` is the recovery path, and it needs an account to exist.
    monkeypatch.setattr(sys, "stdin", io.StringIO("a-replacement-password\n"))
    assert main(["set-password", "nobody-here"]) == 2
    monkeypatch.setattr(sys, "stdin", io.StringIO("a-replacement-password\n"))
    assert main(["set-password", "alice"]) == 0

    app = create_app(load_settings())
    with TestClient(app) as client:
        assert client.get("/auth/me", headers=basic(
            "alice", "first-admin-password-here")).status_code == 401
        assert client.get("/auth/me", headers=basic(
            "alice", "a-replacement-password")).status_code == 200


def test_the_bootstrap_command_needs_a_name(sqlite_url, monkeypatch):
    """A command that guessed a default name would be shipping one."""
    from painfree.__main__ import main

    monkeypatch.setenv("PAINFREE_DATABASE_URL", sqlite_url)
    assert main(["migrate"]) == 0
    assert main(["create-admin"]) == 2


def test_the_generated_password_goes_to_stdout_and_not_to_the_log(sqlite_url,
                                                                  monkeypatch,
                                                                  capsys, caplog):
    """`--generate` prints it once. The log stream is the one place it may not be."""
    from painfree.__main__ import main

    monkeypatch.setenv("PAINFREE_DATABASE_URL", sqlite_url)
    monkeypatch.setenv("PAINFREE_AUTH_MODE", "basic")
    assert main(["migrate"]) == 0
    with caplog.at_level(logging.DEBUG):
        assert main(["create-admin", "carol", "--generate"]) == 0
    # The log stream is stdout too, so the generated password is the one line
    # on it that is not a JSON object.
    printed = [line for line in capsys.readouterr().out.splitlines()
               if line.strip() and not line.startswith("{")]
    assert len(printed) == 1, printed
    generated = printed[0].strip()
    assert len(generated) >= MINIMUM_PASSWORD_LENGTH
    assert generated not in caplog.text
    app = create_app(load_settings())
    with TestClient(app) as client:
        assert client.get("/auth/me",
                          headers=basic("carol", generated)).status_code == 200


# --- the deployment refuses to publish a password ---------------------------

def test_production_refuses_to_start_with_basic_over_plaintext():
    """The primary control, and it is a refusal to boot rather than a runbook."""
    with pytest.raises(ConfigurationError) as refused:
        load_settings(environment="production", role="api",
                      database_url="postgresql+psycopg://painfree@db/painfree",
                      auth_mode="basic")
    message = str(refused.value)
    assert "PAINFREE_TLS_TERMINATED_UPSTREAM" in message
    assert "reversible credential on every request" in message
    assert "compose.yaml" in message


def test_production_starts_when_the_deployment_declares_tls_in_front():
    settings = load_settings(
        environment="production", role="api",
        database_url="postgresql+psycopg://painfree@db/painfree",
        auth_mode="basic", tls_terminated_upstream=True)
    assert settings.auth_mode.value == "basic"
    assert settings.tls_terminated_upstream is True
    # Session cookies still carry `Secure`, derived from the environment.
    assert settings.cookies_are_secure is True


def test_a_worker_needs_no_proxy_because_it_serves_no_http():
    """The one exception to the plaintext refusal, and why it is not a ritual.

    A worker receives no request and therefore no credential. Requiring it to
    declare a proxy it does not have would be requiring it to state something
    untrue, which is the opposite of what the declaration is for.
    """
    worker = load_settings(
        environment="production", role="worker", auth_mode="basic",
        key_encryption_secret="a-long-enough-custody-secret-for-a-test-0001",
        database_url="postgresql+psycopg://painfree@db/painfree")
    assert worker.auth_mode.value == "basic"
    assert worker.tls_terminated_upstream is False


def test_an_empty_variable_is_an_unset_one():
    """`compose.yaml` interpolates `${PAINFREE_OIDC_ISSUER:-}` into an empty
    variable, not an absent one, and an empty issuer that counted as configured
    would be a process that starts in `oidc` mode and authenticates nobody."""
    settings = load_settings(
        environment="production", role="api", auth_mode="",
        oidc_issuer="", oidc_client_id="", oidc_redirect_uri="",
        tls_terminated_upstream=True,
        database_url="postgresql+psycopg://painfree@db/painfree")
    assert settings.auth_mode.value == "basic"
    assert settings.oidc_issuer is None


def test_a_credential_that_crossed_a_plaintext_hop_is_refused_unread(sqlite_url):
    """The second control, for the proxy that was reconfigured after boot.

    It can only ever refuse, never admit, so a forged `X-Forwarded-Proto:
    https` buys nothing: the request would have been accepted anyway, having
    already crossed the hop the attacker is on.
    """
    # Production is asserted here with SQLite underneath, which the startup
    # validators refuse for a real process and rightly so. What is under test is
    # the *request-time* control, so the environment is set on a copy after
    # validation rather than by lying to `load_settings`; the startup half is
    # the two tests above, against a PostgreSQL URL.
    settings = load_settings(
        database_url=sqlite_url, auth_mode="basic",
        tls_terminated_upstream=True).model_copy(
            update={"environment": Environment.production})
    engine = db.build_engine(settings)
    db.migrate(engine)
    app = create_app(settings)
    with TestClient(app) as client:
        _accounts(app).create(ROOT, ROOT_PASSWORD, role=Role.admin,
                              actor=Actor("cli", "test@cli"))
        assert client.get("/auth/me", headers=root(
            **{"x-forwarded-proto": "https"})).status_code == 200
        assert client.get("/auth/me", headers=root(
            **{"x-forwarded-proto": "http"})).status_code == 401
        # A chain appends; the nearest proxy's view is the last entry.
        assert client.get("/auth/me", headers=root(
            **{"x-forwarded-proto": "https, http"})).status_code == 401
        assert client.get("/auth/me", headers=root(
            **{"x-forwarded-proto": "http, https"})).status_code == 200
    engine.dispose()


def test_the_forwarded_address_is_trusted_only_behind_a_declared_proxy(sqlite_url):
    """A per-source lockout keyed on a value the source chooses is not a lockout."""
    request = type("R", (), {"headers": {"x-forwarded-for": "203.0.113.9"},
                             "client": type("C", (), {"host": "10.0.0.2"})()})()
    without = load_settings(database_url=sqlite_url, auth_mode="basic")
    assert authn.source_of(request, without) == "10.0.0.2"
    behind = load_settings(database_url=sqlite_url, auth_mode="basic",
                           tls_terminated_upstream=True)
    assert authn.source_of(request, behind) == "203.0.113.9"


# --- the mode is one mode, and it is predictable ----------------------------

def test_the_mode_is_derived_only_in_production_and_only_when_unset():
    """The table in `painfree.config`, asserted row by row."""
    # Nothing configured, not production: unchanged from before this mode
    # existed.
    assert load_settings().auth_mode.value == "development"
    # An issuer in a checkout does not silently switch a developer's mode.
    assert load_settings(oidc_issuer="https://id.test/",
                         oidc_client_id="painfree",
                         oidc_redirect_uri="https://x.test/cb"
                         ).auth_mode.value == "development"
    production = dict(environment="production", role="api",
                      database_url="postgresql+psycopg://painfree@db/painfree")
    # Production with a provider: oidc.
    assert load_settings(**production, oidc_issuer="https://id.test/",
                         oidc_client_id="painfree",
                         oidc_redirect_uri="https://x.test/cb"
                         ).auth_mode.value == "oidc"
    # Production without one: basic, which is the whole point.
    assert load_settings(**production,
                         tls_terminated_upstream=True).auth_mode.value == "basic"
    # Explicit always wins, including over a configured provider.
    both = load_settings(**production, tls_terminated_upstream=True,
                         auth_mode="basic", oidc_issuer="https://id.test/",
                         oidc_client_id="painfree",
                         oidc_redirect_uri="https://x.test/cb")
    assert both.auth_mode.value == "basic"
    assert "not used" in both.auth_mode_reason
    # And the development mode is still refused in production, unchanged.
    with pytest.raises(ConfigurationError):
        load_settings(**production, auth_mode="development")


def test_a_password_is_refused_where_a_provider_is_configured(sqlite_url):
    """One kind of credential, never two. The weaker of two would decide."""
    settings = load_settings(database_url=sqlite_url, **PRODUCTION_OIDC)
    engine = db.build_engine(settings)
    db.migrate(engine)
    app = create_app(settings)
    with TestClient(app) as client:
        # An account exists, and it authenticates nobody in this mode.
        _accounts(app).create(ROOT, ROOT_PASSWORD, role=Role.admin,
                              actor=Actor("cli", "test@cli"))
        response = client.get("/auth/me", headers=root())
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == 'Bearer realm="painfree"'
        # And the sign-in form is not offered either.
        assert client.post("/auth/login", headers={
            "content-type": "application/x-www-form-urlencoded"},
            content=f"subject={ROOT}&password={ROOT_PASSWORD}"
            ).status_code == 403
    engine.dispose()


def test_the_development_header_still_works_and_a_password_does_not(sqlite_url):
    """The mode a checkout runs in is untouched by it."""
    settings = load_settings(database_url=sqlite_url)
    engine = db.build_engine(settings)
    db.migrate(engine)
    app = create_app(settings)
    with TestClient(app) as client:
        _accounts(app).create(ROOT, ROOT_PASSWORD, role=Role.admin,
                              actor=Actor("cli", "test@cli"))
        assert client.get("/auth/me",
                          headers=dev_credentials(ROOT)).status_code == 200
        assert client.get("/auth/me", headers=root()).status_code == 401
    engine.dispose()


# --- the browser flow -------------------------------------------------------

def test_the_console_signs_in_through_a_form_and_signing_out_works(world):
    """The honest half of the ``basic`` mode, exercised as a browser exercises
    it.

    A native `WWW-Authenticate: Basic` dialog would leave the browser holding a
    credential this service cannot make it forget, so the console asks for the
    password itself and establishes the same revocable session an OIDC sign-in
    establishes. Signing out then actually signs out.
    """
    client, app, _ = world
    # No credential: the console redirects into the sign-in page, not a JSON
    # envelope no browser renders.
    landing = client.get("/ui/connections", headers=BROWSER,
                         follow_redirects=False)
    assert landing.status_code == 303
    assert landing.headers["location"].startswith("/auth/login?next=")

    page = client.get("/auth/login?next=/ui/connections", headers=BROWSER)
    assert page.status_code == 200
    assert 'action="/auth/login"' in page.text
    assert 'name="password"' in page.text
    # No challenge header on the page: the browser must not be offered a dialog.
    assert "www-authenticate" not in page.headers

    signed_in = client.post(
        "/auth/login", headers={**BROWSER,
                                "content-type": "application/x-www-form-urlencoded"},
        content=f"subject={ROOT}&password={ROOT_PASSWORD}&next=/ui/connections",
        follow_redirects=False)
    assert signed_in.status_code == 303
    assert signed_in.headers["location"] == "/ui/connections"
    assert "pf_session" in signed_in.cookies

    # The cookie alone reaches the console. No `Authorization` header anywhere.
    assert client.get("/ui/connections", headers=BROWSER).status_code == 200
    assert client.get("/auth/me").json()["method"] == "session"

    out = client.get("/auth/logout", headers=BROWSER)
    assert out.status_code == 200
    # The page states the limitation rather than shipping a button that lies.
    assert "Close the browser" in out.text
    # And the session really is gone.
    assert client.get("/ui/connections", headers=BROWSER,
                      follow_redirects=False).status_code == 303
    assert client.get("/auth/me").status_code == 401


def test_a_wrong_password_on_the_form_is_the_same_sentence(world):
    client, _, _ = world
    refused = client.post(
        "/auth/login", headers={**BROWSER,
                                "content-type": "application/x-www-form-urlencoded"},
        content=f"subject={ROOT}&password=not-it")
    assert refused.status_code == 401
    assert "www-authenticate" not in refused.headers
    assert "not-it" not in refused.text
    assert 'name="password"' in refused.text


def test_signing_out_stops_a_cached_basic_credential_from_signing_back_in(world):
    """The one case the form does not cover, handled rather than described.

    A browser that answered a native dialog somewhere -- by opening a `/v1` URL
    in the address bar -- caches the credential for the realm and re-sends it.
    Without the signed-out marker, *sign out* would be followed immediately by
    being signed back in.
    """
    client, _, _ = world
    client.get("/auth/login", headers={**BROWSER, **root()},
               follow_redirects=False)
    assert client.get("/ui/connections", headers=BROWSER).status_code == 200

    assert client.get("/auth/logout", headers=BROWSER).status_code == 200
    assert authn.SIGNED_OUT_COOKIE in client.cookies

    # The browser is still sending the credential, and it establishes nothing.
    assert client.get("/ui/connections", headers={**BROWSER, **root()},
                      follow_redirects=False).status_code == 303
    # Asking to sign in again clears the marker, and the same credential works.
    assert client.get("/auth/login", headers=BROWSER).status_code == 200
    assert client.get("/ui/connections", headers={**BROWSER, **root()}
                      ).status_code == 200
    # A program is unaffected throughout: it carries no cookie jar.
    with TestClient(client.app) as machine:
        assert machine.get("/auth/me", headers=root()).status_code == 200


def test_the_marker_never_refuses_a_machine(world):
    """It only ever refuses, and only a browser navigation. Stated as a test.

    A marker that could refuse an API client would be a cookie an attacker
    could set to lock a payment integration out.
    """
    client, _, _ = world
    client.get("/auth/logout", headers=BROWSER)
    assert authn.SIGNED_OUT_COOKIE in client.cookies
    assert client.get("/auth/me", headers=root()).status_code == 200
    assert client.get("/v1/connections", headers=root()).status_code == 200


def test_the_console_manages_accounts_and_lockouts(world):
    """The pages an administrator uses when the console is the only surface."""
    client, app, _ = world
    page = client.get("/ui/accounts", headers=root(**BROWSER))
    assert page.status_code == 200
    for name in (ROOT, MALLORY, WATCHER, NOBODY):
        assert name in page.text
    # No hash on the page, and no password.
    assert "$argon2id$" not in page.text
    for password in EVERY_PASSWORD:
        assert password not in page.text

    form = {**root(**BROWSER),
            "content-type": "application/x-www-form-urlencoded"}
    added = client.post("/ui/accounts", headers=form, follow_redirects=False,
                        content="subject=newcomer&display_name=New+Comer"
                                "&password=a-long-enough-password&role=member")
    assert added.status_code == 303
    assert _accounts(app).get("newcomer") is not None

    # Lock somebody out, then clear it from the page.
    for attempt in range(6):
        client.get("/auth/me", headers=basic("newcomer", f"guess-{attempt}"))
    assert client.get("/auth/me", headers=basic(
        "newcomer", "a-long-enough-password")).status_code == 401
    listing = client.get("/ui/accounts", headers=root(**BROWSER))
    assert "newcomer" in listing.text
    cleared = client.post("/ui/accounts/lockouts/subject/newcomer/clear",
                          headers=form, content="confirm=clear",
                          follow_redirects=False)
    assert cleared.status_code == 303
    assert client.get("/auth/me", headers=basic(
        "newcomer", "a-long-enough-password")).status_code == 200

    # A form that does not confirm changes nothing.
    assert client.post(f"/ui/accounts/{ROOT}/delete", headers=form,
                       content="confirm=no").status_code == 409
    assert client.get("/auth/me", headers=root()).status_code == 200




def test_a_local_administrator_survives_renaming_the_directory_group(sqlite_url):
    """The exception, and the one that would have hurt.

    `PAINFREE_OIDC_ADMIN_ROLE` says what somebody *else's* directory calls an
    administrator. A local account's role is this service's own value, written
    by `create-admin`, so pointing that setting at a directory group must not
    demote every account this deployment issued itself.
    """
    settings = basic_world.settings_for(sqlite_url,
                                        oidc_admin_role="painfree-admins")
    engine = db.build_engine(settings)
    db.migrate(engine)
    app = create_app(settings)
    with TestClient(app) as client:
        _accounts(app).create(ROOT, "a-long-enough-password", role=Role.admin,
                              actor=Actor(type="cli", id="tests"))
        me = client.get("/auth/me", headers=basic_world.basic(
            ROOT, "a-long-enough-password"))

    assert me.status_code == 200, me.text
    assert me.json()["role"] == "admin"
    engine.dispose()

