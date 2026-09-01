"""Who may do what, driven through the running application.

Three claims, and each is asserted rather than described:

1. **Nothing is accidentally public.** Every route the application declares is
   enumerated and called with no credential; the ones that answer are exactly
   the two probes and the three login endpoints, and that list is written out
   here so adding a public route means changing this file.
2. **Reading and paying are different privileges.** A caller holding a read role
   is refused a payment submission, with the missing scope named.
3. **Nothing leaks.** A rejected bearer token, an accepted one that ends up in a
   traceback, and an authorization code whose exchange failed: none of the three
   appears anywhere in what the process wrote to stdout.

There is no reference implementation for any of this, so nothing here claims a
match with one.
"""

from __future__ import annotations

import concurrent.futures
import datetime
import json
import os
import threading
import urllib.parse

import pytest
from fastapi import Header
from fastapi.testclient import TestClient
from sqlalchemy import update

from conftest import (PRODUCTION_OIDC, dev_credentials, grant, payment_body,
                      reset_database)
from idp import CLIENT_ID, SUBJECT, StubProvider, now, serving_provider
from painfree import authn, db, ebics3, identity, oidc
from painfree.api import IDEMPOTENCY_HEADER
from painfree.app import create_app
from painfree.config import ConfigurationError, load_settings
from painfree.connections import ConnectionRegistry
from painfree.identity import Level, Role, Scope
from painfree.schema import bank_connection
from painfree.tokens import AuthenticationFailed

CONNECTION = "acme-ubs"
PAYMENTS = f"/v1/connections/{CONNECTION}/payments"
REDIRECT_URI = "http://testserver/auth/callback"


def register_connection(app) -> None:
    engine = app.state.engine
    ConnectionRegistry(engine).register(
        CONNECTION, host_id="UBSHOST", partner_id="PARTNER1", user_id="USER1",
        host_url="https://ebics.example.test/")
    with engine.begin() as connection:
        connection.execute(
            update(bank_connection)
            .where(bank_connection.c.connection_id == CONNECTION)
            .values(key_state=ebics3.KeyState.READY.value))


@pytest.fixture
def client(settings, capsys):
    app = create_app(settings)
    with TestClient(app) as client:
        register_connection(app)
        # A member reaches nothing until it is granted a connection, so the
        # callers these tests drive are granted one here at the level their
        # name says. `admin` holds everything and needs none.
        grant(app, "reader", CONNECTION, "viewer")
        grant(app, "op", CONNECTION, "operator")
        grant(app, "alice", CONNECTION, "operator")
        client.app = app
        yield client


def emitted(capsys) -> list[dict]:
    return [json.loads(line) for line
            in capsys.readouterr().out.splitlines() if line.strip()]


def submit(client, **kwargs):
    return client.post(PAYMENTS, json=payment_body(),
                       headers={IDEMPOTENCY_HEADER: "authz-0001",
                                **kwargs.pop("headers", {})}, **kwargs)


# --- the model --------------------------------------------------------------

def test_paying_and_reading_are_different_privileges():
    """The claim the whole model exists to make, now at the level of a grant."""
    viewer = identity.LEVEL_SCOPES[Level.viewer]
    operator = identity.LEVEL_SCOPES[Level.operator]
    assert Scope.payments_read in viewer
    assert Scope.payments_submit not in viewer
    assert Scope.payments_submit in operator
    assert Scope.statements_read in viewer


def test_two_scopes_are_carried_by_no_grant_level_at_all():
    """The `admin`-only set, and the reason a member cannot exfiltrate events."""
    for scope in (Scope.connections_write, Scope.webhooks_manage):
        assert scope not in identity.LEVEL_SCOPES[Level.viewer]
        assert scope not in identity.LEVEL_SCOPES[Level.operator]
        assert scope in identity.ROLE_SCOPES[Role.admin]


def test_a_scope_claim_narrows_and_never_grants():
    """`scope` is what the client asked for. It cannot add what no grant gave."""
    assert identity.effective_scopes(["admin"], None) == \
        identity.ROLE_SCOPES[Role.admin]
    assert identity.effective_scopes(["admin"], ["payments:read"]) == \
        frozenset({Scope.payments_read})
    # No admin claim and no grant: the scope claim alone is worth nothing.
    assert identity.effective_scopes([], ["payments:submit"]) == frozenset()
    assert identity.effective_scopes(["member"], ["payments:submit"]) == frozenset()
    # It narrows the per-connection set too, so naming a connection is not a
    # way around a token that asked for less than it was granted.
    narrowed = identity.build_principal(
        subject="m", issuer="i", method="bearer", roles=["member"],
        grants=[("acme", Level.operator)], requested=["payments:read"])
    assert narrowed.may(Scope.payments_read, "acme")
    assert not narrowed.may(Scope.payments_submit, "acme")


def test_an_unmapped_role_makes_a_member_and_no_administrator():
    """It grants nothing, and being a member is not a privilege on its own."""
    assert identity.scopes_for(["payments-admin", "superuser"]) == frozenset()
    assert identity.role_for(["payments-admin"]) is Role.member
    assert identity.unknown_roles(["member", "payments-admin"]) == ("payments-admin",)
    # The old four names are still understood, so a directory that has not been
    # migrated does not fill the log with unmapped-role warnings.
    assert identity.unknown_roles(["viewer", "operator", "auditor"]) == ()
    assert identity.role_for(["administrator"]) is Role.admin


def test_a_nested_roles_claim_is_read_by_a_dotted_path():
    claims = {"realm_access": {"roles": ["operator"]}}
    assert identity.claim_at(claims, "realm_access.roles") == ["operator"]
    assert identity.claim_at(claims, "resource_access.roles") is None


# --- nothing is accidentally public -----------------------------------------

#: Every path reachable with no credential. Adding one means changing this line,
#: which is the point: the list is the review, not the middleware.
EXPECTED_PUBLIC = {"/healthz", "/readyz", "/auth/login", "/auth/callback",
                   "/auth/logout"}


def declared_routes(app) -> list[tuple[str, str]]:
    """Every (method, path) the application serves, minus HEAD and OPTIONS.

    Recursive, because an included router is a *node* in this FastAPI version
    rather than a flattened list -- and a walker that quietly missed a nested
    router would report "nothing is public" by not looking, which is the one
    way this test could pass while being worthless.
    """
    found: list[tuple[str, str]] = []

    def walk(routes) -> None:
        for route in routes:
            nested = (getattr(route, "routes", None)
                      or getattr(getattr(route, "original_router", None),
                                 "routes", None))
            if nested:
                walk(nested)
                continue
            for method in sorted(getattr(route, "methods", None) or ()):
                if method not in {"HEAD", "OPTIONS"}:
                    found.append((method, route.path))

    walk(app.routes)
    return sorted(found)


def test_the_public_set_is_exactly_what_is_declared(settings):
    assert authn.PUBLIC_PATHS == EXPECTED_PUBLIC


def test_every_route_that_is_not_public_refuses_an_unauthenticated_request(settings):
    """The enumeration. Not a sample -- every route the application declares."""
    app = create_app(settings)
    routes = declared_routes(app)
    assert len(routes) >= 8, routes

    protected, public = [], []
    with TestClient(app) as client:
        register_connection(app)
        for method, path in routes:
            url = path.replace("{connection_id}", CONNECTION) \
                      .replace("{order_id}", "ord_missing")
            # Not followed: a redirect to `/` would be a second request, and
            # what is under test is the answer this route gives.
            response = client.request(method, url, json={},
                                      follow_redirects=False)
            if path in EXPECTED_PUBLIC:
                public.append((method, path, response.status_code))
                # `/auth/callback` answers `401` here, from the route rather
                # than from the middleware: it is reachable, it was simply not
                # given a login to finish.
                assert response.status_code != 401 or path == "/auth/callback", \
                    (method, path)
            else:
                protected.append((method, path, response.status_code))
                assert response.status_code == 401, (
                    f"{method} {path} answered {response.status_code} with no "
                    f"credential; it is reachable by anyone")
                assert response.json()["error"]["code"] == "unauthenticated"
                assert "WWW-Authenticate" in response.headers

    # Printed so the evidence is the enumeration itself, not a claim.
    print("\n  public   :", sorted({(m, p) for m, p, _ in public}))
    print("  protected:", sorted({(m, p) for m, p, _ in protected}))
    assert {p for _, p, _ in public} == EXPECTED_PUBLIC
    assert not {p for _, p, _ in protected} & EXPECTED_PUBLIC


def test_a_new_route_is_protected_without_anyone_remembering_to(settings):
    """Deny by default: a route added with no dependency is still not public."""
    app = create_app(settings)

    @app.get("/v1/whatever-someone-adds-next")
    def added() -> dict:  # pragma: no cover - never reached
        return {"reachable": True}

    with TestClient(app) as client:
        assert client.get("/v1/whatever-someone-adds-next").status_code == 401


def test_the_probes_answer_without_a_credential(client):
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200


# --- scopes on the wire -----------------------------------------------------

def test_a_viewer_grant_is_refused_a_payment_submission(client, capsys):
    """The one that matters: seeing a bank is not permission to pay from it."""
    response = submit(client, headers=dev_credentials("reader", "member"))
    assert response.status_code == 403, response.text
    body = response.json()["error"]
    assert body["code"] == "forbidden"
    assert body["detail"]["missing_scopes"] == ["payments:submit"]
    assert body["detail"]["connection_id"] == CONNECTION
    assert "payments:read" in body["detail"]["held_scopes"]

    line = next(l for l in emitted(capsys) if l["event"] == "access.forbidden")
    assert line["subject"] == "reader"
    assert line["missing"] == ["payments:submit"]


def test_an_operator_grant_may_submit_and_an_ungranted_member_may_not(client):
    assert submit(client, headers=dev_credentials("op", "member")
                  ).status_code == 202
    # No grant at all: refused, and told nothing about the connection.
    assert submit(client, headers=dev_credentials("aud", "member")
                  ).status_code == 404


def test_only_an_admin_reads_the_whole_audit_log(client):
    """A member sees its own connections' rows; the deployment's rows are admin."""
    member = client.get("/v1/audit", headers=dev_credentials("op", "member"))
    assert member.status_code == 200
    assert not any(event["action"] == "service.started"
                   for event in member.json()["events"])
    response = client.get("/v1/audit", headers=dev_credentials("root", "admin"))
    assert response.status_code == 200
    assert any(event["action"] == "service.started"
               for event in response.json()["events"])


def test_a_caller_with_no_role_at_all_holds_nothing(client):
    """A working login and an empty console, which is the intended state."""
    assert client.get("/v1/audit", headers=dev_credentials("nobody", "")
                      ).status_code == 403
    # The connection list is the one thing they may ask, and it is empty.
    connections = client.get("/v1/connections",
                             headers=dev_credentials("nobody", ""))
    assert connections.status_code == 200
    assert connections.json() == {"connections": []}
    me = client.get("/auth/me", headers=dev_credentials("nobody", "")).json()
    assert me["scopes"] == [] and me["grants"] == [] and me["role"] == "member"


def test_a_submitted_payment_is_attributed_to_its_subject(client):
    """Every authenticated action names who did it, in the audit log."""
    assert submit(client, headers=dev_credentials("alice", "member")
                  ).status_code == 202
    events = client.get("/v1/audit",
                        headers=dev_credentials("root", "admin")).json()["events"]
    accepted = next(e for e in events if e["action"] == "payment.accepted")
    assert accepted["actor_id"] == "alice"
    assert accepted["actor_type"] == "developer"


# --- the development mode ---------------------------------------------------

def test_the_development_mode_cannot_be_configured_in_production():
    """The same shape as the custody split: production refuses to start."""
    with pytest.raises(ConfigurationError, match="must never serve real traffic"):
        load_settings(environment="production", role="api",
                      auth_mode="development",
                      database_url="postgresql+psycopg://p@db:5432/painfree")


def test_production_starts_once_a_provider_is_configured():
    settings = load_settings(
        environment="production", role="api", migrate_on_startup=False,
        database_url="postgresql+psycopg://p@db:5432/painfree",
        **PRODUCTION_OIDC)
    assert settings.auth_mode.value == "oidc"
    assert settings.cookies_are_secure is True


def test_oidc_mode_refuses_to_start_half_configured():
    with pytest.raises(ConfigurationError, match="PAINFREE_OIDC_CLIENT_ID"):
        load_settings(auth_mode="oidc", oidc_issuer="https://id.example.test")


def test_the_development_mode_still_demands_a_credential(client):
    """It is an authentication step, not an exemption from one."""
    assert client.get("/v1/connections").status_code == 401
    assert client.get("/v1/connections", headers=dev_credentials()
                      ).status_code == 200


def test_a_development_process_does_not_verify_bearer_tokens(client, capsys):
    """No provider is configured, so a token has nothing to be checked against."""
    response = client.get("/v1/connections",
                          headers={"Authorization": "Bearer eyJhbGciOiJub25lIn0.e30."})
    assert response.status_code == 401
    line = next(l for l in emitted(capsys) if l["event"] == "auth.rejected")
    assert line["reason"] == "bearer_not_configured"


# --- against a real identity provider ---------------------------------------

@pytest.fixture
def provider():
    return StubProvider()


@pytest.fixture
def oidc_client(sqlite_url, provider, capsys):
    """The application in `oidc` mode, against the stub provider on a socket."""
    with serving_provider(provider) as issuer:
        settings = load_settings(
            database_url=sqlite_url, auth_mode="oidc", oidc_issuer=issuer,
            oidc_client_id=CLIENT_ID, oidc_redirect_uri=REDIRECT_URI)
        app = create_app(settings)
        with TestClient(app) as client:
            register_connection(app)
            # The provider names the subject; this deployment decides what that
            # subject may touch. Without this row the token below is a valid
            # credential that reaches nothing, which is the model working
            # rather than the test failing.
            grant(app, SUBJECT, CONNECTION, "operator")
            yield client, provider


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_a_machine_client_submits_a_payment_with_a_bearer_token(oidc_client):
    client, provider = oidc_client
    token = provider.token(roles=["operator"])
    assert submit(client, headers=bearer(token)).status_code == 202


def test_a_forged_bearer_token_is_refused_by_the_running_service(oidc_client):
    """Each attack again, this time through the whole ASGI stack."""
    client, provider = oidc_client
    forger = StubProvider()
    forger.issuer = provider.issuer
    for name, token in [
        ("alg:none", provider.unsigned_token()),
        ("confusion", provider.confused_token()),
        ("expired", provider.token(iat=now() - 3700, exp=now() - 3600)),
        ("not yet valid", provider.token(nbf=now() + 3600)),
        ("wrong issuer", provider.token(iss="https://evil.example.test/")),
        ("wrong audience", provider.token(aud="elsewhere")),
        ("unrelated key", forger.token()),
    ]:
        response = client.get("/v1/connections", headers=bearer(token))
        assert response.status_code == 401, f"{name} was accepted"
        assert response.json()["error"]["code"] == "unauthenticated"


def test_a_rejected_bearer_token_is_never_written_to_the_log(oidc_client, capsys):
    client, provider = oidc_client
    capsys.readouterr()
    token = provider.token(iat=now() - 3700, exp=now() - 3600)
    assert client.get("/v1/connections", headers=bearer(token)).status_code == 401

    written = capsys.readouterr().out
    for part in token.split("."):
        assert part not in written, "part of a rejected token reached the log"
    line = next(json.loads(l) for l in written.splitlines()
                if l.strip() and json.loads(l)["event"] == "auth.rejected")
    assert line["reason"] == "expired"
    assert line["path"] == "/v1/connections"


def test_an_accepted_token_does_not_survive_a_traceback(oidc_client, capsys):
    """The path that leaked one the first time this was tested: an exception
    message that interpolated the credential, and the trace repeating it."""
    client, provider = oidc_client
    app = client.app

    @app.get("/v1/_explode")
    def explode(authorization: str = Header(default="")) -> dict:  # pragma: no cover
        raise RuntimeError(f"upload failed for {authorization}")

    token = provider.token(roles=["administrator"])
    capsys.readouterr()
    with TestClient(app, raise_server_exceptions=False,
                    headers=bearer(token)) as inner:
        response = inner.get("/v1/_explode")
    assert response.status_code == 500

    written = capsys.readouterr().out
    for part in token.split("."):
        if len(part) > 8:
            assert part not in written
    failed = next(json.loads(l) for l in written.splitlines()
                  if l.strip() and json.loads(l)["event"] == "request.failed")
    assert "<redacted:jwt>" in failed["exception_message"]
    assert "in explode" in failed["traceback"], "the trace stayed diagnosable"


def test_the_scope_claim_narrows_a_real_token(oidc_client):
    """An operator's token that asked for read scope cannot submit."""
    client, provider = oidc_client
    narrowed = provider.token(roles=["operator"], scope="payments:read")
    # A `403`, not a `404`: the caller holds this connection and lacks the
    # privilege on it, which is the refusal that names what is missing.
    assert submit(client, headers=bearer(narrowed)).status_code == 403
    assert client.get("/auth/me", headers=bearer(narrowed)
                      ).json()["scopes"] == ["payments:read"]


def test_a_discovery_document_naming_another_issuer_is_refused(sqlite_url, provider):
    """The check that keeps every later check meaningful."""
    with serving_provider(provider) as issuer:
        settings = load_settings(
            database_url=sqlite_url, auth_mode="oidc",
            oidc_issuer=issuer.replace("127.0.0.1", "localhost"),
            oidc_client_id=CLIENT_ID, oidc_redirect_uri=REDIRECT_URI)
        app = create_app(settings)
        with TestClient(app) as client:
            response = client.get("/v1/connections",
                                  headers=bearer(provider.token()))
    # The provider is reachable and answers, and its document still does not
    # name the issuer this service was configured for.
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "not_ready"


def test_a_forged_token_is_refused_without_contacting_the_provider(sqlite_url):
    """`401`, not `503`, and no outbound request -- with the provider down.

    Found by pointing the running service at an unreachable issuer: an
    `alg: none` forgery came back `503`, because building a verifier fetched
    the discovery document before the header was ever looked at. Unauthenticated
    traffic must not be able to make this service call out.
    """
    settings = load_settings(
        database_url=sqlite_url, auth_mode="oidc",
        oidc_issuer="http://127.0.0.1:1/never-listening",
        oidc_client_id=CLIENT_ID, oidc_redirect_uri=REDIRECT_URI)
    app = create_app(settings)
    unreachable = StubProvider()
    unreachable.issuer = "http://127.0.0.1:1/never-listening"

    with TestClient(app) as client:
        for token in (unreachable.unsigned_token(), unreachable.confused_token(),
                      "not-a-token"):
            assert client.get("/v1/connections",
                              headers=bearer(token)).status_code == 401
        # A well-formed RS256 token does need the provider, and says so.
        assert client.get("/v1/connections",
                          headers=bearer(unreachable.token())).status_code == 503
    assert app.state.authenticator.directory.fetches == 0


# --- the browser flow -------------------------------------------------------

def begin_login(client, next_page: str = "/") -> dict[str, str]:
    """Follow `/auth/login` one hop and read the authorization request back."""
    response = client.get("/auth/login", params={"next": next_page},
                          follow_redirects=False)
    assert response.status_code == 303, response.text
    query = dict(urllib.parse.parse_qsl(
        urllib.parse.urlparse(response.headers["location"]).query))
    assert query["code_challenge_method"] == "S256"
    assert query["client_id"] == CLIENT_ID
    assert query["redirect_uri"] == REDIRECT_URI
    return query


def finish_login(client, provider, query, *, state=None, nonce=None, code="the-code"):
    provider.authorizations[query["state"]] = query
    provider.next_token_response = {
        "access_token": "opaque", "token_type": "Bearer",
        "id_token": provider.token(nonce=nonce if nonce is not None
                                   else query["nonce"], roles=["operator"]),
    }
    return client.get("/auth/callback", follow_redirects=False,
                      params={"code": code, "state": state or query["state"]})


def test_a_browser_signs_in_and_gets_a_session(oidc_client):
    client, provider = oidc_client
    query = begin_login(client, "/connections")
    response = finish_login(client, provider, query)
    assert response.status_code == 303
    assert response.headers["location"] == "/connections"
    assert oidc.SESSION_COOKIE in response.cookies

    me = client.get("/auth/me").json()
    assert me["method"] == "session"
    assert me["roles"] == ["operator"]
    assert me["role"] == "member", "a provider role that is not admin is a member"
    # The scopes come from the grant, not from the claim: a member with an
    # `operator` grant on this connection may submit at it.
    assert "payments:submit" in me["scopes"]
    assert me["grants"] == [{"connection_id": CONNECTION, "level": "operator",
                             "scopes": me["scopes"]}]
    # The session is a credential in its own right: no bearer token needed.
    assert submit(client).status_code == 202


def test_the_code_flow_does_not_complete_without_pkce(oidc_client):
    """The provider checks the verifier, and this service always sends one.

    Both halves are asserted: the recorded token request carries a
    `code_verifier` that hashes to the challenge the authorization request
    carried, and a provider that insists on it completes the flow.
    """
    client, provider = oidc_client
    query = begin_login(client)
    assert provider.enforce_pkce
    assert finish_login(client, provider, query).status_code == 303

    form = provider.token_requests[-1]
    assert form["grant_type"] == "authorization_code"
    assert oidc.code_challenge(form["code_verifier"]) == query["code_challenge"]
    assert form["code_verifier"] != query["code_challenge"]


def test_a_callback_with_a_mismatched_state_is_refused(oidc_client, capsys):
    """The browser finishing the flow is not the one that started it."""
    client, provider = oidc_client
    query = begin_login(client)
    capsys.readouterr()
    response = finish_login(client, provider, query, state="a-state-of-my-own")
    assert response.status_code == 401
    line = next(l for l in emitted(capsys) if l["event"] == "auth.rejected")
    assert line["reason"] == "state_mismatch"
    assert provider.token_requests == [], "the code was exchanged anyway"


def test_a_callback_with_no_login_cookie_is_refused(oidc_client):
    """A state that exists server-side is still not this browser's state."""
    client, provider = oidc_client
    query = begin_login(client)
    client.cookies.delete(oidc.LOGIN_COOKIE, path="/auth")
    assert finish_login(client, provider, query).status_code == 401


def test_a_replayed_authorization_code_is_refused(oidc_client):
    """The login is claimed once; the second callback finds nothing to claim."""
    client, provider = oidc_client
    query = begin_login(client)
    client.cookies.set(oidc.LOGIN_COOKIE, query["state"], path="/auth")
    assert finish_login(client, provider, query).status_code == 303
    exchanges = len(provider.token_requests)

    client.cookies.set(oidc.LOGIN_COOKIE, query["state"], path="/auth")
    assert finish_login(client, provider, query).status_code == 401
    assert len(provider.token_requests) == exchanges


def test_an_id_token_with_the_wrong_nonce_is_refused(oidc_client, capsys):
    """A valid token for another login is not this login's answer."""
    client, provider = oidc_client
    query = begin_login(client)
    capsys.readouterr()
    response = finish_login(client, provider, query, nonce="a-different-nonce")
    assert response.status_code == 401
    assert next(l for l in emitted(capsys)
                if l["event"] == "auth.rejected")["reason"] == "nonce_mismatch"


def test_an_expired_id_token_does_not_establish_a_session(oidc_client):
    client, provider = oidc_client
    query = begin_login(client)
    provider.authorizations[query["state"]] = query
    provider.next_token_response = {
        "id_token": provider.token(nonce=query["nonce"], iat=now() - 3700,
                                   exp=now() - 3600)}
    assert client.get("/auth/callback", follow_redirects=False,
                      params={"code": "c", "state": query["state"]}
                      ).status_code == 401


def test_the_authorization_code_never_reaches_the_log(oidc_client, capsys):
    """Including the failure path, where the trace is written out."""
    client, provider = oidc_client
    query = begin_login(client)
    provider.authorizations[query["state"]] = query
    provider.token_status = 400
    provider.next_token_response = {"error": "invalid_grant"}
    code = "8e1c4b0f-authorization-code-that-must-not-be-logged"
    capsys.readouterr()

    response = client.get("/auth/callback", follow_redirects=False,
                          params={"code": code, "state": query["state"]})
    # A provider that refuses the exchange is a dependency failing, not a
    # defect here -- and the code the caller sent is gone from the stream even
    # though the trace was written out in full.
    assert response.status_code == 503
    written = capsys.readouterr().out
    assert code not in written
    assert "ProviderUnavailable" in written, "the failure stayed diagnosable"
    assert "the token endpoint answered HTTP 400" in written


def test_next_is_a_relative_path_or_nothing(oidc_client):
    """An open redirect on a login endpoint is a phishing page on our domain."""
    client, provider = oidc_client
    for hostile in ("https://evil.example.test/", "//evil.example.test/",
                    "javascript:alert(1)"):
        assert oidc.safe_redirect(hostile) == "/"
    query = begin_login(client, "https://evil.example.test/steal")
    assert finish_login(client, provider, query).headers["location"] == "/"


def test_logging_out_revokes_the_session(oidc_client):
    client, provider = oidc_client
    finish_login(client, provider, begin_login(client))
    assert client.get("/auth/me").status_code == 200

    stale = client.cookies.get(oidc.SESSION_COOKIE)
    response = client.get("/auth/logout", follow_redirects=False)
    assert response.status_code == 303
    assert "/logout" in response.headers["location"], "the provider is told too"

    # Even a browser that kept the cookie is finished: the row is revoked.
    client.cookies.set(oidc.SESSION_COOKIE, stale, path="/")
    assert client.get("/auth/me").status_code == 401


def test_a_revoked_or_expired_session_is_refused(oidc_client):
    client, provider = oidc_client
    store = client.app.state.authenticator.sessions
    session = store.create(subject="carol", issuer="local", roles=("viewer",))
    client.cookies.set(oidc.SESSION_COOKIE, session.session_id, path="/")
    assert client.get("/auth/me").json()["subject"] == "carol"

    assert store.revoke(session.session_id) is True
    assert client.get("/auth/me").status_code == 401
    assert store.revoke(session.session_id) is False


def test_the_development_login_establishes_a_session_in_a_browser(client):
    """The console needs a browser session without a provider to point at."""
    response = client.get("/auth/login", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert client.get("/auth/me").json()["subject"] == "developer"


# --- on the backend production runs on ---------------------------------------

POSTGRES_URL = os.environ.get("POSTGRES_TEST_URL")
requires_postgres = pytest.mark.skipif(
    POSTGRES_URL is None,
    reason="POSTGRES_TEST_URL is not set: no PostgreSQL server was reached, so "
           "the single-use claim was not proved on the backend that has a "
           "mechanism for it")


@pytest.fixture
def postgres_engine():
    settings = load_settings(database_url=POSTGRES_URL)
    engine = db.build_engine(settings)
    reset_database(engine)
    db.migrate(engine)
    yield engine
    reset_database(engine)
    engine.dispose()


@requires_postgres
def test_a_login_is_claimed_exactly_once_under_concurrency(postgres_engine):
    """Eight browsers replaying one authorization code; one of them wins.

    The single-use property is a conditional `UPDATE`, and a conditional
    `UPDATE` is only worth anything on a backend that can serialise it. SQLite
    takes one write lock over the whole file and would pass this by accident.
    """
    store = oidc.LoginStore(postgres_engine, ttl_seconds=600)
    state, nonce, verifier = store.begin(redirect_to="/orders")

    outcomes: list[str] = []
    lock = threading.Lock()

    def claim() -> None:
        try:
            claimed = store.claim(state)
        except Exception as exc:
            result = type(exc).__name__
        else:
            result = f"claimed:{claimed['nonce']}"
        with lock:
            outcomes.append(result)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: claim(), range(8)))

    won = [o for o in outcomes if o.startswith("claimed:")]
    assert won == [f"claimed:{nonce}"], outcomes
    assert outcomes.count("AuthenticationFailed") == 7


@requires_postgres
def test_a_session_round_trips_and_revokes_on_postgres(postgres_engine):
    store = oidc.SessionStore(postgres_engine, ttl_minutes=60)
    session = store.create(subject="dana", issuer="https://id.example.test",
                           roles=("operator",), display_name="Dana")
    assert store.lookup(session.session_id).roles == ("operator",)
    assert store.revoke(session.session_id) is True
    with pytest.raises(AuthenticationFailed):
        store.lookup(session.session_id)


@requires_postgres
def test_expired_logins_are_purged(postgres_engine):
    store = oidc.LoginStore(postgres_engine, ttl_seconds=600)
    store.begin()
    store.begin()
    assert store.purge(before=datetime.datetime.now(datetime.timezone.utc)
                       + datetime.timedelta(hours=1)) == 2


# --- what this deployment calls an administrator ------------------------------
#
# A directory is not reshaped to suit one service, so the two names this service
# used to insist on are configuration now. The tests that matter are the ones
# about what does *not* change: the defaults, and the local accounts.

def test_the_default_names_are_the_ones_this_service_always_accepted(settings):
    """Nothing breaks on upgrade, which is the whole constraint."""
    assert settings.admin_role_names == {"admin", "administrator"}
    assert settings.member_role_names == {"member", "operator", "viewer", "auditor"}


def test_a_configured_group_makes_an_administrator(settings):
    """The point: `painfree-admins` in a directory, not a word we chose."""
    configured = settings.model_copy(
        update={"oidc_admin_role": "painfree-admins, CN=Treasury Ops"})

    assert identity.role_for(["painfree-admins"],
                             configured.admin_role_names) is identity.Role.admin
    assert identity.role_for(["CN=Treasury Ops"],
                             configured.admin_role_names) is identity.Role.admin
    # And the names it replaced stop conferring anything, which is the reason
    # to configure it at all.
    assert identity.role_for(["admin"],
                             configured.admin_role_names) is identity.Role.member


def test_an_unmapped_name_is_still_a_member_and_still_reported(settings):
    """An unmapped role grants nothing and says so, rather than failing closed."""
    configured = settings.model_copy(update={"oidc_admin_role": "painfree-admins"})

    assert identity.role_for(["whatever"],
                             configured.admin_role_names) is identity.Role.member
    assert identity.unknown_roles(["whatever"],
                                  configured.known_role_names) == ("whatever",)
    # A configured member name is recognised, so it is not logged as noise.
    assert identity.unknown_roles(["viewer"], configured.known_role_names) == ()


def test_the_names_are_parsed_forgivingly(settings):
    """Somebody will type a trailing comma and a space, and should be right."""
    configured = settings.model_copy(
        update={"oidc_admin_role": " admins , ,ops,"})

    assert configured.admin_role_names == {"admins", "ops"}


# --- what the provider's roles claim is allowed to become --------------------
#
# A real directory is not built for one service. Everything below is about the
# gap between what a provider sends and what this deployment is willing to keep,
# and each was found on a live deployment against an organisation-wide realm
# rather than reasoned about here.

def test_a_token_carrying_no_roles_at_all_says_so(oidc_client, capsys):
    """The most likely first-run outcome, and it had been the quietest one.

    Keycloak's realm-roles mapper ships with "Add to ID token" off, and this
    service reads the id_token for browser sessions. So a correctly assigned
    administrator signs in, successfully, holding nothing -- and until this line
    existed the only evidence was `"roles": []` inside an info-level line that
    looked like every other successful login.
    """
    client, provider = oidc_client
    capsys.readouterr()
    # `claims()` drops a None, so this token carries no roles claim at all --
    # which is the shape a mapper that was never enabled produces.
    assert client.get("/auth/me",
                      headers=bearer(provider.token(roles=None))).status_code == 200

    line = next(json.loads(l) for l in capsys.readouterr().out.splitlines()
                if l.strip() and json.loads(l)["event"] == "auth.no_roles_in_token")
    assert line["level"] == "warning"
    # The claim path is configuration, so it can be quoted back: an operator who
    # reads this knows to look at the mapper rather than at their directory.
    assert line["claim"] == "roles"
    assert line["present"] is False
    assert "Add to ID token" in line["reason"]


def test_an_empty_roles_claim_is_reported_as_present_but_empty(oidc_client, capsys):
    """A claim that arrived carrying nothing is a different fault from no claim.

    One says the mapper is missing; the other says it ran and matched nobody.
    Both leave the caller holding nothing, so both warn, and the field that
    tells them apart is the one an operator needs.
    """
    client, provider = oidc_client
    capsys.readouterr()
    assert client.get("/auth/me",
                      headers=bearer(provider.token(roles=[]))).status_code == 200

    line = next(json.loads(l) for l in capsys.readouterr().out.splitlines()
                if l.strip() and json.loads(l)["event"] == "auth.no_roles_in_token")
    assert line["present"] is True


def test_roles_this_deployment_does_not_map_are_counted_and_never_kept(
        oidc_client, capsys):
    """The finding: an org-wide realm sent 34 names, of which two meant anything.

    Keeping the rest cost three things and bought none -- a warning that fired on
    every login and so stopped being a diagnostic, a session row of hundreds of
    bytes that decide nothing, and an audit trail accumulating a durable map of
    who may do what across an entire organisation. This service needs one bit
    from that claim: which of its own roles are present.
    """
    client, provider = oidc_client
    others = ["ena-foerderung-manage", "wupp-payout", "ena-abacus-accounting",
              "enalytics-admin", "offline_access", "uma_authorization"]
    capsys.readouterr()
    me = client.get("/auth/me",
                    headers=bearer(provider.token(roles=["operator", *others])))
    assert me.status_code == 200

    body = me.json()
    # The one it maps survives; the six that belong to somebody else's
    # authorization model do not, anywhere.
    assert body["roles"] == ["operator"]
    assert body["unrecognised_role_count"] == len(others)
    written = capsys.readouterr().out
    for name in others:
        assert name not in written, f"{name} reached the log"

    line = next(json.loads(l) for l in written.splitlines()
                if l.strip() and json.loads(l)["event"] == "auth.unmapped_roles")
    # Info, not warning: a shared realm carrying other people's roles beside
    # ours is the ordinary case, and a warning on every login is not a
    # diagnostic. The count is what is worth reading.
    assert line["level"] == "info"
    assert line["unrecognised_role_count"] == len(others)
    assert "roles" not in line


def test_names_that_are_all_unrecognised_still_warn(oidc_client, capsys):
    """This is the case that actually indicates a misconfigured role name, so
    it is the one that keeps `warning`: the directory answered, and none of it
    was ours. The caller is a member holding nothing and the console is empty,
    which is the symptom this line exists to explain."""
    client, provider = oidc_client
    capsys.readouterr()
    assert client.get(
        "/auth/me",
        headers=bearer(provider.token(roles=["painfree-admins"]))).status_code == 200

    line = next(json.loads(l) for l in capsys.readouterr().out.splitlines()
                if l.strip() and json.loads(l)["event"] == "auth.unmapped_roles")
    assert line["level"] == "warning"
    assert line["unrecognised_role_count"] == 1
    # What this deployment *would* have accepted, so the fix is one comparison
    # rather than a search through the source.
    assert "administrator" in line["known"]


def test_an_administrator_name_is_never_what_gets_dropped(oidc_client):
    """The narrowing must not be able to cost anybody a privilege. An admin name
    is one this deployment maps by definition, so it survives by construction --
    but it is the failure that would matter, so it is asserted."""
    client, provider = oidc_client
    body = client.get("/auth/me", headers=bearer(provider.token(
        roles=["ena-utm", "administrator", "librechat-user"]))).json()

    assert body["roles"] == ["administrator"]
    assert body["role"] == "admin"
    assert body["unrecognised_role_count"] == 2
