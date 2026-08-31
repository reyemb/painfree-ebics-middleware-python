"""The developer page, and the three things on it that must not be hand-written.

Every claim this page makes is a claim about the running service, and the wrong
way to make each of them is a literal in a template that was true once:

**The scope table comes from `painfree.identity`.** A scope added to the model
appears without anyone editing markup. The model was rewritten later -- two
roles and two per-connection grant levels -- and the tables followed without a
template edit, which is what this file checks.

**The route table comes from the router.** `requires(...)` records what it
demands, so the answer to *why did I get a 403* is read off the dependency the
server actually enforces.

**The page itself demands no privilege.** It is the page a caller who holds
nothing reads to find out what they would have needed, and putting it behind a
scope leaves that person with nothing to read.

It must also say, in words, that there is no painfree-issued API token -- the
absence of a "create token" button is not an explanation.
"""

from __future__ import annotations

import enum

import pytest
from fastapi.testclient import TestClient

from painfree import identity
from painfree.app import create_app
from painfree.authn import PUBLIC_PATHS
from painfree.identity import LEVEL_SCOPES, ROLE_SCOPES, Level, Role, Scope
from painfree.ui import reference
from tests.conftest import dev_credentials

BROWSER = {"accept": "text/html,application/xhtml+xml"}


def _headers(subject: str, roles: str) -> dict[str, str]:
    return {**dev_credentials(subject, roles), **BROWSER}


@pytest.fixture
def client(settings):
    app = create_app(settings)
    with TestClient(app) as running:
        yield running


@pytest.fixture
def app(settings):
    return create_app(settings)


# --- who may read it --------------------------------------------------------

@pytest.mark.parametrize("roles", ["member", "admin", "administrator",
                                   "operator", "nonsense-role"])
def test_any_authenticated_caller_reaches_the_page(client, roles):
    """Including one whose role this service has no mapping for, and who
    therefore holds nothing at all -- the caller most in need of it."""
    response = client.get("/ui/api", headers=_headers("someone", roles))
    assert response.status_code == 200


def test_an_unauthenticated_browser_is_still_sent_to_sign_in(client):
    response = client.get("/ui/api", headers=BROWSER, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/auth/login")


def test_a_caller_with_no_scopes_is_told_that_is_why(client):
    body = client.get("/ui/api", headers=_headers("nobody", "nonsense-role")).text
    assert "none, which is why you are being refused" in body


# --- the scope table --------------------------------------------------------

def test_every_scope_in_the_model_is_on_the_page(client):
    body = client.get("/ui/api", headers=_headers("ann", "administrator")).text
    for scope in Scope:
        assert scope.value in body


def test_a_scope_added_to_the_model_appears_without_touching_a_template(
        client, monkeypatch):
    """The generation claim, made falsifiable.

    `Scope` is rebuilt with one extra member and the page is rendered again. No
    template, no view and no fixture mentions the new name, and the row for it
    appears anyway.
    """
    headers = _headers("ann", "admin")
    assert "ledger:read" not in client.get("/ui/api", headers=headers).text

    extended = enum.Enum(  # type: ignore[misc]
        "Scope", {**{member.name: member.value for member in Scope},
                  "ledger_read": "ledger:read"}, type=str)
    granted = {role: (frozenset(scopes) | {extended.ledger_read}
                      if role is Role.admin else scopes)
               for role, scopes in ROLE_SCOPES.items()}
    # And the grant levels, which are the other half of the model: a scope
    # added to one level has to appear in that column too.
    levelled = {level: (frozenset(scopes) | {extended.ledger_read}
                        if level is Level.operator else scopes)
                for level, scopes in LEVEL_SCOPES.items()}
    monkeypatch.setattr(reference, "Scope", extended)
    monkeypatch.setattr(reference, "ROLE_SCOPES", granted)
    monkeypatch.setattr(reference, "LEVEL_SCOPES", levelled)

    body = client.get("/ui/api", headers=headers).text
    assert "ledger:read" in body
    assert {row["scope"]: row["levels"] for row
            in reference.scope_catalogue()}["ledger:read"] == ["operator"]


def test_each_scope_carries_the_sentence_written_beside_it_in_the_model():
    """The prose is the docstring under the enum member, recovered from source.

    Python discards it -- a string after an enum member is an expression
    statement -- so this is the assertion that the recovery still works, rather
    than silently degrading to a table of bare names.
    """
    described = reference.scope_descriptions()
    assert set(described) == {scope.value for scope in Scope}
    assert described["payments:submit"].startswith(
        "Submit a payment instruction")


def test_the_role_matrix_is_the_model_s_own(app):
    catalogue = {row["role"]: set(row["scopes"])
                 for row in reference.role_catalogue()}
    assert catalogue == {role.value: {scope.value for scope in scopes}
                         for role, scopes in ROLE_SCOPES.items()}


def test_the_page_marks_the_scopes_the_reader_holds(client):
    """The fastest answer to "why did I get a 403" is the reader's own row."""
    catalogue = {row["scope"]: row["held"] for row in reference.scope_catalogue(
        _principal("olive", ("acme", Level.operator)))}
    assert catalogue["payments:submit"] is True
    # Held on a connection, and still not held: no grant level carries it.
    assert catalogue["webhooks:manage"] is False


def test_the_level_matrix_says_which_scopes_no_grant_can_carry(app):
    """The row that matters: what a member cannot be given."""
    catalogue = {row["scope"]: row for row in reference.scope_catalogue()}
    assert catalogue["webhooks:manage"]["admin_only"] is True
    assert catalogue["connections:write"]["admin_only"] is True
    assert catalogue["payments:submit"]["levels"] == ["operator"]
    assert catalogue["payments:read"]["levels"] == ["viewer", "operator"]
    assert {row["level"] for row in reference.level_catalogue()} == {
        level.value for level in Level}


def _principal(subject: str, *grants):
    from painfree.identity import build_principal
    return build_principal(subject=subject, issuer="test", method="session",
                           roles=["member"], grants=grants)


# --- the route table --------------------------------------------------------

def test_every_documented_route_is_listed_with_the_scope_it_demands(app):
    rows = {(row["method"], row["path"]): row["scopes"]
            for row in reference.protected_routes(app)}
    assert rows[("POST", "/v1/connections/{connection_id}/payments")] == [
        "payments:submit"]
    assert rows[("GET", "/v1/orders/{order_id}")] == ["payments:read"]
    assert rows[("GET", "/v1/audit")] == ["audit:read"]
    assert rows[("POST", "/v1/webhooks")] == ["webhooks:manage"]
    assert rows[("POST", "/v1/schedules/{schedule_id}/run")] == [
        "schedules:manage"]


def test_the_route_table_sees_the_routes_behind_an_included_router(app):
    """The regression this cost an hour: FastAPI nests included routers, and a
    single pass over `app.routes` reports that `/v1` does not exist."""
    paths = {row["path"] for row in reference.protected_routes(app)}
    assert len([path for path in paths if path.startswith("/v1/")]) > 15


#: Routes an authenticated caller reaches whatever they hold, each with the
#: reason. Three, and every one of them is a decision with an ADR behind it.
SCOPELESS = {
    # The caller's own claims, which their provider gave them.
    ("GET", "/auth/me"),
    # What this caller has access to, which is the one question a caller with
    # no access has to be able to ask. It answers with an empty list rather
    # than a `403`, so a member with no grants reads an empty console instead
    # of a refused one.
    ("GET", "/v1/connections"),
}

#: Grant management demands no *scope*, and is not scopeless: it is refused to
#: anybody who is not an `admin` by a dependency of its own, because a
#: privilege a grant could carry is a privilege its holder could grant
#: themselves.
ADMIN_ONLY = {
    ("GET", "/v1/grants"), ("PUT", "/v1/grants"),
    ("GET", "/v1/grants/subjects"),
    ("PATCH", "/v1/grants/{subject}/{connection_id}"),
    ("DELETE", "/v1/grants/{subject}/{connection_id}"),
    # Issuing deployment-wide read is the same kind of decision and is guarded
    # the same way: by a role, because a scope is something a grant can carry.
    ("GET", "/v1/oversight"), ("PUT", "/v1/oversight"),
    ("DELETE", "/v1/oversight/{subject}"),
    # And so is deciding who may sign in at all. Creating an administrator
    # account *is* granting administration, one step removed, so a scope that
    # could do it is a scope a grant could carry.
    ("GET", "/v1/accounts"), ("PUT", "/v1/accounts"),
    ("PATCH", "/v1/accounts/{subject}"),
    ("DELETE", "/v1/accounts/{subject}"),
    ("POST", "/v1/accounts/{subject}/password"),
    ("GET", "/v1/lockouts"), ("DELETE", "/v1/lockouts/{scope}/{value}"),
}


def test_only_the_endpoints_that_should_be_scopeless_are(app):
    """Deny-by-default, made visible: anything here is reachable by every
    authenticated caller whatever they were granted."""
    listed = {(row["method"], row["path"])
              for row in reference.unprotected(app, PUBLIC_PATHS)}
    assert listed == SCOPELESS


def test_a_route_that_demands_a_role_is_reported_as_demanding_it(app):
    """The page said "any authenticated caller" beside grant management once.

    It was rendered in a browser and read, which is how it was found. A page
    whose whole justification is that it cannot drift from the model
    must not describe the five endpoints that decide who may move money as
    reachable by everybody.
    """
    rows = {(row["method"], row["path"]): row for row
            in reference.protected_routes(app, PUBLIC_PATHS)}
    for key in ADMIN_ONLY:
        assert rows[key]["role"] == "admin", key
        assert rows[key]["scopes"] == [], f"{key} demands a role, not a scope"
    # And every other route reports no role, so the marker means something.
    assert {key for key, row in rows.items() if row["role"]} == ADMIN_ONLY


def test_the_grant_routes_are_refused_to_a_member(client):
    """The page says `admin` only; the server is what makes it true."""
    for method, path in sorted(ADMIN_ONLY):
        target = path.replace("{subject}", "someone").replace(
            "{connection_id}", "acme")
        response = client.request(method, target, json={"level": "viewer"},
                                  headers=_headers("olive", "member"))
        assert response.status_code == 403, f"{method} {target}"


def test_the_page_says_admin_only_beside_those_routes(client):
    """Off the rendered page, as the reader of it sees it."""
    body = client.get("/ui/api", headers=_headers("ann", "admin")).text
    assert "a role, not a scope: no grant can carry it" in body
    assert "/v1/grants/{subject}/{connection_id}" in body


def test_a_public_path_is_not_described_as_needing_a_credential(app, client):
    """`/auth/login` is the endpoint whose purpose is to be reachable before
    there is an identity. Labelling it "any authenticated caller" would be a
    false statement about the one route that cannot be one."""
    rows = {row["path"]: row for row in
            reference.protected_routes(app, PUBLIC_PATHS)}
    assert rows["/auth/login"]["public"] is True
    assert rows["/healthz"]["public"] is True
    assert rows["/auth/me"]["public"] is False
    body = client.get("/ui/api", headers=_headers("ann", "administrator")).text
    assert "no credential: an orchestrator probe" in body


def test_the_console_s_own_pages_are_not_in_the_contract(app):
    assert not [row for row in reference.protected_routes(app)
                if row["path"].startswith("/ui")]


# --- what the page has to say -----------------------------------------------

def test_the_openapi_documents_are_linked(client):
    body = client.get("/ui/api", headers=_headers("ann", "administrator")).text
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert f'href="{path}"' in body


def test_the_page_says_there_is_no_painfree_issued_token(client):
    """Said plainly, so nobody hunts for a button that will never exist."""
    body = client.get("/ui/api", headers=_headers("ann", "administrator")).text
    assert "painfree issues no tokens of its own" in body
    assert "JWT bearer token from the configured OIDC provider" in body


def test_the_page_shows_the_caller_their_own_identity(client):
    body = client.get("/ui/api", headers=_headers("olive", "operator")).text
    assert "olive" in body
    assert "payments:submit" in body


def test_the_page_never_shows_a_secret(sqlite_url):
    """It renders the provider configuration, and a client secret is part of
    that configuration. It is not part of the page."""
    from painfree.config import load_settings
    secret = "super-secret-client-value"
    configured = load_settings(
        database_url=sqlite_url,
        oidc_issuer="https://id.example.test/realms/painfree",
        oidc_client_id="painfree", oidc_client_secret=secret,
        oidc_redirect_uri="https://painfree.example.test/auth/callback")
    with TestClient(create_app(configured)) as client:
        body = client.get("/ui/api", headers=_headers("ann", "administrator")).text
    assert "id.example.test" in body      # the issuer is shown, on purpose
    assert secret not in body
    assert "**" not in body.split("Roles claim")[0].split("Client id")[-1]
