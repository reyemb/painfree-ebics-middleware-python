"""Deployment-wide read-only oversight, written as an attacker.

Oversight is one grant that names no bank connection: every scope called
`:read`, on every connection and on the audit rows that name none, and nothing
that changes anything. Its whole reason to exist is that somebody should be
able to review **who can move money at which bank** without being able to do
it, so the interesting half of this file is the negative half.

There is no reference implementation of an authorisation model and none was
invented. What stands in for one is that every assertion below is a request
issued at the running application, and that the routes attacked are **read off
the router** rather than typed out here.

Five claims, and each is one a screenshot cannot make:

**The reach is real.** An oversight holder reads every connection's orders,
statements, schedules, webhook endpoints and audit trail -- including the rows
that name no connection, which is what `viewer` on every connection could never
give -- against connections nobody ever granted them individually.

**Every write route in the application refuses it.** Not a sample and not a
list: :func:`write_routes` walks the app's own router and yields every route
that is a `POST`/`PUT`/`PATCH`/`DELETE`, or demands a scope outside
:data:`painfree.identity.OVERSIGHT_SCOPES`, or demands a role. Adding a route
next month puts it in this test without anybody remembering to.

**The escalation is closed.** An oversight holder cannot grant -- not a
connection, not oversight, not to somebody else and not to themselves. Grant
management is not a scope, so there is nothing a grant could carry that would
confer it, and this file proves the property holds for the new grant too.

**Only an administrator issues it.** Not a member, and -- the case worth
naming -- not another oversight holder.

**The old word is still just a word.** A token claiming `auditor` produces a
plain member with no oversight. `0012` measured what that role lost and refused
to widen it silently; `0013` builds the destination and still does not.
"""

from __future__ import annotations

import datetime as _dt

import pytest
from fastapi.testclient import TestClient
from fastapi.routing import APIRoute
from sqlalchemy import insert, select

from conftest import (dev_credentials, grant, grant_oversight, payment_body,
                      revoke_oversight)
from painfree import db, wrapping
from painfree.access import require, restrict, visible
from painfree.api import IDEMPOTENCY_HEADER
from painfree.app import create_app
from painfree.authn import PUBLIC_PATHS
from painfree.connections import ConnectionRegistry
from painfree.errors import ForbiddenError
from painfree.identity import (OVERSIGHT_SCOPES, WRITE_SCOPES, Level, Scope,
                               build_principal)
from painfree.schema import bank_connection, oversight_grant, payment_order, statement

BROWSER = {"accept": "text/html,application/xhtml+xml"}

#: Two banks. `WATCHER` is granted **neither** of them individually, which is
#: what makes reading both of them interesting.
ALPHA = "alpha-bank"
BETA = "beta-bank"

#: The reviewer, the operator they review, and the administrator.
WATCHER = "wanda"
OLIVE = "olive"
ROOT = "root"


def member(subject: str, **extra) -> dict[str, str]:
    return {**dev_credentials(subject, "member"), **extra}


def admin(**extra) -> dict[str, str]:
    return {**dev_credentials(ROOT, "admin"), **extra}


def watcher(**extra) -> dict[str, str]:
    return member(WATCHER, **extra)


# --- the world --------------------------------------------------------------

def _seed(engine, connection_id: str) -> None:
    """One connection with an order and a statement on it."""
    now = _dt.datetime.now(_dt.timezone.utc)
    ConnectionRegistry(engine).register(
        connection_id, host_id=f"HOST-{connection_id}", partner_id="PARTNER1",
        user_id="USER1", host_url=f"https://{connection_id}.test/ebics")
    with engine.begin() as db_:
        db_.execute(bank_connection.update().where(
            bank_connection.c.connection_id == connection_id).values(
                key_state="ready", ini_sent=True, hia_sent=True))
        db_.execute(insert(payment_order).values(
            order_id=f"ord_{connection_id}", connection_id=connection_id,
            idempotency_key=f"seed-{connection_id}",
            request_fingerprint="0" * 64, state="submitted",
            msg_id=f"MSG-{connection_id}", payment_information_id="PMT1",
            message_type="pain.001.001.09", document=b"<Document/>",
            transaction_count=1, control_sum="10.00", currency="CHF",
            requested_execution_date="2026-09-01", accepted_at=now,
            updated_at=now))
        db_.execute(insert(statement).values(
            statement_id=f"stm_{connection_id}", connection_id=connection_id,
            message_type="camt.053", document_key=f"doc-{connection_id}",
            content_hash="1" * 64, entry_count=1,
            payload={"messageType": "camt.053"}, ingested_at=now))


@pytest.fixture
def world(custody_settings):
    """Two banks, an operator on one, an oversight holder on neither.

    The subscriptions and schedules are registered through the application as
    the administrator, so what the reviewer later reads are rows this service
    itself wrote. One subscription names **no** connection: the endpoint that
    receives every connection's payment events, which is exactly the thing a
    reviewer of the deployment has to be able to see and a member never can.
    """
    engine = db.build_engine(custody_settings)
    db.migrate(engine)
    wrapping.publish(engine, custody_settings.custody_key())
    _seed(engine, ALPHA)
    _seed(engine, BETA)
    app = create_app(custody_settings)
    with TestClient(app) as client:
        for index, connection_id in enumerate((ALPHA, BETA)):
            assert client.post("/v1/webhooks", headers=admin(**{
                IDEMPOTENCY_HEADER: f"seed-wh-{index}"}), json={
                    "url": f"https://consumer.test/{connection_id}",
                    "event_types": ["order.accepted"],
                    "connection_id": connection_id}).status_code == 201
            assert client.post("/v1/schedules", headers=admin(), json={
                "connection_id": connection_id, "service_name": "EOP",
                "msg_name": "camt.053", "msg_version": "08",
                "cadence_seconds": 3600}).status_code == 201
        assert client.post("/v1/webhooks", headers=admin(**{
            IDEMPOTENCY_HEADER: "seed-wh-global"}), json={
                "url": "https://consumer.test/everything",
                "event_types": ["order.accepted"]}).status_code == 201
        # The person being reviewed, and the person doing the reviewing. Note
        # that `wanda` holds no `connection_grant` row at all.
        grant(app, OLIVE, ALPHA, "operator")
        grant_oversight(app, WATCHER)
        yield client, app, _ids(client)
    engine.dispose()


def _ids(client) -> dict[str, str]:
    found: dict[str, str] = {}
    for row in client.get("/v1/schedules", headers=admin()).json()["schedules"]:
        found[f"schedule:{row['connection_id']}"] = row["schedule_id"]
    for row in client.get("/v1/webhooks", headers=admin()).json()["webhooks"]:
        found[f"webhook:{row['connection_id'] or 'global'}"] = \
            row["subscription_id"]
    return found


# --- the reach --------------------------------------------------------------

def test_oversight_reads_every_connection_it_was_never_granted(world):
    """Both banks, and `wanda` holds a grant on neither of them."""
    client, _, _ = world
    assert client.get("/v1/grants?subject=wanda",
                      headers=admin()).json()["grants"] == []

    listed = client.get("/v1/connections", headers=watcher()).json()
    assert {row["connection_id"] for row in listed["connections"]} == \
        {ALPHA, BETA}
    for connection_id in (ALPHA, BETA):
        assert client.get(f"/v1/orders/ord_{connection_id}",
                          headers=watcher()).status_code == 200
        assert client.get(f"/ui/statements/stm_{connection_id}",
                          headers=watcher(**BROWSER)).status_code == 200
        assert client.get(f"/ui/connections/{connection_id}",
                          headers=watcher(**BROWSER)).status_code == 200
    for path, key in (("/v1/schedules", "schedules"),
                      ("/v1/webhooks", "webhooks")):
        rows = client.get(path, headers=watcher()).json()[key]
        assert {row["connection_id"] for row in rows} >= {ALPHA, BETA}, path


def test_oversight_sees_the_webhook_endpoint_that_names_no_connection(world):
    """`webhooks:read`, which a `viewer` grant on every bank would not carry.

    The connection-less subscription receives *every* connection's payment
    events, so it is the one endpoint a reviewer most needs to know about --
    and the one no per-connection grant can ever name.
    """
    client, _, ids = world
    rows = client.get("/v1/webhooks", headers=watcher()).json()["webhooks"]
    assert sum(1 for row in rows if row["connection_id"] is None) == 1
    assert client.get(f"/v1/webhooks/{ids['webhook:global']}",
                      headers=watcher()).status_code == 200
    # A member holding a connection is still refused it, unchanged by `D-033`.
    assert client.get(f"/v1/webhooks/{ids['webhook:global']}",
                      headers=member(OLIVE)).status_code == 404


def test_oversight_reads_the_audit_rows_that_name_no_connection(world):
    """The rows the grant model could give nobody but an admin: sign-ins,
    starts, grants.

    This is the whole gap oversight closes. A member granted `viewer` on every
    connection sees each bank's trail and never learns that somebody was
    granted the ability to move money at one, because a grant row for a
    *connection-less* decision -- and every sign-in -- names none.
    """
    client, _, _ = world
    events = client.get("/v1/audit?limit=200",
                        headers=watcher()).json()["events"]
    actions = {event["action"] for event in events}
    assert "service.started" in actions
    assert "access.granted" in actions, "the grant that made olive an operator"
    assert "access.oversight_granted" in actions
    assert any(event["connection_id"] is None for event in events)
    assert {event["connection_id"] for event in events} >= {None, ALPHA, BETA}
    # The same page in the console, and the filters it offers are the whole
    # deployment's rather than one bank's.
    page = client.get("/ui/audit", headers=watcher(**BROWSER))
    assert page.status_code == 200
    assert "service.started" in page.text
    # And the member is still bounded exactly as their grants leave them.
    theirs = client.get("/v1/audit?limit=200",
                        headers=member(OLIVE)).json()["events"]
    assert {event["connection_id"] for event in theirs} == {ALPHA}


# --- every write route, enumerated from the router --------------------------

#: What a path parameter is filled with. A route naming a parameter that is not
#: here fails :func:`test_every_write_route_refuses_an_oversight_holder` rather
#: than being quietly skipped, so a new kind of id cannot slip past unattacked.
PARAMETERS = {
    "connection_id": ALPHA,
    "order_id": f"ord_{ALPHA}",
    "statement_id": f"stm_{ALPHA}",
    "subject": OLIVE,
    # The key-lifecycle verb. A real one, so the refusal is the guard's and not
    # a router 404 on an unknown action.
    "action": "create_keys",
    # `DELETE /v1/lockouts/{scope}/{value}` -- clearing a throttled account is
    # `admin` alone like every other decision about who may sign in, so it is
    # one more write route an oversight holder is refused rather than an
    # exception to the rule.
    "scope": "subject",
    "value": OLIVE,
}

#: Filled from the fixture, because they are minted by the service.
SEEDED = {"schedule_id": f"schedule:{ALPHA}",
          "subscription_id": f"webhook:{ALPHA}"}


def write_routes(app):
    """Every route in the application that changes something.

    Three ways of being one, and a route only has to be one of them:

    - it is a `POST`, `PUT`, `PATCH` or `DELETE`;
    - it demands a scope outside :data:`OVERSIGHT_SCOPES` -- which catches the
      `GET` pages that are really the first half of a write, like the form at
      `/ui/webhooks/new` and the replay confirmation;
    - it demands a **role**, which is how grant management is guarded, because
      a privilege a grant could carry is one its holder could grant themselves.

    Read off the router, so this is the application's own answer rather than a
    list in this file that stops being true the week somebody adds a route.
    """
    for route in _routes(app):
        demanded = _demanded(route)
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            if route.path in PUBLIC_PATHS:
                continue
            if not (method in ("POST", "PUT", "PATCH", "DELETE")
                    or demanded & WRITE_SCOPES
                    or _demanded_role(route)):
                continue
            yield method, route.path


def _routes(app):
    found, pending = [], list(app.routes)
    while pending:
        route = pending.pop()
        if isinstance(route, APIRoute):
            found.append(route)
        nested = getattr(route, "routes", None)
        if nested is None:
            nested = getattr(getattr(route, "original_router", None),
                             "routes", None)
        pending.extend(nested or [])
    return found


def _demanded(route) -> set[Scope]:
    found: set[Scope] = set()
    pending = [route.dependant]
    while pending:
        dependant = pending.pop()
        found |= set(getattr(dependant.call, "required_scopes", ()) or ())
        pending.extend(dependant.dependencies)
    return found


def _demanded_role(route) -> str | None:
    pending = [route.dependant]
    while pending:
        dependant = pending.pop()
        role = getattr(dependant.call, "required_role", None)
        if role:
            return str(role)
        pending.extend(dependant.dependencies)
    return None


def _fill(path: str, ids: dict[str, str]) -> str:
    """Substitute every path parameter, or say which one is unaccounted for."""
    filled = path
    for name in _parameters(path):
        if name in SEEDED:
            value = ids[SEEDED[name]]
        else:
            assert name in PARAMETERS, (
                f"{path} names the path parameter {{{name}}}, which this test "
                "does not know how to fill; add it to PARAMETERS so the route "
                "is attacked rather than skipped")
            value = PARAMETERS[name]
        filled = filled.replace(f"{{{name}}}", value)
    return filled


def _parameters(path: str) -> list[str]:
    return [part[1:-1] for part in path.strip("/").split("/")
            if part.startswith("{") and part.endswith("}")]


#: A form body wide enough that no console route is refused for the wrong
#: reason. It is never reached: every dependency runs before the body is bound.
FORM = ("confirm=revoke&subject=x&level=viewer&url=https://x.test/"
        "&service_name=EOP&msg_name=camt.053&cadence=1&cadence_unit=hours"
        "&host_url=https://x.test/&event:order.accepted=on")


def _attack(client, method: str, path: str, ids: dict[str, str], headers):
    target = _fill(path, ids)
    if path.startswith("/ui"):
        return client.request(method, target, headers={
            **headers, **BROWSER,
            "content-type": "application/x-www-form-urlencoded"}, content=FORM)
    return client.request(method, target, headers={
        **headers, IDEMPOTENCY_HEADER: "oversight-attack-0001"}, json={})


def test_the_write_route_enumeration_finds_the_routes_it_should(world):
    """A guard on the guard: an enumeration that found nothing would pass.

    The count is not asserted -- it moves whenever a route is added, which is
    the point -- but the shape is: the payment route, a console form and grant
    management are all in it, and no public path is.
    """
    _, app, _ = world
    found = set(write_routes(app))
    assert ("POST", "/v1/connections/{connection_id}/payments") in found
    assert ("GET", "/ui/webhooks/new") in found, \
        "a GET that is the first half of a write is a write route here"
    assert ("PUT", "/v1/grants") in found
    assert ("PUT", "/v1/oversight") in found
    assert ("GET", "/ui/access") in found, "guarded by a role, not by a scope"
    assert not any(path in PUBLIC_PATHS for _, path in found)
    assert len(found) > 30, f"the enumeration collapsed: {sorted(found)}"


def test_every_write_route_refuses_an_oversight_holder(world):
    """The negative half of the grant, over the application's whole write surface.

    `wanda` can see every one of these connections, so a refusal here is a
    `403` naming what is missing rather than the `404` a member gets -- there is
    nothing to hide from somebody who is allowed to read the resource. What
    there is, is nothing they can do to it.
    """
    client, app, ids = world
    reached = []
    for method, path in sorted(write_routes(app)):
        response = _attack(client, method, path, ids, watcher())
        if response.status_code != 403:
            reached.append(f"{method} {path} -> {response.status_code}")
    assert not reached, (
        "an oversight grant is read-only and these routes did not refuse it: "
        + "; ".join(reached))


def test_nothing_the_write_routes_could_have_done_happened(world):
    """The other half of the assertion above: no state changed under it.

    A route that answered `403` and had already written something would pass
    the test above. So the world is counted before and after.
    """
    client, app, ids = world
    def census():
        return {
            "connections": client.get("/v1/connections",
                                      headers=admin()).json()["connections"],
            "order": client.get(f"/v1/orders/ord_{ALPHA}",
                                headers=admin()).json()["state"],
            "webhooks": len(client.get("/v1/webhooks",
                                       headers=admin()).json()["webhooks"]),
            "schedules": len(client.get("/v1/schedules",
                                        headers=admin()).json()["schedules"]),
            "grants": len(client.get("/v1/grants",
                                     headers=admin()).json()["grants"]),
            "oversight": len(client.get("/v1/oversight",
                                        headers=admin()).json()["oversight"]),
        }
    before = census()
    for method, path in sorted(write_routes(app)):
        _attack(client, method, path, ids, watcher())
    assert census() == before


# --- the escalation ---------------------------------------------------------

def test_an_oversight_holder_cannot_grant_anything_to_anybody(world):
    """Not a connection, not oversight, and not to themselves.

    This is the attack the design exists to prevent. It is closed by grant
    management not being a scope at all: there is nothing an oversight grant
    could carry that would confer it, because there is nothing *any* grant
    could carry that would.
    """
    client, _, _ = world
    probes = [
        ("PUT", "/v1/grants", {"subject": WATCHER, "connection_id": ALPHA,
                               "level": "operator"}),
        ("PUT", "/v1/grants", {"subject": "accomplice",
                               "connection_id": ALPHA, "level": "operator"}),
        ("PATCH", f"/v1/grants/{OLIVE}/{ALPHA}", {"level": "viewer"}),
        ("DELETE", f"/v1/grants/{OLIVE}/{ALPHA}", None),
        ("GET", "/v1/grants", None),
        ("GET", "/v1/grants/subjects", None),
        ("PUT", "/v1/oversight", {"subject": "accomplice"}),
        ("PUT", "/v1/oversight", {"subject": WATCHER}),
        ("GET", "/v1/oversight", None),
        ("DELETE", f"/v1/oversight/{OLIVE}", None),
    ]
    for method, path, body in probes:
        response = client.request(method, path, json=body, headers=watcher())
        assert response.status_code == 403, f"{method} {path}: {response.text}"
        assert response.json()["error"]["detail"]["required_role"] == "admin"
    for path in ("/ui/access", f"/ui/access/{WATCHER}",
                 f"/ui/connections/{ALPHA}/access"):
        assert client.get(path, headers=watcher(**BROWSER)
                          ).status_code == 403, path
    # Nothing moved: `wanda` still holds no connection and `olive` still holds
    # exactly the one they were given.
    assert client.get(f"/v1/grants?subject={WATCHER}",
                      headers=admin()).json()["grants"] == []
    assert [row["level"] for row in client.get(
        f"/v1/grants?subject={OLIVE}",
        headers=admin()).json()["grants"]] == ["operator"]


def test_grant_management_is_still_not_a_scope(world):
    """The structural property, restated for the grant that most needs it.

    An oversight grant carries every scope named `:read`. If granting were a
    scope -- however carefully placed -- it would be one edit from being one of
    them. It is not in the model at all, so there is no edit to make.
    """
    assert not any("grant" in scope.value for scope in Scope)
    assert OVERSIGHT_SCOPES & WRITE_SCOPES == frozenset()
    assert OVERSIGHT_SCOPES | WRITE_SCOPES == frozenset(Scope)
    # Named individually, so the derivation cannot drift without this failing.
    assert sorted(scope.value for scope in WRITE_SCOPES) == [
        "connections:write", "orders:replay", "payments:submit",
        "schedules:manage", "webhooks:manage"]
    assert sorted(scope.value for scope in OVERSIGHT_SCOPES) == [
        "audit:read", "connections:read", "payments:read", "schedules:read",
        "statements:read", "webhooks:read"]


# --- who may issue it -------------------------------------------------------

def test_only_an_administrator_issues_or_revokes_oversight(world):
    """A member cannot, and neither can another oversight holder.

    The second is the one worth writing down: two reviewers who could grant
    each other oversight would be a deployment where oversight spreads without
    an administrator, which is the same failure as granting oneself with one
    more step in it.
    """
    client, app, _ = world
    grant_oversight(app, "second-watcher")
    for headers, who in ((member(OLIVE), "an operator"),
                         (member("nobody"), "a member holding nothing"),
                         (watcher(), "an oversight holder"),
                         (member("second-watcher"), "another oversight holder")):
        issue = client.put("/v1/oversight", json={"subject": "accomplice"},
                           headers=headers)
        assert issue.status_code == 403, f"{who} issued oversight"
        drop = client.delete(f"/v1/oversight/{WATCHER}", headers=headers)
        assert drop.status_code == 403, f"{who} revoked oversight"
    holders = {row["subject"] for row
               in client.get("/v1/oversight", headers=admin()).json()["oversight"]}
    assert holders == {WATCHER, "second-watcher"}


def test_an_administrator_issues_it_and_the_reach_begins_immediately(world):
    """The positive direction, through the REST surface an admin actually uses."""
    client, _, _ = world
    newcomer = member("newcomer")
    assert client.get(f"/v1/orders/ord_{BETA}",
                      headers=newcomer).status_code in (403, 404)
    issued = client.put("/v1/oversight", json={"subject": "newcomer"},
                        headers=admin())
    assert issued.status_code == 201, issued.text
    # The response says what it carries, read out of the model.
    assert issued.json()["scopes"] == sorted(
        scope.value for scope in OVERSIGHT_SCOPES)
    assert client.get(f"/v1/orders/ord_{BETA}", headers=newcomer).status_code == 200
    # Read-only from the first request: no payment, and no grant.
    assert client.post(f"/v1/connections/{BETA}/payments", json=payment_body(),
                       headers={**newcomer, IDEMPOTENCY_HEADER: "new-0001"}
                       ).status_code == 403
    assert client.get("/v1/grants", headers=newcomer).status_code == 403
    # Issuing twice leaves one row rather than a second nobody revokes.
    assert client.put("/v1/oversight", json={"subject": "newcomer"},
                      headers=admin()).status_code == 201
    assert sum(1 for row in client.get(
        "/v1/oversight", headers=admin()).json()["oversight"]
        if row["subject"] == "newcomer") == 1


def test_revoking_oversight_takes_effect_on_the_next_request(world):
    """No restart, no sign-out, no cache to wait for.

    `wanda` is also given a `viewer` grant on one bank first, so that losing
    oversight leaves them holding `payments:read` *somewhere*: the route-level
    check still passes and the refusal is therefore the per-connection `404`,
    which is the one that proves the **reach** went away rather than the scope.
    """
    client, app, _ = world
    grant(app, WATCHER, ALPHA, "viewer")
    mine, theirs = f"/v1/orders/ord_{ALPHA}", f"/v1/orders/ord_{BETA}"
    assert client.get(theirs, headers=watcher()).status_code == 200
    assert revoke_oversight(app, WATCHER) is True
    assert client.get(theirs, headers=watcher()).status_code == 404
    assert client.get(mine, headers=watcher()).status_code == 200, \
        "revoking oversight took away a connection grant as well"
    assert {row["connection_id"] for row in client.get(
        "/v1/connections", headers=watcher()).json()["connections"]} == {ALPHA}
    # And through the route an administrator uses.
    client.put("/v1/oversight", json={"subject": WATCHER}, headers=admin())
    assert client.get(theirs, headers=watcher()).status_code == 200
    assert client.delete(f"/v1/oversight/{WATCHER}",
                         headers=admin()).status_code == 200
    assert client.get(theirs, headers=watcher()).status_code == 404
    # Revoking what nobody holds is a `404`, not a silent success.
    assert client.delete(f"/v1/oversight/{WATCHER}",
                         headers=admin()).status_code == 404


def test_issuing_and_revoking_oversight_are_audit_rows_naming_no_connection(world):
    """A decision about who may see every bank is a row with an actor.

    ``connection_id`` is `NULL` on both, which is the row itself saying that
    this was a decision about the deployment rather than about one bank -- and
    is what keeps it out of a member's view of their own connection's trail.
    """
    client, _, _ = world
    client.put("/v1/oversight", json={"subject": "newcomer"}, headers=admin())
    client.delete("/v1/oversight/newcomer", headers=admin())
    events = client.get("/v1/audit?limit=200",
                        headers=admin()).json()["events"]
    issued = next(e for e in events
                  if e["action"] == "access.oversight_granted"
                  and e["detail"]["subject"] == "newcomer")
    dropped = next(e for e in events
                   if e["action"] == "access.oversight_revoked")
    assert issued["actor_id"] == ROOT and issued["connection_id"] is None
    assert issued["detail"]["scopes"] == sorted(
        scope.value for scope in OVERSIGHT_SCOPES)
    assert dropped["detail"]["subject"] == "newcomer"
    assert "***" not in str(issued["detail"])
    # A member holding a connection never sees either row.
    theirs = client.get("/v1/audit?limit=200",
                        headers=member(OLIVE)).json()["events"]
    assert not any(e["action"].startswith("access.oversight")
                   for e in theirs)


# --- the old word is still just a word --------------------------------------

def test_the_auditor_claim_still_grants_nothing(world):
    """No silent promotion, which is the widening `0012` refused to make.

    The claim value `auditor` is recognised -- so it is not logged as unmapped
    noise -- and it makes a plain member. Mapping it onto this grant would hand
    deployment-wide read of every bank's payment history to everybody in a
    directory group, on the morning of an upgrade, because a migration decided
    it rather than an administrator.
    """
    client, _, _ = world
    headers = dev_credentials("legacy-auditor", "auditor")
    me = client.get("/auth/me", headers=headers)
    assert me.status_code == 200
    body = me.json()
    assert body["role"] == "member"
    assert body["oversight"] is False
    assert body["scopes"] == [] and body["grants"] == []
    # And it reaches nothing, at either bank or across them.
    assert client.get(f"/v1/orders/ord_{ALPHA}",
                      headers=headers).status_code in (403, 404)
    assert client.get("/v1/connections",
                      headers=headers).json()["connections"] == []
    assert client.get("/v1/audit", headers=headers).status_code == 403


def test_the_migration_promotes_nobody(sqlite_url):
    """`0013` adds a table and no rows. Stated as a test, not as a comment."""
    from painfree.config import load_settings

    engine = db.build_engine(load_settings(database_url=sqlite_url))
    assert db.migrate(engine) == "0020_schedule_cron"
    with engine.connect() as connection:
        assert connection.execute(select(oversight_grant)).all() == []
    engine.dispose()


# --- the model, without a database in the way -------------------------------

def test_oversight_is_read_everywhere_and_write_nowhere():
    principal = build_principal(subject="w", issuer="i", method="session",
                                roles=["member"], oversight=True)
    assert principal.oversight and not principal.admin
    for scope in OVERSIGHT_SCOPES:
        assert principal.may(scope, ALPHA)
        assert principal.may(scope, "a-bank-nobody-registered")
        # `None` is the deployment-wide thing: an audit row naming no
        # connection, the subscription that receives every connection's events.
        assert principal.may(scope, None)
    for scope in WRITE_SCOPES:
        assert not principal.has(scope)
        assert not principal.may(scope, ALPHA)
        assert not principal.may(scope, None)
    assert restrict(principal) == (None, True)
    assert visible(principal, None) and visible(principal, BETA)


def test_oversight_and_a_connection_grant_are_a_union_not_a_replacement():
    """Somebody who reviews the deployment and also operates one bank."""
    both = build_principal(subject="w", issuer="i", method="session",
                           roles=["member"], oversight=True,
                           grants=[(ALPHA, Level.operator)])
    assert both.may(Scope.payments_submit, ALPHA)
    assert not both.may(Scope.payments_submit, BETA)
    assert both.may(Scope.payments_read, BETA)
    assert both.scopes_on(BETA) == OVERSIGHT_SCOPES
    assert Scope.payments_submit in both.scopes_on(ALPHA)


def test_a_narrowing_scope_claim_narrows_oversight_too():
    """`Roles grant, scopes narrow` -- and the direction still only takes away."""
    narrowed = build_principal(subject="w", issuer="i", method="session",
                               roles=["member"], oversight=True,
                               requested=["payments:read", "payments:submit"])
    assert narrowed.may(Scope.payments_read, BETA)
    assert not narrowed.may(Scope.audit_read, BETA)
    # The `scope` claim asked for a privilege the grant does not carry. Asking
    # cannot add: narrowing is an intersection.
    assert not narrowed.has(Scope.payments_submit)


def test_the_guard_refuses_a_write_on_a_connection_oversight_can_see():
    """`403` naming the scope, not `404`: there is nothing to hide from a reader."""
    principal = build_principal(subject="w", issuer="i", method="session",
                                roles=["member"], oversight=True)
    require(principal, BETA, Scope.payments_read)  # no exception
    with pytest.raises(ForbiddenError) as refused:
        require(principal, BETA, Scope.payments_submit)
    assert refused.value.detail["missing_scopes"] == ["payments:submit"]
    assert "payments:read" in refused.value.detail["held_scopes"]


def test_an_admin_is_never_reported_as_holding_oversight():
    """They hold everything; a second answer to the same question would be one
    more thing to keep in step. Same treatment as their grants."""
    root = build_principal(subject="r", issuer="i", method="session",
                           roles=["admin"], oversight=True,
                           grants=[(ALPHA, Level.viewer)])
    assert root.admin
    assert root.oversight is False and root.grants == ()
    assert root.as_response()["oversight"] is False
