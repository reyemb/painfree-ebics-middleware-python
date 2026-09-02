"""Per-connection access control, written as an attacker rather than as a user.

This file exists because per-connection grants changed who may move money.
There is no reference implementation of an authorisation model to diff against
and none was invented; what stands in for one is that **every assertion below
is a request issued directly at the running application**, with no page
rendered first and no control clicked, because a refusal proved by a hidden
button is not a refusal.

Four things it holds, and each is a claim a screenshot cannot make:

**A route table nobody can quietly leave out of.** :data:`PER_CONNECTION` names
every route that reaches something belonging to a bank connection, and
:func:`test_every_per_connection_route_is_in_the_attack_table` walks the
application's own router and fails on a route with a connection-shaped path
parameter that is missing from it. Fixing webhooks and leaving a sibling open is
the failure this file is shaped to prevent, so the enumeration is checked rather
than asserted.

**Refusals are told apart.** A caller holding a connection and lacking a
privilege gets `403` naming the scope; a caller holding no grant on the
connection gets `404` and learns nothing -- not that the connection exists, not
that the id they guessed is real. Both are refusals and both are asserted as
the specific one they should be.

**Object-level, not just route-level.** A member with `payments:read` passes the
route check on `GET /v1/orders/{id}` for *any* order. The only thing between
them and another bank's payment history is the check that runs after the row is
loaded, so that is what is attacked here: the same route, a legitimately held
scope, and somebody else's id.

**Revocation without a restart.** A request that succeeds, a revoke, and the
same request refused -- in one process, with the session unchanged.
"""

from __future__ import annotations

import datetime as _dt

import pytest
from fastapi.testclient import TestClient
from fastapi.routing import APIRoute
from sqlalchemy import insert, select

from conftest import dev_credentials, grant, payment_body, revoke
from painfree import db, wrapping
from painfree.access import require, restrict, visible
from painfree.api import IDEMPOTENCY_HEADER
from painfree.app import create_app
from painfree.connections import ConnectionRegistry
from painfree.errors import ForbiddenError, NotFoundError
from painfree.identity import (LEVEL_SCOPES, Level, Scope,
                               build_principal)
from painfree.schema import (bank_connection, connection_grant, payment_order,
                             statement)

BROWSER = {"accept": "text/html,application/xhtml+xml"}

#: The bank the attacker legitimately holds, and the one they do not.
MINE = "alpha-bank"
YOURS = "beta-bank"

#: Everyone in this file. `mallory` is the attacker: a real member with a real
#: `operator` grant on one connection, which is what makes the attacks
#: interesting -- they hold every scope the routes below demand.
MALLORY = "mallory"
VERA = "vera"
NOBODY = "nobody"
ROOT = "root"


def member(subject: str, **extra) -> dict[str, str]:
    return {**dev_credentials(subject, "member"), **extra}


def admin(**extra) -> dict[str, str]:
    return {**dev_credentials(ROOT, "admin"), **extra}


# --- the world these attacks run against ------------------------------------

def _seed(engine, connection_id: str) -> None:
    """One connection with one of everything a member could try to reach."""
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
    """Two banks, a member holding one of them, and an administrator.

    The webhook subscriptions and schedules are registered **through the
    application** as the administrator, so the rows an attacker later tries to
    reach are rows the service itself wrote.
    """
    engine = db.build_engine(custody_settings)
    db.migrate(engine)
    wrapping.publish(engine, custody_settings.custody_key())
    _seed(engine, MINE)
    _seed(engine, YOURS)
    app = create_app(custody_settings)
    with TestClient(app) as client:
        for index, connection_id in enumerate((MINE, YOURS)):
            assert client.post("/v1/webhooks", headers=admin(**{
                IDEMPOTENCY_HEADER: f"seed-wh-{index}"}), json={
                    "url": f"https://consumer.test/{connection_id}",
                    "event_types": ["order.accepted"],
                    "connection_id": connection_id}).status_code == 201
            assert client.post("/v1/schedules", headers=admin(), json={
                "connection_id": connection_id, "service_name": "EOP",
                "msg_name": "camt.053", "msg_version": "08",
                "cadence_seconds": 3600}).status_code == 201
        # The subscription that receives *every* connection's payment events.
        # It is here so the tests below can prove a member is not shown it and
        # cannot create one.
        assert client.post("/v1/webhooks", headers=admin(**{
            IDEMPOTENCY_HEADER: "seed-wh-global"}), json={
                "url": "https://consumer.test/everything",
                "event_types": ["order.accepted"]}).status_code == 201

        grant(app, MALLORY, MINE, "operator")
        grant(app, VERA, MINE, "viewer")
        yield client, app, _ids(client)
    engine.dispose()


def _ids(client) -> dict[str, str]:
    """The opaque ids of everything seeded, by connection."""
    found: dict[str, str] = {}
    for row in client.get("/v1/schedules", headers=admin()).json()["schedules"]:
        found[f"schedule:{row['connection_id']}"] = row["schedule_id"]
    for row in client.get("/v1/webhooks", headers=admin()).json()["webhooks"]:
        key = row["connection_id"] or "global"
        found[f"webhook:{key}"] = row["subscription_id"]
    return found


# --- the route table --------------------------------------------------------
#
# `{cid}` is the connection, `{schedule}` and `{webhook}` its opaque ids. Every
# entry is a request that reaches something belonging to one bank connection.

PER_CONNECTION: tuple[tuple[str, str, object], ...] = (
    ("POST", "/v1/connections/{cid}/payments", "payment"),
    ("GET", "/v1/orders/ord_{cid}", None),
    ("GET", "/v1/schedules/{schedule}", None),
    ("GET", "/v1/schedules/{schedule}/runs", None),
    ("PATCH", "/v1/schedules/{schedule}", {"description": "taken"}),
    ("DELETE", "/v1/schedules/{schedule}", None),
    ("POST", "/v1/schedules/{schedule}/run", None),
    ("POST", "/v1/schedules/{schedule}/refetch", {"since": "2026-08-01"}),
    ("GET", "/v1/webhooks/{webhook}", None),
    ("GET", "/v1/webhooks/{webhook}/deliveries", None),
    ("PATCH", "/v1/webhooks/{webhook}", {"description": "taken"}),
    ("DELETE", "/v1/webhooks/{webhook}", None),
    ("POST", "/v1/webhooks/{webhook}/resume", None),
    ("POST", "/v1/webhooks/{webhook}/ping", None),
    ("POST", "/v1/webhooks/{webhook}/secret", None),
    ("DELETE", "/v1/webhooks/{webhook}/secret/previous", None),
    ("GET", "/ui/connections/{cid}", None),
    ("GET", "/ui/connections/{cid}/edit", None),
    ("POST", "/ui/connections/{cid}/edit", "form"),
    ("GET", "/ui/connections/{cid}/keys", None),
    ("GET", "/ui/connections/{cid}/keys/bank-keys", None),
    ("POST", "/ui/connections/{cid}/keys/create_keys", "form"),
    ("GET", "/ui/connections/{cid}/letter", None),
    # The console's hand-raised payment: the form, the preview it builds
    # and the confirmation that actually sends. All three reach one
    # bank's data and the third one moves money, so all three are
    # attacked rather than only the one that writes.
    ("GET", "/ui/connections/{cid}/payment", None),
    ("POST", "/ui/connections/{cid}/payment/preview", "form"),
    ("POST", "/ui/connections/{cid}/payment", "form"),
    # What the bank publishes for this connection. Read-only, and read
    # with `connections:read` -- but it names one bank, so a member
    # holding another must not reach it.
    ("GET", "/ui/connections/{cid}/catalogue", None),
    ("GET", "/ui/connections/{cid}/access", None),
    ("POST", "/ui/connections/{cid}/access", "form"),
    ("POST", "/ui/connections/{cid}/access/revoke", "form"),
    ("GET", "/ui/orders/ord_{cid}", None),
    ("GET", "/ui/orders/ord_{cid}/refused-request.xml", None),
    ("GET", "/ui/orders/ord_{cid}/replay", None),
    ("POST", "/ui/orders/ord_{cid}/replay", "form"),
    ("GET", "/ui/statements/stm_{cid}", None),
    ("GET", "/ui/schedules/{schedule}", None),
    ("POST", "/ui/schedules/{schedule}/edit", "form"),
    ("POST", "/ui/schedules/{schedule}/pause", "form"),
    ("GET", "/ui/webhooks/{webhook}", None),
    ("POST", "/ui/webhooks/{webhook}/edit", "form"),
    ("POST", "/ui/webhooks/{webhook}/pause", "form"),
)

#: The path parameters that name something a bank connection owns. A route
#: carrying one of these and missing from `PER_CONNECTION` is a hole.
OWNED_BY_A_CONNECTION = ("connection_id", "order_id", "schedule_id",
                         "subscription_id", "statement_id")

#: Routes whose path carries one of those names and which are deliberately not
#: attack targets, each with the reason. A short list that has to stay short.
NOT_ATTACKED = {
    # The two halves of grant management, attacked in their own test below as
    # a whole surface rather than per connection.
    ("GET", "/v1/grants/subjects"),
    ("PATCH", "/v1/grants/{subject}/{connection_id}"),
    ("DELETE", "/v1/grants/{subject}/{connection_id}"),
    ("GET", "/ui/access/{subject}"),
    ("POST", "/ui/access/{subject}"),
    ("POST", "/ui/access/{subject}/revoke"),
}


def _request(client, method: str, path: str, ids: dict, connection_id: str,
             headers: dict, body):
    """One attack, issued directly. No page is rendered and nothing is clicked."""
    target = (path.replace("{cid}", connection_id)
              .replace("{schedule}", ids[f"schedule:{connection_id}"])
              .replace("{webhook}", ids[f"webhook:{connection_id}"]))
    if body == "payment":
        return client.post(target, json=payment_body(), headers={
            **headers, IDEMPOTENCY_HEADER: "attack-0001"})
    if body == "form":
        return client.request(method, target, headers={
            **headers, "content-type": "application/x-www-form-urlencoded"},
            content="confirm=revoke&subject=x&level=viewer&url=https://x.test/"
                    "&service_name=EOP&msg_name=camt.053&cadence=1"
                    "&cadence_unit=hours&host_url=https://x.test/")
    if isinstance(body, dict):
        return client.request(method, target, json=body, headers=headers)
    return client.request(method, target, headers=headers)


# --- the enumeration is checked, not asserted -------------------------------

def test_every_per_connection_route_is_in_the_attack_table(world):
    """A route that reaches a connection's data and is not attacked below fails here.

    The point of this test is that `PER_CONNECTION` cannot go stale. Somebody
    adding `GET /v1/connections/{connection_id}/balances` next month does not
    have to remember this file: the router tells it.
    """
    _, app, _ = world
    listed = {(method, path) for method, path, _ in PER_CONNECTION}
    missing = []
    for route in _routes(app):
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            if not any(f"{{{name}}}" in route.path
                       for name in OWNED_BY_A_CONNECTION):
                continue
            if (method, route.path) in NOT_ATTACKED:
                continue
            if not any(_matches(route.path, path) and method == listed_method
                       for listed_method, path in listed):
                missing.append(f"{method} {route.path}")
    assert not missing, (
        "these routes reach something a bank connection owns and are not in "
        f"PER_CONNECTION, so nothing proves a member is refused them: {missing}")


def _matches(route_path: str, attack_path: str) -> bool:
    """Does an attack entry address this route? Compared segment by segment."""
    left, right = route_path.strip("/").split("/"), attack_path.strip("/").split("/")
    if len(left) != len(right):
        return False
    return all(part.startswith("{") or part == other
               for part, other in zip(left, right))


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


# --- the attacks ------------------------------------------------------------

#: Ids that name nothing at all. Used to state the disclosure property below
#: as a comparison rather than as a list of expected status codes.
NOTHING = {"schedule:no-such-bank": "dsc_0000000000000000000000",
           "webhook:no-such-bank": "whs_0000000000000000000000"}


def test_an_operator_grant_on_one_bank_reaches_nothing_at_another(world):
    """Every per-connection route, as a member holding a *different* connection.

    Not a sample: the table is checked against the router above, so this is
    every route that reaches a connection's data.

    The assertion is stronger than "refused". `mallory` holds `operator` on
    `alpha-bank`, so they hold every scope these routes demand -- and for
    `beta-bank` each route answers **exactly what it answers for a connection
    that does not exist**. That is the property worth having: a caller learns
    nothing from the difference, because there is no difference. A `404` where
    the scope is held, a `403` where it is not, and the same either way for a
    bank that was never registered.
    """
    client, _, ids = world
    for method, path, body in PER_CONNECTION:
        real = _request(client, method, path, ids, YOURS,
                        member(MALLORY, **BROWSER), body)
        invented = _request(client, method, path, {**ids, **NOTHING},
                            "no-such-bank", member(MALLORY, **BROWSER), body)
        assert real.status_code in (403, 404), \
            f"{method} {path} reached another connection: {real.status_code}"
        assert real.status_code == invented.status_code, (
            f"{method} {path} answers {real.status_code} for a connection that "
            f"exists and {invented.status_code} for one that does not, which "
            f"tells the caller which is which")


def test_a_member_with_no_grants_is_refused_every_one_of_them(world):
    """The empty account. It signs in; it reaches nothing."""
    client, _, ids = world
    assert client.get("/auth/me", headers=member(NOBODY)).status_code == 200
    for connection_id in (MINE, YOURS):
        for method, path, body in PER_CONNECTION:
            response = _request(client, method, path, ids, connection_id,
                                member(NOBODY, **BROWSER), body)
            assert response.status_code in (403, 404), \
                f"{method} {path} on {connection_id} answered {response.status_code}"


def test_a_viewer_grant_is_refused_payments_submit_on_its_own_connection(world):
    """The whole reason a grant is levelled rather than a boolean."""
    client, _, _ = world
    response = client.post(f"/v1/connections/{MINE}/payments",
                           json=payment_body(),
                           headers=member(VERA, **{IDEMPOTENCY_HEADER: "viewer-submit-0001"}))
    assert response.status_code == 403, response.text
    detail = response.json()["error"]["detail"]
    assert detail["missing_scopes"] == ["payments:submit"]
    assert detail["connection_id"] == MINE
    # A `403` here and not a `404`, because this caller *does* hold the
    # connection: they are told exactly what they lack, which is the refusal
    # somebody can act on.
    assert "payments:read" in detail["held_scopes"]
    # The same caller reads the same connection's orders perfectly well.
    assert client.get(f"/v1/orders/ord_{MINE}",
                      headers=member(VERA)).status_code == 200


def test_a_member_cannot_reach_another_connections_order_by_guessing_its_id(world):
    """Object level. The route check has already passed by the time this matters.

    `mallory` holds `payments:read` -- so the dependency on
    `GET /v1/orders/{order_id}` lets them through. What refuses them is the
    check made after the row is loaded, against the connection the *row* names.
    """
    client, _, _ = world
    assert client.get(f"/v1/orders/ord_{MINE}",
                      headers=member(MALLORY)).status_code == 200
    stolen = client.get(f"/v1/orders/ord_{YOURS}", headers=member(MALLORY))
    assert stolen.status_code == 404
    assert YOURS not in stolen.text, "the refusal named the connection it hid"
    # And on the console, which is a second surface and therefore a second
    # chance to have forgotten.
    assert client.get(f"/ui/orders/ord_{YOURS}",
                      headers=member(MALLORY, **BROWSER)).status_code == 404
    assert client.get(f"/ui/statements/stm_{YOURS}",
                      headers=member(MALLORY, **BROWSER)).status_code == 404


def test_a_member_is_never_shown_a_connectionless_webhook_subscription(world):
    """The subscription that receives every connection's events is admin-only."""
    client, _, ids = world
    listed = client.get("/v1/webhooks", headers=member(MALLORY)).json()["webhooks"]
    assert [row["connection_id"] for row in listed] == [MINE]
    # Named directly, it is a `404`: its `connection_id` is NULL, so there is
    # no connection anybody could hold a grant on.
    assert client.get(f"/v1/webhooks/{ids['webhook:global']}",
                      headers=member(MALLORY)).status_code == 404
    assert client.get(f"/ui/webhooks/{ids['webhook:global']}",
                      headers=member(MALLORY, **BROWSER)).status_code == 404
    # The administrator sees all three, including the connection-less one.
    everything = client.get("/v1/webhooks", headers=admin()).json()["webhooks"]
    assert sum(1 for row in everything if row["connection_id"] is None) == 1


def test_a_member_cannot_create_a_connectionless_webhook_subscription(world):
    """The exfiltration path, closed by there being no rule to get wrong.

    A `NULL` `connection_id` means *every* connection's payment events go to
    this URL. A member cannot create one -- and cannot create a scoped one
    either, because `webhooks:manage` is carried by no grant level at all. The
    absence is the defence: there is no case to have got right.
    """
    client, _, _ = world
    for body in ({"url": "https://attacker.test/all",
                  "event_types": ["order.accepted"]},
                 {"url": "https://attacker.test/mine",
                  "event_types": ["order.accepted"], "connection_id": MINE}):
        response = client.post("/v1/webhooks", json=body, headers=member(
            MALLORY, **{IDEMPOTENCY_HEADER: f"attack-{body.get('connection_id')}"}))
        assert response.status_code == 403, response.text
        assert response.json()["error"]["detail"]["missing_scopes"] == \
            ["webhooks:manage"]
    # The console's registration form is refused too, and so is its `POST`.
    assert client.get("/ui/webhooks/new",
                      headers=member(MALLORY, **BROWSER)).status_code == 403
    assert client.post("/ui/webhooks", headers={
        **member(MALLORY, **BROWSER),
        "content-type": "application/x-www-form-urlencoded"},
        content="url=https://attacker.test/all&event:order.accepted=on"
        ).status_code == 403
    # Nothing was created by any of it.
    assert len(client.get("/v1/webhooks", headers=admin()).json()["webhooks"]) == 3


def test_a_member_cannot_manage_grants_at_all(world):
    """Not by a scope, and not by holding every connection there is.

    Granting is the one capability the model does not express as a scope, so
    there is nothing a grant could carry that would confer it.
    """
    client, app, _ = world
    grant(app, MALLORY, YOURS, "operator")  # now holds *every* connection
    probes = [
        ("GET", "/v1/grants", None),
        ("GET", "/v1/grants/subjects", None),
        ("PUT", "/v1/grants", {"subject": "mallory", "connection_id": MINE,
                               "level": "operator"}),
        ("PATCH", f"/v1/grants/{VERA}/{MINE}", {"level": "operator"}),
        ("DELETE", f"/v1/grants/{VERA}/{MINE}", None),
    ]
    for method, path, body in probes:
        response = client.request(method, path, json=body,
                                  headers=member(MALLORY))
        assert response.status_code == 403, f"{method} {path}: {response.text}"
        assert response.json()["error"]["detail"]["required_role"] == "admin"
    for path in ("/ui/access", f"/ui/access/{VERA}",
                 f"/ui/connections/{MINE}/access"):
        assert client.get(path, headers=member(MALLORY, **BROWSER)
                          ).status_code == 403, path
    # `vera` still holds exactly what she held.
    assert [g["level"] for g in client.get(
        f"/v1/grants?subject={VERA}", headers=admin()).json()["grants"]] == ["viewer"]


def test_a_revoked_grant_stops_working_on_the_next_request(world):
    """No restart, no sign-out, no cache to wait for."""
    client, app, _ = world
    order = f"/v1/orders/ord_{MINE}"
    # A second grant, so that revoking the first leaves this caller holding
    # `payments:read` somewhere: the route-level check still passes and the
    # refusal is therefore the per-connection one rather than a scope refusal.
    grant(app, MALLORY, YOURS, "viewer")
    assert client.get(order, headers=member(MALLORY)).status_code == 200
    assert revoke(app, MALLORY, MINE) is True
    assert client.get(order, headers=member(MALLORY)).status_code == 404
    assert client.get(f"/v1/orders/ord_{YOURS}",
                      headers=member(MALLORY)).status_code == 200, \
        "revoking one connection took away another"
    # And through the REST surface an administrator actually uses.
    grant(app, MALLORY, MINE, "operator")
    assert client.get(order, headers=member(MALLORY)).status_code == 200
    assert client.delete(f"/v1/grants/{MALLORY}/{MINE}",
                         headers=admin()).status_code == 200
    assert client.get(order, headers=member(MALLORY)).status_code == 404


def test_an_administrator_grants_and_the_access_begins_immediately(world):
    """The other direction, and the level is what was asked for."""
    client, _, _ = world
    newcomer = member("newcomer")
    # Holding nothing at all, this caller is refused at the route: they have no
    # `payments:read` to be narrowed. Either refusal is a refusal.
    assert client.get(f"/v1/orders/ord_{YOURS}",
                      headers=newcomer).status_code in (403, 404)
    created = client.put("/v1/grants", headers=admin(), json={
        "subject": "newcomer", "connection_id": YOURS, "level": "viewer"})
    assert created.status_code == 201, created.text
    # The response names what the level carries, read out of the model.
    assert created.json()["scopes"] == sorted(
        scope.value for scope in LEVEL_SCOPES[Level.viewer])
    assert client.get(f"/v1/orders/ord_{YOURS}", headers=newcomer).status_code == 200
    # A `viewer` and not an `operator`, which is the level that was asked for.
    assert client.post(f"/v1/connections/{YOURS}/payments", json=payment_body(),
                       headers={**newcomer, IDEMPOTENCY_HEADER: "newcomer-0001"}
                       ).status_code == 403
    # Granting again changes the level rather than making a second grant.
    assert client.put("/v1/grants", headers=admin(), json={
        "subject": "newcomer", "connection_id": YOURS,
        "level": "operator"}).status_code == 201
    assert len(client.get("/v1/grants?subject=newcomer",
                          headers=admin()).json()["grants"]) == 1
    assert client.post(f"/v1/connections/{YOURS}/payments", json=payment_body(),
                       headers={**newcomer, IDEMPOTENCY_HEADER: "newcomer-0002"}
                       ).status_code == 202


def test_every_grant_and_revocation_is_in_the_audit_trail(world):
    """The decision about who may move money is a row with an actor."""
    client, _, _ = world
    client.put("/v1/grants", headers=admin(), json={
        "subject": "newcomer", "connection_id": MINE, "level": "viewer"})
    client.delete(f"/v1/grants/newcomer/{MINE}", headers=admin())
    events = client.get("/v1/audit", headers=admin()).json()["events"]
    granted = next(e for e in events if e["action"] == "access.granted"
                   and e["detail"]["subject"] == "newcomer")
    revoked = next(e for e in events if e["action"] == "access.revoked")
    assert granted["actor_id"] == ROOT and granted["connection_id"] == MINE
    assert granted["detail"]["grant_level"] == "viewer"
    assert revoked["detail"]["subject"] == "newcomer"
    # Not `"***"`: `level` collides with the log's severity field, so the
    # detail is written under `grant_level`. Same class of bug as the `state`
    # collision.
    assert "***" not in str(granted["detail"])


# --- what a member is shown ------------------------------------------------

def test_the_lists_a_member_sees_hold_only_their_connections(world):
    """Filtered in the query, not on the page: a page that fetched a hundred
    rows and dropped ninety would show ten."""
    client, _, _ = world
    for path, key in (("/v1/connections", "connections"),
                      ("/v1/schedules", "schedules"),
                      ("/v1/webhooks", "webhooks")):
        rows = client.get(path, headers=member(MALLORY)).json()[key]
        assert {row["connection_id"] for row in rows} == {MINE}, path
    for path in ("/ui/connections", "/ui/orders", "/ui/statements",
                 "/ui/schedules", "/ui/webhooks"):
        page = client.get(path, headers=member(MALLORY, **BROWSER))
        assert page.status_code == 200, path
        assert MINE in page.text and YOURS not in page.text, path


def test_a_member_reads_the_trail_of_their_own_connections_and_no_others(world):
    """`audit:read`, per connection. The deployment's own rows stay admin-only."""
    client, _, _ = world
    events = client.get("/v1/audit", headers=member(MALLORY)).json()["events"]
    assert events, "a member with a connection sees that connection's trail"
    assert {event["connection_id"] for event in events} == {MINE}
    actions = {event["action"] for event in events}
    # Rows that name no connection: the service starting, a sign-in, and the
    # grants made in the fixture. None of them is this member's business.
    assert "service.started" not in actions
    # The filter dropdowns are narrowed with the rows, or the page would list
    # every actor in the deployment beside none of their events.
    page = client.get("/ui/audit", headers=member(MALLORY, **BROWSER))
    assert page.status_code == 200
    assert "service.started" not in page.text


def test_a_member_with_no_grants_gets_a_console_that_explains_itself(world):
    """The intended state, and it has to read as intended rather than broken."""
    client, _, _ = world
    landing = client.get("/ui/connections", headers=member(NOBODY, **BROWSER))
    assert landing.status_code == 200
    assert "not been granted access" in landing.text
    assert "administrator" in landing.text
    # The front page redirects there rather than refusing, so signing in does
    # not land on a `403`.
    home = client.get("/ui", headers=member(NOBODY, **BROWSER),
                      follow_redirects=False)
    assert home.status_code == 303 and home.headers["location"] == "/ui/connections"
    # And the page that explains privileges is reachable, which is the point of
    # it.
    assert client.get("/ui/api",
                      headers=member(NOBODY, **BROWSER)).status_code == 200


def test_the_developer_page_shows_a_member_what_it_actually_holds(world):
    """Generated from the model, so the levels appeared without a template edit."""
    client, _, _ = world
    page = client.get("/ui/api", headers=member(MALLORY, **BROWSER)).text
    assert "level: viewer" in page and "level: operator" in page
    assert "No grant carries this" in page, \
        "the admin-only scopes are not marked as unreachable by a grant"
    assert MINE in page and YOURS not in page


# --- the model, without a database in the way -------------------------------

def test_a_grant_carries_its_level_and_nothing_from_another_connection():
    principal = build_principal(
        subject="m", issuer="i", method="session", roles=["member"],
        grants=[(MINE, Level.operator), (YOURS, Level.viewer)])
    assert principal.may(Scope.payments_submit, MINE)
    assert not principal.may(Scope.payments_submit, YOURS)
    assert principal.may(Scope.payments_read, YOURS)
    assert not principal.may(Scope.payments_read, "a-third-bank")
    # Held *somewhere* is what a route-level check asks, and it is true here --
    # which is exactly why the object-level check has to exist.
    assert principal.has(Scope.payments_submit)


def test_nothing_that_belongs_to_no_connection_is_visible_to_a_member():
    """`None` is the deployment-wide thing: a global subscription, a system row."""
    principal = build_principal(subject="m", issuer="i", method="session",
                                roles=["member"], grants=[(MINE, Level.operator)])
    assert not visible(principal, None)
    assert not principal.may(Scope.webhooks_read, None)
    root = build_principal(subject="r", issuer="i", method="session",
                           roles=["admin"])
    assert visible(root, None) and root.may(Scope.webhooks_read, None)


def test_an_empty_restriction_is_not_an_absent_one():
    """The confusion that would show every bank to the person granted none."""
    nobody = build_principal(subject="n", issuer="i", method="session",
                             roles=["member"])
    assert restrict(nobody) == ([], False)
    root = build_principal(subject="r", issuer="i", method="session",
                           roles=["admin"])
    assert restrict(root) == (None, True)
    holder = build_principal(subject="m", issuer="i", method="session",
                             roles=["member"], grants=[(MINE, Level.viewer)])
    assert restrict(holder) == ([MINE], True)
    # A filter naming somebody else's bank is an empty list, not a `403`: it
    # should answer the same way as a filter naming a bank that does not exist.
    assert restrict(holder, YOURS) == ((), False)


def test_the_guard_tells_its_two_refusals_apart():
    holder = build_principal(subject="m", issuer="i", method="session",
                             roles=["member"], grants=[(MINE, Level.viewer)])
    with pytest.raises(NotFoundError):
        require(holder, YOURS, Scope.payments_read, what="order")
    with pytest.raises(ForbiddenError) as refused:
        require(holder, MINE, Scope.payments_submit)
    assert refused.value.detail["missing_scopes"] == ["payments:submit"]
    require(holder, MINE, Scope.payments_read)  # no exception


# --- the migration, on real rows --------------------------------------------

OLD_ROLES = (("vera", "viewer"), ("olive", "operator"), ("aud", "auditor"),
             ("alice", "administrator"), ("stranger", "payments-admin"))


@pytest.fixture
def before_the_migration(sqlite_url):
    """A database at `0011` with connections and sessions in it, then upgraded.

    The sessions are the only record the old model left of who held what --
    privilege lived in the identity provider and this service saw it in a token
    and nowhere else. That is the fact the backfill has to work from and the
    reason it is best-effort.
    """
    from painfree.config import load_settings
    from painfree.db import alembic_config
    from alembic import command

    settings = load_settings(database_url=sqlite_url)
    engine = db.build_engine(settings)
    now = _dt.datetime.now(_dt.timezone.utc)
    with engine.begin() as connection:
        command.upgrade(alembic_config(connection), "0011_schedule_management")
    with engine.begin() as connection:
        for connection_id in (MINE, YOURS):
            connection.execute(insert(bank_connection).values(
                connection_id=connection_id, host_id=f"H-{connection_id}",
                partner_id="P", user_id="U",
                host_url="https://bank.test/", ebics_version="H005",
                key_state="ready", ini_sent=True, hia_sent=True,
                letter_digest="public_key", created_at=now, updated_at=now))
        for subject, role in OLD_ROLES:
            connection.execute(insert(schema_user_session()).values(
                session_id_hash=f"{subject:0<64}", subject=subject,
                issuer="idp", roles=[role], display_name=subject.title(),
                created_at=now, expires_at=now + _dt.timedelta(days=1),
                last_seen_at=now))
    yield engine
    engine.dispose()


def schema_user_session():
    from painfree.schema import user_session

    return user_session


def test_the_migration_gives_every_old_role_a_defined_landing_place(
        before_the_migration):
    """Nobody silently gains, and only the one that cannot be mapped loses."""
    engine = before_the_migration
    assert db.migrate(engine) == "0018_refused_request"
    with engine.connect() as connection:
        grants = {}
        for row in connection.execute(select(connection_grant)).mappings():
            grants.setdefault(row["subject"], {})[row["connection_id"]] = row["level"]
    assert grants == {
        # `viewer` and `operator` keep exactly what they reached, on every
        # connection that existed.
        "vera": {MINE: "viewer", YOURS: "viewer"},
        "olive": {MINE: "operator", YOURS: "operator"},
        # `auditor` lands on the narrower half, deliberately.
        "aud": {MINE: "viewer", YOURS: "viewer"},
    }
    # An administrator gets no grants: the claim still makes them an admin, and
    # writing rows for them would be a second answer to the same question.
    assert "alice" not in grants
    # A role this deployment never mapped granted nothing before and grants
    # nothing now. Backfilling it would be *gaining* access, which is the one
    # direction a migration must never move.
    assert "stranger" not in grants


def test_the_migration_records_what_it_did_and_what_it_could_not_decide(
        before_the_migration):
    """The audit trail is where an administrator finds the auditor problem."""
    engine = before_the_migration
    db.migrate(engine)
    from painfree.audit import AuditLog

    events = AuditLog(engine).search(limit=50, action_prefix="access.")
    finished = next(e for e in events
                    if e["action"] == "access.migration_finished")
    assert finished["detail"]["subjects_recovered"] == 3
    assert finished["detail"]["grants_written"] == 6
    assert finished["detail"]["needs_admin_decision"] == ["aud"]
    auditor = next(e for e in events if e["action"] == "access.migrated"
                   and e["detail"]["subject"] == "aud")
    assert auditor["detail"]["needs_admin_decision"] is True
    assert "An administrator decides" in auditor["detail"]["reason"]
    # What was lost is named, not just that something was. Both halves: the
    # cross-connection trail and `webhooks:read`, which the `viewer` level does
    # not carry, because the list of event sinks is kept from a viewer.
    assert auditor["detail"]["loses"] == [
        "audit rows that name no connection or another one", "webhooks:read"]
    # And the subjects that lost nothing do not claim to have. Found by reading
    # the rendered audit page rather than the code: every row carried `loses`.
    for subject in ("vera", "olive"):
        row = next(e for e in events if e["action"] == "access.migrated"
                   and e["detail"]["subject"] == subject)
        assert "loses" not in row["detail"]
        assert row["detail"]["needs_admin_decision"] is False


def test_the_migrated_grants_reach_exactly_what_the_old_roles_reached(
        before_the_migration, custody_settings, sqlite_url):
    """The before/after, driven through the application rather than described.

    Each old role is replayed as a member with the grants the migration wrote,
    and the routes it could reach before are the routes it reaches now -- with
    the one documented exception, which is the cross-connection audit view.
    """
    engine = before_the_migration
    db.migrate(engine)
    engine.dispose()
    app = create_app(custody_settings)
    with TestClient(app) as client:
        # `olive` held `operator` globally and now holds `operator` on both.
        for connection_id in (MINE, YOURS):
            assert client.get(f"/ui/connections/{connection_id}",
                              headers=member("olive", **BROWSER)
                              ).status_code == 200
            assert client.get(f"/v1/schedules?connection_id={connection_id}",
                              headers=member("olive")).status_code == 200
        # `vera` held `viewer` and is still refused a submission, as before.
        assert client.post(f"/v1/connections/{MINE}/payments",
                           json=payment_body(),
                           headers=member("vera", **{IDEMPOTENCY_HEADER: "migrated-0001"})
                           ).status_code == 403
        # `aud` keeps every connection it could read and loses the rows that
        # name none, which is the one thing the migration cannot preserve.
        trail = client.get("/v1/audit", headers=member("aud"))
        assert trail.status_code == 200
        assert all(event["connection_id"] in (MINE, YOURS)
                   for event in trail.json()["events"])
        # `alice` was an administrator and still is, by the claim alone.
        assert client.get("/v1/grants", headers=dev_credentials(
            "alice", "administrator")).status_code == 200


def test_a_deployment_with_no_connections_migrates_to_nothing(sqlite_url):
    """The empty case, which is most first upgrades."""
    from painfree.config import load_settings

    engine = db.build_engine(load_settings(database_url=sqlite_url))
    assert db.migrate(engine) == "0018_refused_request"
    with engine.connect() as connection:
        assert connection.execute(select(connection_grant)).all() == []
    engine.dispose()
