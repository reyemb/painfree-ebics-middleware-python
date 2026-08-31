"""Managing webhook subscriptions: the routes, the console, and the secret.

Three properties are what this file exists to hold, and each of them is a claim
that a screenshot cannot make.

**The process that creates a signing secret cannot read it back.** Not "does
not" -- cannot. The API process is built with no custody key, and the secret it
generated is sealed to a public half it has no private half for. So the tests
here do not look for the absence of a "reveal" route; they take the store the
application actually uses and try to open a secret with it.

**A rotation is verified by a consumer written from the contract.** The
signature header gains a second entry during an overlap, and the thing that
matters is that a receiver holding *either* value still accepts the delivery.
The verifier below is
the envelope contract transcribed, and it is what the assertions run through --
not :func:`painfree.webhooks.sign`, which would only prove that a function
agrees with itself.

**Hiding a button is not authorisation.** Every write route is posted to
directly by a caller whose role does not hold `webhooks:manage`, with no page
rendered first, and the `403` names the missing scope.
"""

from __future__ import annotations

import hashlib
import hmac
import logging

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from conftest import BANK_CONNECTION_ID, dev_credentials, grant
from painfree import db, wrapping
from painfree.app import create_app
from painfree.dispatcher import PARK_AFTER, WebhookDispatcher
from painfree.logging import JsonFormatter
from painfree.schema import webhook_delivery, webhook_subscription
from painfree.sealing import CorruptSealError, WrongCustodyKeyError, derive_custody_key
from painfree.webhooks import (PARKED, PENDING, SIGNATURE_HEADER,
                               TIMESTAMP_HEADER, WebhookSubscriptions,
                               canonical_body, delivery_headers, sign_all,
                               utcnow)

BROWSER = {"accept": "text/html,application/xhtml+xml"}
ENDPOINT = "https://consumer.example.test/painfree/events"
TYPES = ["order.accepted", "order.rejected"]


def _admin(**extra) -> dict[str, str]:
    return {**dev_credentials("alice", "admin"), **extra}


def _operator(**extra) -> dict[str, str]:
    """A member with an `operator` grant on the connection, which is where
    the role that carries `webhooks:read` now lives."""
    return {**dev_credentials("olive", "member"), **extra}


def _viewer(**extra) -> dict[str, str]:
    return {**dev_credentials("reader", "member"), **extra}


def verify_from_the_contract(secret: str, headers: dict, body: bytes) -> bool:
    """The contract's verification, transcribed. Touches no painfree code.

    The header carries one or more comma-separated ``v1=<hex>`` entries and the
    consumer accepts if any of them verifies -- which is the whole of what makes
    a secret rotation survivable at the receiving end.
    """
    signed = headers[TIMESTAMP_HEADER].encode("ascii") + b"." + body
    expected = hmac.new(secret.encode("utf-8"), signed,
                        hashlib.sha256).hexdigest()
    for entry in headers[SIGNATURE_HEADER].split(","):
        scheme, _, digest = entry.strip().partition("=")
        if scheme == "v1" and hmac.compare_digest(expected, digest):
            return True
    return False


# --- fixtures ---------------------------------------------------------------

@pytest.fixture
def console(prepared_bank, custody_settings):
    """The application, with the wrapping key a worker start would have published.

    Published explicitly rather than by a worker fixture, because that is the
    only thing about a running worker this surface needs: the public half it
    seals to. Everything else here happens in the API process.
    """
    engine, connection, _ = prepared_bank
    wrapping.publish(engine, custody_settings.custody_key())
    app = create_app(custody_settings)
    with TestClient(app) as client:
        grant(app, "olive", BANK_CONNECTION_ID, "operator")
        grant(app, "reader", BANK_CONNECTION_ID, "viewer")
        yield client, engine, custody_settings


def _register(client, key: str = "wh-0001", **overrides) -> dict:
    body = {"url": ENDPOINT, "event_types": TYPES,
            "description": "Ledger ingest",
            # Scoped to the connection, so a member holding it can see the
            # subscription at all. A connection-less one is `admin` only, which
            # is what stops a member redirecting every connection's payment
            # events.
            "connection_id": BANK_CONNECTION_ID, **overrides}
    response = client.post("/v1/webhooks", json=body,
                           headers=_admin(**{"Idempotency-Key": key}))
    assert response.status_code in (200, 201), response.text
    return response.json()


# --- the wrapping envelope --------------------------------------------------

def test_a_wrapped_secret_opens_only_with_the_custody_key(custody_settings):
    """The whole asymmetry, without a database in the way."""
    key = custody_settings.custody_key()
    recipient = wrapping.recipient_for(key)
    blob = recipient.seal(b"a signing secret", context=b"webhook:whs_1")
    assert wrapping.is_wrapped(blob)
    assert wrapping.unseal(key, blob, context=b"webhook:whs_1") == b"a signing secret"


def test_a_wrapped_secret_is_bound_to_the_row_it_was_sealed_for(custody_settings):
    """A ciphertext moved to another subscription does not open."""
    key = custody_settings.custody_key()
    blob = wrapping.recipient_for(key).seal(b"secret", context=b"webhook:whs_1")
    with pytest.raises(CorruptSealError):
        wrapping.unseal(key, blob, context=b"webhook:whs_2")


def test_a_wrapped_secret_names_the_custody_key_it_wants(custody_settings):
    """A rotated encryption secret is diagnosable, not an anonymous tag failure."""
    key = custody_settings.custody_key()
    blob = wrapping.recipient_for(key).seal(b"secret", context=b"webhook:whs_1")
    other = derive_custody_key("a-completely-different-custody-secret-000001")
    with pytest.raises(WrongCustodyKeyError) as raised:
        wrapping.unseal(other, blob, context=b"webhook:whs_1")
    assert raised.value.sealed_with == key.key_id
    assert raised.value.configured == other.key_id


@pytest.mark.parametrize("cut", [0, 1, -1])
def test_an_edited_wrapped_secret_does_not_authenticate(custody_settings, cut):
    key = custody_settings.custody_key()
    blob = bytearray(
        wrapping.recipient_for(key).seal(b"secret", context=b"webhook:whs_1"))
    blob[cut] ^= 0x01
    with pytest.raises((CorruptSealError, WrongCustodyKeyError)):
        wrapping.unseal(key, bytes(blob), context=b"webhook:whs_1")


def test_publishing_the_wrapping_key_twice_publishes_the_same_bytes(
        custody_settings):
    """A worker restart is not a re-key."""
    engine = db.build_engine(custody_settings)
    db.migrate(engine)
    try:
        first = wrapping.publish(engine, custody_settings.custody_key())
        second = wrapping.publish(engine, custody_settings.custody_key())
        assert first == second == wrapping.published(engine)
    finally:
        engine.dispose()


def test_two_seals_of_one_secret_differ(custody_settings):
    """Ephemeral per message: two ciphertexts of one value are not comparable."""
    recipient = wrapping.recipient_for(custody_settings.custody_key())
    one = recipient.seal(b"secret", context=b"webhook:whs_1")
    two = recipient.seal(b"secret", context=b"webhook:whs_1")
    assert one != two


# --- registration, and the secret -------------------------------------------

def test_registration_returns_the_secret_once_and_never_again(console):
    client, engine, settings = console
    created = _register(client)
    secret = created["secret"]
    assert created["secret_shown_once"] is True
    assert len(secret) >= 32

    subscription_id = created["subscription_id"]
    for path in (f"/v1/webhooks/{subscription_id}", "/v1/webhooks",
                 f"/v1/webhooks/{subscription_id}/deliveries"):
        body = client.get(path, headers=_admin()).text
        assert secret not in body, path
        assert '"secret"' not in body, path

    # And not because a route declines to print it: the store this application
    # actually uses cannot open the seal at all.
    with pytest.raises(Exception, match="custody key"):
        client.app.state.webhooks.open_secret(subscription_id)
    # The worker can, and gets exactly what the caller was shown.
    worker = WebhookSubscriptions(engine, settings.custody_key())
    assert worker.open_secret(subscription_id) == secret


def test_what_is_stored_is_a_wrapped_blob_and_not_the_secret(console):
    client, engine, _ = console
    created = _register(client, "wh-stored")
    with engine.connect() as connection:
        blob = connection.execute(
            select(webhook_subscription.c.sealed_secret)
            .where(webhook_subscription.c.subscription_id
                   == created["subscription_id"])).scalar_one()
    assert wrapping.is_wrapped(bytes(blob))
    assert created["secret"].encode() not in bytes(blob)


def test_a_retried_registration_replays_and_does_not_show_the_secret(console):
    client, _, _ = console
    first = _register(client, "wh-idem")
    again = client.post("/v1/webhooks",
                        json={"url": ENDPOINT, "event_types": TYPES},
                        headers=_admin(**{"Idempotency-Key": "wh-idem"}))
    assert again.status_code == 200
    assert again.headers["Idempotency-Replayed"] == "true"
    assert again.json()["subscription_id"] == first["subscription_id"]
    assert "secret" not in again.json()
    assert len(client.get("/v1/webhooks", headers=_admin()
                          ).json()["webhooks"]) == 1


def test_registering_without_an_idempotency_key_names_the_rule(console):
    client, _, _ = console
    refused = client.post("/v1/webhooks",
                          json={"url": ENDPOINT, "event_types": TYPES},
                          headers=_admin())
    assert refused.status_code == 422
    failures = refused.json()["error"]["detail"]["failures"]
    assert failures[0]["rule"] == "idempotency_key.missing"


def test_an_unknown_event_type_is_refused_with_the_known_ones(console):
    client, _, _ = console
    refused = client.post("/v1/webhooks",
                          json={"url": ENDPOINT,
                                "event_types": ["order.exploded"]},
                          headers=_admin(**{"Idempotency-Key": "wh-bad"}))
    assert refused.status_code == 409
    assert "order.accepted" in refused.json()["error"]["detail"]["known"]


def test_a_connection_that_does_not_exist_is_a_404_not_a_500(console):
    client, _, _ = console
    refused = client.post(
        "/v1/webhooks",
        json={"url": ENDPOINT, "event_types": TYPES,
              "connection_id": "no-such-bank"},
        headers=_admin(**{"Idempotency-Key": "wh-nobank"}))
    assert refused.status_code == 404


def test_a_traceback_that_interpolated_the_secret_is_scrubbed(console, caplog):
    """A secret created over HTTP teaches the redactor, in the API process too.

    The one leak a name-based blocklist cannot see is free text: an exception
    message that formatted the value into itself. `register_secret` runs where
    the secret is generated, which is now the request path.
    """
    import sys

    client, _, _ = console
    secret = _register(client, "wh-log")["secret"]
    try:
        raise RuntimeError(f"posting to the endpoint with {secret} failed")
    except RuntimeError:
        record = logging.LogRecord("painfree.test", logging.ERROR, __file__, 1,
                                   "webhook.delivery_failed", (), sys.exc_info())
    line = JsonFormatter().format(record)
    assert secret not in line
    assert "<redacted:secret>" in line


def test_no_response_or_page_repeats_the_secret_after_registration(console):
    """Every surface that names the subscription, checked against the value."""
    client, _, _ = console
    created = _register(client, "wh-quiet")
    subscription_id = created["subscription_id"]
    client.post(f"/v1/webhooks/{subscription_id}/ping", headers=_admin())
    for path in ("/v1/webhooks", f"/v1/webhooks/{subscription_id}",
                 f"/v1/webhooks/{subscription_id}/deliveries",
                 "/ui/webhooks", f"/ui/webhooks/{subscription_id}",
                 "/v1/audit?limit=100"):
        body = client.get(path, headers=_admin(**BROWSER)).text
        assert created["secret"] not in body, path


# --- the rest of the surface ------------------------------------------------

def test_a_subscription_can_be_edited_paused_and_resumed(console):
    client, _, _ = console
    created = _register(client, "wh-edit")
    path = f"/v1/webhooks/{created['subscription_id']}"

    changed = client.patch(path, json={
        "url": "https://consumer.example.test/moved",
        "event_types": ["statement.available"],
        "description": "Moved"}, headers=_admin()).json()
    assert changed["url"] == "https://consumer.example.test/moved"
    assert changed["event_types"] == ["statement.available"]

    paused = client.patch(path, json={"enabled": False}, headers=_admin()).json()
    assert paused["enabled"] is False and paused["health"] == "paused"
    resumed = client.patch(path, json={"enabled": True}, headers=_admin()).json()
    assert resumed["enabled"] is True


def test_deleting_reports_what_it_dropped(console):
    client, engine, _ = console
    created = _register(client, "wh-del")
    client.post(f"/v1/webhooks/{created['subscription_id']}/ping",
                headers=_admin())
    removed = client.delete(f"/v1/webhooks/{created['subscription_id']}",
                            headers=_admin()).json()
    assert removed["owed_events_dropped"] == 1
    assert client.get(f"/v1/webhooks/{created['subscription_id']}",
                      headers=_admin()).status_code == 404
    with engine.connect() as connection:
        assert connection.execute(select(webhook_delivery)).all() == []


def test_a_ping_is_queued_as_an_ordinary_delivery(console):
    client, _, _ = console
    created = _register(client, "wh-ping")
    queued = client.post(f"/v1/webhooks/{created['subscription_id']}/ping",
                         headers=_admin())
    assert queued.status_code == 202
    assert queued.json()["event_type"] == "webhook.ping"
    assert queued.json()["state"] == PENDING

    listed = client.get(f"/v1/webhooks/{created['subscription_id']}/deliveries",
                        headers=_admin()).json()
    assert listed["owed"] == 1
    assert listed["deliveries"][0]["delivery_id"] == queued.json()["delivery_id"]


def test_a_ping_at_a_paused_endpoint_is_refused_rather_than_stranded(console):
    client, _, _ = console
    created = _register(client, "wh-ping-paused")
    path = f"/v1/webhooks/{created['subscription_id']}"
    client.patch(path, json={"enabled": False}, headers=_admin())
    refused = client.post(f"{path}/ping", headers=_admin())
    assert refused.status_code == 409
    assert "paused" in refused.json()["error"]["message"]


# --- the scope --------------------------------------------------------------

@pytest.mark.parametrize("method,path,body", [
    ("post", "/v1/webhooks", {"url": ENDPOINT, "event_types": TYPES}),
    ("patch", "/v1/webhooks/{id}", {"url": ENDPOINT}),
    ("delete", "/v1/webhooks/{id}", None),
    ("post", "/v1/webhooks/{id}/ping", None),
    ("post", "/v1/webhooks/{id}/resume", None),
    ("post", "/v1/webhooks/{id}/secret", None),
    ("delete", "/v1/webhooks/{id}/secret/previous", None),
])
def test_an_operator_is_refused_every_write_and_told_which_scope(
        console, method, path, body):
    """The server refuses, and names `webhooks:manage`. No page was rendered first."""
    client, _, _ = console
    created = _register(client, "wh-scope")
    headers = _operator(**{"Idempotency-Key": "wh-scope-2"})
    response = getattr(client, method)(
        path.format(id=created["subscription_id"]),
        headers=headers, **({"json": body} if body is not None else {}))
    assert response.status_code == 403
    error = response.json()["error"]
    assert error["code"] == "forbidden"
    assert error["detail"]["missing_scopes"] == ["webhooks:manage"]


def test_an_operator_grant_may_still_see_that_an_endpoint_is_failing(console):
    """`webhooks:read` without `webhooks:manage` is the point of the split."""
    client, _, _ = console
    _register(client, "wh-read")
    listed = client.get("/v1/webhooks", headers=_operator())
    assert listed.status_code == 200
    assert listed.json()["webhooks"][0]["health"] == "untested"


def test_a_viewer_grant_may_not_even_look(console):
    client, _, _ = console
    refused = client.get("/v1/webhooks", headers=_viewer())
    assert refused.status_code == 403
    assert refused.json()["error"]["detail"]["missing_scopes"] == ["webhooks:read"]


# --- rotation ---------------------------------------------------------------

def test_a_rotation_signs_with_both_secrets_until_it_is_finished(console):
    """The property the whole design exists for, checked at the receiving end."""
    client, engine, settings = console
    created = _register(client, "wh-rotate")
    subscription_id = created["subscription_id"]
    first = created["secret"]

    rotated = client.post(f"/v1/webhooks/{subscription_id}/secret",
                          headers=_admin())
    assert rotated.status_code == 201
    second = rotated.json()["secret"]
    assert second != first
    assert rotated.json()["secret_generation"] == 2
    assert rotated.json()["secret_rotating"] is True

    worker = WebhookSubscriptions(engine, settings.custody_key())
    live = worker.signing_secrets(subscription_id)
    assert live == (second, first)

    body = canonical_body({"event_id": "evt-1"})
    headers = delivery_headers(
        event_type="order.accepted", event_id="evt-1", delivery_id="whd_1",
        attempt=1, timestamp=1756512251,
        signature=sign_all(live, 1756512251, body))
    # A consumer that has been switched over, and one that has not. Both accept.
    assert verify_from_the_contract(second, headers, body) is True
    assert verify_from_the_contract(first, headers, body) is True

    retired = client.delete(f"/v1/webhooks/{subscription_id}/secret/previous",
                            headers=_admin())
    assert retired.status_code == 200
    assert retired.json()["secret_rotating"] is False
    assert worker.signing_secrets(subscription_id) == (second,)

    after = delivery_headers(
        event_type="order.accepted", event_id="evt-2", delivery_id="whd_2",
        attempt=1, timestamp=1756512251,
        signature=sign_all(worker.signing_secrets(subscription_id),
                           1756512251, body))
    assert verify_from_the_contract(second, after, body) is True
    assert verify_from_the_contract(first, after, body) is False


def test_a_second_rotation_before_the_first_is_finished_is_refused(console):
    """Otherwise the value the endpoint is actually using is silently dropped."""
    client, _, _ = console
    created = _register(client, "wh-rotate-twice")
    path = f"/v1/webhooks/{created['subscription_id']}/secret"
    assert client.post(path, headers=_admin()).status_code == 201
    refused = client.post(path, headers=_admin())
    assert refused.status_code == 409
    assert "finish that rotation" in refused.json()["error"]["message"]


def test_retiring_when_nothing_is_rotating_is_refused(console):
    client, _, _ = console
    created = _register(client, "wh-retire-none")
    refused = client.delete(
        f"/v1/webhooks/{created['subscription_id']}/secret/previous",
        headers=_admin())
    assert refused.status_code == 409


# --- parking, in the console ------------------------------------------------

def _park(engine, settings, subscription_id: str) -> None:
    """What the dispatcher does after `PARK_AFTER` exhausted deliveries.

    Driven through the dispatcher's own bookkeeping rather than by writing
    `parked_at` and stranding the queue by hand, so what the console renders is
    the state the delivery path actually produces.
    """
    dispatcher = WebhookDispatcher(engine, settings.custody_key())
    now = utcnow()
    for _ in range(PARK_AFTER):
        dispatcher._subscription_failed(
            subscription_id, 500, "the endpoint answered HTTP 500", now)


def test_the_console_shows_a_parked_endpoint_and_un_parks_it(console):
    client, engine, settings = console
    created = _register(client, "wh-park")
    subscription_id = created["subscription_id"]
    client.post(f"/v1/webhooks/{subscription_id}/ping", headers=_admin())
    _park(engine, settings, subscription_id)
    with engine.connect() as connection:
        stranded = connection.execute(
            select(webhook_delivery.c.state)
            .where(webhook_delivery.c.subscription_id
                   == subscription_id)).scalars().all()
    assert stranded == [PARKED]

    page = client.get("/ui/webhooks", headers=_admin(**BROWSER))
    assert page.status_code == 200
    assert "parked" in page.text
    assert "endpoint parked" in page.text

    resumed = client.post(f"/ui/webhooks/{subscription_id}/resume",
                          headers=_admin(**BROWSER), follow_redirects=False)
    assert resumed.status_code == 303
    after = client.get(f"/v1/webhooks/{subscription_id}", headers=_admin()).json()
    assert after["parked"] is False and after["health"] != "parked"
    listed = client.get(f"/v1/webhooks/{subscription_id}/deliveries",
                        headers=_admin()).json()
    assert listed["deliveries"][0]["state"] == PENDING


# --- the console ------------------------------------------------------------

def test_every_webhook_console_page_renders(console):
    client, _, _ = console
    created = _register(client, "wh-pages")
    for path in ("/ui/webhooks", "/ui/webhooks/new",
                 f"/ui/webhooks/{created['subscription_id']}"):
        page = client.get(path, headers=_admin(**BROWSER))
        assert page.status_code == 200, (path, page.text[:300])
        assert "<!doctype html>" in page.text.lower(), path
        assert created["secret"] not in page.text, path


def test_registering_through_the_console_shows_the_secret_once(console):
    client, engine, settings = console
    form = client.get("/ui/webhooks/new", headers=_admin(**BROWSER)).text
    key = form.split('name="idempotency_key" value="')[1].split('"')[0]
    body = (f"idempotency_key={key}&url=https%3A%2F%2Fconsumer.example.test"
            f"%2Fconsole&description=From+the+console"
            f"&event%3Aorder.accepted=1")
    created = client.post(
        "/ui/webhooks", content=body,
        headers=_admin(**BROWSER,
                       **{"content-type": "application/x-www-form-urlencoded"}))
    assert created.status_code == 200
    assert "It is not shown again" in created.text

    listed = client.get("/v1/webhooks", headers=_admin()).json()["webhooks"]
    assert [row["url"] for row in listed] == ["https://consumer.example.test/console"]
    assert listed[0]["event_types"] == ["order.accepted"]

    # The value on the page is the value the worker will sign with.
    secret = created.text.split('class="fingerprint">')[1].split("<")[0]
    worker = WebhookSubscriptions(engine, settings.custody_key())
    assert worker.open_secret(listed[0]["subscription_id"]) == secret

    # And a reload of that POST registers nothing more.
    again = client.post(
        "/ui/webhooks", content=body,
        headers=_admin(**BROWSER,
                       **{"content-type": "application/x-www-form-urlencoded"}))
    assert again.status_code == 200
    assert "already registered" in again.text
    assert secret not in again.text
    assert len(client.get("/v1/webhooks", headers=_admin()).json()["webhooks"]) == 1


def test_an_operator_is_refused_the_console_writes_too(console):
    client, _, _ = console
    created = _register(client, "wh-ui-scope")
    refused = client.post(
        f"/ui/webhooks/{created['subscription_id']}/pause",
        headers=_operator(**BROWSER))
    assert refused.status_code == 403
    assert "webhooks:manage" in refused.text


def test_a_viewer_grant_is_not_offered_the_section_at_all(console):
    client, _, _ = console
    page = client.get("/ui/connections", headers=_viewer(**BROWSER))
    assert 'href="/ui/webhooks"' not in page.text
    operator_page = client.get("/ui/connections", headers=_operator(**BROWSER))
    assert 'href="/ui/webhooks"' in operator_page.text
