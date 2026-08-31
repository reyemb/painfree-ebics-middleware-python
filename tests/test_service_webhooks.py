"""The event contract: what is emitted, what it looks like, and how it is signed.

Two things here are worth stating about method.

**The signature is checked by a verifier written from the contract**, not by
calling :func:`painfree.webhooks.sign`. Asserting that a function agrees with
itself proves nothing about whether a consumer following
the envelope contract can verify what this service sends, which is the only
property that matters. :func:`verify_from_the_contract` below is the envelope
contract transcribed into Python and nothing else.

**The events come out of the real flows.** No test here calls ``fan_out``
directly with a made-up action. A payment is submitted, a bank refuses one, a
`camt` document is ingested, and the deliveries that appear are the ones those
flows produced -- because an event source that has to be driven by hand is one
that will not fire in production.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import logging

import pytest
from sqlalchemy import select, update

from conftest import (BANK_CONNECTION_ID, fixture_bytes, payment_body,
                      transfer)
from painfree import db, ebics3, payments, wrapping
from painfree.audit import AuditLog
from painfree.connections import ConnectionRegistry
from painfree.errors import ConflictError, NotFoundError
from painfree.logging import JsonFormatter
from painfree.orders import OrderStore
from painfree.queue import OrderQueue
from painfree.schema import bank_connection, webhook_delivery
from painfree.sealing import CorruptSealError
from painfree.statements import StatementStore
from painfree.webhooks import (ENVELOPE_VERSION, EVENT_TYPES, PENDING,
                               SIGNATURE_HEADER, TIMESTAMP_HEADER,
                               WebhookSubscriptions, canonical_body,
                               delivery_headers, envelope, sign, utcnow)

CONNECTION = BANK_CONNECTION_ID
SECRET = "webhook-test-signing-secret-do-not-reuse-0001"
ALL_TYPES = sorted(set(EVENT_TYPES.values()))


# --- an independent verifier ------------------------------------------------

def verify_from_the_contract(secret: str, headers: dict, body: bytes) -> bool:
    """The envelope contract, transcribed. Touches no painfree code.

    A consumer reads the timestamp and the signature out of the headers,
    recomputes ``HMAC-SHA256(secret, "<timestamp>.<raw body>")`` and compares.
    The header carries a comma-separated list -- one entry ordinarily, two while
    a secret is being rotated -- and the request is accepted if any entry
    verifies. That is the whole scheme; if this function cannot verify what the
    dispatcher sends, neither can anybody's consumer.
    """
    signed = headers[TIMESTAMP_HEADER].encode("ascii") + b"." + body
    expected = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    for entry in headers[SIGNATURE_HEADER].split(","):
        scheme, _, digest = entry.strip().partition("=")
        if scheme == "v1" and hmac.compare_digest(expected, digest):
            return True
    return False


# --- fixtures ---------------------------------------------------------------

@pytest.fixture
def engine(custody_settings):
    engine = db.build_engine(custody_settings)
    db.migrate(engine)
    ConnectionRegistry(engine).register(
        CONNECTION, host_id="WHHOST", partner_id="PARTNER1", user_id="USER1",
        host_url="https://ebics.example.test/")
    with engine.begin() as connection:
        connection.execute(
            update(bank_connection)
            .where(bank_connection.c.connection_id == CONNECTION)
            .values(key_state=ebics3.KeyState.READY.value,
                    ini_sent=True, hia_sent=True))
    yield engine
    engine.dispose()


@pytest.fixture
def subscriptions(engine, custody_settings):
    return WebhookSubscriptions(engine, custody_settings.custody_key())


def deliveries(engine, event_type: str | None = None) -> list[dict]:
    query = select(webhook_delivery).order_by(webhook_delivery.c.seq)
    if event_type is not None:
        query = query.where(webhook_delivery.c.event_type == event_type)
    with engine.connect() as connection:
        return [dict(row) for row in connection.execute(query).mappings()]


def submit(engine, key: str = "caller-idem-0001", **overrides):
    return OrderStore(engine).submit(
        CONNECTION, idempotency_key=key,
        instruction=payments.PaymentInstruction(**payment_body(**overrides)))


# --- the envelope -----------------------------------------------------------

def test_the_envelope_carries_its_version_and_omits_what_it_does_not_know():
    """An id that is not known is absent, never null -- as in the log stream."""
    event = envelope(event_id="evt-1", event_type="statement.available",
                     occurred_at=_dt.datetime(2026, 8, 30, 10, 4, 11,
                                              tzinfo=_dt.timezone.utc),
                     connection_id="acme-ubs", data={"statement_id": "stm_1"})
    assert event["version"] == ENVELOPE_VERSION
    assert event["occurred_at"] == "2026-08-30T10:04:11.000Z"
    assert "order_id" not in event
    assert "idempotency_key" not in event
    assert event["data"] == {"statement_id": "stm_1"}


def test_the_signed_body_is_stable_across_serialisations():
    """A redelivery signs the same bytes, so its signature is the same too."""
    one = envelope(event_id="e", event_type="order.accepted",
                   occurred_at=utcnow(), data={"b": 2, "a": 1})
    reparsed = json.loads(canonical_body(one).decode())
    assert canonical_body(reparsed) == canonical_body(one)


# --- the signature ----------------------------------------------------------

def test_the_signature_verifies_under_a_verifier_written_from_the_contract():
    body = b'{"event_id":"evt-1"}'
    headers = delivery_headers(event_type="order.accepted", event_id="evt-1",
                               delivery_id="whd_1", attempt=1,
                               timestamp=1756512251,
                               signature=sign(SECRET, 1756512251, body))
    assert verify_from_the_contract(SECRET, headers, body) is True


@pytest.mark.parametrize("tamper", ["body", "timestamp", "secret"])
def test_a_tampered_delivery_does_not_verify(tamper):
    """Each of the three inputs is inside the MAC, so each one breaks it."""
    body = b'{"event_id":"evt-1","data":{"amount":"1.00"}}'
    headers = delivery_headers(event_type="order.accepted", event_id="evt-1",
                               delivery_id="whd_1", attempt=1,
                               timestamp=1756512251,
                               signature=sign(SECRET, 1756512251, body))
    secret = SECRET
    if tamper == "body":
        body = body.replace(b'"1.00"', b'"9999.00"')
    elif tamper == "timestamp":
        headers[TIMESTAMP_HEADER] = "1756512999"
    else:
        secret = SECRET + "x"
    assert verify_from_the_contract(secret, headers, body) is False


def test_the_timestamp_is_inside_the_mac_so_a_replay_cannot_be_re_dated():
    """A receiver that refuses an old timestamp is refusing a signed value."""
    body = b"{}"
    old = sign(SECRET, 1756512251, body)
    fresh = sign(SECRET, 1756599999, body)
    assert old != fresh


# --- subscriptions and their secrets ----------------------------------------

def test_a_registered_secret_round_trips_through_the_seal(subscriptions):
    subscription, secret = subscriptions.register(
        "https://consumer.example.test/hooks", ALL_TYPES,
        connection_id=CONNECTION)
    assert secret == subscriptions.open_secret(subscription.subscription_id)
    assert len(secret) >= 32


def test_the_secret_is_never_stored_in_the_clear(engine, subscriptions):
    from painfree.schema import webhook_subscription

    subscription, secret = subscriptions.register(
        "https://consumer.example.test/hooks", ALL_TYPES)
    with engine.connect() as connection:
        row = connection.execute(select(webhook_subscription)).mappings().one()
    assert secret.encode() not in row["sealed_secret"]
    assert row["custody_key_id"] == subscription.custody_key_id


def test_a_secret_sealed_for_one_subscription_will_not_open_for_another(
        engine, subscriptions, custody_settings):
    """The subscription id is the AEAD's associated data, not decoration."""
    from painfree.schema import webhook_subscription

    first, _ = subscriptions.register("https://a.example.test/", ALL_TYPES)
    second, _ = subscriptions.register("https://b.example.test/", ALL_TYPES)
    with engine.connect() as connection:
        stolen = connection.execute(
            select(webhook_subscription.c.sealed_secret)
            .where(webhook_subscription.c.subscription_id
                   == first.subscription_id)).scalar_one()
    with engine.begin() as connection:
        connection.execute(
            webhook_subscription.update()
            .where(webhook_subscription.c.subscription_id
                   == second.subscription_id)
            .values(sealed_secret=stolen))
    with pytest.raises(CorruptSealError):
        subscriptions.open_secret(second.subscription_id)


def test_a_process_without_a_custody_key_registers_but_cannot_read_back(
        engine, subscriptions, custody_settings):
    """The asymmetry sealing is about, in one test.

    Before sealing, a keyless process could not register at all, which is why
    subscriptions had no HTTP surface: the API process holds no custody key. It
    now registers -- sealing to the published public half -- and still cannot
    open what it stored, which is the stronger property. A refusal here would
    only mean the API cannot register; what matters is that it cannot *read*.
    """
    # What a worker start does, and the only bootstrap there is.
    wrapping.publish(engine, custody_settings.custody_key())
    keyless = WebhookSubscriptions(engine)
    subscription, secret = keyless.register(
        "https://consumer.example.test/keyless", ALL_TYPES)
    with pytest.raises(ConflictError, match="custody key"):
        keyless.signing_secrets(subscription.subscription_id)
    with pytest.raises(ConflictError, match="custody key"):
        keyless.open_secret(subscription.subscription_id)
    # The worker, which holds the key, opens exactly what was generated.
    assert subscriptions.open_secret(subscription.subscription_id) == secret


def test_registering_without_a_published_wrapping_key_says_what_is_missing(
        custody_settings):
    """A first registration before any worker ran is a `503` naming the fix."""
    from painfree.errors import NotReadyError

    engine = db.build_engine(custody_settings)
    db.migrate(engine)
    try:
        with pytest.raises(NotReadyError, match="worker"):
            WebhookSubscriptions(engine).register(
                "https://consumer.example.test/", ALL_TYPES)
    finally:
        engine.dispose()


def test_an_unknown_event_type_is_refused_with_the_known_ones(subscriptions):
    with pytest.raises(ConflictError) as raised:
        subscriptions.register("https://consumer.example.test/",
                               ["order.exploded"])
    assert raised.value.detail["known"] == ALL_TYPES


def test_an_endpoint_that_is_not_http_is_refused(subscriptions):
    with pytest.raises(ConflictError, match="http"):
        subscriptions.register("file:///etc/passwd", ALL_TYPES)


def test_a_missing_subscription_is_a_not_found(subscriptions):
    with pytest.raises(NotFoundError):
        subscriptions.get("whs_nope")


def test_the_secret_does_not_reach_the_log_stream_even_through_a_traceback(
        engine, subscriptions, caplog):
    """The one failure mode a name-based blocklist cannot see: free text.

    `register_secret` teaches the formatter the exact string, so a message or
    a traceback that interpolated it is scrubbed rather than printed.
    """
    _, secret = subscriptions.register("https://consumer.example.test/",
                                       ALL_TYPES)
    formatter = JsonFormatter()
    try:
        raise RuntimeError(f"posting with secret {secret} failed")
    except RuntimeError:
        import sys

        record = logging.LogRecord("t", logging.ERROR, __file__, 1, "boom",
                                   (), sys.exc_info())
    line = formatter.format(record)
    assert secret not in line
    assert "<redacted:secret>" in line


# --- the real flows emit real events ----------------------------------------

def test_accepting_a_payment_owes_an_order_accepted_event(engine, subscriptions):
    subscriptions.register("https://consumer.example.test/", ALL_TYPES,
                           connection_id=CONNECTION)
    submission = submit(engine)

    owed = deliveries(engine)
    assert [row["event_type"] for row in owed] == ["order.accepted"]
    row = owed[0]
    assert row["state"] == PENDING
    assert row["order_id"] == submission.order.order_id
    assert row["idempotency_key"] == "caller-idem-0001"
    event = row["payload"]
    assert event["connection_id"] == CONNECTION
    assert event["data"]["msg_id"] == submission.order.msg_id
    assert event["data"]["transactions"] == 1


def test_the_event_id_is_the_audit_event_id(engine, subscriptions):
    """One id for the fact and for the event, so a consumer's id greps the trail."""
    from painfree.schema import audit_log

    subscriptions.register("https://consumer.example.test/", ALL_TYPES)
    submit(engine)
    with engine.connect() as connection:
        audited = connection.execute(
            select(audit_log.c.event_id)
            .where(audit_log.c.action == "payment.accepted")).scalar_one()
    owed = deliveries(engine)[0]
    assert owed["event_id"] == audited == owed["payload"]["event_id"]


def test_a_bank_refusal_owes_an_order_rejected_event(engine, subscriptions):
    subscriptions.register("https://consumer.example.test/", ALL_TYPES)
    submission = submit(engine)
    OrderQueue(engine).refused(submission.order.order_id,
                               return_code="091002", report_text="[EBICS…] no",
                               name="EBICS_INVALID_ORDER_IDENTIFIER")

    rejected = deliveries(engine, "order.rejected")
    assert len(rejected) == 1
    data = rejected[0]["payload"]["data"]
    assert data["return_code"] == "091002"
    assert data["report_text"] == "[EBICS…] no"
    assert rejected[0]["order_id"] == submission.order.order_id


def test_giving_up_on_an_order_owes_an_order_failed_event(engine, subscriptions):
    """`failed` is this service giving up, and a consumer has to hear about it."""
    from painfree.queue import MAX_ATTEMPTS

    subscriptions.register("https://consumer.example.test/", ALL_TYPES)
    submission = submit(engine)
    OrderQueue(engine).retry_later(submission.order.order_id,
                                   attempts=MAX_ATTEMPTS, reason="unreachable")
    assert [row["event_type"] for row in deliveries(engine)] == [
        "order.accepted", "order.failed"]


def test_ingesting_a_statement_owes_a_statement_available_event(
        engine, subscriptions):
    subscriptions.register("https://consumer.example.test/", ALL_TYPES)
    result = StatementStore(engine).ingest(
        CONNECTION, [fixture_bytes("camt.053.001.08")], run_id="run_test")
    assert result.stored == 1

    owed = deliveries(engine, "statement.available")
    assert len(owed) == 1
    data = owed[0]["payload"]["data"]
    assert data["statement_id"] == result.statement_ids[0]
    assert data["message_type"] == "camt.053.001.08"
    assert data["entries"] == 3
    # Statement content is never in an event: an entry is somebody's payment.
    assert "entries_detail" not in data and "payload" not in data
    assert "Robert Schneider" not in json.dumps(owed[0]["payload"])


def test_a_re_served_statement_owes_nothing_the_second_time(engine, subscriptions):
    """No new row, so no second event. Idempotent ingestion is what decides."""
    subscriptions.register("https://consumer.example.test/", ALL_TYPES)
    store = StatementStore(engine)
    document = [fixture_bytes("camt.053.001.08")]
    store.ingest(CONNECTION, document, run_id="run_1")
    store.ingest(CONNECTION, document, run_id="run_2")
    assert len(deliveries(engine, "statement.available")) == 1


def test_a_validation_failure_is_not_an_order_rejected_event(engine, subscriptions):
    """No order exists to reject, and only the bank rejects."""
    from painfree import sps

    subscriptions.register("https://consumer.example.test/", ALL_TYPES)
    with pytest.raises(sps.ValidationFailed):
        submit(engine, transactions=[transfer(amount="1.005")])
    assert deliveries(engine) == []


def test_a_reused_idempotency_key_is_not_an_order_rejected_event(
        engine, subscriptions):
    subscriptions.register("https://consumer.example.test/", ALL_TYPES)
    submit(engine)
    with pytest.raises(ConflictError):
        submit(engine, transactions=[transfer(amount="1.00")])
    assert [row["event_type"] for row in deliveries(engine)] == ["order.accepted"]


# --- who is owed what -------------------------------------------------------

def test_a_subscription_only_receives_the_types_it_asked_for(engine, subscriptions):
    subscriptions.register("https://only-statements.example.test/",
                           ["statement.available"])
    submit(engine)
    assert deliveries(engine) == []


def test_a_subscription_scoped_to_a_connection_hears_only_that_one(
        engine, subscriptions):
    ConnectionRegistry(engine).register(
        "other-bank", host_id="OHOST", partner_id="P2", user_id="U2",
        host_url="https://other.example.test/")
    subscriptions.register("https://scoped.example.test/", ALL_TYPES,
                           connection_id="other-bank")
    submit(engine)
    assert deliveries(engine) == []


def test_one_event_is_owed_to_every_subscription_that_wants_it(
        engine, subscriptions):
    """Three consumers, one event id: that is what redelivery-safe dedup means."""
    for number in range(3):
        subscriptions.register(f"https://consumer{number}.example.test/",
                               ALL_TYPES)
    submit(engine)
    owed = deliveries(engine)
    assert len(owed) == 3
    assert len({row["event_id"] for row in owed}) == 1
    assert len({row["delivery_id"] for row in owed}) == 3


def test_an_action_that_is_not_an_event_type_owes_nothing(engine, subscriptions):
    subscriptions.register("https://consumer.example.test/", ALL_TYPES)
    AuditLog(engine).record("worker.started", detail={"worker_id": "w"})
    assert deliveries(engine) == []


def test_a_parked_subscription_stops_accruing_events(engine, subscriptions):
    """The bound on growth: a dead endpoint's queue stops rather than fills."""
    from painfree.schema import webhook_subscription

    subscription, _ = subscriptions.register("https://dead.example.test/",
                                             ALL_TYPES)
    with engine.begin() as connection:
        connection.execute(
            webhook_subscription.update().values(parked_at=utcnow()))
    submit(engine)
    assert deliveries(engine) == []


def test_the_event_and_the_fact_are_written_in_one_transaction(engine,
                                                               subscriptions):
    """A fan-out that cannot be written fails the audit write.

    Proved by making the delivery insert impossible -- the delivery table is
    dropped -- and asserting that the audit row is not there either.
    """
    from painfree.schema import audit_log, webhook_delivery as table

    subscriptions.register("https://consumer.example.test/", ALL_TYPES)
    table.drop(engine)
    with pytest.raises(Exception):
        AuditLog(engine).record("payment.accepted", connection_id=CONNECTION,
                                order_id="ord_x", detail={"msg_id": "M1"})
    with engine.connect() as connection:
        assert connection.execute(
            select(audit_log).where(audit_log.c.order_id == "ord_x")
        ).mappings().one_or_none() is None
