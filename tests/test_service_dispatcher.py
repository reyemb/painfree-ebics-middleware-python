"""Delivering the events: at-least-once, in order, isolated, and signed.

Every consumer in this file is a **real HTTP server on a real socket**, and
every signature is checked with :func:`verify_from_the_contract` -- the verifier
written from the envelope contract rather than from this service's signing
function. A mocked transport would prove that the dispatcher calls a method;
the properties claimed here are about what arrives at the other end of a
socket, so that is where they are asserted.

The concurrency tests run against PostgreSQL whenever a server is reachable,
because ``FOR UPDATE SKIP LOCKED`` and SQLite's single write lock are two
mechanisms for one property and only one of them runs by default. A run that
does not happen **skips with a message saying so**.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from sqlalchemy import create_engine, select, update

from conftest import BANK_CONNECTION_ID, payment_body, reset_database
from test_service_webhooks import verify_from_the_contract

from painfree import db, ebics3, payments
from painfree.config import load_settings
from painfree.connections import ConnectionRegistry
from painfree.dispatcher import (BACKOFF, CLAIM_LEASE, MAX_ATTEMPTS,
                                 PARK_AFTER, WebhookDispatcher,
                                 build_dispatcher, post)
from painfree.orders import OrderStore
from painfree.schema import bank_connection, webhook_delivery
from painfree.webhooks import (DELIVERED, EVENT_ID_HEADER, EVENT_TYPES,
                               FAILED, PARKED, PENDING, WebhookSubscriptions,
                               utcnow)

CONNECTION = BANK_CONNECTION_ID
ALL_TYPES = sorted(set(EVENT_TYPES.values()))

POSTGRES_URL = os.environ.get("POSTGRES_TEST_URL")
requires_postgres = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="POSTGRES_TEST_URL is not set: no PostgreSQL server was reached, so "
           "the PostgreSQL half of the concurrent-delivery gate did not run",
)


# --- a consumer -------------------------------------------------------------

class Consumer:
    """An endpoint that records what it was sent and answers how it is told to.

    ``status`` may be a single code or a list consumed one per request, which
    is how "fails twice, then works" is expressed without a mock.
    """

    def __init__(self, status=200, delay: float = 0.0) -> None:
        self._status = status
        self.delay = delay
        self.received: list[tuple[dict, bytes]] = []
        self._lock = threading.Lock()

    def answer(self, headers: dict, body: bytes) -> int:
        if self.delay:
            time.sleep(self.delay)
        with self._lock:
            self.received.append((headers, body))
            if isinstance(self._status, list):
                index = min(len(self.received) - 1, len(self._status) - 1)
                return self._status[index]
            return self._status

    @property
    def bodies(self) -> list[dict]:
        return [json.loads(body) for _, body in self.received]

    @property
    def event_ids(self) -> list[str]:
        return [headers[EVENT_ID_HEADER] for headers, _ in self.received]


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802 -- BaseHTTPRequestHandler API
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        status = self.server.consumer.answer(dict(self.headers), body)
        self.send_response(status)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args) -> None:
        pass


@contextlib.contextmanager
def serving(consumer: Consumer):
    """Run one consumer for the duration of the block; yields its URL."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.consumer = consumer
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{server.server_address[0]}:{server.server_address[1]}/hooks"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# --- fixtures ---------------------------------------------------------------

def provision(engine) -> None:
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


@pytest.fixture
def engine(custody_settings):
    engine = db.build_engine(custody_settings)
    provision(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def dispatcher(engine, custody_settings):
    return WebhookDispatcher(engine, custody_settings.custody_key(),
                             worker_id="test-dispatcher", timeout=5.0)


def submit(engine, key: str = "caller-idem-0001", **overrides):
    """One real payment submission -- which is what emits `order.accepted`."""
    return OrderStore(engine).submit(
        CONNECTION, idempotency_key=key,
        instruction=payments.PaymentInstruction(**payment_body(**overrides)))


def rows(engine, **where) -> list[dict]:
    query = select(webhook_delivery).order_by(webhook_delivery.c.seq)
    for name, value in where.items():
        query = query.where(webhook_delivery.c[name] == value)
    with engine.connect() as connection:
        return [dict(row) for row in connection.execute(query).mappings()]


def drain(dispatcher, limit: int = 20) -> list:
    results = []
    while len(results) < limit:
        result = dispatcher.run_once()
        if result is None:
            break
        results.append(result)
    return results


# --- the happy path, over a socket ------------------------------------------

def test_an_event_is_delivered_and_verifies_under_the_contract(
        engine, dispatcher, custody_settings):
    consumer = Consumer()
    with serving(consumer) as url:
        subscriptions = WebhookSubscriptions(engine,
                                             custody_settings.custody_key())
        _, secret = subscriptions.register(url, ALL_TYPES)
        submission = submit(engine)

        result = dispatcher.run_once()

    assert result.ok and result.status == 200
    headers, body = consumer.received[0]
    # The verifier is written from the contract, not from `webhooks.sign`.
    assert verify_from_the_contract(secret, headers, body) is True
    event = json.loads(body)
    assert event["event_type"] == "order.accepted"
    assert event["order_id"] == submission.order.order_id
    assert event["event_id"] == result.event_id
    assert rows(engine)[0]["state"] == DELIVERED


def test_the_body_the_consumer_verifies_is_the_body_that_was_stored(
        engine, dispatcher, custody_settings):
    """Signing a re-serialisation of the payload would break every consumer."""
    from painfree.webhooks import canonical_body

    consumer = Consumer()
    with serving(consumer) as url:
        WebhookSubscriptions(engine, custody_settings.custody_key()).register(
            url, ALL_TYPES)
        submit(engine)
        stored = rows(engine)[0]["payload"]
        dispatcher.run_once()
    assert consumer.received[0][1] == canonical_body(stored)


def test_nothing_is_claimable_when_nothing_is_owed(dispatcher):
    assert dispatcher.run_once() is None


# --- at-least-once ----------------------------------------------------------

def test_an_event_survives_a_dispatcher_that_died_mid_post(
        engine, dispatcher, custody_settings):
    """The claim is a lease, and the redelivery carries the same event id.

    A dispatcher that POSTed and died before writing the outcome leaves the row
    in `delivering`. The consumer may or may not have received it -- which is
    exactly why the id is stable and the contract says to deduplicate on it.
    """
    consumer = Consumer()
    with serving(consumer) as url:
        WebhookSubscriptions(engine, custody_settings.custody_key()).register(
            url, ALL_TYPES)
        submit(engine)
        first = dispatcher.claim()
        assert first is not None
        # The process dies here: claimed, never settled.
        with engine.begin() as connection:
            connection.execute(
                webhook_delivery.update().values(
                    claimed_at=utcnow() - CLAIM_LEASE - _dt.timedelta(minutes=1)))
        second = dispatcher.run_once()

    assert second.event_id == first.event_id
    assert consumer.event_ids == [first.event_id]
    assert rows(engine)[0]["attempts"] == 2


def test_an_event_recorded_while_nothing_was_dispatching_is_delivered_later(
        engine, dispatcher, custody_settings):
    """Persisted first, delivered second: the order that makes a crash survivable."""
    consumer = Consumer()
    with serving(consumer) as url:
        subscriptions = WebhookSubscriptions(engine,
                                             custody_settings.custody_key())
        subscriptions.register(url, ALL_TYPES)
        submit(engine)
        # Nothing has been delivered and the event is already durable.
        assert rows(engine)[0]["state"] == PENDING
        assert consumer.received == []
        assert dispatcher.run_once().ok

    assert len(consumer.received) == 1


# --- retries, backoff and parking -------------------------------------------

def test_a_failing_endpoint_is_retried_with_backoff_then_given_up_on(
        engine, dispatcher, custody_settings):
    consumer = Consumer(status=500)
    with serving(consumer) as url:
        WebhookSubscriptions(engine, custody_settings.custody_key()).register(
            url, ALL_TYPES)
        submit(engine)

        waits = []
        for attempt in range(1, MAX_ATTEMPTS + 1):
            before = utcnow()
            result = dispatcher.run_once()
            row = rows(engine)[0]
            if row["state"] == PENDING:
                waits.append(round((row["next_attempt_at"] - before)
                                   .total_seconds()))
                # Nothing is claimable until the backoff has expired.
                assert dispatcher.claim() is None
                with engine.begin() as connection:
                    connection.execute(webhook_delivery.update()
                                       .values(next_attempt_at=utcnow()))
        assert result.state == FAILED

    assert waits == [int(wait.total_seconds()) for wait in BACKOFF]
    assert len(consumer.received) == MAX_ATTEMPTS
    row = rows(engine)[0]
    assert row["last_status"] == 500 and row["attempts"] == MAX_ATTEMPTS


def test_a_permanently_dead_endpoint_is_parked_rather_than_retried_for_ever(
        engine, dispatcher, custody_settings):
    """The bound on growth: the subscription stops, and its events are kept."""
    consumer = Consumer(status=503)
    with serving(consumer) as url:
        subscriptions = WebhookSubscriptions(engine,
                                             custody_settings.custody_key())
        subscription, _ = subscriptions.register(url, ALL_TYPES)
        for number in range(PARK_AFTER):
            submit(engine, key=f"caller-idem-{number:04d}")
            _exhaust(engine, dispatcher)

        assert subscriptions.get(subscription.subscription_id).parked is True
        # New events stop being accrued, and nothing more is claimed.
        submit(engine, key="caller-idem-9999")
        assert dispatcher.run_once() is None
        answered = len(consumer.received)

        assert [row["state"] for row in rows(engine)] == [FAILED] * PARK_AFTER
        requeued = subscriptions.resume(subscription.subscription_id)

    assert requeued == 0          # the failed ones stay failed; parked ones return
    assert subscriptions.get(subscription.subscription_id).parked is False
    assert answered == PARK_AFTER * MAX_ATTEMPTS


def test_parking_returns_queued_events_when_the_endpoint_is_resumed(
        engine, dispatcher, custody_settings):
    consumer = Consumer(status=500)
    with serving(consumer) as url:
        subscriptions = WebhookSubscriptions(engine,
                                             custody_settings.custody_key())
        subscription, _ = subscriptions.register(url, ALL_TYPES)
        for number in range(PARK_AFTER + 2):
            submit(engine, key=f"caller-idem-{number:04d}")
        for _ in range(PARK_AFTER):
            _exhaust(engine, dispatcher)

        parked = [row for row in rows(engine) if row["state"] == PARKED]
        assert len(parked) == 2, "queued events were dropped rather than parked"
        assert subscriptions.resume(subscription.subscription_id) == 2
    assert [row["state"] for row in rows(engine)].count(PENDING) == 2


def _exhaust(engine, dispatcher) -> None:
    """Run one delivery to its ceiling, skipping the waits."""
    for _ in range(MAX_ATTEMPTS):
        dispatcher.run_once()
        with engine.begin() as connection:
            connection.execute(webhook_delivery.update()
                               .where(webhook_delivery.c.state == PENDING)
                               .values(next_attempt_at=utcnow()))


# --- ordering and isolation -------------------------------------------------

def test_events_for_one_connection_are_delivered_in_order(
        engine, dispatcher, custody_settings):
    """`order.submitted` before `order.accepted` is not a sequence to act on."""
    from painfree.queue import OrderQueue

    consumer = Consumer()
    with serving(consumer) as url:
        WebhookSubscriptions(engine, custody_settings.custody_key()).register(
            url, ALL_TYPES)
        submission = submit(engine)
        queue = OrderQueue(engine)
        queue.submitted(submission.order.order_id, bank_order_id="N01A",
                        return_code="000000", report_text=None)
        drain(dispatcher)
    assert [event["event_type"] for event in consumer.bodies] == [
        "order.accepted", "order.submitted"]


def test_one_subscription_never_has_two_deliveries_in_flight(
        engine, dispatcher, custody_settings):
    """The predicate that buys ordering: a second claim finds nothing."""
    consumer = Consumer()
    with serving(consumer) as url:
        WebhookSubscriptions(engine, custody_settings.custody_key()).register(
            url, ALL_TYPES)
        submit(engine, key="caller-idem-0001")
        submit(engine, key="caller-idem-0002")
        first = dispatcher.claim()
        assert first is not None
        assert dispatcher.claim() is None, "two events were in flight at once"


def test_a_retrying_event_is_not_overtaken_by_the_next_one(
        engine, dispatcher, custody_settings):
    """The ordering bug a live run found: backing off is still owed.

    A candidate query that skips only the *in-flight* row looks correct and is
    not: while event one waits out its backoff, event two is `pending` and due,
    so the consumer is told a payment was submitted before it is told the
    payment was accepted.
    """
    from painfree.queue import OrderQueue

    consumer = Consumer(status=500)
    with serving(consumer) as url:
        WebhookSubscriptions(engine, custody_settings.custody_key()).register(
            url, ALL_TYPES)
        submission = submit(engine)
        OrderQueue(engine).submitted(submission.order.order_id,
                                     bank_order_id="N01A",
                                     return_code="000000", report_text=None)
        assert [row["event_type"] for row in rows(engine)] == [
            "order.accepted", "order.submitted"]

        first = dispatcher.run_once()          # order.accepted, refused, backs off
        assert first.state == PENDING
        # `order.submitted` is due and would be claimable on its own merits.
        assert dispatcher.claim() is None, "the next event overtook a retrying one"
        with engine.begin() as connection:
            connection.execute(webhook_delivery.update()
                               .values(next_attempt_at=utcnow()))
        second = dispatcher.claim()
    assert second.event_type == "order.accepted", "the retry lost its place"


def test_a_slow_consumer_does_not_stall_another_subscription(
        engine, custody_settings):
    """Real concurrency: two dispatch threads, one endpoint that takes its time."""
    slow = Consumer(delay=1.5)
    quick = Consumer()
    with serving(slow) as slow_url, serving(quick) as quick_url:
        subscriptions = WebhookSubscriptions(engine,
                                             custody_settings.custody_key())
        subscriptions.register(slow_url, ALL_TYPES)
        subscriptions.register(quick_url, ALL_TYPES)
        submit(engine)

        dispatchers = [
            WebhookDispatcher(engine, custody_settings.custody_key(),
                              worker_id=f"d{number}", timeout=10.0)
            for number in range(2)]
        stop = threading.Event()
        threads = [threading.Thread(target=d.run_forever,
                                    kwargs={"stop": stop, "poll_interval": 0.05},
                                    daemon=True) for d in dispatchers]
        started = time.monotonic()
        for thread in threads:
            thread.start()
        # The quick consumer must be answered while the slow one is still held.
        deadline = started + 1.0
        while not quick.received and time.monotonic() < deadline:
            time.sleep(0.02)
        quick_at = time.monotonic() - started
        stop.set()
        for thread in threads:
            thread.join(timeout=5)

    assert quick.received, "the quick consumer waited for the slow one"
    assert quick_at < 1.4, f"the quick delivery took {quick_at:.2f}s"
    assert len(slow.received) == 1


# --- the secret -------------------------------------------------------------

def test_the_signing_secret_never_reaches_the_log_stream(
        engine, custody_settings, capsys):
    """Everything the dispatcher emits, including the failure path's trace."""
    from painfree.logging import configure_logging

    consumer = Consumer(status=500)
    configure_logging("DEBUG")
    with serving(consumer) as url:
        subscriptions = WebhookSubscriptions(engine,
                                             custody_settings.custody_key())
        _, secret = subscriptions.register(url, ALL_TYPES)
        submit(engine)
        dispatcher = WebhookDispatcher(engine, custody_settings.custody_key(),
                                       worker_id="secret-test", timeout=5.0)
        dispatcher.run_once()
    stream = capsys.readouterr().out
    assert stream, "nothing was logged, so nothing was proved"
    assert secret not in stream
    assert custody_settings.key_encryption_secret.get_secret_value() not in stream


# --- delivery over the wire, without a database -----------------------------

def test_a_redirect_is_a_failure_rather_than_a_silent_get():
    """urllib turns a redirected POST into a GET; that must not read as success."""
    class Redirector(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Redirector)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/hooks"
        status, error = post(url, b"{}", {"Content-Type": "application/json"}, 5.0)
    finally:
        server.shutdown()
        server.server_close()
    assert status == 302 and error is not None


def test_an_endpoint_that_cannot_be_reached_has_no_status():
    status, error = post("http://127.0.0.1:1/hooks", b"{}", {}, 1.0)
    assert status is None and "could not be reached" in error


# --- the role boundary ------------------------------------------------------

def test_an_api_process_cannot_build_a_dispatcher(sqlite_url, engine):
    """Signing needs a sealed secret, so it needs the custody key."""
    settings = load_settings(database_url=sqlite_url, role="api")
    with pytest.raises(ValueError, match="custody key"):
        build_dispatcher(settings, engine)


# --- the same claim on PostgreSQL -------------------------------------------

@requires_postgres
def test_concurrent_dispatchers_never_deliver_one_event_twice():
    """Eight dispatchers, four subscriptions: each event goes out exactly once.

    The case a ``SELECT`` in front of an ``UPDATE`` fails. On PostgreSQL the
    candidate query carries ``FOR UPDATE SKIP LOCKED``, so the dispatchers take
    *different* rows instead of queueing behind one.
    """
    import concurrent.futures as futures

    from painfree.config import load_settings as load

    settings = load(database_url=POSTGRES_URL,
                    key_encryption_secret="test-only-custody-secret-"
                                          "Sk9pQ2x1-do-not-reuse")
    engine = db.build_engine(settings)
    consumers = [Consumer() for _ in range(4)]
    try:
        reset_database(engine)
        provision(engine)
        with contextlib.ExitStack() as stack:
            urls = [stack.enter_context(serving(consumer))
                    for consumer in consumers]
            subscriptions = WebhookSubscriptions(engine, settings.custody_key())
            for url in urls:
                subscriptions.register(url, ALL_TYPES)
            submit(engine)

            dispatchers = [
                WebhookDispatcher(engine, settings.custody_key(),
                                  worker_id=f"pg-{number}", timeout=10.0)
                for number in range(8)]
            with futures.ThreadPoolExecutor(max_workers=8) as pool:
                results = [future.result() for future in
                           [pool.submit(d.run_once) for d in dispatchers]]

        delivered = [result for result in results if result is not None]
        assert len(delivered) == 4, "an event was claimed twice or not at all"
        assert sorted(len(c.received) for c in consumers) == [1, 1, 1, 1]
        assert len({result.delivery_id for result in delivered}) == 4
    finally:
        reset_database(engine)
        engine.dispose()


@requires_postgres
def test_the_delivery_constraint_exists_on_postgres():
    """One event per subscription is a constraint, not a check two writers pass."""
    from sqlalchemy import inspect

    engine = create_engine(POSTGRES_URL, future=True)
    try:
        reset_database(engine)
        db.migrate(engine)
        constraints = inspect(engine).get_unique_constraints("webhook_delivery")
        match = [c for c in constraints
                 if c["name"] == "uq_webhook_delivery_subscription_id_event_id"]
        assert match, constraints
        assert match[0]["column_names"] == ["subscription_id", "event_id"]
    finally:
        reset_database(engine)
        engine.dispose()
