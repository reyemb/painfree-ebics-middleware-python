"""Claiming an order, and the retry policy around it.

The claim is the part of the worker that has to be right under concurrency, and
it is testable without a bank: no keys, no HTTP, just the table. So it is tested
here, the way it fails -- several workers claiming at the same instant against a
real database -- and the same tests run against PostgreSQL whenever a server is
reachable, because ``FOR UPDATE SKIP LOCKED`` and SQLite's single write lock are
two different mechanisms for one property and only one of them runs by default.

A run that does not happen **skips with a message saying so**. A skip is not a
pass.
"""

from __future__ import annotations

import concurrent.futures as futures
import datetime as _dt
import os
import threading

import pytest
from sqlalchemy import create_engine, select, update

from conftest import payment_body, reset_database
from painfree import db, ebics3, payments
from painfree.connections import ConnectionRegistry
from painfree.orders import OrderState, OrderStore
from painfree.queue import (BACKOFF, CLAIM_LEASE, MAX_ATTEMPTS, OrderQueue,
                            backoff, utcnow)
from painfree.schema import bank_connection, payment_order

CONNECTION = "queue-bank"

POSTGRES_URL = os.environ.get("POSTGRES_TEST_URL")
requires_postgres = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="POSTGRES_TEST_URL is not set: no PostgreSQL server was reached, so "
           "the PostgreSQL half of the concurrent-claim gate did not run",
)


def provision(engine) -> None:
    """A migrated database with one initialised connection. No keys needed."""
    db.migrate(engine)
    ConnectionRegistry(engine).register(
        CONNECTION, host_id="QHOST", partner_id="PARTNER1", user_id="USER1",
        host_url="https://ebics.example.test/")
    with engine.begin() as connection:
        connection.execute(
            update(bank_connection)
            .where(bank_connection.c.connection_id == CONNECTION)
            .values(key_state=ebics3.KeyState.READY.value,
                    ini_sent=True, hia_sent=True))


@pytest.fixture
def engine(settings):
    engine = db.build_engine(settings)
    provision(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def queue(engine):
    return OrderQueue(engine)


def enqueue(engine, key: str = "queue-idem-0001") -> str:
    instruction = payments.PaymentInstruction(**payment_body())
    return OrderStore(engine).submit(
        CONNECTION, idempotency_key=key, instruction=instruction).order.order_id


def state_of(engine, order_id: str) -> str:
    with engine.connect() as connection:
        return connection.execute(
            select(payment_order.c.state)
            .where(payment_order.c.order_id == order_id)).scalar_one()


# --- claiming --------------------------------------------------------------

def test_claiming_moves_the_order_to_submitting_and_records_the_worker(
        engine, queue):
    order_id = enqueue(engine)

    claimed = queue.claim(worker_id="w1")

    assert claimed is not None
    assert claimed.order_id == order_id
    assert claimed.attempts == 1
    assert claimed.reopens is False
    assert state_of(engine, order_id) == OrderState.SUBMITTING.value
    with engine.connect() as connection:
        row = connection.execute(select(payment_order)).mappings().one()
    assert row["worker_id"] == "w1"
    assert row["claimed_at"] is not None


def test_a_claimed_order_is_not_claimed_again(engine, queue):
    enqueue(engine)
    assert queue.claim(worker_id="w1") is not None
    assert queue.claim(worker_id="w2") is None


def test_orders_are_claimed_in_submission_order(engine, queue):
    first = enqueue(engine, "queue-idem-a")
    second = enqueue(engine, "queue-idem-b")

    assert queue.claim(worker_id="w1").order_id == first
    assert queue.claim(worker_id="w2").order_id == second


def test_an_order_waiting_out_its_backoff_is_not_claimed(engine, queue):
    order_id = enqueue(engine)
    claimed = queue.claim(worker_id="w1")
    queue.retry_later(order_id, attempts=claimed.attempts, reason="bank down")

    assert state_of(engine, order_id) == OrderState.ACCEPTED.value
    assert queue.claim(worker_id="w1") is None
    # The clock, not the state, is what is holding it back.
    assert queue.claim(worker_id="w1",
                       now=utcnow() + BACKOFF[0]) is not None


def test_an_expired_lease_is_reclaimed_by_another_worker(engine, queue):
    """A worker that died mid-upload must not strand the payment for ever."""
    order_id = enqueue(engine)
    assert queue.claim(worker_id="dead-worker") is not None

    assert queue.claim(worker_id="w2") is None
    later = utcnow() + CLAIM_LEASE + _dt.timedelta(seconds=1)
    reclaimed = queue.claim(worker_id="w2", now=later)

    assert reclaimed is not None
    assert reclaimed.order_id == order_id
    assert reclaimed.attempts == 2


def test_a_reclaimed_order_with_an_open_transaction_says_so(engine, queue):
    """The one case that can put the same payment on the wire twice."""
    order_id = enqueue(engine)
    claimed = queue.claim(worker_id="dead-worker")
    queue.opened(order_id, transaction_id="A1B2C3")

    later = utcnow() + CLAIM_LEASE + _dt.timedelta(seconds=1)
    reclaimed = queue.claim(worker_id="w2", now=later)

    assert reclaimed.reopens is True
    # And it is the same message: nothing regenerates a `MsgId`.
    assert reclaimed.order.msg_id == claimed.order.msg_id


def test_a_terminal_order_is_never_claimed(engine, queue):
    for settle, kwargs in (
        (OrderQueue.submitted, {"bank_order_id": "N01A", "return_code": "000000",
                                "report_text": None}),
        (OrderQueue.refused, {"return_code": "091112", "report_text": "no"}),
    ):
        order_id = enqueue(engine, f"idem-{settle.__name__}")
        queue.claim(worker_id="w1")
        settle(queue, order_id, **kwargs)
        assert queue.claim(worker_id="w1") is None


# --- outcomes --------------------------------------------------------------

def test_a_refusal_keeps_the_bank_s_return_code_and_report_text(engine, queue):
    order_id = enqueue(engine)
    queue.claim(worker_id="w1")

    queue.refused(order_id, return_code="091302",
                  report_text="[EBICS_ACCOUNT_AUTHORISATION_FAILED] not you",
                  name="EBICS_ACCOUNT_AUTHORISATION_FAILED")

    with engine.connect() as connection:
        row = connection.execute(select(payment_order)).mappings().one()
    assert row["state"] == OrderState.REJECTED.value
    assert row["return_code"] == "091302"
    assert row["report_text"].startswith("[EBICS_ACCOUNT_AUTHORISATION_FAILED]")
    assert row["worker_id"] is None


def test_retrying_gives_up_at_the_ceiling_and_calls_it_failed(engine, queue):
    """`rejected` is the bank saying no; `failed` is us stopping. Not the same."""
    order_id = enqueue(engine)
    states = []
    for _ in range(MAX_ATTEMPTS):
        # An hour ahead so each attempt is past the previous one's backoff.
        claimed = queue.claim(worker_id="w1",
                              now=utcnow() + _dt.timedelta(hours=1))
        states.append(queue.retry_later(order_id, attempts=claimed.attempts,
                                        reason="the bank did not answer"))

    assert states[:-1] == [OrderState.ACCEPTED] * (MAX_ATTEMPTS - 1)
    assert states[-1] is OrderState.FAILED
    assert state_of(engine, order_id) == OrderState.FAILED.value


def test_the_backoff_grows_and_then_stops_growing():
    assert backoff(1) == BACKOFF[0]
    assert backoff(len(BACKOFF)) == BACKOFF[-1]
    # Past the table, the last wait is reused rather than doubling for ever.
    assert backoff(len(BACKOFF) + 10) == BACKOFF[-1]


def test_a_long_failure_message_is_truncated_rather_than_dropped(engine, queue):
    order_id = enqueue(engine)
    claimed = queue.claim(worker_id="w1")

    queue.retry_later(order_id, attempts=claimed.attempts, reason="x" * 2000)

    with engine.connect() as connection:
        stored = connection.execute(
            select(payment_order.c.last_error)).scalar_one()
    assert len(stored) == 512 and stored.endswith("…")


# --- concurrency, which is the whole point ---------------------------------

def claim_concurrently(url: str, workers: int) -> list[str | None]:
    """Every worker claims at one instant; return what each one got."""
    engines = [create_engine(url, future=True) for _ in range(workers)]
    ready = threading.Barrier(workers)

    def claim(engine, index):
        ready.wait(timeout=20)
        claimed = OrderQueue(engine).claim(worker_id=f"racer-{index}")
        return claimed.order_id if claimed else None

    try:
        with futures.ThreadPoolExecutor(max_workers=workers) as pool:
            return [future.result(timeout=30) for future in
                    [pool.submit(claim, engine, i)
                     for i, engine in enumerate(engines)]]
    finally:
        for engine in engines:
            engine.dispose()


def test_eight_workers_claiming_one_order_produce_exactly_one_claim(
        engine, sqlite_url):
    order_id = enqueue(engine)

    claimed = claim_concurrently(sqlite_url, workers=8)

    assert claimed.count(order_id) == 1, claimed
    assert claimed.count(None) == 7
    assert state_of(engine, order_id) == OrderState.SUBMITTING.value


def test_workers_claiming_several_orders_each_get_a_different_one(
        engine, sqlite_url):
    ids = {enqueue(engine, f"queue-idem-{i}") for i in range(4)}

    claimed = claim_concurrently(sqlite_url, workers=4)

    assert None not in claimed
    assert set(claimed) == ids
    assert len(set(claimed)) == 4


@requires_postgres
def test_eight_workers_claiming_one_order_produce_exactly_one_claim_on_postgres():
    """The same property on the backend production runs on.

    SQLite serialises writers with one database-level lock; PostgreSQL does not,
    and the claim relies on ``FOR UPDATE SKIP LOCKED`` instead. Two mechanisms,
    one property, and the mechanism that runs in production is the one that is
    not exercised by default.
    """
    engine = create_engine(POSTGRES_URL, future=True)
    try:
        _reset(engine)
        provision(engine)
        order_id = enqueue(engine)

        claimed = claim_concurrently(POSTGRES_URL, workers=8)

        assert claimed.count(order_id) == 1, claimed
        assert claimed.count(None) == 7
        assert state_of(engine, order_id) == OrderState.SUBMITTING.value
    finally:
        engine.dispose()


@requires_postgres
def test_workers_claiming_several_orders_each_get_a_different_one_on_postgres():
    """``SKIP LOCKED`` is what keeps four workers from queueing behind one row."""
    engine = create_engine(POSTGRES_URL, future=True)
    try:
        _reset(engine)
        provision(engine)
        ids = {enqueue(engine, f"queue-idem-{i}") for i in range(4)}

        claimed = claim_concurrently(POSTGRES_URL, workers=4)

        assert None not in claimed, claimed
        assert set(claimed) == ids
    finally:
        engine.dispose()


def _reset(engine) -> None:
    reset_database(engine)
