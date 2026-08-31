"""Accepting a payment: validate, build, and land exactly one row per key.

The claim under test: a retried submission never produces a second payment. It
is tested the way it fails in production -- under actual concurrency, with
several threads submitting the same idempotency key at the same instant against
a real database -- because a read-then-write passes every sequential test ever
written and still double-pays.

The same test runs on PostgreSQL whenever a server is reachable. A run that
does not happen **skips with a message saying so**; a skip is not a pass.
"""

from __future__ import annotations

import concurrent.futures as futures
import os
import threading

import pytest
from sqlalchemy import create_engine, func, select, update

from conftest import (PLAIN_IBAN, payment_body, reset_database, scor_transfer,
                      transfer)
from painfree import db, ebics3, payments, sps
from painfree.audit import AuditLog
from painfree.config import load_settings
from painfree.connections import ConnectionRegistry
from painfree.errors import ConflictError, NotFoundError
from painfree.orders import OrderState, OrderStore, fingerprint
from painfree.schema import audit_log, bank_connection, payment_order

CONNECTION = "acme-ubs"
KEY = "caller-idem-0001"

POSTGRES_URL = os.environ.get("POSTGRES_TEST_URL")
requires_postgres = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="POSTGRES_TEST_URL is not set: no PostgreSQL server was reached, so "
           "the PostgreSQL half of the concurrent-idempotency gate did not run",
)


# --- a migrated database with one connection ready to submit ----------------

def provision(engine) -> str:
    """Register a connection and mark it initialised.

    The state is written directly rather than driven through the engine's
    `INI`/`HIA`/`HPB` machine: three RSA key generations per test would pay for
    a property this file is not testing.
    """
    db.migrate(engine)
    ConnectionRegistry(engine).register(
        CONNECTION, host_id="UBSHOST", partner_id="PARTNER1",
        user_id="USER1", host_url="https://ebics.example.test/")
    with engine.begin() as connection:
        connection.execute(
            update(bank_connection)
            .where(bank_connection.c.connection_id == CONNECTION)
            .values(key_state=ebics3.KeyState.READY.value,
                    ini_sent=True, hia_sent=True))
    return CONNECTION


@pytest.fixture
def engine(settings):
    engine = db.build_engine(settings)
    provision(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def store(engine):
    return OrderStore(engine)


def instruction(**overrides) -> payments.PaymentInstruction:
    return payments.PaymentInstruction(**payment_body(**overrides))


def count(engine) -> int:
    with engine.connect() as connection:
        return connection.execute(
            select(func.count()).select_from(payment_order)).scalar_one()


def actions(engine) -> list[str]:
    with engine.connect() as connection:
        return [row[0] for row in connection.execute(
            select(audit_log.c.action).order_by(audit_log.c.seq))]


# --- accepting --------------------------------------------------------------

def test_a_valid_payment_is_accepted_and_queued(store, engine):
    submission = store.submit(CONNECTION, idempotency_key=KEY,
                              instruction=instruction())
    order = submission.order
    assert submission.replayed is False
    assert order.state is OrderState.ACCEPTED
    assert order.transaction_count == 1
    assert order.control_sum == "3949.75"
    assert order.currency == "CHF"
    assert order.message_type == "pain.001.001.09"
    assert order.msg_id.startswith("PF")
    assert count(engine) == 1


def test_the_stored_document_is_the_validated_one(store):
    """Stored, not rebuilt later: a document rebuilt at signing time is not
    the document that was validated."""
    from painfree import pain001
    order = store.submit(CONNECTION, idempotency_key=KEY,
                         instruction=instruction()).order
    assert pain001.schema_failures(order.document) == []
    assert order.msg_id.encode() in order.document


def test_the_order_can_be_read_back_by_its_id(store):
    order = store.submit(CONNECTION, idempotency_key=KEY,
                         instruction=instruction()).order
    assert store.get(order.order_id).msg_id == order.msg_id


def test_an_unknown_order_is_a_not_found(store):
    with pytest.raises(NotFoundError):
        store.get("ord_nope")


def test_an_unknown_connection_is_a_not_found_before_anything_is_built(store, engine):
    with pytest.raises(NotFoundError):
        store.submit("nobody", idempotency_key=KEY, instruction=instruction())
    assert count(engine) == 0


def test_a_connection_that_cannot_submit_yet_is_a_conflict(engine):
    """An order no worker could ever deliver is refused now, not queued."""
    ConnectionRegistry(engine).register(
        "acme-cs", host_id="CSHOST", partner_id="P2", user_id="U2",
        host_url="https://cs.example.test/")
    with pytest.raises(ConflictError, match="not initialised"):
        OrderStore(engine).submit("acme-cs", idempotency_key=KEY,
                                  instruction=instruction())
    assert count(engine) == 0


# --- validation happens before persistence ----------------------------------

def test_a_broken_reference_is_refused_and_nothing_is_stored(store, engine):
    body = payment_body(transactions=[
        transfer(creditor_iban=PLAIN_IBAN,
                 reference={"type": "QRR",
                            "reference": "210000000003139471430009017"})])
    with pytest.raises(sps.ValidationFailed) as raised:
        store.submit(CONNECTION, idempotency_key=KEY,
                     instruction=payments.PaymentInstruction(**body))
    assert raised.value.status_code == 422
    assert raised.value.detail["failures"][0]["rule"] == "qrr.requires_qr_iban"
    assert count(engine) == 0


def test_a_rejection_is_audited_by_rule_and_never_by_value(store, engine):
    body = payment_body(transactions=[transfer(amount="1.005")])
    with pytest.raises(sps.ValidationFailed):
        store.submit(CONNECTION, idempotency_key=KEY,
                     instruction=payments.PaymentInstruction(**body))
    with engine.connect() as connection:
        row = connection.execute(
            select(audit_log).where(
                audit_log.c.action == "payment.validation_failed")
        ).mappings().one()
    assert row["outcome"] == "failure"
    assert row["idempotency_key"] == KEY
    assert row["detail"]["failures"] == [
        {"location": "transactions.0.amount", "rule": "amount.minor_units"}]


def test_an_idempotency_key_that_is_not_a_key_is_refused(store):
    with pytest.raises(sps.ValidationFailed) as raised:
        store.submit(CONNECTION, idempotency_key="short",
                     instruction=instruction())
    assert raised.value.detail["failures"][0]["rule"] == "idempotency_key.format"


# --- idempotency, sequentially ----------------------------------------------

def test_a_repeat_with_the_same_key_returns_the_original_order(store, engine):
    first = store.submit(CONNECTION, idempotency_key=KEY,
                         instruction=instruction())
    second = store.submit(CONNECTION, idempotency_key=KEY,
                          instruction=instruction())
    assert second.replayed is True
    assert second.order.order_id == first.order.order_id
    assert second.order.msg_id == first.order.msg_id
    assert count(engine) == 1


def test_a_repeat_with_the_same_key_and_a_changed_payload_is_a_conflict(store, engine):
    store.submit(CONNECTION, idempotency_key=KEY, instruction=instruction())
    changed = instruction(transactions=[transfer(amount="1.00")])
    with pytest.raises(ConflictError) as raised:
        store.submit(CONNECTION, idempotency_key=KEY, instruction=changed)
    assert raised.value.status_code == 409
    assert count(engine) == 1
    # Not `payment.rejected`: the bank has said nothing, and only the bank
    # rejects.
    assert "payment.conflict" in actions(engine)


def test_the_same_key_on_a_different_connection_is_a_different_payment(engine):
    """The key is unique *per connection*, not globally."""
    ConnectionRegistry(engine).register(
        "acme-cs", host_id="CSHOST", partner_id="P2", user_id="U2",
        host_url="https://cs.example.test/")
    with engine.begin() as connection:
        connection.execute(
            update(bank_connection)
            .where(bank_connection.c.connection_id == "acme-cs")
            .values(key_state=ebics3.KeyState.READY.value))
    store = OrderStore(engine)
    store.submit(CONNECTION, idempotency_key=KEY, instruction=instruction())
    store.submit("acme-cs", idempotency_key=KEY, instruction=instruction())
    assert count(engine) == 2


def test_two_genuinely_identical_payments_with_different_keys_both_land(store, engine):
    """Payload hashing cannot tell these apart from a retry. Keys can."""
    store.submit(CONNECTION, idempotency_key="caller-idem-0001",
                 instruction=instruction())
    store.submit(CONNECTION, idempotency_key="caller-idem-0002",
                 instruction=instruction())
    assert count(engine) == 2


def test_the_fingerprint_ignores_key_order_and_default_filled_fields():
    body = payment_body()
    reordered = {key: body[key] for key in reversed(list(body))}
    explicit = payment_body(batch_booking=True)
    parse = payments.PaymentInstruction
    assert (fingerprint(CONNECTION, parse(**body))
            == fingerprint(CONNECTION, parse(**reordered))
            == fingerprint(CONNECTION, parse(**explicit)))


def test_the_fingerprint_changes_with_the_amount():
    parse = payments.PaymentInstruction
    assert (fingerprint(CONNECTION, parse(**payment_body()))
            != fingerprint(CONNECTION, parse(
                **payment_body(transactions=[transfer(amount="1.00")]))))


def test_the_idempotency_uniqueness_is_a_database_constraint(store, engine):
    """Not a check in Python. The database refuses the second row itself.

    This is what makes the concurrent test below a guarantee rather than an
    observation about thread scheduling.
    """
    from sqlalchemy.exc import IntegrityError
    store.submit(CONNECTION, idempotency_key=KEY, instruction=instruction())
    with engine.connect() as connection:
        row = dict(connection.execute(select(payment_order)).mappings().one())
    row.pop("seq")
    row.update(order_id="ord_someone_else", msg_id="PFSOMEONEELSE")
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(payment_order.insert().values(**row))
    assert count(engine) == 1


# --- idempotency, concurrently ----------------------------------------------

def submit_concurrently(engine, workers: int = 8) -> list[object]:
    """`workers` threads submitting one key, released together."""
    barrier = threading.Barrier(workers)

    def attempt() -> object:
        store = OrderStore(engine)
        payload = instruction()
        barrier.wait()
        try:
            return store.submit(CONNECTION, idempotency_key=KEY,
                                instruction=payload)
        except Exception as exc:  # returned, so the assertion can name it
            return exc

    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        return [future.result()
                for future in [pool.submit(attempt) for _ in range(workers)]]


def assert_exactly_one_payment(engine, results: list[object]) -> None:
    failures = [result for result in results if isinstance(result, Exception)]
    assert not failures, f"a concurrent duplicate failed outright: {failures}"
    assert count(engine) == 1, "a duplicate submission created a second payment"

    created = [result for result in results if not result.replayed]
    assert len(created) == 1, f"{len(created)} submissions believed they created it"
    order_ids = {result.order.order_id for result in results}
    msg_ids = {result.order.msg_id for result in results}
    assert len(order_ids) == 1 and len(msg_ids) == 1
    assert actions(engine).count("payment.accepted") == 1


def test_concurrent_duplicate_submissions_create_exactly_one_payment(engine):
    """The one invariant worth failing a deploy over."""
    assert_exactly_one_payment(engine, submit_concurrently(engine))


def test_the_loser_of_the_race_returns_the_winners_order(store, engine, monkeypatch):
    """The branch the concurrent test relies on, exercised deterministically.

    Threads make that branch likely, not certain, so it is also driven here by
    blinding the fast-path read exactly once: the second submission then does
    what a genuine loser does -- inserts, is refused by the constraint, and
    reads back the row that won.
    """
    first = store.submit(CONNECTION, idempotency_key=KEY,
                         instruction=instruction())
    real_find = OrderStore._find
    blinded = {"done": False}

    def find_once_blind(self, connection_id, idempotency_key):
        if not blinded["done"]:
            blinded["done"] = True
            return None
        return real_find(self, connection_id, idempotency_key)

    monkeypatch.setattr(OrderStore, "_find", find_once_blind)
    second = store.submit(CONNECTION, idempotency_key=KEY,
                          instruction=instruction())
    assert blinded["done"]
    assert second.replayed is True
    assert second.order.order_id == first.order.order_id
    assert count(engine) == 1


@requires_postgres
def test_concurrent_duplicate_submissions_create_exactly_one_payment_on_postgres():
    settings = load_settings(database_url=POSTGRES_URL)
    engine = db.build_engine(settings)
    _drop_everything(engine)
    try:
        provision(engine)
        assert_exactly_one_payment(engine, submit_concurrently(engine))
    finally:
        _drop_everything(engine)
        engine.dispose()


@requires_postgres
def test_the_idempotency_constraint_exists_on_postgres():
    """It is the guarantee, so its absence must not be discoverable only by race."""
    from sqlalchemy import inspect, text
    engine = db.build_engine(load_settings(database_url=POSTGRES_URL))
    _drop_everything(engine)
    try:
        provision(engine)
        names = {constraint["name"] for constraint
                 in inspect(engine).get_unique_constraints("payment_order")}
        assert "uq_payment_order_connection_id_idempotency_key" in names
        assert "uq_payment_order_msg_id" in names
        with engine.begin() as connection:
            connection.execute(text("SELECT 1"))
    finally:
        _drop_everything(engine)
        engine.dispose()


def _drop_everything(engine) -> None:
    reset_database(engine)


# --- the custody boundary this path must not need ---------------------------

def test_submitting_needs_no_key_and_no_custody_secret(sqlite_url):
    """The request path builds and validates a payment with nothing to decrypt.

    `PAINFREE_KEY_ENCRYPTION_SECRET` is not configured at all here, so if any
    step of accepting a payment reached for a private key it would fail loudly
    rather than quietly widening the custody boundary.
    """
    settings = load_settings(database_url=sqlite_url)
    engine = db.build_engine(settings)
    try:
        provision(engine)
        order = OrderStore(engine, AuditLog(engine)).submit(
            CONNECTION, idempotency_key=KEY, instruction=instruction()).order
        assert order.state is OrderState.ACCEPTED
    finally:
        engine.dispose()


def test_the_order_store_does_not_import_the_keyring_or_the_custodian():
    """A structural check, so a later refactor cannot pull one in unremarked."""
    import painfree.orders as module
    source = open(module.__file__).read()
    assert "keyring" not in source.replace("`painfree.keyring`", "")
    assert "KeyCustodian" not in source
