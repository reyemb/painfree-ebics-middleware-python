"""The console asks, the worker performs -- and nothing in between trusts a key.

Two properties are what these tests are for.

**A browser session cannot cause a decryption in the process that served it.**
Every key operation the console offers is a row; the request path that appends
it has no custody key and no method that would use one.

**A bank key is not trusted because it arrived.** `HPB` is unsigned. The whole
walk is driven against a stub bank here -- INI, HIA, HPB, the comparison -- and
the interesting cases are the two where the comparison does not succeed: a
wrong fingerprint, and an operator who declines. Both have to leave the
connection unable to move money.
"""

from __future__ import annotations

import threading

import pytest

from painfree import custody, db, ebics3
from painfree.audit import AuditLog
from painfree.connections import ConnectionRegistry
from painfree.errors import ConflictError, NotFoundError
from painfree.initialiser import KeyWorker
from painfree.keyjobs import JobState, KeyAction, KeyJobQueue, KeyJobStore
from painfree.keyring import ACTIVE, BANK, PENDING, SUBSCRIBER, Keyring
from painfree.orders import OrderStore
from painfree.logging import REDACTED
from painfree.schema import audit_log
from tests.conftest import (bank_subject, initialisation_script, payment_body,
                            serving_bank)

CONNECTION = "acme-ubs"
HOST_ID = "TESTHOST"


@pytest.fixture
def lifecycle(custody_settings):
    """A registered connection, a stub bank, and a worker pointed at it.

    Yields ``(engine, registry, store, worker, bank_keys, seen)``. The bank's
    keys are generated here, so every fingerprint these tests compare against is
    one the test computed itself.
    """
    engine = db.build_engine(custody_settings)
    db.migrate(engine)
    audit = AuditLog(engine)
    registry = ConnectionRegistry(engine, audit)
    keyring = Keyring(engine)
    store = KeyJobStore(engine, audit)

    bank = ebics3.BankKeys(
        authentication=ebics3.EbicsKey.generate(ebics3.KeyVersion.X002,
                                                subject=bank_subject("bank")),
        encryption=ebics3.EbicsKey.generate(ebics3.KeyVersion.E002,
                                            subject=bank_subject("bank")))
    seen: list[bytes] = []

    def subscriber_encryption():
        return keyring.public_key(CONNECTION, ebics3.KeyVersion.E002)

    script = initialisation_script(bank, subscriber_encryption, seen,
                                   host_id=HOST_ID)
    with serving_bank(script) as url:
        registry.register(CONNECTION, host_id=HOST_ID, partner_id="PARTNER1",
                          user_id="USER1", host_url=f"{url}/ebics")
        worker = KeyWorker(engine, custody_settings.custody_key(),
                           worker_id="test-keys", timeout=5.0)
        yield engine, registry, store, worker, bank, seen
    engine.dispose()


def _run(store, worker, connection_id, action, registry, **params):
    """Request one job the way the console does, then let the worker run it."""
    job = store.request(connection_id, action,
                        key_state=registry.get(connection_id).key_state,
                        params=params or None)
    performed = worker.run_once()
    assert performed is not None and performed.job_id == job.job_id
    return performed


def _walk_to_hpb(lifecycle):
    engine, registry, store, worker, bank, seen = lifecycle
    for action in (KeyAction.create_keys, KeyAction.send_ini,
                   KeyAction.send_hia, KeyAction.fetch_hpb):
        done = _run(store, worker, CONNECTION, action, registry)
        assert done.state is JobState.DONE, (action, done.last_error)
    return done


# --- the request path holds nothing ----------------------------------------

def test_the_console_only_appends_a_row_and_holds_no_key(lifecycle):
    """`KeyJobStore` is what a request handler gets. It has no custody surface."""
    _, registry, store, _, _, _ = lifecycle
    surface = {name for name in dir(KeyJobStore) if not name.startswith("_")}
    assert surface == {"get", "history", "outstanding", "request"}

    job = store.request(CONNECTION, KeyAction.create_keys,
                        key_state=registry.get(CONNECTION).key_state)
    assert job.state is JobState.QUEUED
    assert job.result is None
    # Nothing happened to the connection: asking is not doing.
    assert registry.get(CONNECTION).key_state is ebics3.KeyState.CREATED


def test_a_key_worker_cannot_be_built_on_a_request_path(custody_settings):
    """The custody boundary, from the side the console would come at it from."""
    engine = db.build_engine(custody_settings)
    db.migrate(engine)
    try:
        with custody.request_path():
            with pytest.raises(custody.CustodyViolation):
                KeyWorker(engine, custody_settings.custody_key())
    finally:
        engine.dispose()


# --- the preconditions ------------------------------------------------------

def test_an_operation_the_state_does_not_allow_is_refused_before_it_is_queued(
        lifecycle):
    _, registry, store, _, _, _ = lifecycle
    with pytest.raises(ConflictError) as refused:
        store.request(CONNECTION, KeyAction.send_hia,
                      key_state=registry.get(CONNECTION).key_state)
    assert "created" in str(refused.value)
    assert store.outstanding(CONNECTION) is None


def test_only_one_key_operation_is_in_flight_per_connection(lifecycle):
    """Two INIs for one subscriber is how a bank ends up refusing both."""
    _, registry, store, _, _, _ = lifecycle
    store.request(CONNECTION, KeyAction.create_keys,
                  key_state=registry.get(CONNECTION).key_state)
    with pytest.raises(ConflictError) as refused:
        store.request(CONNECTION, KeyAction.create_keys,
                      key_state=registry.get(CONNECTION).key_state)
    assert "in flight" in str(refused.value)


# --- the walk ---------------------------------------------------------------

def test_the_worker_walks_ini_hia_and_hpb_and_stages_what_it_got(lifecycle):
    engine, registry, store, worker, bank, seen = lifecycle
    _walk_to_hpb(lifecycle)

    connection = registry.get(CONNECTION)
    assert connection.ini_sent and connection.hia_sent
    assert connection.ini_order_id == "A001"
    assert connection.hia_order_id == "A002"
    # `bank_keys_received` is not `ready`. This is the whole point of the state.
    assert connection.key_state is ebics3.KeyState.BANK_KEYS_RECEIVED
    assert connection.initialised is False

    keyring = Keyring(engine)
    staged = keyring.staged_bank_keys(CONNECTION)
    assert {key.version for key in staged} == {ebics3.KeyVersion.X002,
                                               ebics3.KeyVersion.E002}
    assert all(key.status == PENDING for key in staged)
    # Nothing resolves them, so nothing can use them.
    assert keyring.entries(CONNECTION, holder=BANK, status=ACTIVE) == []
    with pytest.raises(NotFoundError):
        keyring.bank_keys(CONNECTION)

    received = keyring.staged_fingerprints(registry.get(CONNECTION))
    assert received == {"authentication": bank.authentication.fingerprint_hex,
                        "encryption": bank.encryption.fingerprint_hex}


def test_confirming_with_the_letters_values_makes_the_connection_usable(lifecycle):
    engine, registry, store, worker, bank, _ = lifecycle
    _walk_to_hpb(lifecycle)

    done = _run(store, worker, CONNECTION, KeyAction.confirm_bank_keys, registry,
                # As a human reads them off paper: spaces, and upper case.
                authentication=ebics3.format_fingerprint(
                    bank.authentication.fingerprint_hex).upper(),
                encryption=ebics3.format_fingerprint(
                    bank.encryption.fingerprint_hex))
    assert done.state is JobState.DONE

    connection = registry.get(CONNECTION)
    assert connection.key_state is ebics3.KeyState.READY
    assert connection.initialised is True
    assert connection.bank_fingerprints == {
        "authentication": bank.authentication.fingerprint_hex,
        "encryption": bank.encryption.fingerprint_hex}

    keyring = Keyring(engine)
    assert keyring.staged_bank_keys(CONNECTION) == []
    resolved = keyring.bank_keys(CONNECTION)
    assert resolved.encryption.fingerprint_hex == bank.encryption.fingerprint_hex


def test_a_substituted_key_is_refused_and_the_connection_stays_unusable(lifecycle):
    """The attack the comparison exists for: a different E002, same everything else."""
    engine, registry, store, worker, bank, _ = lifecycle
    _walk_to_hpb(lifecycle)

    done = _run(store, worker, CONNECTION, KeyAction.confirm_bank_keys, registry,
                authentication=bank.authentication.fingerprint_hex,
                encryption="00" * 32)
    assert done.state is JobState.FAILED
    assert "encryption" in (done.last_error or "")

    connection = registry.get(CONNECTION)
    assert connection.key_state is ebics3.KeyState.BANK_KEYS_RECEIVED
    assert connection.initialised is False
    # The evidence is kept: the keys that arrived are still there to look at.
    assert len(Keyring(engine).staged_bank_keys(CONNECTION)) == 2
    with pytest.raises(NotFoundError):
        Keyring(engine).bank_keys(CONNECTION)


def test_declining_leaves_the_connection_unable_to_submit_a_payment(lifecycle):
    """Declining is an outcome, and the outcome is that nothing works yet."""
    engine, registry, store, worker, bank, _ = lifecycle
    _walk_to_hpb(lifecycle)

    done = _run(store, worker, CONNECTION, KeyAction.decline_bank_keys, registry,
                reason="the E002 value on the letter does not match")
    assert done.state is JobState.DONE
    assert done.result["initialised"] is False

    keyring = Keyring(engine)
    assert keyring.staged_bank_keys(CONNECTION) == []
    with pytest.raises(NotFoundError):
        keyring.bank_keys(CONNECTION)

    connection = registry.get(CONNECTION)
    assert connection.key_state is ebics3.KeyState.BANK_KEYS_RECEIVED
    assert connection.initialised is False

    orders = OrderStore(engine)
    with pytest.raises(ConflictError) as refused:
        orders.submit(CONNECTION, idempotency_key="after-a-decline-0001",
                      instruction=_instruction())
    assert "not initialised" in str(refused.value)

    with engine.connect() as connection_:
        actions = [row[0] for row in connection_.execute(
            audit_log.select().with_only_columns(audit_log.c.action))]
    assert "key.bank_keys_declined" in actions
    assert "key.bank_keys_accepted" not in actions


def test_hpb_can_be_repeated_and_a_ready_connection_keeps_the_keys_it_trusts(
        lifecycle):
    """A key roll must not take a working connection down between two clicks."""
    engine, registry, store, worker, bank, _ = lifecycle
    _walk_to_hpb(lifecycle)
    _run(store, worker, CONNECTION, KeyAction.confirm_bank_keys, registry,
         authentication=bank.authentication.fingerprint_hex,
         encryption=bank.encryption.fingerprint_hex)
    assert registry.get(CONNECTION).initialised is True

    _run(store, worker, CONNECTION, KeyAction.fetch_hpb, registry)
    connection = registry.get(CONNECTION)
    assert connection.key_state is ebics3.KeyState.READY
    assert connection.initialised is True
    assert len(Keyring(engine).staged_bank_keys(CONNECTION)) == 2


def test_a_bank_that_refuses_a_registration_leaves_a_readable_outcome(
        custody_settings):
    """The return code and the report text are what a support call is answered with."""
    engine = db.build_engine(custody_settings)
    db.migrate(engine)
    registry = ConnectionRegistry(engine)
    store = KeyJobStore(engine)
    keyring = Keyring(engine)
    bank = ebics3.BankKeys(
        authentication=ebics3.EbicsKey.generate(ebics3.KeyVersion.X002,
                                                subject=bank_subject("bank")),
        encryption=ebics3.EbicsKey.generate(ebics3.KeyVersion.E002,
                                            subject=bank_subject("bank")))
    script = initialisation_script(
        bank, lambda: keyring.public_key(CONNECTION, ebics3.KeyVersion.E002),
        [], host_id=HOST_ID, return_code="091002")
    try:
        with serving_bank(script) as url:
            registry.register(CONNECTION, host_id=HOST_ID, partner_id="PARTNER1",
                              user_id="USER1", host_url=f"{url}/ebics")
            worker = KeyWorker(engine, custody_settings.custody_key(),
                               timeout=5.0)
            _run(store, worker, CONNECTION, KeyAction.create_keys, registry)
            refused = _run(store, worker, CONNECTION, KeyAction.send_ini, registry)
        assert refused.state is JobState.FAILED
        assert refused.return_code == "091002"
        assert "EBICS_INVALID_USER_STATE" in (refused.report_text or "")
        assert registry.get(CONNECTION).ini_sent is False
    finally:
        engine.dispose()


def test_a_finished_job_records_its_outcome_and_not_three_asterisks(lifecycle):
    """`state` is on the log stream's redaction blocklist -- it is an OIDC login
    parameter -- so `key.job_finished` wrote `"state": "***"` and every
    key-lifecycle row in the audit trail hid the one field it was written for.
    The field is `job_state`; the blocklist is a security control and did not
    move. `tests/test_service_audit_actions.py` is what stops the next one.
    """
    engine, registry, store, worker, _bank, _seen = lifecycle
    _run(store, worker, CONNECTION, KeyAction.create_keys, registry)
    with engine.connect() as connection:
        row = connection.execute(
            audit_log.select().where(audit_log.c.action == "key.job_finished")
        ).mappings().one()
    assert row["detail"]["job_state"] == "done"
    assert REDACTED not in row["detail"].values()
    assert "state" not in row["detail"]


# --- renewal and suspension -------------------------------------------------

def test_renewal_mints_a_generation_and_does_not_tell_the_bank(lifecycle):
    engine, registry, store, worker, bank, _ = lifecycle
    _walk_to_hpb(lifecycle)
    _run(store, worker, CONNECTION, KeyAction.confirm_bank_keys, registry,
         authentication=bank.authentication.fingerprint_hex,
         encryption=bank.encryption.fingerprint_hex)

    before = Keyring(engine).entry(CONNECTION, ebics3.KeyVersion.X002)
    done = _run(store, worker, CONNECTION, KeyAction.renew_key, registry,
                version="X002")
    assert done.state is JobState.DONE
    assert done.result["registered_with_bank"] is False

    after = Keyring(engine).entry(CONNECTION, ebics3.KeyVersion.X002)
    assert after.generation == before.generation + 1
    assert after.fingerprint != before.fingerprint
    # The superseded key is kept: the bank still has it on file.
    stored = Keyring(engine).entries(CONNECTION, status=None)
    assert before.fingerprint in {key.fingerprint for key in stored}


def test_suspension_marks_every_key_and_keeps_them(lifecycle):
    engine, registry, store, worker, bank, _ = lifecycle
    _walk_to_hpb(lifecycle)
    done = _run(store, worker, CONNECTION, KeyAction.suspend_keys, registry,
                reason="the export was lost")
    assert done.state is JobState.DONE
    assert len(done.result["suspended"]) == 3
    # The subscriber's keys, and only those: suspending is about what this
    # service signs with, not about what the bank sent.
    assert Keyring(engine).entries(CONNECTION, holder=SUBSCRIBER) == []
    assert len(Keyring(engine).entries(CONNECTION, holder=SUBSCRIBER,
                                       status=None)) == 3


# --- the claim --------------------------------------------------------------

def test_one_job_is_claimed_by_exactly_one_worker(lifecycle):
    engine, registry, store, _, _, _ = lifecycle
    store.request(CONNECTION, KeyAction.create_keys,
                  key_state=registry.get(CONNECTION).key_state)
    queue = KeyJobQueue(engine)
    claimed: list[object] = []
    barrier = threading.Barrier(4)

    def claim(number: int) -> None:
        barrier.wait()
        with custody.worker_context():
            taken = queue.claim(worker_id=f"worker-{number}")
        if taken is not None:
            claimed.append(taken)

    threads = [threading.Thread(target=claim, args=(number,))
               for number in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(claimed) == 1


def _instruction():
    from painfree import payments

    return payments.PaymentInstruction.model_validate(payment_body())
