"""Closing a payment: a `pain.002` matched back to the order it reports on.

The gap this file exists to prove closed is the last step of the lifecycle. A
status report arrives, names a `MsgId` this service generated, and the order it
answers reaches `acknowledged` or `rejected` with the bank's own words on it --
and every consumer subscribed to `order.acknowledged` is told.

Four things are asserted here that a happy-path test would miss, because each
of them is a way the join goes wrong rather than a way it goes right:

* a report for a `MsgId` this service never sent must be **kept**, not dropped
  and not fatal;
* a batch can be **partly** accepted, and calling that "rejected" would make it
  replayable, which would re-send the transactions the bank already took;
* a bank **re-sends**, and the second copy must move nothing and owe nothing;
* an order that is already terminal must not be resurrected by a later report.

**Every document here is built and then validated against the official
`pain.002.001.10` XSD before anything is asserted about it.** The reports have
to carry the `MsgId` this service generated at accept time, which a committed
fixture cannot know, so they are constructed -- and the pooled reference corpus
(`ebics-client-php`, `epics`) ships no `pain.002` document to use instead. The
schema is the independent oracle; the reconciliation rules have none, and are
tested against the mapping in :data:`painfree.reconcile.STATUS_CODES`.
"""

from __future__ import annotations

import logging
import os

import pytest
from sqlalchemy import select

from conftest import (BANK_CONNECTION_ID, CUSTODY_SECRET, payment_body,
                      payment_status, serving_bank, status_transaction,
                      upload_script, valid_payment_status)
from painfree import db, payments
from painfree.audit import AuditLog
from painfree.config import load_settings
from painfree.dispatcher import WebhookDispatcher
from painfree.orders import OrderState, OrderStore
from painfree.queue import OrderQueue
from painfree.reconcile import STATUS_CODES, StatusReconciler, resolve
from painfree.schema import audit_log, payment_order, statement, webhook_delivery
from painfree.statements import StatementStore
from painfree.worker import UploadWorker

POSTGRES_URL = os.environ.get("POSTGRES_TEST_URL")
needs_postgres = pytest.mark.skipif(
    POSTGRES_URL is None,
    reason="POSTGRES_TEST_URL is not set: no PostgreSQL server was reached, so "
           "the conditional state transition was not proved on the production "
           "backend")


# --- fixtures ---------------------------------------------------------------

@pytest.fixture
def bank(prepared_bank):
    """A prepared connection, a statement store, and one submitted order.

    The order is put in `submitted` the way the worker leaves it, because what
    is under test is what happens to it *afterwards*.
    """
    engine, _, bank_keys = prepared_bank
    store = StatementStore(engine)
    order = _submit(engine)
    OrderQueue(engine).submitted(order.order_id, bank_order_id="N01A",
                                 return_code="000000",
                                 report_text="[EBICS_OK] OK")
    return engine, store, OrderStore(engine).get(order.order_id)


def _submit(engine, *, idempotency_key: str = "reconcile-idem-0001"):
    instruction = payments.PaymentInstruction(**payment_body())
    return OrderStore(engine).submit(
        BANK_CONNECTION_ID, idempotency_key=idempotency_key,
        instruction=instruction).order


def ingest(store, document: bytes, *, run_id: str = "run-0001"):
    """Ingest one status report, XSD-checked first."""
    return store.ingest(BANK_CONNECTION_ID, [valid_payment_status(document)],
                        run_id=run_id)


def state_of(engine, order_id: str) -> str:
    return OrderStore(engine).get(order_id).state.value


def actions(engine, order_id: str | None = None) -> list[str]:
    query = select(audit_log.c.action).order_by(audit_log.c.seq)
    if order_id is not None:
        query = query.where(audit_log.c.order_id == order_id)
    with engine.connect() as connection:
        return [row[0] for row in connection.execute(query)]


# --- reading one report, with no database in the way ------------------------

def test_an_accepting_status_acknowledges_the_order():
    outcome = resolve(_payload(group_status="ACSP"))
    assert outcome.state is OrderState.ACKNOWLEDGED
    assert outcome.status == "ACSP"
    assert outcome.name == "AcceptedSettlementInProcess"


def test_a_rejection_carries_the_banks_own_code_and_text():
    outcome = resolve(_payload(group_status="RJCT", reason_code="AM05",
                               reason_text="Duplicate payment"))
    assert outcome.state is OrderState.REJECTED
    assert (outcome.reason_code, outcome.reason_text) == ("AM05",
                                                          "Duplicate payment")


def test_a_pending_report_decides_nothing():
    """`PDNG` is an interim answer. It is not a state and it moves nothing."""
    outcome = resolve(_payload(group_status="PDNG"))
    assert outcome.state is None
    assert not outcome.decides


def test_a_status_code_this_service_does_not_know_moves_nothing():
    """The ISO list grows. An unknown word is a reason to wait, not to guess."""
    outcome = resolve(_payload(group_status="ZZZZ"))
    assert outcome.state is None
    assert outcome.unknown == ("ZZZZ",)


def test_a_partly_accepted_batch_is_acknowledged_and_counted():
    """`PART` is not `rejected`, and the difference is a double payment.

    `rejected` is replayable, and replaying a batch the bank partly executed
    re-sends the transactions it already took. So the file is acknowledged and
    the refusal is recorded beside it rather than instead of it.
    """
    outcome = resolve(_partial_payload())
    assert outcome.state is OrderState.ACKNOWLEDGED
    assert (outcome.accepted, outcome.rejected) == (1, 1)
    assert outcome.reason_code == "AC01"
    assert outcome.reason_text == "Creditor account number invalid"


def test_only_the_refused_transaction_being_listed_is_not_a_refusal():
    """Banks list the failures and leave the successes out. Counting loses that.

    A report whose group says the file was accepted and whose only transaction
    entry is a rejection is a partial acceptance written the short way. Reading
    the transaction level as decisive would call the whole file refused.
    """
    payload = _payload(group_status="ACCP", payment_status="ACCP",
                       transactions=(
                           status_transaction("RJCT", reason_code="AC01",
                                              reason_text="bad account"),))
    assert resolve(payload).state is OrderState.ACKNOWLEDGED


def test_with_no_group_status_the_levels_below_decide_only_unanimously():
    everyone_agrees = _payload(group_status=None, payment_status="ACSC",
                               transactions=(status_transaction("ACSC"),))
    assert resolve(everyone_agrees).state is OrderState.ACKNOWLEDGED

    disagreeing = _payload(
        group_status=None, payment_status=None,
        transactions=(status_transaction("ACSC"),
                      status_transaction("RJCT", end_to_end="E2E-0002")))
    assert resolve(disagreeing).state is None


def test_every_status_code_maps_to_exactly_one_of_three_outcomes():
    """The table is the mapping, and nothing outside it decides anything."""
    assert {code.outcome for code in STATUS_CODES.values()} == {
        "acknowledged", "rejected", "no change"}
    assert STATUS_CODES["PART"].outcome == "acknowledged"
    assert STATUS_CODES["PDNG"].outcome == "no change"


def _payload(**kwargs) -> dict:
    from painfree.statements import normalise

    return normalise(valid_payment_status(
        payment_status("PF-UNUSED", **kwargs)))[0].payload


def _partial_payload(**kwargs) -> dict:
    return _payload(
        group_status="PART", payment_status="ACCP",
        number_of_transactions="2", control_sum="4199.75",
        transactions=(
            status_transaction("ACSP"),
            status_transaction("RJCT", end_to_end="E2E-0002",
                               instruction="INSTR-0002", amount="250.00",
                               reason_code="AC01",
                               reason_text="Creditor account number invalid")),
        **kwargs)


# --- the join, against the database -----------------------------------------

def test_a_status_report_moves_the_order_it_names_and_links_itself_to_it(bank):
    engine, store, order = bank
    result = ingest(store, payment_status(order.msg_id, group_status="ACSP"))

    assert result.stored == 1
    assert state_of(engine, order.order_id) == "acknowledged"
    with engine.connect() as connection:
        linked = connection.execute(
            select(statement.c.order_id)
            .where(statement.c.statement_id == result.statement_ids[0])
        ).scalar_one()
    assert linked == order.order_id, "the link is a column, not a JSON field"

    fresh = OrderStore(engine).get(order.order_id)
    assert fresh.bank_status == "ACSP"
    assert fresh.status_reported_at is not None
    assert "payment.acknowledged" in actions(engine, order.order_id)


def test_the_banks_refusal_keeps_its_reason_code_and_its_own_words(bank):
    engine, store, order = bank
    ingest(store, payment_status(
        order.msg_id, group_status="RJCT", reason_code="AC01",
        reason_text="Creditor account number invalid: IBAN check digit"))

    fresh = OrderStore(engine).get(order.order_id)
    assert fresh.state is OrderState.REJECTED
    assert fresh.bank_status == "RJCT"
    assert fresh.status_reason_code == "AC01"
    assert "IBAN check digit" in fresh.status_reason_text
    # The EBICS return code the *transfer* ended with is untouched: two
    # vocabularies, two columns.
    assert fresh.return_code == "000000"
    assert "payment.rejected" in actions(engine, order.order_id)


def test_a_report_for_an_unknown_msg_id_is_stored_and_said_aloud(bank, caplog):
    """Another system's order, or one predating this deployment. Not a crash.

    What it must not be is silence: the statement is kept with no order on it,
    the log line names the `MsgId` that matched nothing, and the audit trail
    has a row an operator can find.
    """
    engine, store, _ = bank
    with caplog.at_level(logging.WARNING):
        result = ingest(store, payment_status("PF-SOMEBODY-ELSES-MESSAGE"))

    assert result.stored == 1, "an unmatched report is still a statement"
    with engine.connect() as connection:
        row = connection.execute(
            select(statement.c.order_id, statement.c.identification)
            .where(statement.c.statement_id == result.statement_ids[0])
        ).one()
    assert row.order_id is None
    assert row.identification == "PF-SOMEBODY-ELSES-MESSAGE"
    assert "payment.status_unmatched" in actions(engine)
    assert any("status_unmatched" in record.getMessage()
               for record in caplog.records)


def test_a_re_sent_report_changes_nothing_and_owes_nothing(bank):
    """Banks re-serve. The same report twice is one row and one transition."""
    engine, store, order = bank
    document = payment_status(order.msg_id, group_status="ACSC")
    first = ingest(store, document)
    second = ingest(store, document)

    assert (first.stored, second.stored) == (1, 0)
    assert second.duplicates == 1
    assert actions(engine, order.order_id).count("payment.acknowledged") == 1


def test_a_later_report_about_a_terminal_order_neither_resurrects_nor_repeats(
        bank, caplog):
    """A second, genuinely different report. Recorded; the order does not move."""
    engine, store, order = bank
    ingest(store, payment_status(order.msg_id, report_id="STSRPT-0001",
                                 group_status="ACSC"))
    with caplog.at_level(logging.WARNING):
        second = ingest(store, payment_status(
            order.msg_id, report_id="STSRPT-0002", group_status="RJCT",
            reason_code="AM05", reason_text="Duplicate payment"))

    assert second.stored == 1, "a different report is a different document"
    assert state_of(engine, order.order_id) == "acknowledged"
    trail = actions(engine, order.order_id)
    assert trail.count("payment.acknowledged") == 1
    assert "payment.rejected" not in trail
    assert "payment.status_ignored" in trail
    assert any("status_ignored" in record.getMessage()
               for record in caplog.records)


def test_an_interim_report_leaves_the_order_and_a_later_one_decides_it(bank):
    """`PDNG` today, `ACSC` tomorrow. Two documents, one transition, in order."""
    engine, store, order = bank
    ingest(store, payment_status(order.msg_id, report_id="STSRPT-0001",
                                 group_status="PDNG"))
    assert state_of(engine, order.order_id) == "submitted"
    assert "payment.status_reported" in actions(engine, order.order_id)

    ingest(store, payment_status(order.msg_id, report_id="STSRPT-0002",
                                 group_status="ACSC"))
    assert state_of(engine, order.order_id) == "acknowledged"


def test_a_partly_accepted_batch_reaches_acknowledged_with_its_counts(bank):
    engine, store, order = bank
    ingest(store, payment_status(
        order.msg_id, group_status="PART", payment_status="ACCP",
        number_of_transactions="2", control_sum="4199.75",
        transactions=(
            status_transaction("ACSP"),
            status_transaction("RJCT", end_to_end="E2E-0002",
                               instruction="INSTR-0002", amount="250.00",
                               reason_code="AC01",
                               reason_text="Creditor account number invalid"))))

    fresh = OrderStore(engine).get(order.order_id)
    assert fresh.state is OrderState.ACKNOWLEDGED
    assert fresh.bank_status == "PART"
    assert fresh.status_reason_code == "AC01"
    detail = _detail(engine, order.order_id, "payment.acknowledged")
    assert detail["transactions_accepted"] == 1
    assert detail["transactions_rejected"] == 1


def test_an_order_a_worker_is_holding_is_not_moved_out_from_under_it(bank):
    """`submitting` means a worker owns the row and will settle it itself."""
    engine, store, order = bank
    with engine.begin() as connection:
        connection.execute(payment_order.update()
                           .where(payment_order.c.order_id == order.order_id)
                           .values(state=OrderState.SUBMITTING.value))
    ingest(store, payment_status(order.msg_id, group_status="ACSC"))

    assert state_of(engine, order.order_id) == "submitting"
    assert "payment.status_ignored" in actions(engine, order.order_id)


def test_a_report_never_closes_another_connections_order(prepared_bank):
    """The `MsgId` lookup is scoped to the connection it arrived on."""
    engine, _, _ = prepared_bank
    from painfree.connections import ConnectionRegistry

    ConnectionRegistry(engine, AuditLog(engine)).register(
        "other-bank", host_id="OTHER", partner_id="P", user_id="U",
        host_url="http://127.0.0.1:1/ebics")
    order = _submit(engine)
    store = StatementStore(engine)
    store.ingest("other-bank",
                 [valid_payment_status(payment_status(order.msg_id,
                                                      group_status="ACSC"))])

    assert state_of(engine, order.order_id) == "accepted"
    assert "payment.status_unmatched" in actions(engine)


def test_the_order_page_reads_its_reports_back_without_their_payloads(bank):
    engine, store, order = bank
    ingest(store, payment_status(order.msg_id, group_status="ACSP"))
    reports = store.reconciler.reports_for(order.order_id)

    assert len(reports) == 1
    assert reports[0]["outcome"].status == "ACSP"
    assert "payload" not in reports[0], (
        "a pain.002 quotes the payment it answers; the order page shows "
        "references")


def test_both_writers_of_an_order_event_name_the_state_readably(bank):
    """`order.*` events say which state the order reached, and say it in words.

    The key is `order_state` and not `state` because `state` is on the log
    stream's blocklist -- it is an OIDC login parameter -- so a detail written
    under that name reached the audit row, and the webhook, as `***`. The
    envelope has always promised the state; until this it shipped three
    asterisks. Both writers of a terminal transition are checked together,
    because the point is that the two agree.
    """
    engine, store, order = bank
    ingest(store, payment_status(order.msg_id, group_status="ACSC"))

    submitted = _detail(engine, order.order_id, "payment.submitted")
    acknowledged = _detail(engine, order.order_id, "payment.acknowledged")
    assert submitted["order_state"] == "submitted"
    assert acknowledged["order_state"] == "acknowledged"
    assert "***" not in (submitted | acknowledged).values()


def _detail(engine, order_id: str, action: str) -> dict:
    with engine.connect() as connection:
        return connection.execute(
            select(audit_log.c.detail)
            .where(audit_log.c.order_id == order_id,
                   audit_log.c.action == action)).scalar_one()


# --- the whole loop, over a socket ------------------------------------------

def test_a_payment_reaches_acknowledged_and_the_webhook_is_delivered(
        prepared_bank, custody_settings):
    """Submit, upload to a bank, ingest the bank's `pain.002`, deliver the event.

    Nothing is mocked: the upload runs against an HTTP stub bank, the status
    report is a schema-valid document naming the `MsgId` that upload actually
    put on the wire, and the webhook is POSTed to a real endpoint and verified
    by its signature. This is the lifecycle the contract promises, end to end.
    """
    engine, _, bank_keys = prepared_bank
    subscriptions = WebhookDispatcher(
        engine, custody_settings.custody_key(), timeout=5.0).subscriptions
    received: list[dict] = []

    order = _submit(engine)
    seen: list[bytes] = []
    with serving_bank(upload_script(bank_keys.authentication, seen)) as url:
        _point_at(engine, url)
        UploadWorker(engine, custody_settings.custody_key(),
                     timeout=5.0).run_once()
    assert state_of(engine, order.order_id) == "submitted"

    with _consumer(received) as endpoint:
        subscriptions.register(endpoint, ["order.acknowledged"])
        StatementStore(engine).ingest(
            BANK_CONNECTION_ID,
            [valid_payment_status(payment_status(order.msg_id,
                                                 group_status="ACSC"))],
            run_id="run-e2e")
        assert state_of(engine, order.order_id) == "acknowledged"
        dispatcher = WebhookDispatcher(engine, custody_settings.custody_key(),
                                       timeout=5.0)
        result = dispatcher.run_once()

    assert result is not None and result.ok
    assert len(received) == 1
    event = received[0]
    assert event["event_type"] == "order.acknowledged"
    assert event["order_id"] == order.order_id
    assert event["data"]["status"] == "ACSC"
    assert event["data"]["order_state"] == "acknowledged"
    assert event["data"]["source"] == "pain.002"
    with engine.connect() as connection:
        assert connection.execute(
            select(webhook_delivery.c.state)).scalar_one() == "delivered"


def _point_at(engine, url: str) -> None:
    from painfree.schema import bank_connection

    with engine.begin() as connection:
        connection.execute(
            bank_connection.update()
            .where(bank_connection.c.connection_id == BANK_CONNECTION_ID)
            .values(host_url=url))


def _consumer(received: list[dict]):
    """A webhook endpoint that records the bodies it is sent."""
    import contextlib
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            received.append(json.loads(body))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    @contextlib.contextmanager
    def serving():
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_address[1]}/hook"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    return serving()


# --- PostgreSQL -------------------------------------------------------------

@needs_postgres
def test_the_transition_is_one_conditional_update_on_postgres(custody_secret):
    """The guard against a second transition is a `WHERE`, not a read.

    Proved on the production backend, because it is the backend where two
    download workers really do ingest concurrently: the second `UPDATE` matches
    no row, so it writes no audit event and owes no webhook.
    """
    from conftest import reset_database
    from painfree.connections import ConnectionRegistry
    from painfree.keyring import KeyCustodian
    from painfree.schema import bank_connection
    from painfree import ebics3

    settings = load_settings(database_url=POSTGRES_URL,
                             key_encryption_secret=custody_secret)
    engine = db.build_engine(settings)
    reset_database(engine)
    db.migrate(engine)
    try:
        audit = AuditLog(engine)
        ConnectionRegistry(engine, audit).register(
            BANK_CONNECTION_ID, host_id="TESTHOST", partner_id="PARTNER1",
            user_id="USER1", host_url="http://127.0.0.1:1/ebics")
        with engine.begin() as connection:
            connection.execute(
                bank_connection.update()
                .where(bank_connection.c.connection_id == BANK_CONNECTION_ID)
                .values(key_state=ebics3.KeyState.READY.value,
                        ini_sent=True, hia_sent=True))
        order = _submit(engine)
        OrderQueue(engine).submitted(order.order_id, bank_order_id="N01A",
                                     return_code="000000", report_text="OK")

        reconciler = StatusReconciler(engine, audit)
        payload = _payload_for(order.msg_id)
        for _ in range(2):
            reconciler.reconcile(connection_id=BANK_CONNECTION_ID,
                                 statement_id="stm_test", order_id=order.order_id,
                                 payload=payload)

        assert state_of(engine, order.order_id) == "acknowledged"
        trail = actions(engine, order.order_id)
        assert trail.count("payment.acknowledged") == 1
        assert trail.count("payment.status_ignored") == 1
    finally:
        reset_database(engine)
        engine.dispose()


def _payload_for(msg_id: str) -> dict:
    from painfree.statements import normalise

    return normalise(valid_payment_status(
        payment_status(msg_id, group_status="ACSC")))[0].payload
