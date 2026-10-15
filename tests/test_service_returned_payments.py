"""Issue #1: a payment the bank took and then did not deliver.

The order stayed `acknowledged` and nobody downstream heard otherwise. This file
holds what closes that, one rule per section:

* a stored document is read again under the rules in force now, because a rule
  that changes after a document arrived would otherwise never reach it;
* an event a consumer missed can be sent again, under its own id.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from conftest import (BANK_CONNECTION_ID, dev_credentials, grant, payment_body,
                      payment_status, valid_payment_status)
from painfree import reconcile
from painfree.app import create_app
from painfree.orders import OrderState, OrderStore
from painfree.queue import OrderQueue
from painfree.schema import audit_log
from painfree.statements import StatementStore

BROWSER = {"accept": "text/html,application/xhtml+xml"}


@pytest.fixture
def bank(prepared_bank):
    """A statement store and one order the bank has taken (`submitted`)."""
    engine, _, _ = prepared_bank
    order = _order(engine)
    return engine, StatementStore(engine), order


def _order(engine, key: str = "returns-0001"):
    from painfree import payments

    order = OrderStore(engine).submit(
        BANK_CONNECTION_ID, idempotency_key=key,
        instruction=payments.PaymentInstruction(**payment_body())).order
    OrderQueue(engine).submitted(order.order_id, bank_order_id="N01A",
                                 return_code="000000", report_text="OK")
    return OrderStore(engine).get(order.order_id)


def ingest(store, document: bytes):
    return store.ingest(BANK_CONNECTION_ID, [valid_payment_status(document)])


def actions(engine, order_id: str | None = None) -> list[str]:
    query = select(audit_log.c.action).order_by(audit_log.c.seq)
    if order_id is not None:
        query = query.where(audit_log.c.order_id == order_id)
    with engine.connect() as connection:
        return [row[0] for row in connection.execute(query)]


def detail(engine, order_id: str, action: str) -> dict:
    with engine.connect() as connection:
        return connection.execute(
            select(audit_log.c.detail)
            .where(audit_log.c.order_id == order_id,
                   audit_log.c.action == action)
            .order_by(audit_log.c.seq.desc())).scalars().first()


def _late_refusal_under_the_old_rule(store, order, monkeypatch):
    """`ACCP`, then a later `RJCT` ingested while no acknowledgement was revocable.

    Which is what a deployment that took both reports before a later refusal
    could overturn an acknowledgement holds: the refusal stored, ignored, and
    the order still acknowledged.
    """
    ingest(store, payment_status(order.msg_id, report_id="STSRPT-0001",
                                 group_status="ACCP"))
    with monkeypatch.context() as patch:
        patch.setattr(reconcile, "REVOCABLE", frozenset())
        ingest(store, payment_status(
            order.msg_id, report_id="STSRPT-0002", group_status="RJCT",
            reason_code="AC01", reason_text="Creditor account number invalid",
            created_at="2026-08-30T08:00:00Z"))


# --- stored documents, read again -------------------------------------------

def test_re_reading_applies_a_rule_that_arrived_after_the_report(
        bank, monkeypatch):
    engine, store, order = bank
    _late_refusal_under_the_old_rule(store, order, monkeypatch)
    assert OrderStore(engine).get(order.order_id).state is OrderState.ACKNOWLEDGED

    result = store.reconcile_stored(connection_id=BANK_CONNECTION_ID)

    assert result.examined == 2
    assert result.moved == (order.order_id,)
    assert OrderStore(engine).get(order.order_id).state is OrderState.REJECTED
    late = detail(engine, order.order_id, "payment.rejected")
    assert late["rereconciled"] is True
    assert late["revokes_status"] == "ACCP"
    assert late["reason_code"] == "AC01"
    summary = _summary(engine)
    assert (summary["examined"], summary["moved"]) == (2, 1)


def _summary(engine) -> dict:
    with engine.connect() as connection:
        return connection.execute(
            select(audit_log.c.detail)
            .where(audit_log.c.action == "statement.reconciled_again")
            .order_by(audit_log.c.seq.desc())).scalars().first()


def test_re_reading_twice_moves_nothing_and_writes_no_noise(bank, monkeypatch):
    """Only a move writes. Every report re-read does not become an audit row."""
    engine, store, order = bank
    _late_refusal_under_the_old_rule(store, order, monkeypatch)
    store.reconcile_stored(connection_id=BANK_CONNECTION_ID)
    before = actions(engine, order.order_id)

    again = store.reconcile_stored(connection_id=BANK_CONNECTION_ID)

    assert again.moved == ()
    assert actions(engine, order.order_id) == before


def test_re_reading_follows_the_banks_dates_not_the_arrival_order(bank):
    """A newer `ACCP` that arrived first, an older `RJCT` that arrived later.

    Read in arrival order, the refusal would overturn the acknowledgement.
    """
    engine, store, order = bank
    ingest(store, payment_status(order.msg_id, report_id="STSRPT-0002",
                                 group_status="ACCP",
                                 created_at="2026-08-30T08:00:00Z"))
    ingest(store, payment_status(order.msg_id, report_id="STSRPT-0001",
                                 group_status="RJCT",
                                 created_at="2026-08-29T08:00:00Z"))

    assert store.reconcile_stored().moved == ()
    assert OrderStore(engine).get(order.order_id).state is OrderState.ACKNOWLEDGED


def test_since_leaves_older_reports_alone(bank, monkeypatch):
    import datetime as dt

    engine, store, order = bank
    _late_refusal_under_the_old_rule(store, order, monkeypatch)

    result = store.reconcile_stored(since=dt.date(2026, 8, 31))

    assert result.examined == 0
    assert OrderStore(engine).get(order.order_id).state is OrderState.ACKNOWLEDGED


def test_the_command_line_re_reads_and_says_who_asked(
        bank, monkeypatch, sqlite_url):
    from painfree.__main__ import main

    engine, store, order = bank
    _late_refusal_under_the_old_rule(store, order, monkeypatch)
    monkeypatch.setenv("PAINFREE_DATABASE_URL", sqlite_url)

    assert main(["reconcile", BANK_CONNECTION_ID, "--since", "nonsense"]) == 2
    assert main(["reconcile", BANK_CONNECTION_ID]) == 0

    assert OrderStore(engine).get(order.order_id).state is OrderState.REJECTED
    with engine.connect() as connection:
        actor = connection.execute(
            select(audit_log.c.actor_type)
            .where(audit_log.c.action == "statement.reconciled_again")
        ).scalar_one()
    assert actor == "cli"


@pytest.fixture
def console(prepared_bank, custody_settings):
    engine, _, _ = prepared_bank
    app = create_app(custody_settings)
    with TestClient(app) as client:
        grant(app, "olive", BANK_CONNECTION_ID, "operator")
        grant(app, "reader", BANK_CONNECTION_ID, "viewer")
        yield client, engine


def test_an_operator_re_reads_from_the_responses_tab(console, monkeypatch):
    client, engine = console
    order = _order(engine, "returns-console")
    _late_refusal_under_the_old_rule(StatementStore(engine), order, monkeypatch)
    operator = {**dev_credentials("olive", "member"), **BROWSER}

    page = client.get("/ui/statements?family=response", headers=operator)
    assert 'action="/ui/statements/reconcile"' in page.text

    done = client.post("/ui/statements/reconcile",
                       data={"connection_id": BANK_CONNECTION_ID},
                       headers=operator, follow_redirects=True)
    assert done.status_code == 200
    assert "2 stored reports re-read; 1 orders moved." in done.text
    assert OrderStore(engine).get(order.order_id).state is OrderState.REJECTED


def test_a_viewer_is_neither_offered_nor_allowed_the_re_read(console):
    client, _ = console
    viewer = {**dev_credentials("reader", "member"), **BROWSER}

    page = client.get("/ui/statements?family=response", headers=viewer)
    assert 'action="/ui/statements/reconcile"' not in page.text
    refused = client.post("/ui/statements/reconcile",
                          data={"connection_id": BANK_CONNECTION_ID},
                          headers=viewer)
    assert refused.status_code == 403


# --- an event sent again ----------------------------------------------------

ORDER_EVENTS = ["order.accepted", "order.submitted", "order.rejected",
                "order.acknowledged", "order.failed"]


def _subscribe(engine, custody_settings, url="https://consumer.example.test/a"):
    from painfree.webhooks import WebhookSubscriptions

    subscriptions = WebhookSubscriptions(engine, custody_settings.custody_key())
    subscription, _ = subscriptions.register(url, ORDER_EVENTS,
                                             connection_id=BANK_CONNECTION_ID)
    return subscriptions, subscription


def _deliveries(engine, subscription_id: str) -> list[dict]:
    from painfree.schema import webhook_delivery

    with engine.connect() as connection:
        return [dict(row) for row in connection.execute(
            select(webhook_delivery)
            .where(webhook_delivery.c.subscription_id == subscription_id)
            .order_by(webhook_delivery.c.seq)).mappings()]


def _settle_all(engine, state: str = "delivered") -> None:
    from painfree.schema import webhook_delivery

    with engine.begin() as connection:
        connection.execute(webhook_delivery.update().values(state=state,
                                                            attempts=4))


def test_a_delivered_event_goes_back_in_the_queue_under_its_own_id(
        prepared_bank, custody_settings):
    from painfree.redelivery import Redelivery

    engine, _, _ = prepared_bank
    subscriptions, subscription = _subscribe(engine, custody_settings)
    _order(engine)
    _settle_all(engine)
    first = _deliveries(engine, subscription.subscription_id)[0]

    again = Redelivery(engine, subscriptions).redeliver(
        subscription.subscription_id, first["delivery_id"])

    assert (again.state, again.attempts) == ("pending", 0)
    assert again.event_id == first["event_id"]
    assert len(_deliveries(engine, subscription.subscription_id)) == 2, \
        "no new row: the same delivery, queued again"


def test_a_delivery_still_queued_is_not_queued_twice(prepared_bank,
                                                     custody_settings):
    from painfree.errors import ConflictError
    from painfree.redelivery import Redelivery

    engine, _, _ = prepared_bank
    subscriptions, subscription = _subscribe(engine, custody_settings)
    _order(engine)
    pending = _deliveries(engine, subscription.subscription_id)[0]

    with pytest.raises(ConflictError):
        Redelivery(engine, subscriptions).redeliver(
            subscription.subscription_id, pending["delivery_id"])


def test_another_endpoints_delivery_cannot_be_named(prepared_bank,
                                                    custody_settings):
    from painfree.errors import NotFoundError
    from painfree.redelivery import Redelivery

    engine, _, _ = prepared_bank
    subscriptions, one = _subscribe(engine, custody_settings)
    _, other = _subscribe(engine, custody_settings,
                          "https://consumer.example.test/b")
    _order(engine)
    _settle_all(engine)
    theirs = _deliveries(engine, other.subscription_id)[0]

    with pytest.raises(NotFoundError):
        Redelivery(engine, subscriptions).redeliver(one.subscription_id,
                                                    theirs["delivery_id"])


def test_an_order_is_resent_as_its_current_state_to_old_and_new_endpoints(
        prepared_bank, custody_settings):
    """The endpoint that had it gets it again; one registered since gets it once."""
    from painfree.redelivery import Redelivery

    engine, _, _ = prepared_bank
    subscriptions, early = _subscribe(engine, custody_settings)
    order = _order(engine)
    _settle_all(engine)
    _, late = _subscribe(engine, custody_settings,
                         "https://consumer.example.test/late")

    event_type, queued = Redelivery(engine, subscriptions).resend_order(
        order.order_id)

    assert (event_type, queued) == ("order.submitted", 2)
    early_rows = _deliveries(engine, early.subscription_id)
    assert [row["state"] for row in early_rows] == ["delivered", "pending"]
    late_rows = _deliveries(engine, late.subscription_id)
    assert [(row["event_type"], row["state"]) for row in late_rows] == [
        ("order.submitted", "pending")], "the current state, not the history"
    assert late_rows[0]["event_id"] == early_rows[1]["event_id"]
    assert late_rows[0]["payload"]["order_id"] == order.order_id


def test_resending_to_a_paused_endpoint_is_refused(prepared_bank,
                                                   custody_settings):
    from painfree.errors import ConflictError
    from painfree.redelivery import Redelivery

    engine, _, _ = prepared_bank
    subscriptions, subscription = _subscribe(engine, custody_settings)
    _order(engine)
    _settle_all(engine)
    subscriptions.set_enabled(subscription.subscription_id, False)
    first = _deliveries(engine, subscription.subscription_id)[0]

    with pytest.raises(ConflictError):
        Redelivery(engine, subscriptions).redeliver(
            subscription.subscription_id, first["delivery_id"])


def test_the_console_offers_both_and_audits_who_asked(console,
                                                      custody_settings):
    client, engine = console
    admin = {**dev_credentials("alice", "admin"), **BROWSER}
    _, subscription = _subscribe(engine, custody_settings)
    order = _order(engine, "returns-resend")
    _settle_all(engine)

    page = client.get(f"/ui/orders/{order.order_id}", headers=admin)
    assert f'action="/ui/orders/{order.order_id}/resend-events"' in page.text
    client.post(f"/ui/orders/{order.order_id}/resend-events", headers=admin)
    assert "webhook.order_resent" in actions(engine, order.order_id)

    _settle_all(engine)
    endpoint = client.get(f"/ui/webhooks/{subscription.subscription_id}",
                          headers=admin)
    delivery = _deliveries(engine, subscription.subscription_id)[0]
    target = (f"/ui/webhooks/{subscription.subscription_id}/deliveries/"
              f"{delivery['delivery_id']}/redeliver")
    assert f'action="{target}"' in endpoint.text
    assert client.post(target, headers=admin).status_code in (200, 303)
    assert "webhook.redelivery_requested" in actions(engine)


def test_a_viewer_cannot_resend(console):
    client, engine = console
    order = _order(engine, "returns-viewer")
    viewer = {**dev_credentials("reader", "member"), **BROWSER}

    page = client.get(f"/ui/orders/{order.order_id}", headers=viewer)
    assert "resend-events" not in page.text
    assert client.post(f"/ui/orders/{order.order_id}/resend-events",
                       headers=viewer).status_code == 403


# --- the returned state -----------------------------------------------------

def test_a_returned_order_is_terminal_and_not_replayable():
    from painfree.orders import REPLAYABLE

    assert OrderState.RETURNED.value == "returned"
    assert OrderState.RETURNED not in REPLAYABLE, \
        "a replay would send the same wrong creditor again"


def test_a_returned_order_says_which_booking_returned_it(bank):
    """By reference: the statement, the entry, the reason. Never a counterparty."""
    import datetime as dt

    from painfree.schema import payment_order

    engine, _, order = bank
    with engine.begin() as connection:
        connection.execute(
            payment_order.update()
            .where(payment_order.c.order_id == order.order_id)
            .values(state="returned",
                    returned_at=dt.datetime(2026, 10, 14, tzinfo=dt.timezone.utc),
                    return_statement_id="stm_x", return_entry_ref="REF-1",
                    return_reason_code="AC01", return_reason_text="unknown",
                    return_matched_by="rtrinf"))

    body = OrderStore(engine).get(order.order_id).as_response()

    assert body["state"] == "returned"
    assert body["return"] == {
        "returned_at": "2026-10-14T00:00:00+00:00", "reason_code": "AC01",
        "reason_text": "unknown", "statement_id": "stm_x",
        "entry_ref": "REF-1", "matched_by": "rtrinf"}


# --- a returning booking ----------------------------------------------------
#
# Statements are built here, because they have to name the `MsgId` and the
# `PmtInfId` this service generated at accept time, and every one of them is
# held to the official `camt.053.001.08` XSD before anything is asserted.

CAMT053 = "urn:iso:std:iso:20022:tech:xsd:camt.053.001.08"
DEBTOR_ACCOUNT = "CH5604835012345678009"


def credit(*, amount: str = "3949.75", msg_id: str | None = None,
           pmtinf_id: str | None = None, end_to_end: str | None = None,
           return_reason: str | None = None, return_text: str = "",
           reversal: bool = False, sub_family: str = "DMCT",
           family: str = "RCDT", reference: str = "ACSR-RTN-0001",
           counterparty_iban: str | None = None,
           entry_text: str | None = None, status: str = "BOOK",
           booked: str = "2026-10-14") -> str:
    """One booked credit entry, optionally carrying the marks of a return."""
    refs = "".join(f"<{tag}>{value}</{tag}>" for tag, value in (
        ("MsgId", msg_id), ("AcctSvcrRef", reference),
        ("PmtInfId", pmtinf_id), ("EndToEndId", end_to_end)) if value)
    parties = (f"<RltdPties><Dbtr><Pty><Nm>Somebody</Nm></Pty></Dbtr>"
               f"<DbtrAcct><Id><IBAN>{counterparty_iban}</IBAN></Id></DbtrAcct>"
               f"</RltdPties>" if counterparty_iban else "")
    rtrinf = ""
    if return_reason or return_text:
        rtrinf = ("<RtrInf>"
                  + (f"<Rsn><Cd>{return_reason}</Cd></Rsn>" if return_reason else "")
                  + (f"<AddtlInf>{return_text}</AddtlInf>" if return_text else "")
                  + "</RtrInf>")
    return f"""
      <Ntry>
        <NtryRef>{reference}</NtryRef>
        <Amt Ccy="CHF">{amount}</Amt>
        <CdtDbtInd>CRDT</CdtDbtInd>
        {'<RvslInd>true</RvslInd>' if reversal else ''}
        <Sts><Cd>{status}</Cd></Sts>
        <BookgDt><Dt>{booked}</Dt></BookgDt>
        <ValDt><Dt>{booked}</Dt></ValDt>
        <AcctSvcrRef>{reference}</AcctSvcrRef>
        <BkTxCd><Domn><Cd>PMNT</Cd><Fmly><Cd>{family}</Cd>
          <SubFmlyCd>{sub_family}</SubFmlyCd></Fmly></Domn></BkTxCd>
        <NtryDtls><TxDtls>
          {f'<Refs>{refs}</Refs>' if refs else ''}
          <Amt Ccy="CHF">{amount}</Amt>
          <CdtDbtInd>CRDT</CdtDbtInd>
          {parties}
          {rtrinf}
        </TxDtls></NtryDtls>
        {f'<AddtlNtryInf>{entry_text}</AddtlNtryInf>' if entry_text else ''}
      </Ntry>"""


def statement(*entries: str, identification: str = "STMT-RTN-0001",
              created_at: str = "2026-10-15T02:00:00+02:00",
              message: str = "camt.053.001.08",
              account: str = DEBTOR_ACCOUNT) -> bytes:
    from conftest import schema_for

    namespace = CAMT053 if message == "camt.053.001.08" else \
        "urn:iso:std:iso:20022:tech:xsd:camt.052.001.08"
    container, record = (("BkToCstmrStmt", "Stmt")
                         if message == "camt.053.001.08"
                         else ("BkToCstmrAcctRpt", "Rpt"))
    balances = "".join(f"""
      <Bal><Tp><CdOrPrtry><Cd>{code}</Cd></CdOrPrtry></Tp>
        <Amt Ccy="CHF">1000.00</Amt><CdtDbtInd>CRDT</CdtDbtInd>
        <Dt><Dt>2026-10-14</Dt></Dt></Bal>""" for code in ("OPBD", "CLBD"))
    document = f"""<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="{namespace}">
  <{container}>
    <GrpHdr><MsgId>{identification}-MSG</MsgId><CreDtTm>{created_at}</CreDtTm></GrpHdr>
    <{record}>
      <Id>{identification}</Id>
      <CreDtTm>{created_at}</CreDtTm>
      <Acct><Id><IBAN>{account}</IBAN></Id><Ccy>CHF</Ccy></Acct>
      {balances}
      {''.join(entries)}
    </{record}>
  </{container}>
</Document>""".encode()
    from lxml import etree

    schema_for(message).assertValid(etree.fromstring(document))
    return document


def book(store, *documents: bytes):
    return store.ingest(BANK_CONNECTION_ID, list(documents))


def acknowledged(engine, store, key: str = "returns-ack"):
    order = _order(engine, key)
    ingest(store, payment_status(order.msg_id, report_id=f"STS-{key}",
                                 group_status="ACCP"))
    return OrderStore(engine).get(order.order_id)


def test_a_credit_with_rtrinf_naming_our_message_returns_the_order(bank):
    engine, store, _ = bank
    order = acknowledged(engine, store)

    book(store, statement(credit(msg_id=order.msg_id, return_reason="AC01",
                                 return_text="Beguenstigter unbekannt")))

    returned = OrderStore(engine).get(order.order_id)
    assert returned.state is OrderState.RETURNED
    assert (returned.return_reason_code, returned.return_matched_by) == (
        "AC01", "rtrinf")
    assert returned.return_reason_text == "Beguenstigter unbekannt"
    assert returned.return_entry_ref == "ACSR-RTN-0001"
    event = detail(engine, order.order_id, "payment.returned")
    assert event["previous_state"] == "acknowledged"
    assert event["source"] == "camt.053.001.08"
    assert "amount" not in event and "counterparty" not in event


def test_a_reversal_naming_our_payment_block_returns_the_order(bank):
    engine, store, _ = bank
    order = acknowledged(engine, store)

    book(store, statement(credit(pmtinf_id=order.payment_information_id,
                                 reversal=True)))

    returned = OrderStore(engine).get(order.order_id)
    assert (returned.state, returned.return_matched_by) == (
        OrderState.RETURNED, "reversal")


def test_an_rrtn_credit_naming_the_callers_end_to_end_id_returns_the_order(
        prepared_bank):
    engine, _, _ = prepared_bank
    store = StatementStore(engine)
    from painfree import payments

    made = OrderStore(engine).submit(
        BANK_CONNECTION_ID, idempotency_key="returns-e2e",
        instruction=payments.PaymentInstruction(**payment_body(
            transactions=[_transfer(end_to_end_id="INVOICE-4711")]))).order
    OrderQueue(engine).submitted(made.order_id, bank_order_id="N01B",
                                 return_code="000000", report_text="OK")

    book(store, statement(credit(end_to_end="INVOICE-4711",
                                 sub_family="RRTN", family="ICDT")))

    assert OrderStore(engine).get(made.order_id).state is OrderState.RETURNED, \
        "a return booked before the status report still returns the order"


def _transfer(**overrides):
    from conftest import transfer

    return transfer(**overrides)


def test_an_ordinary_credit_moves_nothing(bank):
    """A credit naming our `MsgId` with no mark of a return is not a return."""
    engine, store, _ = bank
    order = acknowledged(engine, store)

    book(store, statement(credit(msg_id=order.msg_id)))

    assert OrderStore(engine).get(order.order_id).state is OrderState.ACKNOWLEDGED


def test_a_return_of_less_than_the_order_is_said_and_not_applied(bank):
    engine, store, _ = bank
    order = acknowledged(engine, store)

    book(store, statement(credit(msg_id=order.msg_id, amount="100.00",
                                 return_reason="AC04")))

    assert OrderStore(engine).get(order.order_id).state is OrderState.ACKNOWLEDGED
    assert "payment.return_partial" in actions(engine, order.order_id)


def test_the_same_return_in_the_intraday_report_and_the_statement_is_one_event(
        bank):
    engine, store, _ = bank
    order = acknowledged(engine, store)
    entry = credit(msg_id=order.msg_id, return_reason="AC01")

    book(store, statement(entry, message="camt.052.001.08",
                          identification="RPT-1"),
         statement(entry, identification="STMT-1"))

    assert actions(engine, order.order_id).count("payment.returned") == 1


def test_a_pending_credit_is_not_yet_a_return(bank):
    engine, store, _ = bank
    order = acknowledged(engine, store)

    book(store, statement(credit(msg_id=order.msg_id, return_reason="AC01",
                                 status="PDNG")))

    assert OrderStore(engine).get(order.order_id).state is OrderState.ACKNOWLEDGED


def test_another_connections_order_is_never_returned(bank, prepared_bank):
    from painfree.connections import ConnectionRegistry

    engine, store, _ = bank
    order = acknowledged(engine, store)
    ConnectionRegistry(engine).register(
        "other-bank", host_id="OTHER", partner_id="P", user_id="U",
        host_url="http://127.0.0.1:1/ebics")

    store.ingest("other-bank", [statement(credit(msg_id=order.msg_id,
                                                 return_reason="AC01"))])

    assert OrderStore(engine).get(order.order_id).state is OrderState.ACKNOWLEDGED


def test_a_return_stored_before_the_upgrade_is_found_by_re_reading(
        bank, monkeypatch):
    """The production case: the statement is already in the database."""
    from painfree import returns

    engine, store, _ = bank
    order = acknowledged(engine, store)
    with monkeypatch.context() as patch:
        patch.setattr(returns, "evidence", lambda payload: [])
        book(store, statement(credit(msg_id=order.msg_id, return_reason="AC01")))
    assert OrderStore(engine).get(order.order_id).state is OrderState.ACKNOWLEDGED

    result = store.reconcile_stored(connection_id=BANK_CONNECTION_ID)

    assert result.moved == (order.order_id,)
    assert detail(engine, order.order_id, "payment.returned")["rereconciled"]
    assert store.reconcile_stored().moved == ()


def test_a_returned_order_reaches_a_subscriber_as_order_returned(
        bank, custody_settings):
    engine, store, _ = bank
    from painfree.webhooks import WebhookSubscriptions

    subscriptions = WebhookSubscriptions(engine, custody_settings.custody_key())
    subscription, _ = subscriptions.register(
        "https://consumer.example.test/r", ["order.returned"],
        connection_id=BANK_CONNECTION_ID)
    order = acknowledged(engine, store)

    book(store, statement(credit(msg_id=order.msg_id, return_reason="AC01")))

    rows = _deliveries(engine, subscription.subscription_id)
    assert [row["event_type"] for row in rows] == ["order.returned"]
    data = rows[0]["payload"]["data"]
    assert data["reason_code"] == "AC01" and data["order_state"] == "returned"


def test_the_order_page_says_the_money_came_back_and_where(console):
    client, engine = console
    store = StatementStore(engine)
    order = acknowledged(engine, store, "returns-page")
    result = book(store, statement(credit(msg_id=order.msg_id,
                                          return_reason="AC01",
                                          return_text="Beguenstigter unbekannt")))

    page = client.get(f"/ui/orders/{order.order_id}",
                      headers={**dev_credentials("alice", "admin"), **BROWSER})

    assert "The money came back." in page.text
    assert "AC01" in page.text and "Beguenstigter unbekannt" in page.text
    assert result.statement_ids[0] in page.text
    assert "the bank&#39;s return information" in page.text \
        or "the bank's return information" in page.text


# --- a booking that only looks like a return (the SGKB case) ----------------

#: An account at St.Galler Kantonalbank: clearing number 781 in the IBAN.
SGKB_ACCOUNT = "CH9300781000012345678"
#: The shape of the production booking: the bank names the payee and their
#: address in the same sentence that says the money came back.
PAYEE = "Erika Muster, CH Musterweg 7 9000 St. Gallen"
SGKB_TEXT = ("Rueckleitung Ihrer Zahlung vom 14.10.2026., Referenznummer "
             f"2026101400042 {PAYEE} Beguenstigter unbekannt / ungenau")


def _today() -> str:
    import datetime as dt

    return dt.date.today().isoformat()


def sgkb_order(engine, store, key: str = "returns-sgkb", **transfer_overrides):
    """An acknowledged single transfer, executed today, the way issue #1's was."""
    from painfree import payments

    made = OrderStore(engine).submit(
        BANK_CONNECTION_ID, idempotency_key=key,
        instruction=payments.PaymentInstruction(**payment_body(
            requested_execution_date=_today(),
            transactions=[_transfer(**transfer_overrides)]))).order
    OrderQueue(engine).submitted(made.order_id, bank_order_id="N01S",
                                 return_code="000000", report_text="OK")
    ingest(store, payment_status(made.msg_id, report_id=f"STS-{key}",
                                 group_status="ACCP"))
    return OrderStore(engine).get(made.order_id)


def sgkb_return(*, amount: str = "3949.75", iban: str | None = None,
                text: str = SGKB_TEXT, account: str = SGKB_ACCOUNT,
                identification: str = "STMT-SGKB-1",
                message: str = "camt.053.001.08",
                reference: str = "ACSR-SGKB-0001") -> bytes:
    """What SGKB sent: a plain `RCDT/DMCT` credit, a new `MsgId`, free text."""
    from conftest import QR_IBAN

    return statement(credit(amount=amount, msg_id="SGKB-NEW-MSGID-0001",
                            counterparty_iban=iban or QR_IBAN,
                            entry_text=text, booked=_today(),
                            reference=reference),
                     account=account, identification=identification,
                     message=message)


def test_the_sgkb_return_raises_a_suspicion_and_moves_nothing(bank):
    engine, store, _ = bank
    order = sgkb_order(engine, store)

    book(store, sgkb_return())

    fresh = OrderStore(engine).get(order.order_id)
    assert fresh.state is OrderState.ACKNOWLEDGED
    assert fresh.return_suspected
    assert fresh.return_suspected_text == SGKB_TEXT
    event = detail(engine, order.order_id, "payment.return_suspected")
    assert event["matched_by"] == "heuristic"
    assert event["entry_ref"] == "ACSR-SGKB-0001"
    body = fresh.as_response()
    assert body["state"] == "acknowledged"
    assert body["return_suspected"]["dismissed_at"] is None


def test_the_same_booking_in_report_and_statement_raises_it_once(bank):
    engine, store, _ = bank
    order = sgkb_order(engine, store)

    book(store, sgkb_return(message="camt.052.001.08", identification="RPT-S"),
         sgkb_return(identification="STMT-S"))

    assert actions(engine, order.order_id).count("payment.return_suspected") == 1


@pytest.mark.parametrize("change", [
    {"account": DEBTOR_ACCOUNT},                       # another bank's account
    {"iban": "CH5800791123000889012"},                 # someone else paid us
    {"amount": "3949.70"},                             # not the order's amount
    {"text": "Rueckerstattung Rechnung 4711"},          # not SGKB's sentence
])
def test_anything_less_than_all_of_it_raises_nothing(bank, change):
    engine, store, _ = bank
    order = sgkb_order(engine, store)

    book(store, sgkb_return(**change))

    assert not OrderStore(engine).get(order.order_id).return_suspected


def test_two_orders_that_both_look_like_it_raise_nothing(bank):
    engine, store, _ = bank
    first = sgkb_order(engine, store, "returns-sgkb-1")
    second = sgkb_order(engine, store, "returns-sgkb-2")

    book(store, sgkb_return())

    assert not OrderStore(engine).get(first.order_id).return_suspected
    assert not OrderStore(engine).get(second.order_id).return_suspected


def test_confirming_returns_the_order_and_names_the_person(bank):
    from painfree.audit import Actor

    engine, store, _ = bank
    order = sgkb_order(engine, store)
    book(store, sgkb_return())

    store.returns.confirm(order.order_id, actor=Actor("user", "olive"))

    returned = OrderStore(engine).get(order.order_id)
    assert (returned.state, returned.return_matched_by) == (
        OrderState.RETURNED, "operator")
    assert returned.return_reason_text is None, "the sentence is not a reason"
    assert returned.return_suspected_text == SGKB_TEXT, "kept for the console"
    assert not returned.return_suspected
    with engine.connect() as connection:
        actor = connection.execute(
            select(audit_log.c.actor_id)
            .where(audit_log.c.order_id == order.order_id,
                   audit_log.c.action == "payment.returned")).scalar_one()
    assert actor == "olive"


def test_dismissing_closes_it_and_the_same_booking_does_not_reopen_it(bank):
    from painfree.errors import ConflictError

    engine, store, _ = bank
    order = sgkb_order(engine, store)
    book(store, sgkb_return(message="camt.052.001.08", identification="RPT-D"))

    store.returns.dismiss(order.order_id)
    book(store, sgkb_return(identification="STMT-D"))

    fresh = OrderStore(engine).get(order.order_id)
    assert fresh.state is OrderState.ACKNOWLEDGED
    assert not fresh.return_suspected
    assert fresh.as_response()["return_suspected"]["dismissed_at"]
    assert "payment.return_dismissed" in actions(engine, order.order_id)
    with pytest.raises(ConflictError):
        store.returns.confirm(order.order_id)


def test_the_stored_sgkb_statement_is_found_by_re_reading(bank, monkeypatch):
    """Issue #1's own order: its statement arrived before this existed."""
    from painfree import returns

    engine, store, _ = bank
    order = sgkb_order(engine, store)
    with monkeypatch.context() as patch:
        patch.setattr(returns, "SUSPECT_PATTERNS", ())
        book(store, sgkb_return())
    assert not OrderStore(engine).get(order.order_id).return_suspected

    store.reconcile_stored(connection_id=BANK_CONNECTION_ID)

    assert OrderStore(engine).get(order.order_id).return_suspected
    assert detail(engine, order.order_id,
                  "payment.return_suspected")["rereconciled"] is True


def test_the_console_rings_the_bell_and_an_operator_decides(console):
    client, engine = console
    store = StatementStore(engine)
    order = sgkb_order(engine, store, "returns-sgkb-console")
    book(store, sgkb_return())
    operator = {**dev_credentials("olive", "member"), **BROWSER}

    page = client.get(f"/ui/orders/{order.order_id}", headers=operator)
    assert "The money may have come back." in page.text
    assert "1 payment may have come back" in page.text, "the bell counts it"
    confirm = f"/ui/orders/{order.order_id}/return/confirm"
    assert f'action="{confirm}"' in page.text

    client.post(confirm, headers=operator)
    assert OrderStore(engine).get(order.order_id).state is OrderState.RETURNED


def test_a_viewer_sees_the_suspicion_and_cannot_decide_it(console):
    client, engine = console
    store = StatementStore(engine)
    order = sgkb_order(engine, store, "returns-sgkb-viewer")
    book(store, sgkb_return())
    viewer = {**dev_credentials("reader", "member"), **BROWSER}

    page = client.get(f"/ui/orders/{order.order_id}", headers=viewer)
    assert "The money may have come back." in page.text
    assert "/return/confirm" not in page.text
    assert client.post(f"/ui/orders/{order.order_id}/return/confirm",
                       headers=viewer).status_code == 403


# --- sending it again, corrected --------------------------------------------

def test_a_returned_payment_is_copied_into_the_form_not_replayed(console):
    from conftest import QR_IBAN

    client, engine = console
    store = StatementStore(engine)
    order = acknowledged(engine, store, "returns-copy")
    book(store, statement(credit(msg_id=order.msg_id, return_reason="AC01")))
    admin = {**dev_credentials("alice", "admin"), **BROWSER}

    page = client.get(f"/ui/orders/{order.order_id}", headers=admin)
    link = (f"/ui/connections/{BANK_CONNECTION_ID}/payment"
            f"?from_order={order.order_id}")
    assert f'href="{link}"' in page.text
    assert f"/ui/orders/{order.order_id}/replay" not in page.text

    form = client.get(link, headers=admin)
    assert form.status_code == 200
    assert f"Copied from {order.order_id}." in form.text
    assert QR_IBAN in form.text and "3949.75" in form.text
    assert "Robert Schneider AG" in form.text


def test_a_copy_is_only_of_an_order_at_the_same_bank(console):
    from painfree.connections import ConnectionRegistry

    client, engine = console
    order = _order(engine, "returns-copy-other")
    ConnectionRegistry(engine).register(
        "other-bank", host_id="OTHER", partner_id="P", user_id="U",
        host_url="http://127.0.0.1:1/ebics")

    answer = client.get(f"/ui/connections/other-bank/payment"
                        f"?from_order={order.order_id}",
                        headers={**dev_credentials("alice", "admin"), **BROWSER})
    assert answer.status_code == 404


def test_the_status_codes_page_says_acknowledged_is_not_received(console):
    client, _ = console
    page = client.get("/ui/status-codes",
                      headers={**dev_credentials("alice", "admin"), **BROWSER})
    assert "not that the beneficiary received it" in page.text



# --- the bank's sentence stays on the console ------------------------------

def _everything_sent(engine, order_id: str) -> str:
    """Every audit detail and every queued envelope for one order, as text."""
    import json

    from painfree.schema import webhook_delivery

    with engine.connect() as connection:
        details = connection.execute(
            select(audit_log.c.detail)
            .where(audit_log.c.order_id == order_id)).scalars().all()
        envelopes = connection.execute(
            select(webhook_delivery.c.payload)
            .where(webhook_delivery.c.order_id == order_id)).scalars().all()
    return json.dumps([details, envelopes], ensure_ascii=False)


def test_a_suspected_return_names_nobody_in_its_event_or_response(
        bank, custody_settings):
    from painfree.audit import Actor
    from painfree.webhooks import WebhookSubscriptions

    engine, store, _ = bank
    WebhookSubscriptions(engine, custody_settings.custody_key()).register(
        "https://consumer.example.test/all",
        ["order.return_suspected", "order.returned"],
        connection_id=BANK_CONNECTION_ID)
    order = sgkb_order(engine, store)

    book(store, sgkb_return())
    suspected = OrderStore(engine).get(order.order_id).as_response()
    store.returns.confirm(order.order_id, actor=Actor("user", "olive"))
    returned = OrderStore(engine).get(order.order_id).as_response()

    for text in (_everything_sent(engine, order.order_id),
                 str(suspected), str(returned)):
        assert "Erika Muster" not in text and "Musterweg" not in text
    assert detail(engine, order.order_id,
                  "payment.return_suspected")["bank"] == "SGKB"


def test_a_marked_return_takes_its_reason_from_rtrinf_not_the_entry(bank):
    engine, store, _ = bank
    order = acknowledged(engine, store)

    book(store, statement(credit(msg_id=order.msg_id, return_reason="AC01",
                                 entry_text=f"Rueckleitung {PAYEE}")))

    returned = OrderStore(engine).get(order.order_id)
    assert returned.return_reason_code == "AC01"
    assert returned.return_reason_text is None
    assert "Erika Muster" not in _everything_sent(engine, order.order_id)


def test_the_console_still_shows_the_sentence(console):
    client, engine = console
    store = StatementStore(engine)
    order = sgkb_order(engine, store, "returns-sentence")
    book(store, sgkb_return())

    page = client.get(f"/ui/orders/{order.order_id}",
                      headers={**dev_credentials("alice", "admin"), **BROWSER})
    assert "Erika Muster" in page.text
