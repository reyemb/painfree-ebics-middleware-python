"""The operator console: what it renders, and what the server refuses.

The tests worth having here are the ones a screenshot cannot give:

**Hiding a control is not authorisation.** Every write route is posted to
directly by a caller whose role does not hold the scope, with no page rendered
first. A `403` from the server is the claim; the missing button is decoration.

**The console cannot open a key.** The key-lifecycle routes are driven and then
the database is inspected: what a click produces is a queued row, and nothing
else moves until a worker runs.

**Replay does not create a payment.** The order count, the row and the `MsgId`
are all compared before and after.
"""

from __future__ import annotations

from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from painfree import ebics3
from painfree.app import create_app
from painfree.keyjobs import JobState, KeyAction
from painfree.orders import OrderState, OrderStore
from painfree.schema import (audit_log, bank_connection, key_material,
                             payment_order)
from painfree.statements import StatementStore
from tests.conftest import (BANK_CONNECTION_ID, dev_credentials, fixture_bytes,
                            grant, payment_body, transfer)

BROWSER = {"accept": "text/html,application/xhtml+xml"}


def _admin(**extra) -> dict[str, str]:
    return {**dev_credentials("alice", "admin"), **BROWSER, **extra}


def _viewer(**extra) -> dict[str, str]:
    """A member holding a `viewer` grant on this connection."""
    return {**dev_credentials("reader", "member"), **BROWSER, **extra}


def _operator(**extra) -> dict[str, str]:
    """A member holding an `operator` grant on this connection."""
    return {**dev_credentials("olive", "member"), **BROWSER, **extra}


@pytest.fixture
def console(prepared_bank, custody_settings):
    """The application, over a connection that is already initialised.

    The two members are granted that connection here, at the levels their names
    say. Without the grants they would be refused everything, which is the
    model working rather than the console being broken -- and is proved as its
    own case in ``tests/test_service_access.py``.
    """
    engine, connection, bank_keys = prepared_bank
    app = create_app(custody_settings)
    with TestClient(app) as client:
        grant(app, "olive", BANK_CONNECTION_ID, "operator")
        grant(app, "reader", BANK_CONNECTION_ID, "viewer")
        yield client, engine, connection


def _submit(client, key: str = "console-0001"):
    return client.post(
        f"/v1/connections/{BANK_CONNECTION_ID}/payments", json=payment_body(),
        headers={**dev_credentials("alice", "admin"),
                 "Idempotency-Key": key})


# --- every page renders -----------------------------------------------------

def test_every_console_page_renders_for_an_operator_who_may_see_it(console):
    client, engine, connection = console
    order = _submit(client).json()
    statement_id = StatementStore(engine).ingest(
        BANK_CONNECTION_ID, [fixture_bytes("camt.053.001.08")]).statement_ids[0]

    pages = [
        "/ui/connections",
        "/ui/connections/new",
        f"/ui/connections/{BANK_CONNECTION_ID}",
        f"/ui/connections/{BANK_CONNECTION_ID}/edit",
        f"/ui/connections/{BANK_CONNECTION_ID}/keys",
        f"/ui/connections/{BANK_CONNECTION_ID}/letter",
        "/ui/orders",
        f"/ui/orders/{order['order_id']}",
        "/ui/statements",
        f"/ui/statements/{statement_id}",
        "/ui/status-codes",
    ]
    for path in pages:
        response = client.get(path, headers=_admin())
        assert response.status_code == 200, (path, response.text[:300])
        assert response.headers["content-type"].startswith("text/html"), path
        assert "<!doctype html>" in response.text.lower(), path

    root = client.get("/", headers=_admin(), follow_redirects=False)
    assert root.status_code == 303
    assert root.headers["location"] == "/ui/connections"


def test_the_letter_carries_the_fingerprints_of_the_stored_keys(console):
    """The value a human compares. It has to be the engine's, not a second one."""
    client, engine, connection = console
    page = client.get(f"/ui/connections/{BANK_CONNECTION_ID}/letter",
                      headers=_admin())
    keyring = client.app.state.keyring
    digest = client.app.state.connections.get(BANK_CONNECTION_ID).letter_digest
    for version in (ebics3.KeyVersion.A006, ebics3.KeyVersion.X002,
                    ebics3.KeyVersion.E002):
        # Whichever of the two fingerprints this connection quotes. Read
        # through the connection: `entry.fingerprint` is the keyring's index,
        # which is the public-key digest whatever the letter says.
        expected = ebics3.ini_letter_hash(
            keyring.public_key(BANK_CONNECTION_ID, version), digest)
        assert ebics3.format_fingerprint(expected) in page.text, version
        assert version.value in page.text


def test_an_order_page_renders_a_summary_and_never_the_document(console):
    """Who was paid, yes. The message itself, no.

    These were one rule and are now two, because they were never the same
    question. Dumping `pain.001` into a page is a rendering mistake: XML nobody
    reads, in a page that then has to escape it. Naming the recipient is what
    the page is *for* -- an operator scanning an order history is looking for
    "did Robert Schneider AG get paid", and an order id cannot answer that.

    It is not a widening of access either. `/ui/orders/{id}/document.xml` needs
    the same `payments:read` this page needs, so the caller reading this
    summary could already download every byte it was taken from. What is
    withheld here is withheld from *the layout*, not from the reader.
    """
    client, engine, _ = console
    order = _submit(client, "console-nodoc").json()
    page = client.get(f"/ui/orders/{order['order_id']}", headers=_admin())
    assert page.status_code == 200
    assert order["msg_id"] in page.text
    assert "pain.001" in page.text  # the message type, which is not content

    # The summary: the recipient and the account, read out of the document.
    assert "CH4431999123000889012" in page.text

    # The document: still never inline, in any form.
    assert "<Document" not in page.text
    assert "CdtTrfTxInf" not in page.text
    assert "urn:iso:std:iso:20022" not in page.text


# --- the browser story ------------------------------------------------------

def test_a_browser_with_no_session_is_sent_to_the_login_and_a_client_is_not(console):
    client, _, _ = console
    browser = client.get("/ui/connections", headers=BROWSER,
                         follow_redirects=False)
    assert browser.status_code == 303
    assert browser.headers["location"] == "/auth/login?next=/ui/connections"

    api = client.get("/ui/connections", follow_redirects=False)
    assert api.status_code == 401
    assert api.json()["error"]["code"] == "unauthenticated"
    assert "WWW-Authenticate" in api.headers


def test_a_console_failure_is_a_page_for_a_browser_and_an_envelope_for_a_client(
        console):
    client, _, _ = console
    page = client.get("/ui/connections/nope", headers=_admin())
    assert page.status_code == 404
    assert page.headers["content-type"].startswith("text/html")
    assert "not_found" in page.text

    envelope = client.get("/ui/connections/nope",
                          headers=dev_credentials("alice", "admin"))
    assert envelope.status_code == 404
    assert envelope.json()["error"]["code"] == "not_found"


# --- hiding a button is not authorisation -----------------------------------

WRITE_ROUTES = [
    ("post", "/ui/connections", {"connection_id": "x"}, "connections:write"),
    ("post", f"/ui/connections/{BANK_CONNECTION_ID}/edit",
     {"host_url": "http://evil.test/ebics"}, "connections:write"),
    ("post", f"/ui/connections/{BANK_CONNECTION_ID}/keys/create_keys", {},
     "connections:write"),
    ("post", f"/ui/connections/{BANK_CONNECTION_ID}/keys/fetch_hpb", {},
     "connections:write"),
]


@pytest.mark.parametrize("method,path,form,scope", WRITE_ROUTES)
def test_a_viewer_is_refused_by_the_server_not_by_a_missing_button(
        console, method, path, form, scope):
    client, engine, _ = console
    response = getattr(client, method)(path, data=form, headers=_viewer())
    assert response.status_code == 403, response.text[:300]
    assert scope in response.text
    with engine.connect() as connection:
        assert connection.execute(
            select(func.count()).select_from(key_material)
            .where(key_material.c.holder == "bank")).scalar_one() == 2


def test_a_viewer_who_never_saw_the_page_still_cannot_replay(console):
    """Issued directly, with no page rendered first. The scope is the control."""
    client, engine, _ = console
    order = _submit(client, "console-scope-0001").json()
    refused = client.post(f"/ui/orders/{order['order_id']}/replay",
                          data={"confirm": "replay"},
                          headers=_viewer(), follow_redirects=False)
    assert refused.status_code == 403
    body = refused.text
    assert "orders:replay" in body
    assert OrderStore(engine).get(order["order_id"]).state is OrderState.ACCEPTED


def test_a_viewer_is_not_offered_the_controls_either(console):
    """The hiding is a courtesy, and it should still work."""
    client, _, _ = console
    page = client.get(f"/ui/connections/{BANK_CONNECTION_ID}", headers=_viewer())
    assert page.status_code == 200
    assert "/edit" not in page.text
    assert "Key lifecycle" in page.text  # reading is allowed


# --- the key lifecycle, from the console's side -----------------------------

def test_a_console_click_appends_a_job_and_opens_nothing(console):
    client, engine, _ = console
    response = client.post(
        f"/ui/connections/{BANK_CONNECTION_ID}/keys/fetch_hpb", data={},
        headers=_admin(), follow_redirects=False)
    assert response.status_code == 303
    job_id = response.headers["location"].split("job=")[1]

    job = client.app.state.key_jobs.get(job_id)
    assert job.state is JobState.QUEUED
    assert job.action is KeyAction.fetch_hpb
    assert job.requested_by_id == "alice"
    # Queued, and that is all: no worker ran, so nothing was decrypted and the
    # bank was never contacted.
    assert job.result is None

    page = client.get(f"/ui/connections/{BANK_CONNECTION_ID}/keys?job={job_id}",
                      headers=_admin())
    assert "Waiting for the worker" in page.text
    assert "http-equiv=\"refresh\"" in page.text


def test_the_comparison_page_needs_keys_to_compare(console):
    client, _, _ = console
    page = client.get(
        f"/ui/connections/{BANK_CONNECTION_ID}/keys/bank-keys", headers=_admin())
    assert page.status_code == 404
    assert "fetch HPB first" in page.text


def test_an_operation_the_key_state_forbids_is_refused_with_a_page(console):
    client, _, _ = console
    refused = client.post(
        f"/ui/connections/{BANK_CONNECTION_ID}/keys/send_ini", data={},
        headers=_admin())
    assert refused.status_code == 409
    assert "send_ini cannot be asked for" in refused.text


def test_confirming_without_typing_a_fingerprint_is_refused(console):
    """The two values are the operator's. Nothing defaults them."""
    client, engine, _ = console
    # Put the connection somewhere the confirmation is offered from.
    refused = client.post(
        f"/ui/connections/{BANK_CONNECTION_ID}/keys/confirm_bank_keys",
        data={"authentication": "", "encryption": ""}, headers=_admin())
    assert refused.status_code == 409
    assert "fingerprint is required" in refused.text


# --- replay -----------------------------------------------------------------

def _make_terminal(engine, order_id: str, state: OrderState) -> None:
    """Put an order where the worker would have put it. Nothing else changes."""
    with engine.begin() as connection:
        connection.execute(payment_order.update()
                           .where(payment_order.c.order_id == order_id)
                           .values(state=state.value, attempts=5,
                                   return_code="091302",
                                   report_text="[EBICS_INVALID_REQUEST] refused"))


def test_replay_is_confirmed_by_a_page_that_names_what_is_resent(console):
    client, engine, _ = console
    order = _submit(client, "console-replay-0001").json()
    _make_terminal(engine, order["order_id"], OrderState.REJECTED)

    page = client.get(f"/ui/orders/{order['order_id']}/replay",
                      headers=_operator())
    assert page.status_code == 200
    # The amount is the one value on this page that a locale is allowed to
    # rewrite, and English groups thousands: the API answered `3949.75` and the
    # page says `3,949.75`. Everything else here is an identifier or a bank's
    # return code and is shown exactly as stored.
    displayed = f"{Decimal(order['control_sum']):,}"
    for named in (order["msg_id"], displayed, order["currency"],
                  BANK_CONNECTION_ID, "091302"):
        assert named in page.text, named
    assert "No second payment is created" in page.text


def test_replay_requeues_the_same_order_and_creates_no_second_payment(console):
    client, engine, _ = console
    order = _submit(client, "console-replay-0002").json()
    _make_terminal(engine, order["order_id"], OrderState.FAILED)

    def orders_and_messages():
        with engine.connect() as connection:
            return (connection.execute(
                        select(func.count()).select_from(payment_order)).scalar_one(),
                    set(connection.execute(
                        select(payment_order.c.msg_id)).scalars()))

    before = orders_and_messages()
    response = client.post(f"/ui/orders/{order['order_id']}/replay",
                           data={"confirm": "replay"}, headers=_operator(),
                           follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].endswith("?replayed=1")
    assert orders_and_messages() == before

    replayed = OrderStore(engine).get(order["order_id"])
    assert replayed.state is OrderState.ACCEPTED
    assert replayed.msg_id == order["msg_id"]
    assert replayed.attempts == 0
    # The document is the one built at accept time. Nothing rebuilt it.
    assert replayed.document == OrderStore(engine).get(order["order_id"]).document

    with engine.connect() as connection:
        rows = connection.execute(
            select(audit_log.c.action, audit_log.c.actor_id, audit_log.c.detail)
            .where(audit_log.c.action == "payment.replay_requested")).all()
    assert len(rows) == 1
    assert rows[0].actor_id == "olive"
    assert rows[0].detail["from_state"] == "failed"
    assert rows[0].detail["msg_id"] == order["msg_id"]


def test_an_order_the_worker_still_owns_cannot_be_replayed(console):
    client, engine, _ = console
    order = _submit(client, "console-replay-0003").json()
    refused = client.post(f"/ui/orders/{order['order_id']}/replay",
                          data={"confirm": "replay"}, headers=_operator())
    assert refused.status_code == 409
    assert "accepted" in refused.text


def test_a_replay_that_was_not_confirmed_does_nothing(console):
    client, engine, _ = console
    order = _submit(client, "console-replay-0004").json()
    _make_terminal(engine, order["order_id"], OrderState.FAILED)
    refused = client.post(f"/ui/orders/{order['order_id']}/replay",
                          data={}, headers=_operator())
    assert refused.status_code == 409
    assert OrderStore(engine).get(order["order_id"]).state is OrderState.FAILED


# --- listings ---------------------------------------------------------------

def test_the_order_list_filters_and_shows_the_banks_own_words(console):
    client, engine, _ = console
    first = _submit(client, "console-list-0001").json()
    second = _submit(client, "console-list-0002").json()
    _make_terminal(engine, second["order_id"], OrderState.REJECTED)

    everything = client.get("/ui/orders", headers=_admin())
    assert first["order_id"] in everything.text
    assert second["order_id"] in everything.text

    rejected = client.get("/ui/orders?state=rejected", headers=_admin())
    assert second["order_id"] in rejected.text
    assert first["order_id"] not in rejected.text
    assert "091302" in rejected.text
    assert "[EBICS_INVALID_REQUEST] refused" in rejected.text

    elsewhere = client.get("/ui/orders?connection_id=someone-else",
                           headers=_admin())
    assert "No orders match" in elsewhere.text


def test_a_statement_page_shows_the_normalised_json_and_the_list_does_not(console):
    client, engine, _ = console
    result = StatementStore(engine).ingest(
        BANK_CONNECTION_ID, [fixture_bytes("camt.053.001.08")])
    statement_id = result.statement_ids[0]

    listing = client.get("/ui/statements", headers=_admin())
    assert statement_id in listing.text
    assert "entries" not in listing.text.split("<table")[1][:200]

    page = client.get(f"/ui/statements/{statement_id}", headers=_admin())
    assert page.status_code == 200
    assert "Normalised JSON" in page.text
    assert "&#34;entries&#34;" in page.text or "\"entries\"" in page.text


def test_an_account_statement_is_drawn_as_an_account_statement(console):
    """Two amount columns, a running balance, and a check that it adds up.

    The balance column is this console's arithmetic: no `camt` message carries
    one. The check against the closing balance the bank stated is what makes
    showing it defensible.
    """
    client, engine, _ = console
    statement_id = StatementStore(engine).ingest(
        BANK_CONNECTION_ID, [fixture_bytes("camt.053.001.08")]).statement_ids[0]

    page = client.get(f"/ui/statements/{statement_id}", headers=_admin())
    assert page.status_code == 200
    assert "Money in" in page.text and "Money out" in page.text
    # Opening 1000.00, one debit of 3949.75, two credits of 0.10 and 0.20.
    # Every running figure, and the closing balance they have to reach.
    for figure in ("1,000.00", "-2,949.75", "-2,949.65", "-2,949.45"):
        assert figure in page.text, figure
    assert "The entries add up to the closing balance" in page.text
    assert "Robert Schneider AG" in page.text and "Bernasconi SA" in page.text
    assert "Normalised JSON" in page.text


def test_a_statement_entry_that_settles_our_payment_links_to_the_order(console):
    """The last link of the chain: the report said taken, this says booked."""
    client, engine, _ = console
    order = _submit(client, "console-booked").json()
    # The fixture books a payment under a `MsgId` of its own. Give it ours, so
    # the entry is one this deployment sent rather than one it merely holds.
    document = fixture_bytes("camt.053.001.08").replace(
        b"PF3868D16485F403EA96B3AF3B78F98E6", order["msg_id"].encode())
    statement_id = StatementStore(engine).ingest(
        BANK_CONNECTION_ID, [document]).statement_ids[0]

    page = client.get(f"/ui/statements/{statement_id}", headers=_admin())
    assert page.status_code == 200
    assert "Our payment" in page.text
    assert f'/ui/orders/{order["order_id"]}' in page.text
    # And the filter that shows only those exists once there is one.
    assert "?show=ours" in page.text

    only_ours = client.get(f"/ui/statements/{statement_id}?show=ours",
                           headers=_admin())
    # Above the normalised payload, which is the whole document either way.
    ledger = only_ours.text.split('<details class="card">')[0]
    assert "Robert Schneider AG" in ledger
    assert "Bernasconi SA" not in ledger, "the credits are filtered out"
    # The balance column is still the account's, not the filter's.
    assert "-2,949.75" in ledger


def test_an_order_shows_the_banks_status_report_and_links_to_it(console):
    """The two directions of the join, both rendered, neither quoting a payment."""
    from tests.conftest import payment_status, valid_payment_status
    from painfree.queue import OrderQueue

    client, engine, _ = console
    order = _submit(client, "console-status").json()
    OrderQueue(engine).submitted(order["order_id"], bank_order_id="N01A",
                                 return_code="000000", report_text="OK")
    result = StatementStore(engine).ingest(
        BANK_CONNECTION_ID,
        [valid_payment_status(payment_status(
            order["msg_id"], group_status="PART", payment_status="ACCP",
            number_of_transactions="2", control_sum="4199.75",
            transactions=(
                _status("ACSP"),
                _status("RJCT", end_to_end="E2E-0002", amount="250.00",
                        reason_code="AC01",
                        reason_text="Creditor account number invalid"))))])
    statement_id = result.statement_ids[0]

    page = client.get(f"/ui/orders/{order['order_id']}", headers=_admin())
    assert page.status_code == 200
    assert "PART" in page.text and "PartiallyAccepted" in page.text
    assert "AC01" in page.text and "Creditor account number invalid" in page.text
    assert statement_id in page.text
    # The report is linked, not quoted: no end-to-end reference, and none of
    # the per-transaction amounts it carries. (The order's own control sum is
    # on the page; it is the order's, not the report's.)
    assert "E2E-0002" not in page.text
    assert "250.00" not in page.text

    report = client.get(f"/ui/statements/{statement_id}", headers=_admin())
    assert order["order_id"] in report.text, "the statement links back"


def test_the_index_is_split_because_it_holds_two_kinds_of_document(console):
    """One table with both would have a closing balance column half empty."""
    from tests.conftest import payment_status, valid_payment_status

    client, engine, _ = console
    order = _submit(client, "console-index").json()
    StatementStore(engine).ingest(
        BANK_CONNECTION_ID,
        [fixture_bytes("camt.053.001.08"),
         valid_payment_status(payment_status(order["msg_id"],
                                             group_status="ACSP"))])

    accounts = client.get("/ui/statements", headers=_admin())
    assert accounts.status_code == 200
    assert "CH5604835012345678009" in accounts.text
    assert "camt.053.001.08" in accounts.text
    assert "pain.002" not in accounts.text.split("<table")[1], \
        "a status report is not an account statement"

    responses = client.get("/ui/statements?family=response", headers=_admin())
    assert responses.status_code == 200
    # What the bank said, and which order it said it about.
    assert "ACSP" in responses.text
    assert "AcceptedSettlementInProcess" in responses.text
    assert order["order_id"] in responses.text
    # Still no entry content on an index, and no money either.
    assert "Robert Schneider AG" not in responses.text
    assert "3,949.75" not in responses.text


def test_a_status_report_is_read_against_the_payment_it_answers(console):
    """The rows are the message's, the verdict is the bank's, and both are said.

    A page rendered from the report alone would show two statuses and no money.
    The transfers come from the stored `pain.001`, so the amount that was
    refused is on the screen beside the reason it was refused for.
    """
    from tests.conftest import PLAIN_IBAN, payment_status, valid_payment_status
    from painfree.queue import OrderQueue

    client, engine, _ = console
    order = client.post(
        f"/v1/connections/{BANK_CONNECTION_ID}/payments",
        headers={**_admin(), "Idempotency-Key": "console-answers"},
        json=payment_body(transactions=[
            transfer(end_to_end_id="E2E-0001"),
            transfer(end_to_end_id="E2E-0002", amount="250.00",
                     creditor_iban=PLAIN_IBAN, reference={"type": "NONE"},
                     creditor={"name": "Muster Handels AG",
                               "postal_address": {"town": "Biel",
                                                  "country": "CH"}}),
        ])).json()
    OrderQueue(engine).submitted(order["order_id"], bank_order_id="N01A",
                                 return_code="000000", report_text="OK")
    statement_id = StatementStore(engine).ingest(
        BANK_CONNECTION_ID,
        [valid_payment_status(payment_status(
            order["msg_id"], group_status="PART", payment_status="ACCP",
            number_of_transactions="2", control_sum="4199.75",
            transactions=(
                _status("ACSP"),
                _status("RJCT", end_to_end="E2E-0002", amount="250.00",
                        reason_code="AC01",
                        reason_text="Creditor account number invalid")),
        ))]).statement_ids[0]

    page = client.get(f"/ui/statements/{statement_id}", headers=_admin())
    assert page.status_code == 200
    # Both halves of the table, and the boundary between them named.
    assert "What we sent" in page.text and "What the bank said" in page.text
    assert "Robert Schneider AG" in page.text
    assert "Muster Handels AG" in page.text
    # The money the bank refused, which is in the message and not in the report
    # this page could have been rendered from alone.
    assert "250.00" in page.text and "3,949.75" in page.text
    assert "ACSP" in page.text and "RJCT" in page.text
    assert "AC01" in page.text
    assert "Creditor account number invalid" in page.text
    # The group status decided the order, and the page says which level did.
    assert "PART" in page.text and "decides the order" in page.text
    assert order["order_id"] in page.text


def test_a_status_report_that_names_nothing_still_answers_every_payment(console):
    """The ordinary case: the bank took the file and named no transaction.

    This is the page that used to be thirteen nulls. Every transfer is
    answered, from the level the bank actually spoke at, and the page says so
    rather than letting `ACCP` read as a verdict on each payment.
    """
    from tests.conftest import payment_status, valid_payment_status

    client, engine, _ = console
    order = client.post(
        f"/v1/connections/{BANK_CONNECTION_ID}/payments",
        headers={**_admin(), "Idempotency-Key": "console-silent"},
        json=payment_body(transactions=[transfer(end_to_end_id="E2E-0001")])).json()
    statement_id = StatementStore(engine).ingest(
        BANK_CONNECTION_ID,
        # The report this deployment actually gets: a group status, and not
        # one field more. No count, no control sum, no payment block, no
        # transaction. Every amount on the page below comes from our message.
        [valid_payment_status(payment_status(
            order["msg_id"], group_status="ACCP",
            number_of_transactions=None, control_sum=None))]
    ).statement_ids[0]

    page = client.get(f"/ui/statements/{statement_id}", headers=_admin())
    assert page.status_code == 200
    assert "The bank accepted the file" in page.text
    assert "Robert Schneider AG" in page.text and "3,949.75" in page.text
    assert "ACCP" in page.text
    # Said at the group level, and marked as such rather than shown as though
    # the bank had answered about this payment.
    assert "from the whole message" in page.text
    assert "not reported" in page.text, "the two silent levels say so"
    assert "The bank restated neither" in page.text
    # The normalised document is still reachable, and is no longer the page.
    assert "Normalised JSON" in page.text


def test_a_report_that_answers_no_order_says_so_rather_than_showing_nothing(console):
    from tests.conftest import payment_status, valid_payment_status

    client, engine, _ = console
    statement_id = StatementStore(engine).ingest(
        BANK_CONNECTION_ID,
        [valid_payment_status(payment_status("PF-NOBODY-SENT-THIS",
                                             group_status="RJCT"))]
    ).statement_ids[0]
    page = client.get(f"/ui/statements/{statement_id}", headers=_admin())
    assert page.status_code == 200
    assert "The bank refused the file" in page.text
    assert "answers no order here" in page.text


def test_the_status_code_page_is_the_mapping_the_reconciler_uses(console):
    """A page an operator can read, rendered from the dictionary that decides."""
    from painfree.reconcile import STATUS_CODES

    client, _, _ = console
    page = client.get("/ui/status-codes", headers=_admin())
    assert page.status_code == 200
    for code in STATUS_CODES.values():
        assert code.code in page.text, code.code
        assert code.name in page.text, code.name
    assert "PART" in page.text and "is an acknowledgement" in page.text


def _status(status: str, **overrides):
    from tests.conftest import status_transaction

    return status_transaction(status, **overrides)


def test_reading_statements_needs_its_own_scope(console):
    client, _, _ = console
    refused = client.get("/ui/statements",
                         headers={**dev_credentials("auditor-only", "unmapped"),
                                  **BROWSER})
    assert refused.status_code == 403
    assert "statements:read" in refused.text


# --- editing ----------------------------------------------------------------

def test_changing_the_host_url_is_audited_with_both_values(console):
    client, engine, connection = console
    response = client.post(
        f"/ui/connections/{BANK_CONNECTION_ID}/edit",
        data={"host_url": "https://new.example.test/ebics",
              # The value the connection already has: this test is
              # about the host URL, and posting a stale convention
              # would trip the confirmation gate instead.
              "letter_digest": "certificate"},
        headers=_admin(), follow_redirects=False)
    assert response.status_code == 303

    with engine.connect() as db_connection:
        row = db_connection.execute(
            select(audit_log.c.detail, audit_log.c.actor_id)
            .where(audit_log.c.action == "connection.updated")).one()
    assert row.actor_id == "alice"
    assert row.detail["changed"]["host_url"] == {
        "from": connection.host_url, "to": "https://new.example.test/ebics"}


def test_the_console_refuses_a_body_that_is_not_a_form(console):
    client, _, _ = console
    refused = client.post(f"/ui/connections/{BANK_CONNECTION_ID}/edit",
                          json={"host_url": "https://x.test"}, headers=_admin())
    assert refused.status_code == 409
    assert "form submissions only" in refused.text


# --- the letter is paper, and it is already at the bank ----------------------
#
# A production incident: the connection was registered with the default hash
# convention, the letter was printed, signed and posted, INI and HIA went out,
# and the convention was changed the next morning. Nothing was wrong with the
# keys -- the bank was comparing the letter against a hash the letter did not
# quote. The change was one select and a save, and it said nothing.

def test_changing_the_hash_convention_after_ini_is_refused_unconfirmed(console):
    """Not blocked -- a bank saying "wrong convention" is exactly when it is
    needed -- but not silent either. The refusal says what it costs."""
    client, engine, *_ = console
    with engine.begin() as connection:
        connection.execute(
            update(bank_connection)
            .where(bank_connection.c.connection_id == BANK_CONNECTION_ID)
            .values(ini_sent=True))

    response = client.post(f"/ui/connections/{BANK_CONNECTION_ID}/edit", data={
        "host_url": "https://ebics.example.test/", "letter_digest": "public_key"},
        headers=_admin())

    assert response.status_code == 409
    body = response.text
    assert "reprinted" in body or "reprint" in body
    # And it did not change.
    with engine.connect() as connection:
        digest = connection.execute(
            select(bank_connection.c.letter_digest)
            .where(bank_connection.c.connection_id == BANK_CONNECTION_ID)).scalar_one()
    assert digest == "certificate"


def test_confirming_it_goes_through(console):
    """The operator who has read the sentence can still do the thing."""
    client, engine, *_ = console
    with engine.begin() as connection:
        connection.execute(
            update(bank_connection)
            .where(bank_connection.c.connection_id == BANK_CONNECTION_ID)
            .values(ini_sent=True))

    response = client.post(f"/ui/connections/{BANK_CONNECTION_ID}/edit", data={
        "host_url": "https://ebics.example.test/", "letter_digest": "public_key",
        "confirm_letter_digest": "yes"}, headers=_admin(),
        follow_redirects=False)

    assert response.status_code in (302, 303), response.text
    with engine.connect() as connection:
        digest = connection.execute(
            select(bank_connection.c.letter_digest)
            .where(bank_connection.c.connection_id == BANK_CONNECTION_ID)).scalar_one()
    assert digest == "public_key"


def test_nothing_is_confirmed_before_a_letter_can_have_been_sent(console):
    """Before INI, the letter is not at a bank and this is an ordinary edit.

    The fixture arrives initialised, so the flags are cleared here: what is
    under test is the state a connection is in on the day it is registered.
    """
    client, engine, *_ = console
    with engine.begin() as connection:
        connection.execute(
            update(bank_connection)
            .where(bank_connection.c.connection_id == BANK_CONNECTION_ID)
            .values(ini_sent=False, hia_sent=False))

    response = client.post(f"/ui/connections/{BANK_CONNECTION_ID}/edit", data={
        "host_url": "https://ebics.example.test/", "letter_digest": "public_key"},
        headers=_admin(), follow_redirects=False)

    assert response.status_code in (302, 303), response.text


def test_the_letter_says_which_hash_it_quotes(console):
    """In words. `public_key` on a document a bank clerk reads is not an answer."""
    client, *_ = console

    page = client.get(f"/ui/connections/{BANK_CONNECTION_ID}/letter",
                      headers=_admin())

    assert page.status_code == 200
    # H005 quotes the certificate's, and the letter says so in words.
    assert "X.509 certificate" in page.text
    assert "certificate" in page.text and "public_key" not in page.text


def test_the_drawer_says_which_version_is_running(console):
    """On every page, because of when the question gets asked.

    "Which version is this?" comes up while somebody is writing a bug report or
    is on the phone to a bank -- neither of which is a moment to go and find a
    shell on the host. It is in the drawer rather than on one page for the same
    reason the custody banner is on every page: a fact that is only where
    somebody remembered to put it is a fact nobody finds.
    """
    from painfree import __version__

    client, _engine, _connection = console
    page = client.get("/ui/connections", headers=dev_credentials())

    assert "pf-drawer-footer" in page.text
    assert f"painfree {__version__}" in page.text


def test_the_commit_appears_beside_it_only_when_the_build_set_one(
        custody_settings):
    """Two deployments can run one version number and differ, which is exactly
    when the commit matters. `unknown` is the unbuilt default and would be
    noise on every page of every development run, so it is left out."""
    built = custody_settings.model_copy(
        update={"git_sha": "0123456789abcdef0123"})
    with TestClient(create_app(built)) as browser:
        page = browser.get("/ui/connections", headers=dev_credentials())
    assert "0123456789ab" in page.text
    # Twelve characters, not twenty: enough to name a commit, short enough to
    # sit on one line in a 264px column.
    assert "0123456789abcdef" not in page.text

    with TestClient(create_app(
            custody_settings.model_copy(update={"git_sha": "unknown"}))) as plain:
        page = plain.get("/ui/connections", headers=dev_credentials())
    assert "unknown" not in page.text


def test_the_avatar_takes_one_letter_per_name(console):
    """`Bastian Meyer` is `BM`.

    It was `BA`: the template sliced the first two characters, which is right
    for a single word and wrong for everyone with a surname.
    """
    from painfree.ui.rendering import _initials

    assert _initials("Bastian Meyer") == "BM"
    assert _initials("Anna Maria Müller") == "AM", "a middle name is not the surname"
    assert _initials("Bastian") == "BA", "one word has no second name to take"
    # An OIDC subject with no display name is whatever the provider issued.
    assert _initials("2db0ebe3-cb34-4c1e") == "2D"
    for empty in ("", "   ", None):
        assert _initials(empty) == "?"

