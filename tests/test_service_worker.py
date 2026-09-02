"""The upload worker, driven against a stub bank over a real socket.

Nothing here mocks the transport. Every test starts an HTTP server, points the
connection's ``HostURL`` at it and lets the worker run the whole path: open the
sealed keys, sign the ``pain.001``, encrypt it, announce it, push the segment,
read the answer, write the outcome. What varies between the tests is what the
bank says back, because that is what the worker's decisions are made of.

The four claims this file is here to settle:

* a payment submitted through the API reaches a terminal state through the
  worker, and the bank sees a schema-valid `BTU`;
* a bank refusal is stored with its return code and its report text, and the
  order stops rather than retrying for ever;
* an interrupted upload is retried without a second `MsgId` reaching the bank;
* two workers racing for one order produce exactly one upload.
"""

from __future__ import annotations

import concurrent.futures as futures
import json
import threading

import pytest
from lxml import etree
from sqlalchemy import select

from conftest import (PRODUCTION_OIDC, BANK_CONNECTION_ID, BANK_ORDER_ID, bank_response,
                      hang_up, msg_ids_in, payment_body, serving_bank,
                      upload_script)
from painfree import db, ebics3, payments
from painfree.config import ConfigurationError, load_settings
from painfree.logging import configure_logging
from painfree.orders import OrderState, OrderStore
from painfree.queue import MAX_ATTEMPTS, OrderQueue
from painfree.schema import audit_log, payment_order
from painfree.worker import UploadWorker, build_worker, service_for

KEY = "worker-idem-0001"


# --- helpers ---------------------------------------------------------------

def submit(engine, *, idempotency_key: str = KEY) -> str:
    """Accept a payment the way the API does, and return its order id."""
    instruction = payments.PaymentInstruction(**payment_body())
    submission = OrderStore(engine).submit(
        BANK_CONNECTION_ID, idempotency_key=idempotency_key,
        instruction=instruction)
    return submission.order.order_id


def worker(engine, custody_settings, url: str, **kwargs) -> UploadWorker:
    """A worker whose connection points at the stub bank on ``url``."""
    _point_at(engine, url)
    return UploadWorker(engine, custody_settings.custody_key(),
                        timeout=5.0, **kwargs)


def _point_at(engine, url: str) -> None:
    from painfree.schema import bank_connection

    with engine.begin() as connection:
        connection.execute(
            bank_connection.update()
            .where(bank_connection.c.connection_id == BANK_CONNECTION_ID)
            .values(host_url=url))


def order_row(engine, order_id: str):
    with engine.connect() as connection:
        return connection.execute(
            select(payment_order).where(
                payment_order.c.order_id == order_id)).mappings().one()


# --- the whole path --------------------------------------------------------

def test_a_submitted_payment_is_uploaded_and_reaches_a_terminal_state(
        prepared_bank, custody_settings):
    engine, _, bank = prepared_bank
    order_id = submit(engine)
    seen: list[bytes] = []

    with serving_bank(upload_script(bank.authentication, seen)) as url:
        result = worker(engine, custody_settings, url).run_once()

    assert result is not None
    assert result.state is OrderState.SUBMITTED
    assert result.bank_order_id == BANK_ORDER_ID
    # Announcement plus one segment: the smallest complete upload there is.
    assert result.exchanges == 2
    assert len(seen) == 2

    row = order_row(engine, order_id)
    assert row["state"] == OrderState.SUBMITTED.value
    assert row["bank_order_id"] == BANK_ORDER_ID
    assert row["return_code"] == ebics3.EBICS_OK
    assert row["transaction_id"] is not None
    # The claim is released in the same write that settles the order.
    assert row["worker_id"] is None and row["claimed_at"] is None


def test_the_bank_receives_a_signed_btu_carrying_the_stored_message(
        prepared_bank, custody_settings):
    """What went out is the document that was validated, not a rebuilt one."""
    engine, _, bank = prepared_bank
    order_id = submit(engine)
    seen: list[bytes] = []

    with serving_bank(upload_script(bank.authentication, seen)) as url:
        worker(engine, custody_settings, url).run_once()

    announcement = etree.fromstring(seen[0])
    assert announcement.xpath(
        "//*[local-name()='AdminOrderType']")[0].text == "BTU"
    # The file name carries the `MsgId`, which is what a retry must not change.
    stored = order_row(engine, order_id)
    assert msg_ids_in(seen) == {f"{stored['msg_id']}.xml"}
    # And the announcement is signed with *our* X002 key, not left blank.
    subscriber = ebics3.EbicsKey.from_public_pem(
        ebics3.KeyVersion.X002,
        _public_pem(engine, ebics3.KeyVersion.X002))
    assert ebics3.verify_auth_signature(
        announcement, subscriber.public_key, "X002").ok


def _public_pem(engine, version: ebics3.KeyVersion) -> bytes:
    from painfree.schema import key_material

    with engine.connect() as connection:
        return connection.execute(
            select(key_material.c.public_pem).where(
                key_material.c.connection_id == BANK_CONNECTION_ID,
                key_material.c.holder == "subscriber",
                key_material.c.version == version.value)).scalar_one()


def test_every_exchange_is_logged_with_its_phase_and_return_code(
        prepared_bank, custody_settings, capsys):
    engine, _, bank = prepared_bank
    order_id = submit(engine)
    configure_logging("INFO")
    seen: list[bytes] = []

    with serving_bank(upload_script(bank.authentication, seen)) as url:
        worker(engine, custody_settings, url).run_once()

    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()
             if line.startswith("{")]
    exchanges = [line for line in lines if line["event"] == "ebics.exchange"]
    assert len(exchanges) == 2
    for line in exchanges:
        # Order type, phase, segment number, return code, report text -- and
        # the id that joins them to everything else.
        assert line["order_type"] == "BTU"
        assert line["order_id"] == order_id
        assert line["header_return_code"] == ebics3.EBICS_OK
        assert line["report_text"] == "[EBICS_OK] OK"
    assert [line["phase"] for line in exchanges] == ["Initialisation", "Transfer"]
    assert exchanges[1]["segment_number"] == 1
    # And nothing logged the payment itself.
    assert "MUSTER AG" not in capsys.readouterr().out


# --- refusal ---------------------------------------------------------------

def test_a_refusal_is_stored_with_its_return_code_and_report_text(
        prepared_bank, custody_settings):
    """`091112` is terminal: the order is rejected, not retried."""
    engine, _, bank = prepared_bank
    order_id = submit(engine)
    report = "[EBICS_INVALID_ORDER_PARAMS] the BTF is not in this bank's catalogue"

    def script(body: bytes) -> bytes:
        return bank_response("Initialisation", signing_key=bank.authentication,
                             return_code="091112", report_text=report)

    with serving_bank(script) as url:
        result = worker(engine, custody_settings, url).run_once()

    assert result.state is OrderState.REJECTED
    row = order_row(engine, order_id)
    assert row["state"] == OrderState.REJECTED.value
    assert row["return_code"] == "091112"
    assert row["report_text"] == report
    # Terminal means terminal: nothing claims it again.
    assert row["next_attempt_at"] is None
    assert OrderQueue(engine).claim(worker_id="w2") is None


def test_the_refused_request_is_kept_and_checked_against_the_schemas(
        prepared_bank, custody_settings):
    """The document the bank refused, so a return code stops being the whole
    diagnosis.

    `091113 EBICS_INVALID_REQUEST_CONTENT` names no element. Without the
    request, an operator holding one has no next step inside the product and
    the only party who can still see it is the bank -- which is how diagnosing
    the real one took source reading and a telephone call.
    """
    engine, _, bank = prepared_bank
    order_id = submit(engine)
    report = "[EBICS_INVALID_REQUEST_CONTENT] Nachrichteninhalt semantisch nicht EBICS-konform"

    def script(body: bytes) -> bytes:
        return bank_response("Initialisation", signing_key=bank.authentication,
                             return_code="091113", report_text=report)

    with serving_bank(script) as url:
        result = worker(engine, custody_settings, url).run_once()

    assert result.state is OrderState.REJECTED
    row = order_row(engine, order_id)
    kept = row["refused_request"]
    assert kept is not None, "the refused request was not kept"
    # Verbatim: the bytes that went to the bank, not a rendering of them.
    assert kept.startswith(b"<?xml")
    assert b"ebicsRequest" in kept
    # And checked, so the first question is answered without asking anybody.
    # This one is well-formed EBICS, which is a finding rather than an
    # exoneration -- it says the disagreement is semantic.
    assert row["refused_request_errors"] == []


def test_the_kept_request_carries_no_payment_file(prepared_bank,
                                                  custody_settings):
    """Why keeping it is safe. An upload's initialisation carries the
    electronic signature and a transaction key wrapped to the *bank's* public
    half; the `pain.001` goes in the transfer phase, which a refusal at
    initialisation never reaches."""
    engine, _, bank = prepared_bank
    submit(engine)

    def script(body: bytes) -> bytes:
        return bank_response("Initialisation", signing_key=bank.authentication,
                             return_code="091113", report_text="no")

    with serving_bank(script) as url:
        worker(engine, custody_settings, url).run_once()

    kept = order_row(engine, list(_order_ids(engine))[0])["refused_request"]
    assert b"CstmrCdtTrfInitn" not in kept
    assert b"IBAN" not in kept


def _order_ids(engine):
    from sqlalchemy import select

    from painfree.schema import payment_order
    with engine.connect() as connection:
        for row in connection.execute(select(payment_order.c.order_id)):
            yield row[0]


def test_a_refusal_is_recorded_in_the_audit_trail_with_the_bank_s_words(

        prepared_bank, custody_settings):
    engine, _, bank = prepared_bank
    order_id = submit(engine)

    def script(body: bytes) -> bytes:
        return bank_response("Initialisation", signing_key=bank.authentication,
                             return_code="091302",
                             report_text="[EBICS_ACCOUNT_AUTHORISATION_FAILED]")

    with serving_bank(script) as url:
        worker(engine, custody_settings, url).run_once()

    with engine.connect() as connection:
        rows = connection.execute(
            select(audit_log).where(
                audit_log.c.action == "payment.rejected",
                audit_log.c.order_id == order_id)).mappings().all()
    assert len(rows) == 1
    assert rows[0]["outcome"] == "failure"
    assert rows[0]["detail"]["return_code"] == "091302"
    assert rows[0]["detail"]["return_code_name"] == "EBICS_ACCOUNT_AUTHORISATION_FAILED"


def test_a_retryable_return_code_goes_back_to_the_queue_and_then_gives_up(
        prepared_bank, custody_settings):
    """`061099` is transient; the order comes back until the ceiling."""
    engine, _, bank = prepared_bank
    order_id = submit(engine)

    def script(body: bytes) -> bytes:
        return bank_response("Initialisation", signing_key=bank.authentication,
                             return_code="061099",
                             report_text="[EBICS_INTERNAL_ERROR]")

    states = []
    with serving_bank(script) as url:
        runner = worker(engine, custody_settings, url)
        for _ in range(MAX_ATTEMPTS):
            # The backoff is cleared between attempts rather than waited out:
            # what is under test is the ceiling, not the clock.
            _clear_backoff(engine)
            states.append(runner.run_once().state)

    assert states[:-1] == [OrderState.ACCEPTED] * (MAX_ATTEMPTS - 1)
    assert states[-1] is OrderState.FAILED
    row = order_row(engine, order_id)
    # `failed` is this service giving up; the bank's own words survive it.
    assert row["state"] == OrderState.FAILED.value
    assert row["return_code"] == "061099"
    assert row["attempts"] == MAX_ATTEMPTS


def _clear_backoff(engine) -> None:
    with engine.begin() as connection:
        connection.execute(payment_order.update().values(next_attempt_at=None))


# --- retry and idempotency -------------------------------------------------

def test_a_retry_after_an_interrupted_upload_sends_one_message_not_two(
        prepared_bank, custody_settings):
    """The bank drops the connection mid-transfer; the retry reuses the MsgId.

    This is the failure that costs money if it is got wrong. The first attempt
    announces the upload, the bank opens a transaction and then hangs up before
    the segment is acknowledged; the order goes back to the queue and is
    claimed again. What must not happen is a second `pain.001` -- a new
    `MsgId`, a new message -- for the same order, because the bank's duplicate
    detection is keyed on exactly that.
    """
    engine, _, bank = prepared_bank
    order_id = submit(engine)
    before = order_row(engine, order_id)["msg_id"]
    seen: list[bytes] = []
    interrupted = threading.Event()

    def script(body: bytes) -> bytes:
        seen.append(body)
        if _is_transfer(body) and not interrupted.is_set():
            interrupted.set()
            raise hang_up()
        if _is_transfer(body):
            return bank_response("Transfer", signing_key=bank.authentication,
                                 segment_number=1, last=True,
                                 order_id=BANK_ORDER_ID)
        return bank_response("Initialisation", signing_key=bank.authentication)

    with serving_bank(script) as url:
        runner = worker(engine, custody_settings, url)
        first = runner.run_once()
        _clear_backoff(engine)
        second = runner.run_once()

    assert interrupted.is_set()
    assert first.state is OrderState.ACCEPTED       # back in the queue
    assert second.state is OrderState.SUBMITTED     # and delivered on the retry

    row = order_row(engine, order_id)
    assert row["msg_id"] == before                  # the same message, always
    assert row["attempts"] == 2
    assert msg_ids_in(seen) == {f"{before}.xml"}    # one message on the wire

    # And exactly one order exists for the idempotency key, unchanged by any
    # of it -- a retry is a re-send, never a second payment.
    with engine.connect() as connection:
        assert connection.execute(
            select(payment_order.c.order_id)).scalars().all() == [order_id]


def _is_transfer(body: bytes) -> bool:
    root = etree.fromstring(body)
    phase = root.xpath("//*[local-name()='TransactionPhase']")
    return bool(phase) and phase[0].text == "Transfer"


def test_a_transport_failure_before_the_bank_answers_is_retried(
        prepared_bank, custody_settings):
    """A `HostURL` nothing is listening on: nothing was sent, so nothing is lost."""
    engine, _, _ = prepared_bank
    order_id = submit(engine)
    _point_at(engine, "http://127.0.0.1:1/ebics")

    runner = UploadWorker(engine, custody_settings.custody_key(), timeout=2.0)
    result = runner.run_once()

    assert result.state is OrderState.ACCEPTED
    row = order_row(engine, order_id)
    assert row["attempts"] == 1
    assert row["next_attempt_at"] is not None
    assert "could not be reached" in row["last_error"]
    # No transaction was ever opened, so the retry is an ordinary first try.
    assert row["transaction_id"] is None


def test_a_terminal_order_is_never_claimed_again(prepared_bank, custody_settings):
    engine, _, bank = prepared_bank
    submit(engine)
    seen: list[bytes] = []

    with serving_bank(upload_script(bank.authentication, seen)) as url:
        runner = worker(engine, custody_settings, url)
        assert runner.run_once().state is OrderState.SUBMITTED
        assert runner.run_once() is None

    assert len(seen) == 2


# --- concurrency -----------------------------------------------------------

def test_two_workers_racing_for_one_order_produce_exactly_one_upload(
        prepared_bank, custody_settings):
    """A double claim is a double payment. Two workers, one order, one BTU."""
    engine, _, bank = prepared_bank
    submit(engine)
    seen: list[bytes] = []
    lock = threading.Lock()

    def script(body: bytes) -> bytes:
        with lock:
            seen.append(body)
        return upload_script(bank.authentication, [])(body)

    ready = threading.Barrier(2)

    with serving_bank(script) as url:
        _point_at(engine, url)
        workers = [UploadWorker(engine, custody_settings.custody_key(),
                                worker_id=f"racer-{i}", timeout=5.0)
                   for i in range(2)]

        def race(runner):
            ready.wait(timeout=10)
            return runner.run_once()

        with futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = [f.result() for f in
                       [pool.submit(race, runner) for runner in workers]]

    uploaded = [r for r in results if r is not None]
    assert len(uploaded) == 1, f"both workers claimed the order: {results}"
    assert uploaded[0].state is OrderState.SUBMITTED
    # Two exchanges, not four: the bank saw one upload.
    assert len(seen) == 2


# --- the process boundary --------------------------------------------------

def test_an_api_process_refuses_to_start_holding_the_custody_secret(
        sqlite_url, custody_secret):
    """The API process cannot hold what it is not given."""
    with pytest.raises(ConfigurationError) as raised:
        load_settings(database_url=sqlite_url, role="api",
                      key_encryption_secret=custody_secret)
    assert "must not be able to open a private key" in str(raised.value)
    # And the secret itself is not in the message.
    assert custody_secret not in str(raised.value)


def test_a_worker_process_refuses_to_start_without_the_custody_secret(sqlite_url):
    with pytest.raises(ConfigurationError) as raised:
        load_settings(database_url=sqlite_url, role="worker")
    assert "cannot open a key cannot upload" in str(raised.value)


def test_production_refuses_to_run_both_halves_in_one_process(custody_secret):
    with pytest.raises(ConfigurationError) as raised:
        load_settings(environment="production", role="combined", **PRODUCTION_OIDC,
                      database_url="postgresql+psycopg://u@h/db",
                      key_encryption_secret=custody_secret)
    assert "separate processes" in str(raised.value)


def test_an_api_process_cannot_derive_a_custody_key_even_deliberately(
        prepared_bank, sqlite_url, monkeypatch):
    """The deliberate case the in-process boundary could not defend against.

    A handler reading ``os.environ`` and rebuilding the key by hand is the
    attack the in-process boundary explicitly did not stop. With the process
    split there is nothing in the environment to read, and the sealed material
    that is in the database does not open.
    """
    engine, _, _ = prepared_bank
    monkeypatch.delenv("PAINFREE_KEY_ENCRYPTION_SECRET", raising=False)
    api = load_settings(database_url=sqlite_url, role="api")

    assert api.key_encryption_secret is None
    with pytest.raises(ConfigurationError):
        api.custody_key()
    with pytest.raises(ValueError, match="does not upload"):
        build_worker(api, engine)

    # And the row it could reach is ciphertext, not a key.
    from painfree.schema import key_material

    with engine.connect() as connection:
        sealed = connection.execute(
            select(key_material.c.sealed_private).where(
                key_material.c.connection_id == BANK_CONNECTION_ID,
                key_material.c.holder == "subscriber",
                key_material.c.version == "X002")).scalar_one()
    assert sealed is not None
    assert b"PRIVATE KEY" not in sealed


def test_a_worker_cannot_be_built_inside_a_request(prepared_bank,
                                                   custody_settings):
    """The in-process mechanisms are still there, and still fail first."""
    from painfree import custody

    engine, _, _ = prepared_bank
    with custody.request_path():
        with pytest.raises(custody.CustodyViolation):
            UploadWorker(engine, custody_settings.custody_key())


# --- the BTF ---------------------------------------------------------------

def test_the_service_is_derived_from_the_message_type():
    service = service_for("pain.001.001.09")
    assert (service.msg_name, service.msg_version) == ("pain.001", "09")
    assert (service.name, service.scope) == ("MCT", "CH")


def test_a_message_type_that_is_not_iso_20022_is_refused():
    with pytest.raises(Exception, match="not an ISO 20022 message type"):
        service_for("camt")
