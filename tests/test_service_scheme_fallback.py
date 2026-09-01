"""The fallback from instant to normal, and every outcome that must not take it.

**This is the file that matters most here.** `instant_or_normal` sends a
payment twice if it is wrong, so the tests that matter here are the negative
ones: an outcome this service does not understand must leave the order exactly
where a `normal` order would be left, carrying the message it was already
carrying.

Nothing is mocked. Every test starts an HTTP server, points the connection's
`HostURL` at it and lets the worker run the whole path. What varies is what the
bank does:

* it refuses the instant BTF and takes the normal one -- the fallback, driven
  end to end, ending in **one** payment at the bank;
* it never answers at all, until the client gives up -- a timeout;
* it answers with half a document -- a response that will not parse;
* it drops the connection with the request already sent;
* it refuses definitively with a code that is **not** on the connection's
  whitelist;
* it refuses *after* opening a transaction, so it may have the file.

Only the first is a fallback. The other five are ordinary retries or an
ordinary rejection, and the order still carries the instant message.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
import time

from lxml import etree
from sqlalchemy import select

from conftest import (BANK_CONNECTION_ID, BANK_ORDER_ID, bank_response, btf_in,
                      hang_up, msg_ids_in, payment_body, payment_type_in,
                      serving_bank)
from painfree import payments, queue as queue_module, worker as worker_module
from painfree.attempts import LIVE, PLANNED, SUPERSEDED, AttemptStore
from painfree.connections import ConnectionRegistry
from painfree.orders import OrderState, OrderStore
from painfree.queue import OrderQueue
from painfree.schema import audit_log, bank_connection, payment_order
from painfree.schemes import (Code, PaymentScheme, SchemeProfile,
                              SchemeProfiles)
from painfree.worker import UploadWorker

KEY = "fallback-idem-0001"

#: What the bank answers when the BTF is not in its catalogue, which is what an
#: instant upload to a bank that cannot do instant looks like.
REFUSED = "091112"
REPORT = "[EBICS_INVALID_ORDER_PARAMS] MCT/INST is not in this bank's catalogue"

PROFILES = SchemeProfiles(
    default=PaymentScheme.NORMAL,
    instant=SchemeProfile(service_name="MCT", service_option="INST",
                          scope="CH", service_level=Code("SEPA"),
                          local_instrument=Code("INST")),
)


# --- helpers ---------------------------------------------------------------

def prepare(engine, profiles: SchemeProfiles = PROFILES) -> None:
    registry = ConnectionRegistry(engine)
    registry.update(BANK_CONNECTION_ID,
                    host_url=registry.get(BANK_CONNECTION_ID).host_url,
                    schemes=profiles)


def submit(engine, *, scheme: str = "instant_or_normal",
           idempotency_key: str = KEY, **overrides) -> str:
    instruction = payments.PaymentInstruction(
        **payment_body(scheme=scheme, **overrides))
    return OrderStore(engine).submit(
        BANK_CONNECTION_ID, idempotency_key=idempotency_key,
        instruction=instruction).order.order_id


def worker(engine, custody_settings, url: str, **kwargs) -> UploadWorker:
    with engine.begin() as connection:
        connection.execute(
            bank_connection.update()
            .where(bank_connection.c.connection_id == BANK_CONNECTION_ID)
            .values(host_url=url))
    kwargs.setdefault("timeout", 5.0)
    return UploadWorker(engine, custody_settings.custody_key(), **kwargs)


def order_row(engine, order_id: str):
    with engine.connect() as connection:
        return connection.execute(
            select(payment_order).where(
                payment_order.c.order_id == order_id)).mappings().one()


def attempts(engine, order_id):
    return AttemptStore(engine).all(order_id)


def downgrades(engine, order_id) -> list[dict]:
    with engine.connect() as connection:
        return [row["detail"] for row in connection.execute(
            select(audit_log).where(
                audit_log.c.action == "payment.scheme_downgraded",
                audit_log.c.order_id == order_id)).mappings().all()]


def _file_name(body: bytes) -> str | None:
    root = etree.fromstring(body)
    found = root.xpath("//*[local-name()='BTUOrderParams']")
    return found[0].get("fileName") if found else None


class Bank:
    """A stub bank that answers per BTF, and remembers what it actually took.

    ``taken`` is the point of it: an upload the bank *acknowledged and
    received*, as opposed to one it was merely shown. The whole question this
    file asks is how many entries end up in that list.
    """

    def __init__(self, signing_key, *, refuse_option: str | None = "INST",
                 code: str = REFUSED, report: str = REPORT,
                 refuse_after_opening: bool = False):
        self.signing_key = signing_key
        self.refuse_option = refuse_option
        self.code = code
        self.report = report
        self.refuse_after_opening = refuse_after_opening
        self.seen: list[bytes] = []
        self.announced: list[tuple[str | None, tuple]] = []
        self.refused: list[str | None] = []
        self.taken: list[str | None] = []
        self._open: str | None = None

    def __call__(self, body: bytes) -> bytes:
        self.seen.append(body)
        triplet = btf_in(body)
        if triplet is None:
            # A transfer segment: the file the bank opened is now received.
            if self.refuse_after_opening:
                return bank_response(
                    "Transfer", signing_key=self.signing_key, segment_number=1,
                    return_code=self.code, report_text=self.report)
            self.taken.append(self._open)
            return bank_response("Transfer", signing_key=self.signing_key,
                                 segment_number=1, last=True,
                                 order_id=BANK_ORDER_ID)
        name = _file_name(body)
        self.announced.append((name, triplet))
        if self.refuse_option is not None and triplet[1] == self.refuse_option:
            # Refused at the announcement, so the bank assigns no
            # `TransactionID` and has nothing.
            self.refused.append(name)
            return bank_response("Initialisation", signing_key=self.signing_key,
                                 transaction_id=None, return_code=self.code,
                                 report_text=self.report)
        self._open = name
        return bank_response("Initialisation", signing_key=self.signing_key)


# --- the fallback, taken ---------------------------------------------------

def test_the_fallback_is_taken_on_a_definitive_refusal_and_pays_once(
        prepared_bank, custody_settings):
    """The whole path: instant refused, normal sent, one payment at the bank."""
    engine, _, keys = prepared_bank
    prepare(engine)
    order_id = submit(engine)
    bank = Bank(keys.authentication)

    with serving_bank(bank) as url:
        runner = worker(engine, custody_settings, url)
        first = runner.run_once()
        second = runner.run_once()

    assert first.state is OrderState.ACCEPTED     # back on the queue, downgraded
    assert second.state is OrderState.SUBMITTED

    row = order_row(engine, order_id)
    assert row["state"] == OrderState.SUBMITTED.value
    assert row["scheme"] == "normal"
    assert row["requested_scheme"] == "instant_or_normal"
    assert row["scheme_reason"] == f"bank_refused_instant:{REFUSED}"

    # The bank was shown two different messages and took exactly one.
    assert [option for _name, (_svc, option, _scope) in bank.announced] == [
        "INST", None]
    assert len(bank.refused) == 1
    assert len(bank.taken) == 1
    assert bank.taken[0] != bank.refused[0]
    assert len(msg_ids_in(bank.seen)) == 2

    # And the one it took is the one the order now carries.
    assert bank.taken[0] == f"{row['msg_id']}.xml"


def test_one_idempotency_key_is_one_order_with_two_attempts(
        prepared_bank, custody_settings):
    """A fallback is a second *attempt*, never a second order."""
    engine, _, keys = prepared_bank
    prepare(engine)
    order_id = submit(engine)
    bank = Bank(keys.authentication)

    with serving_bank(bank) as url:
        runner = worker(engine, custody_settings, url)
        runner.run_once()
        runner.run_once()

    with engine.connect() as connection:
        assert connection.execute(
            select(payment_order.c.order_id)).scalars().all() == [order_id]

    first, second = attempts(engine, order_id)
    assert (first.scheme.value, first.state) == ("instant", SUPERSEDED)
    assert (second.scheme.value, second.state) == ("normal", LIVE)
    # What the bank said to the attempt that provoked it, kept on that attempt.
    assert first.return_code == REFUSED
    assert first.report_text == REPORT
    assert second.return_code == "000000"
    assert order_row(engine, order_id)["state"] == OrderState.SUBMITTED.value


def test_the_btf_and_the_document_agree_on_both_attempts(
        prepared_bank, custody_settings):
    """The announcement and the message, read off the wire and out of the row."""
    engine, _, keys = prepared_bank
    prepare(engine)
    order_id = submit(engine)
    bank = Bank(keys.authentication)

    with serving_bank(bank) as url:
        runner = worker(engine, custody_settings, url)
        runner.run_once()
        runner.run_once()

    by_name = {name: triplet for name, triplet in bank.announced}
    for attempt in attempts(engine, order_id):
        announced = by_name[f"{attempt.msg_id}.xml"]
        assert announced == (attempt.btf_service_name,
                             attempt.btf_service_option, attempt.btf_scope)
        carried = payment_type_in(attempt.document)
        if attempt.scheme is PaymentScheme.INSTANT:
            assert announced == ("MCT", "INST", "CH")
            assert carried == ["PmtInf: SvcLvl/Cd=SEPA LclInstrm/Cd=INST"]
        else:
            assert announced == ("MCT", None, "CH")
            assert carried == []


def test_the_downgrade_is_an_audit_row_naming_both_messages(
        prepared_bank, custody_settings):
    engine, _, keys = prepared_bank
    prepare(engine)
    order_id = submit(engine)
    bank = Bank(keys.authentication)
    with serving_bank(bank) as url:
        worker(engine, custody_settings, url).run_once()

    detail, = downgrades(engine, order_id)
    first, second = attempts(engine, order_id)
    assert detail["previous_scheme"] == "instant"
    assert detail["scheme"] == "normal"
    assert detail["requested_scheme"] == "instant_or_normal"
    assert detail["return_code"] == REFUSED
    assert detail["report_text"] == REPORT
    assert detail["superseded_msg_id"] == first.msg_id
    assert detail["msg_id"] == second.msg_id
    assert detail["btf"] == "MCT/CH"


# --- the fallback, NOT taken. the important half ---------------------------

def unchanged(engine, order_id) -> None:
    """The order is still the instant one, with its reserve still in reserve.

    Asserted after every ambiguous outcome, and it is the whole point: nothing
    was resent, nothing was promoted, and the message the order carries is the
    message it carried before.
    """
    row = order_row(engine, order_id)
    first, second = attempts(engine, order_id)
    assert row["scheme"] == "instant"
    assert row["scheme_reason"] == "requested"
    assert row["msg_id"] == first.msg_id
    assert (first.scheme.value, first.state) == ("instant", LIVE)
    assert (second.scheme.value, second.state) == ("normal", PLANNED)
    assert downgrades(engine, order_id) == []


def test_a_timeout_is_not_a_refusal(prepared_bank, custody_settings):
    """The bank never answers. It may have the file, so nothing is resent.

    This is the case that costs money if it is got wrong: a client that treats
    silence as *instant was refused* sends the normal message too, and the bank
    that was merely slow now has both.
    """
    engine, _, keys = prepared_bank
    prepare(engine)
    order_id = submit(engine)
    seen: list[bytes] = []

    def script(body: bytes) -> bytes:
        seen.append(body)
        time.sleep(2.0)
        return bank_response("Initialisation", signing_key=keys.authentication)

    with serving_bank(script) as url:
        result = worker(engine, custody_settings, url,
                        timeout=0.25).run_once()

    assert result.state is OrderState.ACCEPTED   # retried, not downgraded
    unchanged(engine, order_id)
    # One message was shown to the bank, and it is the instant one.
    assert msg_ids_in(seen) == {f"{order_row(engine, order_id)['msg_id']}.xml"}


def test_a_truncated_response_is_not_a_refusal(prepared_bank, custody_settings):
    """Half a document parses as nothing, and nothing is not a refusal."""
    engine, _, keys = prepared_bank
    prepare(engine)
    order_id = submit(engine)
    whole = bank_response("Initialisation", signing_key=keys.authentication)

    def script(body: bytes) -> bytes:
        return whole[:len(whole) // 2]

    with serving_bank(script) as url:
        result = worker(engine, custody_settings, url).run_once()

    assert result.state is OrderState.ACCEPTED
    unchanged(engine, order_id)


def test_a_response_that_is_not_ebics_at_all_is_not_a_refusal(
        prepared_bank, custody_settings):
    """A misconfigured `HostURL` answering with a login page, say."""
    engine, _, _ = prepared_bank
    prepare(engine)
    order_id = submit(engine)

    with serving_bank(lambda body: b"<html><body>Sign in</body></html>") as url:
        result = worker(engine, custody_settings, url).run_once()

    assert result.state is OrderState.ACCEPTED
    unchanged(engine, order_id)


def test_a_dropped_connection_is_not_a_refusal(prepared_bank, custody_settings):
    """The request went out and the answer never came back."""
    engine, _, _ = prepared_bank
    prepare(engine)
    order_id = submit(engine)

    def script(body: bytes) -> bytes:
        raise hang_up()

    with serving_bank(script) as url:
        result = worker(engine, custody_settings, url).run_once()

    assert result.state is OrderState.ACCEPTED
    unchanged(engine, order_id)


def test_a_bank_that_is_unreachable_is_not_a_refusal(prepared_bank,
                                                     custody_settings):
    """Nothing was sent at all, which is still not the bank refusing instant."""
    engine, _, _ = prepared_bank
    prepare(engine)
    order_id = submit(engine)
    result = worker(engine, custody_settings, "http://127.0.0.1:1/ebics",
                    timeout=0.5).run_once()
    assert result.state is OrderState.ACCEPTED
    unchanged(engine, order_id)


def test_a_retryable_refusal_is_not_a_definitive_one(prepared_bank,
                                                     custody_settings):
    """`061099` is the bank being unwell, not the bank saying no to instant."""
    engine, _, keys = prepared_bank
    prepare(engine)
    order_id = submit(engine)
    bank = Bank(keys.authentication, code="061099",
                report="[EBICS_INTERNAL_ERROR]")

    with serving_bank(bank) as url:
        result = worker(engine, custody_settings, url).run_once()

    assert result.state is OrderState.ACCEPTED
    unchanged(engine, order_id)
    assert bank.taken == []


def test_a_definitive_refusal_that_is_not_on_the_whitelist_ends_the_order(
        prepared_bank, custody_settings):
    """Fail closed: an unrecognised refusal rejects rather than resends."""
    engine, _, keys = prepared_bank
    prepare(engine)
    order_id = submit(engine)
    bank = Bank(keys.authentication, code="091302",
                report="[EBICS_ACCOUNT_AUTHORISATION_FAILED]")

    with serving_bank(bank) as url:
        result = worker(engine, custody_settings, url).run_once()

    assert result.state is OrderState.REJECTED
    row = order_row(engine, order_id)
    assert row["scheme"] == "instant"
    assert row["return_code"] == "091302"
    assert downgrades(engine, order_id) == []
    assert bank.taken == []
    first, second = attempts(engine, order_id)
    assert (first.state, second.state) == (LIVE, PLANNED)


def test_a_refusal_after_the_bank_opened_a_transaction_is_never_a_fallback(
        prepared_bank, custody_settings):
    """`Never fall back after the bank has acknowledged receipt.`

    The bank takes the announcement, assigns a `TransactionID`, and only then
    refuses. It may have the file, so the reserve stays in reserve however
    whitelisted the code is.
    """
    engine, _, keys = prepared_bank
    prepare(engine)
    order_id = submit(engine)
    # Not the instant BTF: the refusal has to arrive *after* the transaction is
    # open, which means the announcement had to be accepted.
    bank = Bank(keys.authentication, refuse_option=None,
                refuse_after_opening=True)

    with serving_bank(bank) as url:
        result = worker(engine, custody_settings, url).run_once()

    assert result.state is OrderState.REJECTED
    row = order_row(engine, order_id)
    assert row["transaction_id"] is not None    # the bank had opened one
    assert row["scheme"] == "instant"
    assert downgrades(engine, order_id) == []


# --- the conditions, one at a time -----------------------------------------

def claim(engine) -> tuple[OrderQueue, object]:
    queue = OrderQueue(engine)
    return queue, queue.claim(worker_id="tester")


def test_the_promotion_refuses_a_code_outside_the_whitelist(prepared_bank):
    engine, _, _ = prepared_bank
    prepare(engine)
    submit(engine)
    queue, claimed = claim(engine)
    assert queue.fall_back(claimed, profiles=PROFILES, return_code="091302",
                           report_text="nope") is None


def test_the_promotion_refuses_an_outcome_with_no_return_code(prepared_bank):
    """A transport failure has none, and `None` is not a member of any set."""
    engine, _, _ = prepared_bank
    prepare(engine)
    submit(engine)
    queue, claimed = claim(engine)
    assert queue.fall_back(claimed, profiles=PROFILES, return_code=None,
                           report_text=None) is None


def test_the_promotion_refuses_an_order_with_no_reserve(prepared_bank):
    """`instant` alone fails if it cannot be done. There is nothing to promote."""
    engine, _, _ = prepared_bank
    prepare(engine)
    submit(engine, scheme="instant")
    queue, claimed = claim(engine)
    assert queue.fall_back(claimed, profiles=PROFILES, return_code=REFUSED,
                           report_text=REPORT) is None


def test_the_promotion_refuses_an_order_that_is_already_normal(prepared_bank):
    engine, _, _ = prepared_bank
    prepare(engine)
    submit(engine, scheme="normal")
    queue, claimed = claim(engine)
    assert queue.fall_back(claimed, profiles=PROFILES, return_code=REFUSED,
                           report_text=REPORT) is None


def test_the_promotion_refuses_when_the_claim_moved_to_another_worker(
        prepared_bank):
    """The guard is a `WHERE` clause, so a stale claim cannot promote."""
    engine, _, _ = prepared_bank
    prepare(engine)
    order_id = submit(engine)
    queue, claimed = claim(engine)
    with engine.begin() as connection:
        connection.execute(payment_order.update()
                           .where(payment_order.c.order_id == order_id)
                           .values(worker_id="somebody-else"))
    assert queue.fall_back(claimed, profiles=PROFILES, return_code=REFUSED,
                           report_text=REPORT) is None


def test_the_promotion_refuses_once_a_transaction_id_exists(prepared_bank):
    """The claimed row says `None`; the database says otherwise, and it wins."""
    engine, _, _ = prepared_bank
    prepare(engine)
    order_id = submit(engine)
    queue, claimed = claim(engine)
    assert claimed.order.transaction_id is None
    queue.opened(order_id, transaction_id="A1B2C3D4E5F60718293A4B5C6D7E8F90")
    assert queue.fall_back(claimed, profiles=PROFILES, return_code=REFUSED,
                           report_text=REPORT) is None


def test_the_promotion_refuses_once_the_bank_assigned_an_order_id(prepared_bank):
    engine, _, _ = prepared_bank
    prepare(engine)
    order_id = submit(engine)
    queue, claimed = claim(engine)
    queue.opened(order_id, transaction_id=None, bank_order_id=BANK_ORDER_ID)
    assert queue.fall_back(claimed, profiles=PROFILES, return_code=REFUSED,
                           report_text=REPORT) is None


def test_the_promotion_happens_at_most_once_for_one_refusal(prepared_bank):
    """A second call finds no reserve and no instant order, and does nothing."""
    engine, _, _ = prepared_bank
    prepare(engine)
    order_id = submit(engine)
    queue, claimed = claim(engine)
    assert queue.fall_back(claimed, profiles=PROFILES, return_code=REFUSED,
                           report_text=REPORT) is not None
    assert queue.fall_back(claimed, profiles=PROFILES, return_code=REFUSED,
                           report_text=REPORT) is None
    assert [row.state for row in attempts(engine, order_id)] == [SUPERSEDED,
                                                                 LIVE]


# --- the one call site -----------------------------------------------------

def test_the_fallback_is_reachable_from_exactly_one_place_in_the_worker():
    """And that place is inside the handler for a parsed, definitive refusal.

    Read off the source rather than asserted in prose, because the separation
    between *the bank said no* and *we do not know* is the whole safety
    argument, and a future call added from the transport handler would be a
    silent second payment.
    """
    tree = ast.parse(pathlib.Path(worker_module.__file__).read_text())
    calls = [node for node in ast.walk(tree)
             if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute)
             and node.func.attr == "fall_back"]
    assert len(calls) == 1, "fall_back is called more than once in the worker"

    # The one call is inside `_fell_back`, and `_fell_back` is used from
    # exactly one branch: the one handling `ebics3.BankRefusedError`.
    handlers = [node for node in ast.walk(tree) if isinstance(node, ast.Try)
                for node in node.handlers]
    reached = [handler for handler in handlers
               if any(isinstance(inner, ast.Call)
                      and isinstance(inner.func, ast.Attribute)
                      and inner.func.attr == "_fell_back"
                      for inner in ast.walk(handler))]
    assert len(reached) == 1
    assert ast.unparse(reached[0].type).endswith("BankRefusedError")


def test_retry_later_cannot_promote_anything():
    """The path every unknown outcome takes has no route to the reserve."""
    source = inspect.getsource(queue_module.OrderQueue.retry_later)
    assert "planned" not in source.lower()
    assert "fall_back" not in source


# --- what a caller and an operator see -------------------------------------

def test_the_order_response_carries_the_scheme_and_both_attempts(
        prepared_bank, custody_settings):
    engine, _, keys = prepared_bank
    prepare(engine)
    order_id = submit(engine)
    bank = Bank(keys.authentication)
    with serving_bank(bank) as url:
        runner = worker(engine, custody_settings, url)
        runner.run_once()
        runner.run_once()

    store = OrderStore(engine)
    body = store.get(order_id).as_response()
    assert body["scheme"]["requested"] == "instant_or_normal"
    assert body["scheme"]["effective"] == "normal"
    assert body["scheme"]["downgraded"] is True
    assert body["scheme"]["reason"] == f"bank_refused_instant:{REFUSED}"

    listed = [attempt.as_response() for attempt in store.attempts_for(order_id)]
    assert [(row["attempt"], row["scheme"], row["state"], row["btf"])
            for row in listed] == [
        (1, "instant", SUPERSEDED, "MCT/INST/CH"),
        (2, "normal", LIVE, "MCT/CH")]
    assert listed[0]["payment_type_information"] == \
        "SvcLvl/Cd=SEPA LclInstrm/Cd=INST"
    assert "payment_type_information" not in listed[1]
    assert listed[0]["return_code"] == REFUSED


def test_a_replay_of_a_rejected_instant_order_can_still_fall_back(
        prepared_bank, custody_settings):
    """The reserve outlives a rejection, and the same rules govern the retry."""
    engine, _, keys = prepared_bank
    prepare(engine)
    order_id = submit(engine)
    store = OrderStore(engine)

    with serving_bank(Bank(keys.authentication, code="091302",
                           report="[EBICS_ACCOUNT_AUTHORISATION_FAILED]")) as url:
        worker(engine, custody_settings, url).run_once()
    assert store.get(order_id).state is OrderState.REJECTED

    store.replay(order_id)
    bank = Bank(keys.authentication)
    with serving_bank(bank) as url:
        runner = worker(engine, custody_settings, url)
        runner.run_once()
        runner.run_once()

    assert store.get(order_id).state is OrderState.SUBMITTED
    assert store.get(order_id).scheme is PaymentScheme.NORMAL
    assert len(bank.taken) == 1


# --- what a consumer and an operator are told ------------------------------

def test_the_webhook_envelope_carries_the_scheme_and_the_downgrade(
        prepared_bank, custody_settings):
    """A consumer learns its instant payment went normal on an event it
    already subscribes to, rather than by subscribing to a new type.

    `data` is the audit row's detail, so the scheme fields ride on
    `order.accepted`, `order.submitted` and `order.rejected` alike.
    """
    from painfree import wrapping
    from painfree.schema import webhook_delivery
    from painfree.webhooks import WebhookSubscriptions

    engine, _, keys = prepared_bank
    prepare(engine)
    wrapping.publish(engine, custody_settings.custody_key())
    WebhookSubscriptions(engine, custody_settings.custody_key()).register(
        "https://consumer.example.test/hook",
        ["order.accepted", "order.submitted"],
        connection_id=BANK_CONNECTION_ID)

    order_id = submit(engine)
    with serving_bank(Bank(keys.authentication)) as url:
        runner = worker(engine, custody_settings, url)
        runner.run_once()
        runner.run_once()

    with engine.connect() as connection:
        payloads = {row["event_type"]: row["payload"] for row in
                    connection.execute(
                        select(webhook_delivery)
                        .where(webhook_delivery.c.order_id == order_id)
                        .order_by(webhook_delivery.c.seq)).mappings()}

    accepted = payloads["order.accepted"]["data"]
    assert accepted["scheme"] == "instant"
    assert accepted["requested_scheme"] == "instant_or_normal"
    assert accepted["scheme_downgraded"] is False

    submitted = payloads["order.submitted"]["data"]
    assert submitted["scheme"] == "normal"
    assert submitted["requested_scheme"] == "instant_or_normal"
    assert submitted["scheme_downgraded"] is True
    assert submitted["scheme_reason"] == f"bank_refused_instant:{REFUSED}"


def test_the_downgrade_is_not_a_subscribable_event_type():
    """It rides on the order events instead, so no consumer has to opt in."""
    from painfree.webhooks import EVENT_TYPES

    assert "payment.scheme_downgraded" not in EVENT_TYPES


def test_a_status_report_naming_the_superseded_message_still_finds_the_order(
        prepared_bank, custody_settings):
    """A `pain.002` about the refused message is still about this order."""
    from painfree.reconcile import StatusReconciler

    engine, _, keys = prepared_bank
    prepare(engine)
    order_id = submit(engine)
    with serving_bank(Bank(keys.authentication)) as url:
        runner = worker(engine, custody_settings, url)
        runner.run_once()
        runner.run_once()

    superseded, live = attempts(engine, order_id)
    reconciler = StatusReconciler(engine)
    for msg_id in (live.msg_id, superseded.msg_id):
        found = reconciler.order_for(
            BANK_CONNECTION_ID,
            {"original": {"message_identification": msg_id}})
        assert found == order_id, msg_id
    # And a `MsgId` this service never sent is still unmatched.
    assert reconciler.order_for(
        BANK_CONNECTION_ID,
        {"original": {"message_identification": "PF" + "F" * 32}}) is None


def test_the_console_shows_the_downgrade_and_both_messages(prepared_bank,
                                                           custody_settings):
    """An operator can see that a payment asked to go instantly went normal."""
    from fastapi.testclient import TestClient

    from conftest import dev_credentials, grant
    from painfree.app import create_app

    engine, _, keys = prepared_bank
    prepare(engine)
    order_id = submit(engine)
    with serving_bank(Bank(keys.authentication)) as url:
        runner = worker(engine, custody_settings, url)
        runner.run_once()
        runner.run_once()

    superseded, live = attempts(engine, order_id)
    app = create_app(custody_settings)
    headers = {**dev_credentials("olive", "member"),
               "accept": "text/html,application/xhtml+xml"}
    with TestClient(app) as client:
        grant(app, "olive", BANK_CONNECTION_ID, "operator")
        page = client.get(f"/ui/orders/{order_id}", headers=headers)
        listing = client.get("/ui/orders", headers=headers)
        connection_page = client.get(f"/ui/connections/{BANK_CONNECTION_ID}",
                                     headers=headers)

    assert page.status_code == 200
    body = page.text
    assert "instant_or_normal" in body and "downgraded" in body
    assert f"bank_refused_instant:{REFUSED}" in body
    # Both messages, each with the BTF it was announced under.
    assert superseded.msg_id in body and live.msg_id in body
    assert "MCT/INST/CH" in body and "MCT/CH" in body
    assert "SvcLvl/Cd=SEPA LclInstrm/Cd=INST" in body
    assert listing.status_code == 200 and "downgraded" in listing.text
    # And the connection page says what this bank is told about each scheme.
    assert connection_page.status_code == 200
    assert "MCT/INST/CH" in connection_page.text
    assert "091112" in connection_page.text


def test_the_console_edits_the_scheme_configuration(prepared_bank,
                                                    custody_settings):
    """The form is the way a deployment corrects its bank without a release."""
    from fastapi.testclient import TestClient

    from conftest import dev_credentials
    from painfree.app import create_app

    engine, _, _ = prepared_bank
    app = create_app(custody_settings)
    # `connections:write` is an administrator's, not an operator's: editing
    # what a bank is told about a payment is not a payment-running privilege.
    headers = {**dev_credentials("alice", "admin"),
               "accept": "text/html,application/xhtml+xml"}
    with TestClient(app) as client:
        assert client.get(f"/ui/connections/{BANK_CONNECTION_ID}/edit",
                          headers=headers).status_code == 200
        posted = client.post(
            f"/ui/connections/{BANK_CONNECTION_ID}/edit",
            headers=headers, follow_redirects=False,
            data={"host_url": "https://ebics.example.test/",
                  # What the connection already has; this test is
                  # about the schemes.
                  "letter_digest": "certificate",
                  "scheme_default": "instant_or_normal",
                  "instant_refusal_codes": "091112 091116",
                  "normal_service_name": "MCT", "normal_scope": "CH",
                  "normal_service_option": "",
                  "normal_service_level": "", "normal_service_level_kind": "cd",
                  "normal_local_instrument": "",
                  "normal_local_instrument_kind": "cd",
                  "normal_category_purpose": "",
                  "normal_category_purpose_kind": "cd",
                  "instant_offered": "1",
                  "instant_service_name": "XIP",
                  "instant_service_option": "URGP",
                  "instant_scope": "CH",
                  "instant_service_level": "SDVA",
                  "instant_service_level_kind": "cd",
                  "instant_local_instrument": "CH03",
                  "instant_local_instrument_kind": "prtry",
                  "instant_category_purpose": "",
                  "instant_category_purpose_kind": "cd",
                  "instant_max_amount": "15000.00"})
    assert posted.status_code == 303, posted.text

    stored = ConnectionRegistry(engine).get(BANK_CONNECTION_ID).schemes
    assert stored.default is PaymentScheme.INSTANT_OR_NORMAL
    assert stored.instant_refusal_codes == ("091112", "091116")
    assert stored.instant.btf_summary() == "XIP/URGP/CH"
    assert stored.instant.payment_type_summary() == \
        "SvcLvl/Cd=SDVA LclInstrm/Prtry=CH03"
    assert str(stored.instant.max_amount) == "15000.00"

    # And a payment submitted afterwards is built to it.
    order_id = submit(engine, idempotency_key="scheme-console-0001")
    live, _reserve = attempts(engine, order_id)
    assert live.btf_summary == "XIP/URGP/CH"
    assert payment_type_in(live.document) == [
        "PmtInf: SvcLvl/Cd=SDVA LclInstrm/Prtry=CH03"]


def test_switching_instant_off_in_the_console_downgrades_new_payments(
        prepared_bank, custody_settings):
    engine, _, _ = prepared_bank
    prepare(engine, SchemeProfiles(instant=None))
    order_id = submit(engine, idempotency_key="scheme-console-0002")
    live, = attempts(engine, order_id)
    assert live.scheme is PaymentScheme.NORMAL
    assert order_row(engine, order_id)["scheme_reason"] == \
        "preflight.instant_not_configured"
