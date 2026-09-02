"""Payment schemes: one decision, two places it has to show up, and the refusals.

The claims this file settles, none of which needs a bank:

* **the decision is one decision.** The BTF a request announces and the
  `PmtTpInf` in the document it carries come off the same profile, in one call,
  and are stored in the same row. They are compared here by reading the XML the
  service actually produced and the BTF it actually stored.
* **every document validates against the vendored ISO 20022 schema**, with the
  `PmtTpInf` at B level or at C level, with `Cd` or with `Prtry`.
* **the pre-flight refusals are refusals**, and they cost no round trip: an
  amount above the ceiling, a scheme the connection cannot send, and a message
  that asks for two schemes at once.
* **`instant_or_normal` builds both documents at accept time**, and the reserve
  is validated like the one that goes first.

The fallback itself is `tests/test_service_scheme_fallback.py`, driven against
a bank over a socket, because what it is about is what the bank said.
"""

from __future__ import annotations

import datetime as _dt
import decimal

import pytest
from lxml import etree
from sqlalchemy import select

from conftest import (BANK_CONNECTION_ID, payment_body, payment_type_in,
                      transfer)
from painfree import pain001, payments, schemes
from painfree.attempts import LIVE, PLANNED, AttemptStore
from painfree.connections import ConnectionRegistry
from painfree.orders import OrderStore
from painfree.schema import payment_attempt
from painfree.schemes import (Code, PaymentScheme, SchemeProfile,
                              SchemeProfiles, SchemeUnavailable)

NOW = _dt.datetime(2026, 9, 15, 8, 30, tzinfo=_dt.timezone.utc)


def instruction(**overrides) -> payments.PaymentInstruction:
    return payments.PaymentInstruction(**payment_body(**overrides))


def configure(engine, profiles: SchemeProfiles) -> None:
    """Give the fixture connection a scheme configuration, the way the console does."""
    ConnectionRegistry(engine).update(
        BANK_CONNECTION_ID,
        host_url=ConnectionRegistry(engine).get(BANK_CONNECTION_ID).host_url,
        schemes=profiles)


INSTANT_ONLY = SchemeProfiles(
    default=PaymentScheme.NORMAL,
    instant=SchemeProfile(service_name="MCT", service_option="INST",
                          scope="CH", service_level=Code("SEPA"),
                          local_instrument=Code("INST")),
)

#: The same connection, but instant is what it sends unless told otherwise.
#: Both of these name their instant profile rather than relying on a default:
#: there is no longer one, because the shipped triplet was the EPC SEPA
#: convention and was wrong for every bank this engine can register. A test
#: that resolves instant has to say which instant it means.
INSTANT_DEFAULT = SchemeProfiles(default=PaymentScheme.INSTANT,
                                 instant=INSTANT_ONLY.instant)


# --- the decision ----------------------------------------------------------

def test_a_connection_with_no_configuration_sends_what_it_always_sent():
    """The defaults are the pre-schemes behaviour, stated as a test.

    A `NULL` column is the state of every connection on the morning this
    migration lands, so what it resolves to is not a detail.
    """
    profiles = SchemeProfiles.parse(None)
    assert profiles.default is PaymentScheme.NORMAL
    normal = profiles.profile(PaymentScheme.NORMAL)
    assert normal.btf_summary() == "MCT/CH"
    assert normal.payment_type_summary() is None
    assert normal.emits_payment_type is False


def test_the_default_scheme_is_the_connections_when_the_caller_names_none():
    decision = schemes.resolve(INSTANT_DEFAULT,
                               instruction=instruction())
    assert decision.effective is PaymentScheme.INSTANT
    assert decision.reason == schemes.CONNECTION_DEFAULT


def test_a_named_scheme_beats_the_connections_default():
    decision = schemes.resolve(INSTANT_DEFAULT,
                               instruction=instruction(scheme="normal"))
    assert decision.effective is PaymentScheme.NORMAL
    assert decision.reason == schemes.REQUESTED
    assert decision.fallback is None


def test_instant_or_normal_plans_a_reserve_and_instant_alone_does_not():
    optional = schemes.resolve(INSTANT_ONLY,
                               instruction=instruction(scheme="instant_or_normal"))
    assert optional.effective is PaymentScheme.INSTANT
    assert optional.fallback is PaymentScheme.NORMAL

    strict = schemes.resolve(INSTANT_ONLY,
                             instruction=instruction(scheme="instant"))
    assert strict.effective is PaymentScheme.INSTANT
    assert strict.fallback is None


def test_a_per_transaction_override_names_the_scheme_for_the_message():
    decision = schemes.resolve(
        INSTANT_ONLY,
        instruction=instruction(transactions=[transfer(scheme="instant")]))
    assert decision.effective is PaymentScheme.INSTANT
    assert decision.per_transaction is True
    assert decision.reason == schemes.REQUESTED


def test_transactions_asking_for_two_schemes_are_refused_by_name():
    """One upload carries one BTF, so a mixed message has no announcement."""
    with pytest.raises(SchemeUnavailable) as raised:
        schemes.resolve(
            SchemeProfiles(),
            instruction=instruction(
                scheme="normal",
                transactions=[transfer(), transfer(scheme="instant")]))
    assert [failure.rule for failure in raised.value.failures] == [
        schemes.RULE_MIXED]


def test_an_override_that_agrees_with_the_message_is_not_a_mixture():
    decision = schemes.resolve(
        INSTANT_ONLY,
        instruction=instruction(scheme="instant",
                                transactions=[transfer(scheme="instant"),
                                              transfer(scheme="instant")]))
    assert decision.effective is PaymentScheme.INSTANT
    assert decision.per_transaction is True


# --- the pre-flight refusals, which cost no round trip ---------------------

def test_instant_on_a_connection_that_cannot_do_it_is_refused_by_name():
    with pytest.raises(SchemeUnavailable) as raised:
        schemes.resolve(SchemeProfiles(instant=None),
                        instruction=instruction(scheme="instant"))
    assert [failure.rule for failure in raised.value.failures] == [
        schemes.RULE_UNSUPPORTED]


def test_instant_or_normal_on_such_a_connection_goes_normal_before_anything():
    decision = schemes.resolve(SchemeProfiles(instant=None),
                               instruction=instruction(scheme="instant_or_normal"))
    assert decision.effective is PaymentScheme.NORMAL
    assert decision.downgraded is True
    assert decision.reason == schemes.PREFLIGHT_NO_INSTANT
    # No reserve: this *is* the reserve, chosen before a message was built.
    assert decision.fallback is None


def test_an_amount_above_the_ceiling_downgrades_before_anything_is_sent():
    profiles = SchemeProfiles(
        instant=SchemeProfile(max_amount=decimal.Decimal("1000.00")))
    decision = schemes.resolve(profiles,
                               instruction=instruction(scheme="instant_or_normal"))
    assert decision.effective is PaymentScheme.NORMAL
    assert decision.reason == schemes.PREFLIGHT_CEILING


def test_an_amount_above_the_ceiling_refuses_a_demand_for_instant():
    profiles = SchemeProfiles(
        instant=SchemeProfile(max_amount=decimal.Decimal("1000.00")))
    with pytest.raises(SchemeUnavailable) as raised:
        schemes.resolve(profiles, instruction=instruction(scheme="instant"))
    failure = raised.value.failures[0]
    assert failure.rule == schemes.RULE_CEILING
    # The transfer is named, not the message: a batch of fifty has one over it.
    assert failure.location == "transactions.0.amount"


def test_the_ceiling_is_per_transfer_and_not_the_control_sum():
    """Two transfers of 600 under a ceiling of 1000 are two instant payments."""
    profiles = SchemeProfiles(
        instant=SchemeProfile(max_amount=decimal.Decimal("1000.00")))
    decision = schemes.resolve(
        profiles,
        instruction=instruction(scheme="instant",
                                transactions=[transfer(amount="600.00"),
                                              transfer(amount="600.00")]))
    assert decision.effective is PaymentScheme.INSTANT


def test_there_is_no_default_ceiling():
    """A constant here would refuse a legitimate payment the day a bank moved."""
    assert schemes.DEFAULT_INSTANT.max_amount is None


# --- the document ----------------------------------------------------------

def build(profile: SchemeProfile, *, per_transaction: bool = False,
          **overrides) -> bytes:
    document = pain001.build(
        instruction(**overrides), message_id="PF" + "0" * 32, created_at=NOW,
        payment_type=profile, per_transaction=per_transaction)
    # The oracle, on every document this file produces.
    pain001.validate_document(document)
    return document


def test_a_normal_document_carries_no_payment_type_information_by_default():
    assert payment_type_in(build(schemes.DEFAULT_NORMAL)) == []


def test_an_instant_document_carries_svclvl_and_lclinstrm_at_b_level():
    assert payment_type_in(build(schemes.DEFAULT_INSTANT)) == [
        "PmtInf: SvcLvl/Cd=SEPA LclInstrm/Cd=INST"]


def test_a_per_transaction_scheme_puts_the_same_block_on_every_transfer():
    document = build(schemes.DEFAULT_INSTANT, per_transaction=True,
                     transactions=[transfer(scheme="instant"),
                                   transfer(scheme="instant")])
    assert payment_type_in(document) == [
        "CdtTrfTxInf: SvcLvl/Cd=SEPA LclInstrm/Cd=INST"] * 2


def test_a_proprietary_code_is_written_as_prtry_and_still_validates():
    """Swiss domestic instruments are `Prtry`; SEPA instant is `Cd`."""
    profile = SchemeProfile(local_instrument=Code("CH01", proprietary=True),
                            service_level=Code("SDVA"),
                            category_purpose=Code("SALA"),
                            instruction_priority="HIGH")
    assert payment_type_in(build(profile)) == [
        "PmtInf: InstrPrty=HIGH SvcLvl/Cd=SDVA LclInstrm/Prtry=CH01 "
        "CtgyPurp/Cd=SALA"]


def test_payment_type_information_sits_where_the_schema_puts_it():
    """`PmtTpInf` after `CtrlSum` and before `ReqdExctnDt`, and after `PmtId`.

    Out of order is not a warning in ISO 20022, it is an invalid document, so
    the position is asserted rather than trusted to `validate_document`.
    """
    at_b = etree.fromstring(build(schemes.DEFAULT_INSTANT))
    order = [etree.QName(child).localname
             for child in at_b.xpath("//*[local-name()='PmtInf']")[0]]
    assert order[:7] == ["PmtInfId", "PmtMtd", "BtchBookg", "NbOfTxs",
                         "CtrlSum", "PmtTpInf", "ReqdExctnDt"]

    at_c = etree.fromstring(build(schemes.DEFAULT_INSTANT, per_transaction=True))
    inner = [etree.QName(child).localname
             for child in at_c.xpath("//*[local-name()='CdtTrfTxInf']")[0]]
    assert inner[:3] == ["PmtId", "PmtTpInf", "Amt"]


def test_an_empty_profile_writes_no_element_rather_than_an_empty_one():
    """An empty `PmtTpInf` is schema-valid and is a bank told something extra."""
    assert payment_type_in(build(SchemeProfile())) == []


# --- accepting an order ----------------------------------------------------

def attempts(engine, order_id):
    return AttemptStore(engine).all(order_id)


def test_a_normal_order_has_one_attempt_and_the_default_btf(prepared_bank):
    engine, _, _ = prepared_bank
    order = OrderStore(engine).submit(
        BANK_CONNECTION_ID, idempotency_key="scheme-normal-01",
        instruction=instruction()).order
    assert order.scheme is PaymentScheme.NORMAL
    assert order.downgraded is False

    rows = attempts(engine, order.order_id)
    assert [(row.attempt_no, row.scheme.value, row.state) for row in rows] == [
        (1, "normal", LIVE)]
    assert rows[0].btf_summary == "MCT/CH"
    assert rows[0].payment_type is None
    assert payment_type_in(rows[0].document) == []


def test_an_instant_order_announces_and_says_the_same_thing(prepared_bank):
    """The BTF and the document, from the row that holds both."""
    engine, _, _ = prepared_bank
    configure(engine, INSTANT_ONLY)
    order = OrderStore(engine).submit(
        BANK_CONNECTION_ID, idempotency_key="scheme-instant-01",
        instruction=instruction(scheme="instant")).order

    live, = attempts(engine, order.order_id)
    assert live.scheme is PaymentScheme.INSTANT
    assert live.btf_summary == "MCT/INST/CH"
    assert live.payment_type == "SvcLvl/Cd=SEPA LclInstrm/Cd=INST"
    # The stored summary is a summary *of the document*, not a second opinion.
    assert payment_type_in(live.document) == [
        "PmtInf: SvcLvl/Cd=SEPA LclInstrm/Cd=INST"]
    pain001.validate_document(live.document)


def test_instant_or_normal_stores_two_validated_documents_and_two_msg_ids(
        prepared_bank):
    """The reserve is built and validated now, not after a bank refusal."""
    engine, _, _ = prepared_bank
    configure(engine, INSTANT_ONLY)
    order = OrderStore(engine).submit(
        BANK_CONNECTION_ID, idempotency_key="scheme-optional-01",
        instruction=instruction(scheme="instant_or_normal")).order

    first, second = attempts(engine, order.order_id)
    assert (first.scheme.value, first.state) == ("instant", LIVE)
    assert (second.scheme.value, second.state) == ("normal", PLANNED)
    assert first.msg_id != second.msg_id
    assert order.msg_id == first.msg_id
    for attempt in (first, second):
        pain001.validate_document(attempt.document)
    assert first.btf_summary == "MCT/INST/CH"
    assert second.btf_summary == "MCT/CH"
    assert payment_type_in(second.document) == []


def test_a_preflight_downgrade_costs_no_second_document(prepared_bank):
    """Downgraded before anything was built, so there is one attempt, not two."""
    engine, _, _ = prepared_bank
    configure(engine, SchemeProfiles(
        instant=SchemeProfile(service_option="INST",
                              service_level=Code("SEPA"),
                              local_instrument=Code("INST"),
                              max_amount=decimal.Decimal("100.00"))))
    order = OrderStore(engine).submit(
        BANK_CONNECTION_ID, idempotency_key="scheme-ceiling-01",
        instruction=instruction(scheme="instant_or_normal")).order

    assert order.scheme is PaymentScheme.NORMAL
    assert order.requested_scheme is PaymentScheme.INSTANT_OR_NORMAL
    assert order.downgraded is True
    assert order.scheme_reason == schemes.PREFLIGHT_CEILING
    rows = attempts(engine, order.order_id)
    assert [(row.scheme.value, row.state) for row in rows] == [("normal", LIVE)]


def test_a_refused_scheme_lands_no_order_at_all(prepared_bank):
    engine, _, _ = prepared_bank
    configure(engine, SchemeProfiles(instant=None))
    with pytest.raises(SchemeUnavailable):
        OrderStore(engine).submit(
            BANK_CONNECTION_ID, idempotency_key="scheme-refused-01",
            instruction=instruction(scheme="instant"))
    with engine.connect() as connection:
        assert connection.execute(
            select(payment_attempt)).mappings().all() == []


def test_every_attempt_of_every_order_has_its_own_msg_id(prepared_bank):
    """Unique in the database, because the bank deduplicates on it."""
    engine, _, _ = prepared_bank
    configure(engine, INSTANT_ONLY)
    store = OrderStore(engine)
    ids = set()
    for number in range(3):
        order = store.submit(
            BANK_CONNECTION_ID, idempotency_key=f"scheme-unique-{number:02d}",
            instruction=instruction(scheme="instant_or_normal")).order
        ids |= {row.msg_id for row in attempts(engine, order.order_id)}
    assert len(ids) == 6


# --- the configuration round trip ------------------------------------------

def test_a_stored_profile_survives_the_round_trip(prepared_bank):
    engine, _, _ = prepared_bank
    profiles = SchemeProfiles(
        default=PaymentScheme.INSTANT_OR_NORMAL,
        normal=SchemeProfile(service_name="XCT", scope="BIL",
                             service_level=Code("SEPA")),
        instant=SchemeProfile(service_name="XIP", service_option="URGP",
                              scope="CH",
                              local_instrument=Code("CH03", proprietary=True),
                              max_amount=decimal.Decimal("15000.00")),
        instant_refusal_codes=("091112", "091116"),
    )
    configure(engine, profiles)
    stored = ConnectionRegistry(engine).get(BANK_CONNECTION_ID).schemes
    assert stored == profiles
    assert stored.instant.local_instrument.proprietary is True
    assert stored.refuses_instant("091116") is True
    assert stored.refuses_instant("091302") is False
    assert stored.refuses_instant(None) is False


def test_the_refusal_codes_are_a_whitelist_and_an_empty_one_refuses_everything():
    """Fail closed: no configured code means no outcome can trigger a fallback."""
    profiles = SchemeProfiles(instant_refusal_codes=())
    assert profiles.refuses_instant("091112") is False


def test_a_connection_defaulting_to_instant_needs_an_instant_profile():
    with pytest.raises(ValueError):
        SchemeProfiles(default=PaymentScheme.INSTANT, instant=None)


# --- the HTTP surface ------------------------------------------------------

def test_the_api_names_the_scheme_and_lists_the_attempts(prepared_bank,
                                                         custody_settings):
    """A caller sees what was asked for, what is being sent, and both messages."""
    from fastapi.testclient import TestClient

    from conftest import dev_credentials
    from painfree.api import IDEMPOTENCY_HEADER
    from painfree.app import create_app

    engine, _, _ = prepared_bank
    configure(engine, INSTANT_ONLY)
    app = create_app(custody_settings)
    with TestClient(app, headers=dev_credentials()) as client:
        response = client.post(
            f"/v1/connections/{BANK_CONNECTION_ID}/payments",
            json=payment_body(scheme="instant_or_normal"),
            headers={IDEMPOTENCY_HEADER: "scheme-api-0001"})
        assert response.status_code == 202, response.text
        body = response.json()
        assert body["scheme"]["requested"] == "instant_or_normal"
        assert body["scheme"]["effective"] == "instant"
        assert body["scheme"]["downgraded"] is False
        assert [(row["attempt"], row["scheme"], row["state"], row["btf"])
                for row in body["scheme"]["attempts"]] == [
            (1, "instant", LIVE, "MCT/INST/CH"),
            (2, "normal", PLANNED, "MCT/CH")]

        # And the same body reading the order back.
        again = client.get(f"/v1/orders/{body['order_id']}").json()
        assert again["scheme"] == body["scheme"]


def test_the_api_refuses_a_scheme_the_connection_cannot_send_by_name(
        prepared_bank, custody_settings):
    from fastapi.testclient import TestClient

    from conftest import dev_credentials
    from painfree.api import IDEMPOTENCY_HEADER
    from painfree.app import create_app

    engine, _, _ = prepared_bank
    configure(engine, SchemeProfiles(instant=None))
    app = create_app(custody_settings)
    with TestClient(app, headers=dev_credentials()) as client:
        response = client.post(
            f"/v1/connections/{BANK_CONNECTION_ID}/payments",
            json=payment_body(scheme="instant"),
            headers={IDEMPOTENCY_HEADER: "scheme-api-0002"})
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_failed"
    assert [failure["rule"] for failure in error["detail"]["failures"]] == [
        schemes.RULE_UNSUPPORTED]


def test_the_api_refuses_an_unknown_scheme_before_it_reaches_the_rules(
        prepared_bank, custody_settings):
    from fastapi.testclient import TestClient

    from conftest import dev_credentials
    from painfree.api import IDEMPOTENCY_HEADER
    from painfree.app import create_app

    engine, _, _ = prepared_bank
    app = create_app(custody_settings)
    with TestClient(app, headers=dev_credentials()) as client:
        response = client.post(
            f"/v1/connections/{BANK_CONNECTION_ID}/payments",
            json=payment_body(scheme="overnight"),
            headers={IDEMPOTENCY_HEADER: "scheme-api-0003"})
    assert response.status_code == 422


def test_a_per_transaction_override_travels_through_the_api(prepared_bank,
                                                            custody_settings):
    """And puts the block on the transfer rather than on the batch."""
    from fastapi.testclient import TestClient

    from conftest import dev_credentials
    from painfree.api import IDEMPOTENCY_HEADER
    from painfree.app import create_app

    engine, _, _ = prepared_bank
    configure(engine, INSTANT_ONLY)
    app = create_app(custody_settings)
    with TestClient(app, headers=dev_credentials()) as client:
        response = client.post(
            f"/v1/connections/{BANK_CONNECTION_ID}/payments",
            json=payment_body(transactions=[transfer(scheme="instant")]),
            headers={IDEMPOTENCY_HEADER: "scheme-api-0004"})
    assert response.status_code == 202, response.text
    order_id = response.json()["order_id"]
    live, = attempts(engine, order_id)
    assert live.scheme is PaymentScheme.INSTANT
    assert live.btf_summary == "MCT/INST/CH"
    assert payment_type_in(live.document) == [
        "CdtTrfTxInf: SvcLvl/Cd=SEPA LclInstrm/Cd=INST"]


def test_the_connection_list_says_what_the_connection_will_send(prepared_bank,
                                                                custody_settings):
    from fastapi.testclient import TestClient

    from conftest import dev_credentials
    from painfree.app import create_app

    engine, _, _ = prepared_bank
    configure(engine, INSTANT_ONLY)
    app = create_app(custody_settings)
    with TestClient(app, headers=dev_credentials()) as client:
        row, = client.get("/v1/connections").json()["connections"]
    assert row["payment_schemes"]["default"] == "normal"
    assert row["payment_schemes"]["instant"]["service_option"] == "INST"
    assert row["payment_schemes"]["instant"]["local_instrument"] == {"cd": "INST"}
    assert row["payment_schemes"]["instant_refusal_codes"] == ["091112"]
