"""The Swiss Payment Standards rules, each one proved to reject *and* to accept.

A validator that never rejects is worthless; a validator that rejects
everything is worse, because it is discovered later. So every rule below
appears twice -- one instruction it refuses and one it lets through -- and the
values it lets through are not ours. The QR-IBAN, the QR reference, the plain
IBAN and the RF reference come from another EBICS implementation's own Swiss
`pain.001` templates (see ``tests/conftest.py``), so "accepted" means accepted
against values a different project publishes as correct.

The three check-digit algorithms are pinned separately, against those same
values: ISO 7064 MOD 97-10 for the IBAN and the RF reference, and the Swiss
Modulo 10 recursive table for the QR reference.
"""

from __future__ import annotations

import decimal

import pytest

from conftest import (DEBTOR_IBAN, PLAIN_IBAN, QRR_REFERENCE, QR_IBAN,
                      SCOR_REFERENCE, payment_body, scor_transfer, transfer)
from painfree import payments, sps


def rules(body: dict) -> set[str]:
    """The rule ids an instruction breaks."""
    instruction = payments.PaymentInstruction(**body)
    return {failure.rule for failure in payments.swiss_failures(instruction)}


# --- the algorithms, against published values -------------------------------

def test_the_recursive_check_digit_matches_the_reference_qr_reference():
    """Modulo 10 recursive, over the 26 digits that precede the check digit."""
    assert sps.mod10_recursive(QRR_REFERENCE[:-1]) == int(QRR_REFERENCE[-1])
    assert sps.qrr_failure(QRR_REFERENCE) is None


def test_a_qr_reference_printed_in_groups_is_the_same_reference():
    assert sps.qrr_failure("21 00000 00003 13947 14300 09017") is None


def test_a_single_wrong_digit_breaks_the_recursive_check_digit():
    broken = QRR_REFERENCE[:5] + "9" + QRR_REFERENCE[6:]
    assert sps.qrr_failure(broken) == "qrr.check_digit"


def test_the_iban_check_digits_are_iso_7064():
    for iban in (QR_IBAN, PLAIN_IBAN, DEBTOR_IBAN):
        assert sps.iban_failure(iban) is None
    # Transposing two characters is the typo the check digits exist to catch.
    assert sps.iban_failure("CH4431999123000889021") == "iban.checksum"


def test_a_swiss_iban_of_the_wrong_length_is_refused_before_the_checksum():
    assert sps.iban_failure(QR_IBAN + "0") == "iban.length"


def test_the_rf_creditor_reference_is_mod_97():
    assert sps.scor_failure(SCOR_REFERENCE) is None
    assert sps.scor_failure("RF19539007547034") == "scor.check_digit"
    assert sps.scor_failure("RF1") == "scor.format"


# --- QR-IBAN detection ------------------------------------------------------

def test_the_qr_iid_range_is_what_makes_an_account_a_qr_iban():
    assert sps.swiss_iid(QR_IBAN) == 31999
    assert sps.is_qr_iban(QR_IBAN) is True
    assert sps.swiss_iid(PLAIN_IBAN) == 21966
    assert sps.is_qr_iban(PLAIN_IBAN) is False


def test_a_non_swiss_iban_has_no_qr_iid():
    assert sps.swiss_iid("DE89370400440532013000") is None
    assert sps.is_qr_iban("DE89370400440532013000") is False


# --- the rules, rejecting and accepting -------------------------------------

def test_a_qr_iban_with_a_qr_reference_is_accepted():
    assert rules(payment_body()) == set()


def test_a_plain_iban_with_an_iso_11649_reference_is_accepted():
    assert rules(payment_body(transactions=[scor_transfer()])) == set()


def test_a_qr_reference_paid_to_a_plain_iban_is_refused():
    """The crossing SIX reserved the IID range to make impossible."""
    body = payment_body(transactions=[
        transfer(creditor_iban=PLAIN_IBAN,
                 reference={"type": "QRR", "reference": QRR_REFERENCE})])
    assert rules(body) == {"qrr.requires_qr_iban"}


def test_an_iso_11649_reference_paid_to_a_qr_iban_is_refused():
    body = payment_body(transactions=[
        transfer(creditor_iban=QR_IBAN,
                 reference={"type": "SCOR", "reference": SCOR_REFERENCE})])
    assert rules(body) == {"scor.forbidden_with_qr_iban"}


def test_a_qr_iban_with_no_reference_at_all_is_refused():
    body = payment_body(transactions=[
        transfer(creditor_iban=QR_IBAN, reference={"type": "NONE"})])
    assert rules(body) == {"qr_iban.requires_qrr"}


def test_a_plain_iban_with_no_reference_at_all_is_accepted():
    body = payment_body(transactions=[
        transfer(creditor_iban=PLAIN_IBAN, reference={"type": "NONE"},
                 remittance_information="invoice 4711")])
    assert rules(body) == set()


def test_a_malformed_qr_reference_names_the_format_rule():
    body = payment_body(transactions=[
        transfer(reference={"type": "QRR", "reference": "12345"})])
    assert rules(body) == {"qrr.format"}


def test_a_qr_reference_with_a_wrong_check_digit_is_refused():
    broken = QRR_REFERENCE[:-1] + str((int(QRR_REFERENCE[-1]) + 1) % 10)
    body = payment_body(transactions=[
        transfer(reference={"type": "QRR", "reference": broken})])
    assert rules(body) == {"qrr.check_digit"}


def test_a_reference_type_with_no_reference_is_refused():
    body = payment_body(transactions=[transfer(reference={"type": "QRR"})])
    assert rules(body) == {"reference.missing"}


def test_a_structured_reference_and_free_text_together_are_refused():
    """Swiss usage is one or the other, and a message with both is rejected."""
    body = payment_body(transactions=[
        transfer(remittance_information="invoice 4711")])
    assert rules(body) == {"reference.exclusive"}


def test_a_broken_creditor_iban_is_refused_and_the_reference_rules_stay_quiet():
    """One failure per mistake: the reference rules mean nothing on a typo."""
    body = payment_body(transactions=[
        transfer(creditor_iban="CH4431999123000889021")])
    assert rules(body) == {"iban.checksum"}


def test_a_broken_debtor_iban_names_the_debtor_field():
    instruction = payments.PaymentInstruction(
        **payment_body(debtor_iban="CH5604835012345678000"))
    failures = payments.swiss_failures(instruction)
    assert [(failure.location, failure.rule) for failure in failures] == [
        ("debtor_iban", "iban.checksum")]


# --- amounts and currencies -------------------------------------------------

def test_a_zero_amount_is_refused_and_a_positive_one_is_not():
    assert "amount.positive" in rules(payment_body(transactions=[
        transfer(amount="0.00")]))
    assert rules(payment_body(transactions=[transfer(amount="0.01")])) == set()


def test_three_decimal_places_in_a_two_decimal_currency_are_refused():
    """Schema-valid -- the XSD allows five -- and refused by the bank."""
    assert rules(payment_body(transactions=[
        transfer(amount="3949.755")])) == {"amount.minor_units"}


def test_a_three_decimal_currency_may_carry_three_decimals():
    body = payment_body(transactions=[
        scor_transfer(amount="199.955", currency="KWD")])
    assert rules(body) == set()
    assert sps.minor_units("KWD") == 3
    assert sps.minor_units("JPY") == 0
    assert sps.minor_units("CHF") == 2


def test_a_qr_bill_is_chf_or_eur_only():
    body = payment_body(transactions=[transfer(currency="USD")])
    assert rules(body) == {"currency.qr_bill"}
    assert rules(payment_body(transactions=[transfer(currency="EUR")])) == set()


def test_one_message_carries_one_currency():
    body = payment_body(transactions=[
        transfer(), scor_transfer(currency="EUR", amount="10.00")])
    assert rules(body) == {"currency.mixed"}


# --- what a failure is allowed to say ---------------------------------------

def test_a_failure_names_the_field_and_never_quotes_the_value():
    """These messages reach the audit trail; a reference identifies a bill."""
    body = payment_body(transactions=[
        transfer(creditor_iban=PLAIN_IBAN,
                 reference={"type": "QRR", "reference": QRR_REFERENCE})])
    failures = payments.swiss_failures(payments.PaymentInstruction(**body))
    assert failures
    for failure in failures:
        assert QRR_REFERENCE not in failure.message
        assert PLAIN_IBAN not in failure.message
        assert failure.location.startswith("transactions.0.")


def test_every_broken_rule_is_reported_not_only_the_first():
    body = payment_body(
        debtor_iban="CH5604835012345678000",
        transactions=[transfer(amount="1.005", currency="USD")])
    assert rules(body) == {"iban.checksum", "amount.minor_units",
                           "currency.qr_bill"}


def test_validate_raises_with_every_failure_in_the_envelope():
    instruction = payments.PaymentInstruction(
        **payment_body(transactions=[transfer(amount="0")]))
    with pytest.raises(sps.ValidationFailed) as raised:
        payments.validate(instruction)
    assert raised.value.status_code == 422
    assert raised.value.code == "validation_failed"
    assert raised.value.detail["failures"][0]["rule"] == "amount.positive"


def test_a_json_float_keeps_the_digits_the_caller_wrote():
    """`Decimal(3949.75)` is not `3949.75`; routing through `repr` keeps it."""
    parsed = payments.Transaction(**transfer(amount=3949.75))
    assert parsed.amount == decimal.Decimal("3949.75")
