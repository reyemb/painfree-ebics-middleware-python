"""Normalising `camt` and `pain.002` to the JSON shape this repo publishes.

**The fixtures are held to the official schemas first.** They were written in
this repository -- neither reference project ships a `camt` document of any
kind -- so without an independent check they would prove only that the parser
reads what the parser expects. Every one of them is validated against the ISO
20022 XSD for its own version before anything is asserted about what came out
of it. The schemas and their provenance are in ``tests/schemas/README.md``.

**There is no reference parser to diff against, and none is claimed.**
`ebics-client-php` and `epics` both read *bank responses* -- the EBICS envelope
-- and this repository's harness compares four implementations field by field on
exactly that. Neither of them parses `camt`; `epics`' `c53` is an order type,
not a reader. And the normalised shape is this repo's own contract, so there is
nothing it could be compared against even if one of them did. The XSD is the
oracle here, and it is a real one.

**Money is the thing these tests exist for.** Two of them fail if a single
amount ever passes through a binary float.
"""

from __future__ import annotations

import decimal
import json

import pytest

from painfree.camt import normalise_camt
from painfree.isoxml import DocumentUnreadable
from painfree.pain002 import normalise_pain002
from painfree.statements import normalise
from conftest import MESSAGE_TYPES, fixture_bytes, schema_for


@pytest.mark.parametrize("message_type", MESSAGE_TYPES)
def test_every_fixture_is_valid_against_its_official_schema(message_type):
    from lxml import etree

    schema = schema_for(message_type)
    document = etree.fromstring(fixture_bytes(message_type))
    assert schema.validate(document), schema.error_log


@pytest.mark.parametrize("message_type", MESSAGE_TYPES)
def test_the_message_type_is_read_off_the_document_not_the_configuration(
        message_type):
    for one in normalise(fixture_bytes(message_type)):
        assert one.message_type == message_type
        assert one.payload["message_type"] == message_type


@pytest.mark.parametrize("message_type", MESSAGE_TYPES)
def test_the_normalised_payload_is_json_with_no_floats_in_it(message_type):
    """Serialisable, and every number in it a string.

    A JSON number is a double. An amount that reaches a consumer as `0.1` has
    already lost, whatever this service did with it internally -- so the
    contract says amounts are strings, and this is what holds it to that.
    """
    for one in normalise(fixture_bytes(message_type)):
        text = json.dumps(one.payload)
        assert json.loads(text) == one.payload
        assert not _floats(one.payload), _floats(one.payload)


def _floats(value, path="$"):
    if isinstance(value, float):
        return [path]
    if isinstance(value, dict):
        return [p for k, v in value.items() for p in _floats(v, f"{path}.{k}")]
    if isinstance(value, list):
        return [p for i, v in enumerate(value) for p in _floats(v, f"{path}[{i}]")]
    return []


# --- camt.053 ---------------------------------------------------------------


def test_a_statement_reads_its_account_period_balances_and_entries():
    statement, = normalise_camt(fixture_bytes("camt.053.001.08"))

    assert statement.kind == "statement"
    assert statement.identification == "STMT-2026-0242"
    assert statement.sequence_number == "242"
    assert statement.iban == "CH5604835012345678009"
    assert statement.currency == "CHF"
    assert statement.entry_count == 3
    assert statement.created_at.isoformat() == "2026-08-29T00:15:00+00:00"
    assert statement.from_datetime.isoformat() == "2026-08-27T22:00:00+00:00"

    account = statement.payload["account"]
    assert account["owner"] == "MUSTER AG"
    assert account["servicer_bic"] == "CRESCHZZ80A"
    # A closing balance the bank marks DBIT is a negative balance, and the
    # signed value is what a consumer needs; the raw indicator is kept too.
    assert statement.payload["closing_balance"]["credit_debit"] == "debit"
    assert statement.closing_balance == decimal.Decimal("-2949.45")
    assert statement.opening_balance == decimal.Decimal("1000.00")


def test_a_debit_entry_names_the_creditor_as_the_counterparty():
    statement, = normalise_camt(fixture_bytes("camt.053.001.08"))
    entry = statement.payload["entries"][0]
    transaction, = entry["transactions"]

    assert entry["credit_debit"] == "debit"
    assert entry["status"] == "BOOK"
    assert entry["bank_transaction_code"] == {
        "domain": "PMNT", "family": "ICDT", "sub_family": "ESCT",
        "proprietary": None}
    assert transaction["counterparty_role"] == "creditor"
    assert transaction["counterparty"]["name"] == "Robert Schneider AG"
    assert transaction["counterparty"]["iban"] == "CH4431999123000889012"
    assert transaction["reference"] == {
        "type": "QRR", "reference": "210000000003139471430009017"}
    assert transaction["message_identification"] == \
        "PF3868D16485F403EA96B3AF3B78F98E6"


def test_a_credit_entry_names_the_debtor_and_joins_split_remittance_lines():
    statement, = normalise_camt(fixture_bytes("camt.053.001.08"))
    transaction, = statement.payload["entries"][1]["transactions"]

    assert transaction["counterparty_role"] == "debtor"
    assert transaction["counterparty"]["name"] == "Bernasconi SA"
    # `Ustrd` is capped at 140 characters, so one remittance text arrives as
    # several elements. Returning a list would push the joining onto every
    # consumer.
    assert transaction["remittance_information"] == \
        "Rueckerstattung Teil 1 von zwei"


def test_the_entries_add_up_to_the_declared_credit_total_which_float_cannot():
    """The money test, and it is not decorative.

    The statement declares a credit total of `0.30` and carries two credits of
    `0.10` and `0.20`. In decimal they are equal. In IEEE 754 doubles they are
    not, and the assertion at the bottom is what would fail if any part of the
    path from XML to here ever went through a float.
    """
    statement, = normalise_camt(fixture_bytes("camt.053.001.08"))
    credits = [entry for entry in statement.entries
               if entry.data["credit_debit"] == "credit"]
    declared = decimal.Decimal(statement.payload["summary"]["credits"]["sum"])

    assert sum((entry.amount for entry in credits), decimal.Decimal(0)) == declared
    assert declared == decimal.Decimal("0.30")

    # The same arithmetic, done the way that is wrong.
    assert sum(float(entry.data["amount"]) for entry in credits) != float(declared)


def test_the_signed_total_reconciles_the_opening_balance_to_the_closing_one():
    statement, = normalise_camt(fixture_bytes("camt.053.001.08"))
    assert statement.opening_balance + statement.total() == statement.closing_balance


# --- camt.052 ---------------------------------------------------------------


def test_an_intraday_report_keeps_eighteen_significant_digits():
    """The other half of the money argument: magnitude, not just scale.

    `9007199254740993.01` has more significant digits than a double can hold.
    ``float()`` of it is `9007199254740992.0`, and the assertion below says the
    parser never went near one.
    """
    report, = normalise_camt(fixture_bytes("camt.052.001.08"))
    entry, = report.entries

    assert report.kind == "report"
    assert entry.data["amount"] == "9007199254740993.01"
    assert entry.amount == decimal.Decimal("9007199254740993.01")
    assert decimal.Decimal(repr(float(entry.amount))) != entry.amount
    # `AmtDtls/InstdAmt` is the amount in the currency it was instructed in,
    # and its digits are kept the same way.
    transaction, = entry.data["transactions"]
    assert transaction["instructed_amount"] == {
        "amount": "9000000000000000.55", "currency": "EUR"}


def test_a_report_falls_back_to_the_previous_closing_balance_for_its_opening():
    report, = normalise_camt(fixture_bytes("camt.052.001.08"))
    assert report.payload["opening_balance"]["type"] == "PRCD"
    assert report.opening_balance == decimal.Decimal("-2949.45")
    assert report.payload["closing_balance"]["type"] == "CLAV"


def test_a_proprietary_bank_transaction_code_is_kept_as_one():
    report, = normalise_camt(fixture_bytes("camt.052.001.08"))
    entry, = report.entries
    assert entry.data["bank_transaction_code"]["proprietary"] == "ZA-CRDT"
    assert entry.data["bank_transaction_code"]["domain"] is None
    assert entry.data["status"] == "PDNG"


# --- camt.054 ---------------------------------------------------------------


def test_a_notification_with_two_accounts_becomes_two_statements():
    """One document, two `Ntfctn` elements, two rows.

    Merging them would produce one statement with two accounts' entries in it,
    which is not a thing the contract can express and not a thing a consumer
    could unpick.
    """
    first, second = normalise_camt(fixture_bytes("camt.054.001.09"))

    assert first.kind == second.kind == "notification"
    assert first.identification == "NTFCTN-2026-0829-A"
    assert second.identification == "NTFCTN-2026-0829-B"
    assert first.iban != second.iban
    assert first.opening_balance is None and first.closing_balance is None


def test_a_reversal_is_marked_as_one():
    _, second = normalise_camt(fixture_bytes("camt.054.001.09"))
    entry, = second.entries
    assert entry.data["reversal"] is True
    assert entry.data["credit_debit"] == "debit"
    assert entry.data["additional_information"] == "Rueckbuchung"
    assert entry.data["transactions"] == []


# --- pain.002 ---------------------------------------------------------------


def test_a_status_report_keeps_all_three_levels_of_status():
    """`PART` at the group, `ACCP` at the payment, one `RJCT` transaction.

    Collapsing these into "the status" is the mistake the fixture is built
    around: any single level answers the question wrongly.
    """
    status, = normalise_pain002(fixture_bytes("pain.002.001.10"))

    assert status.kind == "payment_status"
    assert status.payload["original"]["status"] == "PART"
    payment, = status.payload["payments"]
    assert payment["status"] == "ACCP"
    assert [t["status"] for t in payment["transactions"]] == ["ACSP", "RJCT"]


def test_a_status_report_is_identified_by_the_message_it_answers():
    status, = normalise_pain002(fixture_bytes("pain.002.001.10"))
    # `OrgnlMsgId` is the `MsgId` this service generated and stored on the
    # order. It is the join, and it is why the identity is that and not the
    # status report's own `MsgId`.
    assert status.identification == "PF3868D16485F403EA96B3AF3B78F98E6"
    assert status.payload["group_header"]["message_identification"] == \
        "STSRPT-20260829-0001"
    assert status.entry_count == 2


def test_a_rejection_keeps_the_code_the_originator_and_every_line_of_text():
    status, = normalise_pain002(fixture_bytes("pain.002.001.10"))
    payment, = status.payload["payments"]
    rejected = payment["transactions"][1]

    reason, = rejected["reasons"]
    assert reason["code"] == "AC01"
    assert reason["originator"] == "CREDIT SUISSE (SCHWEIZ) AG"
    assert reason["additional_information"] == [
        "Creditor account number invalid", "IBAN check digit"]
    assert rejected["amount"] == "250.00"
    assert rejected["currency"] == "CHF"
    assert rejected["requested_execution_date"] == "2026-09-01"


# --- refusals ---------------------------------------------------------------


def test_something_that_is_not_an_iso_20022_document_is_refused_by_name():
    with pytest.raises(DocumentUnreadable) as raised:
        normalise(b"<ebicsResponse xmlns='urn:org:ebics:H005'/>")
    assert "Document" in str(raised.value)


def test_a_document_of_a_family_this_service_does_not_read_is_refused():
    with pytest.raises(DocumentUnreadable) as raised:
        normalise(b"<Document xmlns='urn:iso:std:iso:20022:tech:xsd:pain.008.001.08'>"
                  b"<CstmrDrctDbtInitn/></Document>")
    assert "pain.008.001.08" in str(raised.value)


def test_bytes_that_are_not_xml_are_refused_rather_than_stored():
    with pytest.raises(DocumentUnreadable):
        normalise(b"not xml at all")
