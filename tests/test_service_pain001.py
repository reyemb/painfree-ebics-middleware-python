"""The `pain.001` builder, held to the official schema.

**The XSD.** ``painfree/schemas/pain.001.001.09.xsd`` is the ISO 20022 schema --
Standards Editor output, vendored from `ebics-api/ebics-client-php` (MIT).
Every document these tests build is validated against it, so "valid" means the
published schema says so.
"""

from __future__ import annotations

import datetime as _dt
import decimal
import hashlib

import pytest
from lxml import etree

from conftest import (DEBTOR_IBAN, QRR_REFERENCE, payment_body,
                      scor_transfer, transfer)
from painfree import pain001, payments, schemes

CREATED_AT = _dt.datetime(2026, 8, 29, 20, 15, 0, tzinfo=_dt.timezone.utc)
MESSAGE_ID = "PFTEST0000000000000000000000000001"


def build(body: dict | None = None, **kwargs) -> bytes:
    instruction = payments.PaymentInstruction(**(body or payment_body()))
    return pain001.build(instruction, message_id=MESSAGE_ID,
                         created_at=CREATED_AT, **kwargs)


def parse(document: bytes) -> etree._Element:
    return etree.fromstring(document)


def find(document: bytes, path: str) -> list[str]:
    """Text of every element at a slash-separated path, namespaces handled."""
    tree = parse(document)
    steps = "/".join(f"ns:{step}" for step in path.split("/"))
    return [element.text for element
            in tree.xpath(steps, namespaces={"ns": pain001.NAMESPACE})]


# --- the schema oracle ------------------------------------------------------

def test_a_qr_payment_validates_against_the_official_schema():
    assert pain001.schema_failures(build()) == []


def test_an_iso_11649_payment_validates_against_the_official_schema():
    document = build(payment_body(transactions=[scor_transfer()]))
    assert pain001.schema_failures(document) == []


def test_a_batch_of_transfers_validates_against_the_official_schema():
    body = payment_body(transactions=[
        scor_transfer(amount="10.00", end_to_end_id="E2E-1"),
        scor_transfer(amount="20.50", end_to_end_id="E2E-2",
                      reference={"type": "NONE"},
                      remittance_information="invoice 4711"),
    ])
    document = build(body)
    assert pain001.schema_failures(document) == []
    assert find(document, "CstmrCdtTrfInitn/GrpHdr/NbOfTxs") == ["2"]
    assert find(document, "CstmrCdtTrfInitn/GrpHdr/CtrlSum") == ["30.50"]


def test_the_schema_is_the_namespace_this_repo_claims():
    assert pain001.NAMESPACE.endswith("pain.001.001.09")
    assert parse(build()).tag == f"{{{pain001.NAMESPACE}}}Document"
    # No `xsi:schemaLocation` hint, here as in every EBICS request.
    assert b"schemaLocation" not in build()


def test_a_document_the_schema_refuses_is_reported_with_its_element_path():
    """The failure path has to work, or it is only ever exercised in production."""
    broken = build().replace(b"<NbOfTxs>1</NbOfTxs>", b"<NbOfTxs>one</NbOfTxs>")
    failures = pain001.schema_failures(broken)
    assert failures and all(failure.rule == "xsd.invalid" for failure in failures)
    assert "NbOfTxs" in failures[0].location


# --- what the schema cannot say ---------------------------------------------

def test_the_schema_accepts_an_amount_the_swiss_rules_refuse():
    """`ActiveOrHistoricCurrencyAndAmount` permits five decimals in any currency.

    This is the whole argument for `painfree.sps` existing next to the XSD: a
    three-decimal CHF amount is a valid ISO 20022 message and a bank rejection.
    """
    body = payment_body(transactions=[transfer(amount="3949.755")])
    document = build(body)
    assert pain001.schema_failures(document) == []
    assert {failure.rule for failure in payments.swiss_failures(
        payments.PaymentInstruction(**body))} == {"amount.minor_units"}


# --- the encoding details that are easy to get wrong ------------------------

def test_a_qr_reference_is_proprietary_and_scor_is_a_code():
    qr = build()
    assert find(qr, "CstmrCdtTrfInitn/PmtInf/CdtTrfTxInf/RmtInf/Strd/"
                    "CdtrRefInf/Tp/CdOrPrtry/Prtry") == ["QRR"]
    scor = build(payment_body(transactions=[scor_transfer()]))
    assert find(scor, "CstmrCdtTrfInitn/PmtInf/CdtTrfTxInf/RmtInf/Strd/"
                      "CdtrRefInf/Tp/CdOrPrtry/Cd") == ["SCOR"]


def test_emitting_a_qr_reference_as_an_iso_code_is_a_document_the_schema_refuses():
    """`DocumentType3Code` has no `QRR`, which is why the asymmetry matters."""
    wrong = build().replace(b"<Prtry>QRR</Prtry>", b"<Cd>QRR</Cd>")
    assert pain001.schema_failures(wrong) != []


def test_a_reference_printed_in_groups_is_written_without_them():
    body = payment_body(transactions=[
        transfer(reference={"type": "QRR",
                            "reference": "21 00000 00003 13947 14300 09017"})])
    assert find(build(body), "CstmrCdtTrfInitn/PmtInf/CdtTrfTxInf/RmtInf/"
                             "Strd/CdtrRefInf/Ref") == [QRR_REFERENCE]


def test_a_transfer_with_no_end_to_end_reference_gets_the_iso_placeholder():
    assert find(build(), "CstmrCdtTrfInitn/PmtInf/CdtTrfTxInf/PmtId/"
                         "EndToEndId") == [pain001.NOT_PROVIDED]


def test_a_debtor_with_no_bic_still_produces_a_valid_document():
    body = payment_body()
    body.pop("debtor_bic")
    document = build(body)
    assert pain001.schema_failures(document) == []
    assert find(document, "CstmrCdtTrfInitn/PmtInf/DbtrAgt/FinInstnId/BICFI") == []


def test_a_swiss_debtor_agent_with_no_bic_is_named_by_its_IID():
    """Two rules meet here, and the first one on its own produced an invalid
    document for four releases.

    **Never `Othr/Id` of `NOTPROVIDED`.** That is the EPC SEPA convention, and
    a Swiss bank's validator refuses it -- *"Das Element 'Othr' soll in diesem
    Kontext nicht verwendet werden"* -- after the file is signed and uploaded.

    **And never an empty `FinInstnId` either.** That was the first fix, and
    GEFEG.FX found it: *"CH21: At least one sub-element of <FinInstnId> must be
    provided"*. Schema-valid, Swiss-invalid. The XSD accepts an empty
    `FinInstnId` because every child of it is optional, which is exactly why
    `schema_failures` passed the document that got rejected -- the two layers
    answer different questions.

    A BIC is not derivable from an IBAN. The *institution* is: characters 5 to
    9 of a `CH`/`LI` IBAN are the IID, and `ClrSysMmbId` under `CHBCC` is what
    takes it. So the account already in the document names its own bank, with
    nothing stored that could be missing or out of date.
    """
    body = payment_body()
    body.pop("debtor_bic")
    document = build(body)

    assert pain001.schema_failures(document) == []
    agent = parse(document).find(
        f".//{{{pain001.NAMESPACE}}}DbtrAgt/{{{pain001.NAMESPACE}}}FinInstnId")
    assert agent is not None, "DbtrAgt is mandatory and must still be there"
    assert list(agent) != [], "an empty FinInstnId is what CH21 rejects"
    assert [etree.QName(child).localname for child in agent] == ["ClrSysMmbId"]

    assert find(document, "CstmrCdtTrfInitn/PmtInf/DbtrAgt/FinInstnId/"
                          "ClrSysMmbId/ClrSysId/Cd") == ["CHBCC"]
    assert find(document, "CstmrCdtTrfInitn/PmtInf/DbtrAgt/FinInstnId/"
                          "ClrSysMmbId/MmbId") == [DEBTOR_IBAN.replace(" ", "")[4:9]]


def test_the_IID_keeps_its_leading_zeros():
    """`00781` is a five-character field, not the number 781. Read through an
    int on the way out of the IBAN, so this is the assertion that the padding
    came back."""
    body = payment_body()
    body.pop("debtor_bic")
    member = find(build(body), "CstmrCdtTrfInitn/PmtInf/DbtrAgt/FinInstnId/"
                               "ClrSysMmbId/MmbId")
    assert len(member[0]) == 5, member


def test_a_non_swiss_debtor_with_no_bic_is_left_empty():
    """`CH21` is a Swiss rule and a German account is not a Swiss one. There is
    no IID to derive and nothing truthful to put there, so the element stays
    empty and a caller in that position supplies `debtor_bic`."""
    body = payment_body()
    body.pop("debtor_bic")
    body["debtor_iban"] = "DE89370400440532013000"
    document = build(body)

    assert pain001.schema_failures(document) == []
    agent = parse(document).find(
        f".//{{{pain001.NAMESPACE}}}DbtrAgt/{{{pain001.NAMESPACE}}}FinInstnId")
    assert list(agent) == []


def test_under_sepa_the_no_bic_convention_is_still_written():
    """The other half of the rule, and the reason it is a rule rather than a
    deletion.

    `Othr/Id` of `NOTPROVIDED` is what the EPC expects for an IBAN-only SEPA
    credit transfer, and a receiving bank in the euro area looks for it. What
    was wrong was applying it to a Swiss payment, not the convention itself --
    so the fix is a condition, and this is the branch a Swiss-only test would
    have silently deleted.
    """
    body = payment_body()
    body.pop("debtor_bic")
    document = build(body, payment_type=schemes.SchemeProfile(
        service_name="SCT", scope=None, service_level=schemes.Code("SEPA")))

    assert pain001.schema_failures(document) == []
    assert find(document, "CstmrCdtTrfInitn/PmtInf/DbtrAgt/FinInstnId/Othr/"
                          "Id") == [pain001.NOT_PROVIDED]


def test_the_declaration_and_the_convention_cannot_disagree():
    """`SvcLvl/Cd` of `SEPA` is what tells the bank which scheme this is, so it
    is what decides the conventions the rest of the document follows. Reading
    the declaration rather than guessing from a currency or an IBAN country is
    what stops a file claiming one scheme and being built for the other."""
    sepa = schemes.SchemeProfile(service_name="SCT", scope=None,
                                 service_level=schemes.Code("SEPA"))
    assert pain001.declares_sepa(sepa) is True
    # A proprietary code is by definition not the SEPA external code, even
    # spelled the same way -- `SvcLvl/Prtry` is a different element.
    assert pain001.declares_sepa(schemes.SchemeProfile(
        service_level=schemes.Code("SEPA", proprietary=True))) is False
    assert pain001.declares_sepa(schemes.DEFAULT_NORMAL) is False
    # No profile at all is the shape an unconfigured connection produces.
    assert pain001.declares_sepa(None) is False


def test_a_swiss_payment_identifies_no_agent_by_a_generic_other():
    """The refusal this came from, checked across every `FinInstnId` rather
    than the debtor's alone. `Othr` under `CtctDtls` is a different element and
    is how Swiss banks want the software named, so it stays."""
    document = build(payment_body(), software_version="0.3.1")
    tree = parse(document)

    for agent in tree.iter(f"{{{pain001.NAMESPACE}}}FinInstnId"):
        children = [etree.QName(child).localname for child in agent]
        assert "Othr" not in children, (
            f"a FinInstnId carries Othr ({children}), which a Swiss validator "
            "refuses")
    assert find(document, "CstmrCdtTrfInitn/GrpHdr/InitgPty/CtctDtls/Othr/"
                          "Id") == ["painfree", "0.3.1"]


def test_the_amount_carries_the_currency_and_its_minor_units():
    document = build(payment_body(transactions=[transfer(amount="100")]))
    tree = parse(document)
    amount = tree.xpath("//ns:InstdAmt", namespaces={"ns": pain001.NAMESPACE})[0]
    assert amount.text == "100.00"
    assert amount.get("Ccy") == "CHF"
    assert pain001.format_amount(decimal.Decimal("100"), "JPY") == "100"


def test_the_creation_timestamp_is_utc_and_second_precision():
    assert find(build(), "CstmrCdtTrfInitn/GrpHdr/CreDtTm") == [
        "2026-08-29T20:15:00+00:00"]


def test_a_naive_creation_timestamp_is_refused():
    with pytest.raises(ValueError, match="timezone-aware"):
        pain001.build(payments.PaymentInstruction(**payment_body()),
                      message_id=MESSAGE_ID,
                      created_at=_dt.datetime(2026, 8, 29, 20, 15))


def test_a_message_id_is_unique_and_fits_max35text():
    ids = {pain001.new_message_id() for _ in range(100)}
    assert len(ids) == 100
    assert all(len(value) <= 35 and value.startswith("PF") for value in ids)
