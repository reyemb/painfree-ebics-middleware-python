"""Reading a stored `pain.001` back, for the console to say who was paid.

The reader exists so an order list can show a recipient. That makes its most
important property a negative one: it is on a *display* path, so nothing it
meets may raise. An order history that will not render because one stored
message from an older build parses differently is a worse outcome than a row
showing a dash.
"""

from __future__ import annotations

import datetime as _dt

from painfree import pain001, payments
from painfree.painread import summarise


def _instruction(count: int = 1) -> payments.PaymentInstruction:
    return payments.PaymentInstruction.model_validate({
        "debtor": {"name": "MUSTER AG"},
        "debtor_iban": "CH5604835012345678009",
        "requested_execution_date": "2026-09-30",
        "transactions": [
            {"amount": "42.00", "currency": "CHF",
             "creditor": {"name": f"Robert Schneider AG {index}"},
             "creditor_iban": "CH4821966000009613388",
             "remittance_information": f"Invoice {index}"}
            for index in range(count)
        ],
    })


def _document(count: int = 1) -> bytes:
    return pain001.build(
        _instruction(count), message_id="MSG-1",
        payment_information_id="PMT-1",
        created_at=_dt.datetime(2026, 9, 3, 12, 0, tzinfo=_dt.timezone.utc))


def test_the_recipient_and_the_debit_account_come_back():
    summary = summarise(_document())
    assert summary is not None
    assert summary.creditor.name == "Robert Schneider AG 0"
    assert summary.creditor.iban == "CH4821966000009613388"
    assert summary.debtor.name == "MUSTER AG"
    assert summary.debtor.iban == "CH5604835012345678009"
    assert not summary.batch
    assert summary.extra == 0


def test_a_batch_names_the_first_and_counts_the_rest():
    # Picking one recipient for a batch and showing it alone would read as
    # though the payment had one. The count is what makes it honest.
    summary = summarise(_document(5))
    assert summary is not None
    assert summary.creditor.name == "Robert Schneider AG 0"
    assert summary.batch
    assert summary.extra == 4


def test_nothing_a_display_path_meets_may_raise():
    for document in (None, b"", b"not xml at all", b"<Document/>",
                     b"<?xml version='1.0'?><Document><PmtInf/></Document>",
                     "<Document/>".encode("utf-16")):
        summarise(document)          # must not raise


def test_an_unreadable_document_is_none_rather_than_a_blank_summary():
    # None and "a payment with no recipient" are different things, and the
    # template renders them differently: the block is hidden, not shown empty.
    assert summarise(b"not xml at all") is None
    assert summarise(None) is None


def test_a_document_with_no_transactions_still_names_the_debtor():
    # `CdtTrfTxInf` is what the schema requires; a message that somehow has
    # none should still say whose account it draws on rather than vanish.
    document = _document().replace(b"</PmtInf>", b"</PmtInf>")
    summary = summarise(document)
    assert summary is not None
    assert summary.debtor.iban == "CH5604835012345678009"


def test_every_transfer_comes_back_with_the_key_a_bank_answers_by():
    """A status report names `E2E-0002`, so the reader has to hold that key.

    The whole message, not the first transfer: the page that puts a bank's
    verdict beside the payment it is about needs a row per transfer, and the
    row is found by its end-to-end reference.
    """
    summary = summarise(_document(3))
    assert summary is not None
    assert len(summary.transfers) == 3
    assert summary.payment_information_id == "PMT-1"
    assert summary.execution_date == "2026-09-30"
    second = summary.transfers[1]
    assert second.creditor.name == "Robert Schneider AG 1"
    assert second.creditor.iban == "CH4821966000009613388"
    assert second.remittance == "Invoice 1"
    # The digits the document carries, unparsed. A float here would be a
    # double between the signed message and the screen.
    assert second.amount == "42.00" and isinstance(second.amount, str)
    assert second.currency == "CHF"
    assert second.end_to_end_id


def test_a_structured_reference_comes_back_whichever_element_carried_it():
    """`QRR` is proprietary and `SCOR` is an ISO code. A reader wants neither fact."""
    instruction = payments.PaymentInstruction.model_validate({
        "debtor": {"name": "MUSTER AG"},
        "debtor_iban": "CH5604835012345678009",
        "requested_execution_date": "2026-09-30",
        "transactions": [
            {"amount": "3949.75", "currency": "CHF",
             "creditor": {"name": "Robert Schneider AG"},
             "creditor_iban": "CH4431999123000889012",
             "instruction_id": "INSTR-0001",
             "end_to_end_id": "E2E-0001",
             "reference": {"type": "QRR",
                           "reference": "210000000003139471430009017"}},
        ],
    })
    document = pain001.build(
        instruction, message_id="MSG-2", payment_information_id="PMT-2",
        created_at=_dt.datetime(2026, 9, 3, 12, 0, tzinfo=_dt.timezone.utc))
    transfer = summarise(document).transfers[0]
    assert transfer.reference_type == "QRR"
    assert transfer.reference == "210000000003139471430009017"
    assert transfer.instruction_id == "INSTR-0001"
    assert transfer.end_to_end_id == "E2E-0001"


def test_a_transfer_with_no_remittance_and_no_reference_reads_as_absent():
    """Absent is `None`, so a template can ask once and show a dash."""
    transfer = summarise(_document()).transfers[0]
    assert transfer.reference is None and transfer.reference_type is None
