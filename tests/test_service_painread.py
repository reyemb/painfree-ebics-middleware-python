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
