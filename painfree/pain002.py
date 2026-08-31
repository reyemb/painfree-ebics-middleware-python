"""`pain.002`, normalised to JSON: what the bank did with a payment we sent.

A `pain.002` is the answer to a `pain.001`, and it is a three-level document
because a rejection can happen at any of three levels: the whole message
(`OrgnlGrpInfAndSts`), one payment information block (`OrgnlPmtInfAndSts`), or
one transaction inside it (`TxInfAndSts`). A status at one level does not
imply anything about the others -- a message can be `PART` (partially accepted)
with one transaction `RJCT` and the rest `ACSP` -- so all three are kept rather
than collapsed into "the status".

The field that makes it useful is `OrgnlMsgId`: it is the `MsgId` this service
generated when the payment was accepted, and it is stored on `payment_order`.
This module still only reads -- it opens no database and decides no state --
but the value it reads is now acted on: :mod:`painfree.reconcile` resolves
`OrgnlMsgId` to an order and moves it, and `identification` below is that join
key rather than a field kept for later.

A report's *own* `MsgId` is kept too, as `report_identification`. Two reports
about one order are two documents -- a bank sends `PDNG` today and `ACSC`
tomorrow -- and without it the ingestion constraint would file the second as a
duplicate of the first and the final status would never be stored.

The reason codes are kept verbatim, code *and* proprietary code *and* the
originator's free text. `AC01` means "incorrect account number" to anyone with
the ISO list to hand, and the bank's own `AddtlInf` is what tells an operator
which account. Folding them into one message is how a support call becomes a
day's work -- the same rule the REST contract applies to EBICS return codes.

Amounts, as everywhere in this service, are :class:`decimal.Decimal` from the
document's digits and strings in the JSON. Never floats.
"""

from __future__ import annotations

from typing import Any

from lxml import etree

from painfree.isoxml import (DocumentUnreadable, amount, date_choice,
                             datetime_utc, iso_document, kid, kids, local,
                             message_type_of, path, text)

__all__ = ["NormalisedStatus", "normalise_pain002"]

#: The element that says this is a customer payment status report.
CONTAINER = "CstmrPmtStsRpt"


class NormalisedStatus:
    """One `pain.002`, in the shape the statement store writes.

    It carries the same attribute surface as
    :class:`painfree.camt.NormalisedStatement` so the store does not need two
    code paths for two message families -- the fields a status report has no
    equivalent for are simply ``None``.
    """

    __slots__ = ("message_type", "kind", "identification", "sequence_number",
                 "created_at", "from_datetime", "to_datetime", "iban",
                 "currency", "opening_balance", "closing_balance", "payload",
                 "entry_count", "report_identification")

    def __init__(self, message_type: str, payload: dict[str, Any],
                 identification: str | None, currency: str | None,
                 entry_count: int, report_identification: str | None = None
                 ) -> None:
        self.message_type = message_type
        self.kind = "payment_status"
        # The identity is the `MsgId` of the message this reports on, because
        # that is the value the order it answers is stored under.
        self.identification = identification
        # And this is the report's own `MsgId`, which is what tells a re-served
        # copy of one report from a genuinely later report about the same
        # order. `camt` has no equivalent and leaves it None.
        self.report_identification = report_identification
        self.sequence_number = None
        self.created_at = datetime_utc(payload["group_header"]["created_at"])
        self.from_datetime = None
        self.to_datetime = None
        self.iban = None
        self.currency = currency
        self.opening_balance = None
        self.closing_balance = None
        self.entry_count = entry_count
        self.payload = payload


def normalise_pain002(document: bytes | str | etree._Element) -> list[NormalisedStatus]:
    """Read one `pain.002` document. A list, so the store has one interface."""
    root = iso_document(document)
    message_type = message_type_of(root)
    container = next((child for child in root
                      if isinstance(child.tag, str) and local(child) == CONTAINER),
                     None)
    if container is None:
        raise DocumentUnreadable(f"{message_type} carries no <{CONTAINER}>")

    header = kid(container, "GrpHdr")
    original = kid(container, "OrgnlGrpInfAndSts")
    payments = [_payment(node)
                for node in kids(container, "OrgnlPmtInfAndSts")]
    transactions = [transaction
                    for payment in payments
                    for transaction in payment["transactions"]]

    payload = {
        "schema": "painfree.payment_status/1",
        "message_type": message_type,
        "kind": "payment_status",
        "group_header": {
            "message_identification": text(header, "MsgId"),
            "created_at": text(header, "CreDtTm"),
        },
        "original": {
            "message_identification": text(original, "OrgnlMsgId"),
            "message_name": text(original, "OrgnlMsgNmId"),
            "created_at": text(original, "OrgnlCreDtTm"),
            "transactions": text(original, "OrgnlNbOfTxs"),
            "control_sum": text(original, "OrgnlCtrlSum"),
            "status": text(original, "GrpSts"),
        },
        "reasons": _reasons(original),
        "payments": payments,
    }
    currency = next((t["currency"] for t in transactions if t["currency"]), None)
    return [NormalisedStatus(message_type, payload,
                             payload["original"]["message_identification"],
                             currency, len(transactions),
                             payload["group_header"]["message_identification"])]


def _payment(node: etree._Element) -> dict[str, Any]:
    return {
        "payment_information_id": text(node, "OrgnlPmtInfId"),
        "status": text(node, "PmtInfSts"),
        "transactions": [_transaction(child)
                         for child in kids(node, "TxInfAndSts")],
        "transactions_count": text(node, "OrgnlNbOfTxs"),
        "control_sum": text(node, "OrgnlCtrlSum"),
        "reasons": _reasons(node),
    }


def _transaction(node: etree._Element) -> dict[str, Any]:
    reference = kid(node, "OrgnlTxRef")
    instructed = amount(path(reference, "Amt", "InstdAmt"))
    return {
        "status_id": text(node, "StsId"),
        "instruction_id": text(node, "OrgnlInstrId"),
        "end_to_end_id": text(node, "OrgnlEndToEndId"),
        "uetr": text(node, "OrgnlUETR"),
        "status": text(node, "TxSts"),
        "acceptance_datetime": text(node, "AccptncDtTm"),
        "account_servicer_reference": text(node, "AcctSvcrRef"),
        "amount": None if instructed is None else format(instructed.value, "f"),
        "currency": None if instructed is None else instructed.currency,
        "requested_execution_date": date_choice(kid(reference, "ReqdExctnDt")),
        "reasons": _reasons(node),
    }


def _reasons(node: etree._Element | None) -> list[dict[str, Any]]:
    """Every `StsRsnInf`, code and proprietary code and free text all kept.

    A bank sends one or the other or both, and the free text is regularly the
    only part that names the field that was wrong.
    """
    reasons = []
    for info in kids(node, "StsRsnInf"):
        reason = kid(info, "Rsn")
        reasons.append({
            "code": text(reason, "Cd"),
            "proprietary": text(reason, "Prtry"),
            "originator": text(kid(info, "Orgtr"), "Nm"),
            "additional_information": [
                (child.text or "").strip()
                for child in kids(info, "AddtlInf") if (child.text or "").strip()
            ],
        })
    return reasons
