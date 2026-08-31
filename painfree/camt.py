"""`camt.052`, `camt.053` and `camt.054`, normalised to one JSON shape.

Three ISO 20022 messages, one parser, because underneath the three container
elements they are the same document: a group header, one or more account
reports, and inside each of those a list of balances and a list of `Ntry`
elements with the same children in the same places. What differs is the word --
`BkToCstmrAcctRpt` holds `Rpt`, `BkToCstmrStmt` holds `Stmt`,
`BkToCstmrDbtCdtNtfctn` holds `Ntfctn` -- and what the three are *for*: a report
is intraday, a statement is end-of-day, a notification is a single advice.
Consumers should not have to write three parsers to learn the same five facts,
so they get one shape and a `kind` that says which of the three it came from.
The shape is a contract this repo owns.

**Amounts are never floats.** Every `Amt` becomes a :class:`decimal.Decimal`
built from the digits in the document and is serialised back out as a string,
scale intact. There is no point in this module where a monetary value passes
through a binary float, and there is a test that fails if one ever does.

**Reading is namespace-agnostic, by local name** -- see :mod:`painfree.isoxml`
for why, and for the three rules every lookup here obeys. What is *not* guessed
is the message type: it is read off the document's own namespace, so a schedule
configured with the wrong `MsgName` cannot file a `camt.053` as something else.

**Missing is not empty.** Everything optional in the schema is optional here and
arrives as ``None`` rather than as ``""``; a consumer branching on a falsy value
gets the same answer either way, and one branching on ``is None`` gets the truth.
"""

from __future__ import annotations

import datetime as _dt
import decimal
from dataclasses import dataclass, field
from typing import Any

from lxml import etree

from painfree.isoxml import (Amount, DocumentUnreadable, amount, boolean,
                             date_choice, datetime_utc, iso_document, joined,
                             kid, kids, local, message_type_of, path, text)

__all__ = [
    "CONTAINERS",
    "Entry",
    "NormalisedStatement",
    "normalise_camt",
]

#: The container element of each message, the word this repo files it under,
#: and the per-account element inside it.
CONTAINERS = {
    "BkToCstmrAcctRpt": ("report", "Rpt"),
    "BkToCstmrStmt": ("statement", "Stmt"),
    "BkToCstmrDbtCdtNtfctn": ("notification", "Ntfctn"),
}

#: The two values `CdtDbtInd` may take, spelled the way the JSON contract does.
#: The abbreviations are the wire's; a consumer reading `credit` does not have
#: to know that `CRDT` was not `CDIT`.
INDICATORS = {"CRDT": "credit", "DBIT": "debit"}

#: `Bal/Tp/CdOrPrtry/Cd` values that are the balance a statement opens and
#: closes on, in the order they are preferred. `PRCD` (previous closing) is
#: what many banks send in place of `OPBD`, and reading only one of the two
#: loses the opening balance on half the banks there are.
OPENING_BALANCES = ("OPBD", "PRCD", "OPAV")
CLOSING_BALANCES = ("CLBD", "CLAV")


@dataclass(frozen=True, slots=True)
class Entry:
    """One booked or pending movement, with its transaction details."""

    data: dict[str, Any]

    @property
    def amount(self) -> decimal.Decimal:
        return decimal.Decimal(self.data["amount"])

    @property
    def signed_amount(self) -> decimal.Decimal:
        """Positive for a credit, negative for a debit. Exact, either way."""
        value = self.amount
        return -value if self.data["credit_debit"] == "debit" else value


@dataclass(frozen=True, slots=True)
class NormalisedStatement:
    """One account report, statement or notification, ready to be stored."""

    message_type: str
    kind: str
    identification: str | None
    sequence_number: str | None
    created_at: _dt.datetime | None
    from_datetime: _dt.datetime | None
    to_datetime: _dt.datetime | None
    iban: str | None
    currency: str | None
    opening_balance: decimal.Decimal | None
    closing_balance: decimal.Decimal | None
    entries: list[Entry] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)
    #: A `pain.002` has a second identification -- its own `MsgId`, beside the
    #: `MsgId` it reports on -- and the ingestion identity needs both. A `camt`
    #: statement has only the one, so this stays ``None`` and the identity is
    #: unchanged. See :func:`painfree.statements.document_key`.
    report_identification: str | None = None

    @property
    def entry_count(self) -> int:
        return len(self.entries)

    def total(self) -> decimal.Decimal:
        """The sum of the entries, credits positive. Decimal arithmetic only."""
        return sum((entry.signed_amount for entry in self.entries),
                   decimal.Decimal(0))


def normalise_camt(document: bytes | str | etree._Element
                   ) -> list[NormalisedStatement]:
    """Read one `camt` document into one normalised statement per account.

    A `camt` message may carry several `Stmt` elements -- several accounts, or
    several days of one account -- and each becomes its own row, because each
    has its own identification and its own balances. Returning a list rather
    than merging them is what keeps that true.
    """
    root = iso_document(document)
    message_type = message_type_of(root)
    container = next((child for child in root if isinstance(child.tag, str)
                      and local(child) in CONTAINERS), None)
    if container is None:
        raise DocumentUnreadable(
            f"{message_type} carries none of {', '.join(sorted(CONTAINERS))}")
    kind, per_account = CONTAINERS[local(container)]

    header = kid(container, "GrpHdr")
    group = {
        "message_identification": text(header, "MsgId"),
        "created_at": text(header, "CreDtTm"),
        "additional_information": text(header, "AddtlInf"),
    }
    return [_account(node, message_type, kind, group)
            for node in kids(container, per_account)]


# --- one account -----------------------------------------------------------


def _account(node: etree._Element, message_type: str, kind: str,
             group: dict[str, Any]) -> NormalisedStatement:
    account = kid(node, "Acct")
    iban = text(path(account, "Id"), "IBAN")
    balances = [_balance(balance) for balance in kids(node, "Bal")]
    opening = _pick_balance(balances, OPENING_BALANCES)
    closing = _pick_balance(balances, CLOSING_BALANCES)
    period = kid(node, "FrToDt")
    entries = [Entry(_entry(entry)) for entry in kids(node, "Ntry")]

    payload: dict[str, Any] = {
        "schema": "painfree.statement/1",
        "message_type": message_type,
        "kind": kind,
        "group_header": group,
        "identification": text(node, "Id"),
        "sequence_number": text(node, "ElctrncSeqNb"),
        "legal_sequence_number": text(node, "LglSeqNb"),
        "created_at": text(node, "CreDtTm"),
        "from": text(period, "FrDtTm"),
        "to": text(period, "ToDtTm"),
        "account": {
            "iban": iban,
            "other_identification": text(path(account, "Id", "Othr"), "Id"),
            "currency": text(account, "Ccy"),
            "owner": text(path(account, "Ownr"), "Nm"),
            "servicer_bic": text(path(account, "Svcr", "FinInstnId"), "BICFI"),
        },
        "balances": [balance for balance, _ in balances],
        "opening_balance": opening[0] if opening else None,
        "closing_balance": closing[0] if closing else None,
        "summary": _summary(kid(node, "TxsSummry")),
        "entries": [entry.data for entry in entries],
    }
    return NormalisedStatement(
        message_type=message_type, kind=kind,
        identification=payload["identification"],
        sequence_number=payload["sequence_number"],
        created_at=datetime_utc(payload["created_at"]),
        from_datetime=datetime_utc(payload["from"]),
        to_datetime=datetime_utc(payload["to"]),
        iban=iban, currency=payload["account"]["currency"],
        opening_balance=opening[1] if opening else None,
        closing_balance=closing[1] if closing else None,
        entries=entries, payload=payload,
    )


def _balance(node: etree._Element) -> tuple[dict[str, Any], decimal.Decimal | None]:
    """One `Bal`, and its signed value so a caller does not re-derive it."""
    value = amount(kid(node, "Amt"))
    indicator = INDICATORS.get(text(node, "CdtDbtInd") or "")
    signed = None
    if value is not None:
        signed = -value.value if indicator == "debit" else value.value
    kind = path(node, "Tp", "CdOrPrtry")
    data = {
        "type": text(kind, "Cd") or text(kind, "Prtry"),
        "credit_debit": indicator,
        "date": date_choice(kid(node, "Dt")),
        **_money(value),
    }
    return data, signed


def _pick_balance(balances: list[tuple[dict[str, Any], decimal.Decimal | None]],
                  codes: tuple[str, ...]):
    """The first balance whose type is one of ``codes``, in the order given."""
    for code in codes:
        for data, signed in balances:
            if data["type"] == code:
                return data, signed
    return None


def _summary(node: etree._Element | None) -> dict[str, Any]:
    if node is None:
        return {"entries": None, "credits": None, "debits": None}

    def total(name: str) -> dict[str, Any] | None:
        child = kid(node, name)
        if child is None:
            return None
        value = amount(kid(child, "Sum"))
        return {"count": text(child, "NbOfNtries"),
                "sum": format(value.value, "f") if value else None}

    return {"entries": text(kid(node, "TtlNtries"), "NbOfNtries"),
            "credits": total("TtlCdtNtries"), "debits": total("TtlDbtNtries")}


# --- one entry -------------------------------------------------------------


def _entry(node: etree._Element) -> dict[str, Any]:
    code = kid(node, "BkTxCd")
    domain = kid(code, "Domn")
    return {
        "reference": text(node, "NtryRef"),
        **_money(amount(kid(node, "Amt"))),
        "credit_debit": INDICATORS.get(text(node, "CdtDbtInd") or ""),
        "reversal": boolean(text(node, "RvslInd")),
        "status": text(kid(node, "Sts"), "Cd") or text(node, "Sts"),
        "booking_date": date_choice(kid(node, "BookgDt")),
        "value_date": date_choice(kid(node, "ValDt")),
        "account_servicer_reference": text(node, "AcctSvcrRef"),
        "bank_transaction_code": {
            "domain": text(domain, "Cd"),
            "family": text(path(domain, "Fmly"), "Cd"),
            "sub_family": text(path(domain, "Fmly"), "SubFmlyCd"),
            "proprietary": text(path(code, "Prtry"), "Cd"),
        },
        "additional_information": text(node, "AddtlNtryInf"),
        "transactions": [_transaction(details, text(node, "CdtDbtInd"))
                         for group in kids(node, "NtryDtls")
                         for details in kids(group, "TxDtls")],
    }


def _transaction(node: etree._Element, entry_indicator: str | None) -> dict[str, Any]:
    """One `TxDtls`: the payment inside the booking.

    ``counterparty`` is the party on the *other* side of the movement -- the
    creditor of a debit, the debtor of a credit. Emitting one party under one
    name is what lets `camt.053` and `camt.054` be read by the same consumer
    code; ``counterparty_role`` says which of the two it was, so nothing is
    lost by the convenience.
    """
    references = kid(node, "Refs")
    indicator = text(node, "CdtDbtInd") or entry_indicator or ""
    role = "creditor" if INDICATORS.get(indicator) == "debit" else "debtor"
    remittance = kid(node, "RmtInf")
    reference_info = path(remittance, "Strd", "CdtrRefInf")
    reference_kind = path(reference_info, "Tp", "CdOrPrtry")

    return {
        **_money(amount(kid(node, "Amt"))),
        "credit_debit": INDICATORS.get(indicator),
        "end_to_end_id": text(references, "EndToEndId"),
        "instruction_id": text(references, "InstrId"),
        "message_identification": text(references, "MsgId"),
        "payment_information_id": text(references, "PmtInfId"),
        "account_servicer_reference": text(references, "AcctSvcrRef"),
        "uetr": text(references, "UETR"),
        "instructed_amount": _optional_money(path(node, "AmtDtls", "InstdAmt")),
        "counterparty_role": role,
        "counterparty": _party(kid(node, "RltdPties"), kid(node, "RltdAgts"), role),
        "reference": {
            "type": text(reference_kind, "Cd") or text(reference_kind, "Prtry"),
            "reference": text(reference_info, "Ref"),
        },
        "remittance_information": joined(kids(remittance, "Ustrd")),
        "additional_information": text(node, "AddtlTxInf"),
    }


def _party(parties: etree._Element | None, agents: etree._Element | None,
           role: str) -> dict[str, Any]:
    """The named side of one transaction: who, which account, which bank.

    The name sits one level deeper from `camt.05x.001.08` onwards -- `Cdtr` is
    a choice of `Pty` or `Agt` there and was the party itself before it -- so
    both places are read. A parser that knew only the newer one would return a
    nameless counterparty against an older bank rather than an error.
    """
    prefix = "Cdtr" if role == "creditor" else "Dbtr"
    party = kid(parties, prefix)
    return {
        "name": text(kid(party, "Pty"), "Nm") or text(party, "Nm"),
        "iban": text(path(parties, prefix + "Acct", "Id"), "IBAN"),
        "bic": text(path(agents, prefix + "Agt", "FinInstnId"), "BICFI"),
    }


def _money(value: Amount | None) -> dict[str, Any]:
    return value.as_json() if value else {"amount": None, "currency": None}


def _optional_money(node: etree._Element | None) -> dict[str, Any] | None:
    value = amount(kid(node, "Amt"))
    return value.as_json() if value else None
