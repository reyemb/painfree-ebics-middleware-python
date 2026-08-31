"""Reading an ISO 20022 document: elements, dates, and amounts that stay exact.

Shared by :mod:`painfree.camt` and :mod:`painfree.pain002`, which read two
different message families out of the same XML dialect. Nothing here knows what
a statement is; it knows how to walk a `Document` and how to turn its text into
Python values without losing anything.

Three rules, and they are the whole module:

**By local name, never by namespace.** The documents this service reads span
several ISO versions with identical element names, and keying on the namespace
would make the parser refuse `camt.053.001.09` for no better reason than that
it was written against `.08`. The *message type* is still read off the
namespace -- that is the document saying what it is -- but nothing is looked up
by it.

**By path, never by ``//``.** ``//Nm`` finds the debtor's name, the creditor's
name and the account owner's, and returns whichever comes first in document
order. Every lookup here is anchored on the element it belongs to.

**Amounts are decimals from digits.** ``Decimal(text)``, never ``float(text)``,
and the scale the bank sent is kept: `1.10` is `1.10`. A binary float cannot
represent `0.1`, and a statement is what a customer's balance is checked
against.
"""

from __future__ import annotations

import datetime as _dt
import decimal
from dataclasses import dataclass
from typing import Any

from lxml import etree

from painfree.errors import ServiceError

__all__ = [
    "Amount",
    "DocumentUnreadable",
    "amount",
    "boolean",
    "date_choice",
    "datetime_utc",
    "iso_document",
    "joined",
    "kid",
    "kids",
    "local",
    "message_type_of",
    "path",
    "text",
]


class DocumentUnreadable(ServiceError):
    """The bytes are not an ISO 20022 document this service can read."""

    status_code = 422
    code = "unreadable_document"


@dataclass(frozen=True, slots=True)
class Amount:
    """An exact amount and its currency. The pair, always -- never the number."""

    value: decimal.Decimal
    currency: str | None = None

    def as_json(self) -> dict[str, Any]:
        return {"amount": format(self.value, "f"), "currency": self.currency}


def iso_document(document: bytes | str | etree._Element) -> etree._Element:
    """The `<Document>` element, whatever it arrived wrapped in."""
    if isinstance(document, etree._Element):
        root = document
    else:
        try:
            root = etree.fromstring(
                document.encode() if isinstance(document, str) else document)
        except etree.XMLSyntaxError as exc:
            raise DocumentUnreadable(
                f"the document is not well-formed XML: {exc}") from exc
    if local(root) == "Document":
        return root
    # Some banks wrap the message in a business application header envelope.
    # The `Document` inside it is the message; the header is addressing.
    found = root.xpath("//*[local-name()='Document']")
    if not found:
        raise DocumentUnreadable(f"<{local(root)}> is not an ISO 20022 <Document>")
    return found[0]


def message_type_of(root: etree._Element) -> str:
    """`camt.053.001.08`, read off the document's own namespace.

    The namespace is the document saying what it is. The BTF that asked for it
    is configuration and can be wrong; this cannot.
    """
    namespace = etree.QName(root).namespace or ""
    tail = namespace.rsplit(":", 1)[-1]
    if not tail:
        raise DocumentUnreadable(
            "the document carries no namespace to identify it by")
    return tail


def local(node: etree._Element) -> str:
    return etree.QName(node).localname


def kids(node: etree._Element | None, name: str) -> list[etree._Element]:
    return [] if node is None else [c for c in node
                                    if isinstance(c.tag, str) and local(c) == name]


def kid(node: etree._Element | None, name: str) -> etree._Element | None:
    found = kids(node, name)
    return found[0] if found else None


def path(node: etree._Element | None, *names: str) -> etree._Element | None:
    for name in names:
        node = kid(node, name)
        if node is None:
            return None
    return node


def text(node: etree._Element | None, name: str) -> str | None:
    """The text of one named child. Empty and absent mean the same thing."""
    child = kid(node, name)
    if child is None:
        return None
    return (child.text or "").strip() or None


def joined(nodes: list[etree._Element]) -> str | None:
    """Several elements are one text; the schema splits remittance at 140."""
    parts = [(node.text or "").strip() for node in nodes]
    return " ".join(part for part in parts if part) or None


def amount(node: etree._Element | None) -> Amount | None:
    """One amount element. ``Decimal`` from the digits, currency from `@Ccy`."""
    if node is None:
        return None
    value = (node.text or "").strip()
    if not value:
        return None
    try:
        parsed = decimal.Decimal(value)
    except decimal.InvalidOperation as exc:
        raise DocumentUnreadable(f"{value!r} is not an amount") from exc
    return Amount(parsed, node.get("Ccy"))


def boolean(value: str | None) -> bool | None:
    if value is None:
        return None
    return value.strip().lower() in ("true", "1")


def date_choice(node: etree._Element | None) -> str | None:
    """A `Dt`/`DtTm` choice, kept as the ISO string the document used.

    A bank may send a date or a timestamp and both are ISO 8601. Narrowing a
    timestamp to a date here would throw away the only thing that separates two
    bookings on one day, so the contract says "an ISO 8601 date or date-time"
    and the value goes through untouched.
    """
    if node is None:
        return None
    return text(node, "Dt") or text(node, "DtTm")


def datetime_utc(value: str | None) -> _dt.datetime | None:
    """An aware UTC datetime, for the columns that index on time."""
    if not value:
        return None
    try:
        parsed = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # ISO 20022 allows a local date-time with no offset. Reading it as UTC
        # is a decision, not a fact -- but the alternative is a naive value the
        # storage layer refuses, and the original string stays in the payload.
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed.astimezone(_dt.timezone.utc)
