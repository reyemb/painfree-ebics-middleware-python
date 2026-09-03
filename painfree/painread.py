"""Read back the `pain.001` an order was built from, for the console to show.

**Why read the document rather than store the fields.** An order row records
what the *service* needs: the state, the control sum, the currency, the EBICS
bookkeeping. Who is being paid is not any of that -- it is in the message, and
the message is already kept, verbatim, because it is what was signed and sent.

Adding `creditor_name` and `creditor_iban` columns would mean a migration, a
backfill of every order taken before it, and two records of one fact that can
then disagree. Reading the stored document has none of those: it is the same
bytes the bank got, it works for orders taken years ago, and it cannot drift
from what was actually sent, because it *is* what was actually sent.

The cost is an XML parse per order the console lists. The lists are paged, the
documents are a few kilobytes, and the alternative was a schema change to avoid
work nobody has measured.

**Nothing here validates.** The document was validated against the official
schema before it was stored, and re-checking on the way out would answer a
question already answered. A field that is missing comes back ``None`` and the
console shows a dash: a display path is never the place a payment fails.
"""

from __future__ import annotations

from dataclasses import dataclass

from lxml import etree

from painfree.pain001 import NAMESPACE

_NS = {"p": NAMESPACE}


@dataclass(frozen=True)
class Party:
    """One side of a transfer, as far as the document says."""

    name: str | None = None
    iban: str | None = None


@dataclass(frozen=True)
class Summary:
    """What a payment is *about*, for someone reading a list of them.

    ``creditor`` is the first transfer's, and ``extra`` counts the ones not
    shown. A batch has no single recipient, and picking one silently would read
    as though it did -- so the console renders "and 4 more" rather than a name
    that is only a seventh of the truth.
    """

    debtor: Party
    creditor: Party
    extra: int = 0

    @property
    def batch(self) -> bool:
        return self.extra > 0


def _text(node, path: str) -> str | None:
    found = node.find(path, _NS)
    if found is None or found.text is None:
        return None
    return found.text.strip() or None


def summarise(document: bytes | None) -> Summary | None:
    """The debtor and the first creditor, or ``None`` if it cannot be read.

    Broad `except` on purpose. This is called to draw a table cell, and the one
    outcome that must not happen is an order history that will not render
    because one stored message from an older build parses differently.
    """
    if not document:
        return None
    try:
        root = etree.fromstring(document)
        payment = root.find(".//p:PmtInf", _NS)
        if payment is None:
            return None
        transactions = payment.findall("p:CdtTrfTxInf", _NS)
        first = transactions[0] if transactions else None
        creditor = Party()
        if first is not None:
            creditor = Party(
                name=_text(first, "p:Cdtr/p:Nm"),
                iban=_text(first, "p:CdtrAcct/p:Id/p:IBAN"))
        return Summary(
            debtor=Party(name=_text(payment, "p:Dbtr/p:Nm"),
                         iban=_text(payment, "p:DbtrAcct/p:Id/p:IBAN")),
            creditor=creditor,
            extra=max(len(transactions) - 1, 0))
    except Exception:                                     # noqa: BLE001
        return None


__all__ = ["Party", "Summary", "summarise"]
