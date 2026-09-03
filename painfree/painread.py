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
class Transfer:
    """One `CdtTrfTxInf`: who is paid, how much, and under which reference.

    The references are here because they are what a `pain.002` answers *by*.
    A bank reports the status of `E2E-0002`, not of "the second transfer", so
    a page that means to put the bank's verdict beside the payment it is about
    has to hold the same key the bank quotes.
    """

    creditor: Party
    amount: str | None = None
    currency: str | None = None
    end_to_end_id: str | None = None
    instruction_id: str | None = None
    remittance: str | None = None
    reference_type: str | None = None
    reference: str | None = None


@dataclass(frozen=True)
class Summary:
    """What a payment is *about*, for someone reading a list of them.

    ``transfers`` is every `CdtTrfTxInf` in the message, in document order.
    Reading all of them costs the same parse as reading one, and the page that
    puts a status report beside the payment it answers needs every row rather
    than the first.
    """

    debtor: Party
    transfers: tuple[Transfer, ...] = ()
    payment_information_id: str | None = None
    execution_date: str | None = None

    @property
    def creditor(self) -> Party:
        """The first transfer's, for a list that has room for one name.

        A batch has no single recipient, and picking one silently would read as
        though it did -- so the console renders "and 4 more" beside this rather
        than a name that is only a seventh of the truth.
        """
        return self.transfers[0].creditor if self.transfers else Party()

    @property
    def extra(self) -> int:
        """How many transfers :attr:`creditor` does not name."""
        return max(len(self.transfers) - 1, 0)

    @property
    def batch(self) -> bool:
        return self.extra > 0


def _text(node, path: str) -> str | None:
    """The text under ``path``, or ``None`` -- including when ``node`` is None.

    An absent parent is the ordinary case here: a transfer with no structured
    reference has no `CdtrRefInf` to look under, and the caller asking anyway
    is what keeps the reading of one flat.
    """
    return _own_text(node.find(path, _NS)) if node is not None else None


def _own_text(node) -> str | None:
    if node is None or node.text is None:
        return None
    return node.text.strip() or None


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
        return Summary(
            debtor=Party(name=_text(payment, "p:Dbtr/p:Nm"),
                         iban=_text(payment, "p:DbtrAcct/p:Id/p:IBAN")),
            transfers=tuple(_transfer(node) for node
                            in payment.findall("p:CdtTrfTxInf", _NS)),
            payment_information_id=_text(payment, "p:PmtInfId"),
            execution_date=_text(payment, "p:ReqdExctnDt/p:Dt"))
    except Exception:                                     # noqa: BLE001
        return None


def _transfer(node) -> Transfer:
    """One transfer, with the amount left as the digits the document carries.

    ``1234.56`` stays a string all the way to the template, where the locale
    formatter turns it into something a reader recognises. Parsing it to a
    float here to "have a number" would put a double between the signed
    document and the screen, which is the one thing the stored digits exist to
    prevent.
    """
    amount = node.find("p:Amt/p:InstdAmt", _NS)
    reference = node.find("p:RmtInf/p:Strd/p:CdtrRefInf", _NS)
    return Transfer(
        creditor=Party(name=_text(node, "p:Cdtr/p:Nm"),
                       iban=_text(node, "p:CdtrAcct/p:Id/p:IBAN")),
        amount=_own_text(amount),
        currency=amount.get("Ccy") if amount is not None else None,
        end_to_end_id=_text(node, "p:PmtId/p:EndToEndId"),
        instruction_id=_text(node, "p:PmtId/p:InstrId"),
        remittance=_text(node, "p:RmtInf/p:Ustrd"),
        # `QRR` is proprietary and `SCOR` is an ISO code, so the type is in one
        # of two elements. Which one it was is not a distinction a reader needs.
        reference_type=(_text(reference, "p:Tp/p:CdOrPrtry/p:Prtry")
                        or _text(reference, "p:Tp/p:CdOrPrtry/p:Cd")),
        reference=_text(reference, "p:Ref"))


__all__ = ["Party", "Summary", "Transfer", "summarise"]
