"""What a bank sends back, reduced to the fields the transaction protocol needs.

An ``ebicsResponse`` carries three unrelated things at once, and reading it as
one thing is how a client ends up retrying a transaction that succeeded:

* **two return codes.** ``header/mutable/ReturnCode`` is the *technical* status
  of the transaction step; ``body/ReturnCode`` is the *bank-technical* status of
  the order. A download that ends with ``011000`` in the header has finished
  correctly -- the code is not an error -- while a ``000000`` header over a
  non-zero body code means the protocol worked and the order did not.
* **the transaction step.** ``TransactionID``, ``TransactionPhase``,
  ``NumSegments`` and ``SegmentNumber`` are how the client knows what to send
  next, and are the only state the bank keeps on our behalf.
* **the payload**, when there is one: one order-data segment and, in the
  initialisation phase, the transaction key it is encrypted under.

This module reads all of that and hands the two codes to
:mod:`painfree.ebics3.returncodes`, which says what they mean. The split is on
purpose: reading is about where a value sits in the document, interpreting is
about what the digits are worth, and only the first of the two has to change
when a bank sends a shape nobody has seen before. The four codes named below
stay here because the *protocol* branches on them -- they decide which message
comes next -- while the table decides what a caller is told.

Parsing is namespace-agnostic by local name, because the corpus this is proved
against spans H003, H004 and H005 and the shapes are identical across them.
Each field is addressed on its full path, not by ``//ReturnCode``: the two
return codes are siblings in different subtrees and a loose XPath silently
returns whichever comes first in document order.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from lxml import etree

from .canon import parse_xml
from .errors import BankRefusedError, DocumentError
from .returncodes import ReturnCode, lookup

__all__ = [
    "EBICS_DOWNLOAD_POSTPROCESS_DONE",
    "EBICS_DOWNLOAD_POSTPROCESS_SKIPPED",
    "EBICS_OK",
    "EBICS_TX_RECOVERY_SYNC",
    "BankResponse",
    "ResponseStatus",
    "classify",
    "parse_response",
]

#: No technical or business error occurred.
EBICS_OK = "000000"

#: Positive acknowledgement received -- the download is finished at the bank's
#: end. It arrives in the header of the *receipt* response and is a success,
#: which is why a client that treats "not 000000" as failure reports every
#: completed download as an error.
EBICS_DOWNLOAD_POSTPROCESS_DONE = "011000"

#: Negative acknowledgement received: the transaction ended without the
#: download being marked delivered. What the bank answers to ``ReceiptCode`` 1.
EBICS_DOWNLOAD_POSTPROCESS_SKIPPED = "011001"

#: Synchronisation necessary for transaction recovery. The response also
#: carries the bank's own view of the last segment that got through, and the
#: transaction continues from there rather than from where the client thought
#: it was.
EBICS_TX_RECOVERY_SYNC = "061101"


@dataclass(frozen=True)
class BankResponse:
    """One ``ebicsResponse``, reduced to fields and nothing else.

    Everything is optional because almost everything is conditional in the
    schema: an initialisation response has no ``SegmentNumber`` on an upload
    and does have one on a download, a receipt response has neither that nor a
    payload, and an unsecured response has no transaction at all.
    """

    header_return_code: str | None = None
    body_return_code: str | None = None
    report_text: str | None = None
    transaction_id: str | None = None
    transaction_phase: str | None = None
    num_segments: int | None = None
    segment_number: int | None = None
    last_segment: bool | None = None
    order_id: str | None = None
    order_data: str | None = None
    transaction_key_encrypted: bytes | None = None

    @property
    def status(self) -> "ResponseStatus":
        """The two return codes, interpreted."""
        return classify(self)

    @property
    def ok(self) -> bool:
        """Did this step succeed, in both senses of the word?

        ``011000`` counts, and so does every other code the table calls benign:
        they are what the protocol looks like when it is working.
        """
        return self.status.ok

    @property
    def needs_recovery(self) -> bool:
        """Is the bank asking us to resume from *its* recovery point?"""
        return self.status.needs_recovery


@dataclass(frozen=True)
class ResponseStatus:
    """Both return codes of one response, interpreted, and the bank's own words.

    The two are kept apart because they answer different questions and a
    caller acts on both: ``technical`` is how the transaction *step* went,
    ``business`` how the *order* went. ``decisive`` is the one that settles the
    response -- the technical code unless it is ``EBICS_OK``, in which case the
    order's code is what is left to say.
    """

    technical: ReturnCode | None
    business: ReturnCode | None
    #: `header/mutable/ReportText`, and **only** that. H005 gives the body a
    #: `ReturnCode` and no text of its own, so this sentence describes the
    #: technical code and nothing else.
    report_text: str | None = None

    @property
    def decisive(self) -> ReturnCode | None:
        if self.technical is not None and not self.technical.is_ok:
            return self.technical
        return self.business or self.technical

    @property
    def decisive_report_text(self) -> str | None:
        """The bank's sentence, when it describes the code that failed.

        An upload can pass the header and fail the body -- a refused transfer
        phase is exactly that shape -- and then `report_text` is the *header's*
        text, which says `[EBICS_OK] OK` because the header was fine. Attaching
        it to the body's refusal produced an order page, an API response and a
        webhook that described a rejected payment as `OK`: two structured
        fields right and the one sentence a human reads wrong, which is the
        worst of the three arrangements.

        The body has no `ReportText` in H005, so there is nothing truer to put
        there. `None` is the honest answer, and the code name --
        `EBICS_SIGNATURE_VERIFICATION_FAILED` -- is what says what happened.
        """
        code = self.decisive
        if code is None or code is self.technical:
            return self.report_text
        return None

    @property
    def ok(self) -> bool:
        """Nothing here is a refusal -- which is not the same as everything being 000000."""
        return all(code.is_benign or code.needs_recovery
                   for code in (self.technical, self.business) if code is not None)

    @property
    def needs_recovery(self) -> bool:
        return any(code.needs_recovery
                   for code in (self.technical, self.business) if code is not None)

    @property
    def ends_transaction(self) -> bool:
        """Is there nothing left to send -- normally, not because of a refusal?"""
        return any(code.ends_transaction
                   for code in (self.technical, self.business) if code is not None)

    def raise_for_status(self, context: str = "the bank refused") -> None:
        """Raise :class:`BankRefusedError` if, and only if, this is a refusal."""
        code = self.decisive
        if code is None or not code.raises:
            return
        text = self.decisive_report_text
        detail = f": {text}" if text else ""
        raise BankRefusedError(f"{context} -- {code}{detail}",
                               return_code=code.code, name=code.name,
                               report_text=text,
                               retryable=code.is_retryable,
                               terminal=code.is_terminal)


def classify(response: BankResponse) -> ResponseStatus:
    """Interpret both return codes of a parsed response."""
    return ResponseStatus(technical=lookup(response.header_return_code),
                          business=lookup(response.body_return_code),
                          report_text=response.report_text)


def parse_response(document: bytes | str | etree._Element) -> BankResponse:
    """Read one bank response. Raises only when handed something that is not one."""
    root = document if isinstance(document, etree._Element) else parse_xml(document)
    if not etree.QName(root).localname.startswith("ebics"):
        raise DocumentError(
            f"<{etree.QName(root).localname}> is not an EBICS response envelope")

    segment = _first(root, "/*/*[local-name()='header']"
                           "/*[local-name()='mutable']"
                           "/*[local-name()='SegmentNumber']")
    key = _text(root, "/*/*[local-name()='body']"
                      "/*[local-name()='DataTransfer']"
                      "/*[local-name()='DataEncryptionInfo']"
                      "/*[local-name()='TransactionKey']")

    return BankResponse(
        header_return_code=_text(root, "/*/*[local-name()='header']"
                                       "/*[local-name()='mutable']"
                                       "/*[local-name()='ReturnCode']"),
        body_return_code=_text(root, "/*/*[local-name()='body']"
                                     "/*[local-name()='ReturnCode']"),
        report_text=_text(root, "/*/*[local-name()='header']"
                                "/*[local-name()='mutable']"
                                "/*[local-name()='ReportText']"),
        transaction_id=_text(root, "/*/*[local-name()='header']"
                                   "/*[local-name()='static']"
                                   "/*[local-name()='TransactionID']"),
        transaction_phase=_text(root, "/*/*[local-name()='header']"
                                      "/*[local-name()='mutable']"
                                      "/*[local-name()='TransactionPhase']"),
        num_segments=_int(_text(root, "/*/*[local-name()='header']"
                                      "/*[local-name()='static']"
                                      "/*[local-name()='NumSegments']")),
        segment_number=_int(_clean(segment.text) if segment is not None else None),
        last_segment=(None if segment is None
                      else segment.get("lastSegment") == "true"),
        order_id=_text(root, "/*/*[local-name()='header']"
                             "/*[local-name()='mutable']"
                             "/*[local-name()='OrderID']"),
        order_data=_joined(_text(root, "/*/*[local-name()='body']"
                                       "/*[local-name()='DataTransfer']"
                                       "/*[local-name()='OrderData']")),
        transaction_key_encrypted=(None if key is None
                                   else base64.b64decode(_joined(key) or "")),
    )


def _first(root: etree._Element, path: str) -> etree._Element | None:
    found = root.xpath(path)
    return found[0] if found else None


def _text(root: etree._Element, path: str) -> str | None:
    node = _first(root, path)
    return _clean(node.text) if node is not None else None


def _clean(text: str | None) -> str | None:
    """Empty and absent mean the same thing; every other parser agrees."""
    return (text or "").strip() or None


def _joined(text: str | None) -> str | None:
    """base64 with the line breaks a bank wrapped it in taken back out."""
    return None if text is None else "".join(text.split()) or None


def _int(text: str | None) -> int | None:
    try:
        return None if text is None else int(text)
    except ValueError:
        raise DocumentError(f"expected a segment count, got {text!r}") from None
