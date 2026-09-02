"""The three-phase transaction protocol, with segmentation and recovery.

Every EBICS order of any size is the same three phases, and a single-segment
transfer is the degenerate case of the general one rather than a shortcut past
it::

    Initialisation   the bank assigns a TransactionID; a download also states
                     NumSegments and returns the first segment with it
    Transfer         segments in order, SegmentNumber counting from 1 and
                     lastSegment="true" on the final one
    Receipt          downloads only: the client acknowledges, and only then
                     does the bank stop offering the same data again

Segmentation follows the *encoded* stream, not the payload. The order data is
compressed, encrypted and base64-coded, and it is that base64 text that is cut
into pieces of at most 1 MB (EBICS specification, "Segmentation of the order
data": the recipient concatenates the segments, then decodes, decrypts and
inflates the whole). Doing it the other way round -- chunking the payload and
encrypting each chunk -- produces something only the implementation that wrote
it can read back; see ADR D-014.

The engine stays transport-agnostic. These classes produce request documents
and consume response documents; they never open a socket, never see an HTTP
status code, and know nothing about retry policy or persistence. The caller
drives them::

    tx = DownloadTransaction(context, authentication_key=x, encryption_key=e)
    response = post(serialize_request(tx.initialisation_request(service)))
    tx.feed(response)
    while (request := tx.next_request()) is not None:
        tx.feed(post(serialize_request(request)))
    statement = tx.order_data

**Recovery** is why the loop is written against ``next_request`` rather than
against a segment counter the caller keeps. EBICS recovers optimistically: the
client resumes from where it believes the transaction got to, and if it is
wrong the bank answers ``EBICS_TX_RECOVERY_SYNC`` carrying its own view of the
last segment that made it through. Feeding that response rewinds the cursor and
the next request continues from the bank's recovery point. A caller that
crashed and restarted feeds nothing and calls :meth:`resume_at` instead.

Provenance: the message shapes are ported from ``ebics-api/ebics-client-php``
(MIT) -- ``RequestFactory::createTransfer*`` and ``EbicsClient`` fix the header
contents and the order of the exchange. The segmentation rule is taken from the
specification rather than from that port, which segments the payload; D-014
records the divergence and the evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from lxml import etree

from .btf import Service
from .canon import parse_xml
from .errors import RequestError, TransactionError
from .keys import EbicsKey
from .pipeline import SecuredOrderData, open_order_data
from .requests import (RequestContext, build_admin_download_request,
                       build_btd_request, build_btu_request,
                       build_receipt_request, build_transfer_request)
from .responses import BankResponse, parse_response
from .signature import verify_auth_signature

__all__ = [
    "SEGMENT_SIZE",
    "DownloadTransaction",
    "Phase",
    "UploadTransaction",
    "split_segments",
]

#: The largest one segment may be, in bytes of base64 text. A bank answers an
#: oversized upload segment with ``EBICS_SEGMENT_SIZE_EXCEEDED``.
SEGMENT_SIZE = 1_048_576


class Phase(str, Enum):
    """Where a transaction is. ``DONE`` is ours; the other three are the wire's."""

    INITIALISATION = "Initialisation"
    TRANSFER = "Transfer"
    RECEIPT = "Receipt"
    DONE = "Done"


def split_segments(encoded: str, size: int = SEGMENT_SIZE) -> list[str]:
    """Cut encoded order data into transmissible segments.

    The input is base64 and the cut is made on base64 characters, so every
    segment stays decodable as part of the concatenation without the recipient
    having to re-align anything -- which is the whole reason the specification
    segments after the encoding rather than before it.

    Empty input yields one empty segment: an order with no data is still one
    transfer step, and returning zero segments would end the transaction before
    ``lastSegment`` was ever sent.
    """
    if size < 1:
        raise RequestError("segment size must be positive")
    if size % 4:
        raise RequestError("a base64-conformant segment size is a multiple of 4")
    return [encoded[i:i + size] for i in range(0, len(encoded), size)] or [""]


@dataclass
class _Transaction:
    """What the two directions share: identity, phase, and a segment cursor."""

    context: RequestContext
    authentication_key: EbicsKey
    schema_location: str | None = None

    #: The bank's X002 key, if the caller wants responses checked. Left unset
    #: the signature is not looked at -- which is the right default only for a
    #: caller that has not fetched the bank's keys yet (HPB is the request that
    #: fetches them, and it cannot itself be verified against them).
    bank_authentication_key: EbicsKey | None = None

    transaction_id: str | None = None
    phase: Phase = Phase.INITIALISATION
    cursor: int = 0

    def next_request(self) -> etree._Element | None:
        """The next document to send, or ``None`` when there is nothing left."""
        raise NotImplementedError

    def feed(self, document: bytes | str | etree._Element) -> BankResponse:
        """Consume one bank response and advance.

        Recovery is checked before the return code, because
        ``EBICS_TX_RECOVERY_SYNC`` *is* a non-zero return code and treating it
        as a failure is exactly the mistake that turns a resumable transfer
        into a re-upload of several hundred megabytes. Which of the other
        non-zero codes are refusals is not decided here: it is
        :mod:`painfree.ebics3.returncodes` that knows, and this method only
        acts on the answer.
        """
        root = document if isinstance(document, etree._Element) else parse_xml(document)
        if self.bank_authentication_key is not None:
            check = verify_auth_signature(
                root, self.bank_authentication_key.public_key, "X002")
            if not check.ok:
                raise TransactionError(
                    f"the bank's signature does not check out "
                    f"(digest_ok={check.digest_ok}, "
                    f"signature_ok={check.signature_ok})")

        response = parse_response(root)
        status = response.status
        if status.needs_recovery and self.transaction_id is not None:
            self.resume_at(response.segment_number or 0)
            return response
        status.raise_for_status(f"the bank refused the {self.phase.value} step")

        if status.ends_transaction:
            # The other non-zero codes that are not refusals: 011000 and 011001
            # close a download that was acknowledged, 090005 says there was
            # never anything to send. Either way nothing is left to transfer,
            # and a download that ends here ends with no segments rather than
            # with an error.
            self.transaction_id = response.transaction_id or self.transaction_id
            self.phase = Phase.DONE
            return response

        if self.phase is Phase.INITIALISATION:
            if not response.transaction_id:
                raise TransactionError(
                    "initialisation response carries no TransactionID")
            self.transaction_id = response.transaction_id

        self._advance(response)
        return response

    def resume_at(self, segment_number: int) -> None:
        """Rewind the cursor to a recovery point and carry on from there.

        Called for us when a response says ``EBICS_TX_RECOVERY_SYNC``, and by a
        caller that lost its own state and is resuming a transaction it has the
        ``TransactionID`` for. Rewinding is the only safe direction: a cursor
        ahead of the bank's would skip a segment silently.
        """
        if segment_number < 0:
            raise TransactionError("a recovery point is a segment number")
        self.cursor = segment_number
        self.phase = Phase.TRANSFER

    def _advance(self, response: BankResponse) -> None:
        raise NotImplementedError

    def _require_transaction(self) -> str:
        if self.transaction_id is None:
            raise TransactionError("the transaction has not been initialised yet")
        return self.transaction_id


@dataclass
class UploadTransaction(_Transaction):
    """A ``BTU``: announce the payload, then push its segments.

    The order data is already through the pipeline when it gets here --
    :func:`painfree.ebics3.secure_order_data` signed, compressed, encrypted and
    encoded it -- because the initialisation request has to publish its digest
    and its segment count before the first byte is transferred. That is also
    why ``NumSegments`` is not a guess: it is ``len(segments)``, and a bank
    answers a wrong one with ``EBICS_TX_SEGMENT_NUMBER_EXCEEDED`` (too low) or
    ``EBICS_TX_SEGMENT_NUMBER_UNDERRUN`` (too high).
    """

    secured: SecuredOrderData | None = None
    segments: list[str] = field(default_factory=list, repr=False)
    order_id: str | None = None

    @classmethod
    def prepare(cls, order_content: bytes, secured: SecuredOrderData,
                context: RequestContext, *, authentication_key: EbicsKey,
                segment_size: int = SEGMENT_SIZE,
                schema_location: str | None = None) -> "UploadTransaction":
        """Encrypt the payload under the transaction key and cut it into segments."""
        return cls(context=context, authentication_key=authentication_key,
                   schema_location=schema_location, secured=secured,
                   segments=split_segments(secured.encrypt(order_content),
                                           segment_size))

    @property
    def num_segments(self) -> int:
        return len(self.segments)

    def initialisation_request(self, service: Service, *,
                               bank_authentication_key: EbicsKey,
                               bank_encryption_key: EbicsKey,
                               **kwargs) -> etree._Element:
        if self.secured is None:
            raise TransactionError("an upload needs its secured order data")
        return build_btu_request(
            self.context, service, authentication_key=self.authentication_key,
            bank_authentication_key=bank_authentication_key,
            bank_encryption_key=bank_encryption_key, secured=self.secured,
            num_segments=self.num_segments,
            schema_location=self.schema_location, **kwargs)

    def next_request(self) -> etree._Element | None:
        if self.phase is not Phase.TRANSFER or self.cursor >= self.num_segments:
            return None
        number = self.cursor + 1
        return build_transfer_request(
            self.context, authentication_key=self.authentication_key,
            transaction_id=self._require_transaction(),
            segment_number=number, last_segment=number == self.num_segments,
            order_data=self.segments[self.cursor],
            schema_location=self.schema_location)

    def _advance(self, response: BankResponse) -> None:
        # The OrderID arrives whenever the bank chooses to send it -- with the
        # initialisation on some banks, with the last segment on others -- so
        # it is taken from every response rather than from one expected step.
        self.order_id = response.order_id or self.order_id
        if self.phase is Phase.INITIALISATION:
            self.phase = Phase.TRANSFER
            return
        self.cursor += 1
        if self.cursor >= self.num_segments:
            self.phase = Phase.DONE


@dataclass
class DownloadTransaction(_Transaction):
    """A ``BTD``: collect the segments, then acknowledge them.

    The first segment arrives with the initialisation response, together with
    the transaction key it and every later segment are encrypted under -- the
    bank sends ``DataEncryptionInfo`` once, in that first response only.

    The transaction ends in the receipt phase whatever happened in between. A
    download that is never acknowledged stays open at the bank's end and is
    offered again next time, which turns a scheduled statement download into a
    duplicate rather than an error.
    """

    encryption_key: EbicsKey | None = None
    num_segments: int | None = None
    segments: list[str] = field(default_factory=list, repr=False)
    transaction_key_encrypted: bytes | None = None
    acknowledged: bool = True

    def initialisation_request(self, service: Service, *,
                               bank_authentication_key: EbicsKey,
                               bank_encryption_key: EbicsKey,
                               **kwargs) -> etree._Element:
        return build_btd_request(
            self.context, service, authentication_key=self.authentication_key,
            bank_authentication_key=bank_authentication_key,
            bank_encryption_key=bank_encryption_key,
            schema_location=self.schema_location, **kwargs)

    def admin_initialisation_request(self, admin_order_type: str, *,
                                     bank_authentication_key: EbicsKey,
                                     bank_encryption_key: EbicsKey,
                                     **kwargs) -> etree._Element:
        """The same download, opened for an administrative order type.

        ``HTD``, ``HPD`` and ``HAA`` are ordinary three-phase downloads --
        segmented, encrypted to our own ``E002`` half, acknowledged with a
        receipt -- and differ from a ``BTD`` in one element: they carry no BTF,
        because they describe no business traffic. Only the opening request
        changes, so only the opening request is overridden here; the transfer
        and the receipt below are already right for both.
        """
        return build_admin_download_request(
            self.context, admin_order_type,
            authentication_key=self.authentication_key,
            bank_authentication_key=bank_authentication_key,
            bank_encryption_key=bank_encryption_key,
            schema_location=self.schema_location, **kwargs)

    def resume_at(self, segment_number: int) -> None:
        """As the base class, and drop the segments the bank never got out."""
        super().resume_at(segment_number)
        del self.segments[segment_number:]

    def next_request(self) -> etree._Element | None:
        if self.phase not in (Phase.TRANSFER, Phase.RECEIPT):
            return None
        transaction_id = self._require_transaction()
        if self.phase is Phase.RECEIPT:
            return build_receipt_request(
                self.context, authentication_key=self.authentication_key,
                transaction_id=transaction_id, acknowledged=self.acknowledged,
                schema_location=self.schema_location)
        number = self.cursor + 1
        return build_transfer_request(
            self.context, authentication_key=self.authentication_key,
            transaction_id=transaction_id, segment_number=number,
            last_segment=number == self.num_segments,
            schema_location=self.schema_location)

    @property
    def order_data(self) -> bytes:
        """The payload, reassembled: concatenate, decode, decrypt, inflate.

        Concatenation comes first and decryption once, over the whole stream --
        the segments are pieces of one base64 document, not standalone
        ciphertexts, and decrypting them individually fails on every segment
        boundary that is not also a cipher-block boundary.
        """
        if self.transaction_key_encrypted is None:
            raise TransactionError("the bank sent no transaction key")
        if self.encryption_key is None:
            raise TransactionError("decrypting a download needs the E002 key")
        return open_order_data("".join(self.segments),
                               self.transaction_key_encrypted,
                               self.encryption_key)

    def _advance(self, response: BankResponse) -> None:
        if self.phase is Phase.RECEIPT:
            self.phase = Phase.DONE
            return

        if self.phase is Phase.INITIALISATION:
            self.num_segments = response.num_segments
            self.transaction_key_encrypted = response.transaction_key_encrypted
        elif response.segment_number not in (None, self.cursor + 1):
            raise TransactionError(
                f"expected segment {self.cursor + 1}, got {response.segment_number}")

        if response.order_data is None:
            raise TransactionError(
                f"download segment {self.cursor + 1} carries no order data")
        self.segments.append(response.order_data)
        self.cursor += 1

        # ``lastSegment`` terminates the transfer, not the announced count. The
        # specification allows a bank to stop short of NumSegments and requires
        # the client to acknowledge anyway, and allows it to go past.
        self.phase = Phase.RECEIPT if response.last_segment else Phase.TRANSFER
