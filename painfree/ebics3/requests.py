"""The H005 request documents: envelopes, headers and order details.

Three envelopes carry everything a client sends:

===============================  ============================================
``ebicsUnsecuredRequest``        ``INI`` and ``HIA``. No nonce, no timestamp,
                                 no authentication signature -- the keys are
                                 what is being established.
``ebicsNoPubKeyDigestsRequest``  ``HPB``. Signed with X002, but carries no
                                 ``BankPubKeyDigests``: the client does not
                                 have the bank's keys yet, which is the point.
``ebicsRequest``                 everything else, ``BTD`` and ``BTU``
                                 included. Signed, and it does name the digests
                                 of the bank keys it expects to be talking to.
===============================  ============================================

What H005 changed, and where a port from H004 goes wrong:

* ``OrderType`` is renamed **``AdminOrderType``**, and it is now always
  ``BTD``/``BTU`` for business traffic; the format lives in the BTF service
  (see :mod:`painfree.ebics3.btf`).
* ``OrderAttribute`` is **gone** from the request schema. An H004 port that
  keeps emitting ``DZHNN`` produces a document the H005 XSD rejects.
* ``BankPubKeyDigests`` carries the SHA-256 of the bank's **X.509 certificate**,
  not the RSA public-key digest that H004 used and that the INI letter still
  quotes. The two are different values over the same key, and mixing them up
  yields ``EBICS_BANK_PUBKEY_UPDATE_REQUIRED`` from a bank whose keys are fine.

The ``authenticate="true"`` marker sits on ``header`` -- and, on an upload, on
``DataEncryptionInfo`` and ``SignatureData`` in the body as well. All three
together are the node-set the authentication signature covers, so a ``BTU``
whose body is missing signs a strictly smaller document and produces a digest
the bank cannot reproduce. ``TransferReceipt`` carries the marker too and
arrives with the transaction protocol.

Provenance: ported from ``ebics-api/ebics-client-php`` (MIT), whose
``Builders/Request/*`` and ``Orders/*`` fix the build order, checked element by
element against the official H005 schemas. See ADR D-005.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import secrets
from dataclasses import dataclass

from lxml import etree

from .btf import (Service, append_btd_order_params, append_btu_order_params,
                  append_standard_order_params)
from .certificates import certificate_der
from .errors import CertificateError, RequestError
from .keys import EbicsKey
from .orderdata import (build_hia_request_order_data,
                        build_signature_pub_key_order_data, encode_order_data)
from .pipeline import SecuredOrderData
from .signature import build_auth_signature
from .versions import KeyRole, KeyVersion

__all__ = [
    "DIGEST_ALGORITHM",
    "EBICS_NAMESPACE",
    "EBICS_REVISION",
    "EBICS_VERSION",
    "RECEIPT_CODE_NEGATIVE",
    "RECEIPT_CODE_POSITIVE",
    "Product",
    "RequestContext",
    "append_data_transfer",
    "ADMIN_DOWNLOADS",
    "build_admin_download_request",
    "build_btd_request",
    "build_btu_request",
    "build_hia_request",
    "build_hpb_request",
    "build_ini_request",
    "build_receipt_request",
    "build_transfer_request",
    "certificate_digest_b64",
    "generate_nonce",
    "serialize_request",
    "utc_timestamp",
]

EBICS_VERSION = "H005"
EBICS_NAMESPACE = "urn:org:ebics:H005"

#: The schema revision every H005 request declares. Fixed at 1 by the standard.
EBICS_REVISION = "1"

DIGEST_ALGORITHM = "http://www.w3.org/2001/04/xmlenc#sha256"

_DSIG = "http://www.w3.org/2000/09/xmldsig#"
_XSI = "http://www.w3.org/2001/XMLSchema-instance"

#: ``SecurityMediumType``: four digits. ``0000`` means the key lives in
#: software, which is what a server-side connection uses.
DEFAULT_SECURITY_MEDIUM = "0000"

#: ``ReceiptCodeType``: 0 if the download and its processing succeeded, 1 if
#: not. A negative receipt closes the transaction without the bank marking the
#: data delivered, so it is the answer to "we could not store this", never to
#: "we did not like the contents".
RECEIPT_CODE_POSITIVE = "0"
RECEIPT_CODE_NEGATIVE = "1"


@dataclass(frozen=True)
class Product:
    """The client identification a bank logs and sometimes filters on."""

    name: str
    language: str = "de"
    institute: str | None = None

    def __post_init__(self) -> None:
        if not 1 <= len(self.name) <= 64:
            raise RequestError("Product name must be 1-64 characters")
        if len(self.language) != 2 or not self.language.isalpha():
            raise RequestError(
                f"Product language {self.language!r} must be a two-letter ISO 639 code")


@dataclass(frozen=True)
class RequestContext:
    """Who is talking to whom -- the part of a request that never varies.

    Deliberately not a keyring and not a connection: the engine is handed the
    identifiers and the keys it needs for one request, and knows nothing about
    where either came from.
    """

    host_id: str
    partner_id: str
    user_id: str
    product: Product | None = None
    system_id: str | None = None
    security_medium: str = DEFAULT_SECURITY_MEDIUM

    def __post_init__(self) -> None:
        for field, value, limit in (("HostID", self.host_id, 35),
                                    ("PartnerID", self.partner_id, 35),
                                    ("UserID", self.user_id, 35)):
            if not value or len(value) > limit:
                raise RequestError(f"{field} must be 1-{limit} characters")
        if len(self.security_medium) != 4 or not self.security_medium.isdigit():
            raise RequestError(
                f"SecurityMedium {self.security_medium!r} must be four digits")


# --- primitives ------------------------------------------------------------

def generate_nonce() -> str:
    """A fresh ``NonceType``: 16 random bytes as upper-case hex.

    The value is what makes one initialisation message distinguishable from a
    replay of it, so it is generated per request and never reused. It is also
    the reason two runs of the same request can never be compared byte for
    byte.
    """
    return secrets.token_bytes(16).hex().upper()


def utc_timestamp(moment: _dt.datetime | None = None) -> str:
    """``TimestampType`` in UTC, to the second.

    Sub-second precision is legal but pointless -- the timestamp exists so the
    bank can expire its stored nonces -- and a fractional part is one more
    thing for a bank's parser to disagree about.
    """
    moment = moment or _dt.datetime.now(_dt.timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=_dt.timezone.utc)
    return moment.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def certificate_digest_b64(key: EbicsKey) -> str:
    """SHA-256 over the certificate's DER, base64 -- what H005 puts in a digest.

    Not :func:`painfree.ebics3.public_key_digest`, which hashes the RSA numbers
    and is the value on the INI letter. H005 moved the request-side digests to
    the certificate; both values exist for the same key and only one of them is
    accepted here.
    """
    if key.certificate is None:
        raise CertificateError(
            f"EBICS 3.0 requires a certificate; the {key.version.value} key has none"
        )
    return base64.b64encode(
        hashlib.sha256(certificate_der(key.certificate)).digest()).decode("ascii")


def serialize_request(root: etree._Element) -> bytes:
    """The request as the bytes that go on the wire."""
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


# --- the three envelopes ---------------------------------------------------

def build_ini_request(
    context: RequestContext,
    signature_key: EbicsKey,
    *,
    schema_location: str | None = None,
) -> etree._Element:
    """``INI``: send the electronic-signature key, unsecured and unsigned."""
    order_data = build_signature_pub_key_order_data(
        signature_key, context.partner_id, context.user_id)
    return _unsecured_request(context, "INI", encode_order_data(order_data),
                              schema_location=schema_location)


def build_hia_request(
    context: RequestContext,
    authentication_key: EbicsKey,
    encryption_key: EbicsKey,
    *,
    schema_location: str | None = None,
) -> etree._Element:
    """``HIA``: send the authentication and encryption keys, unsecured."""
    order_data = build_hia_request_order_data(
        authentication_key, encryption_key, context.partner_id, context.user_id)
    return _unsecured_request(context, "HIA", encode_order_data(order_data),
                              schema_location=schema_location)


def build_hpb_request(
    context: RequestContext,
    authentication_key: EbicsKey,
    *,
    nonce: str | None = None,
    timestamp: str | None = None,
    schema_location: str | None = None,
) -> etree._Element:
    """``HPB``: ask for the bank's keys, signed with X002 and nothing else.

    ``nonce`` and ``timestamp`` are parameters so a caller that needs a
    reproducible document -- a test, or a differential comparison -- can pin
    them. Left unset they are fresh, which is what a real request wants.
    """
    _require_signing_key(authentication_key)
    root = _root("ebicsNoPubKeyDigestsRequest", with_dsig=True,
                 schema_location=schema_location)
    header = _header(root)
    static = _sub(header, "static")

    _sub(static, "HostID", context.host_id)
    _sub(static, "Nonce", nonce or generate_nonce())
    _sub(static, "Timestamp", timestamp or utc_timestamp())
    _identity(static, context)
    order_details = _sub(static, "OrderDetails")
    _sub(order_details, "AdminOrderType", "HPB")
    _sub(static, "SecurityMedium", context.security_medium)

    _sub(header, "mutable")
    _sub(root, "body")

    _sign(root, authentication_key)
    return root


def build_btd_request(
    context: RequestContext,
    service: Service,
    *,
    authentication_key: EbicsKey,
    bank_authentication_key: EbicsKey,
    bank_encryption_key: EbicsKey,
    date_range: tuple[str, str] | None = None,
    parameters: dict[str, str] | None = None,
    nonce: str | None = None,
    timestamp: str | None = None,
    schema_location: str | None = None,
) -> etree._Element:
    """``BTD`` initialisation: ask the bank for a file described by a BTF.

    The body is empty. A download has nothing to send, so the initialisation
    request is complete as it stands -- unlike ``BTU``, whose body the
    order-data pipeline fills.
    """
    root = _initialisation_request(
        context, "BTD", authentication_key=authentication_key,
        bank_authentication_key=bank_authentication_key,
        bank_encryption_key=bank_encryption_key,
        nonce=nonce, timestamp=timestamp, schema_location=schema_location,
        order_params=lambda details: append_btd_order_params(
            details, service, date_range=date_range, parameters=parameters),
    )
    return root


#: The administrative downloads this engine can ask for, and what each answers.
#: All three are ``StandardOrderParams`` orders -- no BTF, because none of them
#: is business traffic -- and all three come back as ordinary encrypted,
#: compressed order data over the same three-phase download a ``BTD`` uses.
#:
#: They exist to replace a PDF. A bank's EBICS parameter sheet is what an
#: operator otherwise reads to find out which BTFs the bank will accept, and a
#: sheet is a document that goes out of date without telling anybody. These ask
#: the bank instead.
ADMIN_DOWNLOADS: dict[str, str] = {
    "HAA": "the order types this subscriber may retrieve",
    "HTD": "the customer and subscriber data the bank holds, and its BTFs",
    "HPD": "the bank's own parameters: versions, algorithms, limits",
}


def build_admin_download_request(
    context: RequestContext,
    admin_order_type: str,
    *,
    authentication_key: EbicsKey,
    bank_authentication_key: EbicsKey,
    bank_encryption_key: EbicsKey,
    date_range: tuple[str, str] | None = None,
    nonce: str | None = None,
    timestamp: str | None = None,
    schema_location: str | None = None,
) -> etree._Element:
    """Initialisation for an administrative download: ``HAA``, ``HTD``, ``HPD``.

    The same signed ``ebicsRequest`` a ``BTD`` opens with, differing in one
    element: ``StandardOrderParams`` where a ``BTD`` puts ``BTDOrderParams``.
    Both substitute into the mandatory ``OrderParams`` of
    ``StaticHeaderOrderDetailsType``, which is why this shares
    :func:`_initialisation_request` rather than being built separately -- the
    header, the bank digests and the signature are not different problems here,
    and a second copy of them is a second thing to get wrong.

    The body is empty, like every download's.
    """
    if admin_order_type not in ADMIN_DOWNLOADS:
        raise RequestError(
            f"{admin_order_type!r} is not an administrative download this "
            f"engine builds; it knows "
            f"{', '.join(sorted(ADMIN_DOWNLOADS))}")
    return _initialisation_request(
        context, admin_order_type, authentication_key=authentication_key,
        bank_authentication_key=bank_authentication_key,
        bank_encryption_key=bank_encryption_key,
        nonce=nonce, timestamp=timestamp, schema_location=schema_location,
        order_params=lambda details: append_standard_order_params(
            details, date_range=date_range),
    )


def build_btu_request(
    context: RequestContext,
    service: Service,
    *,
    authentication_key: EbicsKey,
    bank_authentication_key: EbicsKey,
    bank_encryption_key: EbicsKey,
    secured: SecuredOrderData,
    num_segments: int,
    file_name: str | None = None,
    request_eds: bool | None = None,
    parameters: dict[str, str] | None = None,
    nonce: str | None = None,
    timestamp: str | None = None,
    schema_location: str | None = None,
) -> etree._Element:
    """``BTU`` initialisation: announce an upload described by a BTF.

    ``secured`` is what :func:`painfree.ebics3.secure_order_data` produced for
    this payload. It is taken rather than built here because the caller needs
    what it holds afterwards: the transfer phase encrypts every segment under
    the same transaction key, and the builder must not be the only thing that
    knows it.

    The body carries the ES and the wrapped transaction key -- but *not* the
    order data. An upload sends its payload in the transfer phase; the
    initialisation request announces the segment count and proves, with the
    digest and the ES, what is about to arrive.
    """
    if num_segments < 1:
        raise RequestError("an upload has at least one segment")
    return _initialisation_request(
        context, "BTU", authentication_key=authentication_key,
        bank_authentication_key=bank_authentication_key,
        bank_encryption_key=bank_encryption_key,
        nonce=nonce, timestamp=timestamp, num_segments=num_segments,
        schema_location=schema_location,
        order_params=lambda details: append_btu_order_params(
            details, service, file_name=file_name, request_eds=request_eds,
            parameters=parameters),
        body=lambda root: append_data_transfer(root, secured,
                                               bank_encryption_key),
    )


def append_data_transfer(body: etree._Element, secured: SecuredOrderData,
                         bank_encryption_key: EbicsKey) -> etree._Element:
    """``DataTransfer`` as the initialisation phase of an upload needs it.

    The schema's sequence is exact -- ``DataEncryptionInfo``, ``SignatureData``,
    ``DataDigest`` -- and two of the three carry ``authenticate="true"``, which
    is the whole reason this element has to exist before the request is signed.
    ``EncryptionPubKeyDigest`` hashes the bank's E002 *certificate*, the same
    H005 rule ``BankPubKeyDigests`` follows.
    """
    _require_role(bank_encryption_key, KeyRole.ENCRYPTION, "DataEncryptionInfo")
    transfer = _sub(body, "DataTransfer")

    encryption = _sub(transfer, "DataEncryptionInfo", authenticate="true")
    _sub(encryption, "EncryptionPubKeyDigest",
         certificate_digest_b64(bank_encryption_key),
         Version=bank_encryption_key.version.value,
         Algorithm=DIGEST_ALGORITHM)
    _sub(encryption, "TransactionKey",
         base64.b64encode(secured.transaction_key_encrypted).decode("ascii"))

    _sub(transfer, "SignatureData", secured.signature_data, authenticate="true")
    _sub(transfer, "DataDigest", secured.digest_b64,
         SignatureVersion=secured.signature_version.value)
    return transfer


# --- the later phases ------------------------------------------------------

def build_transfer_request(
    context: RequestContext,
    *,
    authentication_key: EbicsKey,
    transaction_id: str,
    segment_number: int,
    last_segment: bool,
    order_data: str | None = None,
    schema_location: str | None = None,
) -> etree._Element:
    """``TransactionPhase=Transfer``: send one segment, or ask for one.

    The static header shrinks to two elements. Once the transaction exists,
    ``TransactionID`` is the whole of the client's claim to it -- no nonce, no
    timestamp, no order details, no key digests -- because the schema's
    ``StaticHeaderType`` offers the initialisation sequence and this one as an
    exclusive choice. A port that keeps building the full header here produces a
    document the XSD rejects.

    ``order_data`` is the difference between the two directions: an upload
    carries the segment, a download carries nothing and the payload comes back
    in the response. It is a base64 string, already compressed and encrypted --
    segmentation happens *after* the encoding, so the engine never re-encodes a
    segment here.
    """
    if segment_number < 1:
        raise RequestError("segment numbering starts at 1")
    return _phase_request(
        context, "Transfer", transaction_id,
        authentication_key=authentication_key,
        schema_location=schema_location,
        mutable=lambda element: _sub(
            element, "SegmentNumber", str(segment_number),
            lastSegment="true" if last_segment else "false"),
        body=(None if order_data is None else lambda element: _sub(
            _sub(element, "DataTransfer"), "OrderData", order_data)),
    )


def build_receipt_request(
    context: RequestContext,
    *,
    authentication_key: EbicsKey,
    transaction_id: str,
    acknowledged: bool = True,
    schema_location: str | None = None,
) -> etree._Element:
    """``TransactionPhase=Receipt``: tell the bank the download arrived.

    Without it the transaction stays open at the bank's end and the same data
    is offered again on the next download -- the receipt is what makes a
    scheduled statement download idempotent from the bank's side.

    ``TransferReceipt`` carries ``authenticate="true"``, so this is the one
    request whose body is part of the signed node-set without any of the
    order-data machinery being involved.
    """
    return _phase_request(
        context, "Receipt", transaction_id,
        authentication_key=authentication_key,
        schema_location=schema_location,
        body=lambda element: _sub(
            _sub(element, "TransferReceipt", authenticate="true"), "ReceiptCode",
            RECEIPT_CODE_POSITIVE if acknowledged else RECEIPT_CODE_NEGATIVE),
    )


# --- shared construction ---------------------------------------------------

def _phase_request(
    context: RequestContext,
    phase: str,
    transaction_id: str,
    *,
    authentication_key: EbicsKey,
    mutable=None,
    body=None,
    schema_location: str | None = None,
) -> etree._Element:
    """``ebicsRequest`` in the transfer or receipt phase, signed with X002."""
    _require_signing_key(authentication_key)
    if len(transaction_id) != 32 or not all(c in "0123456789abcdefABCDEF"
                                            for c in transaction_id):
        raise RequestError(
            "TransactionID is 16 hex-encoded bytes as the bank assigned them")

    root = _root("ebicsRequest", with_dsig=True, schema_location=schema_location)
    header = _header(root)
    static = _sub(header, "static")
    _sub(static, "HostID", context.host_id)
    _sub(static, "TransactionID", transaction_id)

    element = _sub(header, "mutable")
    _sub(element, "TransactionPhase", phase)
    if mutable is not None:
        mutable(element)

    element = _sub(root, "body")
    if body is not None:
        body(element)

    _sign(root, authentication_key)
    return root



def _unsecured_request(
    context: RequestContext, admin_order_type: str, order_data: str,
    *, schema_location: str | None = None
) -> etree._Element:
    """``ebicsUnsecuredRequest``: no nonce, no timestamp, no signature.

    ``UnsecuredRequestStaticHeaderType`` restricts ``Nonce`` and ``Timestamp``
    to ``maxOccurs="0"`` -- they are not merely optional here, they are
    forbidden, because there is no signature for them to protect.
    """
    root = _root("ebicsUnsecuredRequest", with_dsig=False,
                 schema_location=schema_location)
    header = _header(root)
    static = _sub(header, "static")

    _sub(static, "HostID", context.host_id)
    _identity(static, context)
    order_details = _sub(static, "OrderDetails")
    _sub(order_details, "AdminOrderType", admin_order_type)
    _sub(static, "SecurityMedium", context.security_medium)

    _sub(header, "mutable")

    body = _sub(root, "body")
    transfer = _sub(body, "DataTransfer")
    _sub(transfer, "OrderData", order_data)
    return root


def _initialisation_request(
    context: RequestContext,
    admin_order_type: str,
    *,
    authentication_key: EbicsKey,
    bank_authentication_key: EbicsKey,
    bank_encryption_key: EbicsKey,
    order_params,
    nonce: str | None = None,
    timestamp: str | None = None,
    num_segments: int | None = None,
    schema_location: str | None = None,
    body=None,
) -> etree._Element:
    """``ebicsRequest`` in the ``Initialisation`` phase, signed with X002."""
    _require_signing_key(authentication_key)
    _require_role(bank_authentication_key, KeyRole.AUTHENTICATION, "BankPubKeyDigests")
    _require_role(bank_encryption_key, KeyRole.ENCRYPTION, "BankPubKeyDigests")

    root = _root("ebicsRequest", with_dsig=True, schema_location=schema_location)
    header = _header(root)
    static = _sub(header, "static")

    _sub(static, "HostID", context.host_id)
    _sub(static, "Nonce", nonce or generate_nonce())
    _sub(static, "Timestamp", timestamp or utc_timestamp())
    _identity(static, context)

    details = _sub(static, "OrderDetails")
    _sub(details, "AdminOrderType", admin_order_type)
    order_params(details)

    digests = _sub(static, "BankPubKeyDigests")
    _sub(digests, "Authentication",
         certificate_digest_b64(bank_authentication_key),
         Version=bank_authentication_key.version.value,
         Algorithm=DIGEST_ALGORITHM)
    _sub(digests, "Encryption",
         certificate_digest_b64(bank_encryption_key),
         Version=bank_encryption_key.version.value,
         Algorithm=DIGEST_ALGORITHM)

    _sub(static, "SecurityMedium", context.security_medium)
    if num_segments is not None:
        _sub(static, "NumSegments", str(num_segments))

    mutable = _sub(header, "mutable")
    _sub(mutable, "TransactionPhase", "Initialisation")

    element = _sub(root, "body")
    if body is not None:
        body(element)

    _sign(root, authentication_key)
    return root


def _root(name: str, *, with_dsig: bool,
          schema_location: str | None = None) -> etree._Element:
    """The request root, with the namespaces the envelope needs in scope.

    ``xmlns:ds`` is declared on the root of every signed envelope even before
    the signature exists, because inclusive canonicalisation re-emits every
    in-scope declaration on the ``header`` apex. Declaring it later -- on
    ``AuthSignature``, say -- produces a different digest over the same header,
    which is the single most expensive way to learn this rule.

    ``schema_location`` is off by default and is the same rule seen from the
    other side. Some clients put an ``xsi:schemaLocation`` hint on the root;
    it is optional, no bank resolves it, and adding it puts ``xmlns:xsi`` in
    scope on ``header`` -- so the same request signed with and without the hint
    has two different digests. Callers who want it supply the string
    themselves; the engine does not invent one, because the value is a pair of
    URIs and the obvious guess is a namespace this document does not use.
    """
    nsmap: dict[str | None, str] = {None: EBICS_NAMESPACE}
    if with_dsig:
        nsmap["ds"] = _DSIG
    if schema_location is not None:
        nsmap["xsi"] = _XSI
    root = etree.Element(etree.QName(EBICS_NAMESPACE, name), nsmap=nsmap)
    root.set("Version", EBICS_VERSION)
    root.set("Revision", EBICS_REVISION)
    if schema_location is not None:
        root.set(etree.QName(_XSI, "schemaLocation"), schema_location)
    return root


def _header(root: etree._Element) -> etree._Element:
    """``<header authenticate="true">`` -- the node-set the signature covers."""
    return _sub(root, "header", authenticate="true")


def _identity(static: etree._Element, context: RequestContext) -> None:
    """``PartnerID``, ``UserID``, then the optional ``SystemID`` and ``Product``.

    The order is the schema's and is shared by all three envelopes, which is
    why it lives in one place: a reordered static header is well-formed,
    schema-invalid, and rejected only once the bank parses it.
    """
    _sub(static, "PartnerID", context.partner_id)
    _sub(static, "UserID", context.user_id)
    if context.system_id is not None:
        _sub(static, "SystemID", context.system_id)
    if context.product is not None:
        attributes = {"Language": context.product.language}
        if context.product.institute is not None:
            attributes["InstituteID"] = context.product.institute
        _sub(static, "Product", context.product.name, **attributes)


def _sign(root: etree._Element, key: EbicsKey) -> None:
    if key.private_key is None:
        raise RequestError(
            f"signing needs the private half of the {key.version.value} key")
    build_auth_signature(root, key.private_key, key.version.value)


def _require_signing_key(key: EbicsKey) -> None:
    if KeyVersion.parse(key.version) is not KeyVersion.X002:
        raise RequestError(
            f"the authentication signature is X002; got {key.version.value}")


def _require_role(key: EbicsKey, role: KeyRole, where: str) -> None:
    if KeyVersion.parse(key.version).role is not role:
        raise RequestError(
            f"{where} needs a {role.value} key; got {key.version.value}")


def _sub(parent: etree._Element, name: str, text: str | None = None,
         **attributes: str) -> etree._Element:
    element = etree.SubElement(parent, etree.QName(EBICS_NAMESPACE, name))
    if text is not None:
        element.text = text
    for key, value in attributes.items():
        element.set(key, value)
    return element
