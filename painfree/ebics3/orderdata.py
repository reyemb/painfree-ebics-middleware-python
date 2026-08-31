"""The order-data payloads the two unsecured initialisation requests carry.

``INI`` sends the electronic-signature key, ``HIA`` the authentication and
encryption keys. Both travel in the request body as ``OrderData``: the XML
below, deflated and base64-encoded. No encryption and no signature -- that is
what "unsecured" means, and it is why the bank still needs the INI letter to
believe the keys arrived unaltered.

**H005 carries the key only inside a certificate.** Under H004 the payload was
a ``PubKeyValue`` with ``ds:Modulus`` and ``ds:Exponent``, and ``ds:X509Data``
was optional beside it. In H005 ``PubKeyInfoType`` has no ``PubKeyValue`` at
all: ``ds:X509Data`` is the single required child. A port that keeps emitting
``PubKeyValue`` produces a document the H005 schema rejects, and a port that
drops the certificate produces one the bank rejects.

::

    SignaturePubKeyOrderData          (http://www.ebics.org/S002)
      SignaturePubKeyInfo
        ds:X509Data
          ds:X509IssuerSerial
            ds:X509IssuerName / ds:X509SerialNumber
          ds:X509Certificate
        SignatureVersion              A005 | A006
      PartnerID
      UserID

    HIARequestOrderData               (urn:org:ebics:H005)
      AuthenticationPubKeyInfo        ds:X509Data + AuthenticationVersion
      EncryptionPubKeyInfo            ds:X509Data + EncryptionVersion
      PartnerID
      UserID

Note on the reference corpus: ``ebics-client-php``'s ``hia_order_data.xml`` is
byte-identical to its ``ini_order_data.xml`` and is rooted at
``SignaturePubKeyOrderData``, which is not what HIA sends. Neither file is
referenced by any test there, so the drift went unnoticed. The structure above
follows the H005 schema and the ``Orders/HIA`` builder instead.
"""

from __future__ import annotations

import base64
import zlib

from lxml import etree

from .certificates import certificate_der, issuer_name
from .errors import CertificateError, RequestError
from .keys import EbicsKey
from .versions import KeyRole, KeyVersion

__all__ = [
    "S002_NAMESPACE",
    "append_x509_data",
    "build_hia_request_order_data",
    "build_signature_pub_key_order_data",
    "compress_order_data",
    "decompress_order_data",
    "encode_order_data",
    "serialize_order_data",
]

#: The order-data signature schema for EBICS 3.0. S001 is its H004 predecessor
#: and is *not* interchangeable: S001 has ``PubKeyValue``, S002 does not.
S002_NAMESPACE = "http://www.ebics.org/S002"

_H005 = "urn:org:ebics:H005"
_DSIG = "http://www.w3.org/2000/09/xmldsig#"


def build_signature_pub_key_order_data(
    key: EbicsKey, partner_id: str, user_id: str
) -> etree._Element:
    """The ``INI`` payload: one A005/A006 key, in its certificate."""
    _require_role(key, KeyRole.SIGNATURE, "INI")
    root = _root(S002_NAMESPACE, "SignaturePubKeyOrderData")
    info = _sub(root, S002_NAMESPACE, "SignaturePubKeyInfo")
    append_x509_data(info, key)
    _sub(info, S002_NAMESPACE, "SignatureVersion", key.version.value)
    _sub(root, S002_NAMESPACE, "PartnerID", partner_id)
    _sub(root, S002_NAMESPACE, "UserID", user_id)
    return root


def build_hia_request_order_data(
    authentication_key: EbicsKey,
    encryption_key: EbicsKey,
    partner_id: str,
    user_id: str,
) -> etree._Element:
    """The ``HIA`` payload: the X002 and E002 keys, each in its certificate.

    The two keys must be *different* keys with different X.509 key usages --
    ``digitalSignature`` for X002, ``keyEncipherment`` for E002. The usage is
    how the bank tells them apart when both arrive in one request, so sending
    the same key twice is registered and only fails later, at first payment.
    """
    _require_role(authentication_key, KeyRole.AUTHENTICATION, "HIA")
    _require_role(encryption_key, KeyRole.ENCRYPTION, "HIA")
    if (authentication_key.public_key.public_numbers()
            == encryption_key.public_key.public_numbers()):
        raise RequestError(
            "HIA must carry two distinct keys: the authentication and "
            "encryption keys are the same key"
        )

    root = _root(_H005, "HIARequestOrderData")

    authentication = _sub(root, _H005, "AuthenticationPubKeyInfo")
    append_x509_data(authentication, authentication_key)
    _sub(authentication, _H005, "AuthenticationVersion",
         authentication_key.version.value)

    encryption = _sub(root, _H005, "EncryptionPubKeyInfo")
    append_x509_data(encryption, encryption_key)
    _sub(encryption, _H005, "EncryptionVersion", encryption_key.version.value)

    _sub(root, _H005, "PartnerID", partner_id)
    _sub(root, _H005, "UserID", user_id)
    return root


def append_x509_data(parent: etree._Element, key: EbicsKey) -> etree._Element:
    """``ds:X509Data``: how to find the certificate, then the certificate.

    ``ds:X509IssuerSerial`` names the issuer and serial so a bank that already
    holds the certificate can identify it without parsing the DER;
    ``ds:X509Certificate`` carries the DER itself, base64 without line breaks.
    """
    if key.certificate is None:
        raise CertificateError(
            f"EBICS 3.0 requires a certificate; the {key.version.value} key has none"
        )
    data = _sub(parent, _DSIG, "X509Data")
    serial = _sub(data, _DSIG, "X509IssuerSerial")
    _sub(serial, _DSIG, "X509IssuerName", issuer_name(key.certificate))
    _sub(serial, _DSIG, "X509SerialNumber", str(key.certificate.serial_number))
    _sub(data, _DSIG, "X509Certificate",
         base64.b64encode(certificate_der(key.certificate)).decode("ascii"))
    return data


def serialize_order_data(root: etree._Element) -> bytes:
    """The order-data document as the bytes that get compressed."""
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def compress_order_data(data: bytes) -> bytes:
    """Deflate, in the zlib wrapper EBICS means by "compressed".

    RFC 1950, not raw deflate and not gzip -- ``gzcompress`` in PHP and
    ``Zlib::Deflate`` in Ruby produce the same stream, which is why the
    base64 in the reference fixtures is directly comparable.
    """
    return zlib.compress(data)


def decompress_order_data(data: bytes) -> bytes:
    return zlib.decompress(data)


def encode_order_data(root: etree._Element) -> str:
    """Serialise, compress, base64 -- what goes into ``<OrderData>``.

    The unsecured path stops here. An upload adds encryption between the
    compression and the base64; that is the order-data pipeline, and it lands
    with the transaction protocol rather than with the request builders.
    """
    return base64.b64encode(
        compress_order_data(serialize_order_data(root))).decode("ascii")


def _require_role(key: EbicsKey, role: KeyRole, order: str) -> None:
    if KeyVersion.parse(key.version).role is not role:
        raise RequestError(
            f"{order} needs a {role.value} key; got {key.version.value}"
        )


def _root(namespace: str, name: str) -> etree._Element:
    """A payload root that declares ``xmlns:ds`` even before it is used.

    The declaration belongs on the root rather than on ``ds:X509Data`` because
    that is where every reference implementation puts it, and because a
    document whose namespace declarations move around is a document whose
    canonical form moves around.
    """
    return etree.Element(etree.QName(namespace, name),
                         nsmap={None: namespace, "ds": _DSIG})


def _sub(parent: etree._Element, namespace: str, name: str,
         text: str | None = None) -> etree._Element:
    element = etree.SubElement(parent, etree.QName(namespace, name))
    if text is not None:
        element.text = text
    return element
