"""The order-data pipeline: sign, compress, encrypt, encode -- and its inverse.

Everything a client uploads takes the same four steps, in this order, and a
port that swaps any two of them produces a request the bank cannot open:

1. **Sign.** SHA-256 the order data, then sign *that digest* with the A005/A006
   key. The result is the electronic signature (the *ES*), carried as a small
   ``UserSignatureData`` document -- not as an XML-DSig ``Signature``, and not
   over the request. The ES authorises the payment; the authentication
   signature in :mod:`painfree.ebics3.signature` only authenticates the
   message, and confusing the two is how a client ends up moving money it
   never meant to.
2. **Compress.** zlib (RFC 1950), the same deflate the unsecured requests use.
   Compression happens *before* encryption, because ciphertext does not
   compress.
3. **Encrypt.** AES-128-CBC under a transaction key that is fresh for this
   transaction, with an all-zero IV and ANSI X.923 padding -- E002.
4. **Encode.** base64, no line breaks.

The transaction key itself travels beside the data, wrapped with
RSAES-PKCS1-v1_5 under the bank's E002 public key, in ``DataEncryptionInfo``.
Both the ES and every order-data segment are encrypted under the *same*
transaction key, which is why :class:`SecuredOrderData` hands it back to the
caller: the transfer phase needs it again for each segment.

::

    order data ──sha256──▶ digest ──A005/A006──▶ ES ─┐
         │                    │                      ├─zlib─▶ AES ─▶ base64
         │                    └──▶ <DataDigest>      │           │
         └──────────────────────────zlib─▶ AES ─▶ base64        <SignatureData>
                                            │
                                    transaction key ──RSA(bank E002)──▶
                                                            <TransactionKey>

The inverse -- decode, decrypt, decompress -- is the download direction, and is
the same transform read backwards: :func:`open_order_data`.

Provenance: ported from ``ebics-api/ebics-client-php`` (MIT), whose
``Handlers/UserSignatureHandlerV3``, ``Builders/Request/DataTransferBuilder``,
``Builders/Request/DataEncryptionInfoBuilder`` and ``Services/CryptService``
fix the element order, the padding scheme and the two signature schemes. See
ADR D-005 and D-013.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field

from lxml import etree

from .crypto import (aes_decrypt, aes_encrypt, generate_transaction_key,
                     rsa_decrypt, rsa_encrypt, sign_digest, verify_digest)
from .errors import DocumentError, KeyMaterialError, RequestError
from .keys import EbicsKey
from .orderdata import (S002_NAMESPACE, compress_order_data,
                        decompress_order_data, serialize_order_data)
from .versions import KeyRole, KeyVersion

__all__ = [
    "USER_SIGNATURE_SCHEMA_LOCATION",
    "SecuredOrderData",
    "build_user_signature",
    "decrypt_payload",
    "encrypt_payload",
    "open_order_data",
    "order_data_digest",
    "secure_order_data",
    "unwrap_transaction_key",
    "user_signature_value",
    "verify_user_signature",
    "wrap_transaction_key",
]

#: The hint every implementation stamps on ``UserSignatureData``.
#:
#: ADR D-012 keeps ``xsi:schemaLocation`` off *request* roots because it drags
#: ``xmlns:xsi`` into scope on the ``header`` apex and so changes the digest the
#: authentication signature covers. Nothing canonicalises this document -- it is
#: compressed and encrypted as a blob -- so that reasoning does not reach here,
#: and emitting the hint keeps the plaintext byte-comparable with the reference
#: implementation. Callers who want it gone pass ``schema_location=None``.
USER_SIGNATURE_SCHEMA_LOCATION = (
    "http://www.ebics.org/S002 http://www.ebics.org/S002/ebics_signature.xsd")

_XSI = "http://www.w3.org/2001/XMLSchema-instance"


# --- step 1: the electronic signature --------------------------------------

def order_data_digest(order_content: bytes) -> bytes:
    """SHA-256 over the order data exactly as it will be uploaded.

    "Exactly as uploaded" is the whole contract: this value is signed into the
    ES *and* published in ``DataDigest``, and the bank recomputes it over the
    bytes it decrypts. Hash a prettified or re-serialised copy of the payload
    and the two disagree, which the bank reports as a signature failure rather
    than as the encoding problem it is.
    """
    return hashlib.sha256(order_content).digest()


def build_user_signature(
    digest: bytes,
    signature_key: EbicsKey,
    partner_id: str,
    user_id: str,
    *,
    schema_location: str | None = USER_SIGNATURE_SCHEMA_LOCATION,
) -> etree._Element:
    """The ``UserSignatureData`` document that carries one ES.

    ``OrderSignatureData`` is a sequence and the schema means it: version,
    value, partner, user. It may repeat -- distributed signature has several
    people sign the same order -- but one client signature is one element.
    """
    if signature_key.private_key is None:
        raise RequestError(
            f"the ES needs the private half of the "
            f"{signature_key.version.value} key")
    if signature_key.version.role is not KeyRole.SIGNATURE:
        raise RequestError(
            f"the ES needs a signature key; got {signature_key.version.value}")

    signature = sign_digest(digest, signature_key.private_key,
                            signature_key.version.value)

    root = etree.Element(etree.QName(S002_NAMESPACE, "UserSignatureData"),
                         nsmap={None: S002_NAMESPACE, "xsi": _XSI})
    if schema_location is not None:
        root.set(etree.QName(_XSI, "schemaLocation"), schema_location)

    order = etree.SubElement(root, etree.QName(S002_NAMESPACE,
                                               "OrderSignatureData"))
    _sub(order, "SignatureVersion", signature_key.version.value)
    _sub(order, "SignatureValue", base64.b64encode(signature).decode("ascii"))
    _sub(order, "PartnerID", partner_id)
    _sub(order, "UserID", user_id)
    return root


def user_signature_value(root: etree._Element) -> bytes | None:
    """The ES bytes out of a ``UserSignatureData`` document, base64-decoded."""
    nodes = root.xpath("//*[local-name()='SignatureValue']")
    if not nodes:
        return None
    return base64.b64decode("".join((nodes[0].text or "").split()))


def verify_user_signature(root: etree._Element, digest: bytes,
                          signature_key: EbicsKey) -> bool:
    """Does the ES in this document authorise that digest?

    The version comes out of the document rather than from the caller: the
    signer states which scheme it used, and verifying under a different one is
    how a client accepts a signature nobody made.
    """
    signature = user_signature_value(root)
    if signature is None:
        raise DocumentError("document carries no OrderSignatureData/SignatureValue")
    versions = root.xpath("//*[local-name()='SignatureVersion']")
    if not versions or not (versions[0].text or "").strip():
        raise DocumentError("document carries no SignatureVersion")
    version = KeyVersion.parse(versions[0].text.strip())
    return verify_digest(digest, signature, signature_key.public_key, version.value)


# --- steps 2-4, and their inverse ------------------------------------------

def encrypt_payload(plaintext: bytes, transaction_key: bytes) -> str:
    """Compress, encrypt, encode -- the three steps that follow the signature."""
    return base64.b64encode(
        aes_encrypt(compress_order_data(plaintext), transaction_key)
    ).decode("ascii")


def decrypt_payload(payload: str | bytes, transaction_key: bytes) -> bytes:
    """Decode, decrypt, decompress: :func:`encrypt_payload` read backwards."""
    try:
        ciphertext = base64.b64decode(_joined(payload), validate=True)
    except ValueError as exc:
        raise DocumentError(f"payload is not base64: {exc}") from exc
    return decompress_order_data(aes_decrypt(ciphertext, transaction_key))


def wrap_transaction_key(transaction_key: bytes,
                         bank_encryption_key: EbicsKey) -> bytes:
    """Encrypt the transaction key to the bank's E002 key."""
    _require_encryption_key(bank_encryption_key)
    return rsa_encrypt(transaction_key, bank_encryption_key.public_key)


def unwrap_transaction_key(wrapped: bytes, encryption_key: EbicsKey) -> bytes:
    """Recover a transaction key wrapped to *our* E002 key."""
    _require_encryption_key(encryption_key)
    if encryption_key.private_key is None:
        raise KeyMaterialError(
            "unwrapping needs the private half of the E002 key")
    return rsa_decrypt(wrapped, encryption_key.private_key)


# --- the two directions, as one call each ----------------------------------

@dataclass(frozen=True)
class SecuredOrderData:
    """One payload, signed and wrapped, with everything the body needs.

    The transaction key is here because the transfer phase needs it again for
    every segment. It is deliberately kept out of ``repr``: key material does
    not belong in a log line or a traceback.
    """

    digest: bytes
    signature_version: KeyVersion
    signature_data: str
    transaction_key_encrypted: bytes
    transaction_key: bytes = field(repr=False)

    def encrypt(self, order_content: bytes) -> str:
        """One order-data segment, under the same transaction key."""
        return encrypt_payload(order_content, self.transaction_key)

    @property
    def digest_b64(self) -> str:
        """The digest as ``DataDigest`` carries it."""
        return base64.b64encode(self.digest).decode("ascii")


def secure_order_data(
    order_content: bytes,
    *,
    signature_key: EbicsKey,
    bank_encryption_key: EbicsKey,
    partner_id: str,
    user_id: str,
    transaction_key: bytes | None = None,
) -> SecuredOrderData:
    """Run the whole upload pipeline over one payload.

    ``transaction_key`` exists so a test or a differential comparison can pin
    it. Left unset it is fresh, which is the only thing a real upload should
    ever do -- see :func:`painfree.ebics3.generate_transaction_key`.
    """
    digest = order_data_digest(order_content)
    signature = build_user_signature(digest, signature_key, partner_id, user_id)
    key = transaction_key if transaction_key is not None else generate_transaction_key()

    return SecuredOrderData(
        digest=digest,
        signature_version=signature_key.version,
        signature_data=encrypt_payload(serialize_order_data(signature), key),
        transaction_key_encrypted=wrap_transaction_key(key, bank_encryption_key),
        transaction_key=key,
    )


def open_order_data(payload: str | bytes, transaction_key_encrypted: bytes,
                    encryption_key: EbicsKey) -> bytes:
    """The download direction: unwrap the key, then decode/decrypt/inflate.

    The bank encrypts to *our* E002 key, so this takes the key with its private
    half -- the mirror image of :func:`secure_order_data`, which encrypts to
    the bank's public one.
    """
    key = unwrap_transaction_key(transaction_key_encrypted, encryption_key)
    return decrypt_payload(payload, key)


def _require_encryption_key(key: EbicsKey) -> None:
    if key.version.role is not KeyRole.ENCRYPTION:
        raise RequestError(
            f"the transaction key is wrapped under E002; got {key.version.value}")


def _joined(payload: str | bytes) -> bytes:
    """base64 with any line breaks removed -- implementations wrap differently."""
    if isinstance(payload, str):
        payload = payload.encode("ascii")
    return b"".join(payload.split())


def _sub(parent: etree._Element, name: str, text: str) -> etree._Element:
    element = etree.SubElement(parent, etree.QName(S002_NAMESPACE, name))
    element.text = text
    return element
