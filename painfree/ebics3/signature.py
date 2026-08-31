"""The EBICS authentication signature over ``authenticate="true"`` elements.

Every EBICS request except the unsecured key-management ones carries an
``AuthSignature`` next to its header. It is an XML-DSig ``Signature`` with two
independent halves:

======================  =====================================================
``ds:DigestValue``      SHA-256 over C14N of ``//*[@authenticate='true']``
``ds:SignatureValue``   RSA over C14N of ``ds:SignedInfo``
======================  =====================================================

They fail for different reasons, so :func:`verify_auth_signature` reports them
separately: a bad digest means the canonicalisation is wrong, a bad signature
over a good digest means the key or the RSA scheme is wrong. Collapsing that
into one boolean costs an afternoon the first time a bank rejects a request.

Provenance: ported from ``ebics-api/ebics-client-php`` (MIT), whose
``Handlers/AuthSignatureHandler`` and ``Services/CryptService::encrypt`` fix the
element order, the algorithm identifiers and the signature schemes. See ADR
D-005 and D-011.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree

from .canon import (AUTHENTICATED_XPATH, C14N_INCLUSIVE, XMLDSIG_NAMESPACE,
                    canonicalize_element, canonicalize_nodeset)
from .crypto import sign, verify
from .errors import DocumentError

__all__ = [
    "DIGEST_METHOD",
    "SIGNATURE_METHOD",
    "AuthSignatureCheck",
    "auth_digest",
    "auth_digest_b64",
    "build_auth_signature",
    "declared_digest",
    "declared_signature",
    "signed_info_c14n",
    "verify_auth_signature",
]

DIGEST_METHOD = "http://www.w3.org/2001/04/xmlenc#sha256"
SIGNATURE_METHOD = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

#: What the reference URI points at. EBICS always signs the same node-set, so
#: the pointer is a constant rather than something a caller chooses.
REFERENCE_URI = f"#xpointer({AUTHENTICATED_XPATH})"

_NS = {"ds": XMLDSIG_NAMESPACE}


def auth_digest(root: etree._Element) -> bytes:
    """SHA-256 over the canonical ``authenticate='true'`` node-set."""
    return hashlib.sha256(canonicalize_nodeset(root, AUTHENTICATED_XPATH)).digest()


def auth_digest_b64(root: etree._Element) -> str:
    """The digest as it appears in ``ds:DigestValue``."""
    return base64.b64encode(auth_digest(root)).decode("ascii")


def signed_info_c14n(root: etree._Element) -> bytes:
    """The octets the RSA signature covers: canonical ``ds:SignedInfo``.

    Addressed by name. ``ebics-client-php`` reaches it as
    ``//AuthSignature/*``, which is the same node while the document is being
    signed but also selects ``ds:SignatureValue`` once it has been -- so a
    verifier written that way disagrees with the signer that produced it.
    """
    nodes = root.xpath("//ds:SignedInfo", namespaces=_NS)
    if not nodes:
        raise DocumentError("document has no ds:SignedInfo")
    return canonicalize_element(nodes[0])


def declared_digest(root: etree._Element) -> str | None:
    """The ``ds:DigestValue`` the document carries, or ``None`` if it has none.

    An element that is present but empty reports ``""``, not ``None``: several
    corpus fixtures ship ``<DigestValue/>`` as an unfilled slot, and "the
    document does not claim a digest" is a different statement from "the
    document claims the empty digest".
    """
    nodes = root.xpath("//ds:DigestValue", namespaces=_NS)
    return (nodes[0].text or "").strip() if nodes else None


def declared_signature(root: etree._Element) -> bytes | None:
    """The ``ds:SignatureValue`` the document carries, base64-decoded.

    ``None`` where the element is absent, empty bytes where it is present but
    empty -- the same absent/empty distinction :func:`declared_digest` makes.
    Whitespace is stripped because signers wrap the base64 differently and a
    line break must not decide whether a signature verifies.
    """
    nodes = root.xpath("//ds:SignatureValue", namespaces=_NS)
    if not nodes:
        return None
    return base64.b64decode("".join((nodes[0].text or "").split()))


@dataclass(frozen=True)
class AuthSignatureCheck:
    """Why an authentication signature was accepted or rejected."""

    digest_ok: bool
    digest_expected: str | None
    digest_actual: str
    signature_present: bool
    signature_ok: bool

    @property
    def ok(self) -> bool:
        return self.digest_ok and self.signature_ok

    def as_dict(self) -> dict[str, object]:
        return {
            "digest_ok": self.digest_ok,
            "digest_expected": self.digest_expected,
            "digest_actual": self.digest_actual,
            "signature_present": self.signature_present,
            "signature_ok": self.signature_ok,
            "ok": self.ok,
        }


def verify_auth_signature(
    root: etree._Element, key: rsa.RSAPublicKey, version: str = "X002"
) -> AuthSignatureCheck:
    """Check both halves of an ``AuthSignature`` against ``key``.

    A rejected signature is an ordinary protocol outcome -- a bank sends one
    when its own keys have rotated -- so this reports rather than raises.
    """
    expected = declared_digest(root)
    actual = auth_digest_b64(root)
    signature = declared_signature(root)

    return AuthSignatureCheck(
        digest_ok=expected is not None and expected == actual,
        digest_expected=expected,
        digest_actual=actual,
        signature_present=signature is not None,
        signature_ok=signature is not None
        and verify(signed_info_c14n(root), signature, key, version),
    )


def build_auth_signature(
    root: etree._Element, key: rsa.RSAPrivateKey, version: str = "X002"
) -> etree._Element:
    """Insert a complete ``AuthSignature`` into an EBICS document, in place.

    The element is built and inserted *before* the digest is taken, in the
    order a real client does it. That is safe because ``AuthSignature`` carries
    no ``authenticate`` attribute and so is not part of its own digest -- but
    doing it the other way round would hand the caller back a tree whose digest
    was computed over a different document than the one it now holds.
    """
    header = _header(root)
    auth = _empty_auth_signature(etree.QName(root).namespace)

    for stale in root.xpath("//*[local-name()='AuthSignature']"):
        stale.getparent().remove(stale)

    parent = header.getparent()
    if parent is None:
        raise DocumentError("header element has no parent")
    auth.tail = header.tail  # keep the document's indentation intact
    parent.insert(parent.index(header) + 1, auth)

    digest_value = auth.find(f".//{{{XMLDSIG_NAMESPACE}}}DigestValue")
    signature_value = auth.find(f"{{{XMLDSIG_NAMESPACE}}}SignatureValue")
    digest_value.text = auth_digest_b64(root)
    signature_value.text = base64.b64encode(
        sign(signed_info_c14n(root), key, version)
    ).decode("ascii")
    return root


def _header(root: etree._Element) -> etree._Element:
    headers = root.xpath("//*[local-name()='header']")
    if not headers:
        raise DocumentError("document has no header element")
    return headers[0]


def _empty_auth_signature(ebics_namespace: str | None) -> etree._Element:
    """The ``AuthSignature`` skeleton, with both values still empty.

    ``AuthSignature`` itself is in the EBICS namespace while everything under
    it is XML-DSig -- an asymmetry the schema insists on.
    """
    auth = etree.Element(etree.QName(ebics_namespace, "AuthSignature"))
    signed_info = etree.SubElement(auth, _ds("SignedInfo"))
    etree.SubElement(signed_info, _ds("CanonicalizationMethod")).set(
        "Algorithm", C14N_INCLUSIVE)
    etree.SubElement(signed_info, _ds("SignatureMethod")).set(
        "Algorithm", SIGNATURE_METHOD)

    reference = etree.SubElement(signed_info, _ds("Reference"))
    reference.set("URI", REFERENCE_URI)
    transforms = etree.SubElement(reference, _ds("Transforms"))
    etree.SubElement(transforms, _ds("Transform")).set("Algorithm", C14N_INCLUSIVE)
    etree.SubElement(reference, _ds("DigestMethod")).set("Algorithm", DIGEST_METHOD)
    etree.SubElement(reference, _ds("DigestValue"))
    etree.SubElement(auth, _ds("SignatureValue"))
    return auth


def _ds(local_name: str) -> etree.QName:
    return etree.QName(XMLDSIG_NAMESPACE, local_name)
