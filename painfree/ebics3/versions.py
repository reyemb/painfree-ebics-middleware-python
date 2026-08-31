"""The EBICS key versions and what each one is allowed to do.

EBICS names a key by the algorithm version it plays, not by its role, so the
role has to be carried alongside it. Three roles, four versions:

============ ================================================================
``A005``     Electronic signature over order data, RSASSA-PKCS1-v1_5.
``A006``     Electronic signature over order data, RSASSA-PSS. Preferred for
             EBICS 3.0; ``A005`` remains legal and some banks still require it.
``X002``     Authentication signature over the request header.
``E002``     Encryption of the per-transaction key. Never signs.
============ ================================================================

The X.509 key usages are the ones ``ebics-client-php``'s ``X509Generator``
sets, and they are what a bank's CA checks: a certificate whose key usage does
not match its EBICS role is rejected at registration, not at first payment.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["KeyRole", "KeyVersion"]


class KeyRole(str, Enum):
    """What a key is for. Several versions can play the same role."""

    SIGNATURE = "signature"
    AUTHENTICATION = "authentication"
    ENCRYPTION = "encryption"


class KeyVersion(str, Enum):
    """An EBICS key version, carrying its role and its X.509 key usage."""

    A005 = "A005"
    A006 = "A006"
    X002 = "X002"
    E002 = "E002"

    @property
    def role(self) -> KeyRole:
        return _ROLES[self]

    @property
    def can_sign(self) -> bool:
        return self.role is not KeyRole.ENCRYPTION

    @property
    def key_usage(self) -> str:
        """The single X.509 key usage this version's certificate must assert."""
        return _KEY_USAGES[self]

    @classmethod
    def parse(cls, value: "str | KeyVersion") -> "KeyVersion":
        """Coerce a wire string to a version, with an EBICS-shaped error."""
        from .errors import UnsupportedVersionError

        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).upper())
        except ValueError as exc:
            raise UnsupportedVersionError(f"unknown EBICS key version: {value!r}") from exc


_ROLES = {
    KeyVersion.A005: KeyRole.SIGNATURE,
    KeyVersion.A006: KeyRole.SIGNATURE,
    KeyVersion.X002: KeyRole.AUTHENTICATION,
    KeyVersion.E002: KeyRole.ENCRYPTION,
}

#: Signature keys are non-repudiation (they authorise money), the auth key is a
#: plain digital signature, the encryption key only wraps the transaction key.
_KEY_USAGES = {
    KeyVersion.A005: "content_commitment",
    KeyVersion.A006: "content_commitment",
    KeyVersion.X002: "digital_signature",
    KeyVersion.E002: "key_encipherment",
}
