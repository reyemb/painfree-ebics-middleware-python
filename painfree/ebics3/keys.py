"""An EBICS key: an RSA key pair, the version it plays, and its certificate.

The engine deliberately does *not* own a keyring. Where keys live, how they are
encrypted at rest and which process may decrypt them is a service-layer concern
and a security boundary in its own right. This module only knows how to hold
one key correctly and derive from it the values the protocol needs.

An :class:`EbicsKey` may be public-only. That is not a degenerate case: the
bank's keys arrive from ``HPB`` with no private half, and half the operations
in the protocol -- verifying the bank's authentication signature, encrypting a
transaction key under ``E002`` -- need nothing more.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from . import certificates, crypto
from .errors import CertificateError, KeyMaterialError, UnsupportedVersionError
from .versions import KeyVersion

__all__ = ["EbicsKey"]


@dataclass(frozen=True)
class EbicsKey:
    """One EBICS key. Frozen, because a key that mutates is a key you cannot log about."""

    version: KeyVersion
    public_key: rsa.RSAPublicKey
    private_key: rsa.RSAPrivateKey | None = None
    certificate: x509.Certificate | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "version", KeyVersion.parse(self.version))
        if self.public_key.key_size < crypto.MINIMUM_KEY_SIZE:
            raise KeyMaterialError(
                f"{self.version.value} key is {self.public_key.key_size} bits; "
                f"EBICS 3.0 requires at least {crypto.MINIMUM_KEY_SIZE}"
            )
        if self.private_key is not None and (
            self.private_key.public_key().public_numbers() != self.public_key.public_numbers()
        ):
            raise KeyMaterialError("private and public halves do not belong together")
        if self.certificate is not None:
            cert_key = self.certificate.public_key()
            if (not isinstance(cert_key, rsa.RSAPublicKey)
                    or cert_key.public_numbers() != self.public_key.public_numbers()):
                raise CertificateError(
                    f"certificate does not carry the {self.version.value} public key"
                )

    # --- construction ------------------------------------------------------

    @classmethod
    def generate(
        cls,
        version: KeyVersion | str,
        *,
        subject: x509.Name | None = None,
        key_size: int = crypto.MINIMUM_KEY_SIZE,
        **certificate_options,
    ) -> "EbicsKey":
        """Mint a new key, with a self-signed certificate when a subject is given.

        EBICS 3.0 requires the certificate, so a caller registering a new
        connection always passes a subject; leaving it out is for the cases
        where the certificate is issued elsewhere and attached later with
        :meth:`with_certificate`.
        """
        version = KeyVersion.parse(version)
        private_key = crypto.generate_private_key(key_size)
        certificate = None
        if subject is not None:
            certificate = certificates.self_signed_certificate(
                private_key, version, subject, **certificate_options
            )
        return cls(version, private_key.public_key(), private_key, certificate)

    @classmethod
    def from_private_pem(
        cls,
        version: KeyVersion | str,
        pem: bytes | str,
        password: bytes | None = None,
        certificate: x509.Certificate | None = None,
    ) -> "EbicsKey":
        private_key = crypto.load_private_key(pem, password)
        return cls(KeyVersion.parse(version), private_key.public_key(), private_key, certificate)

    @classmethod
    def from_public_pem(
        cls,
        version: KeyVersion | str,
        pem: bytes | str,
        certificate: x509.Certificate | None = None,
    ) -> "EbicsKey":
        return cls(KeyVersion.parse(version), crypto.load_public_key(pem), None, certificate)

    @classmethod
    def from_certificate(cls, version: KeyVersion | str, data: bytes) -> "EbicsKey":
        """Take the public key out of a certificate -- how a bank's keys arrive."""
        certificate = certificates.load_certificate(data)
        public_key = certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise CertificateError("EBICS certificates must carry an RSA key")
        return cls(KeyVersion.parse(version), public_key, None, certificate)

    def with_certificate(self, certificate: x509.Certificate) -> "EbicsKey":
        """Attach a certificate issued elsewhere, keeping the key immutable."""
        return replace(self, certificate=certificate)

    # --- identity ----------------------------------------------------------

    @property
    def has_private(self) -> bool:
        return self.private_key is not None

    @property
    def fingerprint(self) -> bytes:
        """The EBICS public-key digest -- the value on the INI letter."""
        return crypto.public_key_digest(self.public_key)

    @property
    def fingerprint_hex(self) -> str:
        return crypto.public_key_digest_hex(self.public_key)

    @property
    def exponent_hex(self) -> str:
        return crypto.public_key_hex(self.public_key)[0]

    @property
    def modulus_hex(self) -> str:
        return crypto.public_key_hex(self.public_key)[1]

    @property
    def exponent_b64(self) -> str:
        """``ds:CryptoBinary`` exponent, as ``PubKeyValue`` carries it."""
        return crypto.crypto_binary(self.public_key.public_numbers().e)

    @property
    def modulus_b64(self) -> str:
        return crypto.crypto_binary(self.public_key.public_numbers().n)

    # --- serialisation -----------------------------------------------------

    def public_pem(self) -> bytes:
        return crypto.public_pem(self.public_key)

    def private_pem(self, password: bytes | None = None) -> bytes:
        if self.private_key is None:
            raise KeyMaterialError(f"{self.version.value} key has no private half")
        return crypto.private_pem(self.private_key, password)

    def certificate_der(self) -> bytes:
        if self.certificate is None:
            raise CertificateError(f"{self.version.value} key has no certificate")
        return certificates.certificate_der(self.certificate)

    # --- signatures --------------------------------------------------------

    def sign(self, message: bytes) -> bytes:
        if not self.version.can_sign:
            raise UnsupportedVersionError(f"{self.version.value} is an encryption key")
        if self.private_key is None:
            raise KeyMaterialError(f"{self.version.value} key has no private half")
        return crypto.sign(message, self.private_key, self.version.value)

    def verify(self, message: bytes, signature: bytes) -> bool:
        if not self.version.can_sign:
            raise UnsupportedVersionError(f"{self.version.value} is an encryption key")
        return crypto.verify(message, signature, self.public_key, self.version.value)

    def __repr__(self) -> str:
        """Fingerprint, never material: this string ends up in logs."""
        return (f"EbicsKey({self.version.value}, {self.public_key.key_size} bit, "
                f"fingerprint={self.fingerprint_hex[:16]}…, "
                f"private={self.has_private}, certificate={self.certificate is not None})")
