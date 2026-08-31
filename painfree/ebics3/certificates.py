"""X.509 handling. EBICS 3.0 makes certificates mandatory, not optional.

Under H004 a bank could be given a bare modulus and exponent. Under H005 --
which is what Swiss banks run -- every key travels inside a certificate, and
``SignaturePubKeyInfo`` carries ``ds:X509Data`` with the issuer name, the serial
number and the DER certificate itself. Those three fields are exactly what the
conformance goldens ask this engine to fill.

Self-signed certificates are the normal case for a customer connection: the
bank pins the key at registration through the INI letter, so the certificate is
a container, not a trust anchor. Banks that run their own CA hand back a signed
certificate instead, which :func:`load_certificate` reads.

Key usage per version follows ``ebics-client-php``'s ``X509Generator`` (MIT);
see :mod:`painfree.ebics3.versions`.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .errors import CertificateError
from .versions import KeyVersion

__all__ = [
    "certificate_der",
    "certificate_fingerprint",
    "issuer_name",
    "load_certificate",
    "self_signed_certificate",
    "subject_name",
]

#: A year, matching what the reference implementations issue by default.
DEFAULT_VALIDITY = _dt.timedelta(days=365)

#: Backdated so a certificate is not "not yet valid" on a peer whose clock lags.
_BACKDATE = _dt.timedelta(days=1)


def subject_name(common_name: str, organization: str | None = None,
                 country: str | None = None) -> x509.Name:
    """Build the minimal EBICS subject: CN, optionally O and C."""
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if organization:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    if country:
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    return x509.Name(attributes)


def _key_usage(version: KeyVersion) -> x509.KeyUsage:
    """Exactly one usage asserted, the rest explicitly denied.

    A certificate that asserts everything is the one a bank CA bounces: the
    usage is how the bank tells a signature key from an encryption key when
    both arrive in the same HIA request.
    """
    flags = dict(
        digital_signature=False, content_commitment=False, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=False,
        crl_sign=False, encipher_only=False, decipher_only=False,
    )
    flags[version.key_usage] = True
    return x509.KeyUsage(**flags)


def self_signed_certificate(
    private_key: rsa.RSAPrivateKey,
    version: KeyVersion | str,
    subject: x509.Name,
    *,
    serial_number: int | None = None,
    not_valid_before: _dt.datetime | None = None,
    validity: _dt.timedelta = DEFAULT_VALIDITY,
) -> x509.Certificate:
    """Wrap an EBICS key in a self-signed certificate with the right key usage.

    ``serial_number`` and ``not_valid_before`` are parameters rather than always
    generated so a caller that needs a reproducible certificate -- a test, or a
    comparison against another implementation -- can pin them. Left unset they
    are random and now, which is what a real connection wants.
    """
    version = KeyVersion.parse(version)
    start = not_valid_before or _dt.datetime.now(_dt.timezone.utc) - _BACKDATE
    if start.tzinfo is None:
        start = start.replace(tzinfo=_dt.timezone.utc)
    serial = serial_number if serial_number is not None else secrets.randbits(64) + 1

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(serial)
        .not_valid_before(start)
        .not_valid_after(start + validity)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(version), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
    )
    return builder.sign(private_key, hashes.SHA256())


def load_certificate(data: bytes) -> x509.Certificate:
    """Read a certificate from PEM or DER, whichever the bank sent."""
    try:
        if b"-----BEGIN" in data:
            return x509.load_pem_x509_certificate(data)
        return x509.load_der_x509_certificate(data)
    except ValueError as exc:
        raise CertificateError(f"cannot parse certificate: {exc}") from exc


def certificate_der(certificate: x509.Certificate) -> bytes:
    """The DER octets that go, base64-encoded, into ``ds:X509Certificate``."""
    return certificate.public_bytes(serialization.Encoding.DER)


def certificate_fingerprint(certificate: x509.Certificate) -> str:
    """SHA-256 over the DER, lower-case hex -- what a bank portal displays.

    Distinct from the EBICS public-key digest in :mod:`painfree.ebics3.crypto`: that one
    hashes the RSA numbers and is what the INI letter carries. Confusing the two
    is a plausible mistake, so they do not share a name.
    """
    return hashlib.sha256(certificate_der(certificate)).hexdigest()


def issuer_name(certificate: x509.Certificate) -> str:
    """RFC 4514 issuer string, as ``ds:X509IssuerName`` expects it."""
    return certificate.issuer.rfc4514_string()
