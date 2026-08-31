"""RSA primitives the EBICS protocol is built out of.

Four things live here, and nothing that knows about XML:

* the **signature schemes** behind each EBICS version (X002/A005 are
  RSASSA-PKCS1-v1_5 over SHA-256, A006 is RSASSA-PSS),
* the **public-key fingerprint** printed on the INI letter,
* the two **encodings** EBICS uses for a raw RSA number: the zero-stripped
  lower-case hex that goes into the fingerprint, and ``ds:CryptoBinary``, and
* the **E002 hybrid encryption** an upload rides on: AES-128-CBC under a random
  per-transaction key, that key wrapped with RSAES-PKCS1-v1_5 for the bank.

Ported from ``ebics-api/ebics-client-php`` (MIT): ``Services/CryptService``
``calculatePublicKeyDigest`` / ``calculateKey`` are the provenance of
:func:`public_key_digest` and :func:`public_key_hex`; see ADR D-005.
"""

from __future__ import annotations

import base64
import hashlib
import secrets

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .errors import KeyMaterialError, UnsupportedVersionError

__all__ = [
    "AES_BLOCK_SIZE",
    "MINIMUM_KEY_SIZE",
    "TRANSACTION_KEY_SIZE",
    "aes_decrypt",
    "aes_encrypt",
    "crypto_binary",
    "generate_private_key",
    "generate_transaction_key",
    "load_private_key",
    "load_public_key",
    "private_pem",
    "public_key_digest",
    "public_key_digest_hex",
    "public_key_hex",
    "public_pem",
    "rsa_decrypt",
    "rsa_encrypt",
    "sign",
    "sign_digest",
    "verify",
    "verify_digest",
]

#: EBICS 3.0 requires at least 2048-bit RSA keys; banks reject anything shorter.
MINIMUM_KEY_SIZE = 2048

#: Versions signing with RSASSA-PKCS1-v1_5 over SHA-256.
_PKCS1_VERSIONS = frozenset({"X002", "A005"})
#: Versions signing with RSASSA-PSS, SHA-256/MGF1-SHA256, salt length 32.
_PSS_VERSIONS = frozenset({"A006"})

#: Versions that may carry an electronic signature over order data. X002 signs
#: request headers and nothing else, so it is deliberately absent.
_ES_VERSIONS = frozenset({"A005", "A006"})

#: AES block size, and therefore the length of the all-zero IV E002 uses.
AES_BLOCK_SIZE = 16

#: E002 transaction keys are 128-bit: EBICS fixes the symmetric cipher at
#: AES-128, so a 32-byte key is not "stronger", it is a key the bank rejects.
TRANSACTION_KEY_SIZE = 16

_ZERO_IV = bytes(AES_BLOCK_SIZE)


def _signature_padding(version: str):
    if version in _PKCS1_VERSIONS:
        return padding.PKCS1v15()
    if version in _PSS_VERSIONS:
        return padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=hashes.SHA256().digest_size,
        )
    raise UnsupportedVersionError(f"not a signature version: {version}")


# --- key material ----------------------------------------------------------

def generate_private_key(key_size: int = MINIMUM_KEY_SIZE) -> rsa.RSAPrivateKey:
    """A fresh RSA key with the public exponent every EBICS peer expects.

    65537 is not merely conventional here: the fingerprint on the INI letter is
    derived from the exponent, and banks have tooling that assumes the usual
    one.
    """
    if key_size < MINIMUM_KEY_SIZE:
        raise KeyMaterialError(
            f"EBICS 3.0 requires at least {MINIMUM_KEY_SIZE}-bit RSA keys, asked for {key_size}"
        )
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def load_private_key(pem: bytes | str, password: bytes | None = None) -> rsa.RSAPrivateKey:
    """Load a private key from PKCS#1 or PKCS#8 PEM.

    Both formats are accepted because the reference implementations disagree:
    ``ebics-client-php``'s ``RSAFactory`` maps PKCS#1 only, while most tooling
    writes PKCS#8.
    """
    if isinstance(pem, str):
        pem = pem.encode("ascii")
    try:
        key = serialization.load_pem_private_key(pem, password=password)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise KeyMaterialError(f"cannot load private key: {type(exc).__name__}") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise KeyMaterialError("EBICS keys must be RSA")
    return key


def load_public_key(pem: bytes | str) -> rsa.RSAPublicKey:
    """Load a public key from PKCS#1 (``BEGIN RSA PUBLIC KEY``) or SPKI PEM."""
    if isinstance(pem, str):
        pem = pem.encode("ascii")
    try:
        key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise KeyMaterialError(f"cannot load public key: {type(exc).__name__}") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise KeyMaterialError("EBICS keys must be RSA")
    return key


def private_pem(key: rsa.RSAPrivateKey, password: bytes | None = None) -> bytes:
    """PKCS#1 private PEM, optionally passphrase-encrypted.

    PKCS#1 rather than PKCS#8 so the bytes round-trip through every reference
    implementation this engine was checked against, without conversion.
    """
    encryption: serialization.KeySerializationEncryption = serialization.NoEncryption()
    if password:
        encryption = serialization.BestAvailableEncryption(password)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        encryption,
    )


def public_pem(key: rsa.RSAPublicKey) -> bytes:
    """PKCS#1 public PEM (``BEGIN RSA PUBLIC KEY``)."""
    return key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.PKCS1,
    )


# --- encodings -------------------------------------------------------------

def public_key_hex(key: rsa.RSAPublicKey) -> tuple[str, str]:
    """Exponent and modulus as lower-case hex with leading zeros stripped.

    The stripping is what the other implementations spell out: PHP renders the
    number to an even number of hex digits and then ``ltrim``s the zeros, epics
    does the same with a regex. Python's formatter never emits a leading zero,
    so the ``lstrip`` is a no-op here -- it stays because the *invariant* is the
    interoperable part, not the formatter's habits.
    """
    numbers = key.public_numbers()
    return format(numbers.e, "x").lstrip("0"), format(numbers.n, "x").lstrip("0")


def public_key_digest(key: rsa.RSAPublicKey) -> bytes:
    """The SHA-256 fingerprint a human compares against the INI letter.

    ``sha256(hex(exponent) + " " + hex(modulus))`` over the zero-stripped hex.
    Getting the leading zeros wrong produces a value that will not match the
    printed letter, which is a phone call to the bank rather than a stack trace.
    """
    exponent, modulus = public_key_hex(key)
    return hashlib.sha256(f"{exponent} {modulus}".encode("ascii")).digest()


def public_key_digest_hex(key: rsa.RSAPublicKey) -> str:
    return public_key_digest(key).hex()


def crypto_binary(value: int) -> str:
    """``ds:CryptoBinary``: base64 of the minimal big-endian representation.

    Minimal means no leading zero octet -- the opposite convention from a DER
    INTEGER, and a classic source of a modulus the bank reads one byte short.
    """
    if value < 0:
        raise ValueError("ds:CryptoBinary is unsigned")
    width = max(1, (value.bit_length() + 7) // 8)
    return base64.b64encode(value.to_bytes(width, "big")).decode("ascii")


# --- signatures ------------------------------------------------------------

def sign(message: bytes, key: rsa.RSAPrivateKey, version: str) -> bytes:
    """Sign already-canonicalised octets under an EBICS signature version."""
    return key.sign(message, _signature_padding(version), hashes.SHA256())


def verify(message: bytes, signature: bytes, key: rsa.RSAPublicKey, version: str) -> bool:
    """Verify a signature, returning a bool rather than raising.

    A failed verification is an expected outcome of a protocol exchange, not an
    exceptional one; the caller decides whether it is fatal.
    """
    try:
        key.verify(signature, message, _signature_padding(version), hashes.SHA256())
    except InvalidSignature:
        return False
    return True


# --- the electronic signature over order data ------------------------------

def sign_digest(digest: bytes, key: rsa.RSAPrivateKey, version: str) -> bytes:
    """The ES: an A005/A006 signature over an *already computed* order digest.

    The two versions do not treat that digest the same way, and the difference
    is the kind that produces a signature every bank rejects:

    ``A005``  RSASSA-PKCS1-v1_5 where the digest **is** the hash -- it is
              wrapped in a SHA-256 ``DigestInfo`` and signed as it stands.
    ``A006``  RSASSA-PSS where the digest is the **message** -- PSS hashes it
              again, so the signature is over ``sha256(sha256(order data))``.

    That asymmetry is EBICS's, not this engine's; it is what
    ``CryptService::encrypt`` does and what the bank verifies against. See ADR
    D-013.
    """
    _require_es_version(version)
    if version in _PKCS1_VERSIONS:
        return key.sign(digest, padding.PKCS1v15(), Prehashed(hashes.SHA256()))
    return key.sign(digest, _signature_padding(version), hashes.SHA256())


def verify_digest(digest: bytes, signature: bytes, key: rsa.RSAPublicKey,
                  version: str) -> bool:
    """Verify an ES, the exact inverse of :func:`sign_digest`."""
    _require_es_version(version)
    try:
        if version in _PKCS1_VERSIONS:
            key.verify(signature, digest, padding.PKCS1v15(),
                       Prehashed(hashes.SHA256()))
        else:
            key.verify(signature, digest, _signature_padding(version),
                       hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def _require_es_version(version: str) -> None:
    if version not in _ES_VERSIONS:
        raise UnsupportedVersionError(
            f"the electronic signature is A005 or A006; got {version}")


# --- E002 hybrid encryption ------------------------------------------------

def generate_transaction_key() -> bytes:
    """A fresh 128-bit AES key for one transaction, and one transaction only.

    Reusing it across uploads would let a bank -- or anyone holding one
    decrypted payload -- read every other payload sent under the same key.
    """
    return secrets.token_bytes(TRANSACTION_KEY_SIZE)


def aes_encrypt(data: bytes, key: bytes, iv: bytes = _ZERO_IV) -> bytes:
    """AES-CBC with **ANSI X.923** padding -- what E002 means by "encrypted".

    Two details are easy to get wrong and impossible to debug from the bank's
    return code:

    * the padding is X.923 (zero bytes, then one byte holding the padding
      length), *not* PKCS#7, whose filler bytes all carry the length; and
    * the IV is a block of zeros. That is weak in general and fine here,
      because the key is fresh for every transaction and is used once.

    A payload whose length is already a multiple of the block size still gets a
    whole block of padding, so the inverse always has something to strip.
    """
    _require_transaction_key(key)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(_pad_x923(data)) + encryptor.finalize()


def aes_decrypt(data: bytes, key: bytes, iv: bytes = _ZERO_IV) -> bytes:
    """The inverse of :func:`aes_encrypt`."""
    _require_transaction_key(key)
    if not data or len(data) % AES_BLOCK_SIZE:
        raise KeyMaterialError(
            f"ciphertext is {len(data)} bytes, not a whole number of AES blocks")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return _unpad_x923(decryptor.update(data) + decryptor.finalize())


def rsa_encrypt(data: bytes, key: rsa.RSAPublicKey) -> bytes:
    """Wrap a transaction key for the bank: RSAES-PKCS1-v1_5, not OAEP.

    OAEP is the better scheme and the wrong one here -- E002 is defined as
    PKCS#1 v1.5, and a bank handed an OAEP block reports a decryption failure
    that says nothing about which of the two you used.
    """
    return key.encrypt(data, padding.PKCS1v15())


def rsa_decrypt(data: bytes, key: rsa.RSAPrivateKey) -> bytes:
    """Unwrap a transaction key the bank encrypted to us."""
    try:
        return key.decrypt(data, padding.PKCS1v15())
    except ValueError as exc:
        raise KeyMaterialError(
            f"cannot decrypt the transaction key: {type(exc).__name__}") from exc


def _pad_x923(data: bytes) -> bytes:
    length = AES_BLOCK_SIZE - (len(data) % AES_BLOCK_SIZE)
    return data + bytes(length - 1) + bytes([length])


def _unpad_x923(data: bytes) -> bytes:
    length = data[-1]
    if not 1 <= length <= AES_BLOCK_SIZE or length > len(data):
        raise KeyMaterialError(f"invalid X.923 padding: trailing byte {length}")
    return data[:-length]


def _require_transaction_key(key: bytes) -> None:
    if len(key) != TRANSACTION_KEY_SIZE:
        raise KeyMaterialError(
            f"E002 uses AES-128: the transaction key is {len(key)} bytes, "
            f"expected {TRANSACTION_KEY_SIZE}")
