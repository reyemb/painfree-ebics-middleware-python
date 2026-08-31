"""Envelope encryption for the one kind of secret this service stores.

An EBICS private key authorises money movement. It is written to the database
sealed and never in the clear, and this module is the only place that seals or
opens one.

The envelope is deliberately boring::

    b"pfk1" | version | key_id (16 hex chars) | nonce (12 bytes) | AES-256-GCM

Four properties are worth stating, because each is a failure this shape is
chosen to prevent:

**The key id travels with the ciphertext.** A rotated or mistyped
``PAINFREE_KEY_ENCRYPTION_SECRET`` is then diagnosable from one log line -- the
error names the key the material was sealed with and the key the process was
configured with -- rather than surfacing as an authentication-tag failure with
nothing to identify it. It is a hash of the derived key, not the key, so it is
safe to log and safe to store beside the ciphertext.

**Every seal is bound to where it is stored.** The row's identity (connection,
holder, key version, generation) is the AEAD's associated data. A ciphertext
moved to another row -- by a restore of the wrong backup, or by someone with
write access to one table -- fails to open instead of silently decrypting as
another connection's signing key.

**Opening fails closed and loudly.** There is no "try the old key" path and no
fallback to plaintext. A seal that will not open raises, is logged where it is
raised, and the caller decides; nothing here returns ``None`` and hopes.

**Nothing in this module logs the secret or the plaintext**, and the exceptions
it raises carry key *ids* and lengths only, because an exception message ends up
in a traceback and a traceback ends up in the log stream.

The secret is expected to be generated, not chosen: ``python -m painfree
new-secret`` prints one, and :func:`derive_custody_key` refuses anything shorter
than :data:`MINIMUM_SECRET_LENGTH`. That assumption is what makes HKDF the right
derivation here; a human-chosen passphrase would need a memory-hard function
instead, and the length check is there so the assumption is enforced rather than
trusted.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from painfree.logging import get_logger, register_secret

log = get_logger("painfree.sealing")

MAGIC = b"pfk1"
ENVELOPE_VERSION = 1
KEY_ID_LENGTH = 16
NONCE_SIZE = 12
HEADER_SIZE = len(MAGIC) + 1 + KEY_ID_LENGTH

#: A generated secret, not a passphrase. 32 characters is 192 bits from the
#: alphabet `new-secret` uses; below that HKDF is being asked to stretch
#: something it cannot stretch.
MINIMUM_SECRET_LENGTH = 32

#: Fixed, and not a substitute for the secret's own entropy. A per-installation
#: salt would have to be stored somewhere, and the only place available is the
#: configuration the secret already comes from.
_HKDF_SALT = b"painfree/key-encryption/v1"
_HKDF_INFO = b"painfree custody key"
_KEY_ID_INFO = b"painfree custody key id"


class SealingError(Exception):
    """A sealed secret could not be produced or opened. Never recoverable here."""


class WrongCustodyKeyError(SealingError):
    """The material was sealed with a different key than the one configured.

    Its own type because it is the one failure with an operational answer:
    restore the previous ``PAINFREE_KEY_ENCRYPTION_SECRET``, or re-key the
    connection. Both key ids are on the exception.
    """

    def __init__(self, sealed_with: str, configured: str) -> None:
        super().__init__(
            f"sealed with custody key {sealed_with}, but this process is "
            f"configured with {configured}; the encryption secret was rotated "
            f"or is wrong"
        )
        self.sealed_with = sealed_with
        self.configured = configured


class CorruptSealError(SealingError):
    """The envelope is not one of ours, or its authentication tag failed."""


@dataclass(frozen=True)
class CustodyKey:
    """The symmetric key every stored private key is sealed under.

    Holding one of these *is* the ability to read every private key in the
    database, which is why nothing on the request-handling path is given one --
    see :mod:`painfree.custody`. It is passed explicitly, never fetched from a
    module-level global, so a reviewer can see every place it reaches by
    reading the call sites.
    """

    _key: bytes = field(repr=False)
    key_id: str

    def __post_init__(self) -> None:
        if len(self._key) != 32:
            raise SealingError("a custody key is 32 bytes")

    def seal(self, plaintext: bytes, *, context: bytes) -> bytes:
        """Seal ``plaintext``, bound to ``context``, into one opaque blob."""
        if not plaintext:
            raise SealingError("refusing to seal empty material")
        header = MAGIC + bytes([ENVELOPE_VERSION]) + self.key_id.encode("ascii")
        nonce = secrets.token_bytes(NONCE_SIZE)
        ciphertext = AESGCM(self._key).encrypt(
            nonce, plaintext, header + context
        )
        return header + nonce + ciphertext

    def derive_subkey(self, info: bytes, length: int = 32) -> bytes:
        """A key for a *different* purpose, derived from the same custody secret.

        One secret in the environment, several keys in the code. The label is
        the whole separation: material derived under one ``info`` is unrelated
        to material derived under another, so the X25519 scalar
        :mod:`painfree.wrapping` builds from this is not the AES key that seals
        a private key, and neither can be used in the other's place.

        It exists so that a second key does not become a second thing to
        configure, back up and rotate. Anything derived here is readable by
        exactly whoever holds the custody secret -- which is the property the
        process split already enforces.
        """
        return HKDF(algorithm=hashes.SHA256(), length=length,
                    salt=_HKDF_SALT, info=info).derive(self._key)

    def open(self, blob: bytes, *, context: bytes) -> bytes:
        """Open a blob sealed by :meth:`seal` with the same key and context.

        Raises :class:`WrongCustodyKeyError` when the key ids disagree and
        :class:`CorruptSealError` for everything else -- a truncated blob, a
        foreign envelope, or an authentication tag that does not verify because
        the row was moved or edited.
        """
        if len(blob) <= HEADER_SIZE + NONCE_SIZE or not blob.startswith(MAGIC):
            raise CorruptSealError(
                f"not a painfree sealed secret ({len(blob)} bytes)")
        version = blob[len(MAGIC)]
        if version != ENVELOPE_VERSION:
            raise CorruptSealError(
                f"sealed secret envelope version {version} is not supported")
        sealed_with = blob[len(MAGIC) + 1:HEADER_SIZE].decode("ascii", "replace")
        if not hmac.compare_digest(sealed_with, self.key_id):
            # The loud half of failing closed. Both ids and the row are on the
            # line, because "which secret does this database want" is the only
            # question an operator has here and it should not need a debugger.
            log.error(
                "custody.key_mismatch",
                sealed_with_key_id=sealed_with,
                configured_key_id=self.key_id,
                context=context.decode("utf-8", "replace"),
                reason="the key encryption secret was rotated or is wrong",
            )
            raise WrongCustodyKeyError(sealed_with, self.key_id)

        header, rest = blob[:HEADER_SIZE], blob[HEADER_SIZE:]
        nonce, ciphertext = rest[:NONCE_SIZE], rest[NONCE_SIZE:]
        try:
            return AESGCM(self._key).decrypt(nonce, ciphertext, header + context)
        except InvalidTag as exc:
            # Logged where it is raised: an authentication failure on stored key
            # material is the line an operator has to see, and the context tells
            # them which row it was without revealing anything about the key.
            log.error(
                "custody.seal_unreadable",
                key_id=self.key_id,
                context=context.decode("utf-8", "replace"),
                reason="authentication tag failed",
            )
            raise CorruptSealError(
                "the sealed secret did not authenticate; it was edited, "
                "truncated, or moved to a row it was not sealed for"
            ) from exc


def sealed_with(blob: bytes) -> str | None:
    """The key id a blob was sealed under, without needing the key.

    Used by the diagnostics path -- listing which connections a rotated secret
    has orphaned should not require the ability to open any of them.
    """
    if len(blob) < HEADER_SIZE or not blob.startswith(MAGIC):
        return None
    return blob[len(MAGIC) + 1:HEADER_SIZE].decode("ascii", "replace")


def derive_custody_key(secret: str) -> CustodyKey:
    """Derive the custody key from the configured secret.

    Deterministic: the same secret always produces the same key and the same
    key id, which is what makes an existing database readable after a restart
    and a *changed* secret detectable rather than merely broken.
    """
    if secret is None or len(secret) < MINIMUM_SECRET_LENGTH:
        raise SealingError(
            f"the key encryption secret must be at least "
            f"{MINIMUM_SECRET_LENGTH} characters; generate one with "
            f"`python -m painfree new-secret`"
        )
    # A process that can open the keyring has now taught the log stream what
    # not to print. The secret is high-entropy free text, so no shape-based
    # rule can recognise it in an exception message a call site interpolated it
    # into -- which is exactly how a credential leaked the first time this
    # repo's logging was tested.
    register_secret(secret)
    material = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=_HKDF_SALT, info=_HKDF_INFO
    ).derive(secret.encode("utf-8"))
    return CustodyKey(material, key_id_for(material))


def key_id_for(material: bytes) -> str:
    """A stable, non-reversible name for a custody key. Safe to log and store."""
    return hashlib.sha256(_KEY_ID_INFO + material).hexdigest()[:KEY_ID_LENGTH]


def new_secret() -> str:
    """A fresh secret for ``PAINFREE_KEY_ENCRYPTION_SECRET``."""
    return secrets.token_urlsafe(32)


__all__ = [
    "CorruptSealError",
    "CustodyKey",
    "ENVELOPE_VERSION",
    "MINIMUM_SECRET_LENGTH",
    "SealingError",
    "WrongCustodyKeyError",
    "derive_custody_key",
    "key_id_for",
    "new_secret",
    "sealed_with",
]
