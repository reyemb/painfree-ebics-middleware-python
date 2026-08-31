"""Writing a secret the writer cannot read back.

:mod:`painfree.sealing` is symmetric: sealing and opening are the same
capability, so a process that can store a secret can also recover it. That is
right for an EBICS private key, which only the worker ever touches. It is the
wrong shape for a **webhook signing secret**, because of who has to see one.

A signing secret is generated when a consumer registers an endpoint, and the
consumer needs the value -- it goes into their receiver's configuration. The
only process talking to that consumer is the API process, and the API process
holds no custody key by construction: it cannot seal, so it cannot store what
it just generated. Handing it the custody key to fix that would put the ability
to read every EBICS private key back into the request path, which is the one
thing the process split exists to prevent.

So this module gives the request path the *other* half of the pair. Sealing is
public-key: anybody holding the published public half can write a secret, and
only a process that can derive the private half -- which is a process holding
the custody secret -- can read one. The API generates the secret, shows it to
the registering caller exactly once, seals it to the public half and forgets
it. From that moment the value is unrecoverable in the process that made it.

**"Shown once" becomes a property rather than a promise.** A future debug
route, a serialiser that dumps a row, an exception that interpolated a
subscription -- none of them can produce the secret in the API process, because
it is not there in any form that process can undo.

The envelope::

    b"pfw1" | version | custody_key_id (16 chars) | ephemeral X25519 public key
            | nonce (12 bytes) | AES-256-GCM ciphertext

which is the standard sealed-box construction: an ephemeral X25519 keypair per
message, ECDH against the recipient, HKDF over the shared secret **and both
public keys**, then AES-256-GCM with the header and the row's context as
associated data. The ephemeral private half is discarded with the function's
stack frame, so the ciphertext cannot be opened again by whoever produced it.

**The recipient keypair is derived, not stored.** Its private scalar comes from
:meth:`painfree.sealing.CustodyKey.derive_subkey` under a label of its own, so
there is no second secret to configure, back up or rotate: whoever holds
``PAINFREE_KEY_ENCRYPTION_SECRET`` holds this too, and whoever does not, does
not. What is *stored* is the public half, in :data:`painfree.schema.
webhook_wrapping_key`, published by the worker at startup so the API can find
it. That row is public material -- it lets its holder write secrets and read
none.

**A rotated custody secret gives a new recipient.** The custody key id travels
in the envelope, exactly as it does in :mod:`painfree.sealing`, so a secret
sealed to the old one fails with the same named, diagnosable error rather than
an anonymous authentication-tag failure.
"""

from __future__ import annotations

import datetime as _dt
import secrets as _secrets
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey,
                                                              X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import Engine, select

from painfree.logging import get_logger
from painfree.schema import webhook_wrapping_key
from painfree.sealing import (KEY_ID_LENGTH, CorruptSealError, CustodyKey,
                              SealingError, WrongCustodyKeyError)

log = get_logger("painfree.wrapping")

MAGIC = b"pfw1"
ENVELOPE_VERSION = 1
PUBLIC_KEY_SIZE = 32
NONCE_SIZE = 12
HEADER_SIZE = len(MAGIC) + 1 + KEY_ID_LENGTH
SEALED_PREFIX_SIZE = HEADER_SIZE + PUBLIC_KEY_SIZE + NONCE_SIZE

#: The label the recipient's private scalar is derived under. Changing it
#: changes the keypair, which orphans every secret sealed to the old one -- so
#: it is a constant and not a parameter.
_RECIPIENT_INFO = b"painfree webhook secret wrapping key v1"

_HKDF_SALT = b"painfree/webhook-secret-wrapping/v1"
_HKDF_INFO = b"painfree webhook secret wrapping"


@dataclass(frozen=True, slots=True)
class Recipient:
    """The published public half, and the custody key it belongs to.

    What the request path is given. Holding one is the ability to *write* a
    secret nobody but the worker can read -- and nothing else.
    """

    custody_key_id: str
    public_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if len(self.public_key) != PUBLIC_KEY_SIZE:
            raise SealingError(
                f"a wrapping public key is {PUBLIC_KEY_SIZE} bytes, "
                f"got {len(self.public_key)}")
        if len(self.custody_key_id) != KEY_ID_LENGTH:
            raise SealingError("a wrapping key carries a 16-character key id")

    def seal(self, plaintext: bytes, *, context: bytes) -> bytes:
        """Seal ``plaintext`` to this recipient, bound to ``context``."""
        if not plaintext:
            raise SealingError("refusing to seal empty material")
        header = (MAGIC + bytes([ENVELOPE_VERSION])
                  + self.custody_key_id.encode("ascii"))
        ephemeral = X25519PrivateKey.generate()
        ephemeral_public = ephemeral.public_key().public_bytes_raw()
        shared = ephemeral.exchange(
            X25519PublicKey.from_public_bytes(self.public_key))
        key = _derive(shared, ephemeral_public, self.public_key)
        nonce = _secrets.token_bytes(NONCE_SIZE)
        prefix = header + ephemeral_public + nonce
        ciphertext = AESGCM(key).encrypt(nonce, plaintext,
                                         header + ephemeral_public + context)
        return prefix + ciphertext


def recipient_for(custody_key: CustodyKey) -> Recipient:
    """The recipient this custody key is the private half of."""
    return Recipient(custody_key.key_id, _private(custody_key)
                     .public_key().public_bytes_raw())


def unseal(custody_key: CustodyKey, blob: bytes, *, context: bytes) -> bytes:
    """Open a blob sealed to this custody key's recipient.

    Fails closed and loudly, exactly as :meth:`painfree.sealing.CustodyKey.open`
    does, and raises the same two exception types so a caller that already
    handles a rotated custody secret handles this one too.
    """
    if len(blob) <= SEALED_PREFIX_SIZE or not blob.startswith(MAGIC):
        raise CorruptSealError(
            f"not a painfree wrapped secret ({len(blob)} bytes)")
    version = blob[len(MAGIC)]
    if version != ENVELOPE_VERSION:
        raise CorruptSealError(
            f"wrapped secret envelope version {version} is not supported")
    sealed_with = blob[len(MAGIC) + 1:HEADER_SIZE].decode("ascii", "replace")
    if not _secrets.compare_digest(sealed_with, custody_key.key_id):
        log.error("wrapping.key_mismatch", sealed_with_key_id=sealed_with,
                  configured_key_id=custody_key.key_id,
                  context=context.decode("utf-8", "replace"),
                  reason="the key encryption secret was rotated or is wrong")
        raise WrongCustodyKeyError(sealed_with, custody_key.key_id)

    header = blob[:HEADER_SIZE]
    ephemeral_public = blob[HEADER_SIZE:HEADER_SIZE + PUBLIC_KEY_SIZE]
    nonce = blob[HEADER_SIZE + PUBLIC_KEY_SIZE:SEALED_PREFIX_SIZE]
    ciphertext = blob[SEALED_PREFIX_SIZE:]
    private = _private(custody_key)
    try:
        shared = private.exchange(
            X25519PublicKey.from_public_bytes(ephemeral_public))
    except ValueError as exc:  # a public key that is not on the curve
        raise CorruptSealError(
            "the wrapped secret's ephemeral public key is not usable") from exc
    key = _derive(shared, ephemeral_public,
                  private.public_key().public_bytes_raw())
    try:
        return AESGCM(key).decrypt(nonce, ciphertext,
                                   header + ephemeral_public + context)
    except InvalidTag as exc:
        log.error("wrapping.seal_unreadable", key_id=custody_key.key_id,
                  context=context.decode("utf-8", "replace"),
                  reason="authentication tag failed")
        raise CorruptSealError(
            "the wrapped secret did not authenticate; it was edited, "
            "truncated, or moved to a row it was not sealed for") from exc


def is_wrapped(blob: bytes) -> bool:
    """Whether this blob is one of ours rather than a symmetric seal.

    Both envelopes are stored in the same column: a subscription registered
    before the request path could seal at all carries a
    :mod:`painfree.sealing` blob, and one registered since carries this. The
    magic is what tells them apart, so neither has to be migrated.
    """
    return blob.startswith(MAGIC)


# --- the published public half ---------------------------------------------

def publish(engine: Engine, custody_key: CustodyKey) -> Recipient:
    """Make this custody key's public half available to the request path.

    Called by the worker at startup. Idempotent: the row is keyed by the
    custody key id and the value is deterministic, so publishing twice writes
    the same bytes and publishing after a custody rotation adds a second row
    rather than replacing the first.
    """
    published = recipient_for(custody_key)
    with engine.begin() as connection:
        existing = connection.execute(
            select(webhook_wrapping_key.c.public_key)
            .where(webhook_wrapping_key.c.custody_key_id
                   == published.custody_key_id)).scalar_one_or_none()
        if existing is None:
            connection.execute(webhook_wrapping_key.insert().values(
                custody_key_id=published.custody_key_id,
                public_key=published.public_key,
                created_at=_dt.datetime.now(_dt.timezone.utc)))
            log.info("wrapping.key_published",
                     custody_key_id=published.custody_key_id)
        elif bytes(existing) != published.public_key:
            # Two different public halves under one custody key id is not a
            # collision anybody should try to recover from silently: it means
            # the row was edited, or the derivation changed under a stored
            # value. Refuse rather than seal to a key nothing can open.
            raise SealingError(
                f"the published wrapping key for custody key "
                f"{published.custody_key_id} is not the one this process "
                f"derives; the row was edited or restored from elsewhere")
    return published


def published(engine: Engine) -> Recipient | None:
    """The newest published recipient, or ``None`` if no worker has run.

    Newest, so that after a custody-secret rotation new subscriptions are
    sealed to the key the current worker can open. What was sealed to the old
    one is unreadable either way, and says so by name.
    """
    with engine.connect() as connection:
        row = connection.execute(
            select(webhook_wrapping_key.c.custody_key_id,
                   webhook_wrapping_key.c.public_key)
            .order_by(webhook_wrapping_key.c.seq.desc())
            .limit(1)).mappings().one_or_none()
    if row is None:
        return None
    return Recipient(row["custody_key_id"], bytes(row["public_key"]))


# --- internals --------------------------------------------------------------

def _private(custody_key: CustodyKey) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(
        custody_key.derive_subkey(_RECIPIENT_INFO, 32))


def _derive(shared: bytes, ephemeral_public: bytes,
            recipient_public: bytes) -> bytes:
    """The AEAD key for one message.

    Both public keys go into the ``info`` as well as the shared secret, which
    is what binds the ciphertext to the pair it was produced for -- without it
    a shared secret is just 32 bytes and says nothing about who agreed on it.
    """
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=_HKDF_SALT,
                info=_HKDF_INFO + ephemeral_public + recipient_public
                ).derive(shared)


__all__ = ["ENVELOPE_VERSION", "MAGIC", "NONCE_SIZE", "PUBLIC_KEY_SIZE",
           "Recipient", "is_wrapped", "publish", "published", "recipient_for",
           "unseal"]
