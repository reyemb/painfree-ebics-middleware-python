"""The envelope: what it protects, and how it fails.

Every assertion here is about a failure mode rather than about AES-GCM working.
The three that matter operationally: a rotated secret says so instead of
producing a tag failure, a ciphertext moved to another row does not open, and
nothing on the failure path prints the secret or the plaintext.
"""

from __future__ import annotations

import pytest

from painfree import sealing
from painfree.sealing import (CorruptSealError, SealingError,
                              WrongCustodyKeyError, derive_custody_key,
                              new_secret)

CONTEXT = b"painfree/key/acme/subscriber/X002/1"
PLAINTEXT = b"-----BEGIN PRIVATE KEY-----\nnot really a key\n-----END PRIVATE KEY-----"


@pytest.fixture
def key(custody_secret):
    return derive_custody_key(custody_secret)


def test_a_secret_derives_the_same_key_every_time(custody_secret):
    """Otherwise a restart cannot read the database it wrote."""
    assert derive_custody_key(custody_secret).key_id == \
        derive_custody_key(custody_secret).key_id


def test_two_secrets_derive_different_keys():
    assert derive_custody_key(new_secret()).key_id != \
        derive_custody_key(new_secret()).key_id


def test_a_short_secret_is_refused_rather_than_stretched():
    """HKDF is the right choice only because the secret is generated.

    The length check is what makes that assumption true rather than assumed;
    without it the same code would be quietly derivation-hardening a passphrase
    it cannot harden.
    """
    with pytest.raises(SealingError, match="new-secret"):
        derive_custody_key("hunter2")


def test_a_generated_secret_is_long_enough_to_be_accepted():
    assert len(new_secret()) >= sealing.MINIMUM_SECRET_LENGTH
    derive_custody_key(new_secret())


def test_material_round_trips(key):
    assert key.open(key.seal(PLAINTEXT, context=CONTEXT), context=CONTEXT) == PLAINTEXT


def test_the_sealed_blob_does_not_contain_the_plaintext(key):
    blob = key.seal(PLAINTEXT, context=CONTEXT)
    assert PLAINTEXT not in blob
    assert b"BEGIN PRIVATE KEY" not in blob


def test_two_seals_of_the_same_material_differ(key):
    """A fresh nonce per seal; equal ciphertexts would leak equal keys."""
    assert key.seal(PLAINTEXT, context=CONTEXT) != key.seal(PLAINTEXT, context=CONTEXT)


def test_a_seal_is_bound_to_the_row_it_belongs_in(key):
    """A ciphertext moved to another connection's row must not open there."""
    blob = key.seal(PLAINTEXT, context=CONTEXT)
    with pytest.raises(CorruptSealError, match="did not authenticate"):
        key.open(blob, context=b"painfree/key/other/subscriber/X002/1")


def test_a_wrong_or_rotated_key_says_which_key_it_wanted(key):
    """The operationally useful failure: both key ids, named, before the tag fails."""
    blob = key.seal(PLAINTEXT, context=CONTEXT)
    other = derive_custody_key(new_secret())
    with pytest.raises(WrongCustodyKeyError) as raised:
        other.open(blob, context=CONTEXT)
    assert raised.value.sealed_with == key.key_id
    assert raised.value.configured == other.key_id
    assert key.key_id in str(raised.value) and other.key_id in str(raised.value)


def test_an_edited_ciphertext_does_not_open(key):
    blob = bytearray(key.seal(PLAINTEXT, context=CONTEXT))
    blob[-1] ^= 0x01
    with pytest.raises(CorruptSealError):
        key.open(bytes(blob), context=CONTEXT)


@pytest.mark.parametrize("blob", [b"", b"pfk1", b"not an envelope at all",
                                 b"pfk1" + bytes([9]) + b"0" * 40])
def test_a_foreign_or_truncated_envelope_is_refused(key, blob):
    with pytest.raises(CorruptSealError):
        key.open(blob, context=CONTEXT)


def test_the_key_id_is_readable_without_the_key(key):
    """Listing what a rotated secret orphaned must not need the ability to open it."""
    assert sealing.sealed_with(key.seal(PLAINTEXT, context=CONTEXT)) == key.key_id
    assert sealing.sealed_with(b"nonsense") is None


def test_nothing_about_the_key_is_printable(key, custody_secret):
    """`repr` ends up in tracebacks; the key must not."""
    assert custody_secret not in repr(key)
    assert key.key_id in repr(key)


def test_empty_material_is_refused(key):
    """Sealing nothing would store a row that looks like it has a private key."""
    with pytest.raises(SealingError):
        key.seal(b"", context=CONTEXT)
