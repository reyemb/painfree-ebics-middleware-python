"""Unit tests for the order-data pipeline and its inverse.

The differential gate proves the interesting half: that `ebics-client-php`
decrypts what this engine encrypts and the other way round, that both produce
the same compressed and encrypted bytes under a pinned transaction key, and
that each accepts the other's electronic signature under both A005 and A006.
What is pinned here is what no other implementation can tell us -- that the
inverse really is an inverse, that the padding is X.923 rather than PKCS#7,
and the refusals that stop a wrongly-shaped call before a bank sees it.

Deliberately free of external key material: the module mints its own keys.
"""

from __future__ import annotations

import base64
import datetime
import zlib

import pytest
from lxml import etree

from painfree import ebics3

S002 = "http://www.ebics.org/S002"

SUBJECT = ebics3.subject_name("painfree.invalid", "painfree", "CH")

KEYS = {
    version: ebics3.EbicsKey.generate(
        version, subject=SUBJECT, serial_number=index + 1,
        not_valid_before=datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
    for index, version in enumerate(("A005", "A006", "E002", "X002"))
}

PAYLOAD = b"<Document><Payment>1</Payment></Document>"
KEY = bytes(range(16))


def package(signature_version="A006", **kwargs):
    return ebics3.secure_order_data(
        kwargs.pop("order_content", PAYLOAD),
        signature_key=KEYS[signature_version],
        bank_encryption_key=KEYS["E002"],
        partner_id="PARTNER1", user_id="USER0001",
        transaction_key=kwargs.pop("transaction_key", KEY), **kwargs)


# --- the electronic signature ----------------------------------------------

def test_user_signature_is_the_sequence_the_s002_schema_fixes():
    root = ebics3.build_user_signature(
        ebics3.order_data_digest(PAYLOAD), KEYS["A006"], "PARTNER1", "USER0001")
    assert etree.QName(root) == etree.QName(S002, "UserSignatureData")
    assert [etree.QName(node).localname for node in root[0]] == [
        "SignatureVersion", "SignatureValue", "PartnerID", "UserID"]
    assert root[0][0].text == "A006"


def test_a005_and_a006_treat_the_digest_differently():
    """The asymmetry that decides whether a bank accepts the ES at all.

    A005 signs the digest *as a hash* -- PKCS#1 v1.5 wraps it in a DigestInfo
    and stops. A006 signs it *as a message* -- PSS hashes it a second time. A
    port that treats them alike produces a signature that verifies nowhere.
    """
    digest = ebics3.order_data_digest(PAYLOAD)
    a005 = ebics3.sign_digest(digest, KEYS["A005"].private_key, "A005")
    assert ebics3.verify_digest(digest, a005, KEYS["A005"].public_key, "A005")
    assert not ebics3.verify_digest(
        ebics3.order_data_digest(b"other"), a005, KEYS["A005"].public_key, "A005")

    a006 = ebics3.sign_digest(digest, KEYS["A006"].private_key, "A006")
    assert ebics3.verify_digest(digest, a006, KEYS["A006"].public_key, "A006")


def test_a005_is_byte_reproducible_and_a006_is_not():
    """PKCS#1 v1.5 is deterministic; PSS salts every signature."""
    digest = ebics3.order_data_digest(PAYLOAD)
    assert (ebics3.sign_digest(digest, KEYS["A005"].private_key, "A005")
            == ebics3.sign_digest(digest, KEYS["A005"].private_key, "A005"))
    assert (ebics3.sign_digest(digest, KEYS["A006"].private_key, "A006")
            != ebics3.sign_digest(digest, KEYS["A006"].private_key, "A006"))


def test_the_es_version_is_read_out_of_the_document_being_verified():
    root = ebics3.build_user_signature(
        ebics3.order_data_digest(PAYLOAD), KEYS["A005"], "PARTNER1", "USER0001")
    assert ebics3.verify_user_signature(
        root, ebics3.order_data_digest(PAYLOAD), KEYS["A005"])
    assert not ebics3.verify_user_signature(root, b"\x00" * 32, KEYS["A005"])


@pytest.mark.parametrize("version", ["X002", "E002"])
def test_the_es_refuses_a_key_that_is_not_a_signature_key(version):
    with pytest.raises((ebics3.RequestError, ebics3.UnsupportedVersionError)):
        ebics3.build_user_signature(b"\x00" * 32, KEYS[version], "P", "U")


# --- compress, encrypt, encode ---------------------------------------------

def test_the_pipeline_round_trips():
    encoded = ebics3.encrypt_payload(PAYLOAD, KEY)
    assert ebics3.decrypt_payload(encoded, KEY) == PAYLOAD


def test_the_pipeline_compresses_before_it_encrypts():
    """Order matters: ciphertext does not compress, so the reverse saves nothing.

    Asserted by undoing the steps by hand -- if encryption came first, the
    inflate would fail on the outer layer rather than yielding the payload.
    """
    encoded = ebics3.encrypt_payload(PAYLOAD, KEY)
    ciphertext = base64.b64decode(encoded)
    assert zlib.decompress(ebics3.aes_decrypt(ciphertext, KEY)) == PAYLOAD


def test_padding_is_ansi_x923_and_not_pkcs7():
    """X.923 pads with zeros and one length byte; PKCS#7 repeats the length.

    They agree only when a single byte is missing, so a payload one byte short
    of a block is what tells them apart.
    """
    data = b"a" * (ebics3.AES_BLOCK_SIZE - 3)
    padded = ebics3.aes_decrypt(
        ebics3.aes_encrypt(data, KEY), KEY, iv=bytes(ebics3.AES_BLOCK_SIZE))
    assert padded == data

    raw = ebics3.aes_encrypt(data, KEY)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    decryptor = Cipher(algorithms.AES(KEY),
                       modes.CBC(bytes(ebics3.AES_BLOCK_SIZE))).decryptor()
    assert decryptor.update(raw) + decryptor.finalize() == data + b"\x00\x00\x03"


def test_a_block_aligned_payload_still_gets_a_whole_block_of_padding():
    """Otherwise the inverse would strip a byte of real data."""
    data = b"a" * ebics3.AES_BLOCK_SIZE
    assert len(ebics3.aes_encrypt(data, KEY)) == 2 * ebics3.AES_BLOCK_SIZE
    assert ebics3.aes_decrypt(ebics3.aes_encrypt(data, KEY), KEY) == data


def test_e002_refuses_a_key_that_is_not_aes_128():
    with pytest.raises(ebics3.KeyMaterialError, match="AES-128"):
        ebics3.aes_encrypt(PAYLOAD, bytes(32))


def test_a_truncated_ciphertext_is_refused_rather_than_mis_decrypted():
    with pytest.raises(ebics3.KeyMaterialError, match="AES blocks"):
        ebics3.aes_decrypt(b"short", KEY)


def test_the_transaction_key_is_128_bit_and_fresh_every_time():
    assert len(ebics3.generate_transaction_key()) == ebics3.TRANSACTION_KEY_SIZE
    assert ebics3.generate_transaction_key() != ebics3.generate_transaction_key()


# --- the two directions, end to end ----------------------------------------

def test_secure_order_data_and_open_order_data_are_inverses():
    secured = package()
    recovered = ebics3.open_order_data(
        secured.signature_data, secured.transaction_key_encrypted, KEYS["E002"])
    root = ebics3.parse_xml(recovered)
    assert ebics3.verify_user_signature(root, secured.digest, KEYS["A006"])
    assert secured.digest == ebics3.order_data_digest(PAYLOAD)
    assert base64.b64decode(secured.digest_b64) == secured.digest


def test_segments_ride_on_the_same_transaction_key():
    """The transfer phase encrypts every segment under the key the body wrapped."""
    secured = package()
    assert ebics3.decrypt_payload(secured.encrypt(PAYLOAD),
                                  secured.transaction_key) == PAYLOAD


def test_wrapping_is_not_byte_reproducible_but_still_unwraps():
    """RSAES-PKCS1-v1_5 pads with random bytes, so the ciphertext moves."""
    first = ebics3.wrap_transaction_key(KEY, KEYS["E002"])
    second = ebics3.wrap_transaction_key(KEY, KEYS["E002"])
    assert first != second
    assert ebics3.unwrap_transaction_key(first, KEYS["E002"]) == KEY
    assert ebics3.unwrap_transaction_key(second, KEYS["E002"]) == KEY


def test_the_transaction_key_stays_out_of_the_repr():
    """Key material in a traceback is key material in a log file."""
    secured = package()
    assert secured.transaction_key.hex() not in repr(secured)
    assert repr(secured.transaction_key) not in repr(secured)


@pytest.mark.parametrize("version", ["X002", "A006"])
def test_wrapping_refuses_a_key_that_is_not_e002(version):
    with pytest.raises(ebics3.RequestError, match="E002"):
        ebics3.wrap_transaction_key(KEY, KEYS[version])


def test_unwrapping_needs_the_private_half():
    public_only = ebics3.EbicsKey("E002", KEYS["E002"].public_key)
    with pytest.raises(ebics3.KeyMaterialError, match="private"):
        ebics3.unwrap_transaction_key(b"\x00" * 256, public_only)
