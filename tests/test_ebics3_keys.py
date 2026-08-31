"""Unit tests for the ebics3 crypto layer.

These complement the differential gate, they do not replace it: byte-level
agreement with the other EBICS implementations on the fingerprint is proved
there, against the shared fixture keys. What is pinned here is the behaviour no
other implementation exercises for us -- the invariants of the encodings, the
refusals that protect key custody, and the certificate shape EBICS 3.0 requires.

Deliberately free of external key material: these tests mint their own keys, so
the engine's own test suite stands alone.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import pathlib
import types

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from painfree import ebics3

VERSIONS = ("A005", "A006", "X002", "E002")
SUBJECT = ebics3.subject_name("painfree.invalid", "painfree", "CH")

#: Two 2048-bit keys, generated once for the whole module: RSA keygen is slow
#: and none of these tests need a *particular* key, only a valid one.
KEY = ebics3.generate_private_key()
OTHER_KEY = ebics3.generate_private_key()


@pytest.fixture(scope="module")
def generated():
    return KEY


# --- the INI-letter fingerprint -------------------------------------------

def test_public_key_hex_is_lowercase_and_zero_stripped():
    exponent, modulus = ebics3.public_key_hex(KEY.public_key())
    for value in (exponent, modulus):
        assert value == value.lower()
        assert not value.startswith("0")
        assert int(value, 16) > 0


def test_digest_is_sha256_over_the_space_separated_hex_pair():
    key = KEY.public_key()
    exponent, modulus = ebics3.public_key_hex(key)
    assert ebics3.public_key_digest(key) == hashlib.sha256(
        f"{exponent} {modulus}".encode("ascii")).digest()
    assert ebics3.public_key_digest_hex(key) == ebics3.public_key_digest(key).hex()


def test_leading_zeros_are_stripped_from_a_small_top_byte():
    """The bug this guards: a modulus whose top nibble is zero.

    Python's formatter happens never to emit a leading zero, but the property is
    what the other implementations spell out explicitly, so it is pinned against
    a stub rather than left to the formatter.
    """
    stub = types.SimpleNamespace(public_numbers=lambda: types.SimpleNamespace(e=3, n=0x0abc))
    assert ebics3.public_key_hex(stub) == ("3", "abc")


def test_crypto_binary_is_minimal_big_endian():
    assert ebics3.crypto_binary(65537) == "AQAB"
    assert base64.b64decode(ebics3.crypto_binary(0x00ff)) == b"\xff"
    assert base64.b64decode(ebics3.crypto_binary(0)) == b"\x00"
    with pytest.raises(ValueError):
        ebics3.crypto_binary(-1)


# --- signature versions ----------------------------------------------------

@pytest.mark.parametrize("version", ["A005", "A006", "X002"])
def test_sign_verify_roundtrip(version):
    key = ebics3.EbicsKey(version, KEY.public_key(), KEY)
    signature = key.sign(b"canonical bytes")
    assert key.verify(b"canonical bytes", signature)
    assert not key.verify(b"other bytes", signature)


def test_a006_is_pss_and_therefore_not_deterministic():
    """A006 salts every signature, so two signatures over the same bytes differ.

    Recorded because it is the one place a byte-level differential comparison
    cannot be used, and future work will need to know that.
    """
    assert ebics3.EbicsKey("A006", KEY.public_key(), KEY).sign(b"m") \
        != ebics3.EbicsKey("A006", KEY.public_key(), KEY).sign(b"m")
    assert ebics3.EbicsKey("A005", KEY.public_key(), KEY).sign(b"m") \
        == ebics3.EbicsKey("A005", KEY.public_key(), KEY).sign(b"m")


def test_encryption_key_refuses_to_sign():
    key = ebics3.EbicsKey("E002", KEY.public_key(), KEY)
    with pytest.raises(ebics3.UnsupportedVersionError):
        key.sign(b"m")


def test_public_only_key_cannot_sign_but_can_verify():
    private = ebics3.EbicsKey("X002", KEY.public_key(), KEY)
    public = ebics3.EbicsKey.from_public_pem("X002", private.public_pem())
    signature = private.sign(b"m")
    assert public.verify(b"m", signature)
    with pytest.raises(ebics3.KeyMaterialError):
        public.sign(b"m")
    with pytest.raises(ebics3.KeyMaterialError):
        public.private_pem()


def test_unknown_version_is_rejected():
    assert [v.value for v in ebics3.KeyVersion] == list(VERSIONS)
    with pytest.raises(ebics3.UnsupportedVersionError):
        ebics3.KeyVersion.parse("A007")


# --- key material ----------------------------------------------------------

def test_pem_roundtrip_including_a_passphrase(generated):
    key = ebics3.EbicsKey("X002", generated.public_key(), generated)
    plain = ebics3.EbicsKey.from_private_pem("X002", key.private_pem())
    sealed = ebics3.EbicsKey.from_private_pem(
        "X002", key.private_pem(b"secret"), password=b"secret")
    assert plain.fingerprint == sealed.fingerprint == key.fingerprint
    assert key.public_pem().startswith(b"-----BEGIN RSA PUBLIC KEY-----")


def test_short_keys_and_garbage_are_refused():
    with pytest.raises(ebics3.KeyMaterialError):
        ebics3.generate_private_key(1024)
    with pytest.raises(ebics3.KeyMaterialError):
        ebics3.load_public_key(b"not a pem")


def test_mismatched_halves_are_refused(generated):
    with pytest.raises(ebics3.KeyMaterialError):
        ebics3.EbicsKey("X002", generated.public_key(), OTHER_KEY)


def test_repr_carries_the_fingerprint_and_no_key_material(generated):
    text = repr(ebics3.EbicsKey("X002", generated.public_key(), generated))
    assert ebics3.public_key_digest_hex(generated.public_key())[:16] in text
    assert "BEGIN" not in text and str(generated.private_numbers().p) not in text


# --- certificates ----------------------------------------------------------

@pytest.mark.parametrize("version,usage", [
    ("A006", "content_commitment"), ("X002", "digital_signature"),
    ("E002", "key_encipherment"),
])
def test_certificate_asserts_exactly_the_key_usage_for_its_version(generated, version, usage):
    cert = ebics3.self_signed_certificate(generated, version, SUBJECT, serial_number=7)
    key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    asserted = [name for name in (
        "digital_signature", "content_commitment", "key_encipherment",
        "data_encipherment", "key_agreement") if getattr(key_usage, name)]
    assert asserted == [usage]
    assert cert.serial_number == 7
    assert ebics3.issuer_name(cert) == "C=CH,O=painfree,CN=painfree.invalid"


def test_certificate_is_reproducible_when_serial_and_start_are_pinned(generated):
    start = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    args = (generated, "X002", SUBJECT)
    first = ebics3.self_signed_certificate(*args, serial_number=1, not_valid_before=start)
    second = ebics3.self_signed_certificate(*args, serial_number=1, not_valid_before=start)
    assert ebics3.certificate_der(first) == ebics3.certificate_der(second)
    assert ebics3.certificate_fingerprint(first) == hashlib.sha256(
        ebics3.certificate_der(first)).hexdigest()


def test_key_travels_through_its_certificate(generated):
    cert = ebics3.self_signed_certificate(generated, "E002", SUBJECT)
    key = ebics3.EbicsKey.from_certificate("E002", ebics3.certificate_der(cert))
    assert key.fingerprint == ebics3.public_key_digest(generated.public_key())
    assert not key.has_private
    pem = cert.public_bytes(serialization.Encoding.PEM)
    assert ebics3.load_certificate(pem) == cert


def test_a_certificate_for_a_different_key_is_refused(generated):
    cert = ebics3.self_signed_certificate(generated, "X002", SUBJECT)
    with pytest.raises(ebics3.CertificateError):
        ebics3.EbicsKey("X002", OTHER_KEY.public_key(), certificate=cert)


def test_generate_attaches_a_certificate_only_when_asked():
    assert ebics3.EbicsKey.generate("X002").certificate is None


# --- architecture ----------------------------------------------------------

def test_engine_does_not_import_the_service_layer():
    """The engine ships inside `painfree` but must not depend on it.

    A one-way dependency is the whole reason the engine can be released on its
    own; it is cheap to break by reflex and invisible until packaging time, so
    it is pinned here rather than left to review.
    """
    root = pathlib.Path(ebics3.__file__).parent
    offenders = [source.name for source in root.glob("*.py")
                 if "import painfree" in source.read_text()]
    assert not offenders


def test_importing_the_engine_does_not_pull_in_the_service_stack():
    """The source-level rule above, checked at runtime.

    `painfree/__init__.py` staying empty is what makes `from painfree import
    ebics3` work without FastAPI, SQLAlchemy or a database driver installed --
    the property that lets the engine ship on its own. A stray import in the
    package root would break it invisibly, because the service tests always have
    those packages present.
    """
    import subprocess
    import sys

    probe = (
        "import painfree.ebics3, sys;"
        "leaked = sorted(m for m in sys.modules"
        " if m.split('.')[0] in {'fastapi','sqlalchemy','alembic','uvicorn',"
        "'pydantic_settings','psycopg','starlette'});"
        "print(','.join(leaked))"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True,
        cwd=pathlib.Path(ebics3.__file__).parents[2],
    )
    assert result.stdout.strip() == ""
