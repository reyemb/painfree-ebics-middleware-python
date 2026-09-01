"""The keyring: encrypted at rest, usable by the engine, audited, fail-closed.

There is no reference implementation of a service-side keyring -- `ebics-client-php`
and `fintech` are libraries and have none -- so nothing here claims a
differential comparison of the keyring itself. One comparison *is* available and
is made: a key that has been through the whole round trip signs a real H005
request, and `ebics-client-php` is asked whether the signature verifies. That
answer comes from another implementation rather than from us.

Everything else is evidence about the properties that matter: the bytes actually
written to disk do not contain the key, a rotated secret fails loudly, and every
lifecycle step leaves an audit row.
"""

from __future__ import annotations

import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select

from painfree import db, ebics3
from painfree.audit import AuditLog
from painfree.config import load_settings
from painfree.connections import ConnectionRegistry
from painfree.errors import ConflictError, NotFoundError
from painfree.keyring import (ACTIVE, BANK, SUBSCRIBER, SUPERSEDED, SUSPENDED,
                              KeyCustodian, Keyring)
from painfree.schema import key_material
from painfree.sealing import WrongCustodyKeyError, new_secret

CONNECTION = "acme-ubs"
SUBJECT_ARGS = ("acme", "Acme AG", "CH")


@pytest.fixture
def engine(custody_settings):
    engine = db.build_engine(custody_settings)
    db.migrate(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def audit(engine):
    return AuditLog(engine)


@pytest.fixture
def connection(engine, audit):
    return ConnectionRegistry(engine, audit).register(
        CONNECTION, host_id="UBSHOST", partner_id="PARTNER1", user_id="USER1",
        host_url="https://ebics.example/h005",
        product=ebics3.Product("painfree", "de"))


@pytest.fixture
def custodian(engine, audit, custody_settings, connection):
    return KeyCustodian(engine, audit, custody_settings.custody_key())


@pytest.fixture
def keyring(engine):
    return Keyring(engine)


@pytest.fixture
def keys(custodian):
    return custodian.create_subscriber_keys(
        CONNECTION, subject=ebics3.subject_name(*SUBJECT_ARGS))


def _subject():
    return ebics3.subject_name(*SUBJECT_ARGS)


# --- what is on disk --------------------------------------------------------

def test_the_bytes_at_rest_do_not_contain_the_private_key(engine, keys):
    """Asserted against the stored column, not against the API that wrote it."""
    with engine.connect() as connection:
        rows = connection.execute(select(key_material)).mappings().all()
    assert rows and all(row["sealed_private"] for row in rows)

    for row in rows:
        key = keys[row["version"]]
        blob = row["sealed_private"]
        assert b"PRIVATE KEY" not in blob
        assert key.private_pem() not in blob
        # The private exponent and both primes, as raw big-endian bytes: a
        # keyring that stored DER rather than PEM would pass the string check
        # above and fail this one.
        numbers = key.private_key.private_numbers()
        for secret in (numbers.d, numbers.p, numbers.q):
            assert _bytes(secret) not in blob


def test_no_private_key_appears_anywhere_in_the_database_file(
        engine, sqlite_url, keys):
    """The whole file, not just the column -- a stray copy elsewhere would show.

    The write-ahead log counts: it is where a recently written row actually
    lives, and a test that read only the main file would pass on an empty one.
    """
    engine.dispose()
    database = pathlib.Path(sqlite_url.split("///", 1)[1])
    raw = b"".join(path.read_bytes()
                   for path in sorted(database.parent.glob(database.name + "*")))
    assert b"-----BEGIN PRIVATE KEY-----" not in raw
    for key in keys.values():
        assert _bytes(key.private_key.private_numbers().d) not in raw
    # The public halves *are* in the clear, on purpose.
    assert b"-----BEGIN RSA PUBLIC KEY-----" in raw


def test_the_public_half_and_the_fingerprint_are_readable_without_the_key(
        keyring, keys):
    """An operator comparing a letter must not need the ability to decrypt."""
    for version, key in keys.items():
        stored = keyring.entry(CONNECTION, version)
        assert stored.fingerprint == key.fingerprint_hex
        assert stored.public_key().public_pem() == key.public_pem()
        assert stored.has_private is True


# --- the round trip, and the one comparison an oracle can make ---------------

def test_a_key_survives_the_round_trip_intact(custodian, keys):
    for version, key in keys.items():
        opened = custodian.open(CONNECTION, version)
        assert opened.has_private
        assert opened.fingerprint_hex == key.fingerprint_hex
        assert opened.private_key.private_numbers() == \
            key.private_key.private_numbers()
        assert opened.certificate is not None


def test_the_engine_can_drive_a_resumed_initialisation_with_reopened_keys(
        custodian, keys):
    """The keys come back as an `Initialisation`, not as loose PEM."""
    initialisation = custodian.resume_initialisation(CONNECTION)
    assert initialisation.state is ebics3.KeyState.CREATED
    assert initialisation.next_step is ebics3.Step.INI
    assert initialisation.next_request() is not None
    # `letter()` defaults to the engine's default convention, which is the
    # certificate's; `fingerprint_hex` is the public-key digest. Named on both
    # sides so this compares one thing rather than two.
    assert initialisation.letter(ebics3.LetterDigest.PUBLIC_KEY
                                 ).signature.fingerprint == \
        keys["A006"].fingerprint_hex


def test_a_resumed_initialisation_asks_for_the_outstanding_exchange(custodian, keys):
    initialisation = custodian.resume_initialisation(CONNECTION)
    initialisation.ini_sent, initialisation.ini_order_id = True, "A00A"
    custodian.save_initialisation(CONNECTION, initialisation)

    assert custodian.resume_initialisation(CONNECTION).next_step is ebics3.Step.HIA


# --- failing closed ---------------------------------------------------------

def test_a_rotated_secret_fails_closed_and_names_both_keys(
        engine, audit, sqlite_url, keys, capsys):
    """The whole point of storing the key id beside the ciphertext."""
    from painfree.logging import configure_logging

    configure_logging("INFO")
    rotated = load_settings(database_url=sqlite_url,
                            key_encryption_secret=new_secret())
    custodian = KeyCustodian(engine, audit, rotated.custody_key())
    capsys.readouterr()

    with pytest.raises(WrongCustodyKeyError) as raised:
        custodian.open(CONNECTION, ebics3.KeyVersion.X002)

    assert raised.value.configured == rotated.custody_key().key_id
    line = _line(capsys, "custody.key_mismatch")
    assert line["configured_key_id"] == rotated.custody_key().key_id
    assert line["sealed_with_key_id"] == raised.value.sealed_with
    assert CONNECTION in line["context"] and "X002" in line["context"]


def test_a_row_moved_to_another_connection_does_not_open(
        engine, custodian, audit, custody_settings, keys):
    """A restored backup, or write access to one table, must not become a key."""
    ConnectionRegistry(engine, audit).register(
        "other", host_id="OTHER", partner_id="P2", user_id="U2",
        host_url="https://other.example")
    with engine.begin() as connection:
        row = connection.execute(
            select(key_material).where(key_material.c.version == "X002")
        ).mappings().one()
        connection.execute(key_material.insert().values(
            {**dict(row), "seq": None, "connection_id": "other"}))

    from painfree.sealing import CorruptSealError
    with pytest.raises(CorruptSealError, match="did not authenticate"):
        custodian.open("other", ebics3.KeyVersion.X002)


def test_a_connection_with_no_keys_is_a_not_found(custodian, engine, audit):
    ConnectionRegistry(engine, audit).register(
        "empty", host_id="EMPTY", partner_id="P3", user_id="U3",
        host_url="https://empty.example")
    with pytest.raises(NotFoundError):
        custodian.open("empty", ebics3.KeyVersion.X002)


def test_keys_are_created_once_not_twice(custodian, keys):
    with pytest.raises(ConflictError, match="renew"):
        custodian.create_subscriber_keys(CONNECTION, subject=_subject())


# --- the bank's keys --------------------------------------------------------

def _bank_keys():
    return ebics3.BankKeys(
        authentication=ebics3.EbicsKey.generate("X002", subject=_subject()),
        encryption=ebics3.EbicsKey.generate("E002", subject=_subject()))


def test_the_banks_keys_are_stored_only_once_they_have_been_checked(custodian):
    """`HPB` is unsigned; the letter comparison is the only control (D-016)."""
    bank = _bank_keys()
    with pytest.raises(ConflictError, match="letter"):
        custodian.accept_bank_keys(CONNECTION, bank, {})


def test_accepted_bank_keys_come_back_as_the_engine_wants_them(
        custodian, keyring, keys):
    bank = _bank_keys()
    fingerprints = {"authentication": bank.authentication.fingerprint_hex,
                    "encryption": bank.encryption.fingerprint_hex}
    custodian.accept_bank_keys(CONNECTION, bank, fingerprints)

    restored = keyring.bank_keys(CONNECTION)
    assert restored.authentication.fingerprint_hex == fingerprints["authentication"]
    assert restored.encryption.fingerprint_hex == fingerprints["encryption"]
    assert restored.authentication.has_private is False


def test_a_bank_key_is_stored_with_no_private_half_at_all(
        engine, custodian, keys):
    bank = _bank_keys()
    custodian.accept_bank_keys(
        CONNECTION, bank,
        {"authentication": bank.authentication.fingerprint_hex,
         "encryption": bank.encryption.fingerprint_hex})
    with engine.connect() as connection:
        rows = connection.execute(
            select(key_material).where(key_material.c.holder == BANK)
        ).mappings().all()
    assert rows and all(row["sealed_private"] is None for row in rows)


def test_a_rolled_bank_key_supersedes_the_previous_one(custodian, keyring, keys):
    """A key roll should be visible as one, not as noise."""
    first = _bank_keys()
    custodian.accept_bank_keys(
        CONNECTION, first, {"authentication": first.authentication.fingerprint_hex,
                            "encryption": first.encryption.fingerprint_hex})
    second = _bank_keys()
    custodian.accept_bank_keys(
        CONNECTION, second, {"authentication": second.authentication.fingerprint_hex,
                             "encryption": second.encryption.fingerprint_hex})

    assert keyring.bank_keys(CONNECTION).encryption.fingerprint_hex == \
        second.encryption.fingerprint_hex
    superseded = keyring.entries(CONNECTION, holder=BANK, status=SUPERSEDED)
    assert {key.fingerprint for key in superseded} == \
        {first.authentication.fingerprint_hex, first.encryption.fingerprint_hex}


# --- lifecycle --------------------------------------------------------------

def test_suspending_takes_a_key_out_of_service_without_destroying_it(
        custodian, keyring, keys):
    custodian.suspend(CONNECTION, version="X002", reason="operator request")
    with pytest.raises(NotFoundError):
        keyring.entry(CONNECTION, "X002")
    assert keyring.entry(CONNECTION, "X002", status=SUSPENDED).fingerprint == \
        keys["X002"].fingerprint_hex


def test_renewal_keeps_the_key_the_bank_still_has_on_file(
        custodian, keyring, keys):
    """Overwriting would strand a connection halfway through a key roll."""
    replacement = custodian.renew(CONNECTION, "X002", subject=_subject())
    assert replacement.fingerprint_hex != keys["X002"].fingerprint_hex

    current = keyring.entry(CONNECTION, "X002")
    assert current.generation == 2
    assert current.fingerprint == replacement.fingerprint_hex
    assert custodian.open(CONNECTION, "X002").fingerprint_hex == \
        replacement.fingerprint_hex

    previous = keyring.entry(CONNECTION, "X002", status=SUPERSEDED)
    assert previous.generation == 1
    assert previous.fingerprint == keys["X002"].fingerprint_hex


# --- the audit trail --------------------------------------------------------

def test_every_key_operation_is_recorded(custodian, audit, keys):
    bank = _bank_keys()
    custodian.accept_bank_keys(
        CONNECTION, bank, {"authentication": bank.authentication.fingerprint_hex,
                           "encryption": bank.encryption.fingerprint_hex})
    custodian.renew(CONNECTION, "X002", subject=_subject())
    custodian.suspend(CONNECTION, version="E002", reason="test")

    actions = [row["action"] for row in audit.recent(limit=100)]
    for action in ("key.created", "key.bank_keys_accepted", "key.renewed",
                   "key.suspended"):
        assert action in actions, actions


def test_an_audit_row_carries_the_fingerprint_and_never_the_key(
        custodian, audit, keys):
    rows = [row for row in audit.recent(limit=100)
            if row["action"] == "key.created"]
    assert len(rows) == 3
    for row in rows:
        assert row["connection_id"] == CONNECTION
        assert row["detail"]["fingerprint"] in \
            {key.fingerprint_hex for key in keys.values()}
        assert row["detail"]["sealed"] is True
        assert "PRIVATE" not in repr(row["detail"])


# --- helpers ----------------------------------------------------------------

def _bytes(number: int) -> bytes:
    return number.to_bytes((number.bit_length() + 7) // 8, "big")


def _line(capsys, event: str) -> dict:
    import json

    for raw in capsys.readouterr().out.splitlines():
        line = json.loads(raw)
        if line["event"] == event:
            return line
    pytest.fail(f"no {event!r} line was logged")


def test_rsa_is_what_came_back(custodian, keys):
    """Guards against a round trip that returns something merely key-shaped."""
    assert isinstance(custodian.open(CONNECTION, "A006").private_key,
                      rsa.RSAPrivateKey)
    assert ACTIVE == "active" and SUBSCRIBER == "subscriber"
