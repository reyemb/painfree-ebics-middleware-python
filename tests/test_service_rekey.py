"""Rotating the custody secret: every row moves, or the run fails saying which.

No reference implementation is involved and none is claimed -- nothing else
seals a painfree keyring. What *is* borrowed is the same oracle the keyring
already uses: a key that has been re-sealed under a new custody secret and
opened again signs a real `HPB` request, and `ebics-client-php` is asked whether
that signature verifies. A rotation that damaged the key material would be
caught by another implementation rather than by us.

The rest is evidence about the failure modes: a wrong secret opens nothing and
says so, a rotation left half-done finishes on the next run, and a row sealed
under some third key is reported by name rather than skipped.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest
from sqlalchemy import select, update

from painfree import db, ebics3, wrapping
from painfree.audit import AuditLog
from painfree.config import ConfigurationError, load_settings
from painfree.connections import ConnectionRegistry
from painfree.keyring import KeyCustodian
from painfree.rekey import rekey, sealed_key_id, survey
from painfree.schema import key_material, webhook_subscription
from painfree.sealing import WrongCustodyKeyError, derive_custody_key
from painfree.webhooks import WebhookSubscriptions

CONNECTION = "acme-ubs"
SUBJECT_ARGS = ("acme", "Acme AG", "CH")

OLD_SECRET = "rekey-test-old-secret-Aa1Bb2Cc3Dd4Ee5Ff6Gg7"
NEW_SECRET = "rekey-test-new-secret-Zz9Yy8Xx7Ww6Vv5Uu4Tt3"


@pytest.fixture
def old_settings(sqlite_url):
    return load_settings(database_url=sqlite_url,
                         key_encryption_secret=OLD_SECRET)


@pytest.fixture
def engine(old_settings):
    engine = db.build_engine(old_settings)
    db.migrate(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def audit(engine):
    return AuditLog(engine)


@pytest.fixture
def old_key(old_settings):
    return old_settings.custody_key()


@pytest.fixture
def new_key():
    return derive_custody_key(NEW_SECRET)


@pytest.fixture
def sealed(engine, audit, old_key):
    """A connection with sealed subscriber keys and a webhook subscription."""
    ConnectionRegistry(engine, audit).register(
        CONNECTION, host_id="UBSHOST", partner_id="PARTNER1", user_id="USER1",
        host_url="https://ebics.example/h005",
        product=ebics3.Product("painfree", "de"))
    custodian = KeyCustodian(engine, audit, old_key)
    keys = custodian.create_subscriber_keys(
        CONNECTION, subject=ebics3.subject_name(*SUBJECT_ARGS))
    wrapping.publish(engine, old_key)
    subscription, secret = WebhookSubscriptions(engine).register(
        "https://consumer.example/hook", ["order.accepted"],
        connection_id=CONNECTION)
    return {"keys": keys, "subscription": subscription, "secret": secret}


def _fingerprints(engine):
    with engine.connect() as connection:
        return {
            (row["version"], row["generation"]): row["fingerprint"]
            for row in connection.execute(select(key_material)).mappings()
        }


# --- the survey, which needs no key at all ----------------------------------

def test_the_survey_names_the_key_the_material_wants(engine, sealed, old_key):
    """The diagnostic an operator runs while holding the wrong secret."""
    assert survey(engine) == {old_key.key_id: 4}  # three EBICS keys, one webhook


def test_sealed_key_id_reads_both_envelope_shapes(engine, sealed, old_key):
    with engine.connect() as connection:
        private = connection.execute(
            select(key_material.c.sealed_private).limit(1)).scalar_one()
        secret = connection.execute(
            select(webhook_subscription.c.sealed_secret)).scalar_one()
    assert bytes(private).startswith(b"pfk1")
    assert bytes(secret).startswith(wrapping.MAGIC)
    assert sealed_key_id(bytes(private)) == old_key.key_id
    assert sealed_key_id(bytes(secret)) == old_key.key_id
    assert sealed_key_id(b"") is None
    assert sealed_key_id(b"not an envelope at all") is None


# --- the rotation itself ----------------------------------------------------

def test_every_sealed_row_moves_to_the_new_key(engine, audit, sealed,
                                               old_key, new_key):
    before = _fingerprints(engine)

    report = rekey(engine, previous=old_key, current=new_key, audit=audit)

    assert report.complete
    assert report.keys_resealed == 3
    assert report.webhook_secrets_resealed == 1
    assert report.keys_already_current == 0
    assert survey(engine) == {new_key.key_id: 4}
    # The public halves and the fingerprints are untouched: a rotation changes
    # how the private half is stored and nothing an operator has compared
    # against a bank's letter.
    assert _fingerprints(engine) == before


def test_the_custody_key_id_column_follows_the_ciphertext(engine, sealed,
                                                          old_key, new_key):
    rekey(engine, previous=old_key, current=new_key)
    with engine.connect() as connection:
        ids = set(connection.execute(
            select(key_material.c.custody_key_id)
            .where(key_material.c.sealed_private.is_not(None))).scalars())
        ids |= set(connection.execute(
            select(webhook_subscription.c.custody_key_id)).scalars())
    assert ids == {new_key.key_id}


def test_the_webhook_secret_is_the_same_value_after_the_rotation(
        engine, audit, sealed, old_key, new_key):
    """A consumer's receiver keeps verifying: the value did not change, only
    the envelope it is stored in."""
    subscription_id = sealed["subscription"].subscription_id
    before = WebhookSubscriptions(engine, old_key).signing_secrets(subscription_id)

    rekey(engine, previous=old_key, current=new_key)

    after = WebhookSubscriptions(engine, new_key).signing_secrets(subscription_id)
    assert after == before == (sealed["secret"],)


def test_the_new_wrapping_key_is_published_so_registration_keeps_working(
        engine, audit, sealed, old_key, new_key):
    rekey(engine, previous=old_key, current=new_key)
    assert wrapping.published(engine).custody_key_id == new_key.key_id

    subscription, secret = WebhookSubscriptions(engine).register(
        "https://consumer.example/second", ["order.accepted"])
    opened = WebhookSubscriptions(engine, new_key)\
        .signing_secrets(subscription.subscription_id)
    assert opened == (secret,)


# --- idempotence and resumption ---------------------------------------------

def test_running_it_twice_moves_nothing_the_second_time(engine, sealed,
                                                        old_key, new_key):
    rekey(engine, previous=old_key, current=new_key)
    again = rekey(engine, previous=old_key, current=new_key)

    assert again.complete
    assert again.resealed == 0
    assert again.keys_already_current == 3
    assert again.webhook_secrets_already_current == 1


def test_a_dry_run_writes_nothing(engine, sealed, old_key, new_key):
    with engine.connect() as connection:
        before = connection.execute(
            select(key_material.c.sealed_private)).scalars().all()

    report = rekey(engine, previous=old_key, current=new_key, dry_run=True)

    assert report.complete and report.keys_resealed == 3
    assert report.wrapping_key_published is False
    with engine.connect() as connection:
        after = connection.execute(
            select(key_material.c.sealed_private)).scalars().all()
    assert [bytes(blob) for blob in after] == [bytes(blob) for blob in before]
    assert survey(engine) == {old_key.key_id: 4}


def test_a_half_finished_rotation_is_finished_by_the_next_run(
        engine, sealed, old_key, new_key):
    """The interrupted-run case, made explicit: one row moved, two did not."""
    with engine.connect() as connection:
        row = connection.execute(
            select(key_material.c.seq, key_material.c.connection_id,
                   key_material.c.holder, key_material.c.version,
                   key_material.c.generation, key_material.c.sealed_private)
            .order_by(key_material.c.seq).limit(1)).mappings().one()
    from painfree.keyring import seal_context
    context = seal_context(row["connection_id"], row["holder"],
                           row["version"], row["generation"])
    moved = new_key.seal(old_key.open(bytes(row["sealed_private"]),
                                      context=context), context=context)
    with engine.begin() as connection:
        connection.execute(update(key_material)
                           .where(key_material.c.seq == row["seq"])
                           .values(sealed_private=moved,
                                   custody_key_id=new_key.key_id))

    report = rekey(engine, previous=old_key, current=new_key)

    assert report.complete
    assert report.keys_resealed == 2
    assert report.keys_already_current == 1
    assert survey(engine) == {new_key.key_id: 4}


# --- failing closed ---------------------------------------------------------

def test_a_row_under_a_third_key_is_named_and_the_run_fails(
        engine, sealed, old_key, new_key, capsys):
    """Neither key opens it, so it is reported rather than skipped."""
    from painfree.logging import configure_logging
    configure_logging("INFO")

    stranger = derive_custody_key("a-third-custody-secret-nobody-here-holds!")
    with engine.connect() as connection:
        row = connection.execute(
            select(key_material.c.seq, key_material.c.connection_id,
                   key_material.c.holder, key_material.c.version,
                   key_material.c.generation, key_material.c.sealed_private)
            .order_by(key_material.c.seq).limit(1)).mappings().one()
    from painfree.keyring import seal_context
    context = seal_context(row["connection_id"], row["holder"],
                           row["version"], row["generation"])
    orphan = stranger.seal(old_key.open(bytes(row["sealed_private"]),
                                        context=context), context=context)
    with engine.begin() as connection:
        connection.execute(update(key_material)
                           .where(key_material.c.seq == row["seq"])
                           .values(sealed_private=orphan,
                                   custody_key_id=stranger.key_id))

    report = rekey(engine, previous=old_key, current=new_key)

    assert not report.complete
    assert report.keys_resealed == 2
    assert [row.identity for row in report.stranded] == [
        f"{CONNECTION}/subscriber/{row['version']}/generation 1"]
    assert report.stranded[0].sealed_with == stranger.key_id

    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()
              if line.startswith("{")]
    stranded = [event for event in events if event["event"] == "rekey.stranded"]
    assert stranded and stranded[0]["sealed_with_key_id"] == stranger.key_id
    assert any(event["event"] == "rekey.incomplete" for event in events)


def test_opening_with_the_wrong_secret_names_both_keys(engine, sealed,
                                                       audit, new_key):
    """The lost-secret failure mode: loud, named, and nothing decrypts."""
    custodian = KeyCustodian(engine, audit, new_key)
    with pytest.raises(WrongCustodyKeyError) as raised:
        custodian.open(CONNECTION, ebics3.KeyVersion.X002)
    assert raised.value.configured == new_key.key_id
    assert raised.value.sealed_with == derive_custody_key(OLD_SECRET).key_id


def test_rotating_to_the_same_key_is_refused(engine, sealed, old_key):
    with pytest.raises(Exception, match="nothing to rotate"):
        rekey(engine, previous=old_key, current=old_key)


# --- the configuration around it --------------------------------------------

def test_the_api_process_may_not_hold_the_previous_secret(sqlite_url):
    with pytest.raises(ConfigurationError, match="PREVIOUS_KEY_ENCRYPTION_SECRET"):
        load_settings(database_url=sqlite_url, role="api",
                      previous_key_encryption_secret=OLD_SECRET)


def test_a_rotation_needs_two_different_secrets(sqlite_url):
    with pytest.raises(ConfigurationError, match="the same value"):
        load_settings(database_url=sqlite_url,
                      key_encryption_secret=OLD_SECRET,
                      previous_key_encryption_secret=OLD_SECRET)
    with pytest.raises(ConfigurationError, match="is not"):
        load_settings(database_url=sqlite_url,
                      previous_key_encryption_secret=OLD_SECRET)


def test_neither_secret_appears_in_the_redacted_configuration(sqlite_url):
    settings = load_settings(database_url=sqlite_url,
                             key_encryption_secret=NEW_SECRET,
                             previous_key_encryption_secret=OLD_SECRET)
    rendered = json.dumps(settings.redacted())
    assert NEW_SECRET not in rendered and OLD_SECRET not in rendered
    assert settings.redacted()["custody_key_id"] == \
        derive_custody_key(NEW_SECRET).key_id
    assert settings.redacted()["previous_custody_key_id"] == \
        derive_custody_key(OLD_SECRET).key_id


# --- the command line, which is what a playbook actually runs ---------------

def _run(command, sqlite_url, **environment):
    import os
    env = {name: value for name, value in os.environ.items()
           if not name.startswith("PAINFREE_")}
    env.update({"PAINFREE_DATABASE_URL": sqlite_url, **environment})
    return subprocess.run([sys.executable, "-m", "painfree", *command],
                          capture_output=True, text=True, env=env,
                          cwd=str(pathlib.Path(__file__).resolve().parent.parent))


def test_the_rekey_command_rotates_and_exits_zero(engine, sealed, sqlite_url,
                                                  old_key, new_key):
    engine.dispose()
    finished = _run(["rekey"], sqlite_url,
                    PAINFREE_KEY_ENCRYPTION_SECRET=NEW_SECRET,
                    PAINFREE_PREVIOUS_KEY_ENCRYPTION_SECRET=OLD_SECRET)
    assert finished.returncode == 0, finished.stdout + finished.stderr

    events = [json.loads(line) for line in finished.stdout.splitlines()
              if line.startswith("{")]
    completed = [event for event in events if event["event"] == "rekey.completed"]
    assert completed and completed[0]["keys_resealed"] == 3
    assert NEW_SECRET not in finished.stdout
    assert OLD_SECRET not in finished.stdout

    engine2 = db.build_engine(load_settings(database_url=sqlite_url))
    try:
        assert survey(engine2) == {new_key.key_id: 4}
    finally:
        engine2.dispose()


def test_custody_status_answers_without_holding_any_secret(engine, sealed,
                                                           sqlite_url, old_key):
    engine.dispose()
    finished = _run(["custody-status"], sqlite_url)
    assert finished.returncode == 0, finished.stdout + finished.stderr
    status = [json.loads(line) for line in finished.stdout.splitlines()
              if line.startswith("{")][-1]
    assert status["event"] == "custody.status"
    assert status["sealed_rows_by_key_id"] == {old_key.key_id: 4}
    assert status["configured_key_id"] is None
    assert status["readable"] is False
