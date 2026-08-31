"""The custody secret, said out loud, and the gate in front of the keys.

Three claims, and the first is the one that matters most:

**Nothing here can disclose the secret.** The console runs in the process that
is refused the custody secret, so the card it renders and the file it offers
carry a key *id* -- a hash beside the ciphertext -- and never a key. The tests
below assert the absence directly rather than trusting the architecture to hold.

**The gate refuses rather than warns.** Generating a connection's first keys is
the one irreversible action in this console whose cost is a bank's calendar
rather than ours. Until somebody says a copy of the secret exists, it is a
`409`, not a red box somebody scrolls past.

**A rotation asks again.** An acknowledgement is made against the key it is an
acknowledgement *of*, so an archive taken before a rotation does not go on
counting for the key that replaced it.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from conftest import dev_credentials
from painfree import db
from painfree.app import create_app
from painfree.audit import Actor, AuditLog
from painfree.connections import ConnectionRegistry
from painfree.recovery import CustodyRecovery

CONNECTION = "acme-ubs"


@pytest.fixture
def engine(settings):
    engine = db.build_engine(settings)
    db.migrate(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def recovery(engine):
    return CustodyRecovery(engine, AuditLog(engine))


@pytest.fixture
def console(settings):
    app = create_app(settings)
    with TestClient(app, headers=dev_credentials()) as client:
        ConnectionRegistry(app.state.engine).register(
            CONNECTION, host_id="UBSHOST", partner_id="PARTNER1",
            user_id="USER1", host_url="https://ebics.example.test/")
        yield client


# --- what the card may carry --------------------------------------------------

def test_a_fresh_deployment_has_acknowledged_nothing(recovery):
    """The honest state, and the one a migration must not fill in."""
    card = recovery.card(version="0.1.0", git_sha="abc")

    assert card.acknowledgement is None
    assert card.acknowledged is False
    assert card.key_ids == []


def test_the_card_names_no_secret(console):
    """The whole point: a hash that says which secret, never the secret."""
    page = console.get("/ui/recovery")
    downloaded = console.get("/ui/recovery/card.txt")

    assert page.status_code == 200
    assert downloaded.status_code == 200
    assert "deploy/secrets/custody_secret" in downloaded.text
    assert "backup-secrets.sh" in downloaded.text
    # The process serving this holds no custody secret at all, so there is
    # nothing it could leak -- asserted rather than assumed.
    assert console.app.state.settings.key_encryption_secret is None


def test_the_card_downloads_as_a_file(console):
    """Meant to leave this host, which is the only place it helps."""
    downloaded = console.get("/ui/recovery/card.txt")

    assert downloaded.headers["content-type"].startswith("text/plain")
    assert "attachment" in downloaded.headers["content-disposition"]
    assert "painfree-recovery-card.txt" in downloaded.headers["content-disposition"]


def test_the_page_needs_no_privilege(console):
    """Like `/ui/api`: whoever inherited this deployment has to be able to read it."""
    response = console.get("/ui/recovery",
                           headers=dev_credentials(subject="nobody", roles="member"))

    assert response.status_code == 200


# --- the gate -----------------------------------------------------------------

def test_generating_the_first_keys_is_refused_until_a_copy_is_confirmed(console):
    """A refusal, not a warning: the cost of this one is a bank's calendar."""
    response = console.post(
        f"/ui/connections/{CONNECTION}/keys/create_keys", data={})

    assert response.status_code == 409
    assert "custody" in response.text.lower()


def test_confirming_it_unblocks_key_generation(console):
    """And nothing else does, which is what makes the confirmation mean something."""
    console.post("/ui/recovery/acknowledge", data={}, follow_redirects=False)
    response = console.post(f"/ui/connections/{CONNECTION}/keys/create_keys",
                            data={}, follow_redirects=False)

    assert response.status_code in (302, 303), response.text


def test_a_member_may_not_confirm_it(console):
    """A statement about the deployment, so it is the same scope as registering one."""
    response = console.post(
        "/ui/recovery/acknowledge", data={},
        headers=dev_credentials(subject="mallory", roles="member"))

    assert response.status_code == 403


def test_the_confirmation_is_in_the_audit_trail(console):
    """Who said the backup exists, kept where every other decision is kept."""
    console.post("/ui/recovery/acknowledge", data={}, follow_redirects=False)
    rows = console.get("/v1/audit").json()["events"]

    assert "custody.backup_acknowledged" in [row["action"] for row in rows]


# --- a rotation asks again ----------------------------------------------------

def test_an_acknowledgement_before_any_key_covers_the_keys_that_follow(recovery):
    """The ordinary path: back it up first, then generate. That has to count."""
    recovery.acknowledge(actor=Actor(type="user", id="alice"))
    card = recovery.card(version="0.1.0", git_sha="abc")

    assert card.acknowledgement.key_id is None
    assert card.acknowledged is True


def test_an_acknowledgement_of_a_replaced_key_does_not_carry_over(recovery, engine):
    """An archive taken before a rotation opens nothing after it."""
    from painfree.schema import custody_acknowledgement
    import datetime as _dt

    with engine.begin() as connection:
        connection.execute(custody_acknowledgement.insert().values(
            key_id="0123456789abcdef",
            acknowledged_at=_dt.datetime.now(_dt.timezone.utc),
            acknowledged_by="alice"))

    card = recovery.card(version="0.1.0", git_sha="abc")
    rotated = type(card)(key_ids=["fedcba9876543210"],
                         acknowledgement=card.acknowledgement,
                         version="0.1.0", git_sha="abc")

    assert rotated.acknowledged is False


def test_a_half_finished_rotation_is_said_rather_than_hidden(recovery):
    """Two key ids is a fact an operator needs, not one to pick from."""
    card = recovery.card(version="0.1.0", git_sha="abc")
    two = type(card)(key_ids=["aaaa", "bbbb"], acknowledgement=None,
                     version="0.1.0", git_sha="abc")

    assert two.rotation_unfinished is True
    assert two.key_id is None
