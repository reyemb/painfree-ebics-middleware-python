"""The world the three `basic` authentication files attack, in one place.

A helper module rather than a `conftest` fixture, the way `tests/idp.py` is one:
this world means nothing to the other forty test files, and putting it where
every one of them imports it would be putting it where every one of them pays
for it.

It is deliberately **the access tests' world**, seeded through
:func:`test_service_access._seed`, with the same two banks, the same grants and
the same opaque ids. That is what lets `tests/test_service_basic_access.py`
import the grant and oversight route tables and drive them with a password
rather than restating them: the claim being made is that authentication changed
and authorisation did not, and a claim about a different world would be a claim
about something else.

The one difference from that fixture is the credential. Every identity here
signs in with a password.
"""

from __future__ import annotations

import base64

from fastapi.testclient import TestClient

import test_service_access as access
from conftest import CUSTODY_SECRET, grant, grant_oversight
from painfree import db, wrapping
from painfree.accounts import Accounts
from painfree.api import IDEMPOTENCY_HEADER
from painfree.app import create_app
from painfree.audit import Actor
from painfree.config import load_settings
from painfree.identity import Role

BROWSER = {"accept": "text/html,application/xhtml+xml"}

#: The two banks that route table is written against, reused verbatim.
MINE = access.MINE
YOURS = access.YOURS

ROOT = "root"
MALLORY = "mallory"
WATCHER = "wanda"
NOBODY = "nobody"

#: Long enough for the policy, and nothing like each other, so a test that
#: passed by sending the wrong one would fail rather than pass quietly.
ROOT_PASSWORD = "root-correct-horse-battery"
MALLORY_PASSWORD = "mallory-tin-lantern-parade"
WATCHER_PASSWORD = "wanda-slate-harbour-eleven"
NOBODY_PASSWORD = "nobody-plain-copper-window"

#: Every password these files create, for the leak sweep.
EVERY_PASSWORD = (ROOT_PASSWORD, MALLORY_PASSWORD, WATCHER_PASSWORD,
                  NOBODY_PASSWORD)

CLI_ACTOR = Actor("cli", "test@cli")


def credential(subject: str, password: str) -> str:
    return base64.b64encode(f"{subject}:{password}".encode()).decode()


def basic(subject: str, password: str, **extra) -> dict[str, str]:
    """One `Authorization: Basic` header, built the way a client builds it."""
    return {"authorization": f"Basic {credential(subject, password)}", **extra}


def root(**extra) -> dict[str, str]:
    return basic(ROOT, ROOT_PASSWORD, **extra)


def mallory(**extra) -> dict[str, str]:
    return basic(MALLORY, MALLORY_PASSWORD, **extra)


def watcher(**extra) -> dict[str, str]:
    return basic(WATCHER, WATCHER_PASSWORD, **extra)


def settings_for(sqlite_url: str, **overrides):
    """A `basic` deployment, with a custody secret so the seed can wrap one."""
    return load_settings(database_url=sqlite_url, auth_mode="basic",
                         key_encryption_secret=CUSTODY_SECRET, **overrides)


def accounts_of(app) -> Accounts:
    return app.state.accounts


def seed_accounts(app) -> None:
    """The four identities, created the way an administrator creates them."""
    store = accounts_of(app)
    store.create(ROOT, ROOT_PASSWORD, role=Role.admin, actor=CLI_ACTOR)
    store.create(MALLORY, MALLORY_PASSWORD, role=Role.member,
                 display_name="Mallory Marsh", actor=CLI_ACTOR)
    store.create(WATCHER, WATCHER_PASSWORD, role=Role.member, actor=CLI_ACTOR)
    store.create(NOBODY, NOBODY_PASSWORD, role=Role.member, actor=CLI_ACTOR)


def build(sqlite_url: str):
    """Two banks, four accounts, and the same grants the access and oversight
    tests attack.

    A generator, so a test module's own `world` fixture is
    ``yield from basic_world.build(sqlite_url)`` and nothing has to import a
    fixture out of another module and hope pytest notices it.

    `mallory` holds `operator` on one connection and nothing at the other;
    `wanda` holds deployment-wide oversight and no connection grant at all;
    `nobody` holds nothing.
    """
    settings = settings_for(sqlite_url)
    engine = db.build_engine(settings)
    db.migrate(engine)
    wrapping.publish(engine, settings.custody_key())
    access._seed(engine, MINE)
    access._seed(engine, YOURS)
    app = create_app(settings)
    with TestClient(app) as client:
        seed_accounts(app)
        for index, connection_id in enumerate((MINE, YOURS)):
            assert client.post("/v1/webhooks", headers=root(**{
                IDEMPOTENCY_HEADER: f"seed-wh-{index}"}), json={
                    "url": f"https://consumer.test/{connection_id}",
                    "event_types": ["order.accepted"],
                    "connection_id": connection_id}).status_code == 201
            assert client.post("/v1/schedules", headers=root(), json={
                "connection_id": connection_id, "service_name": "EOP",
                "msg_name": "camt.053", "msg_version": "08",
                "cadence_seconds": 3600}).status_code == 201
        # The subscription that receives *every* connection's payment events:
        # what an oversight holder must be able to read and a member never can.
        assert client.post("/v1/webhooks", headers=root(**{
            IDEMPOTENCY_HEADER: "seed-wh-global"}), json={
                "url": "https://consumer.test/everything",
                "event_types": ["order.accepted"]}).status_code == 201
        grant(app, MALLORY, MINE, "operator")
        grant_oversight(app, WATCHER)
        yield client, app, ids_of(client)
    engine.dispose()


def ids_of(client) -> dict[str, str]:
    """The opaque ids of everything seeded, keyed the way those tests key them."""
    found: dict[str, str] = {}
    for row in client.get("/v1/schedules", headers=root()).json()["schedules"]:
        found[f"schedule:{row['connection_id']}"] = row["schedule_id"]
    for row in client.get("/v1/webhooks", headers=root()).json()["webhooks"]:
        found[f"webhook:{row['connection_id'] or 'global'}"] = \
            row["subscription_id"]
    return found
