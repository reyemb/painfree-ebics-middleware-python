"""Proving the credential: what a stranger with a keyboard and a stopwatch gets.

The ``basic`` mode moves the thing standing between a stranger and a bank
connection from *a signature this service verifies* to *a password this service
stores*. This file is the part of that which is about the password itself; what
a successful sign-in may then reach is `tests/test_service_basic_access.py`,
and how the deployment is configured to accept one at all is
`tests/test_service_basic_deployment.py`.

Four things it holds.

**One refusal, whatever went wrong.** A wrong password, a name nobody has, an
empty password, a header that is not base64, one with no colon, one naming
nobody, and the wrong scheme entirely. The assertion is *equality between them*
rather than a list of expected values: a caller learns nothing from the
difference because there is no difference, and a change that starts telling two
of them apart fails here without anybody having predicted which two.

**No stopwatch.** Whether a stranger can tell a real account name from an
invented one by timing the refusal is the difference between guessing passwords
for one person and enumerating the people who work at a company.
:func:`test_an_unknown_name_and_a_wrong_password_cost_the_same` measures it,
interleaved and compared as medians, and also asserts that both are slow so that
two equally fast answers cannot pass by having skipped the hash in both.

**A bounded flood.** Failures are counted per account name *and* per source
address, an unknown name is counted exactly as a real one is, a lockout refuses
the correct password, it expires by itself, and an administrator can end it
sooner. The audit trail those produce exists at all only because the throttle
bounds it, so the trail is asserted too.

**Nothing escapes.** The password must not reach a log line, an audit row, an
API response or a traceback. The last of those is the one a name-based blocklist
cannot see, so a `500` is forced out of the sign-in path with the credential in
hand and the whole captured stream is swept.

There is no reference implementation of a password store and none was invented.
The evidence is that every assertion below is a request issued at a running
application, or a measurement taken from one.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
import logging
import re
import statistics
import time

import pytest
from fastapi.testclient import TestClient

import basic_world
from basic_world import (BROWSER, EVERY_PASSWORD, MALLORY, MALLORY_PASSWORD,
                         MINE, NOBODY, NOBODY_PASSWORD, ROOT, ROOT_PASSWORD,
                         basic, credential, mallory, root)
from basic_world import accounts_of as _accounts
from basic_world import seed_accounts as _seed_accounts
from basic_world import settings_for as _basic_settings
from painfree import accounts as accounts_module
from painfree import db
from painfree.accounts import (MINIMUM_PASSWORD_LENGTH, Accounts,
                               PasswordRejected)
from painfree.app import create_app
from painfree.audit import Actor
from painfree.identity import Role
from painfree.schema import basic_account, basic_lockout


@pytest.fixture
def world(sqlite_url):
    """Two banks and four password-holding identities. See `basic_world`."""
    yield from basic_world.build(sqlite_url)


# --- the refusals, and that they are one refusal ----------------------------

#: Four ways of not having a credential. Each is issued at the running
#: application and each must come back as the same sentence: which one of them
#: went wrong is the operator's business, in the log, and a hint to whoever is
#: guessing.
REFUSALS = {
    "a wrong password": lambda: basic(ROOT, "not-the-right-password"),
    "a name nobody has": lambda: basic("ghost", "not-the-right-password"),
    "an empty password": lambda: basic(ROOT, ""),
    "a malformed header": lambda: {"authorization": "Basic ????not-base64"},
    "a header with no colon": lambda: {
        "authorization": "Basic " + base64.b64encode(b"rootnopassword").decode()},
    "an empty name": lambda: basic("", ROOT_PASSWORD),
    "the wrong scheme": lambda: {"authorization": "Bearer " + ROOT_PASSWORD},
    "an empty credential": lambda: {"authorization": "Basic "},
}


def test_every_way_of_not_having_a_credential_answers_the_same_thing(world):
    """Eight refusals, one body, one status, one `WWW-Authenticate`.

    The assertion is *equality between them*, not a list of expected values: a
    caller learns nothing from the difference because there is no difference,
    and a future change that starts distinguishing two of them fails here
    without anybody having predicted which two.
    """
    client, _, _ = world
    answers = {}
    for name, build in REFUSALS.items():
        response = client.get("/auth/me", headers=build())
        body = response.json()["error"]
        answers[name] = (response.status_code, body["code"], body["message"],
                         response.headers.get("www-authenticate"))
        assert response.status_code == 401, f"{name} was not refused"
        # No part of what was sent comes back, including the parts that were
        # correct: naming the account would confirm it exists.
        assert ROOT_PASSWORD not in response.text
        assert "request_id" in body

    distinct = set(answers.values())
    assert len(distinct) == 1, (
        "these refusals are told apart by their response, so a caller can "
        f"work out which half of a guess was wrong: {answers}")
    status, code, message, challenge = distinct.pop()
    assert (status, code) == (401, "unauthenticated")
    assert message == "the request is not authenticated"
    # The scheme advertised is the one this process actually accepts. A `401`
    # offering `Bearer` to a caller holding a password is a caller who never
    # works out why.
    assert challenge == 'Basic realm="painfree", charset="UTF-8"'


def test_a_correct_password_is_the_same_principal_a_token_would_have_been(world):
    """One identity model, reached by a second door."""
    client, _, _ = world
    me = client.get("/auth/me", headers=root()).json()
    assert me["subject"] == ROOT
    assert me["role"] == "admin"
    assert me["issuer"] == "painfree-local"
    # The `method` is the one thing that differs, and it reaches the audit
    # column and nothing else.
    assert me["method"] == "basic"

    member = client.get("/auth/me", headers=mallory()).json()
    assert member["role"] == "member"
    assert member["display_name"] == "Mallory Marsh"
    # The reach is the grant's, read from this deployment's own table.
    assert [row["connection_id"] for row in member["grants"]] == [MINE]
    assert "payments:submit" in member["scopes"]


# --- the stopwatch ----------------------------------------------------------

#: How many measurements per case. Argon2id at 64 MiB is tens of milliseconds,
#: so this is a few seconds and buys a median that is not one scheduler hiccup.
TIMING_SAMPLES = 24


def test_an_unknown_name_and_a_wrong_password_cost_the_same(sqlite_url):
    """The measurement, not the assertion. Interleaved, and compared as medians.

    A service that skips the hash for a name it does not have answers in
    microseconds, and a stranger holding a stopwatch then enumerates the people
    who work here without ever guessing a password. So an unknown name is
    verified against :data:`painfree.accounts.DUMMY_HASH`, which costs what a
    real one costs.

    The thresholds are raised for this test alone: the property being measured
    is the hash comparison, and the lockout -- which is deliberately the one
    branch that *does* short-circuit -- would otherwise stop the run after five
    attempts. The same two names are used throughout so that the database work
    behind each attempt is identical too.
    """
    settings = _basic_settings(sqlite_url, basic_lockout_threshold=100,
                               basic_source_lockout_threshold=1000)
    engine = db.build_engine(settings)
    db.migrate(engine)
    app = create_app(settings)
    with TestClient(app) as client:
        _accounts(app).create(ROOT, ROOT_PASSWORD, role=Role.admin,
                              actor=Actor("cli", "test@cli"))
        known, unknown = [], []
        for _ in range(TIMING_SAMPLES):
            # Interleaved, so a machine that gets busy halfway through makes
            # both samples slower rather than one of them.
            for target, bucket in ((ROOT, known), ("ghost", unknown)):
                started = time.perf_counter()
                response = client.get(
                    "/auth/me", headers=basic(target, "not-the-right-password"))
                bucket.append(time.perf_counter() - started)
                assert response.status_code == 401
    engine.dispose()

    wrong = statistics.median(known)
    missing = statistics.median(unknown)
    # Both must be *slow*: two equal microsecond answers would satisfy a ratio
    # test while proving the hash was skipped in both.
    assert min(wrong, missing) > 0.005, (
        f"neither case ran a memory-hard hash: wrong={wrong*1000:.1f} ms, "
        f"unknown={missing*1000:.1f} ms")
    difference = abs(wrong - missing) / min(wrong, missing)
    assert difference < 0.35, (
        "a wrong password and a name nobody has take measurably different "
        f"times, so account names can be enumerated with a stopwatch: "
        f"wrong={wrong*1000:.1f} ms, unknown={missing*1000:.1f} ms, "
        f"difference={difference*100:.0f}%")


def test_a_disabled_account_is_verified_before_it_is_refused(world):
    """Suspension must not be readable with a stopwatch either.

    A suspended account whose password is wrong and a suspended account whose
    password is right are both refused, and both after the hash has run. The
    assertion here is the behaviour; the cost of it is the same code path the
    measurement above covers.
    """
    client, app, _ = world
    _accounts(app).change(NOBODY, disabled=True, actor=Actor("user", ROOT))
    assert client.get("/auth/me",
                      headers=basic(NOBODY, NOBODY_PASSWORD)).status_code == 401
    # And it comes back the moment it is resumed, with no password reset.
    _accounts(app).change(NOBODY, disabled=False, actor=Actor("user", ROOT))
    assert client.get("/auth/me",
                      headers=basic(NOBODY, NOBODY_PASSWORD)).status_code == 200


# --- brute force ------------------------------------------------------------

def test_guessing_locks_the_account_and_an_administrator_clears_it(sqlite_url):
    """The whole cycle: guess, lock, be refused while correct, be let back in.

    The correct password is offered *after* the lock, which is the assertion
    that matters: a throttle that only refuses wrong passwords throttles
    nothing, because the attacker's last guess is the right one.
    """
    settings = _basic_settings(sqlite_url, basic_lockout_threshold=3,
                               basic_source_lockout_threshold=1000)
    engine = db.build_engine(settings)
    db.migrate(engine)
    app = create_app(settings)
    with TestClient(app) as client:
        _seed_accounts(app)
        for attempt in range(3):
            assert client.get(
                "/auth/me",
                headers=basic(MALLORY, f"guess-{attempt}")).status_code == 401

        # Locked, and the correct password is refused too.
        assert client.get("/auth/me", headers=mallory()).status_code == 401

        locked = client.get("/v1/lockouts?only_locked=true",
                            headers=root()).json()["lockouts"]
        assert [(row["scope"], row["value"]) for row in locked] == \
            [("subject", MALLORY)]
        assert locked[0]["failures"] >= 3
        assert locked[0]["locked"] is True

        # An administrator clears it. The counter goes with the lock, so the
        # next mistyped password starts from one rather than re-locking.
        cleared = client.delete(f"/v1/lockouts/subject/{MALLORY}", headers=root())
        assert cleared.status_code == 200, cleared.text
        assert cleared.json() == {"scope": "subject", "value": MALLORY,
                                  "cleared": True}
        remaining = client.get("/v1/lockouts", headers=root()).json()["lockouts"]
        # The source counter is a different counter and is deliberately left
        # alone: clearing one person's lockout is not clearing an address.
        assert [row["scope"] for row in remaining] == ["source"]

        # Back in, immediately, with no restart and no new password.
        assert client.get("/auth/me", headers=mallory()).status_code == 200

        # Clearing one nobody holds is a `404`, not a silent success.
        assert client.delete(f"/v1/lockouts/subject/{MALLORY}",
                             headers=root()).status_code == 404
        assert client.delete("/v1/lockouts/nonsense/x",
                             headers=root()).status_code == 404
    engine.dispose()


def test_a_name_nobody_has_is_throttled_exactly_as_a_real_one_is(sqlite_url):
    """Otherwise the lockout is the account oracle the password check is not.

    Five wrong guesses at a real name and five at an invented one have to end
    the same way, or a stranger learns which names exist by watching which ones
    start being refused differently.
    """
    settings = _basic_settings(sqlite_url, basic_lockout_threshold=3,
                               basic_source_lockout_threshold=1000)
    engine = db.build_engine(settings)
    db.migrate(engine)
    app = create_app(settings)
    with TestClient(app) as client:
        _seed_accounts(app)
        for name in (MALLORY, "ghost"):
            for attempt in range(4):
                assert client.get(
                    "/auth/me",
                    headers=basic(name, f"guess-{attempt}")).status_code == 401
        counters = {(row["scope"], row["value"]): row for row
                    in client.get("/v1/lockouts", headers=root()).json()["lockouts"]}
        assert counters[("subject", MALLORY)]["locked"] is True
        assert counters[("subject", "ghost")]["locked"] is True
        assert counters[("subject", MALLORY)]["failures"] == \
            counters[("subject", "ghost")]["failures"]
    engine.dispose()


def test_a_source_address_is_throttled_across_the_names_it_tries(sqlite_url):
    """Per-account counting alone lets one address spray a hundred names.

    The source threshold is higher than the per-account one on purpose -- a
    shared office address is many people -- so this is the counter that catches
    spraying rather than guessing.
    """
    settings = _basic_settings(sqlite_url, basic_lockout_threshold=100,
                               basic_source_lockout_threshold=4)
    engine = db.build_engine(settings)
    db.migrate(engine)
    app = create_app(settings)
    with TestClient(app) as client:
        _seed_accounts(app)
        for index in range(5):
            assert client.get(
                "/auth/me",
                headers=basic(f"name-{index}", "spray")).status_code == 401
        # No account name has been guessed at more than once, and the address
        # is locked anyway -- which is what stops the sixth name being tried.
        # Read from the store, not from `/v1/lockouts`: the administrator is
        # coming from the locked address too, which is the next assertion.
        locked = _accounts(app).lockouts(only_locked=True)
        assert [row.scope for row in locked] == ["source"]

        # The cost of a per-source control, stated rather than hidden: the
        # administrator's own correct password is refused from the same
        # address, so the console cannot be used to clear it.
        assert client.get("/auth/me", headers=root()).status_code == 401
        assert client.get("/v1/lockouts", headers=root()).status_code == 401

        # Which is why the lever also exists outside the front door.
        from painfree.__main__ import main

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setenv("PAINFREE_DATABASE_URL", sqlite_url)
        monkeypatch.setenv("PAINFREE_AUTH_MODE", "basic")
        try:
            assert main(["unlock", locked[0].value]) == 0
        finally:
            monkeypatch.undo()
        assert client.get("/auth/me", headers=root()).status_code == 200
        # Running it again says so rather than pretending it did something.
        assert _accounts(app).lockouts(only_locked=True) == []
    engine.dispose()


def test_a_lockout_expires_by_itself(sqlite_url):
    """Not only an administrator can end one. Proved by moving the clock back."""
    settings = _basic_settings(sqlite_url, basic_lockout_threshold=2,
                               basic_lockout_minutes=15)
    engine = db.build_engine(settings)
    db.migrate(engine)
    app = create_app(settings)
    with TestClient(app) as client:
        _seed_accounts(app)
        for attempt in range(2):
            client.get("/auth/me", headers=basic(MALLORY, f"guess-{attempt}"))
        assert client.get("/auth/me", headers=mallory()).status_code == 401

        # Age the row rather than sleep: the lock is a timestamp, and the thing
        # being tested is that the timestamp is what decides.
        from sqlalchemy import update

        past = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=30)
        with engine.begin() as connection:
            connection.execute(update(basic_lockout).values(
                locked_until=past, last_failure_at=past))
        assert client.get("/auth/me", headers=mallory()).status_code == 200
    engine.dispose()


def test_every_failure_is_an_audit_row_and_none_of_them_holds_the_password(world):
    """The trail the lockout makes safe to write.

    Rejected authentications are kept out of the audit log because
    unauthenticated traffic is unbounded. It is not unbounded here: the
    throttle stops counting once a name locks, so what a guessing run appends
    is the threshold in rows.
    """
    client, app, _ = world
    for attempt in range(3):
        client.get("/auth/me", headers=basic(MALLORY, f"guess-{attempt}"))
    rows = client.get("/v1/audit?limit=200", headers=root()).json()["events"]
    failures = [row for row in rows if row["action"] == "auth.sign_in_failed"]
    assert len(failures) == 3
    for row in failures:
        assert row["outcome"] == "failure"
        # The row names who *claimed* to be signing in, and says the claim was
        # not verified. Reading a trail where an unverified claim looks like a
        # verified one is worse than not having the row.
        assert row["actor_type"] == "unverified"
        assert row["actor_id"] == MALLORY
        assert row["detail"]["reason"] == "unknown_or_wrong_password"
        serialised = json.dumps(row)
        assert "guess-" not in serialised
        assert MALLORY_PASSWORD not in serialised


def test_a_successful_sign_in_clears_that_name_s_failures(world):
    """A mistyped password twice this morning must not lock somebody at noon."""
    client, app, _ = world
    for attempt in range(2):
        client.get("/auth/me", headers=basic(MALLORY, f"guess-{attempt}"))
    assert client.get("/auth/me", headers=mallory()).status_code == 200
    counters = client.get("/v1/lockouts", headers=root()).json()["lockouts"]
    assert not [row for row in counters
                if row["scope"] == "subject" and row["value"] == MALLORY]


# --- the password does not escape -------------------------------------------

def test_no_password_reaches_the_log_stream_or_an_audit_row(world, caplog):
    """Every path a credential travels, swept for the value afterwards.

    Including the two a name-based blocklist cannot see: an exception message
    and the traceback that repeats it. The `500` below is forced deliberately,
    with the credential in hand, because that is the shape that leaked a bearer
    token the first time it was tested.
    """
    client, app, _ = world
    with caplog.at_level(logging.DEBUG):
        client.get("/auth/me", headers=root())
        client.get("/auth/me", headers=basic(ROOT, "a-wrong-password-value"))
        client.post("/auth/login", headers={
            **BROWSER, "content-type": "application/x-www-form-urlencoded"},
            content=f"subject={ROOT}&password={ROOT_PASSWORD}")
        client.put("/v1/accounts", headers=root(), json={
            "subject": "logged", "password": "a-password-through-the-api",
            "role": "member"})
        client.post(f"/v1/accounts/{MALLORY}/password", headers=root(),
                    json={"password": "another-password-through-the-api"})
        # Refused by the policy, which is the path that renders a message.
        rejected = client.put("/v1/accounts", headers=root(), json={
            "subject": "short", "password": "tiny", "role": "member"})
        assert rejected.status_code == 422
        assert "tiny" not in rejected.text

        # And a `500` raised out of the sign-in path, credential in hand.
        def explode(*args, **kwargs):
            raise RuntimeError("verification blew up")

        original = accounts_module.Accounts.authenticate
        accounts_module.Accounts.authenticate = explode
        try:
            crashed = client.get("/auth/me", headers=basic(ROOT, "boom-password"))
        finally:
            accounts_module.Accounts.authenticate = original
        assert crashed.status_code == 500
        assert "boom-password" not in crashed.text

    stream = caplog.text
    leaked = [value for value in (
        *EVERY_PASSWORD, "a-wrong-password-value", "boom-password",
        "a-password-through-the-api", "another-password-through-the-api",
        "tiny") if value in stream]
    assert not leaked, f"these values reached the log stream: {leaked}"
    # The traceback was still written, so this passed for the right reason.
    assert "Traceback" in stream and "verification blew up" in stream

    # The base64 the credential travelled in is not in the stream either: it is
    # reversible, so logging it is logging the password.
    assert credential(ROOT, ROOT_PASSWORD) not in stream

    rows = json.dumps(client.get("/v1/audit?limit=500",
                                 headers=root()).json())
    assert not [value for value in EVERY_PASSWORD if value in rows]
    assert "$argon2id$" not in rows


def test_no_response_ever_carries_a_hash(world):
    """The stored hash never leaves `painfree.accounts`."""
    client, _, _ = world
    for path in ("/v1/accounts", "/v1/lockouts", "/auth/me",
                 f"/v1/grants?subject={MALLORY}"):
        body = client.get(path, headers=root()).text
        assert "$argon2id$" not in body
        assert "password_hash" not in body
    listing = client.get("/v1/accounts", headers=root()).json()["accounts"]
    assert {"subject", "display_name", "role", "disabled", "created_at",
            "created_by", "updated_at", "password_changed_at"} == set(listing[0])


# --- the store, on its own --------------------------------------------------

def test_a_stored_hash_is_argon2id_with_the_parameters_this_build_uses(sqlite_url):
    """Not a comparison against another implementation: there is none to make.

    What is asserted is the encoded form itself, which carries the algorithm,
    the version and the cost parameters, so a build that silently fell back to
    a weaker primitive fails here.
    """
    from sqlalchemy import select

    settings = _basic_settings(sqlite_url)
    engine = db.build_engine(settings)
    db.migrate(engine)
    store = Accounts(engine)
    store.create(ROOT, ROOT_PASSWORD, role=Role.admin,
                 actor=Actor("cli", "test@cli"))
    with engine.connect() as connection:
        stored = connection.execute(
            select(basic_account.c.password_hash)).scalar_one()
    assert re.match(r"^\$argon2id\$v=19\$m=65536,t=3,p=4\$", stored), stored
    # The password is not recoverable from it, and two accounts with the same
    # password do not share a hash: the salt is per row.
    assert ROOT_PASSWORD not in stored
    store.create("twin", ROOT_PASSWORD, actor=Actor("cli", "test@cli"))
    with engine.connect() as connection:
        hashes = [row[0] for row in
                  connection.execute(select(basic_account.c.password_hash))]
    assert len(set(hashes)) == 2
    engine.dispose()


def test_the_policy_refuses_a_short_password_without_quoting_it():
    with pytest.raises(PasswordRejected) as refused:
        accounts_module.check_password_policy("short")
    assert "short" not in str(refused.value).replace("shortest", "")
    assert str(MINIMUM_PASSWORD_LENGTH) in str(refused.value)
    with pytest.raises(PasswordRejected):
        accounts_module.check_password_policy(
            "x" * (accounts_module.MAXIMUM_PASSWORD_LENGTH + 1))


def test_an_oversized_credential_is_refused_before_the_hasher(sqlite_url):
    """A megabyte-long password is a request to spend a second, not a guess."""
    settings = _basic_settings(sqlite_url)
    engine = db.build_engine(settings)
    db.migrate(engine)
    app = create_app(settings)
    with TestClient(app) as client:
        _accounts(app).create(ROOT, ROOT_PASSWORD, role=Role.admin,
                              actor=Actor("cli", "test@cli"))
        huge = "x" * (accounts_module.MAXIMUM_PASSWORD_LENGTH + 1)
        started = time.perf_counter()
        assert client.get("/auth/me",
                          headers=basic(ROOT, huge)).status_code == 401
        assert time.perf_counter() - started < 0.02
        # And it did not consume the account's failure budget either.
        assert client.get("/v1/lockouts", headers=root()).json()["lockouts"] == []
    engine.dispose()


def test_the_verification_cache_holds_no_password_and_dies_with_the_process():
    """It is keyed by a keyed hash of the credential *and* the stored hash."""
    cache = accounts_module._VerificationCache(ttl=60.0, size=4)
    key = cache.key("alice", "a-password", "$argon2id$stored")
    assert b"a-password" not in key and b"alice" not in key
    assert not cache.holds(key)
    cache.remember(key)
    assert cache.holds(key)
    # A different stored hash is a different key: replacing a password makes
    # every cached verification of the old one unreachable at once.
    assert not cache.holds(cache.key("alice", "a-password", "$argon2id$other"))
    # It is bounded.
    for index in range(20):
        cache.remember(cache.key(f"user{index}", "p", "h"))
    assert len(cache._entries) <= 4


def test_an_expired_cache_entry_is_not_a_credential(monkeypatch):
    cache = accounts_module._VerificationCache(ttl=0.0, size=4)
    key = cache.key("alice", "a-password", "$argon2id$stored")
    cache.remember(key)
    assert not cache.holds(key)
