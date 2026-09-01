"""The custody boundary, proved against a running application.

Private keys are decrypted only inside the worker and are never reachable from
the request-handling path, and :mod:`painfree.custody` says how that is
enforced. These tests are the evidence, and they are deliberately driven
through a real ``TestClient`` request rather than by calling a function and
asserting a flag -- the claim is about what happens inside an HTTP request, so
the test has to be inside one.

Three mechanisms, one test each, plus the negative space: what the application's
own state does *not* contain, and what never reaches the log.
"""

from __future__ import annotations

import json

import pytest
from fastapi import Body
from fastapi.testclient import TestClient

from conftest import PRODUCTION_OIDC, dev_credentials
from painfree import custody, db, ebics3
from painfree.app import create_app
from painfree.audit import AuditLog
from painfree.config import load_settings
from painfree.connections import ConnectionRegistry
from painfree.custody import CustodyViolation
from painfree.keyring import KeyCustodian, Keyring
from painfree.sealing import CustodyKey, new_secret

CONNECTION = "acme-ubs"


@pytest.fixture
def app(custody_settings):
    return create_app(custody_settings)


@pytest.fixture
def prepared(custody_settings):
    """A database with one connection and a full set of sealed keys."""
    engine = db.build_engine(custody_settings)
    db.migrate(engine)
    audit = AuditLog(engine)
    ConnectionRegistry(engine, audit).register(
        CONNECTION, host_id="UBSHOST", partner_id="PARTNER1", user_id="USER1",
        host_url="https://ebics.example/h005")
    custodian = KeyCustodian(engine, audit, custody_settings.custody_key())
    keys = custodian.create_subscriber_keys(
        CONNECTION, subject=ebics3.subject_name("acme", "Acme AG", "CH"))
    yield engine, audit, custodian, keys
    engine.dispose()


def emitted(capsys) -> list[dict]:
    return [json.loads(line) for line in capsys.readouterr().out.splitlines()
            if line.strip()]


# --- 1: the application cannot reach a custody key at all -------------------

def test_the_application_state_carries_no_way_to_open_a_key(app, custody_secret):
    """What `request.app.state` offers is the whole reachable object graph."""
    with TestClient(app, headers=dev_credentials()):
        state = vars(app.state)["_state"]

    assert isinstance(state["keyring"], Keyring)
    assert not any(isinstance(value, (KeyCustodian, CustodyKey))
                   for value in state.values())
    # The settings the request path can read no longer carry the secret, even
    # though the process was started with one.
    assert state["settings"].key_encryption_secret is None
    assert custody_secret not in json.dumps(state["resolved_config"])


def test_the_startup_line_names_the_custody_key_and_never_the_secret(
        app, custody_secret, capsys):
    """An operator has to see *which* key is loaded; that is a hash, not the key."""
    with TestClient(app, headers=dev_credentials()):
        pass
    lines = emitted(capsys)
    starting = next(line for line in lines if line["event"] == "service.starting")
    assert starting["config"]["key_encryption_secret"] == "***"
    assert starting["config"]["custody_key_id"]
    assert custody_secret not in json.dumps(lines)

    started = next(line for line in lines
                   if line.get("action") == "service.started")
    assert started["detail"]["custody_key_id"] == \
        starting["config"]["custody_key_id"]


def test_settings_reached_through_the_app_cannot_derive_the_key(app):
    from painfree.config import ConfigurationError

    with TestClient(app, headers=dev_credentials()):
        with pytest.raises(ConfigurationError, match="KEY_ENCRYPTION_SECRET"):
            app.state.settings.custody_key()


# --- 2: a handler cannot build a custodian ---------------------------------

def test_a_request_handler_cannot_build_a_key_custodian(
        custody_settings, prepared, capsys):
    """The refusal happens where the mistake is, not at the first signature."""
    engine, audit, _, _ = prepared
    app = create_app(custody_settings)
    key = custody_settings.custody_key()

    @app.post("/_mistake")
    def mistake(body: dict = Body(default={})):
        # A handler that has, by whatever route, got hold of everything it
        # needs. It still cannot have a custodian.
        return {"key_id": KeyCustodian(engine, audit, key).key_id}

    with TestClient(app, headers=dev_credentials()) as client:
        response = client.post("/_mistake", json={})

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    lines = emitted(capsys)
    violation = next(line for line in lines if line["event"] == "custody.violation")
    assert violation["operation"] == "building a key custodian"
    failed = next(line for line in lines if line["event"] == "request.failed")
    assert failed["exception"] == "CustodyViolation"
    assert "opened only in the worker" in failed["traceback"]


def test_a_request_handler_holding_a_custodian_still_cannot_open_a_key(
        custody_settings, prepared, capsys):
    """The mechanism that holds even when every other one has been bypassed."""
    _, _, custodian, _ = prepared
    app = create_app(custody_settings)

    @app.post("/_open")
    def open_key(body: dict = Body(default={})):
        return {"fingerprint": custodian.open(CONNECTION, "X002").fingerprint_hex}

    with TestClient(app, headers=dev_credentials()) as client:
        response = client.post("/_open", json={})

    assert response.status_code == 500
    violation = next(line for line in emitted(capsys)
                     if line["event"] == "custody.violation")
    assert violation["operation"] == "opening a private key"


def test_a_synchronous_route_cannot_escape_through_the_thread_pool(
        custody_settings, prepared):
    """Context variables follow into the pool, so `def` is not a way out.

    The route above is synchronous, so this is really the same test twice; it
    is stated separately because "the check was async-only" is the plausible
    way for this boundary to quietly stop working.
    """
    _, _, custodian, _ = prepared
    app = create_app(custody_settings)
    seen = {}

    @app.get("/_sync")
    def sync_route():
        seen["in_request"] = custody.in_request_path()
        return {"in_request": seen["in_request"]}

    with TestClient(app, headers=dev_credentials()) as client:
        assert client.get("/_sync").json() == {"in_request": True}


def test_a_handler_cannot_declare_itself_a_worker(custody_settings, prepared):
    """The obvious way around the check, closed."""
    app = create_app(custody_settings)

    @app.get("/_pretend")
    def pretend():
        with custody.worker_context():
            return {"ok": True}

    with TestClient(app, headers=dev_credentials()) as client:
        assert client.get("/_pretend").status_code == 500


# --- 3: outside a request, everything works --------------------------------

def test_the_same_operations_succeed_outside_a_request(prepared, keys=None):
    """The positive control: the boundary refuses a place, not the operation."""
    _, _, custodian, keys = prepared
    with custody.worker_context():
        assert custodian.open(CONNECTION, "X002").fingerprint_hex == \
            keys["X002"].fingerprint_hex


def test_the_public_keyring_still_serves_a_request(custody_settings, prepared):
    """Everything the request path legitimately needs, it still gets."""
    engine, _, _, keys = prepared
    app = create_app(custody_settings)

    @app.get("/_fingerprints")
    def fingerprints():
        keyring = Keyring(engine)
        connection = ConnectionRegistry(engine).get(CONNECTION)
        return {"fingerprints": keyring.fingerprints(CONNECTION),
                "letter": keyring.letter(connection).signature.fingerprint}

    with TestClient(app, headers=dev_credentials()) as client:
        body = client.get("/_fingerprints").json()
    assert body["fingerprints"]["subscriber/X002"] == keys["X002"].fingerprint_hex
    # The letter quotes whichever fingerprint the connection names, and H005
    # names the certificate's. `fingerprints()` is the public-key digest either
    # way: it is the keyring's own index, not a letter.
    assert body["letter"] == ebics3.ini_letter_hash(
        keys["A006"], ConnectionRegistry(engine).get(CONNECTION).letter_digest)


def test_the_keyring_has_no_method_that_returns_private_material():
    """Reviewed as a surface, so a new accessor cannot appear unnoticed."""
    surface = {name for name in dir(Keyring) if not name.startswith("_")}
    # `staged_*` read the bank keys HPB delivered and nobody has vouched for
    # yet. They are on this side of the boundary deliberately: the screen where
    # an operator compares a fingerprint against a letter is read-only, and
    # public material is what it reads.
    assert surface == {"bank_keys", "entries", "entry", "fingerprints",
                       "letter", "public_key", "signature_version",
                       "staged_bank_keys", "staged_fingerprints"}
    stored = {name for name in dir(Keyring) if "private" in name or "open" in name}
    assert stored == set()


# --- what never reaches the log --------------------------------------------

def test_no_key_material_or_custody_secret_reaches_the_log_even_via_a_traceback(
        custody_settings, custody_secret, prepared, capsys):
    """The leak this repo already found once, re-tested with the new secret.

    A request carries, at once: a private key and a custody secret interpolated
    into an exception message -- so they arrive through the *traceback*, under no
    field name at all -- and order data logged as a field. None of it may appear
    in what the process wrote.

    What is claimed, precisely: the private key is caught by shape, the custody
    secret because deriving it registered it, and the order data by field name.
    Payment content interpolated into free text is caught by none of those and
    is prevented by the call-site rule instead -- payloads are logged by
    ``order_id``, never by content -- which is a review property, not a
    mechanism, and is stated rather than pretended.
    """
    _, _, custodian, _ = prepared
    with custody.worker_context():
        private_pem = custodian.open(CONNECTION, "A006").private_pem().decode()
    app = create_app(custody_settings)
    order_data = "CH9300762011623852957 EUR 4200.00 Alice pays Bob"

    @app.post("/_leak")
    def leak(body: dict = Body()):
        from painfree.logging import get_logger

        # A call site doing the right thing with the payment...
        get_logger("painfree.test").info(
            "order.accepted", order_id="o-1", order_data=body["order_data"])
        # ...and the wrong thing with the credentials, which must still not leak.
        raise RuntimeError(
            f"upload failed with key {private_pem} and secret {custody_secret}")

    with TestClient(app, headers=dev_credentials()) as client:
        response = client.post("/_leak", json={"order_data": order_data})
    assert response.status_code == 500

    written = capsys.readouterr().out
    for value, what in ((custody_secret, "the custody secret"),
                        (private_pem.strip(), "the private key"),
                        ("MII", "base64 key material"),
                        (order_data, "the order data")):
        assert value not in written, f"{what} reached the log stream"
    line = next(json.loads(raw) for raw in written.splitlines()
                if raw.strip() and json.loads(raw)["event"] == "request.failed")
    # A message carrying a PEM block is replaced outright; the *traceback* is
    # scrubbed instead, so it stays a usable trace with the two secrets removed
    # in place.
    assert line["exception_message"] == "<redacted:pem>"
    assert "<redacted:secret>" in line["traceback"]
    assert "<redacted:pem>" in line["traceback"]
    assert "RuntimeError" in line["traceback"] and ", in leak" in line["traceback"]


def test_a_key_material_row_is_never_logged_by_content(prepared, capsys):
    """Key rows are logged by fingerprint. Nothing else is claimed, or needed."""
    _, _, custodian, keys = prepared
    with custody.worker_context():
        custodian.open(CONNECTION, "E002")
    for line in emitted(capsys):
        assert "sealed_private" not in json.dumps(line)
        assert "PRIVATE KEY" not in json.dumps(line)


# --- configuration ----------------------------------------------------------

def test_production_refuses_to_start_without_a_custody_secret():
    """A production process that cannot open its keyring finds out at boot."""
    from painfree.config import ConfigurationError

    with pytest.raises(ConfigurationError, match="KEY_ENCRYPTION_SECRET"):
        load_settings(environment="production", role="worker", **PRODUCTION_OIDC,
                      database_url="postgresql+psycopg://p:x@db/painfree")


def test_production_starts_with_one():
    settings = load_settings(
        environment="production", role="worker", **PRODUCTION_OIDC,
        database_url="postgresql+psycopg://p:x@db/painfree",
        key_encryption_secret=new_secret())
    assert settings.custody_key_id


def test_development_may_run_without_one_and_says_so_when_asked(settings):
    from painfree.config import ConfigurationError

    assert settings.custody_key_id is None
    with pytest.raises(ConfigurationError, match="no EBICS private key"):
        settings.custody_key()


def test_the_violation_is_not_a_service_error():
    """It is a defect, so it gets a stack trace and an opaque 500, not a code."""
    from painfree.errors import ServiceError

    assert not issubclass(CustodyViolation, ServiceError)
