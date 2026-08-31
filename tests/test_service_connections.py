"""The bank connection registry, and the state a resumed initialisation needs.

The interesting claim is not that rows round-trip. It is that the key state the
engine hands back is persisted faithfully enough that a restart continues the
initialisation instead of restarting it -- which, against a real bank, means the
difference between finishing a registration and being told the subscriber is
already initialised.
"""

from __future__ import annotations

import pytest

from painfree import db, ebics3
from painfree.audit import AuditLog
from painfree.connections import ConnectionRegistry
from painfree.errors import ConflictError, NotFoundError


@pytest.fixture
def engine(settings):
    engine = db.build_engine(settings)
    db.migrate(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def audit(engine):
    return AuditLog(engine)


@pytest.fixture
def registry(engine, audit):
    return ConnectionRegistry(engine, audit)


def _register(registry, connection_id="acme-ubs", **overrides):
    fields = {"host_id": "UBSHOST", "partner_id": "PARTNER1",
              "user_id": "USER1", "host_url": "https://ebics.example/h005",
              "product": ebics3.Product("painfree", "de")}
    fields.update(overrides)
    return registry.register(connection_id, **fields)


# --- registration -----------------------------------------------------------

def test_a_registered_connection_starts_at_created(registry):
    connection = _register(registry)
    assert connection.key_state is ebics3.KeyState.CREATED
    assert connection.ini_sent is False and connection.hia_sent is False
    assert connection.initialised is False


def test_the_engine_gets_the_identifiers_and_nothing_else(registry):
    """`RequestContext` is the engine's whole view of a connection."""
    context = _register(registry).context
    assert context.host_id == "UBSHOST"
    assert context.product.name == "painfree"


def test_several_connections_coexist_and_are_addressed_independently(registry):
    _register(registry, "acme-ubs")
    _register(registry, "acme-postfinance", host_id="PFHOST",
              partner_id="PARTNER2", user_id="USER2",
              host_url="https://pf.example/h005")
    assert [c.connection_id for c in registry.all()] == \
        ["acme-ubs", "acme-postfinance"]
    assert registry.get("acme-postfinance").host_id == "PFHOST"


def test_the_same_subscriber_cannot_be_registered_twice(registry):
    """Two rows for one `HostID`/`PartnerID`/`UserID` are two key sets at one bank."""
    _register(registry)
    with pytest.raises(ConflictError):
        _register(registry, "acme-ubs-again")


def test_a_reused_connection_id_is_refused(registry):
    _register(registry)
    with pytest.raises(ConflictError):
        _register(registry, "acme-ubs", host_id="OTHER", partner_id="P2",
                  user_id="U2")


@pytest.mark.parametrize("bad", ["", "Acme UBS", "acme/ubs", "-leading",
                                 "x" * 65])
def test_a_connection_id_that_would_be_awkward_in_a_log_line_is_refused(
        registry, bad):
    with pytest.raises(ConflictError):
        _register(registry, bad)


def test_an_identifier_the_bank_would_refuse_is_refused_here(registry):
    """The engine's own limits, not a second set of rules that can disagree."""
    with pytest.raises(ebics3.RequestError):
        _register(registry, "acme-long", host_id="H" * 36)


def test_an_unsupported_protocol_version_is_refused(registry):
    with pytest.raises(ConflictError, match="H005"):
        _register(registry, "acme-h004", ebics_version="H004")


def test_an_unknown_connection_is_a_not_found(registry):
    with pytest.raises(NotFoundError):
        registry.get("nobody")


# --- the state a resume depends on -----------------------------------------

def _initialisation(connection):
    keys = {version: ebics3.EbicsKey.generate(
                version, subject=ebics3.subject_name("acme"), key_size=2048)
            for version in ("A006", "X002", "E002")}
    return ebics3.Initialisation(connection.context, keys["A006"],
                                 keys["X002"], keys["E002"])


def test_progress_is_written_back_after_every_exchange(registry):
    connection = _register(registry)
    initialisation = _initialisation(connection)

    initialisation.ini_sent, initialisation.ini_order_id = True, "A00A"
    saved = registry.save_progress("acme-ubs", initialisation)
    assert saved.key_state is ebics3.KeyState.INI_SENT
    assert saved.ini_order_id == "A00A"

    initialisation.hia_sent, initialisation.hia_order_id = True, "A00B"
    saved = registry.save_progress("acme-ubs", initialisation)
    assert saved.key_state is ebics3.KeyState.KEYS_SENT
    assert (saved.ini_sent, saved.hia_sent) == (True, True)


def test_a_half_finished_initialisation_asks_only_for_what_is_outstanding(registry):
    """The reason the state is a column at all.

    Rebuilt from what was stored, the engine's state machine asks for `HIA` --
    not `INI`, which the bank has already accepted and would refuse a second
    time.
    """
    connection = _register(registry)
    initialisation = _initialisation(connection)
    initialisation.ini_sent, initialisation.ini_order_id = True, "A00A"
    registry.save_progress("acme-ubs", initialisation)

    stored = registry.get("acme-ubs")
    resumed = ebics3.Initialisation(
        stored.context, initialisation.signature_key,
        initialisation.authentication_key, initialisation.encryption_key,
        ini_sent=stored.ini_sent, hia_sent=stored.hia_sent,
        ini_order_id=stored.ini_order_id, hia_order_id=stored.hia_order_id)
    assert resumed.next_step is ebics3.Step.HIA
    assert resumed.state is ebics3.KeyState.INI_SENT


# --- the audit trail --------------------------------------------------------

def test_every_step_is_audited_through_the_one_chokepoint(registry, audit):
    connection = _register(registry)
    initialisation = _initialisation(connection)
    initialisation.ini_sent, initialisation.ini_order_id = True, "A00A"
    registry.save_progress("acme-ubs", initialisation)

    actions = [row["action"] for row in audit.recent()]
    assert "connection.registered" in actions
    assert "key.sent" in actions
    assert "connection.key_state_changed" in actions


def test_a_repeated_save_that_achieved_nothing_is_not_recorded_as_progress(
        registry, audit):
    connection = _register(registry)
    initialisation = _initialisation(connection)
    initialisation.ini_sent = True
    registry.save_progress("acme-ubs", initialisation)
    before = len(audit.recent(limit=100))
    registry.save_progress("acme-ubs", initialisation)
    assert len(audit.recent(limit=100)) == before


def test_an_audit_row_carries_the_connection_it_is_about(registry, audit):
    _register(registry)
    row = next(r for r in audit.recent() if r["action"] == "connection.registered")
    assert row["connection_id"] == "acme-ubs"


# --- registering one over the JSON API ---------------------------------------
#
# The console had the only route that could register a connection, so a
# deployment was rebuilt by retyping a bank's parameter sheet into a browser.
# These hold the JSON route to the same rules the console route obeys: the same
# scope, the same refusal on a duplicate, and no way to smuggle key material in.

from fastapi.testclient import TestClient                          # noqa: E402

from conftest import dev_credentials                               # noqa: E402
from painfree.app import create_app                                # noqa: E402

BODY = {"connection_id": "acme-sgkb", "host_id": "SGKBHOST",
        "partner_id": "PARTNER1", "user_id": "USER1",
        "host_url": "https://ebics.example.test/h005"}


@pytest.fixture
def api(settings):
    app = create_app(settings)
    with TestClient(app, headers=dev_credentials()) as client:
        yield client


def test_a_connection_can_be_registered_without_a_browser(api):
    """The point of the route: six identifiers in, a registered subscriber out."""
    response = api.post("/v1/connections", json=BODY)

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["connection_id"] == "acme-sgkb"
    assert body["host_id"] == "SGKBHOST"
    assert body["key_state"] == ebics3.KeyState.CREATED.value
    assert body["initialised"] is False
    # No keys were minted, and none can be: that is the worker's, and this
    # process cannot open one.
    assert "private_key" not in response.text and "secret" not in response.text


def test_the_registration_is_the_one_the_list_returns(api):
    """Both bodies come from one function, so a reader sees the same shape."""
    created = api.post("/v1/connections", json=BODY).json()
    listed = [row for row in api.get("/v1/connections").json()["connections"]
              if row["connection_id"] == "acme-sgkb"]

    assert listed == [created]


def test_registering_the_same_id_twice_is_a_conflict(api):
    """A retry does not quietly produce a second subscriber at the same bank."""
    assert api.post("/v1/connections", json=BODY).status_code == 201
    again = api.post("/v1/connections", json=BODY)

    assert again.status_code == 409
    assert again.json()["error"]["code"] == "conflict"


def test_a_member_may_not_register_a_connection(api):
    """`connections:write` is carried by no grant level, only by `admin`."""
    response = api.post("/v1/connections", json=BODY,
                        headers=dev_credentials(subject="mallory", roles="member"))

    assert response.status_code == 403


def test_an_identifier_the_bank_would_refuse_is_refused_by_the_api(api):
    """Validated by the engine's own context rather than a second rule set."""
    response = api.post("/v1/connections",
                        json={**BODY, "host_id": "x" * 40})

    assert response.status_code == 422, response.text


def test_a_misspelled_field_is_refused_rather_than_dropped(api):
    """A silently ignored `partnerid` is a connection that fails at INI."""
    body = {**BODY}
    body["partnerid"] = body.pop("partner_id")
    response = api.post("/v1/connections", json=body)

    assert response.status_code == 422


def test_the_registration_is_in_the_audit_trail(api):
    """Who registered which bank, kept where every other decision is kept."""
    api.post("/v1/connections", json=BODY)
    rows = api.get("/v1/audit", params={"connection_id": "acme-sgkb"}).json()

    actions = [row["action"] for row in rows["events"]]
    assert "connection.registered" in actions
