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
