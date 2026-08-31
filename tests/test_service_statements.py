"""Ingesting downloaded documents once, and only once.

The re-ingestion tests are the point of the file. Banks re-serve, and the
guarantee that a re-served statement does not become a second row has to be a
**database constraint** rather than a check some path can skip -- so it is
asserted at that level, on PostgreSQL as well as on SQLite, and the concurrent
case is run with eight threads racing on one document.

The PostgreSQL run is opt-in through ``POSTGRES_TEST_URL``. Skips are not
passes, and the skip reason says what was not proved.
"""

from __future__ import annotations

import concurrent.futures
import decimal
import os

import pytest
from sqlalchemy import inspect, select

from painfree import db
from painfree.audit import AuditLog
from painfree.config import load_settings
from painfree.connections import ConnectionRegistry
from painfree.isoxml import DocumentUnreadable
from painfree.schema import audit_log, statement
from painfree.statements import StatementStore, document_key, normalise, unpack
from conftest import (BANK_CONNECTION_ID, MESSAGE_TYPES, fixture_bytes,
                            zipped)

POSTGRES_URL = os.environ.get("POSTGRES_TEST_URL")
needs_postgres = pytest.mark.skipif(
    POSTGRES_URL is None,
    reason="POSTGRES_TEST_URL is not set: no PostgreSQL server was reached, so "
           "the ingestion constraint was not proved on the production backend")


@pytest.fixture
def store(sqlite_url):
    engine = db.build_engine(load_settings(database_url=sqlite_url))
    db.migrate(engine)
    _register(engine)
    yield engine, StatementStore(engine)
    engine.dispose()


def _register(engine):
    ConnectionRegistry(engine, AuditLog(engine)).register(
        BANK_CONNECTION_ID, host_id="TESTHOST", partner_id="PARTNER1",
        user_id="USER1", host_url="http://127.0.0.1:1/ebics")


# --- unpacking --------------------------------------------------------------


def test_a_bare_xml_document_is_one_document():
    data = fixture_bytes("camt.053.001.08")
    assert unpack(data) == [data]


def test_a_zip_container_is_unpacked_into_its_members():
    """`Container containerType="ZIP"` is how a bank sends a week of statements.

    Sniffed from the bytes rather than taken from the BTF, so a bank that
    declares a container and sends a bare document is still read.
    """
    documents = unpack(zipped(*MESSAGE_TYPES))
    assert len(documents) == len(MESSAGE_TYPES)
    assert {normalise(d)[0].message_type for d in documents} == set(MESSAGE_TYPES)


def test_something_that_claims_to_be_a_zip_and_is_not_is_refused():
    with pytest.raises(DocumentUnreadable):
        unpack(b"PK\x03\x04 and then nothing that follows the format")


# --- ingestion --------------------------------------------------------------


def test_one_download_of_four_documents_stores_four_statements(store):
    engine, statements = store
    result = statements.ingest(BANK_CONNECTION_ID, unpack(zipped(*MESSAGE_TYPES)),
                               run_id="run_test")

    # `camt.054` carries two notifications, so four documents are five rows.
    assert result.stored == 5
    assert result.duplicates == 0
    assert statements.count(BANK_CONNECTION_ID) == 5


def test_ingesting_the_same_statement_twice_stores_it_once(store):
    """The guarantee, at its simplest. A bank re-serves; this is a no-op."""
    engine, statements = store
    document = fixture_bytes("camt.053.001.08")

    first = statements.ingest(BANK_CONNECTION_ID, [document], run_id="run_a")
    second = statements.ingest(BANK_CONNECTION_ID, [document], run_id="run_b")

    assert first.stored == 1 and first.duplicates == 0
    assert second.stored == 0 and second.duplicates == 1
    with engine.connect() as connection:
        rows = connection.execute(select(statement)).mappings().all()
    assert len(rows) == 1
    assert rows[0]["run_id"] == "run_a"


def test_the_identity_is_the_statement_and_not_the_bytes(store):
    """A re-serve with a new `CreDtTm` is the same statement.

    This is why the key is the document's identification rather than a hash of
    its bytes: a bank that regenerates the file changes the timestamp, and a
    content hash would let the same statement in twice.
    """
    engine, statements = store
    document = fixture_bytes("camt.053.001.08")
    amended = document.replace(b"<CreDtTm>2026-08-29T02:15:00+02:00</CreDtTm>",
                               b"<CreDtTm>2026-08-29T06:00:00+02:00</CreDtTm>")
    assert amended != document

    statements.ingest(BANK_CONNECTION_ID, [document])
    result = statements.ingest(BANK_CONNECTION_ID, [amended])

    assert result.duplicates == 1
    assert statements.count(BANK_CONNECTION_ID) == 1


def test_the_same_document_on_two_connections_is_two_statements(store):
    """Identity is per connection. Two subscribers may hold the same account."""
    engine, statements = store
    ConnectionRegistry(engine, AuditLog(engine)).register(
        "second-bank", host_id="TESTHOST", partner_id="PARTNER2",
        user_id="USER2", host_url="http://127.0.0.1:1/ebics")
    document = fixture_bytes("camt.053.001.08")

    statements.ingest(BANK_CONNECTION_ID, [document])
    statements.ingest("second-bank", [document])

    assert statements.count(BANK_CONNECTION_ID) == 1
    assert statements.count("second-bank") == 1


def test_a_document_with_no_identification_falls_back_to_its_content(store):
    engine, statements = store
    document = fixture_bytes("camt.053.001.08").replace(
        b"<Id>STMT-2026-0242</Id>", b"<Id></Id>")

    assert statements.ingest(BANK_CONNECTION_ID, [document]).stored == 1
    assert statements.ingest(BANK_CONNECTION_ID, [document]).duplicates == 1
    key = document_key(BANK_CONNECTION_ID,
                       normalise(document)[0], "content-hash")
    assert key == document_key(BANK_CONNECTION_ID, normalise(document)[0],
                               "content-hash")


def test_an_unreadable_member_does_not_lose_the_readable_ones(store, caplog):
    engine, statements = store
    result = statements.ingest(
        BANK_CONNECTION_ID,
        [b"not xml", fixture_bytes("camt.053.001.08")], run_id="run_mixed")

    assert result.stored == 1
    assert result.unreadable == 1
    assert result.statements == 2


# --- money at the database level --------------------------------------------


def test_an_eighteen_digit_balance_survives_the_round_trip_through_the_column(store):
    """The `Money` column, proved where a float would have lost.

    `9007199254740990.06` is beyond what a double holds. If the column stored a
    binary float -- which is what SQLAlchemy's ``Numeric`` does on SQLite -- the
    value that came back would not be this one.
    """
    engine, statements = store
    result = statements.ingest(BANK_CONNECTION_ID,
                               [fixture_bytes("camt.052.001.08")])
    stored = statements.get(result.statement_ids[0])

    assert stored["closing_balance"] == decimal.Decimal("9007199254740990.06")
    assert isinstance(stored["closing_balance"], decimal.Decimal)
    assert str(stored["closing_balance"]) == "9007199254740990.06"
    assert float(stored["closing_balance"]) != stored["closing_balance"]


def test_the_money_column_refuses_a_float_rather_than_rounding_it(store):
    """A float that reaches the column has already lost its digits.

    Converting it would store a wrong number quietly; refusing it puts the
    defect where it happened.
    """
    engine, _ = store
    from painfree.schema import Money

    with pytest.raises(TypeError):
        Money().bind_processor(engine.dialect)(0.1)


# --- the event a webhook dispatcher will consume ----------------------------


def test_ingestion_records_a_statement_available_event_by_reference(store):
    """The event the webhook layer will deliver, and nothing of the payment in
    it.

    An entry is somebody's payment: a counterparty, an amount, a reference.
    None of that may reach the audit trail, which is read by more people than
    the database is.
    """
    engine, statements = store
    result = statements.ingest(BANK_CONNECTION_ID,
                               [fixture_bytes("camt.053.001.08")],
                               run_id="run_evt")
    with engine.connect() as connection:
        rows = [dict(r) for r in connection.execute(
            select(audit_log).where(
                audit_log.c.action == "statement.available")).mappings()]

    assert len(rows) == 1
    detail = rows[0]["detail"]
    assert detail["statement_id"] == result.statement_ids[0]
    assert detail["message_type"] == "camt.053.001.08"
    assert detail["entries"] == 3
    assert rows[0]["connection_id"] == BANK_CONNECTION_ID

    blob = repr(rows[0])
    for secret in ("Robert Schneider", "3949.75", "CH4431999123000889012",
                   "210000000003139471430009017"):
        assert secret not in blob


def test_no_statement_content_reaches_the_log_stream(store, caplog):
    """The same rule, for `docker logs` rather than for the audit table."""
    import logging

    engine, statements = store
    with caplog.at_level(logging.DEBUG, logger="painfree"):
        statements.ingest(BANK_CONNECTION_ID,
                          [fixture_bytes("camt.053.001.08")], run_id="run_log")

    text = "\n".join(f"{r.getMessage()} {getattr(r, 'painfree_fields', '')}"
                     for r in caplog.records)
    assert "statement.ingested" in text
    for secret in ("Robert Schneider", "3949.75", "CH4431999123000889012",
                   "Bernasconi"):
        assert secret not in text


# --- the constraint, on both backends ---------------------------------------


def test_the_ingestion_constraint_exists_on_sqlite(store):
    engine, _ = store
    _assert_constraint(engine)


@needs_postgres
def test_the_ingestion_constraint_exists_on_postgres():
    engine = db.build_engine(load_settings(database_url=POSTGRES_URL))
    try:
        db.migrate(engine)
        _assert_constraint(engine)
    finally:
        engine.dispose()


def _assert_constraint(engine):
    """It is a unique constraint, not a convention, and it names both columns."""
    inspector = inspect(engine)
    constraints = inspector.get_unique_constraints("statement")
    match = [c for c in constraints
             if c["name"] == "uq_statement_connection_id_document_key"]
    assert match, constraints
    assert match[0]["column_names"] == ["connection_id", "document_key"]


@needs_postgres
def test_concurrent_ingestion_of_one_statement_creates_exactly_one_row():
    """Eight threads, one re-served statement, one row.

    The case a ``SELECT`` in front of an ``INSERT`` fails: every thread reads
    "not there" and every thread inserts. Only the constraint decides.
    """
    from painfree.schema import bank_connection

    engine = db.build_engine(load_settings(database_url=POSTGRES_URL))
    # A connection id of its own, so this test neither sees nor disturbs what
    # the other PostgreSQL tests leave in the shared database.
    connection_id = "ingest-race"
    try:
        db.migrate(engine)
        with engine.begin() as connection:
            connection.execute(bank_connection.delete().where(
                bank_connection.c.connection_id == connection_id))
        ConnectionRegistry(engine, AuditLog(engine)).register(
            connection_id, host_id="TESTHOST", partner_id="PARTNER9",
            user_id="USER9", host_url="http://127.0.0.1:1/ebics")
        store = StatementStore(engine)
        document = fixture_bytes("camt.053.001.08")

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = [f.result() for f in [
                pool.submit(store.ingest, connection_id, [document])
                for _ in range(8)]]

        assert sum(r.stored for r in results) == 1
        assert sum(r.duplicates for r in results) == 7
        assert store.count(connection_id) == 1
    finally:
        engine.dispose()
