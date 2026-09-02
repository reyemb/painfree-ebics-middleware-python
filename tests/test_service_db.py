"""Schema and migrations: the same history on SQLite and PostgreSQL.

Development runs on SQLite with nothing installed, production on PostgreSQL. The
tests that matter here are the ones that would otherwise only fail in
production: the places where the two backends are not the same.

The PostgreSQL run is opt-in through ``POSTGRES_TEST_URL`` (deliberately not a
``PAINFREE_`` name -- the configuration loader refuses unknown variables in that
namespace). Without it those tests **skip, and a skip is not a pass**.
"""

from __future__ import annotations

import datetime as _dt
import os

import pytest
from sqlalchemy import create_engine, exc, inspect, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.schema import CreateTable

from conftest import reset_database

from painfree import db
from painfree.config import load_settings
from painfree.schema import audit_log, bank_connection, key_material, metadata

#: Every table the schema declares. Named here so that anything adding one has
#: to say so in this file too.
TABLES = {"audit_log", "bank_connection", "key_material", "payment_order",
          "payment_attempt",
          "download_schedule", "download_run", "statement",
          "webhook_subscription", "webhook_delivery", "webhook_wrapping_key",
          "oidc_login", "user_session", "key_job", "connection_grant",
          "oversight_grant", "basic_account", "basic_lockout",
          "custody_acknowledgement", "bank_catalogue"}

POSTGRES_URL = os.environ.get("POSTGRES_TEST_URL")
requires_postgres = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="POSTGRES_TEST_URL is not set: no PostgreSQL server was reached, so "
           "the PostgreSQL half of the migration gate did not run",
)


@pytest.fixture
def engine(settings):
    engine = db.build_engine(settings)
    yield engine
    engine.dispose()


@pytest.fixture
def postgres_engine():
    """A throwaway schema-per-test would be nicer; dropping the tables is enough."""
    engine = create_engine(POSTGRES_URL, future=True, pool_pre_ping=True)
    _drop_everything(engine)
    yield engine
    _drop_everything(engine)
    engine.dispose()


def _drop_everything(engine) -> None:
    reset_database(engine)


# --- the schema the two dialects actually get -------------------------------

def test_the_sequence_column_is_INTEGER_on_sqlite_and_BIGSERIAL_on_postgres():
    """SQLite only auto-assigns a rowid alias for `INTEGER PRIMARY KEY`.

    Declared as `BIGINT PRIMARY KEY` the column is ordinary and stays NULL --
    which works in every Postgres test and fails on the developer's laptop, or
    the other way round. Pinned in both directions.
    """
    on_sqlite = str(CreateTable(audit_log).compile(dialect=sqlite.dialect()))
    on_postgres = str(CreateTable(audit_log).compile(dialect=postgresql.dialect()))
    assert "seq INTEGER NOT NULL" in on_sqlite
    assert "seq BIGSERIAL NOT NULL" in on_postgres


def test_binary_columns_are_blob_on_sqlite_and_bytea_on_postgres():
    """Sealed key material is bytes, and the two dialects spell that differently."""
    on_sqlite = str(CreateTable(key_material).compile(dialect=sqlite.dialect()))
    on_postgres = str(CreateTable(key_material).compile(dialect=postgresql.dialect()))
    assert "sealed_private BLOB" in on_sqlite
    assert "sealed_private BYTEA" in on_postgres


def test_the_keyring_is_keyed_by_connection_holder_version_and_generation():
    """Renewal mints a generation; without the constraint it would overwrite."""
    on_postgres = str(CreateTable(key_material).compile(dialect=postgresql.dialect()))
    assert ("UNIQUE (connection_id, holder, version, generation)" in on_postgres)


def test_json_is_jsonb_where_jsonb_exists():
    on_sqlite = str(CreateTable(audit_log).compile(dialect=sqlite.dialect()))
    on_postgres = str(CreateTable(audit_log).compile(dialect=postgresql.dialect()))
    assert "detail JSON" in on_sqlite
    assert "detail JSONB" in on_postgres


def test_timestamps_are_declared_with_a_time_zone_where_that_means_something():
    on_postgres = str(CreateTable(audit_log).compile(dialect=postgresql.dialect()))
    assert "occurred_at TIMESTAMP WITH TIME ZONE" in on_postgres


# --- migrations, from empty -------------------------------------------------

def test_migrations_apply_from_empty_on_sqlite(engine):
    assert db.current_revision(engine) is None
    revision = db.migrate(engine)
    assert revision == db.head_revision()
    assert set(inspect(engine).get_table_names()) >= TABLES | {"alembic_version"}


def test_migrating_twice_is_a_no_op(engine):
    db.migrate(engine)
    assert db.migrate(engine) == db.head_revision()


def test_the_migration_and_the_model_agree_on_sqlite(engine):
    """The revision writes the columns; `schema.py` describes them. They drift."""
    db.migrate(engine)
    _assert_every_table_matches_the_model(engine)


def test_a_migrated_database_is_ready(engine):
    db.migrate(engine)
    assert db.check_ready(engine) == {
        "dialect": "sqlite", "revision": db.head_revision(),
        "head": db.head_revision(), "ready": True,
    }


def test_an_unmigrated_database_is_not_ready(engine):
    """A process serving traffic against a schema older than its queries is broken."""
    result = db.check_ready(engine)
    assert result["ready"] is False
    assert result["reason"] == "schema_out_of_date"


def test_an_unreachable_database_is_not_ready(tmp_path):
    settings = load_settings(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'missing' / 'x.db'}"
    )
    engine = db.build_engine(settings)
    result = db.check_ready(engine)
    assert result["ready"] is False
    assert result["reason"] == "unreachable"


# --- the timestamp round trip, which is where the backends differ ------------

def test_an_aware_utc_datetime_survives_the_round_trip_on_sqlite(engine):
    db.migrate(engine)
    _assert_timestamp_round_trip(engine)


def test_a_naive_datetime_is_refused_rather_than_stored_ambiguously(engine):
    db.migrate(engine)
    # SQLAlchemy wraps a bind-parameter failure, so the type here is its own.
    with pytest.raises(exc.StatementError, match="naive"):
        with engine.begin() as connection:
            connection.execute(audit_log.insert().values(
                event_id="e", occurred_at=_dt.datetime(2026, 1, 1),
                actor_type="system", actor_id="system",
                action="a", outcome="success", detail={},
            ))


def _assert_timestamp_round_trip(engine) -> None:
    when = _dt.datetime(2026, 8, 29, 10, 4, 11, tzinfo=_dt.timezone.utc)
    with engine.begin() as connection:
        connection.execute(audit_log.insert().values(
            event_id="e-1", occurred_at=when, actor_type="system",
            actor_id="system", action="test", outcome="success",
            detail={"nested": {"n": 1}},
        ))
    with engine.connect() as connection:
        row = connection.execute(select(audit_log)).mappings().one()
    assert row["occurred_at"] == when
    assert row["occurred_at"].tzinfo is not None
    assert row["detail"] == {"nested": {"n": 1}}
    assert row["seq"] is not None, "the sequence column did not auto-assign"


# --- the same history on PostgreSQL -----------------------------------------

@requires_postgres
def test_migrations_apply_from_empty_on_postgres(postgres_engine):
    assert db.current_revision(postgres_engine) is None
    assert db.migrate(postgres_engine) == db.head_revision()
    assert db.check_ready(postgres_engine)["ready"] is True
    assert set(inspect(postgres_engine).get_table_names()) >= TABLES
    _assert_every_table_matches_the_model(postgres_engine)


@requires_postgres
def test_sealed_key_material_round_trips_on_postgres(postgres_engine):
    """`BYTEA` and `BLOB` are the same bytes, or the keyring only works locally."""
    db.migrate(postgres_engine)
    _assert_sealed_bytes_round_trip(postgres_engine)


@requires_postgres
def test_migrating_twice_is_a_no_op_on_postgres(postgres_engine):
    db.migrate(postgres_engine)
    assert db.migrate(postgres_engine) == db.head_revision()


@requires_postgres
def test_an_aware_utc_datetime_survives_the_round_trip_on_postgres(postgres_engine):
    db.migrate(postgres_engine)
    _assert_timestamp_round_trip(postgres_engine)


@requires_postgres
def test_the_migration_takes_an_advisory_lock_on_postgres(postgres_engine):
    """Several replicas starting at once must not race the same DDL."""
    from sqlalchemy import text
    db.migrate(postgres_engine)
    with postgres_engine.connect() as connection:
        held = connection.execute(
            text("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'")
        ).scalar()
    assert held == 0, "the migration lock was not released"


@requires_postgres
def test_downgrade_returns_a_postgres_database_to_empty(postgres_engine):
    from alembic import command
    db.migrate(postgres_engine)
    with postgres_engine.begin() as connection:
        command.downgrade(db.alembic_config(connection), "base")
    assert "audit_log" not in inspect(postgres_engine).get_table_names()


def test_sealed_key_material_round_trips_on_sqlite(engine):
    db.migrate(engine)
    _assert_sealed_bytes_round_trip(engine)


def _assert_sealed_bytes_round_trip(engine) -> None:
    """Arbitrary bytes, including a NUL and a high byte -- an envelope has both."""
    blob = bytes(range(256))
    when = _dt.datetime(2026, 8, 29, 10, 4, 11, tzinfo=_dt.timezone.utc)
    with engine.begin() as connection:
        connection.execute(bank_connection.insert().values(
            connection_id="c-1", host_id="H", partner_id="P", user_id="U",
            host_url="https://example", ebics_version="H005",
            key_state="created", ini_sent=False, hia_sent=False,
            letter_digest="public_key", created_at=when, updated_at=when))
        connection.execute(key_material.insert().values(
            connection_id="c-1", holder="subscriber", version="X002",
            generation=1, status="active", fingerprint="f" * 64,
            public_pem=b"-----BEGIN RSA PUBLIC KEY-----",
            sealed_private=blob, custody_key_id="0123456789abcdef",
            created_at=when, updated_at=when))
    with engine.connect() as connection:
        row = connection.execute(select(key_material)).mappings().one()
        registered = connection.execute(select(bank_connection)).mappings().one()
    assert bytes(row["sealed_private"]) == blob
    # SQLite has no boolean type and stores 0/1; the model has to hand back the
    # same answer on both, or a resume reads `0` as truthy.
    assert bool(registered["ini_sent"]) is False


def _assert_every_table_matches_the_model(engine) -> None:
    """The revisions write the columns; `schema.py` describes them. They drift."""
    inspector = inspect(engine)
    for table in (audit_log, bank_connection, key_material):
        columns = {c["name"] for c in inspector.get_columns(table.name)}
        assert columns == {column.name for column in table.columns}, table.name


def test_metadata_holds_only_what_these_slices_need():
    """Speculative tables for later work are a promise the schema has to keep."""
    assert set(metadata.tables) == TABLES
