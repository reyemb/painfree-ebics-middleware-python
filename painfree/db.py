"""Engine construction and migrations, for SQLite and PostgreSQL alike.

Everything above this module writes one query and one schema
(:mod:`painfree.schema`). Everything below is the part where the two backends
are not the same, kept in one file so it can be reviewed as a whole:

* **Connection setup.** SQLite gets ``foreign_keys=ON`` (off by default, so a
  foreign key added later would be decorative), WAL (so a reader does not block
  the writer) and a busy timeout (so the second writer waits instead of raising
  ``database is locked``). PostgreSQL gets pool pre-ping, so a connection the
  database closed overnight fails on checkout rather than mid-transaction.
* **Migrations.** One Alembic history runs on both. On PostgreSQL the runner
  takes a session-level advisory lock first, so several replicas starting at
  once do not race; SQLite has no such thing and needs none, because its whole
  file takes one write lock anyway.
* **RETURNING.** Both backends support it (SQLite since 3.35), and SQLAlchemy
  emits it where it helps. Nothing here depends on it; the note is here so that
  nothing later assumes it is unavailable.
"""

from __future__ import annotations

import contextlib
import sqlite3
from typing import Any, Iterator

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.engine import Connection, make_url
from sqlalchemy.pool import StaticPool

from painfree.config import Settings
from painfree.logging import get_logger

log = get_logger("painfree.db")

MIGRATIONS_PATH = str((__import__("pathlib").Path(__file__).parent / "migrations").resolve())

#: Arbitrary but fixed: the key PostgreSQL advisory locking uses for migrations.
MIGRATION_LOCK_KEY = 0x7061_696E  # "pain"

SQLITE_BUSY_TIMEOUT_MS = 5000


def build_engine(settings: Settings) -> Engine:
    """Create the engine for the configured URL, with per-dialect setup applied."""
    url = make_url(settings.database_url)
    backend = url.get_backend_name()
    kwargs: dict[str, Any] = {"future": True, "echo": False}

    if backend == "sqlite":
        # A file database is reached from FastAPI's thread pool, so the
        # per-connection thread check has to go; an in-memory one additionally
        # needs a single shared connection or each checkout gets its own empty
        # database and the migrations vanish.
        kwargs["connect_args"] = {"check_same_thread": False}
        if url.database in (None, "", ":memory:"):
            kwargs["poolclass"] = StaticPool
    else:
        kwargs["pool_pre_ping"] = True

    engine = create_engine(url, **kwargs)
    if backend == "sqlite":
        event.listen(engine, "connect", _configure_sqlite_connection)
    return engine


def _configure_sqlite_connection(dbapi_connection: Any, _record: Any) -> None:
    if not isinstance(dbapi_connection, sqlite3.Connection):  # pragma: no cover
        return
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
        cursor.execute("PRAGMA journal_mode=WAL")
    finally:
        cursor.close()


def alembic_config(connection: Connection | None = None) -> Config:
    """Alembic configured in code, not from an ``alembic.ini`` on disk.

    The URL is never read from a file: a migration must run against the same
    database the process resolved, or the two can disagree.
    """
    config = Config()
    config.set_main_option("script_location", MIGRATIONS_PATH)
    if connection is not None:
        config.attributes["connection"] = connection
    return config


@contextlib.contextmanager
def _migration_lock(connection: Connection) -> Iterator[None]:
    if connection.dialect.name != "postgresql":
        yield
        return
    connection.exec_driver_sql(f"SELECT pg_advisory_lock({MIGRATION_LOCK_KEY})")
    try:
        yield
    finally:
        connection.exec_driver_sql(f"SELECT pg_advisory_unlock({MIGRATION_LOCK_KEY})")


def current_revision(engine: Engine) -> str | None:
    """The revision the database is at, or ``None`` if it has never migrated."""
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def head_revision() -> str:
    """The revision the code expects."""
    script = ScriptDirectory.from_config(alembic_config())
    head = script.get_current_head()
    if head is None:  # pragma: no cover - only if the versions directory is empty
        raise RuntimeError("no Alembic revisions found")
    return head


def migrate(engine: Engine) -> str:
    """Bring the database to head and return the revision it is now at.

    Logged either way: an operator should be able to see from the stream alone
    whether a container start migrated anything.
    """
    before = current_revision(engine)
    with engine.begin() as connection:
        with _migration_lock(connection):
            command.upgrade(alembic_config(connection), "head")
    after = current_revision(engine)
    log.info(
        "database.migrated",
        dialect=engine.dialect.name,
        revision_before=before,
        revision_after=after,
        applied=before != after,
    )
    return after or ""


def check_ready(engine: Engine) -> dict[str, Any]:
    """Answer whether the database is usable, without raising.

    Readiness is two questions, not one: the database has to answer, *and* the
    schema has to be the one this code was written against. A process serving
    traffic against a schema older than its queries is not ready, it is broken
    in a way that shows up as a 500 per request instead of a red probe.
    """
    result: dict[str, Any] = {"dialect": engine.dialect.name}
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            revision = MigrationContext.configure(connection).get_current_revision()
    except Exception as exc:
        # `exception` and its trace are added by the formatter.
        log.exception("database.unreachable")
        result.update(ready=False, reason="unreachable", error=type(exc).__name__)
        return result

    head = head_revision()
    result.update(revision=revision, head=head)
    if revision != head:
        log.warning("database.schema_stale", revision=revision, head=head)
        result.update(ready=False, reason="schema_out_of_date")
        return result
    result["ready"] = True
    return result
