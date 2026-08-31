"""Alembic environment.

Configured entirely from :mod:`painfree.db`, which passes a live connection in
``config.attributes``. There is no ``alembic.ini`` and no URL in this file on
purpose: a migration runs against the database the process resolved, or the two
can disagree about which database was upgraded.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import engine_from_config, pool

from painfree.schema import metadata

target_metadata = metadata


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of running it (``alembic upgrade --sql``)."""
    context.configure(
        url=context.config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # SQLite cannot ALTER most things; batch mode rewrites the table.
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = context.config.attributes.get("connection")
    if connection is None:
        # Only reached by a bare `alembic` invocation, which this repo does not
        # use; fail loudly rather than inventing a URL.
        configuration = context.config.get_section(context.config.config_ini_section) or {}
        if not configuration.get("sqlalchemy.url"):
            raise RuntimeError(
                "no connection supplied; run migrations through painfree.db.migrate"
            )
        engine = engine_from_config(configuration, prefix="sqlalchemy.", poolclass=pool.NullPool)
        with engine.connect() as own_connection:
            _run(own_connection)
        return
    _run(connection)


def _run(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=connection.dialect.name == "sqlite",
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
