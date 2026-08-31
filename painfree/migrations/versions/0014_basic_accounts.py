"""Local accounts for the deployments that have no identity provider.

Two tables and no backfill. The absence is again the part worth reading, and it
is a stronger absence than `0013`'s.

`0013` declined to *widen* access on upgrade. This revision declines to create
a way in at all. It would be one line to insert an `admin` account here so that
a fresh deployment is reachable — and that line is how every appliance that ever
shipped `admin`/`admin` shipped it. A default credential is not a convenience
with a caveat in the documentation; it is a published password, present on every
installation that has not yet been hardened, which is all of them on the first
day.

So the first administrator is created by a person, with a password they supply
or one this service generates and prints once:

    python -m painfree create-admin <subject>

A deployment that has migrated and not run it has an empty `basic_account` table
and refuses every credential offered to it, saying so in the log on every
attempt. That is the correct state for a service nobody has been given an
account on yet, and it is recoverable in one command by anybody with a shell on
the host — which is a smaller set of people than "everybody who has read the
documentation of this project".

Revision ID: 0014_basic_accounts
Revises: 0013_oversight_grants
Create Date: 2026-08-30
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from painfree.schema import Sequence64, UtcDateTime

revision = "0014_basic_accounts"
down_revision = "0013_oversight_grants"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "basic_account",
        sa.Column("seq", Sequence64, primary_key=True, autoincrement=True),
        # Unique: a second row with the same name would be a second person
        # holding the first one's grants, since a grant names a subject.
        sa.Column("subject", sa.String(255), nullable=False, unique=True),
        sa.Column("display_name", sa.String(255), nullable=True),
        # `admin` or `member`, the same two names a roles claim maps onto.
        sa.Column("role", sa.String(16), nullable=False),
        # Argon2id, encoded with its own salt and parameters. Never reversible,
        # and there is deliberately no column that could hold a plaintext one.
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("disabled_at", UtcDateTime, nullable=True),
        sa.Column("created_at", UtcDateTime, nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("updated_at", UtcDateTime, nullable=False),
        sa.Column("password_changed_at", UtcDateTime, nullable=False),
    )
    op.create_index("ix_basic_account_role", "basic_account", ["role"])

    op.create_table(
        "basic_lockout",
        sa.Column("seq", Sequence64, primary_key=True, autoincrement=True),
        # `subject` or `source`. An unknown account name is counted exactly as
        # a real one is, so that being locked out does not answer the question
        # the password check refuses to answer.
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("value", sa.String(255), nullable=False),
        sa.Column("failures", sa.Integer, nullable=False),
        sa.Column("first_failure_at", UtcDateTime, nullable=False),
        sa.Column("last_failure_at", UtcDateTime, nullable=False),
        sa.Column("locked_until", UtcDateTime, nullable=True),
        sa.UniqueConstraint("scope", "value", name="uq_basic_lockout_scope_value"),
    )
    op.create_index("ix_basic_lockout_locked_until", "basic_lockout",
                    ["locked_until"])


def downgrade() -> None:
    op.drop_index("ix_basic_lockout_locked_until", table_name="basic_lockout")
    op.drop_table("basic_lockout")
    op.drop_index("ix_basic_account_role", table_name="basic_account")
    op.drop_table("basic_account")
