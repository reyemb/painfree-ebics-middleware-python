"""Deployment-wide read-only oversight, and the backfill this revision does not do.

The table is additive and nothing else changes. What is worth reading is the
absence.

`0012` collapsed four role names to two and moved reach into per-connection
grants. It mapped the old `auditor` claim onto a `viewer` grant on every
connection and **flagged** every subject it did so for, because `auditor` had
held two things no grant level carries: the audit rows that name no connection,
and `webhooks:read`. There was nowhere else to put them.

This revision builds the place. It would therefore be one line to look those
flagged subjects up and issue each of them an oversight grant, closing the gap
`0012` opened -- and that line is not here.

**A migration must not widen access.** Reach comes from the claim in a token
until an administrator decides otherwise, and a deployment whose directory still
sends `auditor` -- which is every deployment that upgraded through `0012`, since
the identity provider is not migrated by a database migration -- would find that
everyone in that directory group could read every bank's payment history and
every sign-in in the deployment, on the morning this deployed, because a
revision decided it. `0012` measured that exact widening and refused it. The
argument has not changed just because the destination now exists.

What `0012` left instead is the right artefact: an `access.migrated` audit row
per affected subject, naming what was lost and saying that an administrator
decides. This revision gives that administrator something to decide *to*.
`painfree.identity.LEGACY_MEMBER_ROLE_NAMES` keeps `auditor` mapped to a plain
member for the same reason, and `tests/test_service_oversight.py` proves the
claim still grants nothing.

Revision ID: 0013_oversight_grants
Revises: 0012_connection_grants
Create Date: 2026-08-30
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from painfree.schema import Sequence64, UtcDateTime

revision = "0013_oversight_grants"
down_revision = "0012_connection_grants"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "oversight_grant",
        sa.Column("seq", Sequence64, primary_key=True, autoincrement=True),
        sa.Column("grant_id", sa.String(36), nullable=False, unique=True),
        # Unique: oversight is held or it is not, so `PUT` twice leaves one row
        # rather than a second one nobody revokes.
        sa.Column("subject", sa.String(255), nullable=False, unique=True),
        sa.Column("granted_by", sa.String(255), nullable=False),
        sa.Column("created_at", UtcDateTime, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("oversight_grant")
