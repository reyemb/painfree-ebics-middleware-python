"""The queue the operator console asks the worker to act on.

The console runs in the API process, which cannot open a private key. Every
step of a key lifecycle needs one, so a click enqueues a row here and a worker
performs the operation. Additive: a deployment that never opens the console
never writes a row.

Revision ID: 0008_key_jobs
Revises: 0007_identity
Create Date: 2026-08-30
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from painfree.schema import JsonBlob, Sequence64, UtcDateTime

revision = "0008_key_jobs"
down_revision = "0007_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "key_job",
        sa.Column("seq", Sequence64, primary_key=True, autoincrement=True),
        sa.Column("job_id", sa.String(36), nullable=False, unique=True),
        sa.Column("connection_id", sa.String(64),
                  sa.ForeignKey("bank_connection.connection_id"), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("params", JsonBlob, nullable=False, server_default="{}"),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("requested_by_type", sa.String(32), nullable=False),
        sa.Column("requested_by_id", sa.String(255), nullable=False),
        sa.Column("worker_id", sa.String(64), nullable=True),
        sa.Column("claimed_at", UtcDateTime, nullable=True),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("result", JsonBlob, nullable=True),
        sa.Column("return_code", sa.String(16), nullable=True),
        sa.Column("report_text", sa.String(1024), nullable=True),
        sa.Column("last_error", sa.String(512), nullable=True),
        sa.Column("created_at", UtcDateTime, nullable=False),
        sa.Column("updated_at", UtcDateTime, nullable=False),
        sa.Column("finished_at", UtcDateTime, nullable=True),
    )
    op.create_index("ix_key_job_connection_id", "key_job", ["connection_id"])
    op.create_index("ix_key_job_state", "key_job", ["state"])


def downgrade() -> None:
    op.drop_index("ix_key_job_state", table_name="key_job")
    op.drop_index("ix_key_job_connection_id", table_name="key_job")
    op.drop_table("key_job")
