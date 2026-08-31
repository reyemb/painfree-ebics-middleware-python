"""The three tables scheduled downloads need.

`download_schedule` is the cadence and the claim, `download_run` is the ledger
of what was asked for and how it ended, and `statement` is one normalised
document with the unique constraint that makes re-ingesting a re-served
statement a no-op rather than a second row.

Nothing existing is touched. The three tables are additive, so a deployment
that never registers a schedule is unaffected by this revision.

Revision ID: 0005_downloads
Revises: 0004_upload_claim
Create Date: 2026-08-29
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from painfree.schema import JsonBlob, Money, Sequence64, UtcDateTime

revision = "0005_downloads"
down_revision = "0004_upload_claim"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "download_schedule",
        sa.Column("seq", Sequence64, primary_key=True, autoincrement=True),
        sa.Column("schedule_id", sa.String(36), nullable=False, unique=True),
        sa.Column("connection_id", sa.String(64),
                  sa.ForeignKey("bank_connection.connection_id",
                                ondelete="CASCADE"), nullable=False),
        sa.Column("service_name", sa.String(3), nullable=False),
        sa.Column("scope", sa.String(3), nullable=True),
        sa.Column("service_option", sa.String(10), nullable=True),
        sa.Column("container", sa.String(3), nullable=True),
        sa.Column("msg_name", sa.String(10), nullable=False),
        sa.Column("msg_variant", sa.String(3), nullable=True),
        sa.Column("msg_version", sa.String(3), nullable=True),
        sa.Column("cadence_seconds", sa.Integer, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="1"),
        sa.Column("window_days", sa.Integer, nullable=True),
        sa.Column("fetched_through", sa.String(10), nullable=True),
        sa.Column("due_at", UtcDateTime, nullable=False),
        sa.Column("worker_id", sa.String(64), nullable=True),
        sa.Column("claimed_at", UtcDateTime, nullable=True),
        sa.Column("last_run_at", UtcDateTime, nullable=True),
        sa.Column("last_return_code", sa.String(16), nullable=True),
        sa.Column("last_error", sa.String(512), nullable=True),
        sa.Column("created_at", UtcDateTime, nullable=False),
        sa.Column("updated_at", UtcDateTime, nullable=False),
        sa.UniqueConstraint("connection_id", "service_name", "msg_name",
                            "msg_version", name="uq_download_schedule_btf"),
    )
    op.create_index("ix_download_schedule_enabled_due_at", "download_schedule",
                    ["enabled", "due_at"])

    op.create_table(
        "download_run",
        sa.Column("seq", Sequence64, primary_key=True, autoincrement=True),
        sa.Column("run_id", sa.String(36), nullable=False, unique=True),
        sa.Column("schedule_id", sa.String(36),
                  sa.ForeignKey("download_schedule.schedule_id",
                                ondelete="CASCADE"), nullable=False),
        sa.Column("connection_id", sa.String(64), nullable=False),
        sa.Column("worker_id", sa.String(64), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("window_start", sa.String(10), nullable=True),
        sa.Column("window_end", sa.String(10), nullable=True),
        sa.Column("transaction_id", sa.String(64), nullable=True),
        sa.Column("bank_order_id", sa.String(16), nullable=True),
        sa.Column("return_code", sa.String(16), nullable=True),
        sa.Column("report_text", sa.String(1024), nullable=True),
        sa.Column("acknowledged", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("segments", sa.Integer, nullable=False, server_default="0"),
        sa.Column("bytes", sa.Integer, nullable=False, server_default="0"),
        sa.Column("documents", sa.Integer, nullable=False, server_default="0"),
        sa.Column("statements", sa.Integer, nullable=False, server_default="0"),
        sa.Column("duplicates", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_error", sa.String(512), nullable=True),
        sa.Column("started_at", UtcDateTime, nullable=False),
        sa.Column("finished_at", UtcDateTime, nullable=True),
    )
    op.create_index("ix_download_run_schedule_id_seq", "download_run",
                    ["schedule_id", "seq"])

    op.create_table(
        "statement",
        sa.Column("seq", Sequence64, primary_key=True, autoincrement=True),
        sa.Column("statement_id", sa.String(36), nullable=False, unique=True),
        sa.Column("connection_id", sa.String(64),
                  sa.ForeignKey("bank_connection.connection_id",
                                ondelete="CASCADE"), nullable=False),
        sa.Column("run_id", sa.String(36), nullable=True),
        sa.Column("message_type", sa.String(32), nullable=False),
        sa.Column("document_key", sa.String(64), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("identification", sa.String(64), nullable=True),
        sa.Column("sequence_number", sa.String(16), nullable=True),
        sa.Column("iban", sa.String(34), nullable=True),
        sa.Column("currency", sa.String(3), nullable=True),
        sa.Column("entry_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_at", UtcDateTime, nullable=True),
        sa.Column("from_datetime", UtcDateTime, nullable=True),
        sa.Column("to_datetime", UtcDateTime, nullable=True),
        sa.Column("opening_balance", Money, nullable=True),
        sa.Column("closing_balance", Money, nullable=True),
        sa.Column("payload", JsonBlob, nullable=False),
        sa.Column("ingested_at", UtcDateTime, nullable=False),
        # The whole idempotency story for ingestion, and it is a constraint
        # rather than a check so two workers racing on one re-served statement
        # cannot both win.
        sa.UniqueConstraint("connection_id", "document_key",
                            name="uq_statement_connection_id_document_key"),
    )
    op.create_index("ix_statement_connection_id_message_type", "statement",
                    ["connection_id", "message_type"])
    op.create_index("ix_statement_run_id", "statement", ["run_id"])


def downgrade() -> None:
    op.drop_index("ix_statement_run_id", table_name="statement")
    op.drop_index("ix_statement_connection_id_message_type", table_name="statement")
    op.drop_table("statement")
    op.drop_index("ix_download_run_schedule_id_seq", table_name="download_run")
    op.drop_table("download_run")
    op.drop_index("ix_download_schedule_enabled_due_at",
                  table_name="download_schedule")
    op.drop_table("download_schedule")
