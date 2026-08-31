"""The three columns a download schedule needs to be operated rather than seeded.

Additive, and nullable throughout: an existing schedule is correct with `NULL`
in all three.

`download_schedule.description` is what an operator calls one schedule on a list
of eight — `EOP/camt.053.08` says what it fetches and nothing about why.

`download_schedule.run_requested_by` and `download_run.requested_by` are one
fact in two places, because the two writes happen in two processes. A "run now"
or a window re-fetch is taken in the API process, which cannot download; it
records *who* asked on the schedule, and the worker's claim moves it onto the
run row it opens and clears it. Without that, an operator-driven re-fetch and an
ordinary cadence run are the same row in the ledger — and they mean opposite
things when the run reports duplicates.

Revision ID: 0011_schedule_management
Revises: 0010_webhook_management
Create Date: 2026-08-30
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0011_schedule_management"
down_revision = "0010_webhook_management"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("download_schedule",
                  sa.Column("description", sa.String(255), nullable=True))
    op.add_column("download_schedule",
                  sa.Column("run_requested_by", sa.String(255), nullable=True))
    op.add_column("download_run",
                  sa.Column("requested_by", sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column("download_run", "requested_by")
    op.drop_column("download_schedule", "run_requested_by")
    op.drop_column("download_schedule", "description")
