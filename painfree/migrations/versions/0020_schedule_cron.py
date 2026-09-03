"""A cron expression on a download schedule, for the runs an interval cannot say.

One nullable column, and nothing changes for a schedule that does not use it:
`NULL` means the cadence decides, which is what every existing row means and
what it went on meaning after this ran.

`cadence_seconds` stays non-null beside it, deliberately. A cron says when a run
starts and says nothing about how soon a *failed* one is retried, and the retry
is capped by the cadence so one broken connection cannot become the busiest
thing in the deployment. Dropping it would have meant inventing a retry rule.

Revision ID: 0020_schedule_cron
Revises: 0019_request_eds
Create Date: 2026-09-03
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0020_schedule_cron"
down_revision = "0019_request_eds"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("download_schedule",
                  sa.Column("cron", sa.String(120), nullable=True))


def downgrade() -> None:
    op.drop_column("download_schedule", "cron")
