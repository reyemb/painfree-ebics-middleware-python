"""Link a `pain.002` to the order it reports on, and record what it said.

Five nullable columns and one index. `statement.order_id` is the join --
`OrgnlMsgId` resolved to a `payment_order` at ingestion time -- and the four
columns on `payment_order` are the bank's own status vocabulary, kept apart
from the EBICS return code that already lives there.

Additive and nullable throughout: every existing row is correct with NULL in
all five, which is what it means for an order nobody has had a status report
about yet.

Revision ID: 0009_status_reports
Revises: 0008_key_jobs
Create Date: 2026-08-30
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from painfree.schema import UtcDateTime

revision = "0009_status_reports"
down_revision = "0008_key_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("payment_order",
                  sa.Column("bank_status", sa.String(8), nullable=True))
    op.add_column("payment_order",
                  sa.Column("status_reason_code", sa.String(35), nullable=True))
    op.add_column("payment_order",
                  sa.Column("status_reason_text", sa.String(1024), nullable=True))
    op.add_column("payment_order",
                  sa.Column("status_reported_at", UtcDateTime, nullable=True))
    # The foreign key is declared in the model and created here only where the
    # backend can add one to a populated table. SQLite cannot ALTER a table to
    # add a constraint at all -- batch mode would rewrite `statement` and every
    # row in it to gain a check the application already enforces -- so on SQLite
    # the column carries the value and the index, and `payment_order.order_id`
    # is unique, which is the property the join actually needs.
    order_id = sa.Column("order_id", sa.String(36), nullable=True)
    if op.get_bind().dialect.name == "postgresql":
        op.add_column("statement", order_id)
        op.create_foreign_key("fk_statement_order_id_payment_order", "statement",
                              "payment_order", ["order_id"], ["order_id"],
                              ondelete="SET NULL")
    else:
        op.add_column("statement", order_id)
    op.create_index("ix_statement_order_id", "statement", ["order_id"])


def downgrade() -> None:
    op.drop_index("ix_statement_order_id", table_name="statement")
    if op.get_bind().dialect.name == "postgresql":
        op.drop_constraint("fk_statement_order_id_payment_order", "statement",
                           type_="foreignkey")
    op.drop_column("statement", "order_id")
    for name in ("status_reported_at", "status_reason_text",
                 "status_reason_code", "bank_status"):
        op.drop_column("payment_order", name)
