"""Whether an upload asks the bank to hold the payment for a human release.

One boolean, and unlike most migrations here it **changes behaviour on
upgrade**, deliberately.

`BTUOrderParams` may carry a `SignatureFlag`, and the H005 schema says what
its absence means: *the order contains no ES and is authorised outside EBICS*.
This service was sending a full A006 electronic signature and omitting the
flag, so every upload told the bank, by omission, that a signed order was
unsigned. SGKB answered `091113 EBICS_INVALID_ORDER_PARAMS`, which is the
correct answer to that document.

So the column cannot default to "off" and preserve existing behaviour, because
existing behaviour was a rejected upload. It defaults to `true`: the flag is
written, with `requestEDS`, and the bank holds the payment for release in its
portal. That is also the mode this repository's key-custody rule prefers -- a
human releases the payment and this service alone cannot move funds -- so the
default and the rule now agree instead of only the rule existing.

A connection whose mandate is sole authority sets it to `false` on the
connection page, which writes `SignatureFlag` without `requestEDS`.

`server_default` rather than a data migration: the column is non-null on a
table that already has rows, and `true` is the answer for every one of them.

Revision ID: 0019_request_eds
Revises: 0018_refused_request
Create Date: 2026-09-03
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0019_request_eds"
down_revision = "0018_refused_request"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("bank_connection",
                  sa.Column("request_eds", sa.Boolean, nullable=False,
                            server_default=sa.true()))


def downgrade() -> None:
    op.drop_column("bank_connection", "request_eds")
