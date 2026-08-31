"""The two tables browser authentication needs.

`oidc_login` is one authorization-code flow in flight; `user_session` is one
established browser session. Both are additive, and a deployment authenticating
only machine callers with bearer tokens never writes a row in either -- a JWT
is verified against the provider's published keys and needs no state here.

Revision ID: 0007_identity
Revises: 0006_webhooks
Create Date: 2026-08-30
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from painfree.schema import JsonBlob, Sequence64, UtcDateTime

revision = "0007_identity"
down_revision = "0006_webhooks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "oidc_login",
        sa.Column("seq", Sequence64, primary_key=True, autoincrement=True),
        sa.Column("state_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("nonce", sa.String(64), nullable=False),
        sa.Column("code_verifier", sa.String(128), nullable=False),
        sa.Column("redirect_to", sa.String(512), nullable=True),
        sa.Column("created_at", UtcDateTime, nullable=False),
        sa.Column("expires_at", UtcDateTime, nullable=False),
        sa.Column("consumed_at", UtcDateTime, nullable=True),
    )
    op.create_index("ix_oidc_login_expires_at", "oidc_login", ["expires_at"])

    op.create_table(
        "user_session",
        sa.Column("seq", Sequence64, primary_key=True, autoincrement=True),
        sa.Column("session_id_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("roles", JsonBlob, nullable=False),
        sa.Column("display_name", sa.String(255), nullable=True),
        sa.Column("created_at", UtcDateTime, nullable=False),
        sa.Column("expires_at", UtcDateTime, nullable=False),
        sa.Column("last_seen_at", UtcDateTime, nullable=False),
        sa.Column("revoked_at", UtcDateTime, nullable=True),
    )
    op.create_index("ix_user_session_subject", "user_session", ["subject"])
    op.create_index("ix_user_session_expires_at", "user_session", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_user_session_expires_at", table_name="user_session")
    op.drop_index("ix_user_session_subject", table_name="user_session")
    op.drop_table("user_session")
    op.drop_index("ix_oidc_login_expires_at", table_name="oidc_login")
    op.drop_table("oidc_login")
