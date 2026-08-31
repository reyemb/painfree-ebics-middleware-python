"""Per-connection access grants, and the backfill that keeps the old model's people.

The table is additive. The backfill is not, and it is the part worth reading.

Before this revision, privilege was four global role names in a token:
`viewer`, `operator`, `auditor`, `administrator`. After it, `administrator` (and
the new name `admin`) is still a claim, and everybody else holds nothing until
they are granted a connection. Left alone, that upgrade would sign every
existing operator and viewer out of every bank on the morning it deployed.

So this revision reconstructs grants for the people it can find, at the level
their old role implies, on every connection that exists:

| held before          | granted here                                   |
|----------------------|------------------------------------------------|
| `operator`           | `operator` on every existing connection        |
| `viewer`             | `viewer` on every existing connection          |
| `auditor`            | `viewer` on every existing connection, flagged |
| `administrator`      | nothing -- the claim still makes them an admin |

**`auditor` has no safe automatic mapping and is not given one.** It held two
things no grant level carries: `audit:read` across *every* connection, and
`webhooks:read` -- which the `viewer` level does not have, because the list of
external event sinks is deliberately kept away from a viewer. The new model has
no audit-everywhere-but-administer-nothing level: the only privilege that spans
connections is `admin`, which also carries the key lifecycle and the webhook
perimeter. Promoting an auditor would hand them both, which is a security
incident.

So this revision takes the narrower half -- everything an auditor could read
about a connection, **minus the cross-connection audit rows and minus
`webhooks:read`** -- and writes an audit row per affected subject naming exactly
that. An administrator decides whether the person becomes an `admin` or is
granted `operator` on the connections whose webhook health they have to see.
Losing access is an outage and gaining it is an incident, and only one of those
is recoverable by asking.

**The reconstruction is best-effort, and it has to be.** The old model kept no
record of who held what -- privilege lived in the identity provider and this
service only ever saw it in a token. The one trace is `user_session.roles`, so
that is what this reads, unexpired sessions and expired ones alike. A person who
held `operator` and had not signed in since the session table was last pruned
cannot be recovered from anything in this database, and no migration can invent
them. What they get is the intended new-model state -- a working login and an
empty console -- and an administrator grants them a connection. The audit rows
this writes name exactly who was recovered, so the gap is visible rather than
assumed away.

Nothing is widened. Every subject below ends with access to a subset of what
their old role reached, on the connections that already existed.

Revision ID: 0012_connection_grants
Revises: 0011_schedule_management
Create Date: 2026-08-30
"""
from __future__ import annotations

import datetime as _dt
import json
import uuid

import sqlalchemy as sa
from alembic import op

from painfree.schema import JsonBlob, Sequence64, UtcDateTime

revision = "0012_connection_grants"
down_revision = "0011_schedule_management"
branch_labels = None
depends_on = None

#: Old role name to the level it becomes on every existing connection.
#: `administrator` is absent because it stays a claim rather than a grant.
BACKFILL_LEVELS = {"operator": "operator", "viewer": "viewer",
                   "auditor": "viewer"}

#: The one old role whose reach this migration cannot preserve. Recorded rather
#: than resolved: see the module docstring.
NEEDS_A_DECISION = "auditor"

#: Who the backfill rows are attributed to. Not a person: no person ran this.
MIGRATION_ACTOR = "migration:0012_connection_grants"


def upgrade() -> None:
    op.create_table(
        "connection_grant",
        sa.Column("seq", Sequence64, primary_key=True, autoincrement=True),
        sa.Column("grant_id", sa.String(36), nullable=False, unique=True),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("connection_id", sa.String(64),
                  sa.ForeignKey("bank_connection.connection_id",
                                ondelete="CASCADE"), nullable=False),
        sa.Column("level", sa.String(16), nullable=False),
        sa.Column("granted_by", sa.String(255), nullable=False),
        sa.Column("created_at", UtcDateTime, nullable=False),
        sa.Column("updated_at", UtcDateTime, nullable=False),
        sa.UniqueConstraint("subject", "connection_id",
                            name="uq_connection_grant_subject_connection_id"),
    )
    op.create_index("ix_connection_grant_subject", "connection_grant",
                    ["subject"])
    op.create_index("ix_connection_grant_connection_id", "connection_grant",
                    ["connection_id"])
    _backfill()


def _backfill() -> None:
    """Reconstruct grants from the sessions this deployment still holds."""
    connection = op.get_bind()
    now = _dt.datetime.now(_dt.timezone.utc)

    connections = [row[0] for row in connection.execute(
        sa.text("SELECT connection_id FROM bank_connection ORDER BY seq"))]
    if not connections:
        # A deployment with no bank connection has nothing to grant access to,
        # and the new model's answer for it is the same as the old one's: an
        # administrator registers a connection first.
        return

    # Newest session per subject wins: a person whose role changed held the
    # newer one, and re-granting from a stale row would restore a privilege
    # somebody had already taken away.
    latest: dict[str, list[str]] = {}
    for subject, roles in connection.execute(sa.text(
            "SELECT subject, roles FROM user_session ORDER BY seq")):
        latest[subject] = _roles(roles)

    grants: list[dict[str, object]] = []
    recovered: dict[str, dict[str, object]] = {}
    for subject, roles in sorted(latest.items()):
        if any(name in ("admin", "administrator") for name in roles):
            continue
        levels = [BACKFILL_LEVELS[name] for name in roles
                  if name in BACKFILL_LEVELS]
        if not levels:
            continue
        # The most privileged of the names they held, which is what the old
        # model gave them: scopes were a union across roles.
        level = "operator" if "operator" in levels else "viewer"
        recovered[subject] = {
            "held": sorted(roles), "level": level,
            "connections": len(connections),
            "needs_decision": NEEDS_A_DECISION in roles,
        }
        for connection_id in connections:
            grants.append({
                "grant_id": f"grn_{uuid.uuid4().hex[:24]}", "subject": subject,
                "connection_id": connection_id, "level": level,
                "granted_by": MIGRATION_ACTOR,
                "created_at": now, "updated_at": now})

    if grants:
        op.bulk_insert(_grant_table(), grants)
    _record(connection, now, recovered, connections)


def _grant_table() -> sa.Table:
    return sa.table(
        "connection_grant",
        sa.column("grant_id", sa.String),
        sa.column("subject", sa.String),
        sa.column("connection_id", sa.String),
        sa.column("level", sa.String),
        sa.column("granted_by", sa.String),
        sa.column("created_at", UtcDateTime),
        sa.column("updated_at", UtcDateTime),
    )


def _record(connection: sa.Connection, now: _dt.datetime,
            recovered: dict[str, dict[str, object]],
            connections: list[str]) -> None:
    """One audit row per subject, and one for the migration itself.

    Written here rather than left to a log line because this is the record of
    who was given access to a bank connection, and that belongs in the trail
    with an actor on it. The actor is the migration, which is true and is the
    point: nobody decided these, and the row saying so is what an administrator
    reviews.
    """
    rows = [{
        "event_id": str(uuid.uuid4()),
        "occurred_at": now,
        "actor_type": "system",
        "actor_id": MIGRATION_ACTOR,
        "action": "access.migrated",
        "outcome": "success",
        "connection_id": None,
        "detail": {
            "subject": subject,
            "held_roles": summary["held"],
            "grant_level": summary["level"],
            "connections": summary["connections"],
            "needs_admin_decision": summary["needs_decision"],
            # Only where something was actually lost. A `viewer` or an
            # `operator` keeps everything their role reached, so a `loses` key
            # on their row would be a false statement about them -- and a
            # migration's own audit trail is the last place to put one.
            **({"loses": ["audit rows that name no connection or another one",
                          "webhooks:read"]}
               if summary["needs_decision"] else {}),
            "reason": ("auditor read every connection's trail and held "
                       "webhooks:read; no grant level carries either, and the "
                       "only privilege that spans connections also carries the "
                       "key lifecycle. An administrator decides whether this "
                       "subject becomes an admin")
            if summary["needs_decision"] else
            "the level the subject's previous role carried, on every "
            "connection that existed",
        },
    } for subject, summary in sorted(recovered.items())]
    rows.append({
        "event_id": str(uuid.uuid4()),
        "occurred_at": now,
        "actor_type": "system",
        "actor_id": MIGRATION_ACTOR,
        "action": "access.migration_finished",
        "outcome": "success",
        "connection_id": None,
        "detail": {
            "subjects_recovered": len(recovered),
            "connections": len(connections),
            "grants_written": len(recovered) * len(connections),
            "needs_admin_decision": sorted(
                subject for subject, summary in recovered.items()
                if summary["needs_decision"]),
            "note": "reconstructed from user_session; a subject with no "
                    "session row could not be recovered and starts with an "
                    "empty console",
        },
    })
    op.bulk_insert(sa.table(
        "audit_log",
        sa.column("event_id", sa.String),
        sa.column("occurred_at", UtcDateTime),
        sa.column("actor_type", sa.String),
        sa.column("actor_id", sa.String),
        sa.column("action", sa.String),
        sa.column("outcome", sa.String),
        sa.column("connection_id", sa.String),
        sa.column("detail", JsonBlob),
    ), rows)


def _roles(value: object) -> list[str]:
    """`user_session.roles` as a list, whichever backend answered.

    `JSONB` on PostgreSQL comes back decoded; SQLite's `JSON` comes back as the
    text it was stored as. Both are read here rather than in two places.
    """
    if isinstance(value, (list, tuple)):
        return [str(name) for name in value]
    if isinstance(value, (str, bytes)):
        try:
            decoded = json.loads(value)
        except ValueError:
            return []
        return [str(name) for name in decoded] if isinstance(
            decoded, list) else []
    return []


def downgrade() -> None:
    # The audit rows stay. They are the record that the backfill happened, and
    # an append-only log that a downgrade edits is not one.
    op.drop_index("ix_connection_grant_connection_id",
                  table_name="connection_grant")
    op.drop_index("ix_connection_grant_subject", table_name="connection_grant")
    op.drop_table("connection_grant")
