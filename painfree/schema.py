"""The database schema, written once for SQLite and PostgreSQL both.

Development runs on SQLite with nothing to install; production runs on
PostgreSQL. One ``MetaData`` describes both, and the handful of places where the
two genuinely differ are named here rather than discovered in production:

``BIGINT`` **primary keys.** SQLite only auto-assigns a rowid alias for a column
declared exactly ``INTEGER PRIMARY KEY``; ``BIGINT PRIMARY KEY`` is an ordinary
column that stays ``NULL``. So the sequence column is ``BigInteger`` with an
``Integer`` variant for SQLite.

**Timestamps.** ``TIMESTAMP WITH TIME ZONE`` is real on PostgreSQL and a
suggestion on SQLite, which stores whatever string it is handed and returns it
naive. :class:`UtcDateTime` converts to UTC on the way in and re-attaches UTC on
the way out, so application code sees an aware datetime on both.

**JSON.** PostgreSQL gets ``JSONB``, which is indexable; SQLite gets the generic
``JSON`` type, which is ``TEXT`` with SQLAlchemy doing the serialisation. The
Python side is a ``dict`` either way.

**Money.** Neither backend is trusted with it. PostgreSQL has a real ``NUMERIC``
and SQLite has nothing of the kind -- ``NUMERIC`` there is an affinity, and
SQLAlchemy's own ``Numeric`` warns that it round-trips a decimal through a C
double to get back to it. One float in that path is one wrong statement, so
:class:`Money` stores the digits as text and rebuilds a :class:`decimal.Decimal`
from exactly those digits on the way out, on both backends. The scale the bank
sent survives with it: ``1.10`` comes back ``1.10`` and not ``1.1``.

Ordering, concurrency and ``RETURNING`` are handled in :mod:`painfree.db`.
"""

from __future__ import annotations

import datetime as _dt
import decimal
from typing import Any

from sqlalchemy import (BigInteger, Boolean, Column, DateTime, ForeignKey,
                        Index, Integer, JSON, LargeBinary, MetaData, String,
                        Table, TypeDecorator, UniqueConstraint)
from sqlalchemy.dialects.postgresql import JSONB

#: Explicit naming so a constraint added later gets the same name on both
#: backends, and so Alembic can drop one it did not name itself.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_N_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=NAMING_CONVENTION)


class UtcDateTime(TypeDecorator):
    """An aware UTC datetime on both backends.

    SQLite has no timestamp type; PostgreSQL has a real one. Without this,
    ``occurred_at`` comes back aware in production and naive in development, and
    the comparison that works locally raises in the container.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if not isinstance(value, _dt.datetime):
            raise TypeError(f"expected datetime, got {type(value).__name__}")
        if value.tzinfo is None:
            raise ValueError("naive datetimes are refused; pass an aware UTC value")
        return value.astimezone(_dt.timezone.utc)

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=_dt.timezone.utc)
        return value.astimezone(_dt.timezone.utc)


class Money(TypeDecorator):
    """An exact decimal amount, stored as the digits the bank sent.

    Text rather than ``NUMERIC`` because only one of the two backends has a
    real one, and the fallback on the other is a binary float. An amount that
    survives development and is wrong in production is the worst shape this
    could take, so both backends get the same storage and the same exactness.

    Refuses a ``float`` outright rather than converting it: by the time a
    float reaches here the digits are already gone, and accepting it would
    hide the defect one layer further down.
    """

    impl = String(40)
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, float):
            raise TypeError(
                "money is never a float; pass a Decimal or its digits as a string")
        if not isinstance(value, decimal.Decimal):
            value = decimal.Decimal(str(value))
        return format(value, "f")

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        return None if value is None else decimal.Decimal(value)


#: ``JSONB`` where it exists, ``JSON`` where it does not.
JsonBlob = JSON().with_variant(JSONB(), "postgresql")

#: A rowid-alias-compatible auto-incrementing key.
Sequence64 = BigInteger().with_variant(Integer(), "sqlite")


audit_log = Table(
    "audit_log",
    metadata,
    # `seq` is the append order, `event_id` is the identity anyone outside the
    # database quotes. Two columns because a gapless local sequence and a
    # globally unique reference are different jobs.
    Column("seq", Sequence64, primary_key=True, autoincrement=True),
    Column("event_id", String(36), nullable=False, unique=True),
    Column("occurred_at", UtcDateTime, nullable=False),
    # Who. `actor_type` is `system` for anything the service did on its own
    # behalf; OIDC subjects arrive with identity.
    Column("actor_type", String(32), nullable=False),
    Column("actor_id", String(255), nullable=False),
    # What, and how it went.
    Column("action", String(128), nullable=False),
    Column("outcome", String(16), nullable=False),
    # Correlation -- the same ids the log lines carry, so an audit row and the
    # log stream can be joined by grepping one value.
    Column("request_id", String(64), nullable=True),
    Column("connection_id", String(64), nullable=True),
    Column("order_id", String(64), nullable=True),
    Column("job_id", String(64), nullable=True),
    Column("idempotency_key", String(255), nullable=True),
    # Never payment content: references, return codes, report text.
    Column("detail", JsonBlob, nullable=False, server_default="{}"),
    Index("ix_audit_log_occurred_at", "occurred_at"),
    Index("ix_audit_log_action", "action"),
    Index("ix_audit_log_request_id", "request_id"),
)


bank_connection = Table(
    "bank_connection",
    metadata,
    Column("seq", Sequence64, primary_key=True, autoincrement=True),
    # `connection_id` is the name every other table, every log line and every
    # URL uses. It is chosen by the operator rather than generated, because it
    # is the value they will be reading in a log stream at two in the morning.
    Column("connection_id", String(64), nullable=False, unique=True),
    # Who we are to this bank. The three EBICS identifiers are `1..35` in the
    # schema, and the bank assigns all three.
    Column("host_id", String(35), nullable=False),
    Column("partner_id", String(35), nullable=False),
    Column("user_id", String(35), nullable=False),
    Column("host_url", String(1024), nullable=False),
    # `Product` is optional in the protocol and some banks filter on it.
    Column("product_name", String(64), nullable=True),
    Column("product_language", String(2), nullable=True),
    Column("product_institute", String(64), nullable=True),
    Column("ebics_version", String(8), nullable=False),
    # The engine's `KeyState`, persisted rather than recomputed: it is what lets
    # a half-finished initialisation resume instead of restarting with keys the
    # bank has never seen.
    Column("key_state", String(32), nullable=False),
    Column("ini_sent", Boolean, nullable=False),
    Column("hia_sent", Boolean, nullable=False),
    Column("ini_order_id", String(16), nullable=True),
    Column("hia_order_id", String(16), nullable=True),
    # Which of the two conventions this bank's letter quotes; the engine will
    # not guess, so the answer belongs with the connection.
    Column("letter_digest", String(16), nullable=False),
    # What was accepted at HPB, so a later key roll is visible as one rather
    # than as noise. Fingerprints only -- they are public values.
    Column("bank_fingerprints", JsonBlob, nullable=True),
    # Which BTF triplet and which ISO 20022 codes this bank means by "normal"
    # and by "instant", and which of its refusals mean instant was unavailable.
    # Per-connection rather than a constant because the answer differs by bank
    # and by scheme version, and a wrong value produces
    # `EBICS_INVALID_ORDER_PARAMS` rather than anything a release could catch
    # (`painfree.schemes`). NULL is the default set, which sends what this
    # service sent before schemes existed.
    Column("payment_schemes", JsonBlob, nullable=True),
    Column("created_at", UtcDateTime, nullable=False),
    Column("updated_at", UtcDateTime, nullable=False),
    UniqueConstraint("host_id", "partner_id", "user_id",
                     name="uq_bank_connection_host_id_partner_id_user_id"),
)


#: Two kinds of row live here and the distinction is the whole security story:
#: a `subscriber` row may carry `sealed_private`, a `bank` row never does. The
#: public halves are stored in the clear on purpose -- they are public, and a
#: fingerprint an operator has to compare against a letter should not need the
#: custody key to read.
key_material = Table(
    "key_material",
    metadata,
    Column("seq", Sequence64, primary_key=True, autoincrement=True),
    Column("connection_id", String(64),
           ForeignKey("bank_connection.connection_id", ondelete="CASCADE"),
           nullable=False),
    Column("holder", String(16), nullable=False),      # subscriber | bank
    Column("version", String(8), nullable=False),      # A006 | X002 | E002
    # Renewal mints a new generation rather than overwriting: the key the bank
    # still has on file has to stay readable until it confirms the new one.
    Column("generation", Integer, nullable=False),
    Column("status", String(16), nullable=False),      # active | suspended | superseded
    # The EBICS public-key digest -- the value on the letter, and the value log
    # lines carry in place of the key.
    Column("fingerprint", String(64), nullable=False),
    Column("certificate_fingerprint", String(64), nullable=True),
    Column("public_pem", LargeBinary, nullable=False),
    Column("certificate_der", LargeBinary, nullable=True),
    # The sealed envelope from `painfree.sealing`, or NULL for a public-only
    # key. Never the PEM.
    Column("sealed_private", LargeBinary, nullable=True),
    # Which custody key sealed it. Stored so a rotated secret is diagnosable
    # from a query rather than from a decryption failure.
    Column("custody_key_id", String(32), nullable=True),
    Column("created_at", UtcDateTime, nullable=False),
    Column("updated_at", UtcDateTime, nullable=False),
    UniqueConstraint("connection_id", "holder", "version", "generation",
                     name="uq_key_material_connection_id_holder_version_generation"),
    Index("ix_key_material_connection_id_status", "connection_id", "status"),
    Index("ix_key_material_fingerprint", "fingerprint"),
)


#: One submitted payment, from the moment it is accepted until the bank has
#: answered for it. The two unique constraints are the whole idempotency story:
#: `(connection_id, idempotency_key)` makes a duplicate submission a constraint
#: violation rather than a race two readers can both win, and `msg_id` is
#: unique because it is what the *bank* deduplicates on.
#:
#: The generated `pain.001` is stored here rather than rebuilt later. It is the
#: document that will be signed, and a document rebuilt at signing time from a
#: newer builder is not the document that was validated.
payment_order = Table(
    "payment_order",
    metadata,
    Column("seq", Sequence64, primary_key=True, autoincrement=True),
    # What the caller quotes and every log line carries.
    Column("order_id", String(36), nullable=False, unique=True),
    Column("connection_id", String(64),
           ForeignKey("bank_connection.connection_id", ondelete="RESTRICT"),
           nullable=False),
    Column("idempotency_key", String(255), nullable=False),
    # SHA-256 of the canonical request body. A repeat with the same key and a
    # different payload is a caller bug worth surfacing, not an overwrite --
    # and the hash is stored instead of the body so the comparison does not
    # require keeping a second copy of the payment content.
    Column("request_fingerprint", String(64), nullable=False),
    Column("state", String(32), nullable=False),
    # The `MsgId` of the generated message, persisted because the mapping from
    # an idempotency key to a `MsgId` is what stops a retry paying twice.
    Column("msg_id", String(35), nullable=False, unique=True),
    Column("payment_information_id", String(35), nullable=False),
    Column("message_type", String(32), nullable=False),
    Column("document", LargeBinary, nullable=False),
    # Enough to answer "what did I submit?" without opening the document.
    Column("transaction_count", Integer, nullable=False),
    Column("control_sum", String(32), nullable=False),
    Column("currency", String(3), nullable=False),
    Column("requested_execution_date", String(10), nullable=False),
    # Filled by the worker: the bank's `OrderID`, and the return code and
    # report text it answered with. Surfaced verbatim -- never folded into a
    # generic message.
    Column("bank_order_id", String(16), nullable=True),
    Column("return_code", String(16), nullable=True),
    Column("report_text", String(1024), nullable=True),
    # The EBICS `TransactionID`, written the moment the bank assigns it. It is
    # the only handle on an open transaction, and a worker that loses it after
    # uploading twenty segments has to upload them again.
    Column("transaction_id", String(64), nullable=True),
    # The claim. `state='submitting'` plus these three is what makes "one
    # worker owns this order" a fact in the database rather than a convention:
    # the claim is an atomic conditional UPDATE, and `claimed_at` is the lease
    # that lets a second worker take over from one that died -- see
    # `painfree.queue`.
    Column("worker_id", String(64), nullable=True),
    Column("claimed_at", UtcDateTime, nullable=True),
    # The retry policy's two columns. `attempts` counts claims, not failures,
    # so an order that is claimed and never released still converges on the
    # retry ceiling instead of being retried for ever.
    Column("attempts", Integer, nullable=False, server_default="0"),
    Column("next_attempt_at", UtcDateTime, nullable=True),
    # Why the last attempt did not finish. A transport failure or an engine
    # error, in one short line -- never a payload, and never a key.
    Column("last_error", String(512), nullable=True),
    # What the bank's `pain.002` said, in the bank's own vocabulary. Separate
    # columns from `return_code` above on purpose: an EBICS return code is six
    # digits about the *transfer* and an ISO 20022 status is four letters about
    # the *payment*, and one column holding either is a column nobody can read.
    # `status_reason_code` is `AC01` or the bank's proprietary equivalent;
    # `status_reason_text` is its own `AddtlInf`.
    Column("bank_status", String(8), nullable=True),
    Column("status_reason_code", String(35), nullable=True),
    Column("status_reason_text", String(1024), nullable=True),
    # When the *bank* wrote the report, not when this service read it.
    Column("status_reported_at", UtcDateTime, nullable=True),
    # The payment scheme. `requested_scheme` is what the caller asked for and
    # never changes; `scheme` is what the **live attempt** is actually sending,
    # so the two differing is exactly the fact an operator has to be able to
    # see -- a payment asked to go instantly that went normal, and
    # `scheme_reason` saying why.
    Column("requested_scheme", String(20), nullable=False,
           server_default="normal"),
    Column("scheme", String(20), nullable=False, server_default="normal"),
    Column("scheme_reason", String(64), nullable=True),
    Column("accepted_at", UtcDateTime, nullable=False),
    Column("updated_at", UtcDateTime, nullable=False),
    UniqueConstraint("connection_id", "idempotency_key",
                     name="uq_payment_order_connection_id_idempotency_key"),
    # How the worker finds its next order without scanning the table.
    Index("ix_payment_order_state_seq", "state", "seq"),
    # And how it finds the ones whose backoff has expired.
    Index("ix_payment_order_state_next_attempt_at", "state", "next_attempt_at"),
    Index("ix_payment_order_connection_id", "connection_id"),
)


#: Every attempt this service has made, or is holding in reserve, at one order.
#:
#: **One idempotency key is one order; an attempt is not an order.** A caller
#: that asks for `instant_or_normal` gets one row in `payment_order` and two
#: rows here: the instant one, live, and the normal one, `planned` and dormant.
#: The fallback promotes the second and supersedes the first, which is why the
#: order can end accepted at most once no matter how many attempts it took.
#:
#: **The BTF and the document are in the same row on purpose.** A BTF claiming
#: instant over a document that does not is refused by the bank with a code
#: that will not explain itself, so the two halves of one scheme decision are
#: stored together and the worker reads the announcement off the row carrying
#: the bytes it announces. There is no code path that computes one without the
#: other.
#:
#: `payment_order.document` and `payment_order.msg_id` carry a copy of whichever
#: attempt is live. That duplication is deliberate: every reader of an order
#: written before this table existed keeps working, and the promotion is the one
#: writer of both.
payment_attempt = Table(
    "payment_attempt",
    metadata,
    Column("seq", Sequence64, primary_key=True, autoincrement=True),
    Column("attempt_id", String(36), nullable=False, unique=True),
    Column("order_id", String(36),
           ForeignKey("payment_order.order_id", ondelete="CASCADE"),
           nullable=False),
    # 1, 2, ... within one order. Not a claim count -- `payment_order.attempts`
    # is that, and the two answer different questions: how many times a worker
    # picked this order up, versus how many different messages were built for it.
    Column("attempt_no", Integer, nullable=False),
    Column("scheme", String(20), nullable=False),
    # planned | live | superseded | settled
    Column("state", String(16), nullable=False),
    # Its own `MsgId`, unique across every attempt of every order: the bank
    # deduplicates on it, so two attempts sharing one would be the second
    # payment this design exists to prevent.
    Column("msg_id", String(35), nullable=False, unique=True),
    Column("payment_information_id", String(35), nullable=False),
    Column("document", LargeBinary, nullable=False),
    # The BTF this attempt is announced under, decided with the document above.
    Column("btf_service_name", String(3), nullable=False),
    Column("btf_service_option", String(10), nullable=True),
    Column("btf_scope", String(3), nullable=True),
    # The `PmtTpInf` this document carries, as one short line an operator can
    # read beside the BTF. Derived from the same profile that produced the XML,
    # stored so that comparing the two needs no XML parsing.
    Column("payment_type", String(255), nullable=True),
    # Why this attempt exists: the pre-flight downgrade that produced it, or
    # the bank refusal that promoted it.
    Column("reason", String(255), nullable=True),
    Column("return_code", String(16), nullable=True),
    Column("report_text", String(1024), nullable=True),
    Column("created_at", UtcDateTime, nullable=False),
    Column("updated_at", UtcDateTime, nullable=False),
    UniqueConstraint("order_id", "attempt_no",
                     name="uq_payment_attempt_order_id_attempt_no"),
    # How the promotion finds the one dormant attempt, and how the console
    # lists an order's attempts.
    Index("ix_payment_attempt_order_id_state", "order_id", "state"),
)


#: One periodic download per bank connection and BTF. The cadence lives in the
#: database rather than in a process, which is what makes it survive a restart:
#: `due_at` is the next moment this schedule may run, and a scheduler that was
#: down for a day finds one overdue row rather than a day's worth of missed
#: ticks to catch up on.
#:
#: `worker_id` and `claimed_at` are the same claim the upload queue uses, for
#: the same reason: two schedulers is the ordinary deployment and both fetching
#: one window is a duplicate download at the bank's end.
#:
#: `fetched_through` is the download window's high-water mark. It advances only
#: when a run finished -- so a run that failed leaves it where it was and the
#: next run asks for the same window again, which is what makes a gap
#: recoverable instead of silently skipped.
download_schedule = Table(
    "download_schedule",
    metadata,
    Column("seq", Sequence64, primary_key=True, autoincrement=True),
    Column("schedule_id", String(36), nullable=False, unique=True),
    Column("connection_id", String(64),
           ForeignKey("bank_connection.connection_id", ondelete="CASCADE"),
           nullable=False),
    # The BTF, column by column. It is per-bank configuration and not something
    # to be guessed: a wrong `ServiceName` is answered with
    # `EBICS_INVALID_ORDER_PARAMS` and not with a local error.
    Column("service_name", String(3), nullable=False),
    Column("scope", String(3), nullable=True),
    Column("service_option", String(10), nullable=True),
    Column("container", String(3), nullable=True),
    Column("msg_name", String(10), nullable=False),
    Column("msg_variant", String(3), nullable=True),
    Column("msg_version", String(3), nullable=True),
    # What an operator calls this schedule on a list of eight. Free text, and
    # never anything the download path reads.
    Column("description", String(255), nullable=True),
    # How often, and whether at all. `enabled` is how an operator stops one
    # schedule without losing its window.
    Column("cadence_seconds", Integer, nullable=False),
    Column("enabled", Boolean, nullable=False, server_default="1"),
    # `window_days`, when set, is how far back a `DateRange` reaches. Left
    # NULL no `DateRange` is sent at all and the bank serves what it has
    # pending -- which is the ordinary EBICS model, where the *receipt* is
    # what stops a statement being offered twice.
    Column("window_days", Integer, nullable=True),
    Column("fetched_through", String(10), nullable=True),
    Column("due_at", UtcDateTime, nullable=False),
    Column("worker_id", String(64), nullable=True),
    Column("claimed_at", UtcDateTime, nullable=True),
    Column("last_run_at", UtcDateTime, nullable=True),
    Column("last_return_code", String(16), nullable=True),
    Column("last_error", String(512), nullable=True),
    # Who asked for the *next* run out of band -- a "run now" or a window
    # re-fetch. Set by the surface that took the click, consumed and cleared by
    # the claim, and copied onto the run it opens. It is how the ledger says a
    # run happened because a human asked rather than because the cadence came
    # round, which is the difference between a re-fetch and a duplicate.
    Column("run_requested_by", String(255), nullable=True),
    Column("created_at", UtcDateTime, nullable=False),
    Column("updated_at", UtcDateTime, nullable=False),
    # One schedule per connection and BTF: two rows asking the same bank for
    # the same thing on two cadences is two downloads of one statement.
    # Named short by hand: the convention's generated name is longer than the
    # 63 characters PostgreSQL keeps, and a silently truncated constraint is
    # one a later migration cannot drop by the name it thinks it has.
    UniqueConstraint("connection_id", "service_name", "msg_name", "msg_version",
                     name="uq_download_schedule_btf"),
    Index("ix_download_schedule_enabled_due_at", "enabled", "due_at"),
)


#: One attempt at one schedule, kept whether it worked or not. This is the
#: window ledger: every run records the window it asked for and how it ended,
#: so a missing statement is a row an operator can find rather than an absence
#: they have to infer.
download_run = Table(
    "download_run",
    metadata,
    Column("seq", Sequence64, primary_key=True, autoincrement=True),
    Column("run_id", String(36), nullable=False, unique=True),
    Column("schedule_id", String(36),
           ForeignKey("download_schedule.schedule_id", ondelete="CASCADE"),
           nullable=False),
    Column("connection_id", String(64), nullable=False),
    Column("worker_id", String(64), nullable=False),
    Column("state", String(16), nullable=False),
    # What was asked for. NULL when the request carried no `DateRange`.
    Column("window_start", String(10), nullable=True),
    Column("window_end", String(10), nullable=True),
    # What came back. `acknowledged` is the receipt: without it the bank offers
    # the same data again on the next run.
    Column("transaction_id", String(64), nullable=True),
    Column("bank_order_id", String(16), nullable=True),
    Column("return_code", String(16), nullable=True),
    Column("report_text", String(1024), nullable=True),
    Column("acknowledged", Boolean, nullable=False, server_default="0"),
    Column("segments", Integer, nullable=False, server_default="0"),
    Column("bytes", Integer, nullable=False, server_default="0"),
    # `documents` is what the container held; `statements` is how many rows
    # came out of them, which is not the same number -- one `camt.054` carries
    # a notification per account.
    Column("documents", Integer, nullable=False, server_default="0"),
    Column("statements", Integer, nullable=False, server_default="0"),
    Column("duplicates", Integer, nullable=False, server_default="0"),
    Column("last_error", String(512), nullable=True),
    # NULL for a run the cadence caused, and the operator's subject for one a
    # human asked for. A re-fetch of a window already covered is expected to
    # find duplicates; an ordinary run that does is a receipt that never
    # arrived, and the two must not look the same in the ledger.
    Column("requested_by", String(255), nullable=True),
    Column("started_at", UtcDateTime, nullable=False),
    Column("finished_at", UtcDateTime, nullable=True),
    Index("ix_download_run_schedule_id_seq", "schedule_id", "seq"),
)


#: One normalised document out of one download: a `camt` report, statement or
#: notification, or a `pain.002` status report.
#:
#: `document_key` is the identity, and the unique constraint on it with
#: `connection_id` is the whole idempotency story for ingestion. Banks re-serve
#: -- a download that was never acknowledged is offered again, and an operator
#: replaying a run asks for the same days twice -- so re-ingesting has to be a
#: no-op at the database level and not a check some code path can skip.
#:
#: `content_hash` is stored beside it so the *other* case is visible: the same
#: identity arriving with different content is a bank amending a statement, and
#: that deserves a warning rather than a silent first-wins.
statement = Table(
    "statement",
    metadata,
    Column("seq", Sequence64, primary_key=True, autoincrement=True),
    Column("statement_id", String(36), nullable=False, unique=True),
    Column("connection_id", String(64),
           ForeignKey("bank_connection.connection_id", ondelete="CASCADE"),
           nullable=False),
    Column("run_id", String(36), nullable=True),
    # The order this document reports on, for a `pain.002`, and NULL for
    # everything else. A column rather than a field inside `payload`, because
    # "which reports answer this order" is a question the console asks on every
    # order page and a JSON scan is not an answer to it. NULL is also a fact
    # worth storing: a status report naming a `MsgId` this service never sent
    # is kept rather than dropped (`painfree.reconcile`).
    Column("order_id", String(36),
           ForeignKey("payment_order.order_id", ondelete="SET NULL"),
           nullable=True),
    # Read off the document's own namespace, not off the BTF that asked for it:
    # the document says what it is, and a misconfigured `MsgName` must not be
    # able to file a `camt.053` as something else.
    Column("message_type", String(32), nullable=False),
    Column("document_key", String(64), nullable=False),
    Column("content_hash", String(64), nullable=False),
    # Enough to find a statement without opening the payload.
    Column("identification", String(64), nullable=True),
    Column("sequence_number", String(16), nullable=True),
    Column("iban", String(34), nullable=True),
    Column("currency", String(3), nullable=True),
    Column("entry_count", Integer, nullable=False, server_default="0"),
    Column("created_at", UtcDateTime, nullable=True),
    Column("from_datetime", UtcDateTime, nullable=True),
    Column("to_datetime", UtcDateTime, nullable=True),
    # Exact, on both backends. See `Money`.
    Column("opening_balance", Money, nullable=True),
    Column("closing_balance", Money, nullable=True),
    # The normalised document, in the interchange shape this service publishes.
    # Amounts inside it are strings for the same reason the columns above are
    # text: a JSON number is a double.
    Column("payload", JsonBlob, nullable=False),
    Column("ingested_at", UtcDateTime, nullable=False),
    UniqueConstraint("connection_id", "document_key",
                     name="uq_statement_connection_id_document_key"),
    Index("ix_statement_connection_id_message_type", "connection_id", "message_type"),
    Index("ix_statement_run_id", "run_id"),
    Index("ix_statement_order_id", "order_id"),
)

#: Where events are pushed, and the secret each endpoint's signature is made
#: with. One row per consumer endpoint.
#:
#: `connection_id` is NULL for a subscription that wants every connection's
#: events; a value scopes it to one. `event_types` is the list of envelope
#: types this endpoint asked for -- stored rather than assumed, because a
#: consumer that only handles `statement.available` should not have to receive
#: and discard four other kinds.
#:
#: `sealed_secret` is the signing secret in the envelope
#: :mod:`painfree.sealing` produces, under the same custody key as an EBICS
#: private key and with the subscription's own identity as associated data. It
#: is a lesser secret than a signing key, but it is still what lets anyone
#: forge an event into a consumer's system, so it is stored the way the other
#: secrets are stored and not in a column an operator can read.
#:
#: `consecutive_failures` and `parked_at` are the other half of the retry
#: policy. A delivery gives up after its own ceiling; a *subscription* whose
#: deliveries keep giving up is parked, which is what stops a permanently dead
#: endpoint accumulating rows for ever.
webhook_subscription = Table(
    "webhook_subscription",
    metadata,
    Column("seq", Sequence64, primary_key=True, autoincrement=True),
    Column("subscription_id", String(36), nullable=False, unique=True),
    Column("connection_id", String(64),
           ForeignKey("bank_connection.connection_id", ondelete="CASCADE"),
           nullable=True),
    Column("url", String(1024), nullable=False),
    Column("event_types", JsonBlob, nullable=False),
    # What an operator calls this endpoint on a list of six. Free text, and
    # never anything the delivery path reads.
    Column("description", String(255), nullable=True),
    Column("sealed_secret", LargeBinary, nullable=False),
    # The secret being retired. Present only while a rotation is in flight:
    # both halves sign every delivery, so an endpoint keeps verifying with the
    # old value until its operator has switched it.
    Column("sealed_secret_previous", LargeBinary, nullable=True),
    Column("secret_generation", Integer, nullable=False, server_default="1"),
    Column("secret_rotated_at", UtcDateTime, nullable=True),
    Column("custody_key_id", String(32), nullable=False),
    # The registering caller's `Idempotency-Key`. Unique, so a retried
    # registration cannot become two endpoints receiving one payment's events.
    # Nullable because a subscription registered in code supplies none.
    Column("idempotency_key", String(255), nullable=True, unique=True),
    Column("enabled", Boolean, nullable=False, server_default="1"),
    Column("parked_at", UtcDateTime, nullable=True),
    Column("consecutive_failures", Integer, nullable=False, server_default="0"),
    Column("last_delivery_at", UtcDateTime, nullable=True),
    Column("last_status", Integer, nullable=True),
    Column("last_error", String(512), nullable=True),
    Column("created_at", UtcDateTime, nullable=False),
    Column("updated_at", UtcDateTime, nullable=False),
    Index("ix_webhook_subscription_enabled_connection_id",
          "enabled", "connection_id"),
)


#: The public half of the keypair a webhook signing secret is sealed to.
#:
#: Public material: holding it is the ability to *write* a secret and not to
#: read one. It is published by the worker -- the only process that can derive
#: the private half from the custody secret -- so that the API process, which
#: holds no custody key, can still register an endpoint and show its secret
#: once (:mod:`painfree.wrapping`).
#:
#: Keyed by custody key id: rotating ``PAINFREE_KEY_ENCRYPTION_SECRET`` adds a
#: row rather than editing one, and the envelope names which row it wants.
webhook_wrapping_key = Table(
    "webhook_wrapping_key",
    metadata,
    Column("seq", Sequence64, primary_key=True, autoincrement=True),
    Column("custody_key_id", String(32), nullable=False, unique=True),
    Column("public_key", LargeBinary, nullable=False),
    Column("created_at", UtcDateTime, nullable=False),
)


#: One event owed to one subscription, written **in the same transaction as the
#: fact it reports**. Everything the dispatcher sends is read back out of
#: `payload`, so a redelivery is byte-identical to the first attempt and
#: carries the same `event_id`.
#:
#: The unique constraint on `(subscription_id, event_id)` is what makes fan-out
#: safe to repeat: two processes recording the same audit event cannot both
#: create the delivery, because the second is refused by the database rather
#: than by a `SELECT` both of them passed.
#:
#: `worker_id` and `claimed_at` are the claim and its lease, exactly as in
#: `payment_order`: a dispatcher that dies mid-POST must not strand the event,
#: and the consumer deduplicates on `event_id` when the redelivery arrives.
webhook_delivery = Table(
    "webhook_delivery",
    metadata,
    Column("seq", Sequence64, primary_key=True, autoincrement=True),
    Column("delivery_id", String(36), nullable=False, unique=True),
    Column("subscription_id", String(36),
           ForeignKey("webhook_subscription.subscription_id",
                      ondelete="CASCADE"), nullable=False),
    # The identity the consumer deduplicates on. Deliberately *not* unique on
    # its own: one event owed to three subscriptions is three rows carrying one
    # id, which is what "the same event, delivered to three consumers" means.
    Column("event_id", String(36), nullable=False),
    Column("event_type", String(64), nullable=False),
    # Correlation, denormalised out of the envelope so an operator can find
    # every event of one order without opening a JSON column.
    Column("connection_id", String(64), nullable=True),
    Column("order_id", String(64), nullable=True),
    Column("idempotency_key", String(255), nullable=True),
    Column("occurred_at", UtcDateTime, nullable=False),
    # The whole envelope, as it will be signed and sent.
    Column("payload", JsonBlob, nullable=False),
    Column("state", String(16), nullable=False),
    Column("attempts", Integer, nullable=False, server_default="0"),
    Column("next_attempt_at", UtcDateTime, nullable=True),
    Column("worker_id", String(64), nullable=True),
    Column("claimed_at", UtcDateTime, nullable=True),
    # What the endpoint answered. A status, never its body: a consumer's error
    # page is not something to store.
    Column("last_status", Integer, nullable=True),
    Column("last_error", String(512), nullable=True),
    Column("delivered_at", UtcDateTime, nullable=True),
    Column("created_at", UtcDateTime, nullable=False),
    Column("updated_at", UtcDateTime, nullable=False),
    UniqueConstraint("subscription_id", "event_id",
                     name="uq_webhook_delivery_subscription_id_event_id"),
    Index("ix_webhook_delivery_state_seq", "state", "seq"),
    Index("ix_webhook_delivery_subscription_id_state",
          "subscription_id", "state"),
    Index("ix_webhook_delivery_event_id", "event_id"),
)


#: One browser login in flight: the `state` it was issued with, the `nonce` the
#: `id_token` has to echo, and the PKCE verifier whose challenge went to the
#: provider. Server-side rather than in a cookie, so that a login can be
#: consumed exactly once -- the callback claims the row with a conditional
#: `UPDATE`, and a replayed authorization code finds nothing left to claim.
#:
#: `state` itself is not stored: the row is keyed by its SHA-256, so read
#: access to this table does not hand out usable login states.
oidc_login = Table(
    "oidc_login",
    metadata,
    Column("seq", Sequence64, primary_key=True, autoincrement=True),
    Column("state_hash", String(64), nullable=False, unique=True),
    Column("nonce", String(64), nullable=False),
    Column("code_verifier", String(128), nullable=False),
    # Where the browser was going before it was sent to log in. Validated as a
    # relative path before it is stored -- an open redirect is a phishing tool.
    Column("redirect_to", String(512), nullable=True),
    Column("created_at", UtcDateTime, nullable=False),
    Column("expires_at", UtcDateTime, nullable=False),
    Column("consumed_at", UtcDateTime, nullable=True),
    Index("ix_oidc_login_expires_at", "expires_at"),
)


#: A browser session. The cookie carries a random id; this row carries its
#: SHA-256 and the identity it was established for, so the database never holds
#: a value that could be presented as a session.
#:
#: The claims are copied in rather than referenced, because the point of a
#: session is that the provider is not consulted on every request. It expires;
#: it can be revoked; and it is not a token -- no `id_token` is stored, so
#: there is nothing here to steal that is useful anywhere else.
user_session = Table(
    "user_session",
    metadata,
    Column("seq", Sequence64, primary_key=True, autoincrement=True),
    Column("session_id_hash", String(64), nullable=False, unique=True),
    Column("subject", String(255), nullable=False),
    Column("issuer", String(512), nullable=False),
    Column("roles", JsonBlob, nullable=False),
    Column("display_name", String(255), nullable=True),
    Column("created_at", UtcDateTime, nullable=False),
    Column("expires_at", UtcDateTime, nullable=False),
    Column("last_seen_at", UtcDateTime, nullable=False),
    Column("revoked_at", UtcDateTime, nullable=True),
    Index("ix_user_session_subject", "subject"),
    Index("ix_user_session_expires_at", "expires_at"),
)


#: Who may touch which bank connection, and how much.
#:
#: This is the whole of what a `member` holds. The identity provider says who
#: someone is and whether they administer the deployment; everything else is a
#: row here, which is what makes access something this deployment can grant and
#: **revoke** rather than something that lives in a directory nobody here
#: operates.
#:
#: `subject` is the provider's `sub` claim, verbatim and unresolved. There is
#: deliberately no user table beside it: a second store of identity is a second
#: place a departed employee has to be removed from, and the one this service
#: needs to be able to remove them from is this one.
#:
#: `level` is `viewer` or `operator` and is the reason a grant is not a boolean:
#: seeing a bank and moving money at it are separate answers.
#:
#: The unique constraint is the model. One subject holds at most one level on
#: one connection, so granting again is a change of level rather than a second
#: row somebody has to notice, and revoking is one delete rather than a loop
#: that can leave one behind.
connection_grant = Table(
    "connection_grant",
    metadata,
    Column("seq", Sequence64, primary_key=True, autoincrement=True),
    Column("grant_id", String(36), nullable=False, unique=True),
    Column("subject", String(255), nullable=False),
    Column("connection_id", String(64),
           ForeignKey("bank_connection.connection_id", ondelete="CASCADE"),
           nullable=False),
    Column("level", String(16), nullable=False),
    # Who granted it, so the trail on a connection answers "why does this
    # person have this" without leaving the page. The audit row is the record;
    # this is the current fact.
    Column("granted_by", String(255), nullable=False),
    Column("created_at", UtcDateTime, nullable=False),
    Column("updated_at", UtcDateTime, nullable=False),
    UniqueConstraint("subject", "connection_id",
                     name="uq_connection_grant_subject_connection_id"),
    Index("ix_connection_grant_subject", "subject"),
    Index("ix_connection_grant_connection_id", "connection_id"),
)


#: Deployment-wide read-only oversight: one row per subject, and no connection.
#:
#: The table that lets somebody review **who can move money at which bank**
#: without being able to do either. It carries every scope named `:read`, on
#: every connection and on the audit rows that name none -- the sign-ins, the
#: service starts, and the grants themselves.
#:
#: **There is no `connection_id` column, and that is the design.** The obvious
#: alternative was a nullable `connection_id` on `connection_grant` with `NULL`
#: meaning *everywhere*, which is exactly the shape `webhook_subscription` has
#: and exactly the shape a member is deliberately kept away from: a single
#: field away from a per-connection grant, unenforceable by a unique constraint
#: (`NULL` is distinct from `NULL` on both backends), and a `level` column that
#: would then have to reject one of its own values. A separate table has no
#: field to clear and no level to mis-set.
#:
#: **There is no `level` column either.** Oversight is one thing or it is
#: absent; a levelled oversight grant would be a write privilege spanning every
#: connection, which is an administrator.
oversight_grant = Table(
    "oversight_grant",
    metadata,
    Column("seq", Sequence64, primary_key=True, autoincrement=True),
    Column("grant_id", String(36), nullable=False, unique=True),
    # Unique, not indexed-and-hoped: one subject holds oversight or does not,
    # so issuing it twice is idempotent rather than two rows to revoke.
    Column("subject", String(255), nullable=False, unique=True),
    Column("granted_by", String(255), nullable=False),
    Column("created_at", UtcDateTime, nullable=False),
)


#: One key-lifecycle operation the operator console asked the worker to perform.
#:
#: The console runs in the API process, which by construction cannot open a
#: private key. Every step of INI/HIA/HPB needs one, so the UI does not perform
#: key operations -- it **requests** them, and this table is the request. A
#: browser click therefore cannot cause a decryption in the process that
#: handled the click; it can only cause a row to appear that another process
#: picks up.
#:
#: ``params`` carries what the operator supplied -- the fingerprints they read
#: off the bank's letter, the reason for a suspension -- and ``result`` what the
#: worker found. Both go through the same redaction as an audit detail, and
#: neither ever holds key material: the fingerprints are public values, which is
#: the whole reason the comparison can be made on a read-only screen.
key_job = Table(
    "key_job",
    metadata,
    Column("seq", Sequence64, primary_key=True, autoincrement=True),
    Column("job_id", String(36), nullable=False, unique=True),
    Column("connection_id", String(64),
           ForeignKey("bank_connection.connection_id"), nullable=False),
    # `create_keys`, `send_ini`, `send_hia`, `fetch_hpb`, `confirm_bank_keys`,
    # `decline_bank_keys`, `renew_key`, `suspend_keys`.
    Column("action", String(32), nullable=False),
    Column("params", JsonBlob, nullable=False, server_default="{}"),
    # queued | running | done | failed
    Column("state", String(16), nullable=False),
    # Who asked. A key operation is the one thing in this service that a named
    # human is always behind, so the actor is on the row and not only in the
    # audit trail -- the console shows it beside the outcome.
    Column("requested_by_type", String(32), nullable=False),
    Column("requested_by_id", String(255), nullable=False),
    Column("worker_id", String(64), nullable=True),
    Column("claimed_at", UtcDateTime, nullable=True),
    Column("attempts", Integer, nullable=False, server_default="0"),
    Column("result", JsonBlob, nullable=True),
    Column("return_code", String(16), nullable=True),
    Column("report_text", String(1024), nullable=True),
    Column("last_error", String(512), nullable=True),
    Column("created_at", UtcDateTime, nullable=False),
    Column("updated_at", UtcDateTime, nullable=False),
    Column("finished_at", UtcDateTime, nullable=True),
    Index("ix_key_job_connection_id", "connection_id"),
    Index("ix_key_job_state", "state"),
)


#: A local account, for the deployments that have no identity provider. It is
#: the ``basic`` authentication mode's answer to the one question OIDC answers
#: everywhere else: *who is this*.
#:
#: **The row carries a role and no scopes.** Everything a caller may touch is
#: still a grant in `connection_grant` and `oversight_grant`, read per request,
#: exactly as it is for a token or a session. This table replaces the identity
#: provider and nothing else, which is why there is no `level`, no
#: `connection_id` and no scope column here to disagree with the model.
#:
#: **`password_hash` is an Argon2id encoded hash**, salt and parameters
#: included, in the `$argon2id$v=19$m=...` form the verifier reads them back
#: out of. There is no separate salt column and no separate parameter column
#: for the same reason there is no plaintext one: the format already carries
#: them, and a second copy is the one that goes stale when the cost is raised.
basic_account = Table(
    "basic_account",
    metadata,
    Column("seq", Sequence64, primary_key=True, autoincrement=True),
    # The subject, and therefore the audit `actor_id` and the key every grant
    # names. Unique because a second account with the same name would be a
    # second person holding one person's grants.
    Column("subject", String(255), nullable=False, unique=True),
    Column("display_name", String(255), nullable=True),
    # `admin` or `member` -- `painfree.identity.Role`, the same two names the
    # roles claim maps onto. Stored as its value rather than as a boolean so a
    # third role, if there is ever one, is a migration and not a schema change.
    Column("role", String(16), nullable=False),
    Column("password_hash", String(255), nullable=False),
    # Set when the account is suspended without being deleted, which is what an
    # administrator wants when somebody is on leave or under investigation:
    # the grants stay, the login stops.
    Column("disabled_at", UtcDateTime, nullable=True),
    Column("created_at", UtcDateTime, nullable=False),
    Column("created_by", String(255), nullable=False),
    Column("updated_at", UtcDateTime, nullable=False),
    # When the password last changed. Shown to an administrator, and the reason
    # a stale password is a fact rather than a guess. Never *what* it changed to.
    Column("password_changed_at", UtcDateTime, nullable=False),
    Index("ix_basic_account_role", "role"),
)


#: Failed sign-ins, counted, and the lockout they produce. One row per thing
#: being counted: an account name, or a source address.
#:
#: **An unknown account name gets a counter too.** Otherwise the lockout would
#: be the account oracle the password check is careful not to be -- five wrong
#: guesses at a real name would start answering differently from five wrong
#: guesses at an invented one. The cost is rows for names nobody has, which are
#: purged once their window has passed.
#:
#: The two scopes have different thresholds and that is the point of having two.
#: An account is one person and five failures is a lot; a source address is an
#: office, and locking everybody in it out because one of them mistyped is an
#: outage this service caused.
#: The operator's confirmation that they hold a copy of the custody secret.
#:
#: One row, or none. It exists because the most destructive thing a deployment
#: can lose was named in exactly one place -- a block of stderr from a
#: provisioning script, printed once, at the moment nothing is at stake yet --
#: and because key generation is the point at which that stops being true.
#:
#: **No secret is here and none can be.** The process serving the console cannot
#: read the custody secret; what it can read is which key id the sealed rows
#: name, which is a hash and is safe to store. That is what `key_id` records: an
#: acknowledgement made against one custody key does not carry over to the key a
#: rotation replaces it with.
custody_acknowledgement = Table(
    "custody_acknowledgement",
    metadata,
    Column("seq", Sequence64, primary_key=True, autoincrement=True),
    # The custody key the acknowledgement was made against, or NULL when it was
    # made before any key existed -- which is the ordinary case, because the
    # point is to confirm the backup *before* the first key is generated.
    Column("key_id", String(32), nullable=True),
    Column("acknowledged_at", UtcDateTime, nullable=False),
    Column("acknowledged_by", String(255), nullable=False),
)


basic_lockout = Table(
    "basic_lockout",
    metadata,
    Column("seq", Sequence64, primary_key=True, autoincrement=True),
    # `subject` or `source`. Not two tables, because "who is locked out" is one
    # question an administrator asks and one page has to answer it.
    Column("scope", String(16), nullable=False),
    Column("value", String(255), nullable=False),
    Column("failures", Integer, nullable=False),
    Column("first_failure_at", UtcDateTime, nullable=False),
    Column("last_failure_at", UtcDateTime, nullable=False),
    # Null until the threshold is crossed. A lockout expires by itself and can
    # be cleared by an administrator before it does -- the row is deleted in
    # that case rather than back-dated, so the trail of it is the audit log's
    # and not a column somebody has to interpret.
    Column("locked_until", UtcDateTime, nullable=True),
    UniqueConstraint("scope", "value", name="uq_basic_lockout_scope_value"),
    Index("ix_basic_lockout_locked_until", "locked_until"),
)


__all__ = [
    "JsonBlob",
    "Money",
    "NAMING_CONVENTION",
    "Sequence64",
    "UtcDateTime",
    "audit_log",
    "bank_connection",
    "basic_account",
    "basic_lockout",
    "connection_grant",
    "download_run",
    "download_schedule",
    "key_job",
    "key_material",
    "metadata",
    "oidc_login",
    "oversight_grant",
    "payment_attempt",
    "payment_order",
    "statement",
    "user_session",
    "webhook_delivery",
    "webhook_subscription",
    "webhook_wrapping_key",
]
