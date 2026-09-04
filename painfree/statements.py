"""Ingesting downloaded documents: unpack, normalise, and store exactly once.

The last third of a download. The worker has the decrypted order data; this
turns it into rows.

**Banks re-serve, so ingestion has to be idempotent.** Three ordinary things
make the same statement arrive twice: a download that was not acknowledged is
offered again on the next run, a worker that stored the documents and died
before sending the receipt gets the whole file again, and an operator replaying
a window asks for days that were already fetched. None of those is an error and
none of them may produce a second row. So the identity of a document is
computed, a unique constraint on ``(connection_id, document_key)`` enforces it,
and a re-ingestion is the ``IntegrityError`` this module catches and counts --
not a ``SELECT`` in front of an ``INSERT``, which two workers both pass.

**The identity is the document's, not the download's.** `camt` gives every
statement an `Id` that is unique per account, and `pain.002` names the `MsgId`
it reports on; those, with the account and the message type, are what a
statement *is*. Hashing the bytes instead would make a bank that re-sends the
same statement with a new `CreDtTm` look like a new one -- which is exactly the
duplicate this exists to prevent. The content hash is stored beside the key
anyway, so the other case stays visible: same identity, different content is a
bank amending a statement, and that is worth a warning rather than a silent
first-wins.

A `pain.002` needs **both** of its identifications, because a bank answers one
`pain.001` more than once: `PDNG` today, `ACSC` tomorrow. Keyed on the reported
`MsgId` alone the second report would be filed as a re-serve of the first and
the final status would never be stored -- so the report's own `MsgId` joins the
key. A re-served *copy* of one report still carries the same pair and is still
one row.

**A `pain.002` is also reconciled here, because ingesting one is what
reconciling one is.** The order it names is resolved before the insert, so
``statement.order_id`` lands in the same row, and the order is moved after it
by :mod:`painfree.reconcile`. A reconciliation that raises is logged with its
trace and the loop continues: the download it belongs to has other documents
in it, and losing them to re-fetch one report is the worse trade.

**Statement content never reaches the log stream.** An entry is somebody's
payment: a counterparty name, an amount, a reference. The log lines and audit
rows here carry the `statement_id`, the message type, the counts and the run --
references, the way payment payloads are logged everywhere else. The content
goes to the database, which is what it is for.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import io
import uuid
import zipfile
from dataclasses import dataclass, field
from typing import Any, Sequence

from sqlalchemy import Engine, func, select
from sqlalchemy.exc import IntegrityError

from painfree.audit import AuditLog
from painfree.camt import CONTAINERS, normalise_camt
from painfree.isoxml import DocumentUnreadable, iso_document, local, message_type_of
from painfree.logging import bind, get_logger
from painfree.pain002 import CONTAINER as PAIN002_CONTAINER
from painfree.pain002 import normalise_pain002
from painfree.reconcile import PAYMENT_STATUS, StatusReconciler, resolve
from painfree.schema import statement

log = get_logger("painfree.statements")

STATEMENT_ID_PREFIX = "stm_"

#: The two kinds of document this table holds, as the prefix of the message
#: type the document's own namespace gave it. `camt` is an account's own
#: history; `pain.002` is a bank answering something this service sent. They
#: share a table and a route and nothing else.
ACCOUNTS = "account"
RESPONSES = "response"
FAMILIES: dict[str, str] = {ACCOUNTS: "camt.%", RESPONSES: "pain.002%"}


def _of_family(query: Any, family: str | None) -> Any:
    """Narrow a statement query to one family, or leave it alone."""
    pattern = FAMILIES.get(family or "")
    return query.where(statement.c.message_type.like(pattern)) if pattern \
        else query

#: The local part of a ZIP file's magic. A BTF may declare
#: ``Container containerType="ZIP"`` and a bank then packs one archive of one
#: document per day; sniffing the bytes rather than trusting the declaration
#: means a bank that sends a bare document under a ZIP container -- or the
#: reverse -- is still read.
ZIP_MAGIC = b"PK\x03\x04"

#: A downloaded archive is bank output, not user upload, but it is still
#: untrusted input arriving over a network. Two caps, so a malformed or hostile
#: archive is a refusal rather than a filled disk.
MAX_MEMBERS = 1000
MAX_MEMBER_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class IngestResult:
    """What one download produced, counted rather than described."""

    stored: int = 0
    duplicates: int = 0
    unreadable: int = 0
    statement_ids: list[str] = field(default_factory=list)

    @property
    def statements(self) -> int:
        """Every statement this download accounted for, new or already held."""
        return self.stored + self.duplicates + self.unreadable


def unpack(order_data: bytes) -> list[bytes]:
    """One download's order data as a list of documents.

    A `camt` download is usually a ZIP -- one archive holding one statement per
    day -- and occasionally a bare XML document. Both are handled here so
    nothing downstream has to ask which it got.
    """
    if not order_data.startswith(ZIP_MAGIC):
        return [order_data]
    try:
        with zipfile.ZipFile(io.BytesIO(order_data)) as archive:
            members = [info for info in archive.infolist() if not info.is_dir()]
            if len(members) > MAX_MEMBERS:
                raise DocumentUnreadable(
                    f"the archive holds {len(members)} members, more than the "
                    f"{MAX_MEMBERS} this service will unpack")
            documents = []
            for info in members:
                if info.file_size > MAX_MEMBER_BYTES:
                    raise DocumentUnreadable(
                        f"archive member {info.filename!r} declares "
                        f"{info.file_size} bytes")
                documents.append(archive.read(info))
    except zipfile.BadZipFile as exc:
        raise DocumentUnreadable(f"the order data is not a readable ZIP: {exc}") from exc
    return documents


def normalise(document: bytes) -> list[Any]:
    """Read one document, whichever of the four message families it is.

    Dispatch is on the container element rather than on the message type
    string, so a version this service has not seen is read by the parser that
    knows its shape instead of refused for its digits.
    """
    root = iso_document(document)
    message_type = message_type_of(root)
    for child in root:
        if not isinstance(child.tag, str):
            continue
        if local(child) in CONTAINERS:
            return normalise_camt(root)
        if local(child) == PAIN002_CONTAINER:
            return normalise_pain002(root)
    raise DocumentUnreadable(
        f"{message_type} is not a camt.052/053/054 or pain.002 document")


def document_key(connection_id: str, normalised: Any, content_hash: str) -> str:
    """What makes two downloaded documents the same document.

    The account, the message type and the identification the document gives
    itself -- and, for a `pain.002`, the report's own `MsgId` as well, because
    one order gets several reports and they are not each other's duplicates.
    A document with no identification -- which the schema permits and no bank
    should send -- falls back to the hash of its bytes, so it is still ingested
    once per distinct file rather than once per download.
    """
    if not normalised.identification:
        return hashlib.sha256(
            f"{connection_id}\x00{normalised.message_type}\x00{content_hash}"
            .encode()).hexdigest()
    parts = [connection_id, normalised.message_type, normalised.iban or "",
             normalised.identification, normalised.sequence_number or ""]
    # Appended only where there is one, so a `camt` document's identity is the
    # value it always had: a schema change that re-keyed every stored statement
    # would turn one migration into a table of duplicates.
    if normalised.report_identification:
        parts.append(normalised.report_identification)
    return hashlib.sha256("\x00".join(parts).encode()).hexdigest()


class StatementStore:
    """Writes ``statement``. One insert per document, one transaction each.

    Per document rather than per download on purpose: on PostgreSQL a failed
    ``INSERT`` aborts the transaction it is in, so batching would make the
    first duplicate discard every statement after it -- the opposite of what a
    re-served file needs.
    """

    __slots__ = ("_engine", "_audit", "_reconciler")

    def __init__(self, engine: Engine, audit: AuditLog | None = None) -> None:
        self._engine = engine
        self._audit = audit or AuditLog(engine)
        self._reconciler = StatusReconciler(engine, self._audit)

    @property
    def reconciler(self) -> StatusReconciler:
        """The status reconciler, so a reader can ask it what answers an order."""
        return self._reconciler

    def ingest(self, connection_id: str, documents: list[bytes], *,
               run_id: str | None = None) -> IngestResult:
        """Normalise and store every document of one download."""
        stored: list[str] = []
        duplicates = 0
        unreadable = 0
        for document in documents:
            content_hash = hashlib.sha256(document).hexdigest()
            try:
                normalised = normalise(document)
            except DocumentUnreadable as exc:
                # Logged where it is caught, with the trace, and counted. One
                # unreadable member of an archive must not lose the others.
                log.exception("statement.unreadable", run_id=run_id,
                              content_hash=content_hash, bytes=len(document),
                              reason=str(exc))
                unreadable += 1
                continue
            for one in normalised:
                statement_id = self._store(connection_id, one, content_hash,
                                           run_id=run_id)
                if statement_id is None:
                    duplicates += 1
                else:
                    stored.append(statement_id)
        return IngestResult(stored=len(stored), duplicates=duplicates,
                            unreadable=unreadable, statement_ids=stored)

    def get(self, statement_id: str) -> dict[str, Any] | None:
        with self._engine.connect() as connection:
            row = connection.execute(
                select(statement)
                .where(statement.c.statement_id == statement_id)
            ).mappings().one_or_none()
        return dict(row) if row else None

    def recent(self, *, connection_id: str | None = None,
               connection_ids: Sequence[str] | None = None,
               message_type: str | None = None,
               family: str | None = None,
               limit: int = 50) -> list[dict[str, Any]]:
        """Ingested statements, newest first, without their payloads.

        The payload is deliberately not in the list: an entry is somebody's
        payment, and a hundred of them on an index page is a hundred more
        places for a screenshot to leak one. :meth:`get` returns it for the one
        statement an operator opened.

        ``family`` narrows to one of the two kinds of document this table
        holds, by the message type the document's own namespace gave it. They
        answer different questions and an index that lists both has a closing
        balance column that is empty for half its rows.
        """
        query = (select(statement.c.statement_id, statement.c.connection_id,
                        statement.c.order_id,
                        statement.c.message_type, statement.c.identification,
                        statement.c.sequence_number, statement.c.iban,
                        statement.c.currency, statement.c.entry_count,
                        statement.c.opening_balance, statement.c.closing_balance,
                        statement.c.from_datetime, statement.c.to_datetime,
                        statement.c.ingested_at, statement.c.run_id)
                 .order_by(statement.c.seq.desc()))
        if connection_id:
            query = query.where(statement.c.connection_id == connection_id)
        if connection_ids is not None:
            # Which connections this caller may see at all.
            query = query.where(
                statement.c.connection_id.in_(list(connection_ids)))
        if message_type:
            query = query.where(statement.c.message_type == message_type)
        query = _of_family(query, family)
        with self._engine.connect() as connection:
            rows = connection.execute(
                query.limit(max(1, min(limit, 500)))).mappings().all()
        return [dict(row) for row in rows]

    def responses(self, *, connection_ids: Sequence[str] | None = None,
                  connection_id: str | None = None,
                  message_type: str | None = None,
                  limit: int = 50) -> list[dict[str, Any]]:
        """Status reports, newest first, each resolved to what it said.

        This one **does** read payloads, and the rule above is why it is a
        separate method rather than a flag: what it takes out of them is the
        status, the counts and the bank's reason, which is what the reconciler
        already writes to the audit log and the webhook envelope. No amount and
        no counterparty reaches the index.
        """
        query = (select(statement.c.statement_id, statement.c.connection_id,
                        statement.c.order_id, statement.c.message_type,
                        statement.c.identification, statement.c.ingested_at,
                        statement.c.payload)
                 .order_by(statement.c.seq.desc()))
        if connection_id:
            query = query.where(statement.c.connection_id == connection_id)
        if connection_ids is not None:
            query = query.where(
                statement.c.connection_id.in_(list(connection_ids)))
        if message_type:
            query = query.where(statement.c.message_type == message_type)
        query = _of_family(query, RESPONSES)
        with self._engine.connect() as connection:
            rows = connection.execute(
                query.limit(max(1, min(limit, 500)))).mappings().all()
        return [{name: value for name, value in row.items() if name != "payload"}
                | {"outcome": resolve(row["payload"] or {})} for row in rows]

    def message_types(self) -> list[str]:
        """The distinct message types held, so a filter offers what exists."""
        with self._engine.connect() as connection:
            return sorted(row[0] for row in connection.execute(
                select(statement.c.message_type).distinct()))

    def counts_by_family(self, *, connection_ids: Sequence[str] | None = None,
                         connection_id: str | None = None,
                         message_type: str | None = None) -> dict[str, int]:
        """How many documents of each kind the filters in force would show.

        On the tabs, so an operator can see that the other half has something in
        it without going and looking. Counted under the *same* filters as the
        table below, or the number would be about a page nobody is on.
        """
        found = {}
        with self._engine.connect() as connection:
            for family in FAMILIES:
                query = select(func.count()).select_from(statement)
                if connection_id:
                    query = query.where(
                        statement.c.connection_id == connection_id)
                if connection_ids is not None:
                    query = query.where(
                        statement.c.connection_id.in_(list(connection_ids)))
                if message_type:
                    query = query.where(
                        statement.c.message_type == message_type)
                found[family] = connection.execute(
                    _of_family(query, family)).scalar_one()
        return found

    def count(self, connection_id: str) -> int:
        with self._engine.connect() as connection:
            return connection.execute(
                select(func.count()).select_from(statement)
                .where(statement.c.connection_id == connection_id)).scalar_one()

    # --- one document ------------------------------------------------------

    def _store(self, connection_id: str, normalised: Any, content_hash: str, *,
               run_id: str | None) -> str | None:
        """Insert one statement. ``None`` when the database already had it."""
        key = document_key(connection_id, normalised, content_hash)
        statement_id = STATEMENT_ID_PREFIX + uuid.uuid4().hex
        now = _dt.datetime.now(_dt.timezone.utc)
        # Resolved before the insert so the join is in the row from the start.
        # ``None`` is a legitimate answer: a status report for a `MsgId` this
        # service never sent is stored with no order on it, not dropped.
        order_id = (self._reconciler.order_for(connection_id, normalised.payload)
                    if normalised.kind == PAYMENT_STATUS else None)
        values = {
            "statement_id": statement_id,
            "connection_id": connection_id,
            "run_id": run_id,
            "order_id": order_id,
            "message_type": normalised.message_type,
            "document_key": key,
            "content_hash": content_hash,
            "identification": normalised.identification,
            "sequence_number": normalised.sequence_number,
            "iban": normalised.iban,
            "currency": normalised.currency,
            "entry_count": normalised.entry_count,
            "created_at": normalised.created_at,
            "from_datetime": normalised.from_datetime,
            "to_datetime": normalised.to_datetime,
            "opening_balance": normalised.opening_balance,
            "closing_balance": normalised.closing_balance,
            "payload": normalised.payload,
            "ingested_at": now,
        }
        try:
            with self._engine.begin() as connection:
                connection.execute(statement.insert().values(**values))
        except IntegrityError:
            self._duplicate(connection_id, key, content_hash, normalised, run_id)
            return None

        with bind(connection_id=connection_id, job_id=run_id):
            # References only: the entries are somebody's payments.
            self._audit.record(
                "statement.available", connection_id=connection_id,
                detail={"statement_id": statement_id,
                        "message_type": normalised.message_type,
                        "kind": normalised.kind,
                        "entries": normalised.entry_count,
                        "run_id": run_id},
            )
            log.info("statement.ingested", statement_id=statement_id,
                     message_type=normalised.message_type, kind=normalised.kind,
                     entries=normalised.entry_count, run_id=run_id,
                     order_id=order_id)
        if normalised.kind == PAYMENT_STATUS:
            self._reconcile(connection_id, statement_id, order_id,
                            normalised.payload, run_id)
        return statement_id

    def _reconcile(self, connection_id: str, statement_id: str,
                   order_id: str | None, payload: dict[str, Any],
                   run_id: str | None) -> None:
        """Move the order this report answers, without losing the download.

        The statement is already committed when this runs, so a failure here
        cannot cost the document. It can cost the *transition*, which is why it
        is logged with its trace under an id an operator can grep rather than
        raised into the download loop, where it would abandon every remaining
        document of the run and leave the receipt unsent.
        """
        try:
            self._reconciler.reconcile(
                connection_id=connection_id, statement_id=statement_id,
                order_id=order_id, payload=payload, run_id=run_id)
        except Exception:
            log.exception("payment.status_reconcile_failed",
                          statement_id=statement_id, order_id=order_id,
                          connection_id=connection_id, run_id=run_id)

    def _duplicate(self, connection_id: str, key: str, content_hash: str,
                   normalised: Any, run_id: str | None) -> None:
        """Say which of the two duplicates this is: a re-serve, or an amendment."""
        with self._engine.connect() as connection:
            existing = connection.execute(
                select(statement.c.statement_id, statement.c.content_hash)
                .where(statement.c.connection_id == connection_id,
                       statement.c.document_key == key)).mappings().one_or_none()
        fields = {"statement_id": existing["statement_id"] if existing else None,
                  "message_type": normalised.message_type, "run_id": run_id}
        with bind(connection_id=connection_id, job_id=run_id):
            if existing is not None and existing["content_hash"] != content_hash:
                # The identity is the same and the bytes are not. The first
                # version is kept -- overwriting a stored statement is a
                # decision an operator should make, not a parser -- and the
                # fact is a warning rather than a silence.
                log.warning("statement.amended", stored_content_hash=existing["content_hash"],
                            content_hash=content_hash, **fields)
                return
            log.info("statement.duplicate", content_hash=content_hash, **fields)


__all__ = ["IngestResult", "MAX_MEMBERS", "MAX_MEMBER_BYTES", "STATEMENT_ID_PREFIX",
           "StatementStore", "ZIP_MAGIC", "document_key", "normalise", "unpack"]
