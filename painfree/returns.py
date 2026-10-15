"""Finding the booking that brought an order's money back, and closing the order.

The `camt` counterpart of :mod:`painfree.reconcile`. A status report answers a
`pain.001` by naming its `MsgId`; a statement does not answer anything, it books
movements. Most of them are none of this service's business. One kind is: a
**credit that returns the money of an order this service sent**. That makes the
order `returned`.

**Only deterministic evidence moves an order here.** A booked credit counts as
a return when the bank says so in the document -- `RtrInf` on the transaction,
`RvslInd` on the entry, or a `RRTN` sub-family in its bank transaction code --
*and* it names one of our orders by a reference this service generated or the
caller chose:

* `MsgId`, live or of any earlier attempt, as :mod:`painfree.reconcile` reads it;
* `PmtInfId`, which this service generates per message;
* `EndToEndId`, which the caller chose and which is therefore not unique. It
  counts only among this connection's open orders, only when exactly one of
  their transfers carries it, and never when it is `NOTPROVIDED`.

**A return has to cover the whole order.** The amount and currency must be the
order's control sum and currency. A booking that returns one transfer of a
batch is a partial return: audited as ``payment.return_partial``, with no state
change, because most of the batch did arrive and `returned` would say it had
not.

**Idempotent the way the reconciler is.** One conditional ``UPDATE`` whose
``WHERE`` names :data:`RETURNS_FROM`. The same booking in a `camt.052` and then
in the `camt.053` moves the order once and owes one event.

**References only reach the event.** The statement, the entry's bank reference,
the bank's reason. Never an amount, never a counterparty.

**What the bank does not mark is only a suspicion.** Some banks book a return
as an ordinary credit with a sentence in it -- SGKB writes *"Rueckleitung Ihrer
Zahlung vom ..."* under `PMNT/RCDT/DMCT`, with a new `MsgId` and no reference
to ours. That is recognisable, and not provable. So a credit like that raises a
**suspected return** on the order and sends ``order.return_suspected``, and a
person confirms it -- which writes `returned` with ``matched_by: operator`` --
or dismisses it. It is raised only when *all* of these hold:

* the statement is from a bank in :data:`SUSPECT_PATTERNS`, by the clearing
  number in the account's IBAN or the servicer's BIC, and the booking's text
  matches that bank's sentence;
* the credit comes *from* the creditor of one open, single-transfer order on
  the same connection, for that order's amount and currency;
* it was booked within :data:`SUSPECT_WINDOW` of the order's execution date.
"""

from __future__ import annotations

import datetime as _dt
import decimal
import re
from dataclasses import dataclass
from typing import Any, Sequence

from sqlalchemy import Engine, select

from painfree.audit import FAILURE, SUCCESS, SYSTEM_ACTOR, Actor, AuditLog
from painfree.errors import ConflictError, NotFoundError
from painfree.isoxml import datetime_utc
from painfree.logging import bind, get_logger
from painfree.orders import OrderState, scheme_fields
from painfree.pain001 import NOT_PROVIDED
from painfree.painread import summarise
from painfree.schema import payment_attempt, payment_order

log = get_logger("painfree.returns")

#: The states a returning booking may move an order out of. ``acknowledged``
#: is the ordinary one. ``submitted`` is here because a bank may book the
#: return before it sends the status report, and a return is proof enough that
#: the bank took the payment.
RETURNS_FROM = (OrderState.SUBMITTED.value, OrderState.ACKNOWLEDGED.value)

#: How far before a booking an order it returns may have been accepted. Bounds
#: the `EndToEndId` search, which has to read stored documents.
LOOKBACK = _dt.timedelta(days=120)

#: How the booking was tied to the order, as ``return_matched_by`` stores it.
RTRINF = "rtrinf"
REVERSAL = "reversal"
#: A person confirmed a suspected return the documents could not prove.
OPERATOR = "operator"
MATCHED_BY = (RTRINF, REVERSAL, OPERATOR)

#: How long after an order's execution date a booking may still be its return.
SUSPECT_WINDOW = _dt.timedelta(days=14)


@dataclass(frozen=True, slots=True)
class BankPattern:
    """How one bank words a return it does not mark as one.

    Matched against the statement rather than the connection's EBICS settings:
    ``clearing`` is the IID in positions 5-9 of a Swiss or Liechtenstein IBAN,
    which every statement carries for its own account, and ``bics`` is the
    account servicer's BIC, which most do.
    """

    bank: str
    clearing: tuple[str, ...]
    bics: tuple[str, ...]
    sentence: re.Pattern[str]

    def covers(self, account: dict[str, Any]) -> bool:
        iban = (account.get("iban") or "").replace(" ", "").upper()
        if iban[:2] in ("CH", "LI") and iban[4:9] in self.clearing:
            return True
        bic = (account.get("servicer_bic") or "").upper()
        return any(bic.startswith(prefix) for prefix in self.bics)


#: Every bank whose unmarked returns this service recognises. Added to one
#: bank at a time, from a booking that bank actually sent, with a test that
#: carries that booking's shape.
SUSPECT_PATTERNS: tuple[BankPattern, ...] = (
    # St.Galler Kantonalbank, issue #1: `PMNT/RCDT/DMCT`, a new `MsgId`, no
    # `EndToEndId`, and "Rueckleitung Ihrer Zahlung vom 14.10.2026.,
    # Referenznummer ... Beguenstigter unbekannt / ungenau" in `AddtlNtryInf`.
    BankPattern(bank="SGKB", clearing=("00781",), bics=("KBSGCH",),
                sentence=re.compile(r"r(?:ue|ü)ckleitung\s+ihrer\s+zahlung",
                                    re.IGNORECASE)),
)

MAX_TEXT = 1024


@dataclass(frozen=True, slots=True)
class Evidence:
    """One booked credit the bank marked as a return, and what it names."""

    entry: dict[str, Any]
    transaction: dict[str, Any]
    matched_by: str
    reason_code: str | None
    reason_text: str | None
    amount: str | None
    currency: str | None

    @property
    def entry_ref(self) -> str | None:
        return (self.entry.get("account_servicer_reference")
                or self.entry.get("reference"))

    @property
    def booked_at(self) -> _dt.datetime | None:
        return datetime_utc(self.entry.get("booking_date"))


def evidence(payload: dict[str, Any]) -> list[Evidence]:
    """Every booked credit in one normalised statement the bank calls a return.

    Pure; no database. An entry with no transaction details is read as one
    transaction carrying the entry's own amount, because a bank that books a
    return without details has still said it is one.
    """
    found = []
    for entry in payload.get("entries") or ():
        if entry.get("credit_debit") != "credit":
            continue
        if entry.get("status") not in (None, "BOOK"):
            continue
        code = entry.get("bank_transaction_code") or {}
        flagged = bool(entry.get("reversal")) or code.get("sub_family") == "RRTN"
        transactions = entry.get("transactions") or [
            {"amount": entry.get("amount"), "currency": entry.get("currency")}]
        for transaction in transactions:
            info = transaction.get("return_information")
            if info is None and not flagged:
                continue
            code_, text = _reason(info, entry)
            single = len(transactions) == 1
            found.append(Evidence(
                entry=entry, transaction=transaction,
                matched_by=RTRINF if info is not None else REVERSAL,
                reason_code=code_, reason_text=text,
                amount=transaction.get("amount")
                or (entry.get("amount") if single else None),
                currency=transaction.get("currency")
                or (entry.get("currency") if single else None)))
    return found


def _reason(info: dict[str, Any] | None,
            entry: dict[str, Any]) -> tuple[str | None, str | None]:
    """The bank's reason code and its words, from `RtrInf` or the entry."""
    code = None
    words: list[str] = []
    if info:
        code = info.get("reason_code") or info.get("reason_proprietary")
        words = list(info.get("additional_information") or ())
    if not words and entry.get("additional_information"):
        words = [entry["additional_information"]]
    text = " ".join(" ".join(words).split()) or None
    if text and len(text) > MAX_TEXT:
        text = text[:MAX_TEXT - 1] + "…"
    return code, text


class ReturnMatcher:
    """Ties a returning booking to its order and moves the order once.

    Constructed by :class:`painfree.statements.StatementStore`, which calls it
    for every `camt` document it stores and for every one an operator asks to
    be read again.
    """

    __slots__ = ("_engine", "_audit")

    def __init__(self, engine: Engine, audit: AuditLog | None = None) -> None:
        self._engine = engine
        self._audit = audit or AuditLog(engine)

    def match(self, *, connection_id: str, statement_id: str,
              payload: dict[str, Any], replay: bool = False) -> list[str]:
        """Apply every return one stored statement books. Returns orders moved.

        Suspected returns are raised as well, and are not in the list: nothing
        about the order moved.
        """
        moved = []
        self._suspect(connection_id, statement_id, payload, replay)
        for one in evidence(payload):
            order = self._order_for(connection_id, one)
            if order is None:
                continue
            with bind(order_id=order["order_id"], connection_id=connection_id):
                if not _whole(one, order):
                    if not replay:
                        self._partial(connection_id, statement_id, one, order)
                    continue
                if self._return(connection_id, statement_id, one, order,
                                payload, replay):
                    moved.append(order["order_id"])
        return moved

    # --- which order --------------------------------------------------------

    def _order_for(self, connection_id: str,
                   one: Evidence) -> dict[str, Any] | None:
        """The order the booking names, by the strongest reference it carries."""
        transaction = one.transaction
        columns = (payment_order.c.order_id, payment_order.c.state,
                   payment_order.c.control_sum, payment_order.c.currency,
                   payment_order.c.idempotency_key,
                   payment_order.c.requested_scheme, payment_order.c.scheme,
                   payment_order.c.scheme_reason)
        with self._engine.connect() as connection:
            msg_id = transaction.get("message_identification")
            if msg_id:
                row = connection.execute(
                    select(*columns).where(
                        payment_order.c.connection_id == connection_id,
                        payment_order.c.msg_id == msg_id)).mappings().first()
                if row is None:
                    row = connection.execute(
                        select(*columns)
                        .join(payment_attempt, payment_attempt.c.order_id
                              == payment_order.c.order_id)
                        .where(payment_order.c.connection_id == connection_id,
                               payment_attempt.c.msg_id == msg_id)
                    ).mappings().first()
                if row is not None:
                    return dict(row)
            information = transaction.get("payment_information_id")
            if information:
                rows = connection.execute(
                    select(*columns).where(
                        payment_order.c.connection_id == connection_id,
                        payment_order.c.payment_information_id == information)
                ).mappings().all()
                if len(rows) == 1:
                    return dict(rows[0])
            end_to_end = transaction.get("end_to_end_id")
            if not end_to_end or end_to_end == NOT_PROVIDED:
                return None
            since = (one.booked_at or _dt.datetime.now(_dt.timezone.utc)) \
                - LOOKBACK
            candidates = connection.execute(
                select(*columns, payment_order.c.document).where(
                    payment_order.c.connection_id == connection_id,
                    payment_order.c.state.in_(RETURNS_FROM),
                    payment_order.c.accepted_at >= since)).mappings().all()
        named = [row for row in candidates
                 if _carries(row["document"], end_to_end)]
        if len(named) != 1:
            if len(named) > 1:
                log.warning("payment.return_ambiguous", end_to_end_id=end_to_end,
                            orders=[row["order_id"] for row in named],
                            reason="several open orders carry this EndToEndId; "
                                   "none is moved")
            return None
        return {name: value for name, value in named[0].items()
                if name != "document"}

    # --- the two endings ---------------------------------------------------

    def _return(self, connection_id: str, statement_id: str, one: Evidence,
                order: dict[str, Any], payload: dict[str, Any],
                replay: bool) -> bool:
        """The conditional ``UPDATE`` that makes a booking seen twice a no-op."""
        now = _dt.datetime.now(_dt.timezone.utc)
        moved = (
            payment_order.update()
            .where(payment_order.c.order_id == order["order_id"],
                   payment_order.c.state.in_(RETURNS_FROM))
            .values(state=OrderState.RETURNED.value,
                    returned_at=one.booked_at or now,
                    return_statement_id=statement_id,
                    return_entry_ref=one.entry_ref,
                    return_reason_code=one.reason_code,
                    return_reason_text=one.reason_text,
                    return_matched_by=one.matched_by,
                    worker_id=None, claimed_at=None, next_attempt_at=None,
                    updated_at=now)
            .returning(payment_order.c.state))
        with self._engine.begin() as connection:
            if connection.execute(moved).one_or_none() is None:
                return False
        detail = {
            "order_state": OrderState.RETURNED.value,
            "previous_state": order["state"],
            "reason_code": one.reason_code, "reason_text": one.reason_text,
            "statement_id": statement_id, "entry_ref": one.entry_ref,
            "booking_date": one.entry.get("booking_date"),
            "matched_by": one.matched_by,
            "source": payload.get("message_type"),
            "rereconciled": True if replay else None,
            **scheme_fields(order["requested_scheme"], order["scheme"],
                            order["scheme_reason"]),
        }
        with bind(idempotency_key=order["idempotency_key"]):
            # The fact and the event commit together.
            self._audit.record(
                "payment.returned", outcome=FAILURE,
                order_id=order["order_id"], connection_id=connection_id,
                idempotency_key=order["idempotency_key"],
                detail={name: value for name, value in detail.items()
                        if value is not None})
            log.warning("payment.state_changed", state="returned",
                        previous_state=order["state"],
                        reason_code=one.reason_code,
                        matched_by=one.matched_by, statement_id=statement_id,
                        source=payload.get("message_type"))
        return True

    def _partial(self, connection_id: str, statement_id: str, one: Evidence,
                 order: dict[str, Any]) -> None:
        """A return of less than the order. Said, not applied."""
        self._audit.record(
            "payment.return_partial", order_id=order["order_id"],
            connection_id=connection_id,
            detail={"applied": False, "statement_id": statement_id,
                    "entry_ref": one.entry_ref, "reason_code": one.reason_code,
                    "matched_by": one.matched_by})
        log.warning("payment.return_partial", statement_id=statement_id,
                    entry_ref=one.entry_ref,
                    reason="the booking returns less than the whole order; "
                           "the order is left as it is")


    # --- suspicions --------------------------------------------------------

    def _suspect(self, connection_id: str, statement_id: str,
                 payload: dict[str, Any], replay: bool) -> None:
        """Raise a suspected return for each unmarked credit that looks like one."""
        patterns = [pattern for pattern in SUSPECT_PATTERNS
                    if pattern.covers(payload.get("account") or {})]
        if not patterns:
            return
        for entry, transaction, words in _unmarked(payload):
            if not any(pattern.sentence.search(words) for pattern in patterns):
                continue
            booked = datetime_utc(entry.get("booking_date"))
            iban = ((transaction.get("counterparty") or {}).get("iban") or "")
            amount = transaction.get("amount") or entry.get("amount")
            currency = transaction.get("currency") or entry.get("currency")
            if not (booked and iban and amount):
                continue
            orders = self._lookalikes(connection_id, iban, amount, currency,
                                      booked)
            if len(orders) != 1:
                if orders:
                    log.warning("payment.return_ambiguous",
                                statement_id=statement_id,
                                orders=[row["order_id"] for row in orders],
                                reason="several open orders look like this "
                                       "booking; no return is suspected")
                continue
            self._raise(connection_id, statement_id, orders[0], entry,
                        _short(words), booked, payload, replay)

    def _lookalikes(self, connection_id: str, iban: str, amount: str,
                    currency: str | None,
                    booked: _dt.datetime) -> list[dict[str, Any]]:
        """Open single-transfer orders to ``iban`` for this amount, near ``booked``."""
        columns = (payment_order.c.order_id, payment_order.c.state,
                   payment_order.c.control_sum, payment_order.c.currency,
                   payment_order.c.idempotency_key,
                   payment_order.c.requested_execution_date,
                   payment_order.c.requested_scheme, payment_order.c.scheme,
                   payment_order.c.scheme_reason, payment_order.c.document,
                   payment_order.c.return_suspected_entry_ref,
                   payment_order.c.return_suspected_at,
                   payment_order.c.return_suspicion_dismissed_at)
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(*columns).where(
                    payment_order.c.connection_id == connection_id,
                    payment_order.c.state.in_(RETURNS_FROM),
                    payment_order.c.transaction_count == 1,
                    payment_order.c.accepted_at >= booked - LOOKBACK,
                    # A booking date is a day; an order accepted later that
                    # same day is still before it.
                    payment_order.c.accepted_at
                    < booked + _dt.timedelta(days=1))).mappings().all()
        found = []
        for row in rows:
            if currency and row["currency"] != currency:
                continue
            if not _same_amount(amount, row["control_sum"]):
                continue
            execution = _day(row["requested_execution_date"])
            if execution is None or not (
                    execution <= booked.date()
                    <= (execution + SUSPECT_WINDOW)):
                continue
            summary = summarise(row["document"])
            creditor = (summary.creditor.iban if summary else None) or ""
            if creditor.replace(" ", "").upper() != iban.replace(" ", "").upper():
                continue
            found.append({name: value for name, value in row.items()
                          if name != "document"})
        return found

    def _raise(self, connection_id: str, statement_id: str,
               order: dict[str, Any], entry: dict[str, Any], words: str,
               booked: _dt.datetime, payload: dict[str, Any],
               replay: bool) -> None:
        """Mark the order suspected, once per booking, and say so."""
        reference = (entry.get("account_servicer_reference")
                     or entry.get("reference"))
        now = _dt.datetime.now(_dt.timezone.utc)
        fresh = (payment_order.c.return_suspected_at.is_(None)
                 | (payment_order.c.return_suspicion_dismissed_at.is_not(None)
                    & (payment_order.c.return_suspected_entry_ref
                       != (reference or ""))))
        raised = (
            payment_order.update()
            .where(payment_order.c.order_id == order["order_id"],
                   payment_order.c.state.in_(RETURNS_FROM), fresh)
            .values(return_suspected_at=now, return_suspected_booked_at=booked,
                    return_suspected_statement_id=statement_id,
                    return_suspected_entry_ref=reference,
                    return_suspected_text=words,
                    return_suspicion_dismissed_at=None, updated_at=now)
            .returning(payment_order.c.order_id))
        with self._engine.begin() as connection:
            if connection.execute(raised).one_or_none() is None:
                return
        detail = {"order_state": order["state"], "statement_id": statement_id,
                  "entry_ref": reference,
                  "booking_date": entry.get("booking_date"),
                  "reason_text": words, "matched_by": "heuristic",
                  "source": payload.get("message_type"),
                  "rereconciled": True if replay else None,
                  **scheme_fields(order["requested_scheme"], order["scheme"],
                                  order["scheme_reason"])}
        with bind(order_id=order["order_id"], connection_id=connection_id,
                  idempotency_key=order["idempotency_key"]):
            self._audit.record(
                "payment.return_suspected", outcome=FAILURE,
                order_id=order["order_id"], connection_id=connection_id,
                idempotency_key=order["idempotency_key"],
                detail={name: value for name, value in detail.items()
                        if value is not None})
            log.warning("payment.return_suspected", statement_id=statement_id,
                        entry_ref=reference,
                        reason="a credit from this order's creditor, for its "
                               "amount, worded the way this bank words a "
                               "return; a person has to confirm it")

    # --- a person decides ---------------------------------------------------

    def confirm(self, order_id: str, *, actor: Actor = SYSTEM_ACTOR) -> None:
        """A person says the suspected booking is this order's money coming back."""
        now = _dt.datetime.now(_dt.timezone.utc)
        with self._engine.connect() as connection:
            row = connection.execute(
                select(payment_order).where(
                    payment_order.c.order_id == order_id)
            ).mappings().one_or_none()
        if row is None:
            raise NotFoundError(f"no order {order_id}")
        moved = (
            payment_order.update()
            .where(payment_order.c.order_id == order_id,
                   payment_order.c.state.in_(RETURNS_FROM),
                   payment_order.c.return_suspected_at.is_not(None),
                   payment_order.c.return_suspicion_dismissed_at.is_(None))
            .values(state=OrderState.RETURNED.value,
                    returned_at=row["return_suspected_booked_at"] or now,
                    return_statement_id=row["return_suspected_statement_id"],
                    return_entry_ref=row["return_suspected_entry_ref"],
                    return_reason_code=None,
                    return_reason_text=row["return_suspected_text"],
                    return_matched_by=OPERATOR, updated_at=now)
            .returning(payment_order.c.order_id))
        with self._engine.begin() as connection:
            if connection.execute(moved).one_or_none() is None:
                raise ConflictError(
                    f"order {order_id} has no open suspected return to "
                    f"confirm; it is {row['state']}")
        with bind(order_id=order_id, connection_id=row["connection_id"],
                  idempotency_key=row["idempotency_key"]):
            self._audit.record(
                "payment.returned", actor=actor, outcome=FAILURE,
                order_id=order_id, connection_id=row["connection_id"],
                idempotency_key=row["idempotency_key"],
                detail={name: value for name, value in {
                    "order_state": OrderState.RETURNED.value,
                    "previous_state": row["state"],
                    "reason_text": row["return_suspected_text"],
                    "statement_id": row["return_suspected_statement_id"],
                    "entry_ref": row["return_suspected_entry_ref"],
                    "booking_date": (row["return_suspected_booked_at"].date()
                                     .isoformat()
                                     if row["return_suspected_booked_at"]
                                     else None),
                    "matched_by": OPERATOR,
                    **scheme_fields(row["requested_scheme"], row["scheme"],
                                    row["scheme_reason"]),
                }.items() if value is not None})

    def dismiss(self, order_id: str, *, actor: Actor = SYSTEM_ACTOR) -> None:
        """A person says the suspected booking is not this order's money."""
        now = _dt.datetime.now(_dt.timezone.utc)
        dismissed = (
            payment_order.update()
            .where(payment_order.c.order_id == order_id,
                   payment_order.c.return_suspected_at.is_not(None),
                   payment_order.c.return_suspicion_dismissed_at.is_(None),
                   payment_order.c.state != OrderState.RETURNED.value)
            .values(return_suspicion_dismissed_at=now, updated_at=now)
            .returning(payment_order.c.connection_id,
                       payment_order.c.idempotency_key,
                       payment_order.c.state,
                       payment_order.c.return_suspected_statement_id,
                       payment_order.c.return_suspected_entry_ref))
        with self._engine.begin() as connection:
            row = connection.execute(dismissed).mappings().one_or_none()
        if row is None:
            raise ConflictError(
                f"order {order_id} has no open suspected return to dismiss")
        with bind(order_id=order_id, connection_id=row["connection_id"],
                  idempotency_key=row["idempotency_key"]):
            self._audit.record(
                "payment.return_dismissed", actor=actor, outcome=SUCCESS,
                order_id=order_id, connection_id=row["connection_id"],
                idempotency_key=row["idempotency_key"],
                detail={"order_state": row["state"],
                        "statement_id": row["return_suspected_statement_id"],
                        "entry_ref": row["return_suspected_entry_ref"]})


def _unmarked(payload: dict[str, Any]):
    """Every booked credit the bank did not mark, with the words it carries."""
    for entry in payload.get("entries") or ():
        if entry.get("credit_debit") != "credit":
            continue
        if entry.get("status") not in (None, "BOOK"):
            continue
        code = entry.get("bank_transaction_code") or {}
        if entry.get("reversal") or code.get("sub_family") == "RRTN":
            continue
        transactions = entry.get("transactions") or [{}]
        if len(transactions) != 1:
            continue
        transaction = transactions[0]
        if transaction.get("return_information") is not None:
            continue
        words = " ".join(part for part in (
            entry.get("additional_information"),
            transaction.get("additional_information"),
            transaction.get("remittance_information")) if part)
        if words:
            yield entry, transaction, words


def _same_amount(left: str | None, right: str | None) -> bool:
    try:
        return decimal.Decimal(left or "") == decimal.Decimal(right or "")
    except decimal.InvalidOperation:
        return False


def _day(value: str | None) -> _dt.date | None:
    try:
        return _dt.date.fromisoformat(value or "")
    except ValueError:
        return None


def _short(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= MAX_TEXT else text[:MAX_TEXT - 1] + "…"


def _whole(one: Evidence, order: dict[str, Any]) -> bool:
    """Does the booking return the whole order: its sum, in its currency?"""
    if one.currency and one.currency != order["currency"]:
        return False
    return _same_amount(one.amount, order["control_sum"])


def _carries(document: bytes | None, end_to_end_id: str) -> bool:
    summary = summarise(document)
    return bool(summary) and any(transfer.end_to_end_id == end_to_end_id
                                 for transfer in summary.transfers)


__all__: Sequence[str] = ["LOOKBACK", "MATCHED_BY", "OPERATOR", "RETURNS_FROM",
                          "REVERSAL", "RTRINF", "SUSPECT_PATTERNS",
                          "SUSPECT_WINDOW", "BankPattern",
                          "Evidence", "ReturnMatcher", "evidence"]
