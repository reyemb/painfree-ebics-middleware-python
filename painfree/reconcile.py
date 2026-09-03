"""Matching a `pain.002` back to the order it reports on, and closing the order.

The last step of a payment. A `pain.002` is the bank answering a `pain.001`
this service sent, and it names the answer's subject in one field:
`OrgnlMsgId`, which is the `MsgId` generated at accept time and stored on
``payment_order``. That is the whole join. Everything else here is deciding
what the answer *means*.

**The join is a column, not a JSON lookup.** ``statement.order_id`` is written
when the report is ingested, so "which reports answer this order" is an indexed
query rather than a scan of a hundred payloads. The `MsgId` is unique per
connection, and the lookup is scoped to the connection anyway: a report from
one bank must not be able to close another bank's order.

**ISO 20022 statuses are their own vocabulary.** `ACSP` is not an EBICS return
code and does not live in the same columns as one. :data:`STATUS_CODES` is the
whole mapping -- every code this service recognises, the ISO name, what it
means in plain words, and which of four dispositions it carries -- and it is
the only place the translation happens. The table an operator reads is
``/ui/status-codes``.

**A report decides the order only from the top.** `GrpSts` is the headline and
the levels below refine it, because a bank that partially accepts a file
routinely lists *only* the transactions it refused. Counting statuses would
therefore read "one transaction, rejected" as "the file was rejected", which is
the opposite of what happened. So `PART` is an acknowledgement -- part of it
went through -- with the refused transactions recorded beside it, and the
transaction level is only decisive when the group level said nothing.

`PART` deliberately does **not** become `rejected`, and the reason is not
taxonomy: `rejected` is replayable (``painfree.orders.REPLAYABLE``), and
replaying a partly-executed batch re-sends the transactions the bank already
accepted. One wrong word here is a double payment.

**Nothing here resurrects an order.** The transition is a single conditional
``UPDATE`` whose ``WHERE`` names the states a report may move an order out of,
so a second report -- banks re-send -- affects no row, writes no audit event
and owes no webhook. A report for an order that is already terminal, or that a
worker currently holds, is recorded and logged rather than applied.

**A report for an unknown `MsgId` is stored, logged and audited.** Another
system's order, or one predating this deployment. It is not an error and it is
not silence: the statement row is kept with no order on it, the log line says
which `MsgId` matched nothing, and the audit trail has a row.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from sqlalchemy import Engine, select

from painfree.audit import FAILURE, SUCCESS, AuditLog
from painfree.isoxml import datetime_utc
from painfree.logging import bind, get_logger
from painfree.orders import OrderState
from painfree.schema import payment_attempt, payment_order, statement

log = get_logger("painfree.reconcile")

#: The `kind` :mod:`painfree.pain002` files its documents under.
PAYMENT_STATUS = "payment_status"

#: What a status code tells this service to do with the order.
ACCEPTS = "accepts"
REFUSES = "refuses"
PARTIAL = "partial"
UNDECIDED = "undecided"


@dataclass(frozen=True, slots=True)
class StatusCode:
    """One ISO 20022 payment status code and what painfree does with it."""

    code: str
    name: str
    meaning: str
    disposition: str

    @property
    def outcome(self) -> str:
        """The order state this disposition drives, in words, for a reader."""
        return {ACCEPTS: "acknowledged", REFUSES: "rejected",
                PARTIAL: "acknowledged", UNDECIDED: "no change"}[self.disposition]


def _code(code: str, name: str, meaning: str, disposition: str) -> StatusCode:
    return StatusCode(code, name, meaning, disposition)


#: `ExternalPaymentTransactionStatus1Code`, restricted to what a `pain.002`
#: actually carries at any of its three levels, with this service's reading of
#: each. A code that is not here moves nothing and is logged by name -- the ISO
#: list grows, and a vocabulary this service has not been taught is a reason to
#: leave an order where it is rather than to guess at it.
#:
#: The four dispositions, and why they are four rather than two:
#:
#: * ``accepts`` -- the bank has taken responsibility for the payment at some
#:   stage of its own processing. Terminal here: the order is `acknowledged`.
#: * ``refuses`` -- it will not be executed. Terminal: the order is `rejected`,
#:   carrying the bank's own reason code and text.
#: * ``partial`` -- some of the batch was taken. Also `acknowledged`, because
#:   the file *was* accepted and re-sending it would duplicate the accepted
#:   part; the refused transactions are recorded beside the state.
#: * ``undecided`` -- the bank has not answered yet. **No transition.** A
#:   `PDNG` is an interim report and the order stays where it is until a later
#:   one decides it.
STATUS_CODES: dict[str, StatusCode] = {
    entry.code: entry for entry in (
        _code("ACTC", "AcceptedTechnicalValidation",
              "the file passed the bank's technical checks", ACCEPTS),
        _code("ACCP", "AcceptedCustomerProfile",
              "the file passed the customer-profile checks", ACCEPTS),
        _code("ACFC", "AcceptedFundsChecked",
              "accepted, and the debtor's cover was checked", ACCEPTS),
        _code("ACSP", "AcceptedSettlementInProcess",
              "accepted and being settled", ACCEPTS),
        _code("ACSC", "AcceptedSettlementCompleted",
              "settled on the debtor's side", ACCEPTS),
        _code("ACCC", "AcceptedSettlementCompletedCreditorAccount",
              "settled and credited to the beneficiary", ACCEPTS),
        _code("ACWC", "AcceptedWithChange",
              "accepted, with something the bank changed", ACCEPTS),
        _code("ACWP", "AcceptedWithoutPosting",
              "accepted, not yet posted to the creditor's account", ACCEPTS),
        _code("ACPD", "AcceptedClearingProcessed",
              "accepted and handed to clearing", ACCEPTS),
        _code("PART", "PartiallyAccepted",
              "some of the batch was accepted and some refused", PARTIAL),
        _code("PATC", "PartiallyAcceptedTechnicalCorrect",
              "technically correct, partially accepted", PARTIAL),
        _code("RJCT", "Rejected",
              "refused; it will not be executed", REFUSES),
        _code("CANC", "Cancelled",
              "cancelled; it will not be executed", REFUSES),
        _code("RCVD", "Received",
              "received, nothing decided yet", UNDECIDED),
        _code("PDNG", "Pending",
              "pending; the bank is still working on it", UNDECIDED),
        _code("BLCK", "Blocked",
              "blocked at the bank; somebody there has to act", UNDECIDED),
    )
}

#: The states a status report may move an order out of. ``submitting`` is
#: deliberately absent: a worker holds that order and its own settlement would
#: overwrite whatever were written here. The report is recorded against the
#: order regardless, so nothing is lost -- see :meth:`StatusReconciler.reconcile`.
RECONCILES_FROM = (OrderState.ACCEPTED.value, OrderState.SUBMITTED.value)

#: `status_reason_text` is a diagnostic in one column, not a document.
MAX_REASON_LENGTH = 1024


@dataclass(frozen=True, slots=True)
class StatusOutcome:
    """What one `pain.002` says about one order.

    ``state`` is ``None`` when the report decides nothing -- an interim
    `PDNG`, or a vocabulary this service does not know. That is not a failure
    and it is not a state.
    """

    state: OrderState | None
    status: str | None
    reason_code: str | None = None
    reason_text: str | None = None
    accepted: int = 0
    rejected: int = 0
    pending: int = 0
    unknown: tuple[str, ...] = ()

    @property
    def decides(self) -> bool:
        return self.state is not None

    @property
    def name(self) -> str | None:
        """The ISO name of the decisive code, for a log line or a page."""
        known = STATUS_CODES.get(self.status or "")
        return known.name if known else None

    def as_detail(self, **extra: Any) -> dict[str, Any]:
        """The audit detail, which is also the webhook event's ``data``.

        References and the bank's own words: a status code, a reason code, the
        text the bank wrote, and how many transactions went each way. Never an
        amount, never a counterparty.
        """
        detail = {
            "status": self.status,
            "status_name": self.name,
            "reason_code": self.reason_code,
            "reason_text": self.reason_text,
            "transactions_accepted": self.accepted or None,
            "transactions_rejected": self.rejected or None,
            "transactions_pending": self.pending or None,
            "unknown_status_codes": list(self.unknown) or None,
            "source": "pain.002",
            **extra,
        }
        return {name: value for name, value in detail.items() if value is not None}


# --- reading one report -----------------------------------------------------

def resolve(payload: dict[str, Any]) -> StatusOutcome:
    """What one normalised `pain.002` payload says. Pure; no database.

    The group status is the headline. When the bank gave none -- it is optional
    in the schema -- the levels below decide, and only unanimously: a report
    whose transactions disagree with nothing above them to arbitrate is one
    this service leaves alone.
    """
    original = payload.get("original") or {}
    payments = payload.get("payments") or []
    transactions = [one for block in payments
                    for one in (block.get("transactions") or [])]

    accepted, rejected, pending = _tally(one.get("status") for one in transactions)
    unknown = _unknown([original.get("status"),
                        *(block.get("status") for block in payments),
                        *(one.get("status") for one in transactions)])
    reason_code, reason_text = _reason(payload, payments, transactions)

    group = original.get("status")
    head = STATUS_CODES.get(group or "")
    if head is None and group is None:
        # No `GrpSts`. Fall through to the levels below rather than refusing to
        # read a document the schema permits.
        head = _unanimous(payments, transactions)
        group = head.code if head else None

    state = None
    if head is not None:
        if head.disposition in (ACCEPTS, PARTIAL):
            state = OrderState.ACKNOWLEDGED
        elif head.disposition == REFUSES:
            state = OrderState.REJECTED

    return StatusOutcome(state=state, status=group, reason_code=reason_code,
                         reason_text=reason_text, accepted=accepted,
                         rejected=rejected, pending=pending, unknown=unknown)


def _tally(statuses: Iterable[str | None]) -> tuple[int, int, int]:
    """How many transactions the bank took, refused and has not decided."""
    accepted = rejected = pending = 0
    for status in statuses:
        known = STATUS_CODES.get(status or "")
        if known is None:
            pending += 1
        elif known.disposition in (ACCEPTS, PARTIAL):
            accepted += 1
        elif known.disposition == REFUSES:
            rejected += 1
        else:
            pending += 1
    return accepted, rejected, pending


def _unanimous(payments: list[dict[str, Any]],
               transactions: list[dict[str, Any]]) -> StatusCode | None:
    """The one disposition every reported level below the group agrees on.

    Used only when the group said nothing. Anything less than unanimity leaves
    the order where it is: half an answer is not an answer.
    """
    for level in (transactions, payments):
        codes = [STATUS_CODES.get(one.get("status") or "") for one in level]
        if not codes or any(code is None for code in codes):
            continue
        dispositions = {code.disposition for code in codes}  # type: ignore[union-attr]
        if dispositions <= {ACCEPTS, PARTIAL} or dispositions == {REFUSES}:
            return codes[0]
    return None


def _unknown(statuses: Iterable[str | None]) -> tuple[str, ...]:
    """Every status code in the document this service has no reading for."""
    return tuple(sorted({status for status in statuses
                         if status and status not in STATUS_CODES}))


def _reason(payload: dict[str, Any], payments: list[dict[str, Any]],
            transactions: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    """The bank's own reason, from the most specific level that gave one.

    Group, then payment block, then the first transaction carrying one. The
    code and the free text are both kept: `AC01` means "incorrect account
    number" to anyone with the ISO list to hand, and the bank's `AddtlInf` is
    what says *which* account.
    """
    for reasons in (payload.get("reasons"),
                    *(block.get("reasons") for block in payments),
                    *(one.get("reasons") for one in transactions)):
        for reason in reasons or ():
            code = reason.get("code") or reason.get("proprietary")
            text = "; ".join(reason.get("additional_information") or ())
            if code or text:
                return code, _short(text) or None
    return None, None


def _short(text: str) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= MAX_REASON_LENGTH else (
        text[:MAX_REASON_LENGTH - 1] + "…")


def reported_at(payload: dict[str, Any]) -> _dt.datetime | None:
    """When the bank wrote the report -- its `GrpHdr/CreDtTm`, not our clock."""
    header = payload.get("group_header") or {}
    try:
        return datetime_utc(header.get("created_at"))
    except Exception:  # pragma: no cover - a malformed date must not lose a report
        log.warning("payment.status_date_unreadable",
                    created_at=header.get("created_at"))
        return None


def original_message_id(payload: dict[str, Any]) -> str | None:
    """`OrgnlMsgId`: the `MsgId` this service generated for the order."""
    return (payload.get("original") or {}).get("message_identification")


# --- reading it for a page --------------------------------------------------
#
# `resolve` above answers "what does this report do to the order", which is one
# code and one transition. A page has the other question: **what did the bank
# say about each payment we sent** -- and the answer is not in the report for
# most of them, because a bank reports by exception. A file the bank took whole
# names no transaction at all.
#
# So the rows on that page come from the `pain.001` this service sent, and this
# is what annotates them. The three levels stay three levels: an answer carries
# the level it was read at, and a page that shows an inherited status says so
# rather than letting it read as the bank having spoken about that payment.

#: Where an answer came from. Not an ordering: `group` is the level that
#: *decides*, and `transaction` is only the most specific.
TRANSACTION = "transaction"
PAYMENT = "payment"
GROUP = "group"
UNANSWERED = "unanswered"


@dataclass(frozen=True, slots=True)
class Answer:
    """What one `pain.002` says about one thing, and at which level it said it."""

    status: str | None
    level: str
    reasons: tuple[dict[str, Any], ...] = ()
    accepted_at: str | None = None

    @property
    def code(self) -> StatusCode | None:
        """This service's reading of the status, or ``None`` for a new one."""
        return STATUS_CODES.get(self.status or "")

    @property
    def inherited(self) -> bool:
        """True when the bank did not say this about *this* transfer."""
        return self.level in (PAYMENT, GROUP)

    @property
    def refused(self) -> bool:
        code = self.code
        return code is not None and code.disposition == REFUSES


@dataclass(frozen=True, slots=True)
class Block:
    """One `OrgnlPmtInfAndSts`, for the level of the report between the two."""

    payment_information_id: str | None
    answer: Answer
    transactions: int = 0
    accepted: int = 0
    rejected: int = 0


@dataclass(frozen=True, slots=True)
class Reading:
    """One report, indexed so a page can ask it about one transfer at a time.

    Built once per page. Asking the payload directly per transfer would rescan
    every block for every row, which is quadratic on exactly the batch that
    makes the page worth having.
    """

    group: Answer
    blocks: tuple[Block, ...]
    #: Every transfer the report named, by `EndToEndId` and by `InstrId`. Both,
    #: because a bank may echo one and not the other.
    by_reference: dict[str, Answer]
    #: The references the report named, in document order, for finding the ones
    #: our own message did not send.
    named: tuple[str, ...]

    def for_transfer(self, end_to_end_id: str | None = None,
                     instruction_id: str | None = None,
                     payment_information_id: str | None = None) -> Answer:
        """The most specific thing the bank said that covers this transfer.

        Transaction, then the payment block it is in, then the whole message.
        Never a status derived from a *sibling*: a bank listing one refusal has
        said nothing about the transfer beside it, and reading the refusal
        across would invent a rejection.
        """
        for reference in (end_to_end_id, instruction_id):
            if reference and reference in self.by_reference:
                return self.by_reference[reference]
        block = self._block(payment_information_id)
        if block is not None and block.answer.status:
            return Answer(block.answer.status, PAYMENT, block.answer.reasons)
        if self.group.status:
            return Answer(self.group.status, GROUP, self.group.reasons)
        return Answer(None, UNANSWERED)

    def _block(self, payment_information_id: str | None) -> Block | None:
        """The block this transfer is in, by id, or the only one there is."""
        for block in self.blocks:
            if (payment_information_id
                    and block.payment_information_id == payment_information_id):
                return block
        return self.blocks[0] if len(self.blocks) == 1 else None

    def unsent(self, references: Iterable[str | None]) -> tuple[str, ...]:
        """References the report names that the message we sent does not have.

        A bank answering about a payment this service did not send is worth
        showing rather than dropping: it is either the wrong report or the
        wrong join, and both are things an operator has to see.
        """
        ours = {reference for reference in references if reference}
        return tuple(name for name in self.named if name not in ours)


def reading(payload: dict[str, Any]) -> Reading:
    """Index one normalised `pain.002` for display. Pure; no database."""
    original = payload.get("original") or {}
    group = Answer(original.get("status"),
                   GROUP if original.get("status") else UNANSWERED,
                   tuple(payload.get("reasons") or ()))

    blocks: list[Block] = []
    by_reference: dict[str, Answer] = {}
    named: list[str] = []
    for one in payload.get("payments") or ():
        transactions = tuple(one.get("transactions") or ())
        accepted, rejected, _pending = _tally(
            each.get("status") for each in transactions)
        for each in transactions:
            answer = Answer(each.get("status"), TRANSACTION,
                            tuple(each.get("reasons") or ()),
                            each.get("acceptance_datetime"))
            first = True
            for reference in (each.get("end_to_end_id"),
                              each.get("instruction_id")):
                if not reference:
                    continue
                by_reference.setdefault(reference, answer)
                if first:
                    named.append(reference)
                    first = False
        blocks.append(Block(
            payment_information_id=one.get("payment_information_id"),
            answer=Answer(one.get("status"),
                          PAYMENT if one.get("status") else UNANSWERED,
                          tuple(one.get("reasons") or ())),
            transactions=len(transactions),
            accepted=accepted, rejected=rejected))

    return Reading(group=group, blocks=tuple(blocks),
                   by_reference=by_reference, named=tuple(named))


# --- applying it ------------------------------------------------------------

class StatusReconciler:
    """Joins a stored `pain.002` to its order and moves the order once.

    Constructed by :class:`painfree.statements.StatementStore`, which is the
    only caller: reconciling is what ingesting a status report *is*, and a
    second entry point would be a second place for the state machine to differ.
    """

    __slots__ = ("_engine", "_audit")

    def __init__(self, engine: Engine, audit: AuditLog | None = None) -> None:
        self._engine = engine
        self._audit = audit or AuditLog(engine)

    def order_for(self, connection_id: str,
                  payload: dict[str, Any]) -> str | None:
        """The order this report answers, or ``None`` if this service has none.

        The live ``MsgId`` first, then **every attempt this order ever made**.
        An order that fell back from instant to normal sent one message the
        bank refused and a second it took, and a `pain.002` naming the first is
        still about this order. Resolving only the live message would file that
        report as unmatched, which is the one outcome that loses the bank's own
        words about a payment.
        """
        msg_id = original_message_id(payload)
        if not msg_id:
            return None
        with self._engine.connect() as connection:
            order_id = connection.execute(
                select(payment_order.c.order_id)
                .where(payment_order.c.connection_id == connection_id,
                       payment_order.c.msg_id == msg_id)).scalar_one_or_none()
            if order_id is not None:
                return order_id
            # The join is on the order, so a `MsgId` from another connection's
            # attempt cannot be attributed to this one.
            return connection.execute(
                select(payment_attempt.c.order_id)
                .join(payment_order,
                      payment_order.c.order_id == payment_attempt.c.order_id)
                .where(payment_order.c.connection_id == connection_id,
                       payment_attempt.c.msg_id == msg_id)
            ).scalar_one_or_none()

    def reconcile(self, *, connection_id: str, statement_id: str,
                  order_id: str | None, payload: dict[str, Any],
                  run_id: str | None = None) -> StatusOutcome:
        """Apply one stored status report. Returns what it said, applied or not.

        Four endings, and every one of them writes something:

        * the order moved -- an audit row, and with it the webhook the envelope
          promises;
        * the report decided nothing (`PDNG`, or a code this service does not
          know) -- ``payment.status_reported``, no state change, no event;
        * the order was already terminal, or a worker holds it --
          ``payment.status_ignored``, with the state that refused the move;
        * no order carries that `MsgId` -- ``payment.status_unmatched``.
        """
        outcome = resolve(payload)
        msg_id = original_message_id(payload)
        detail = outcome.as_detail(statement_id=statement_id, msg_id=msg_id)

        if order_id is None:
            return self._unmatched(connection_id, statement_id, msg_id,
                                   outcome, detail, run_id)
        with bind(order_id=order_id, connection_id=connection_id, job_id=run_id):
            if not outcome.decides:
                return self._undecided(connection_id, order_id, outcome, detail)
            return self._apply(connection_id, order_id, outcome, detail, payload)

    # --- the four endings --------------------------------------------------

    def _apply(self, connection_id: str, order_id: str, outcome: StatusOutcome,
               detail: dict[str, Any], payload: dict[str, Any]) -> StatusOutcome:
        """The conditional ``UPDATE`` that makes a re-sent report a no-op."""
        state = outcome.state or OrderState.ACKNOWLEDGED
        now = _dt.datetime.now(_dt.timezone.utc)
        moved = (
            payment_order.update()
            .where(payment_order.c.order_id == order_id,
                   payment_order.c.state.in_(RECONCILES_FROM))
            .values(state=state.value, bank_status=outcome.status,
                    status_reason_code=outcome.reason_code,
                    status_reason_text=outcome.reason_text,
                    status_reported_at=reported_at(payload),
                    worker_id=None, claimed_at=None, next_attempt_at=None,
                    updated_at=now)
            .returning(payment_order.c.idempotency_key)
        )
        with self._engine.begin() as connection:
            row = connection.execute(moved).one_or_none()
        if row is None:
            return self._ignored(connection_id, order_id, outcome, detail)

        action = ("payment.acknowledged" if state is OrderState.ACKNOWLEDGED
                  else "payment.rejected")
        with bind(idempotency_key=row[0]):
            # One audit row, and with it the event every subscription is owed.
            # The fact and the obligation commit together.
            self._audit.record(
                action, outcome=SUCCESS if state is OrderState.ACKNOWLEDGED
                else FAILURE,
                order_id=order_id, connection_id=connection_id,
                idempotency_key=row[0],
                detail={"order_state": state.value, **detail})
            log.info("payment.state_changed", state=state.value,
                     status=outcome.status, status_name=outcome.name,
                     reason_code=outcome.reason_code,
                     reason_text=outcome.reason_text,
                     transactions_accepted=outcome.accepted,
                     transactions_rejected=outcome.rejected,
                     source="pain.002")
        return outcome

    def _undecided(self, connection_id: str, order_id: str,
                   outcome: StatusOutcome,
                   detail: dict[str, Any]) -> StatusOutcome:
        """An interim report. Recorded, not applied -- `PDNG` is not a state."""
        self._audit.record("payment.status_reported", order_id=order_id,
                           connection_id=connection_id,
                           detail={"applied": False, **detail})
        log.info("payment.status_reported", status=outcome.status,
                 status_name=outcome.name, unknown=list(outcome.unknown),
                 reason="the bank has not decided; the order is left as it is")
        return outcome

    def _ignored(self, connection_id: str, order_id: str,
                 outcome: StatusOutcome,
                 detail: dict[str, Any]) -> StatusOutcome:
        """No row moved: the order is terminal already, or a worker holds it."""
        state = self._state_of(order_id)
        self._audit.record("payment.status_ignored", order_id=order_id,
                           connection_id=connection_id,
                           detail={"applied": False, "order_state": state,
                                   "would_be": outcome.state.value
                                   if outcome.state else None, **detail})
        log.warning(
            "payment.status_ignored", order_state=state, status=outcome.status,
            would_be=outcome.state.value if outcome.state else None,
            reason="the order is not in a state a status report may move it "
                   "out of; it was neither resurrected nor reported twice")
        return outcome

    def _unmatched(self, connection_id: str, statement_id: str,
                   msg_id: str | None, outcome: StatusOutcome,
                   detail: dict[str, Any],
                   run_id: str | None) -> StatusOutcome:
        """A report for a `MsgId` this service never sent. Kept, and said aloud."""
        with bind(connection_id=connection_id, job_id=run_id):
            self._audit.record("payment.status_unmatched",
                               connection_id=connection_id,
                               detail={"applied": False, **detail})
            log.warning(
                "payment.status_unmatched", statement_id=statement_id,
                msg_id=msg_id, status=outcome.status,
                reason="no order on this connection was submitted under that "
                       "MsgId; the report is stored with no order on it")
        return outcome

    def _state_of(self, order_id: str) -> str | None:
        with self._engine.connect() as connection:
            return connection.execute(
                select(payment_order.c.state)
                .where(payment_order.c.order_id == order_id)
            ).scalar_one_or_none()

    # --- reading back ------------------------------------------------------

    def reports_for(self, order_id: str,
                    limit: int = 20) -> list[dict[str, Any]]:
        """Every status report linked to one order, newest first.

        Summaries, not payloads. A `pain.002` quotes the amounts and the
        end-to-end references of the payment it answers, and the order page is
        held to the same rule as the order itself: reported by reference.
        """
        with self._engine.connect() as connection:
            rows = connection.execute(
                select(statement.c.statement_id, statement.c.message_type,
                       statement.c.identification, statement.c.ingested_at,
                       statement.c.run_id, statement.c.payload)
                .where(statement.c.order_id == order_id)
                .order_by(statement.c.seq.desc())
                .limit(max(1, min(limit, 100)))).mappings().all()
        return [{"statement_id": row["statement_id"],
                 "message_type": row["message_type"],
                 "identification": row["identification"],
                 "ingested_at": row["ingested_at"], "run_id": row["run_id"],
                 "outcome": resolve(row["payload"])} for row in rows]


__all__: Sequence[str] = [
    "ACCEPTS", "GROUP", "MAX_REASON_LENGTH", "PARTIAL", "PAYMENT",
    "PAYMENT_STATUS", "RECONCILES_FROM", "REFUSES", "STATUS_CODES",
    "TRANSACTION", "UNANSWERED", "UNDECIDED", "Answer", "Block", "Reading",
    "StatusCode", "StatusOutcome", "StatusReconciler", "original_message_id",
    "reading", "reported_at", "resolve",
]
