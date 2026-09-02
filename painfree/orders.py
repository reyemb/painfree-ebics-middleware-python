"""Payment orders: validate, build, and land exactly one row per idempotency key.

This is the accept step. It ends at a durable, validated, queued order and goes
no further: nothing here signs, uploads, or talks to a bank, and nothing here
can open a private key -- the request path has no custody key to build a
custodian from, and this module imports neither :mod:`painfree.keyring` nor
:mod:`painfree.custody`.

**The order of operations is the gate.** Shape, then the Swiss Payment
Standards rules, then the document, then the official XSD -- and only then a
row. A rejection therefore costs the caller one round trip and reaches them
naming the field, which is the whole argument for validating here: the
alternative is learning about a malformed reference from the bank, hours later,
with the order already in the audit trail.

**Idempotency is a constraint, not a check.** A retry must never produce a
second payment. A read-then-write cannot promise that -- two concurrent
submissions both read "no such key" and both insert. So the uniqueness lives in
the database, as ``uq_payment_order_connection_id_idempotency_key``, and the
loser of the race is the request that catches the integrity error, re-reads the
winner's row and returns it. The fast path in front of the insert is an
optimisation for the ordinary retry, not the guarantee; the guarantee is the
constraint underneath it.

What is compared on a repeat is a **fingerprint** of the canonical request,
not the request: a SHA-256 over the instruction as it was parsed. Same key,
same fingerprint returns the original order. Same key, different fingerprint is
a `409` -- silently accepting it would hide a caller bug that costs money.
"""

from __future__ import annotations

import datetime as _dt
import enum
import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any, Sequence

from sqlalchemy import Engine, select
from sqlalchemy.exc import IntegrityError

from painfree import pain001, payments, schemes, sps
from painfree.attempts import LIVE, PLANNED, AttemptStore
from painfree.audit import FAILURE, Actor, AuditLog, SYSTEM_ACTOR
from painfree.connections import ConnectionRegistry
from painfree.errors import ConflictError, NotFoundError
from painfree.logging import bind, get_logger
from painfree.schema import payment_order
from painfree.schemes import PaymentScheme, SchemeDecision

log = get_logger("painfree.orders")

#: Printable ASCII, no spaces, and long enough to be a key rather than a digit.
#: It travels in a header, into log lines and into audit rows, so a value that
#: needs quoting in any of those is a value that will be grepped for wrongly.
IDEMPOTENCY_KEY = re.compile(r"^[\x21-\x7e]{8,255}$")

ORDER_ID_PREFIX = "ord_"


class OrderState(str, enum.Enum):
    """The states of the order lifecycle, in one place.

    ``SUBMITTED`` is not success -- the bank has taken the file, not executed
    the payments. Only the worker and the scheduler move an order past
    ``ACCEPTED``; this module only ever writes the first one, and
    :mod:`painfree.queue` writes the rest.

    ``REJECTED`` is the bank refusing the file; ``FAILED`` is this service
    giving up on delivering it. An operator reads the two differently, so they
    are not one state with a flag.

    ``ACKNOWLEDGED`` is written by :mod:`painfree.reconcile` when a `pain.002`
    naming this order's ``MsgId`` says the bank took the payment. A bank that
    refuses at that stage rather than at submission writes ``REJECTED`` from
    the same place, which is why both terminal words have two writers and one
    meaning each.
    """

    ACCEPTED = "accepted"
    SUBMITTING = "submitting"
    SUBMITTED = "submitted"
    REJECTED = "rejected"
    ACKNOWLEDGED = "acknowledged"
    FAILED = "failed"


#: The states an operator may re-queue an order from. Defined next to the
#: state machine rather than in the console, so the rule is one fact --
#: ``failed`` is this service having given up, ``rejected`` is the bank having
#: refused, and everything else is an order somebody still owns.
REPLAYABLE = frozenset({OrderState.FAILED, OrderState.REJECTED})


@dataclass(frozen=True, slots=True)
class PaymentOrder:
    """One accepted order. ``document`` is the message; it is not a response field."""

    order_id: str
    connection_id: str
    idempotency_key: str
    state: OrderState
    msg_id: str
    payment_information_id: str
    message_type: str
    transaction_count: int
    control_sum: str
    currency: str
    requested_execution_date: str
    bank_order_id: str | None
    return_code: str | None
    report_text: str | None
    #: What the bank's `pain.002` said, in the bank's own vocabulary and not in
    #: the EBICS one above: an ISO 20022 status, its reason code and the text
    #: the bank wrote. Filled by :mod:`painfree.reconcile`; ``None`` until a
    #: status report has arrived for this order.
    bank_status: str | None
    status_reason_code: str | None
    status_reason_text: str | None
    status_reported_at: _dt.datetime | None
    #: Written by the worker, read here: the open EBICS transaction, and how
    #: many times this order has been claimed. Neither is a response field --
    #: a caller polls a state, not this service's retry bookkeeping.
    transaction_id: str | None
    attempts: int
    #: The payment scheme. ``requested_scheme`` is what the caller asked for
    #: and never changes; ``scheme`` is what is actually being sent, so the two
    #: differing *is* the downgrade, and ``scheme_reason`` says why.
    requested_scheme: PaymentScheme
    scheme: PaymentScheme
    scheme_reason: str | None
    accepted_at: _dt.datetime
    updated_at: _dt.datetime
    document: bytes
    #: The EBICS request the bank refused, and what the H005 schemas said
    #: about it. ``None`` means nothing was captured -- an order that was
    #: never refused, or one refused before this was kept. An empty list of
    #: errors is a finding, not an exoneration: see
    #: :mod:`painfree.ebics3.envelope_schema`.
    refused_request: bytes | None = None
    refused_request_errors: list[str] | None = None

    @property
    def downgraded(self) -> bool:
        """Was instant asked for and normal sent?

        True for a pre-flight downgrade and for a fallback taken after the bank
        refused instant. **Not** true of an ``instant_or_normal`` that is
        actually going instant: the request named two acceptable outcomes and
        got the first one, which is the request being satisfied rather than
        stepped down.

        Deliberately not a stored column: it is a comparison of two columns,
        and a third that could disagree with them is a third that eventually
        does.
        """
        return (self.requested_scheme.wants_instant
                and self.scheme is PaymentScheme.NORMAL)

    def as_response(self) -> dict[str, Any]:
        """What a caller is told. Never the document, and never the fingerprint.

        The bank's `return_code` and `report_text` are surfaced verbatim once
        there are any -- the return code is the single most useful field when a
        bank refuses something, and folding it into a generic message is how a
        support call becomes a day's work.
        """
        body: dict[str, Any] = {
            "order_id": self.order_id,
            "connection_id": self.connection_id,
            "idempotency_key": self.idempotency_key,
            "state": self.state.value,
            "msg_id": self.msg_id,
            "message_type": self.message_type,
            "transactions": self.transaction_count,
            "control_sum": self.control_sum,
            "currency": self.currency,
            "requested_execution_date": self.requested_execution_date,
            "scheme": {
                "requested": self.requested_scheme.value,
                "effective": self.scheme.value,
                "downgraded": self.downgraded,
                "reason": self.scheme_reason,
            },
            "accepted_at": self.accepted_at.isoformat(),
        }
        if self.bank_order_id:
            body["bank_order_id"] = self.bank_order_id
        if self.return_code:
            body["return_code"] = self.return_code
            body["report_text"] = self.report_text
        if self.bank_status:
            # The bank's status report, kept apart from the EBICS return code
            # above because they are two vocabularies about two different
            # things. A caller that has both is looking at the transfer and at
            # the payment, and it should be able to tell which.
            body["bank_status"] = self.bank_status
            body["status_reason_code"] = self.status_reason_code
            body["status_reason_text"] = self.status_reason_text
            body["status_reported_at"] = (
                self.status_reported_at.isoformat()
                if self.status_reported_at else None)
        return body


@dataclass(frozen=True, slots=True)
class Submission:
    """The outcome of one submission, and whether it was the one that created it."""

    order: PaymentOrder
    replayed: bool


@dataclass(frozen=True, slots=True)
class Preview:
    """What a submission would produce, without having produced it.

    Carries the document rather than a summary of it: the question an operator
    is answering is whether *this* is what should reach the bank, and a
    rendering of the fields they already typed cannot answer it.
    """

    connection_id: str
    decision: SchemeDecision
    profile: Any
    document: bytes
    message_id: str
    transaction_count: int
    control_sum: str
    currency: str


def fingerprint(connection_id: str,
                instruction: payments.PaymentInstruction) -> str:
    """A canonical SHA-256 of what was asked for.

    Canonical rather than raw so that key order and whitespace do not make two
    identical retries look different; over the *parsed* instruction so that a
    field left at its default and a field sent at its default agree.
    """
    body = json.dumps(
        {"connection_id": connection_id,
         "instruction": instruction.model_dump(mode="json")},
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class OrderStore:
    """Reads and writes ``payment_order``. Safe on the request path."""

    __slots__ = ("_engine", "_audit", "_connections", "_attempts")

    def __init__(self, engine: Engine, audit: AuditLog | None = None,
                 connections: ConnectionRegistry | None = None) -> None:
        self._engine = engine
        self._audit = audit or AuditLog(engine)
        self._connections = connections or ConnectionRegistry(engine, self._audit)
        self._attempts = AttemptStore(engine)

    # --- submission --------------------------------------------------------

    def submit(
        self,
        connection_id: str,
        *,
        idempotency_key: str,
        instruction: payments.PaymentInstruction,
        actor: Actor = SYSTEM_ACTOR,
        software_version: str | None = None,
    ) -> Submission:
        """Validate, build, and record one order. Returns the original on a retry."""
        if not IDEMPOTENCY_KEY.match(idempotency_key or ""):
            raise sps.ValidationFailed([sps.RuleFailure(
                "Idempotency-Key", "idempotency_key.format",
                "the Idempotency-Key header must be 8 to 255 printable "
                "characters with no spaces")])

        with bind(connection_id=connection_id, idempotency_key=idempotency_key):
            # A 404 for an unknown connection, before anything is built.
            connection = self._connections.get(connection_id)
            if not connection.initialised:
                # Queueing a payment for a subscriber the bank has not yet
                # activated produces an order no worker can ever deliver. The
                # caller learns now rather than from a stuck queue.
                raise ConflictError(
                    f"connection {connection_id!r} is not initialised "
                    f"(key state {connection.key_state.value}); it cannot "
                    f"submit payments yet",
                    detail={"key_state": connection.key_state.value},
                )

            digest = fingerprint(connection_id, instruction)
            existing = self._find(connection_id, idempotency_key)
            if existing is not None:
                return self._replay(existing, digest)

            # Validate before building, build before persisting, and nothing at
            # all before validating.
            self._validate(instruction, connection_id, idempotency_key)
            # The scheme decision is made here, once, and everything that has
            # to agree about it -- the document, the `PmtTpInf`, the BTF -- is
            # derived from the value it returns.
            decision = self._decide(connection.schemes, instruction,
                                    connection_id, idempotency_key)
            order_id = f"{ORDER_ID_PREFIX}{uuid.uuid4().hex}"
            built = self._build(instruction, order_id=order_id,
                                decision=decision, profiles=connection.schemes,
                                software_version=software_version)
            return self._insert(connection_id, idempotency_key, digest,
                                order_id, built, decision, actor)

    # --- the steps, each of which can refuse -------------------------------

    def _validate(self, instruction: payments.PaymentInstruction,
                  connection_id: str, idempotency_key: str) -> None:
        failures = payments.swiss_failures(instruction)
        if failures:
            self._reject(failures, connection_id, idempotency_key)

    def _decide(self, profiles: schemes.SchemeProfiles,
                instruction: payments.PaymentInstruction, connection_id: str,
                idempotency_key: str) -> SchemeDecision:
        """Resolve the scheme, or refuse the submission naming the rule.

        The three refusals here -- an unconfigured scheme, an amount above the
        ceiling, a message that asks for two schemes at once -- are all
        knowable without sending anything, which is the point. A pre-flight
        downgrade is strictly safer than a refusal-and-retry, and an `instant`
        that cannot be done should fail here rather than after a key has been
        opened and a file has been signed.
        """
        try:
            return schemes.resolve(profiles, instruction=instruction)
        except schemes.SchemeUnavailable as exc:
            self._record_rejection(list(exc.failures), connection_id,
                                   idempotency_key)
            raise

    def _reject(self, failures: list[sps.RuleFailure], connection_id: str,
                idempotency_key: str) -> None:
        # Rule ids and field locations only. The messages name fields rather
        # than quoting values, but the audit trail does not need even that --
        # a rejected reference identifies a bill exactly as an account number
        # identifies an account.
        # `payment.validation_failed`, not `payment.rejected`: no order exists
        # to be rejected, and `payment.rejected` is the bank refusing a file
        # this service already submitted. The distinction became load-bearing
        # when the audit log became the webhook event source -- one action name
        # covering three different facts would have emitted `order.rejected`
        # for a caller's own malformed request.
        self._record_rejection(failures, connection_id, idempotency_key)
        raise sps.ValidationFailed(failures)

    def _record_rejection(self, failures: list[sps.RuleFailure],
                          connection_id: str, idempotency_key: str) -> None:
        self._audit.record(
            "payment.validation_failed", outcome=FAILURE,
            connection_id=connection_id, idempotency_key=idempotency_key,
            detail={"failures": [{"location": failure.location,
                                  "rule": failure.rule}
                                 for failure in failures]},
        )

    def _build(self, instruction: payments.PaymentInstruction, *,
               order_id: str, decision: SchemeDecision,
               profiles: schemes.SchemeProfiles,
               software_version: str | None) -> dict[str, Any]:
        """The documents, and everything derived from them worth a column.

        **Both** documents, when the caller asked for `instant_or_normal`: the
        instant one that goes first and the normal one held in reserve. Each
        gets its own `MsgId` -- the bank deduplicates on it, so two attempts
        sharing one would be the second payment the design exists to prevent --
        and each is validated against the official schema here, on the request
        path, before anything is signed.

        Building the reserve now rather than in the worker is the whole safety
        argument for building the reserve at all. A worker that built it would
        be validating a payment document with a private key already open, after
        a bank refusal, under a retry policy; here the fallback is a state
        transition over a row that was validated in the ordinary way.
        """
        created_at = _dt.datetime.now(_dt.timezone.utc)
        currency = next(iter(instruction.currencies))
        attempts: list[dict[str, Any]] = []
        live: dict[str, Any] | None = None

        planned = [(decision.effective, LIVE, decision.reason)]
        if decision.fallback is not None:
            planned.append((decision.fallback, PLANNED,
                            "held in reserve for " + decision.effective.value))

        for number, (scheme, state, reason) in enumerate(planned, start=1):
            profile = profiles.profile(scheme)
            msg_id = pain001.new_message_id()
            payment_information_id = (instruction.payment_information_id
                                      or msg_id)
            document = pain001.build(
                instruction, message_id=msg_id, created_at=created_at,
                payment_information_id=payment_information_id,
                software_version=software_version, payment_type=profile,
                per_transaction=decision.per_transaction,
            )
            # The official schema, on the document that will actually be
            # signed -- on the reserve too, because a fallback that turns out
            # to be invalid is a fallback discovered by a bank.
            pain001.validate_document(document)
            attempts.append(AttemptStore.values(
                order_id, attempt_no=number, scheme=scheme, state=state,
                msg_id=msg_id,
                payment_information_id=payment_information_id,
                document=document, profile=profile, now=created_at,
                reason=reason))
            if state == LIVE:
                live = {
                    "msg_id": msg_id,
                    "payment_information_id": payment_information_id,
                    "message_type": pain001.MESSAGE_TYPE,
                    "document": document,
                    "transaction_count": len(instruction.transactions),
                    "control_sum": pain001.format_amount(
                        instruction.control_sum, currency),
                    "currency": currency,
                    "requested_execution_date":
                        instruction.requested_execution_date.isoformat(),
                    "requested_scheme": decision.requested.value,
                    "scheme": decision.effective.value,
                    "scheme_reason": decision.reason,
                    "accepted_at": created_at,
                }
        assert live is not None  # the live attempt is always first
        return {"order": live, "attempts": attempts}

    def preview(self, connection_id: str,
                instruction: payments.PaymentInstruction,
                *, software_version: str | None = None) -> "Preview":
        """Everything :meth:`submit` would do, stopping before the row.

        The console shows an operator what a payment *would* send before it
        sends it, and the only preview worth showing is one built by the code
        that does the sending. So this runs the same four steps in the same
        order -- the connection, the Swiss rules, the scheme decision, the
        document and its schema -- and differs from :meth:`submit` in what it
        omits: no idempotency key is consumed, no audit row is written, no
        order is inserted, and nothing is queued.

        It refuses in exactly the places a submission refuses, which is the
        point: a preview that accepted what a submission would reject would be
        worse than no preview, because it would be trusted.

        Two fields are regenerated when the payment is actually sent -- the
        ``MsgId`` and the ``CreDtTm``, both minted at submission -- so the
        document here is byte-identical to the one that will go except for
        those. `tests/test_service_payment_console.py` pins that rather than
        asserting it in a comment, because it is the claim the console makes
        to somebody about to move money.
        """
        with bind(connection_id=connection_id):
            connection = self._connections.get(connection_id)
            if not connection.initialised:
                raise ConflictError(
                    f"connection {connection_id!r} is not initialised "
                    f"(key state {connection.key_state.value}); it cannot "
                    f"submit payments yet",
                    detail={"key_state": connection.key_state.value},
                )
            # `swiss_failures` and `resolve` rather than `_validate` and
            # `_decide`: those two record a rejection against an idempotency
            # key, and a preview has neither a key nor anything to reject.
            failures = payments.swiss_failures(instruction)
            if failures:
                raise sps.ValidationFailed(failures)
            decision = schemes.resolve(connection.schemes, instruction=instruction)
            profile = connection.schemes.profile(decision.effective)
            created_at = _dt.datetime.now(_dt.timezone.utc)
            msg_id = pain001.new_message_id()
            document = pain001.build(
                instruction, message_id=msg_id, created_at=created_at,
                payment_information_id=(instruction.payment_information_id
                                        or msg_id),
                software_version=software_version, payment_type=profile,
                per_transaction=decision.per_transaction,
            )
            pain001.validate_document(document)
            currency = next(iter(instruction.currencies))
            return Preview(
                connection_id=connection_id, decision=decision,
                profile=profile, document=document, message_id=msg_id,
                transaction_count=len(instruction.transactions),
                control_sum=pain001.format_amount(
                    instruction.control_sum, currency),
                currency=currency)

    def _insert(self, connection_id: str, idempotency_key: str, digest: str,
                order_id: str, built: dict[str, Any],
                decision: SchemeDecision, actor: Actor) -> Submission:
        """One order row and its attempt rows, in one transaction.

        One transaction because they are one fact: an order that existed for an
        instant with no live attempt is an order a worker could claim and find
        nothing to send.
        """
        values = {
            "order_id": order_id,
            "connection_id": connection_id,
            "idempotency_key": idempotency_key,
            "request_fingerprint": digest,
            "state": OrderState.ACCEPTED.value,
            "bank_order_id": None, "return_code": None, "report_text": None,
            "updated_at": built["order"]["accepted_at"],
            **built["order"],
        }
        try:
            with self._engine.begin() as connection:
                connection.execute(payment_order.insert().values(**values))
                self._attempts.record(connection, built["attempts"])
        except IntegrityError:
            # Two submissions with one key raced and this one lost. The winner's
            # row is authoritative; the constraint decided, not a read.
            log.info("payment.duplicate_lost_race", connection_id=connection_id,
                     idempotency_key=idempotency_key)
            existing = self._find(connection_id, idempotency_key)
            if existing is None:
                # Not the idempotency constraint, then -- an order id or a
                # `MsgId` collision. Logged where it is caught and converted.
                log.exception("payment.insert_failed",
                              connection_id=connection_id,
                              idempotency_key=idempotency_key)
                raise ConflictError(
                    "the order could not be recorded") from None
            return self._replay(existing, digest)

        with bind(order_id=order_id):
            self._audit.record(
                "payment.accepted", actor=actor,
                detail={"msg_id": built["order"]["msg_id"],
                        "message_type": built["order"]["message_type"],
                        "transactions": built["order"]["transaction_count"],
                        "currency": built["order"]["currency"],
                        **_scheme_detail(decision)},
            )
            # By reference, never by content: an order id, a count, a currency.
            log.info("payment.accepted", state=OrderState.ACCEPTED.value,
                     msg_id=built["order"]["msg_id"],
                     transactions=built["order"]["transaction_count"],
                     scheme=decision.effective.value,
                     requested_scheme=decision.requested.value,
                     scheme_reason=decision.reason)
        return Submission(order=self.get(order_id), replayed=False)

    def _replay(self, existing: PaymentOrder, digest: str) -> Submission:
        """The original outcome, or a `409` if the payload changed underneath it."""
        stored = self._fingerprint_of(existing.order_id)
        if stored != digest:
            # `payment.conflict`, for the same reason: the caller reused a key,
            # the bank has said nothing, and the original order still stands.
            self._audit.record(
                "payment.conflict", outcome=FAILURE,
                connection_id=existing.connection_id,
                idempotency_key=existing.idempotency_key,
                order_id=existing.order_id,
                detail={"reason": "idempotency_key_reused_with_changed_payload"},
            )
            raise ConflictError(
                "this idempotency key was already used for a different payment",
                detail={"order_id": existing.order_id,
                        "state": existing.state.value},
            )
        self._audit.record(
            "payment.replayed", connection_id=existing.connection_id,
            idempotency_key=existing.idempotency_key,
            order_id=existing.order_id,
            # `order_state` for the reason in `_settle` above: `state` is on
            # the redaction blocklist, and this row is read by an operator.
            detail={"msg_id": existing.msg_id,
                    "order_state": existing.state.value},
        )
        log.info("payment.replayed", order_id=existing.order_id,
                 order_state=existing.state.value)
        return Submission(order=existing, replayed=True)

    # --- replay ------------------------------------------------------------

    def replay(self, order_id: str, *, actor: Actor = SYSTEM_ACTOR) -> PaymentOrder:
        """Put a terminally-undelivered order back on the queue. Not a new payment.

        This creates nothing. It moves an existing row back to ``accepted`` and
        clears the claim bookkeeping, so the worker picks up **the same order**:
        the same ``pain.001``, built once at accept time and stored, carrying
        the same ``MsgId``. There is no path in this service that builds a
        second message for one order, which is what makes replaying safe --
        a file the bank did receive is deduplicated by the ``MsgId`` it already
        has.

        Only from a terminal state this service put the order in: ``failed``
        (we gave up) or ``rejected`` (the bank refused). An order that is
        ``accepted``, ``submitting`` or ``submitted`` is already someone's --
        re-queueing it would be the one way to get two workers onto one
        payment, which is exactly what the atomic claim exists to prevent.

        ``attempts`` is reset, because the operator is asking for a fresh set of
        tries and not for the sixth of the old five.
        """
        order = self.get(order_id)
        if order.state not in REPLAYABLE:
            raise ConflictError(
                f"order {order_id!r} is {order.state.value}; only "
                f"{' or '.join(sorted(state.value for state in REPLAYABLE))} "
                f"orders can be replayed",
                detail={"state": order.state.value})

        now = _dt.datetime.now(_dt.timezone.utc)
        with self._engine.begin() as connection:
            connection.execute(
                payment_order.update()
                .where(payment_order.c.order_id == order_id)
                .values(state=OrderState.ACCEPTED.value, worker_id=None,
                        claimed_at=None, next_attempt_at=None, attempts=0,
                        transaction_id=None, updated_at=now))
        with bind(order_id=order_id, connection_id=order.connection_id,
                  idempotency_key=order.idempotency_key):
            self._audit.record(
                "payment.replay_requested", actor=actor, order_id=order_id,
                connection_id=order.connection_id,
                idempotency_key=order.idempotency_key,
                detail={"from_state": order.state.value,
                        "msg_id": order.msg_id,
                        "return_code": order.return_code,
                        "report_text": order.report_text,
                        "reason": "the stored document is re-sent unchanged; "
                                  "the MsgId is the bank's duplicate control"})
            log.info("payment.replay_requested", from_state=order.state.value,
                     msg_id=order.msg_id, state=OrderState.ACCEPTED.value)
        return self.get(order_id)

    # --- reading -----------------------------------------------------------

    def recent(self, *, connection_id: str | None = None,
               connection_ids: Sequence[str] | None = None,
               state: OrderState | str | None = None,
               limit: int = 50) -> list[PaymentOrder]:
        """Orders newest first, optionally narrowed. What the console lists.

        ``connection_id`` is the filter a reader chose; ``connection_ids`` is
        the set they are allowed to see at all. Both are applied, and the
        second is applied in the query rather than to its result -- a page that
        fetched a hundred rows and discarded ninety would show ten.
        """
        query = select(payment_order).order_by(payment_order.c.seq.desc())
        if connection_id:
            query = query.where(payment_order.c.connection_id == connection_id)
        if connection_ids is not None:
            query = query.where(
                payment_order.c.connection_id.in_(list(connection_ids)))
        if state:
            query = query.where(
                payment_order.c.state == OrderState(state).value)
        with self._engine.connect() as connection:
            rows = connection.execute(
                query.limit(max(1, min(limit, 500)))).mappings().all()
        return [from_row(row) for row in rows]

    def attempts_for(self, order_id: str):
        """Every attempt at this order, oldest first.

        On the store rather than on the order so that listing a hundred orders
        does not fetch a hundred documents: an attempt row carries the message.
        """
        return self._attempts.all(order_id)

    def get(self, order_id: str) -> PaymentOrder:
        with self._engine.connect() as connection:
            row = connection.execute(
                select(payment_order).where(
                    payment_order.c.order_id == order_id)
            ).mappings().one_or_none()
        if row is None:
            raise NotFoundError(f"no such order: {order_id!r}")
        return from_row(row)

    def _find(self, connection_id: str,
              idempotency_key: str) -> PaymentOrder | None:
        with self._engine.connect() as connection:
            row = connection.execute(
                select(payment_order).where(
                    payment_order.c.connection_id == connection_id,
                    payment_order.c.idempotency_key == idempotency_key)
            ).mappings().one_or_none()
        return None if row is None else from_row(row)

    def _fingerprint_of(self, order_id: str) -> str:
        with self._engine.connect() as connection:
            return connection.execute(
                select(payment_order.c.request_fingerprint).where(
                    payment_order.c.order_id == order_id)
            ).scalar_one()


def _scheme_detail(decision: SchemeDecision) -> dict[str, Any]:
    """The scheme fields every payment audit row carries.

    They reach a webhook consumer as `data`, which is how a consumer learns
    that the payment it asked to send instantly went normal without subscribing
    to anything new.
    """
    return {"scheme": decision.effective.value,
            "requested_scheme": decision.requested.value,
            "scheme_downgraded": decision.downgraded,
            "scheme_reason": decision.reason}


def from_row(row: Any) -> PaymentOrder:
    return PaymentOrder(
        order_id=row["order_id"], connection_id=row["connection_id"],
        idempotency_key=row["idempotency_key"],
        state=OrderState(row["state"]), msg_id=row["msg_id"],
        payment_information_id=row["payment_information_id"],
        message_type=row["message_type"],
        transaction_count=row["transaction_count"],
        control_sum=row["control_sum"], currency=row["currency"],
        requested_execution_date=row["requested_execution_date"],
        bank_order_id=row["bank_order_id"], return_code=row["return_code"],
        report_text=row["report_text"],
        bank_status=row["bank_status"],
        status_reason_code=row["status_reason_code"],
        status_reason_text=row["status_reason_text"],
        status_reported_at=row["status_reported_at"],
        transaction_id=row["transaction_id"],
        attempts=row["attempts"],
        requested_scheme=PaymentScheme(row["requested_scheme"]),
        scheme=PaymentScheme(row["scheme"]),
        scheme_reason=row["scheme_reason"],
        accepted_at=row["accepted_at"],
        updated_at=row["updated_at"], document=row["document"],
        refused_request=row["refused_request"],
        refused_request_errors=row["refused_request_errors"],
    )


__all__ = ["IDEMPOTENCY_KEY", "ORDER_ID_PREFIX", "REPLAYABLE", "OrderState",
           "OrderStore", "PaymentOrder", "PaymentScheme", "Submission",
           "fingerprint", "from_row"]
