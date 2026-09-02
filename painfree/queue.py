"""Claiming an order for upload, and recording how the upload went.

Everything here is database work with no keys in it, which is why it is a
module of its own: the claim is the part that must be right under concurrency,
and it is reviewable without reading a line of EBICS.

**The claim is one statement.** Two workers polling the same table is the
default deployment, not an edge case, and a read-then-write cannot survive it --
both read "state = accepted", both write "state = submitting", both upload, and
the payment goes out twice. So the claim is a single conditional ``UPDATE``
whose subquery selects the candidate and whose ``RETURNING`` hands back the row
it actually took:

```sql
UPDATE payment_order SET state='submitting', worker_id=…, attempts=attempts+1
 WHERE seq = (SELECT seq FROM payment_order
               WHERE …            -- queued, or a lease that has expired
               ORDER BY seq LIMIT 1
               FOR UPDATE SKIP LOCKED)      -- PostgreSQL only
RETURNING *
```

On PostgreSQL ``FOR UPDATE SKIP LOCKED`` is what makes several workers pick
*different* rows instead of queueing behind the same one. SQLite has no such
clause and needs none: its writers are serialised by one database-level write
lock, so the subquery is evaluated under the same lock as the update. Either
way exactly one worker's ``UPDATE`` affects a row, and a worker that affected
none simply has nothing to do.

**The lease is the other half.** A worker that dies mid-upload leaves an order
in ``submitting`` with nobody driving it, and an order nobody will ever pick up
again is a payment that silently never happens. ``claimed_at`` is therefore a
lease: after :data:`CLAIM_LEASE` another worker may take the order over. That is
deliberately an at-least-once guarantee and not an exactly-once one -- the
window where a worker uploaded the last segment and died before writing the
outcome is real, and what covers it is that a retry re-sends the *same*
``MsgId`` and the same bytes, which the bank deduplicates. The alternative --
never reclaiming -- trades a duplicate the bank catches for a payment that never
goes out, which is worse.

**Retry policy lives here, not in the worker.** ``attempts`` counts claims, so
an order that is claimed and lost still converges on the ceiling rather than
being retried for ever; :func:`backoff` spaces the attempts out; and the
transition to ``failed`` happens in one place so "permanently undeliverable"
means one thing.

The states are the order lifecycle's: ``rejected`` is the bank saying no,
``failed`` is this service giving up. They are not the same event and an
operator reads them differently.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Engine, and_, or_, select

from painfree.attempts import LIVE, PLANNED, SUPERSEDED, Attempt, AttemptStore
from painfree.ebics3 import envelope_schema
from painfree.audit import FAILURE, SUCCESS, AuditLog
from painfree.logging import bind, get_logger
from painfree.orders import OrderState, PaymentOrder, from_row
from painfree.schema import payment_attempt, payment_order
from painfree.schemes import (BANK_REFUSED_INSTANT, PaymentScheme,
                              SchemeProfiles)

log = get_logger("painfree.queue")

#: How long a claim is good for. Long enough that a slow multi-segment upload
#: to a slow bank is never mistaken for a dead worker, short enough that a
#: crashed worker's order is not stranded for a business day.
CLAIM_LEASE = _dt.timedelta(minutes=15)

#: How many times one order is claimed before it is called undeliverable. The
#: last entry of :data:`BACKOFF` is reused for anything past its length, so the
#: two numbers do not have to be kept in step.
MAX_ATTEMPTS = 5

#: The wait before each subsequent attempt. Not exponential to the sky: a bank
#: that is down is down for minutes, and an order that has waited half an hour
#: four times is one an operator should be looking at, not one the queue should
#: keep quietly deferring.
BACKOFF = (
    _dt.timedelta(seconds=30),
    _dt.timedelta(minutes=2),
    _dt.timedelta(minutes=10),
    _dt.timedelta(minutes=30),
)

#: `last_error` is a diagnostic, not a payload. Anything longer is truncated
#: rather than refused, because losing the row would lose the diagnosis too.
MAX_ERROR_LENGTH = 512


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def backoff(attempts: int) -> _dt.timedelta:
    """How long to wait before the attempt after ``attempts`` failed ones."""
    index = max(0, min(attempts, len(BACKOFF)) - 1)
    return BACKOFF[index]


@dataclass(frozen=True, slots=True)
class ClaimedOrder:
    """One order this worker now owns, with the claim's own bookkeeping.

    ``order`` is the full row including the ``pain.001`` document. ``attempts``
    is *this* attempt's number, counting from 1, which is what the retry
    decision is made against.
    """

    order: PaymentOrder
    worker_id: str
    attempts: int
    claimed_at: _dt.datetime
    reopens: bool
    """Did a previous attempt already open an EBICS transaction for this order?

    The one flag worth carrying out of the claim: it marks the case where the
    same payment may reach the bank twice, and it is why the ``MsgId`` is
    never regenerated.
    """

    @property
    def order_id(self) -> str:
        return self.order.order_id

    @property
    def connection_id(self) -> str:
        return self.order.connection_id


@dataclass(frozen=True, slots=True)
class Downgrade:
    """A fallback that was taken: what was refused, and what is now live."""

    order_id: str
    attempt: Attempt
    was: PaymentScheme
    now: PaymentScheme
    return_code: str | None
    report_text: str | None
    reason: str


class OrderQueue:
    """The worker's view of ``payment_order``: claim it, then say how it went.

    Deliberately separate from :class:`painfree.orders.OrderStore`, which is
    the request path's view. The two touch the same table and neither can do
    the other's job: the store never claims and this never validates.
    """

    __slots__ = ("_engine", "_audit", "_attempts")

    def __init__(self, engine: Engine, audit: AuditLog | None = None) -> None:
        self._engine = engine
        self._audit = audit or AuditLog(engine)
        self._attempts = AttemptStore(engine)

    @property
    def attempts(self) -> AttemptStore:
        return self._attempts

    # --- claiming ----------------------------------------------------------

    def claim(self, *, worker_id: str, now: _dt.datetime | None = None,
              lease: _dt.timedelta = CLAIM_LEASE) -> ClaimedOrder | None:
        """Take the oldest claimable order, atomically. ``None`` if there is none."""
        now = now or utcnow()
        expired = now - lease
        statement = (
            payment_order.update()
            .where(payment_order.c.seq
                   == self._candidate(now, expired).scalar_subquery())
            .values(state=OrderState.SUBMITTING.value, worker_id=worker_id,
                    claimed_at=now, attempts=payment_order.c.attempts + 1,
                    updated_at=now)
            .returning(*payment_order.c)
        )
        with self._engine.begin() as connection:
            row = connection.execute(statement).mappings().one_or_none()
        if row is None:
            return None

        # `attempts` is post-increment, so a value above 1 means this order has
        # been here before -- either a retry after a failure, or a lease that
        # expired under a worker that never came back. The second is worth a
        # warning: it is the only path in this service that can put the same
        # payment on the wire twice.
        claimed = ClaimedOrder(order=from_row(row), worker_id=worker_id,
                               attempts=row["attempts"], claimed_at=now,
                               reopens=row["transaction_id"] is not None)
        with bind(order_id=claimed.order_id,
                  connection_id=claimed.connection_id):
            if claimed.reopens:
                log.warning(
                    "order.reclaimed", worker_id=worker_id,
                    attempt=claimed.attempts,
                    transaction_id=row["transaction_id"],
                    reason="a previous attempt had an open EBICS transaction; "
                           "the retry re-sends the same MsgId, which the bank "
                           "deduplicates",
                )
            log.info("order.claimed", worker_id=worker_id,
                     attempt=claimed.attempts,
                     state=OrderState.SUBMITTING.value,
                     msg_id=claimed.order.msg_id)
        return claimed

    def _candidate(self, now: _dt.datetime, expired: _dt.datetime):
        """The one row a claim will try to take, locked where the backend can."""
        query = (
            select(payment_order.c.seq)
            .where(or_(
                # Queued, and past its backoff if it has one.
                and_(payment_order.c.state == OrderState.ACCEPTED.value,
                     or_(payment_order.c.next_attempt_at.is_(None),
                         payment_order.c.next_attempt_at <= now)),
                # Claimed by a worker that has not been heard from since.
                and_(payment_order.c.state == OrderState.SUBMITTING.value,
                     payment_order.c.claimed_at.is_not(None),
                     payment_order.c.claimed_at < expired),
            ))
            .order_by(payment_order.c.seq)
            .limit(1)
        )
        if self._engine.dialect.name == "postgresql":
            # So two workers pick different rows instead of one waiting for the
            # other. SQLite has no such clause and does not need one -- its
            # writers are serialised by a single database-level lock.
            query = query.with_for_update(skip_locked=True)
        return query

    # --- outcomes ----------------------------------------------------------

    def opened(self, order_id: str, *, transaction_id: str | None,
               bank_order_id: str | None = None) -> None:
        """Persist the ``TransactionID`` the moment the bank assigns it.

        Written before a single segment goes out, because it is the only handle
        on an open transaction and a worker that loses it has to start again.
        """
        self._update(order_id, transaction_id=transaction_id,
                     **({"bank_order_id": bank_order_id} if bank_order_id else {}))

    def submitted(self, order_id: str, *, bank_order_id: str | None,
                  return_code: str | None, report_text: str | None) -> OrderState:
        """The bank took the file. Not success -- the bank has not judged it
        yet."""
        return self._settle(order_id, OrderState.SUBMITTED, "payment.submitted",
                            bank_order_id=bank_order_id, return_code=return_code,
                            report_text=report_text, last_error=None,
                            outcome_ok=True)

    def refused(self, order_id: str, *, return_code: str | None,
                report_text: str | None, name: str | None = None,
                request: bytes | None = None) -> OrderState:
        """The bank said no, and repeating it would not change the answer.

        The return code and the bank's own ``ReportText`` are stored verbatim.
        They are the two fields a support call is answered with, and folding
        them into a generic message is how that call becomes a day's work.

        ``request`` is the EBICS document that was refused, kept for the same
        reason: a code like `091113` names no element, and without the document
        the only party who can still see it is the bank. It is checked against
        the official H005 schemas here, once, and the verdict stored beside it
        -- a clean result is a *finding* (the disagreement is semantic, not
        structural) and not this service being exonerated.
        """
        errors = None
        if request is not None:
            errors = envelope_schema.schema_failures(request)
            log.info("ebics.refused_request_checked", order_id=order_id,
                     return_code=return_code, bytes=len(request),
                     schema_failures=len(errors),
                     reason="the request the bank refused, kept and checked "
                            "against the H005 schemas")
        return self._settle(order_id, OrderState.REJECTED, "payment.rejected",
                            return_code=return_code, report_text=report_text,
                            last_error=None, outcome_ok=False,
                            refused_request=request,
                            refused_request_errors=errors,
                            detail={"return_code_name": name,
                                    "request_schema_failures":
                                        None if errors is None else len(errors)})

    def retry_later(self, order_id: str, *, attempts: int, reason: str,
                    return_code: str | None = None,
                    report_text: str | None = None,
                    now: _dt.datetime | None = None) -> OrderState:
        """Put the order back, or give up on it. The only place that decides.

        Back to ``accepted`` with a wait in front of it, until the ceiling --
        and then ``failed``, which means this service stopped trying, not that
        the bank refused. Keeping the two words apart is what lets an operator
        tell "the bank rejected the file" from "we never got it there".
        """
        now = now or utcnow()
        if attempts >= MAX_ATTEMPTS:
            return self._settle(
                order_id, OrderState.FAILED, "payment.failed",
                return_code=return_code, report_text=report_text,
                last_error=_short(reason), outcome_ok=False,
                detail={"attempts": attempts, "reason": _short(reason)})

        wait = backoff(attempts)
        self._update(order_id, state=OrderState.ACCEPTED.value, worker_id=None,
                     claimed_at=None, next_attempt_at=now + wait,
                     last_error=_short(reason), return_code=return_code,
                     report_text=report_text, updated_at=now)
        with bind(order_id=order_id):
            log.warning("payment.retry_scheduled", state=OrderState.ACCEPTED.value,
                        attempt=attempts, next_attempt_in_s=int(wait.total_seconds()),
                        return_code=return_code, report_text=report_text,
                        reason=_short(reason))
        return OrderState.ACCEPTED

    # --- the fallback, and every reason it does not happen -----------------

    def fall_back(self, claimed: ClaimedOrder, *, profiles: SchemeProfiles,
                  return_code: str | None, report_text: str | None,
                  name: str | None = None) -> "Downgrade | None":
        """Promote the reserve attempt, or refuse to and return ``None``.

        **This is the one method in this service that can put a second message
        on the wire for one order, and it is written to be read as such.**
        These are its conditions, and every one of them has to hold:

        1. the caller asked for ``instant_or_normal``, so a reserve attempt was
           built and validated at accept time and is sitting in ``planned``;
        2. the live attempt is ``instant`` -- a normal attempt has nothing to
           fall back to;
        3. the return code is in **this connection's whitelist** of codes that
           mean *instant could not be used*. A whitelist, so an unrecognised
           refusal ends the order instead of sending a second file;
        4. the order is still ``submitting`` and still claimed by **this**
           worker, so a lease that expired under us cannot be promoted from
           underneath the worker that took over;
        5. the order has **no ``TransactionID`` and no ``OrderID``**. EBICS
           assigns a ``TransactionID`` in the initialisation response and
           :meth:`opened` persists it before a single segment goes out, so this
           is the check that the bank never acknowledged receipt of anything.

        4 and 5 are ``WHERE`` clauses on a conditional ``UPDATE``, so they are
        decided by the database in the same statement that acts on them, the way
        the claim is. There is no read-then-write here either.

        What is **not** a condition, and cannot become one: a timeout, a dropped
        connection, an unparseable response, or any other outcome where the bank
        might have taken the file. None of those reaches this method at all --
        they end in :meth:`retry_later`, which has no path to a promotion -- and
        that separation is the reason an unknown outcome cannot become a second
        payment.
        """
        if not profiles.refuses_instant(return_code):
            return None
        if claimed.order.scheme is not PaymentScheme.INSTANT:
            return None
        reserve = self._attempts.planned(claimed.order_id)
        if reserve is None:
            return None

        now = utcnow()
        reason = f"{BANK_REFUSED_INSTANT}:{return_code}"
        promotion = (
            payment_order.update()
            .where(payment_order.c.order_id == claimed.order_id,
                   payment_order.c.state == OrderState.SUBMITTING.value,
                   payment_order.c.worker_id == claimed.worker_id,
                   payment_order.c.scheme == PaymentScheme.INSTANT.value,
                   # The bank acknowledged nothing. Both, not either: a bank
                   # that assigned an `OrderID` has the file.
                   payment_order.c.transaction_id.is_(None),
                   payment_order.c.bank_order_id.is_(None))
            .values(state=OrderState.ACCEPTED.value, worker_id=None,
                    claimed_at=None, next_attempt_at=None,
                    transaction_id=None,
                    # The reserve gets its own five tries. It is a different
                    # message to a different scheme, not the sixth try of the
                    # one that was refused.
                    attempts=0,
                    msg_id=reserve.msg_id, document=reserve.document,
                    payment_information_id=reserve.payment_information_id,
                    scheme=reserve.scheme.value, scheme_reason=reason,
                    return_code=return_code, report_text=report_text,
                    last_error=None, updated_at=now)
        )
        with self._engine.begin() as connection:
            if connection.execute(promotion).rowcount != 1:
                # A condition the database owns did not hold. Nothing was
                # written, and the caller records an ordinary refusal.
                return None
            # Same transaction: an instant that no longer exists next to a
            # reserve that is not yet live is a state no reader may observe.
            connection.execute(
                payment_attempt.update()
                .where(payment_attempt.c.order_id == claimed.order_id,
                       payment_attempt.c.state == LIVE)
                .values(state=SUPERSEDED, return_code=return_code,
                        report_text=report_text, updated_at=now))
            connection.execute(
                payment_attempt.update()
                .where(payment_attempt.c.attempt_id == reserve.attempt_id,
                       payment_attempt.c.state == PLANNED)
                .values(state=LIVE, reason=reason, updated_at=now))

        downgrade = Downgrade(
            order_id=claimed.order_id, attempt=reserve,
            was=PaymentScheme.INSTANT, now=reserve.scheme,
            return_code=return_code, report_text=report_text, reason=reason)
        connection_id, idempotency_key, _ = self._correlation_of(
            claimed.order_id)
        with bind(order_id=claimed.order_id, connection_id=connection_id,
                  idempotency_key=idempotency_key):
            self._audit.record(
                "payment.scheme_downgraded", order_id=claimed.order_id,
                connection_id=connection_id, idempotency_key=idempotency_key,
                detail={"scheme": reserve.scheme.value,
                        "previous_scheme": PaymentScheme.INSTANT.value,
                        "requested_scheme":
                            claimed.order.requested_scheme.value,
                        "scheme_downgraded": True,
                        "scheme_reason": reason,
                        "return_code": return_code,
                        "return_code_name": name,
                        "report_text": report_text,
                        "msg_id": reserve.msg_id,
                        "superseded_msg_id": claimed.order.msg_id,
                        "btf": reserve.btf_summary,
                        "payment_type_information": reserve.payment_type},
            )
            log.warning(
                "payment.scheme_downgraded", state=OrderState.ACCEPTED.value,
                scheme=reserve.scheme.value,
                previous_scheme=PaymentScheme.INSTANT.value,
                requested_scheme=claimed.order.requested_scheme.value,
                return_code=return_code, report_text=report_text,
                msg_id=reserve.msg_id, superseded_msg_id=claimed.order.msg_id,
                btf=reserve.btf_summary, scheme_reason=reason)
        return downgrade

    # --- storage -----------------------------------------------------------

    def _settle(self, order_id: str, state: OrderState, action: str, *,
                outcome_ok: bool, detail: dict[str, Any] | None = None,
                **values: Any) -> OrderState:
        """Move an order to a state no worker will claim again, and record it.

        The claim columns are cleared in the same statement as the state, so
        there is no instant in which a terminal order still looks claimed.
        """
        now = utcnow()
        self._update(order_id, state=state.value, worker_id=None,
                     claimed_at=None, next_attempt_at=None, updated_at=now,
                     **values)
        # The bank's answer belongs on the attempt that provoked it as well as
        # on the order: an order that fell back carries the *second* attempt's
        # return code, and the first one's would otherwise be lost.
        if "return_code" in values or "report_text" in values:
            with self._engine.begin() as connection:
                connection.execute(
                    payment_attempt.update()
                    .where(payment_attempt.c.order_id == order_id,
                           payment_attempt.c.state == LIVE)
                    .values(return_code=values.get("return_code"),
                            report_text=values.get("report_text"),
                            updated_at=now))
        connection_id, idempotency_key, scheme = self._correlation_of(order_id)
        # `order_state`, not `state`: `state` is on the log stream's blocklist
        # -- it is an OIDC login parameter -- so a detail written under that
        # name reaches the audit row and the webhook as `***`. The name is the
        # part that can move; the blocklist is a security control and cannot.
        recorded = {"order_state": state.value,
                    "bank_order_id": values.get("bank_order_id"),
                    "return_code": values.get("return_code"),
                    "report_text": values.get("report_text"),
                    # On every terminal transition, not only on the accept: a
                    # consumer that learns a payment was submitted has to be
                    # able to see it went normal after asking for instant,
                    # without subscribing to anything new.
                    **scheme,
                    **(detail or {})}
        with bind(order_id=order_id, connection_id=connection_id,
                  idempotency_key=idempotency_key):
            self._audit.record(
                action, outcome=SUCCESS if outcome_ok else FAILURE,
                order_id=order_id, connection_id=connection_id,
                idempotency_key=idempotency_key,
                detail={k: v for k, v in recorded.items() if v is not None},
            )
            log.info("payment.state_changed", state=state.value,
                     bank_order_id=values.get("bank_order_id"),
                     return_code=values.get("return_code"),
                     report_text=values.get("report_text"))
        return state

    def _update(self, order_id: str, **values: Any) -> None:
        values.setdefault("updated_at", utcnow())
        with self._engine.begin() as connection:
            connection.execute(
                payment_order.update()
                .where(payment_order.c.order_id == order_id)
                .values(**values))

    def _correlation_of(
        self, order_id: str
    ) -> tuple[str | None, str | None, dict[str, Any]]:
        """The connection, the caller's own key, and the scheme, for the row.

        The idempotency key is the value the *caller* chose, so it is what they
        correlate a later event against; every terminal transition carries it
        rather than only the accept did. The scheme rides along for the same
        reason, and is read off the order rather than passed in: a caller that
        forgot to pass it would produce an event that quietly omits the fact
        that a payment went out under a scheme nobody asked for.
        """
        with self._engine.connect() as connection:
            row = connection.execute(
                select(payment_order.c.connection_id,
                       payment_order.c.idempotency_key,
                       payment_order.c.requested_scheme,
                       payment_order.c.scheme,
                       payment_order.c.scheme_reason)
                .where(payment_order.c.order_id == order_id)).one_or_none()
        if row is None:
            return None, None, {}
        return row[0], row[1], {
            "scheme": row[3],
            "requested_scheme": row[2],
            "scheme_downgraded": (PaymentScheme(row[2]).wants_instant
                                  and row[3] == PaymentScheme.NORMAL.value),
            "scheme_reason": row[4],
        }


def _short(reason: str) -> str:
    reason = " ".join(str(reason).split())
    return reason if len(reason) <= MAX_ERROR_LENGTH else (
        reason[:MAX_ERROR_LENGTH - 1] + "…")


__all__ = ["BACKOFF", "CLAIM_LEASE", "MAX_ATTEMPTS", "ClaimedOrder",
           "Downgrade", "OrderQueue", "backoff", "utcnow"]
