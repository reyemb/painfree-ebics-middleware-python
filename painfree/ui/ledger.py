"""A normalised `camt` statement as the rows of a bank statement.

Pure, and no database. It takes the normalised payload and the opening balance
the ingestion already computed, and returns the lines a page draws.

**Debit and credit are columns, not a sign.** The payload keeps the bank's own
`credit_debit` beside an unsigned amount, and a statement has put the two
directions in two columns for as long as there have been statements. Turning
them into one signed column would be a formatting choice that loses the shape
every reader already knows, and it would put a minus sign in front of the one
figure an operator most often adds up by eye.

**The running balance is computed here and is marked as computed.** No `camt`
message carries one: a bank sends an opening balance, a closing balance and a
list of entries, and the column between them is arithmetic. It is done in
:class:`decimal.Decimal` over the digits the document carries, because the
whole reason those digits are stored as strings is that a double cannot hold
them. Where there is no opening balance there is no column: guessing a start
would produce a column of numbers that are all wrong by the same amount, which
is worse than not showing one.

**Only booked entries move it.** A `PDNG` entry is money the bank has seen and
not posted; adding it to a running balance would produce a figure that matches
no balance the bank ever states. They are a group of their own, above the
booked ones, with no balance against them.

**An entry that names one of our `MsgId`s is one of our payments.** That is the
last link of the chain a `pain.002` starts: the report said the bank took it,
this says the money left the account. The lookup is done by the caller, which
has the database; this only says which references to look up.
"""

from __future__ import annotations

import decimal
import math
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

#: `Sts/Cd` for an entry that has been posted. Anything else is money the bank
#: has told us about and not booked, whatever it called that state.
BOOKED = "BOOK"

#: What the filter above the table can be set to. `ours` is the entries that
#: settle a payment this service sent.
SHOWS = ("all", "debit", "credit", "ours")


@dataclass(frozen=True, slots=True)
class Line:
    """One `Ntry`, with what a statement row needs to draw it."""

    entry: dict[str, Any]
    credit: bool
    amount: decimal.Decimal | None
    #: The balance after this entry, or ``None`` when there is no column.
    balance: decimal.Decimal | None = None
    #: The order this entry settles, when it names a `MsgId` this service sent.
    order_id: str | None = None

    @property
    def booked(self) -> bool:
        status = self.entry.get("status")
        return status is None or status == BOOKED

    @property
    def counterparty(self) -> dict[str, Any] | None:
        """The other side, from the first transaction that names one."""
        for transaction in self.entry.get("transactions") or ():
            party = transaction.get("counterparty") or {}
            if party.get("name") or party.get("iban"):
                return party
        return None

    @property
    def reference(self) -> dict[str, Any] | None:
        for transaction in self.entry.get("transactions") or ():
            found = transaction.get("reference") or {}
            if found.get("reference"):
                return found
        return None

    @property
    def description(self) -> str | None:
        """What the entry is about, from the most specific place it is said."""
        for transaction in self.entry.get("transactions") or ():
            for name in ("remittance_information", "additional_information"):
                if transaction.get(name):
                    return transaction[name]
        return self.entry.get("additional_information")

    @property
    def batch(self) -> int:
        """How many transactions this one entry collects. One is not a batch."""
        return len(self.entry.get("transactions") or ())


@dataclass(frozen=True, slots=True)
class Ledger:
    """One account statement, as rows and as the two figures under them."""

    booked: tuple[Line, ...]
    pending: tuple[Line, ...]
    #: Whether the balance column means anything. False with no opening balance.
    running: bool
    credited: decimal.Decimal
    debited: decimal.Decimal
    credits: int
    debits: int
    ours: int
    #: Opening plus every booked entry, against the balance the bank stated.
    #: ``None`` when either is missing, so "not checked" and "does not add up"
    #: stay different answers.
    reconciles: bool | None = None

    @property
    def lines(self) -> tuple[Line, ...]:
        return self.pending + self.booked

    def showing(self, show: str) -> tuple[Line, ...]:
        """The booked lines a filter leaves. The balance is not recomputed.

        A filtered statement still shows the account's real balance after each
        entry it does show. Recomputing over the visible rows would produce a
        column that agrees with nothing, including itself on the next filter.
        """
        if show == "debit":
            return tuple(line for line in self.booked if not line.credit)
        if show == "credit":
            return tuple(line for line in self.booked if line.credit)
        if show == "ours":
            return tuple(line for line in self.booked if line.order_id)
        return self.booked


@dataclass(frozen=True, slots=True)
class Day:
    """One end-of-day statement inside an account overview.

    The heading row of a group and the lines under it, newest entry first,
    which is the order a person scanning "what happened lately" reads in. The
    statement's own page keeps document order; the two are different questions.
    """

    row: Mapping[str, Any]
    ledger: Ledger
    lines: tuple[Line, ...]

    @property
    def date(self) -> Any:
        return self.row.get("to_datetime") or self.row.get("ingested_at")


@dataclass(frozen=True, slots=True)
class Overview:
    """One account over a period: its statements read as one ledger.

    Built from end-of-day statements only. An intraday report and a
    notification repeat entries the statement will carry, and an overview that
    added them up would count money twice; what they add is *recency*, so the
    entries they report after the newest statement are shown separately, with
    no balance beside them, as :attr:`intraday`.
    """

    days: tuple[Day, ...]
    intraday: tuple[Line, ...]
    credited: decimal.Decimal
    debited: decimal.Decimal
    credits: int
    debits: int
    ours: int
    #: Consecutive statements whose balances do not meet: the older one closed
    #: with a figure the newer one did not open with. A gap is a statement this
    #: service has not got, and is the one thing an overview must not paper
    #: over.
    gaps: tuple[tuple[Mapping[str, Any], Mapping[str, Any]], ...]
    #: The closing balance of every statement that stated one, oldest first.
    points: tuple[tuple[Any, decimal.Decimal], ...]

    @property
    def newest(self) -> Mapping[str, Any] | None:
        return self.days[0].row if self.days else None

    @property
    def oldest(self) -> Mapping[str, Any] | None:
        return self.days[-1].row if self.days else None

    @property
    def closing(self) -> decimal.Decimal | None:
        """The balance the newest statement stated, which is *the* balance."""
        return self.newest["closing_balance"] if self.newest else None

    @property
    def continuous(self) -> bool:
        return not self.gaps

    def chart(self, width: int = 720, height: int = 160) -> dict[str, Any] | None:
        """The closing balances as a line, in SVG user units.

        Geometry and nothing else: the figures a reader acts on are the decimal
        ones on the page, and this is a picture of their shape. Floats are fine
        for a picture. ``None`` when there are not two points to join.
        """
        if len(self.points) < 2:
            return None
        left, right, top, bottom = 64, 12, 10, 26
        values = [float(value) for _, value in self.points]
        low, high = min(values), max(values)
        pad = (high - low) * 0.15 or max(abs(high) * 0.05, 1.0)
        low, high = low - pad, high + pad
        span = len(self.points) - 1

        def x(index: int) -> float:
            return left + index / span * (width - left - right)

        def y(value: float) -> float:
            return top + (1 - (value - low) / (high - low)) * (height - top - bottom)

        step = _nice_step((high - low) / 3)
        ticks = []
        tick = -(-low // step) * step
        while tick <= high:
            ticks.append({"y": round(y(tick), 1), "value": int(tick)})
            tick += step
        path = " ".join(f"{'M' if i == 0 else 'L'}{x(i):.1f} {y(v):.1f}"
                        for i, v in enumerate(values))
        floor = f"{y(low):.1f}"
        return {
            "width": width, "height": height, "left": left,
            "right": width - right, "bottom": height - 6,
            "path": path,
            "area": f"{path} L{x(span):.1f} {floor} L{left} {floor} Z",
            "ticks": ticks,
            "end": {"x": round(x(span), 1), "y": round(y(values[-1]), 1)},
            "first": self.points[0][0], "last": self.points[-1][0],
        }


def _nice_step(raw: float) -> float:
    """A gridline spacing a reader would have chosen: 1, 2 or 5 times a power of ten."""
    if raw <= 0:
        return 1.0
    power = 10 ** math.floor(math.log10(raw))
    mantissa = raw / power
    factor = 1 if mantissa < 1.5 else 2 if mantissa < 3.5 else 5 if mantissa < 7.5 else 10
    return factor * power


def overview(rows: Sequence[Mapping[str, Any]], *,
             orders: Mapping[str, str] | None = None, show: str = "all",
             intraday: Sequence[Mapping[str, Any]] = ()) -> Overview:
    """One account's end-of-day statements, newest first, read as one ledger.

    ``rows`` are statement rows with their payloads, newest first. Each is read
    with :func:`read` against its own opening and closing balance, so every
    line's balance is still the bank's arithmetic checked per statement, and
    the totals are sums over what those statements booked.
    """
    days = []
    credited = debited = decimal.Decimal(0)
    credits = debits = ours = 0
    for row in rows:
        book = read(row.get("payload") or {}, opening=row.get("opening_balance"),
                    closing=row.get("closing_balance"), orders=orders)
        days.append(Day(row=row, ledger=book,
                        lines=tuple(reversed(book.showing(show)))))
        credited += book.credited
        debited += book.debited
        credits += book.credits
        debits += book.debits
        ours += book.ours

    gaps = []
    for older, newer in zip(reversed(rows), list(reversed(rows))[1:]):
        closing, opening = older.get("closing_balance"), newer.get("opening_balance")
        if closing is not None and opening is not None and closing != opening:
            gaps.append((older, newer))

    points = tuple((row.get("to_datetime") or row.get("ingested_at"),
                    row["closing_balance"])
                   for row in reversed(rows)
                   if row.get("closing_balance") is not None)

    return Overview(days=tuple(days), intraday=_since_last(intraday, orders),
                    credited=credited, debited=debited, credits=credits,
                    debits=debits, ours=ours, gaps=tuple(gaps), points=points)


def _since_last(reports: Sequence[Mapping[str, Any]],
                orders: Mapping[str, str] | None) -> tuple[Line, ...]:
    """The entries the intraday reports carry, each once, newest report first.

    Two reports of the same day repeat each other's entries; a bank reference
    names an entry across them, and an entry without one is told apart by what
    it is.
    """
    orders = orders or {}
    seen: set[Any] = set()
    lines: list[Line] = []
    for report in reports:
        for entry in reversed((report.get("payload") or {}).get("entries") or ()):
            key = (entry.get("reference") or entry.get("account_servicer_reference")
                   or (entry.get("booking_date"), entry.get("amount"),
                       entry.get("credit_debit")))
            if key in seen:
                continue
            seen.add(key)
            lines.append(Line(entry=entry, credit=entry.get("credit_debit") == "credit",
                              amount=_amount(entry.get("amount")),
                              order_id=_order_for(entry, orders)))
    return tuple(lines)


def message_ids(payload: Mapping[str, Any]) -> set[str]:
    """Every `MsgId` the entries name: the candidates for one of our orders."""
    return {transaction["message_identification"]
            for entry in payload.get("entries") or ()
            for transaction in entry.get("transactions") or ()
            if transaction.get("message_identification")}


def read(payload: Mapping[str, Any], *, opening: decimal.Decimal | None = None,
         closing: decimal.Decimal | None = None,
         orders: Mapping[str, str] | None = None) -> Ledger:
    """The statement's entries as lines, in document order."""
    orders = orders or {}
    balance = opening
    booked: list[Line] = []
    pending: list[Line] = []
    credited = debited = decimal.Decimal(0)
    credits = debits = ours = 0

    for entry in payload.get("entries") or ():
        credit = entry.get("credit_debit") == "credit"
        amount = _amount(entry.get("amount"))
        line = Line(entry=entry, credit=credit, amount=amount,
                    order_id=_order_for(entry, orders))
        if not line.booked:
            pending.append(line)
            continue
        if amount is not None:
            if credit:
                credited += amount
                credits += 1
            else:
                debited += amount
                debits += 1
            if balance is not None:
                balance = balance + amount if credit else balance - amount
        ours += 1 if line.order_id else 0
        booked.append(Line(entry=entry, credit=credit, amount=amount,
                           balance=balance, order_id=line.order_id))

    return Ledger(
        booked=tuple(booked), pending=tuple(pending), running=opening is not None,
        credited=credited, debited=debited, credits=credits, debits=debits,
        ours=ours,
        reconciles=None if opening is None or closing is None
        else balance == closing)


def _order_for(entry: Mapping[str, Any], orders: Mapping[str, str]) -> str | None:
    for transaction in entry.get("transactions") or ():
        found = orders.get(transaction.get("message_identification") or "")
        if found:
            return found
    return None


def _amount(value: Any) -> decimal.Decimal | None:
    """The digits the bank sent, or ``None``. A display path never raises."""
    try:
        return decimal.Decimal(str(value))
    except (decimal.InvalidOperation, TypeError, ValueError):
        return None


__all__: Iterable[str] = ["BOOKED", "SHOWS", "Day", "Ledger", "Line", "Overview",
                          "message_ids", "overview", "read"]
