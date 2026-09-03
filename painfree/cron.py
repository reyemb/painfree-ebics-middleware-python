"""A cron expression, for schedules that run at a time rather than at a rate.

**Why an interval was not enough.** ``cadence`` answers "how often", which is
right for a statement nobody is waiting on and wrong for the two cases an
operator actually asks for: *at 08:00*, before anyone looks at the console, and
*every fifteen minutes on working days*, which is a rate with a shape. Neither
can be said with a number of seconds.

**Why this is written here and not installed.** ``croniter`` is the obvious
answer and it is a dependency in a service that holds bank credentials, added to
a lock file that is installed with ``--require-hashes`` precisely so nothing
arrives that nobody chose. The subset below is what an operator writes; anything
else is **refused by name** rather than approximated, so an expression this
cannot evaluate is a message at the form and never a schedule that runs at a
time nobody meant.

Supported, in the five standard fields ``minute hour day-of-month month
day-of-week``:

===============  =========================================
``*``            every value
``5``            exactly that one
``1-5``          a range, inclusive
``*/15``         every 15th value from the start of the range
``1-5/2``        every 2nd value in that range
``0,15,30``      a list of any of the above
===============  =========================================

Sunday is ``0`` **and** ``7``. Names (``MON``, ``JAN``), ``?``, ``L``, ``#``,
``W`` and ``@daily`` are refused: each means something in some other cron, and
guessing which is how a payment download silently moves to a different hour.

**Day-of-month and day-of-week are OR, not AND**, when both are restricted --
the historical Vixie behaviour, and the one every operator's mental model
matches: ``0 8 1 * 1`` is the first of the month *and* every Monday.

Times are UTC, like everything else this service stores. A schedule that must
follow an office's clock is a schedule whose hour moves twice a year, and this
does not pretend otherwise.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass

#: Inclusive bounds per field, in the order cron writes them.
_BOUNDS = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))
_NAMES = ("minute", "hour", "day of month", "month", "day of week")

#: How far ahead a search gives up. A schedule that matches nothing inside four
#: years is one that matches nothing -- 29 February on a weekday, say -- and the
#: honest answer is to say so rather than to loop.
_HORIZON_DAYS = 366 * 4


class CronError(ValueError):
    """The expression is not one this service will act on."""


@dataclass(frozen=True)
class Cron:
    """Five sets of permitted values, and the text they were parsed from."""

    minute: frozenset[int]
    hour: frozenset[int]
    day: frozenset[int]
    month: frozenset[int]
    weekday: frozenset[int]
    expression: str
    #: Whether either day field was restricted. Both unrestricted means every
    #: day; one restricted means that one decides; both restricted means either
    #: may match, which is the Vixie rule.
    day_restricted: bool = False
    weekday_restricted: bool = False

    def matches(self, moment: _dt.datetime) -> bool:
        if moment.minute not in self.minute or moment.hour not in self.hour:
            return False
        if moment.month not in self.month:
            return False
        return self._day_matches(moment)

    def _day_matches(self, moment: _dt.datetime) -> bool:
        # `isoweekday` is 1..7 Monday..Sunday; cron is 0..7 Sunday..Sunday.
        weekday = moment.isoweekday() % 7
        by_day = moment.day in self.day
        by_weekday = weekday in self.weekday
        if self.day_restricted and self.weekday_restricted:
            return by_day or by_weekday
        if self.day_restricted:
            return by_day
        if self.weekday_restricted:
            return by_weekday
        return True

    def next_after(self, moment: _dt.datetime) -> _dt.datetime:
        """The first matching minute strictly after *moment*.

        Whole days are skipped when the date cannot match, so this costs a few
        hundred comparisons rather than a walk over every minute of a year.
        """
        if moment.tzinfo is None:
            raise CronError("a cron search needs an aware moment")
        candidate = (moment.replace(second=0, microsecond=0)
                     + _dt.timedelta(minutes=1))
        limit = moment + _dt.timedelta(days=_HORIZON_DAYS)
        while candidate <= limit:
            if candidate.month not in self.month or not self._day_matches(candidate):
                # Nothing today can match: jump to midnight tomorrow.
                candidate = (candidate.replace(hour=0, minute=0)
                             + _dt.timedelta(days=1))
                continue
            if candidate.hour not in self.hour:
                candidate = candidate.replace(minute=0) + _dt.timedelta(hours=1)
                continue
            if candidate.minute not in self.minute:
                candidate += _dt.timedelta(minutes=1)
                continue
            return candidate
        raise CronError(
            f"{self.expression!r} matches no time in the next "
            f"{_HORIZON_DAYS // 366} years")


def _field(text: str, index: int) -> tuple[frozenset[int], bool]:
    """One field as the set of values it permits, and whether it restricts."""
    low, high = _BOUNDS[index]
    name = _NAMES[index]
    if not text:
        raise CronError(f"the {name} field is empty")
    for forbidden, why in ((",,", "an empty item"), ("?", "`?`"), ("L", "`L`"),
                           ("#", "`#`"), ("W", "`W`"), ("@", "`@`")):
        if forbidden in text.upper():
            raise CronError(
                f"the {name} field uses {why}, which this service does not "
                f"read. Write plain numbers, ranges and steps: * 5 1-5 */15")
    if any(character.isalpha() for character in text):
        raise CronError(
            f"the {name} field uses a name; write the number instead "
            f"(Sunday is 0 or 7, January is 1)")

    values: set[int] = set()
    restricts = False
    for item in text.split(","):
        body, _, step_text = item.partition("/")
        try:
            step = int(step_text) if step_text else 1
        except ValueError:
            raise CronError(f"{step_text!r} is not a step in the {name} field")
        if step < 1:
            raise CronError(f"a step in the {name} field must be 1 or more")

        if body == "*":
            start, stop = low, high
        elif "-" in body.lstrip("-"):
            first, _, last = body.partition("-")
            start, stop = _number(first, index), _number(last, index)
            if start > stop:
                raise CronError(
                    f"{body!r} runs backwards in the {name} field")
            restricts = True
        else:
            start = stop = _number(body, index)
            restricts = True
        if step > 1:
            restricts = True
        values.update(range(start, stop + 1, step))

    if not values:
        raise CronError(f"the {name} field permits nothing")
    if index == 4 and 7 in values:
        # Sunday is written either way and means one day.
        values.discard(7)
        values.add(0)
    return frozenset(values), restricts


def _number(text: str, index: int) -> int:
    low, high = _BOUNDS[index]
    try:
        value = int(text)
    except ValueError:
        raise CronError(f"{text!r} is not a number in the {_NAMES[index]} field")
    if not low <= value <= high:
        raise CronError(
            f"{value} is outside {low}-{high} in the {_NAMES[index]} field")
    return value


def parse(expression: str) -> Cron:
    """Read a five-field expression, or refuse it with the reason."""
    text = " ".join((expression or "").split())
    if not text:
        raise CronError("no expression")
    fields = text.split(" ")
    if len(fields) != 5:
        raise CronError(
            f"a cron expression has five fields -- minute hour day month "
            f"weekday -- and this has {len(fields)}: {text!r}")

    parsed = [_field(field, index) for index, field in enumerate(fields)]
    return Cron(minute=parsed[0][0], hour=parsed[1][0], day=parsed[2][0],
                month=parsed[3][0], weekday=parsed[4][0],
                expression=text,
                day_restricted=parsed[2][1], weekday_restricted=parsed[4][1])


def describe(expression: str) -> str:
    """A short sentence for the console, or the reason it will not run."""
    try:
        cron = parse(expression)
    except CronError as error:
        return str(error)
    now = _dt.datetime.now(_dt.timezone.utc)
    return f"next run {cron.next_after(now).strftime('%Y-%m-%d %H:%M')} UTC"


__all__ = ["Cron", "CronError", "describe", "parse"]
