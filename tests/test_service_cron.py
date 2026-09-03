"""A cron expression, and every way this service refuses one.

The parser is small on purpose and the refusals are the point of it. An
expression it cannot evaluate has to be a message at the form, never a schedule
that runs at an hour nobody meant — a download at the wrong time is a bank
conversation nobody is watching.
"""

from __future__ import annotations

import datetime as _dt

import pytest

from painfree.cron import CronError, describe, parse

#: A Thursday, mid-afternoon, so weekday and weekend cases differ visibly.
NOW = _dt.datetime(2026, 9, 3, 16, 42, tzinfo=_dt.timezone.utc)


def runs(expression: str, count: int = 3, after: _dt.datetime = NOW):
    cron = parse(expression)
    out = []
    moment = after
    for _ in range(count):
        moment = cron.next_after(moment)
        out.append(moment)
    return out


def test_a_daily_time_is_the_case_this_exists_for():
    """"At 08:00" is what an interval cannot say."""
    assert [moment.strftime("%a %d.%m %H:%M") for moment in runs("0 8 * * *")] == [
        "Fri 04.09 08:00", "Sat 05.09 08:00", "Sun 06.09 08:00"]


def test_a_rate_with_a_shape():
    """Every quarter hour, working days only -- a rate an interval cannot express."""
    assert [moment.strftime("%a %H:%M") for moment in runs("*/15 * * * 1-5")] == [
        "Thu 16:45", "Thu 17:00", "Thu 17:15"]
    # And it stops at the weekend.
    friday_night = _dt.datetime(2026, 9, 4, 23, 50, tzinfo=_dt.timezone.utc)
    assert runs("*/15 * * * 1-5", 1, friday_night)[0].strftime("%a %H:%M") == "Mon 00:00"


def test_day_of_month_and_weekday_are_or_not_and():
    """The Vixie rule, and the one an operator's mental model matches: `0 8 1 * 1`
    is the first of the month *and* every Monday, not their intersection."""
    days = {moment.strftime("%d.%m") for moment in runs("0 8 1 * 1", 8)}
    assert "07.09" in days, "Mondays"
    assert "01.10" in days, "and the first of the month"


def test_one_restricted_day_field_decides_alone():
    """With only the weekday restricted, every matching weekday runs -- the
    unrestricted day-of-month must not narrow it."""
    assert all(moment.isoweekday() == 7 for moment in runs("5 4 * * 0", 4))


def test_a_search_that_spans_years_still_terminates():
    """29 February exists in one year in four, and the walk skips whole days
    rather than every minute of them."""
    assert [moment.year for moment in runs("0 0 29 2 *", 3)] == [2028, 2032, 2036]


def test_sunday_is_written_either_way_and_means_one_day():
    assert parse("0 8 * * 0").weekday == parse("0 8 * * 7").weekday


def test_lists_and_stepped_ranges():
    assert [moment.strftime("%d.%m %H:%M") for moment in runs("30 6,18 * * *")] == [
        "03.09 18:30", "04.09 06:30", "04.09 18:30"]
    assert parse("0 8-16/4 * * *").hour == frozenset({8, 12, 16})


@pytest.mark.parametrize("expression, fragment", [
    ("0 8 * *", "five fields"),
    ("0 8 * * * *", "five fields"),
    ("", "no expression"),
    ("0 8 * * MON", "uses a name"),
    ("0 JAN * * *", "uses a name"),
    ("0 8 * * ?", "`?`"),
    ("0 L * * *", "`L`"),
    ("0 8 * * 1#2", "`#`"),
    ("0 8 15W * *", "`W`"),
    ("@daily", "five fields"),
    ("70 8 * * *", "outside 0-59"),
    ("0 25 * * *", "outside 0-23"),
    ("0 8 32 * *", "outside 1-31"),
    ("0 8 * 13 *", "outside 1-12"),
    ("5-1 8 * * *", "runs backwards"),
    ("0 8 * * 1-", "not a number"),
    ("*/0 8 * * *", "must be 1 or more"),
])
def test_what_is_refused_and_why(expression, fragment):
    """Every one of these means something in some other cron. Guessing which is
    how a payment download silently moves to a different hour."""
    with pytest.raises(CronError) as refused:
        parse(expression)
    assert fragment in str(refused.value), str(refused.value)


def test_a_naive_moment_is_refused_rather_than_assumed_utc():
    with pytest.raises(CronError, match="aware"):
        parse("0 8 * * *").next_after(_dt.datetime(2026, 9, 3, 16, 42))


def test_describe_says_the_next_run_or_the_reason():
    assert "next run" in describe("0 8 * * *")
    assert "five fields" in describe("0 8 * *")


def test_the_expression_is_kept_as_written_but_normalised_for_spacing():
    assert parse("  0   8 * * *  ").expression == "0 8 * * *"
