"""The scheduler: what is due, who owns it, and where the window got to.

Three properties are worth failing a deploy over and each is tested the way it
breaks:

* **two schedulers do not both fetch one window** -- eight threads claiming at
  one instant, on SQLite and on PostgreSQL, asserting one claim;
* **a restart does not stampede** -- a schedule overdue by a day runs once, not
  once per missed interval;
* **a failed run does not advance the window** -- so the missed days are asked
  for again instead of being skipped in silence.
"""

from __future__ import annotations

import concurrent.futures
import datetime as _dt
import os
import random

import pytest

from painfree import db
from painfree.audit import AuditLog
from painfree.config import load_settings
from painfree.connections import ConnectionRegistry
from painfree.errors import ConflictError
from painfree.schedule import (COMPLETE, EMPTY, FAILED, RUNNING, DownloadSchedules,
                               utcnow)
from painfree.schema import bank_connection, download_run, download_schedule
from conftest import BANK_CONNECTION_ID

POSTGRES_URL = os.environ.get("POSTGRES_TEST_URL")
needs_postgres = pytest.mark.skipif(
    POSTGRES_URL is None,
    reason="POSTGRES_TEST_URL is not set: no PostgreSQL server was reached, so "
           "the claim was not proved against FOR UPDATE SKIP LOCKED")

#: A statement download, as a Swiss bank publishes it. The BTF is registered
#: rather than inferred -- see `DownloadSchedules.register`.
STATEMENTS = {"service_name": "EOP", "scope": "CH", "container": "ZIP",
              "msg_name": "camt.053", "msg_version": "08"}


@pytest.fixture
def schedules(sqlite_url):
    engine = db.build_engine(load_settings(database_url=sqlite_url))
    db.migrate(engine)
    ConnectionRegistry(engine, AuditLog(engine)).register(
        BANK_CONNECTION_ID, host_id="TESTHOST", partner_id="PARTNER1",
        user_id="USER1", host_url="http://127.0.0.1:1/ebics")
    # A pinned jitter source, so "the next run is roughly a cadence away" is an
    # assertion rather than a coin toss.
    yield engine, DownloadSchedules(engine, jitter=random.Random(20260829))
    engine.dispose()


def register(store, **overrides):
    values = {**STATEMENTS, "cadence": _dt.timedelta(hours=1)}
    values.update(overrides)
    return store.register(BANK_CONNECTION_ID, **values)


# --- registration -----------------------------------------------------------


def test_a_schedule_carries_the_btf_the_bank_publishes(schedules):
    _, store = schedules
    schedule = register(store)

    service = schedule.service
    assert service.name == "EOP"
    assert service.msg_name == "camt.053"
    assert service.msg_version == "08"
    assert service.container == "ZIP"
    assert schedule.label == "EOP/camt.053.08"


def test_a_btf_the_bank_would_refuse_is_refused_here(schedules):
    """Validated by the engine's own rules, not by a second set written here.

    A `ServiceName` of four characters is answered with
    `EBICS_INVALID_ORDER_PARAMS` hours later; refusing it at registration is
    the same rule the payment path applies to `pain.001`.
    """
    from painfree.ebics3 import RequestError

    _, store = schedules
    with pytest.raises(RequestError):
        register(store, service_name="EOPX")


def test_a_cadence_shorter_than_the_minimum_is_refused(schedules):
    _, store = schedules
    with pytest.raises(ConflictError):
        register(store, cadence=_dt.timedelta(seconds=1))


def test_two_schedules_for_one_btf_on_one_connection_are_refused(schedules):
    """Two rows asking one bank for one thing is two downloads of one statement.

    The refusal is the unique constraint, and it is surfaced as a named
    `409` that quotes the schedule already holding the BTF -- so a caller
    retrying a registration is told what exists rather than handed an
    `internal_error`. It is a constraint and not a check because two processes
    registering at once both pass a check.
    """
    _, store = schedules
    first = register(store)
    with pytest.raises(ConflictError) as refused:
        register(store, cadence=_dt.timedelta(hours=2))
    assert first.schedule_id in str(refused.value)
    assert refused.value.detail["schedule_id"] == first.schedule_id
    assert len(store.all(BANK_CONNECTION_ID)) == 1


def test_a_second_message_type_on_the_same_connection_is_fine(schedules):
    _, store = schedules
    register(store)
    register(store, msg_name="camt.052", service_name="STM")
    assert len(store.all(BANK_CONNECTION_ID)) == 2


# --- claiming ---------------------------------------------------------------


def test_a_schedule_that_is_not_due_is_not_claimed(schedules):
    _, store = schedules
    register(store, due_at=utcnow() + _dt.timedelta(hours=1))
    assert store.claim(worker_id="w1") is None


def test_claiming_opens_a_run_that_records_what_was_asked_for(schedules):
    engine, store = schedules
    schedule = register(store, window_days=7)
    claimed = store.claim(worker_id="w1")

    assert claimed is not None
    assert claimed.schedule_id == schedule.schedule_id
    assert claimed.window_start and claimed.window_end
    runs = store.runs(schedule.schedule_id)
    assert len(runs) == 1
    assert runs[0]["state"] == RUNNING
    assert runs[0]["window_start"] == claimed.window_start
    assert runs[0]["worker_id"] == "w1"


def test_a_disabled_schedule_is_never_claimed(schedules):
    _, store = schedules
    schedule = register(store)
    store.set_enabled(schedule.schedule_id, False)
    assert store.claim(worker_id="w1") is None


def test_a_claimed_schedule_is_not_claimed_again_while_the_lease_holds(schedules):
    _, store = schedules
    register(store)
    assert store.claim(worker_id="w1") is not None
    assert store.claim(worker_id="w2") is None


def test_a_lease_that_expired_is_taken_over(schedules):
    """A scheduler that died must not strand a schedule for ever."""
    _, store = schedules
    register(store)
    store.claim(worker_id="w1")
    later = utcnow() + _dt.timedelta(minutes=20)
    assert store.claim(worker_id="w2", now=later) is not None


@pytest.mark.parametrize("workers", [8])
def test_concurrent_schedulers_claim_one_schedule_once_on_sqlite(schedules, workers):
    """The property that matters: one window, one fetch.

    Two schedulers both claiming would have the bank serve one statement twice,
    of which one copy is then never acknowledged.
    """
    _, store = schedules
    register(store)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        claims = [f.result() for f in [
            pool.submit(store.claim, worker_id=f"w{i}") for i in range(workers)]]
    assert sum(1 for claim in claims if claim is not None) == 1


@needs_postgres
def test_concurrent_schedulers_claim_one_schedule_once_on_postgres():
    engine, store, connection_id = _postgres_store("sched-race-one")
    try:
        store.register(connection_id, cadence=_dt.timedelta(hours=1), **STATEMENTS)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            claims = [f.result() for f in [
                pool.submit(store.claim, worker_id=f"w{i}") for i in range(8)]]
        assert sum(1 for claim in claims if claim is not None) == 1
    finally:
        engine.dispose()


@needs_postgres
def test_four_schedulers_claiming_four_schedules_each_get_a_different_one():
    """What ``SKIP LOCKED`` buys, and a plain lock would not.

    Without it the three losers queue behind the winner's row and come back
    empty-handed while three other schedules sit due.
    """
    engine, store, connection_id = _postgres_store("sched-race-four")
    try:
        for name, version in (("EOP", "08"), ("STM", "08"), ("EOP", "09"),
                              ("STM", "09")):
            store.register(connection_id, cadence=_dt.timedelta(hours=1),
                           service_name=name, msg_name="camt.053",
                           msg_version=version, scope="CH")
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            claims = [f.result() for f in [
                pool.submit(store.claim, worker_id=f"w{i}") for i in range(4)]]
        taken = [claim.schedule_id for claim in claims if claim is not None]
        assert len(taken) == 4
        assert len(set(taken)) == 4
    finally:
        engine.dispose()


def _postgres_store(connection_id: str):
    engine = db.build_engine(load_settings(database_url=POSTGRES_URL))
    db.migrate(engine)
    with engine.begin() as connection:
        connection.execute(bank_connection.delete().where(
            bank_connection.c.connection_id == connection_id))
    ConnectionRegistry(engine, AuditLog(engine)).register(
        connection_id, host_id="TESTHOST", partner_id=connection_id[:35].upper(),
        user_id="USER1", host_url="http://127.0.0.1:1/ebics")
    return engine, DownloadSchedules(engine, jitter=random.Random(1)), connection_id


# --- the cadence ------------------------------------------------------------


def test_a_finished_run_schedules_the_next_one_about_a_cadence_away(schedules):
    _, store = schedules
    schedule = register(store)
    claimed = store.claim(worker_id="w1")
    now = utcnow()
    store.finished(claimed, state=COMPLETE, now=now)

    after = store.get(schedule.schedule_id)
    assert after.worker_id is None
    gap = after.due_at - now
    assert _dt.timedelta(minutes=54) <= gap <= _dt.timedelta(minutes=66)


def test_the_next_due_time_is_jittered_so_schedules_do_not_lock_step(schedules):
    """Without jitter a hundred hourly schedules arrive in one second, hourly."""
    engine, store = schedules
    gaps = set()
    for index in range(6):
        schedule = store.register(BANK_CONNECTION_ID, cadence=_dt.timedelta(hours=1),
                                  service_name="EOP", msg_name="camt.053",
                                  msg_version=f"{index:02d}", scope="CH")
        claimed = store.claim(worker_id="w1")
        now = utcnow()
        store.finished(claimed, state=COMPLETE, now=now)
        gaps.add((store.get(schedule.schedule_id).due_at - now).total_seconds())
    assert len(gaps) == 6


def test_a_schedule_overdue_by_a_day_runs_once_and_not_once_per_missed_hour(schedules):
    """The restart case. Catching up would be a stampede at the bank's end."""
    _, store = schedules
    schedule = register(store, due_at=utcnow() - _dt.timedelta(days=1))

    claimed = store.claim(worker_id="w1")
    assert claimed is not None
    now = utcnow()
    store.finished(claimed, state=COMPLETE, now=now)

    assert store.claim(worker_id="w1") is None
    assert store.get(schedule.schedule_id).due_at > now


def test_a_run_that_failed_comes_back_sooner_than_the_cadence(schedules):
    _, store = schedules
    schedule = register(store)
    claimed = store.claim(worker_id="w1")
    now = utcnow()
    store.finished(claimed, state=FAILED, error="the bank hung up", now=now)

    after = store.get(schedule.schedule_id)
    assert after.due_at - now == _dt.timedelta(minutes=5)
    assert after.last_error == "the bank hung up"


# --- the window -------------------------------------------------------------


def test_the_first_window_reaches_back_by_the_configured_days(schedules):
    _, store = schedules
    schedule = register(store, window_days=7)
    today = _dt.date(2026, 8, 29)
    assert schedule.window(today) == ("2026-08-22", "2026-08-29")


def test_a_schedule_with_no_window_sends_no_date_range(schedules):
    """The ordinary EBICS model: the bank serves what is pending.

    What stops it being served twice is the receipt, not a date range -- so a
    schedule that does not need one does not invent one.
    """
    _, store = schedules
    assert register(store).window(_dt.date(2026, 8, 29)) == (None, None)


def test_a_completed_run_advances_the_window(schedules):
    _, store = schedules
    schedule = register(store, window_days=7)
    claimed = store.claim(worker_id="w1")
    store.finished(claimed, state=COMPLETE, documents=1)

    after = store.get(schedule.schedule_id)
    assert after.fetched_through == claimed.window_end
    # And the next window starts the day after, rather than re-asking for one
    # that is already stored.
    start, _ = after.window(_dt.date.fromisoformat(claimed.window_end) +
                            _dt.timedelta(days=3))
    assert start == (_dt.date.fromisoformat(claimed.window_end)
                     + _dt.timedelta(days=1)).isoformat()


def test_a_bank_with_nothing_to_send_still_advances_the_window(schedules):
    """`090005` is the bank answering for the window, not failing to.

    A day with no traffic is a day that is done. Refusing to move on would make
    a quiet account's window grow without limit.
    """
    _, store = schedules
    schedule = register(store, window_days=7)
    claimed = store.claim(worker_id="w1")
    store.finished(claimed, state=EMPTY, return_code="090005")

    assert store.get(schedule.schedule_id).fetched_through == claimed.window_end


def test_a_failed_run_leaves_the_window_where_it_was(schedules):
    """The recoverable-gap property, stated as a test.

    The next run asks for the same days again. A window that advanced on
    failure would be a statement nobody ever fetched and nobody ever missed.
    """
    _, store = schedules
    schedule = register(store, window_days=7)
    first = store.claim(worker_id="w1")
    store.finished(first, state=FAILED, error="connection refused")

    assert store.get(schedule.schedule_id).fetched_through is None
    second = store.claim(worker_id="w2",
                         now=utcnow() + _dt.timedelta(minutes=6))
    assert second.window_start == first.window_start


def test_every_attempt_leaves_a_row_in_the_ledger(schedules):
    """Including the ones that failed -- those are the rows an operator wants."""
    engine, store = schedules
    schedule = register(store, window_days=7)
    store.finished(store.claim(worker_id="w1"), state=FAILED, error="one")
    later = utcnow() + _dt.timedelta(minutes=6)
    store.finished(store.claim(worker_id="w1", now=later), state=COMPLETE,
                   documents=2, acknowledged=True, segments=3)

    runs = store.runs(schedule.schedule_id)
    assert [run["state"] for run in runs] == [COMPLETE, FAILED]
    assert runs[0]["acknowledged"] is True
    assert runs[0]["documents"] == 2
    assert runs[1]["last_error"] == "one"
    assert all(run["window_start"] for run in runs)


def test_the_transaction_id_is_recorded_as_soon_as_the_bank_assigns_it(schedules):
    engine, store = schedules
    schedule = register(store)
    claimed = store.claim(worker_id="w1")
    store.opened(claimed.run_id, transaction_id="A1B2C3")

    from sqlalchemy import select

    with engine.connect() as connection:
        row = connection.execute(
            select(download_run).where(
                download_run.c.run_id == claimed.run_id)).mappings().one()
    assert row["transaction_id"] == "A1B2C3"


# --- writing a schedule as a time, not a rate --------------------------------

def test_a_cron_expression_decides_the_next_run(schedules):
    """`0 8 * * *` is what a cadence cannot say, and the row is still the state.

    The expression is consulted once, when a finished run computes the next
    `due_at`. Nothing holds it in memory, so a restart still finds one overdue
    schedule rather than every run it slept through -- the property this
    module's whole design rests on, and the reason a cron *daemon* was refused
    while a cron *expression* is not.
    """
    _, store = schedules
    schedule = register(store, cron="0 8 * * *")
    assert schedule.cron == "0 8 * * *"
    assert store.get(schedule.schedule_id).cron == "0 8 * * *"


def test_a_refused_expression_never_reaches_the_row(schedules):
    """Validated on the way in, so the scheduler can only ever read one it can
    evaluate -- and so the API and the console cannot disagree about what runs."""
    from painfree.cron import CronError

    _, store = schedules
    with pytest.raises(CronError, match="uses a name"):
        register(store, cron="0 8 * * MON")


def test_an_empty_expression_means_the_cadence_decides(schedules):
    """The ordinary case, and what every row written before this meant."""
    _, store = schedules
    for index, empty in enumerate((None, "", "   ")):
        schedule = register(store, cron=empty, msg_version=f"0{index}")
        assert schedule.cron is None
