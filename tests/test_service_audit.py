"""The audit log: one writer, append-only, and redacted like the log stream."""

from __future__ import annotations

import datetime as _dt
import io
import json
import logging

import pytest
from sqlalchemy import exc, text

from painfree import db
from painfree.audit import FAILURE, SUCCESS, SYSTEM, Actor, AuditLog
from painfree.logging import REDACTED, bind, configure_logging


@pytest.fixture
def audit(settings):
    engine = db.build_engine(settings)
    db.migrate(engine)
    yield AuditLog(engine)
    engine.dispose()


@pytest.fixture
def stream():
    buffer = io.StringIO()
    configure_logging("DEBUG", stream=buffer)
    yield buffer
    logging.getLogger().handlers.clear()


def test_recording_appends_one_row(audit):
    event = audit.record("connection.registered", detail={"bank": "acme"})
    rows = audit.recent()
    assert len(rows) == 1
    assert rows[0]["event_id"] == event.event_id
    assert rows[0]["action"] == "connection.registered"
    assert rows[0]["outcome"] == SUCCESS
    assert rows[0]["actor_type"] == SYSTEM
    assert rows[0]["occurred_at"].tzinfo is not None


def test_correlation_ids_default_to_the_bound_context(audit):
    """A handler that bound `request_id` once does not repeat it -- or forget it."""
    with bind(request_id="r-42", order_id="o-7"):
        audit.record("order.accepted")
    row = audit.recent()[0]
    assert row["request_id"] == "r-42"
    assert row["order_id"] == "o-7"
    assert row["job_id"] is None


def test_an_explicit_id_wins_over_the_bound_one(audit):
    with bind(request_id="r-42"):
        audit.record("order.accepted", request_id="r-99")
    assert audit.recent()[0]["request_id"] == "r-99"


def test_an_unknown_correlation_field_is_a_caller_error(audit):
    """The columns are the gate's five ids; a sixth silently vanishing is worse."""
    with pytest.raises(ValueError, match="unknown correlation fields: bank_id"):
        audit.record("order.accepted", bank_id="b-1")


def test_an_unknown_outcome_is_refused(audit):
    with pytest.raises(ValueError):
        audit.record("order.accepted", outcome="maybe")


def test_an_actor_needs_both_a_type_and_an_id():
    with pytest.raises(ValueError):
        Actor("oidc_subject", "")


def test_the_detail_column_is_redacted_before_it_is_stored(audit):
    """An audit trail is read by more people than a log stream is."""
    audit.record(
        "connection.key_generated",
        detail={"fingerprint": "6c002af6", "private_key": "-----BEGIN X-----"},
    )
    detail = audit.recent()[0]["detail"]
    assert detail["fingerprint"] == "6c002af6"
    assert detail["private_key"] == REDACTED


def test_recording_also_logs_the_event(audit, stream):
    with bind(request_id="r-1"):
        event = audit.record("order.rejected", outcome=FAILURE)
    line = json.loads(stream.getvalue().splitlines()[-1])
    assert line["event"] == "audit.recorded"
    assert line["action"] == "order.rejected"
    assert line["outcome"] == FAILURE
    assert line["event_id"] == event.event_id
    assert line["request_id"] == "r-1"


def test_events_come_back_newest_first(audit):
    for name in ("first", "second", "third"):
        audit.record(name)
    assert [row["action"] for row in audit.recent()] == ["third", "second", "first"]
    assert [row["seq"] for row in audit.recent()] == sorted(
        (row["seq"] for row in audit.recent()), reverse=True
    )


def test_the_module_offers_no_way_to_amend_a_row():
    """Append-only is a property of the surface, not a promise in a comment.

    Enumerated rather than pattern-matched: `record` is the one writer and
    everything else here reads. A method added to this class has to be added to
    this list too, which is the moment to notice that it amends something.
    """
    surface = {name for name in dir(AuditLog) if not name.startswith("_")}
    assert surface == {"record", "recent", "search", "actions", "actors"}


def test_a_failed_write_is_logged_where_it_is_caught_and_re_raised(audit, stream):
    """A caller that wanted an audit trail must not be told the write succeeded."""
    with audit._engine.begin() as connection:
        connection.execute(text("DROP TABLE audit_log"))
    with pytest.raises(exc.SQLAlchemyError):
        audit.record("order.accepted")
    line = json.loads(stream.getvalue().splitlines()[-1])
    assert line["event"] == "audit.write_failed"
    assert line["level"] == "error"
    assert "traceback" in line


def test_event_ids_are_unique(audit):
    ids = {audit.record("event").event_id for _ in range(20)}
    assert len(ids) == 20


def test_occurred_at_is_utc(audit):
    audit.record("event")
    row = audit.recent()[0]
    assert row["occurred_at"].utcoffset() == _dt.timedelta(0)
