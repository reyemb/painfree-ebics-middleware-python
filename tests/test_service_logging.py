"""Structured logging: one JSON object per line, correlated, and safe.

These tests are the unit half of the log-diagnosability rule. The end-to-end
half -- that a real request produces a correlated stream and a real failure is
diagnosable from it alone -- is in `test_service_app.py`.
"""

from __future__ import annotations

import io
import json
import logging

import pytest

from painfree.logging import (CORRELATION_FIELDS, MAX_STRING, REDACTED, bind,
                              configure_logging, context, get_logger, redact)


@pytest.fixture
def stream():
    buffer = io.StringIO()
    configure_logging("DEBUG", stream=buffer)
    yield buffer
    logging.getLogger().handlers.clear()


def lines(stream) -> list[dict]:
    """Every line has to parse, or the format is broken rather than merely ugly."""
    return [json.loads(line) for line in stream.getvalue().splitlines() if line]


# --- shape ------------------------------------------------------------------

def test_one_event_is_exactly_one_line_of_json(stream):
    log = get_logger("painfree.test")
    log.info("first.event", a=1)
    log.info("second.event", a=2)
    assert [line["event"] for line in lines(stream)] == ["first.event", "second.event"]


def test_a_multi_line_value_still_leaves_one_line(stream):
    """A stack trace or an XML document must not become forty log lines."""
    get_logger("painfree.test").info("noisy", blob="a\nb\nc")
    assert len(stream.getvalue().strip().splitlines()) == 1
    assert lines(stream)[0]["blob"] == "a\nb\nc"


def test_every_line_carries_level_logger_and_timestamp(stream):
    get_logger("painfree.test").warning("careful")
    line = lines(stream)[0]
    assert line["level"] == "warning"
    assert line["logger"] == "painfree.test"
    assert line["timestamp"].endswith("Z")


def test_library_records_go_through_the_same_formatter(stream):
    """uvicorn and SQLAlchemy log to stdlib loggers; the stream stays uniform."""
    logging.getLogger("some.library").info("started up")
    assert lines(stream)[0] == {
        **lines(stream)[0], "logger": "some.library", "event": "started up",
    }


def test_configure_logging_replaces_its_handler_rather_than_adding_one():
    first, second = io.StringIO(), io.StringIO()
    configure_logging("INFO", stream=first)
    configure_logging("INFO", stream=second)
    get_logger("painfree.test").info("once")
    assert first.getvalue() == ""
    assert len(second.getvalue().splitlines()) == 1
    logging.getLogger().handlers.clear()


# --- correlation ------------------------------------------------------------

def test_bound_ids_appear_on_every_line_underneath(stream):
    log = get_logger("painfree.test")
    with bind(request_id="r-1", order_id="o-1"):
        log.info("one")
        logging.getLogger("some.library").info("two")
    log.info("three")
    first, second, third = lines(stream)
    assert first["request_id"] == second["request_id"] == "r-1"
    assert first["order_id"] == "o-1"
    assert "request_id" not in third


def test_nested_binds_add_rather_than_replace(stream):
    log = get_logger("painfree.test")
    with bind(request_id="r-1"):
        with bind(job_id="j-1"):
            log.info("inner")
        log.info("outer")
    inner, outer = lines(stream)
    assert (inner["request_id"], inner["job_id"]) == ("r-1", "j-1")
    assert "job_id" not in outer


def test_an_unknown_id_is_absent_not_null(stream):
    """`"order_id": null` invites a grep that silently matches nothing."""
    get_logger("painfree.test").info("event", order_id=None)
    assert "order_id" not in lines(stream)[0]


def test_the_context_is_restored_after_an_exception(stream):
    with pytest.raises(RuntimeError):
        with bind(request_id="r-1"):
            raise RuntimeError("boom")
    assert context() == {}


def test_the_correlation_fields_are_the_ones_the_gate_names():
    assert CORRELATION_FIELDS == (
        "request_id", "connection_id", "order_id", "job_id", "idempotency_key",
    )


# --- exceptions -------------------------------------------------------------

def test_an_exception_is_logged_with_its_stack_trace(stream):
    log = get_logger("painfree.test")
    try:
        raise ValueError("the bank said no")
    except ValueError:
        log.exception("work.failed", step="upload")
    line = lines(stream)[0]
    assert line["exception"] == "ValueError"
    assert line["exception_message"] == "the bank said no"
    assert "test_an_exception_is_logged_with_its_stack_trace" in line["traceback"]
    assert line["step"] == "upload"


# --- redaction --------------------------------------------------------------

@pytest.mark.parametrize(
    "field", ["password", "token", "authorization", "private_key", "secret",
              "transaction_key", "order_data", "payload"],
)
def test_a_sensitive_field_name_never_reaches_the_stream(stream, field):
    get_logger("painfree.test").info("event", **{field: "the actual value"})
    assert lines(stream)[0][field] == REDACTED
    assert "the actual value" not in stream.getvalue()


def test_redaction_reaches_nested_values(stream):
    get_logger("painfree.test").info(
        "event", detail={"nested": {"api_key": "abc"}, "safe": "kept"},
    )
    line = lines(stream)[0]
    assert line["detail"]["nested"]["api_key"] == REDACTED
    assert line["detail"]["safe"] == "kept"


def test_key_material_is_caught_by_shape_as_well_as_by_name(stream):
    """A PEM under an unrecognised field name is still a key.

    Defence in depth: the control is that call sites log a fingerprint, but a
    blocklist that is the only defence eventually meets a name it has not heard.
    """
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow…\n-----END RSA PRIVATE KEY-----"
    get_logger("painfree.test").info("event", material=pem)
    assert lines(stream)[0]["material"] == "<redacted:pem>"
    assert "BEGIN RSA PRIVATE KEY" not in stream.getvalue()


def test_a_long_string_is_truncated(stream):
    get_logger("painfree.test").info("event", blob="x" * (MAX_STRING + 100))
    value = lines(stream)[0]["blob"]
    assert value.startswith("x" * MAX_STRING)
    assert "truncated" in value


def test_bytes_are_reported_by_length_never_by_content(stream):
    get_logger("painfree.test").info("event", chunk=b"\x00\x01secret")
    assert lines(stream)[0]["chunk"] == "<8 bytes>"


def test_redact_is_reusable_outside_the_formatter():
    assert redact({"token": "t", "n": 1}) == {"token": REDACTED, "n": 1}


def test_a_jwt_shaped_token_is_caught_wherever_it_appears(stream):
    """The shape check exists because the name-based one demonstrably missed this.

    A bearer token interpolated into an exception message reaches the stream
    through the traceback, under no field name at all.
    """
    token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"
    log = get_logger("painfree.test")
    try:
        raise RuntimeError(f"upload rejected for {token}")
    except RuntimeError:
        log.exception("upload.failed", note=f"retrying with {token}")
    line = lines(stream)[0]
    assert token not in stream.getvalue()
    assert line["exception_message"] == "upload rejected for <redacted:jwt>"
    assert line["note"] == "retrying with <redacted:jwt>"


def test_scrubbing_leaves_the_trace_diagnosable(stream):
    """Redacting the whole trace would defeat the point of logging it."""
    log = get_logger("painfree.test")
    try:
        raise RuntimeError("plain failure")
    except RuntimeError:
        log.exception("work.failed")
    trace = lines(stream)[0]["traceback"]
    assert "test_scrubbing_leaves_the_trace_diagnosable" in trace
    assert "RuntimeError: plain failure" in trace


def test_the_default_stream_follows_stdout_rather_than_binding_it():
    """A handler that captured stdout at install time writes where no one reads."""
    import contextlib
    configure_logging("INFO")
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        get_logger("painfree.test").info("late")
    assert json.loads(buffer.getvalue())["event"] == "late"
    logging.getLogger().handlers.clear()


def test_uvicorns_uncorrelated_access_log_is_turned_off():
    """It is one line per request with no request id, and it doubled every line.

    `request.completed` is the same fact with correlation attached, and it also
    honours the probe-path quieting that the uvicorn line ignored.
    """
    configure_logging("DEBUG")
    assert logging.getLogger("uvicorn.access").level == logging.WARNING
    assert logging.getLogger("uvicorn.error").propagate is True
    logging.getLogger().handlers.clear()


def test_uvicorns_ansi_twin_of_the_message_is_dropped(stream):
    logging.getLogger("uvicorn.error").info(
        "Started server process", extra={"color_message": "Started \x1b[36mprocess\x1b[0m"},
    )
    line = lines(stream)[0]
    assert "color_message" not in line
    assert "\x1b" not in stream.getvalue()
