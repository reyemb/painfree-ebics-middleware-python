"""The application: it starts, serves, correlates, fails legibly, and stops.

This is the end-to-end half of the log-diagnosability rule. The claim being
tested is the one that rule actually makes -- that an operator holding nothing
but the log stream can tie a request together and diagnose a failure -- so the
assertions are made against captured stdout, not against a mock.

There is no reference implementation to diff a service against, so nothing here
claims a match with one.
"""

from __future__ import annotations

import json

import pytest
from fastapi import Body
from fastapi.testclient import TestClient

from conftest import PRODUCTION_OIDC, dev_credentials
from painfree.app import REQUEST_ID_HEADER, create_app
from painfree.audit import AuditLog
from painfree.config import load_settings
from painfree.errors import NotFoundError


@pytest.fixture
def app(settings):
    return create_app(settings)


@pytest.fixture
def client(app, capsys):
    # `capsys` is requested here so stdout capture is in place before the
    # lifespan installs the log handler; otherwise the startup lines and the
    # request lines land in two different buffers.
    with TestClient(app, headers=dev_credentials()) as client:
        yield client


def emitted(capsys) -> list[dict]:
    """Everything the process wrote to stdout, parsed. Any unparseable line fails."""
    captured = capsys.readouterr().out
    return [json.loads(line) for line in captured.splitlines() if line.strip()]


def events(capsys) -> list[str]:
    return [line["event"] for line in emitted(capsys)]


# --- lifespan ---------------------------------------------------------------

def test_the_service_starts_serves_and_stops_cleanly(settings, capsys):
    with TestClient(create_app(settings), headers=dev_credentials()) as client:
        assert client.get("/healthz").status_code == 200
    names = events(capsys)
    assert "service.starting" in names
    assert "service.started" in names
    assert "service.stopped" in names
    assert names.index("service.started") < names.index("service.stopped")


def test_the_startup_line_carries_the_resolved_configuration_with_no_secret(capsys):
    # `role="api"` is what a production HTTP process is, and it is refused the
    # custody secret outright -- so the startup line of the process that
    # handles requests names a custody key id of `None` by construction rather
    # than by remembering to strip one.
    settings = load_settings(
        environment="production", role="api", **PRODUCTION_OIDC,
        database_url="postgresql+psycopg://painfree:s3cr3t@db:5432/painfree",
        migrate_on_startup=False,
    )
    # No PostgreSQL is reachable here, so the start fails -- which is the point.
    # The line is emitted before any connection is made: a misconfigured process
    # has to say what it resolved *before* it fails on it, or the failure is
    # unreadable.
    with pytest.raises(Exception):
        with TestClient(create_app(settings), headers=dev_credentials()):
            pass

    line = next(l for l in emitted(capsys) if l["event"] == "service.starting")
    assert line["version"] and line["git_sha"] == "unknown"
    assert line["config"]["database_url"] == "postgresql+psycopg://painfree:***@db:5432/painfree"
    assert line["config"]["environment"] == "production"
    assert line["config"]["role"] == "api"
    assert line["config"]["custody_key_id"] is None
    assert "s3cr3t" not in json.dumps(line)


def test_startup_is_recorded_in_the_audit_log(app):
    with TestClient(app, headers=dev_credentials()):
        rows = AuditLog(app.state.engine).recent()
    assert rows[0]["action"] == "service.started"
    assert rows[0]["detail"]["schema_revision"]


def test_a_failed_start_refuses_to_serve_rather_than_failing_one_request_at_a_time(
    tmp_path, capsys
):
    settings = load_settings(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'no' / 'such' / 'dir' / 'x.db'}"
    )
    with pytest.raises(Exception):
        with TestClient(create_app(settings), headers=dev_credentials()):
            pass
    line = next(l for l in emitted(capsys) if l["event"] == "service.start_failed")
    assert "traceback" in line


# --- health -----------------------------------------------------------------

def test_healthz_answers_without_touching_a_dependency(client, settings):
    body = client.get("/healthz").json()
    assert body == {"status": "ok", "version": settings.version, "git_sha": "unknown"}


def test_readyz_reports_the_schema_it_is_running_against(client):
    body = client.get("/readyz").json()
    assert body["status"] == "ready"
    assert body["checks"]["database"]["revision"] == body["checks"]["database"]["head"]


def test_readyz_is_503_when_the_database_is_gone(app, capsys):
    with TestClient(app, headers=dev_credentials()) as client:
        app.state.engine.dispose()
        # Point the engine at a database that cannot answer.
        from painfree.db import build_engine
        app.state.engine = build_engine(
            load_settings(database_url="sqlite+pysqlite:////nonexistent/dir/x.db")
        )
        response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "not_ready"
    assert response.json()["error"]["detail"]["database"]["reason"] == "unreachable"
    assert "readiness.failed" in events(capsys)


# --- correlation ------------------------------------------------------------

def test_every_line_of_one_request_carries_the_same_request_id(app, capsys):
    @app.get("/_probe")
    def probe():
        from painfree.logging import get_logger
        get_logger("painfree.test").info("work.done", step=1)
        return {"ok": True}

    with TestClient(app, headers=dev_credentials()) as client:
        response = client.get("/_probe")
    request_id = response.headers[REQUEST_ID_HEADER]
    tied = [l for l in emitted(capsys) if l.get("request_id") == request_id]
    assert {l["event"] for l in tied} == {"work.done", "request.completed"}
    assert len(request_id) == 32


def test_a_caller_supplied_request_id_is_adopted_and_echoed(client, capsys):
    """So one trace spans the caller's system and this one."""
    response = client.get("/no-such-endpoint",
                          headers={REQUEST_ID_HEADER: "caller-trace-1"})
    assert response.headers[REQUEST_ID_HEADER] == "caller-trace-1"
    assert response.json()["error"]["request_id"] == "caller-trace-1"
    assert any(l.get("request_id") == "caller-trace-1" for l in emitted(capsys))


def test_the_request_id_is_in_the_error_body_as_well_as_the_header(client):
    response = client.get("/no-such-endpoint")
    assert response.status_code == 404
    body = response.json()["error"]
    assert body["code"] == "not_found"
    assert body["request_id"] == response.headers[REQUEST_ID_HEADER]


# --- errors -----------------------------------------------------------------

def test_an_unhandled_exception_is_diagnosable_from_the_log_alone(app, capsys):
    """The gate's real question: could an operator debug this from `docker logs`?"""
    @app.get("/_boom")
    def boom():
        raise RuntimeError("the connection pool is on fire")

    with TestClient(app, raise_server_exceptions=False, headers=dev_credentials()) as client:
        response = client.get("/_boom")

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    # The caller learns nothing about our internals...
    assert "on fire" not in response.text
    # ...and the operator learns everything.
    line = next(l for l in emitted(capsys) if l["event"] == "request.failed")
    assert line["request_id"] == response.headers[REQUEST_ID_HEADER]
    assert line["exception"] == "RuntimeError"
    assert line["exception_message"] == "the connection pool is on fire"
    assert "in boom" in line["traceback"]
    assert line["path"] == "/_boom" and line["method"] == "GET"


def test_a_named_service_error_is_converted_deliberately(app, capsys):
    @app.get("/_missing")
    def missing():
        raise NotFoundError("no such connection", detail={"connection_id": "c-1"})

    with TestClient(app, headers=dev_credentials()) as client:
        response = client.get("/_missing")

    assert response.status_code == 404
    assert response.json()["error"] == {
        "code": "not_found",
        "message": "no such connection",
        "request_id": response.headers[REQUEST_ID_HEADER],
        "detail": {"connection_id": "c-1"},
    }
    line = next(l for l in emitted(capsys) if l["event"] == "request.rejected")
    assert line["level"] == "warning", "an expected failure is not an error"


def test_a_validation_failure_names_the_failing_rule(app):
    @app.post("/_echo")
    def echo(amount: int = Body(embed=True)):
        return {"amount": amount}

    with TestClient(app, headers=dev_credentials()) as client:
        response = client.post("/_echo", json={"amount": "not a number"})

    assert response.status_code == 422
    failures = response.json()["error"]["detail"]["failures"]
    assert failures[0]["location"] == "body.amount"
    assert failures[0]["rule"]  # never a generic "invalid"


# --- what must never be in the stream ---------------------------------------

def test_key_material_order_data_and_bearer_tokens_never_reach_the_log(tmp_path, capsys):
    """The one test this file would be negligent without.

    Everything a request can carry that must not be logged is put through one:
    a bearer token, a private key and a payment payload in the body, and a
    database password in the configuration. None of it may appear anywhere in
    what the process wrote to stdout.

    The token arrives in a cookie and in the body rather than in
    ``Authorization`` because an ``Authorization`` header that does not verify
    never reaches a route at all -- that path, and its own no-leak assertion,
    is
    ``tests/test_service_authz.py::test_a_rejected_bearer_token_is_never_written_to_the_log``.
    """
    token = "eyJhbGciOiJSUzI1NiJ9.THIS-IS-A-BEARER-TOKEN"
    private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ-SECRET-KEY\n-----END RSA PRIVATE KEY-----"
    payment = "CH9300762011623852957 EUR 4200.00 Alice pays Bob"
    password = "database-password-s3cr3t"

    settings = load_settings(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'p.db'}?password={password}",
    )
    app = create_app(settings)

    @app.post("/_submit")
    def submit(body: dict = Body()):
        from painfree.logging import get_logger
        log = get_logger("painfree.test")
        # A call site doing the right thing: the payment is referenced, not logged.
        log.info("order.accepted", order_id="o-1", fingerprint="6c002af6b59dd1d4")
        # ...and one doing the wrong thing, which must still not leak.
        log.info("order.debug", private_key=body["key"], order_data=body["payment"])
        AuditLog(app.state.engine).record(
            "order.accepted", order_id="o-1",
            detail={"payload": body["payment"], "private_key": body["key"]},
        )
        raise RuntimeError(f"upload failed for {token}")

    with TestClient(app, raise_server_exceptions=False, headers=dev_credentials()) as client:
        response = client.post(
            "/_submit",
            headers={"Cookie": f"pf_other={token}"},
            json={"key": private_key, "payment": payment},
        )

    assert response.status_code == 500
    written = capsys.readouterr().out
    for forbidden, what in [
        (token, "the bearer token"),
        ("MIIEowIBAAKCAQ-SECRET-KEY", "key material"),
        (payment, "decrypted order data"),
        (password, "the database password"),
    ]:
        assert forbidden not in written, f"{what} reached the log stream"

    lines = [json.loads(line) for line in written.splitlines() if line.strip()]
    accepted = next(l for l in lines if l["event"] == "order.accepted")
    assert accepted["order_id"] == "o-1"
    assert accepted["fingerprint"] == "6c002af6b59dd1d4"
    # The failure stays diagnosable: the token is gone from both the message and
    # the trace that repeats it, and everything else is intact. It was this
    # exact path -- a credential interpolated into an exception message -- that
    # a name-based blocklist missed, which is why `scrub` exists.
    failed = next(l for l in lines if l["event"] == "request.failed")
    assert failed["exception"] == "RuntimeError"
    assert "in submit" in failed["traceback"]
    assert failed["exception_message"] == "upload failed for <redacted:jwt>"


def test_probe_endpoints_do_not_flood_the_stream(client, capsys):
    """A readiness probe every two seconds must not bury the events that matter."""
    capsys.readouterr()
    for _ in range(5):
        client.get("/readyz")
    assert "request.completed" not in events(capsys)
