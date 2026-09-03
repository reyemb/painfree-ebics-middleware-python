"""Managing download schedules: the routes, the console, and the window ledger.

The scheduler and the download worker were built, tested and unreachable: a
schedule could not be created or changed without writing SQL. This file is about
the surface, and four properties of it are what it exists to hold.

**An empty download is not a failure anywhere an operator can see.**
`EBICS_NO_DOWNLOAD_DATA_AVAILABLE` is what a scheduled download finds most days,
and this service classifies it as a *completed* transaction. So the assertions
below are about the rendered page and the JSON, not about the scheduler: after
a real `090005` exchange with a stub bank, `health` is `healthy`, the failing
panel is absent, and the page says the bank had nothing.

**A failing schedule is unmissable.** The same page, after a bank that refuses,
carries the bank's return code and its report text.

**A re-fetch produces no second statement.** Proved at the database level, by
counting rows and comparing `statement_id`s across two real downloads of the same
window -- not by trusting that a constraint exists.

**Hiding a button is not authorisation.** Every write route is posted to directly
by a caller whose role does not hold `schedules:manage`, with no page rendered
first, and the `403` names the missing scope.
"""

from __future__ import annotations

import datetime as _dt
import logging

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from painfree.app import create_app
from painfree.downloader import DownloadWorker
from painfree.errors import ConflictError
from painfree.identity import (LEVEL_SCOPES, ROLE_SCOPES, Level, Role,
                               Scope)
from painfree.keyring import Keyring
from painfree.logging import JsonFormatter
from painfree.schedule import COMPLETE, EMPTY, REFUSED, DownloadSchedules
from painfree.schema import bank_connection, download_run, statement
from conftest import (BANK_CONNECTION_ID, bank_response, dev_credentials,
                      download_script, grant, no_data_script, serving_bank,
                      zipped)

BROWSER = {"accept": "text/html,application/xhtml+xml"}

#: A statement download as a Swiss bank publishes it.
BTF = {"service_name": "EOP", "msg_name": "camt.053", "msg_version": "08",
       "scope": "CH", "container": "ZIP"}


def _admin(**extra) -> dict[str, str]:
    return {**dev_credentials("alice", "admin"), **extra}


def _operator(**extra) -> dict[str, str]:
    return {**dev_credentials("olive", "member"), **extra}


def _viewer(**extra) -> dict[str, str]:
    return {**dev_credentials("reader", "member"), **extra}


def _auditor(**extra) -> dict[str, str]:
    """A member holding a `viewer` grant on the connection, which is where
    the old `auditor` role's reach over a schedule now lives."""
    return {**dev_credentials("aud", "member"), **extra}


@pytest.fixture
def console(prepared_bank, custody_settings):
    """The API process, on a connection a download worker could really use.

    `olive` and the two readers hold grants on that connection rather than
    global roles; `alice` is an `admin`, so she needs none. The levels are the
    ones the old role table became.
    """
    engine, _, bank_keys = prepared_bank
    app = create_app(custody_settings)
    with TestClient(app) as client:
        grant(app, "olive", BANK_CONNECTION_ID, "operator")
        grant(app, "reader", BANK_CONNECTION_ID, "viewer")
        grant(app, "aud", BANK_CONNECTION_ID, "viewer")
        yield client, engine, bank_keys, custody_settings


def _create(client, **overrides) -> dict:
    body = {"connection_id": BANK_CONNECTION_ID, "cadence_seconds": 21600,
            "window_days": 7, "description": "Daily statements", **BTF}
    body.update(overrides)
    response = client.post("/v1/schedules", json=body, headers=_admin())
    assert response.status_code == 201, response.text
    return response.json()


def _point_at(engine, url: str) -> None:
    """Send this connection's downloads at the stub bank on ``url``."""
    with engine.begin() as connection:
        connection.execute(
            bank_connection.update()
            .where(bank_connection.c.connection_id == BANK_CONNECTION_ID)
            .values(host_url=url))


def _worker(engine, settings, worker_id: str = "test-downloader") -> DownloadWorker:
    return DownloadWorker(engine, settings.custody_key(), worker_id=worker_id,
                          timeout=10)


def _subscriber_e002(engine):
    return Keyring(engine).public_key(BANK_CONNECTION_ID, "E002")


# --- the scope --------------------------------------------------------------

def test_the_level_table_grants_reading_to_both_and_managing_to_the_operator():
    """The schedule role split, carried into two grant levels rather than four
    roles.

    The asymmetry with `webhooks:manage` is the decision, and it survived the
    collapse: a schedule creates no recipient outside the deployment, so the
    operator who is paged about a missing statement can re-fetch its window --
    on the connection they were granted, and on no other.
    """
    assert Scope.schedules_read in LEVEL_SCOPES[Level.viewer]
    assert Scope.schedules_read in LEVEL_SCOPES[Level.operator]
    assert Scope.schedules_manage in LEVEL_SCOPES[Level.operator]
    assert Scope.schedules_manage in ROLE_SCOPES[Role.admin]
    assert Scope.schedules_manage not in LEVEL_SCOPES[Level.viewer]
    # The contrast that makes the decision worth writing down, and which is now
    # structural: no grant level carries `webhooks:manage` at all.
    assert Scope.webhooks_manage not in LEVEL_SCOPES[Level.operator]


def test_a_caller_without_the_manage_scope_is_refused_by_the_server(console):
    """Every write route, posted to directly. No page is rendered first."""
    client, _, _, _ = console
    created = _create(client)
    sid = created["schedule_id"]

    refusals = [
        ("POST", "/v1/schedules",
         {"json": {"connection_id": BANK_CONNECTION_ID,
                   "cadence_seconds": 3600, **BTF, "msg_name": "camt.052"}}),
        ("PATCH", f"/v1/schedules/{sid}", {"json": {"enabled": False}}),
        ("POST", f"/v1/schedules/{sid}/run", {}),
        ("POST", f"/v1/schedules/{sid}/refetch",
         {"json": {"since": "2026-08-01"}}),
        ("DELETE", f"/v1/schedules/{sid}", {}),
    ]
    for method, path, kwargs in refusals:
        response = client.request(method, path, headers=_viewer(), **kwargs)
        assert response.status_code == 403, f"{method} {path}: {response.text}"
        body = response.json()["error"]
        assert body["code"] == "forbidden"
        assert body["detail"]["missing_scopes"] == ["schedules:manage"]

    # And the console's own write routes, which are a separate router.
    for path in (f"/ui/schedules/{sid}/run", f"/ui/schedules/{sid}/pause",
                 f"/ui/schedules/{sid}/edit", f"/ui/schedules/{sid}/delete"):
        response = client.post(path, headers=_viewer(**BROWSER))
        assert response.status_code == 403, path


def test_a_viewer_grant_may_read_a_schedule_but_not_change_one(console):
    """The read half is carried by both levels -- unlike `webhooks:read`."""
    client, _, _, _ = console
    created = _create(client)
    for headers in (_viewer(), _operator(), _auditor()):
        assert client.get("/v1/schedules", headers=headers).status_code == 200
    assert client.get(f"/v1/schedules/{created['schedule_id']}",
                      headers=_auditor()).status_code == 200
    assert client.patch(f"/v1/schedules/{created['schedule_id']}",
                        json={"enabled": False},
                        headers=_auditor()).status_code == 403


def test_an_operator_may_run_and_refetch(console):
    """The whole point: the person on call can recover a window."""
    client, _, _, _ = console
    sid = _create(client)["schedule_id"]
    assert client.post(f"/v1/schedules/{sid}/run",
                       headers=_operator()).status_code == 202
    assert client.post(f"/v1/schedules/{sid}/refetch",
                       json={"since": "2026-08-20"},
                       headers=_operator()).status_code == 202


# --- the routes -------------------------------------------------------------

def test_a_schedule_is_created_through_the_api_with_its_whole_btf(console):
    client, _, _, _ = console
    created = _create(client)

    assert created["label"] == "EOP/camt.053.08"
    assert created["service"]["container"] == "ZIP"
    assert created["cadence_seconds"] == 21600
    assert created["enabled"] is True
    # Never run, so `health` says exactly that rather than guessing.
    assert created["health"] == "untried"
    assert created["window"]["dated"] is True
    assert created["window"]["covered_through"] is None
    assert created["window"]["behind"] is False


def test_a_repeated_registration_makes_no_second_schedule(console):
    """The idempotency of this endpoint is the unique constraint, not a header.

    A schedule's identity is its connection and its BTF. A second row for the
    same pair would download one statement twice, so it is refused by
    `uq_download_schedule_btf` -- which two concurrent registrations both hit,
    unlike a check either of them could pass.
    """
    client, _, _, _ = console
    first = _create(client)
    again = client.post("/v1/schedules", headers=_admin(), json={
        "connection_id": BANK_CONNECTION_ID, "cadence_seconds": 60, **BTF})
    assert again.status_code == 409
    assert again.json()["error"]["detail"]["schedule_id"] == first["schedule_id"]
    assert len(client.get("/v1/schedules",
                          headers=_admin()).json()["schedules"]) == 1


def test_a_btf_the_bank_would_refuse_is_refused_at_registration(console):
    """Validated by the engine's rules, not by a second set written in the API."""
    client, _, _, _ = console
    response = client.post("/v1/schedules", headers=_admin(), json={
        "connection_id": BANK_CONNECTION_ID, "cadence_seconds": 3600,
        "service_name": "EOPX", "msg_name": "camt.053"})
    assert response.status_code >= 400


def test_a_cadence_under_the_minimum_is_refused(console):
    client, _, _, _ = console
    response = client.post("/v1/schedules", headers=_admin(), json={
        "connection_id": BANK_CONNECTION_ID, "cadence_seconds": 5, **BTF})
    assert response.status_code == 409


def test_a_schedule_for_a_connection_that_does_not_exist_is_a_404(console):
    """Named, rather than surfacing as a foreign-key violation."""
    client, _, _, _ = console
    response = client.post("/v1/schedules", headers=_admin(), json={
        "connection_id": "no-such-bank", "cadence_seconds": 3600, **BTF})
    assert response.status_code == 404


def test_an_edit_changes_the_cadence_without_touching_the_window(console):
    """The two are unrelated facts and an edit that reset the mark would re-ask
    the bank for a month."""
    client, engine, _, _ = console
    sid = _create(client)["schedule_id"]
    DownloadSchedules(engine)._write(sid, fetched_through="2026-08-25")

    changed = client.patch(f"/v1/schedules/{sid}", headers=_admin(),
                           json={"cadence_seconds": 3600,
                                 "description": "Twice a day"}).json()
    assert changed["cadence_seconds"] == 3600
    assert changed["description"] == "Twice a day"
    assert changed["window"]["covered_through"] == "2026-08-25"


def test_pausing_keeps_the_window_and_stops_the_claim(console):
    client, engine, _, _ = console
    sid = _create(client)["schedule_id"]
    store = DownloadSchedules(engine)
    store._write(sid, fetched_through="2026-08-25")

    paused = client.patch(f"/v1/schedules/{sid}", headers=_admin(),
                          json={"enabled": False}).json()
    assert paused["enabled"] is False
    assert paused["health"] == "paused"
    assert paused["window"]["covered_through"] == "2026-08-25"
    assert store.claim(worker_id="w1") is None


def test_deleting_a_schedule_keeps_the_statements_it_fetched(console):
    """`statement.run_id` is a plain column precisely so this cascade cannot happen."""
    client, engine, bank_keys, settings = console
    sid = _create(client)["schedule_id"]
    _run_a_download(engine, settings, bank_keys, zipped("camt.053.001.08"))

    with engine.connect() as connection:
        before = connection.execute(
            select(func.count()).select_from(statement)).scalar_one()
    assert before > 0

    deleted = client.delete(f"/v1/schedules/{sid}", headers=_admin()).json()
    assert deleted["deleted"] is True
    assert deleted["runs_dropped"] == 1
    with engine.connect() as connection:
        assert connection.execute(
            select(func.count()).select_from(statement)).scalar_one() == before
        assert connection.execute(
            select(func.count()).select_from(download_run)).scalar_one() == 0


# --- run now ----------------------------------------------------------------

def test_run_now_makes_the_schedule_due_and_the_worker_does_the_download(console):
    """The console holds no key, so "run now" is a row write and a claim.

    What is asserted is the whole chain: `202` from a process that cannot
    decrypt anything, then a real `BTD` over a socket by the worker that can,
    then the run in the ledger carrying the operator's name.
    """
    client, engine, bank_keys, settings = console
    sid = _create(client, cadence_seconds=86400)["schedule_id"]
    # Put it where a schedule that has just run sits: not due for a day, so
    # nothing happens without the request.
    store = DownloadSchedules(engine)
    store._write(sid, due_at=_dt.datetime.now(_dt.timezone.utc)
                 + _dt.timedelta(days=1))
    assert store.claim(worker_id="probe") is None

    queued = client.post(f"/v1/schedules/{sid}/run", headers=_admin())
    assert queued.status_code == 202
    assert queued.json()["queued"] is True

    result = _run_a_download(engine, settings, bank_keys,
                             zipped("camt.053.001.08"))
    assert result.state == COMPLETE
    runs = client.get(f"/v1/schedules/{sid}/runs",
                      headers=_admin()).json()["runs"]
    assert runs[0]["requested_by"] == "alice"
    assert runs[0]["finished"] is True
    assert runs[0]["statements"] == 1


def test_run_now_on_a_paused_schedule_is_refused_rather_than_silently_lost(console):
    """The claim filters on `enabled`; pretending otherwise would report success
    for a row nothing will ever pick up."""
    client, _, _, _ = console
    sid = _create(client)["schedule_id"]
    client.patch(f"/v1/schedules/{sid}", headers=_admin(),
                 json={"enabled": False})
    refused = client.post(f"/v1/schedules/{sid}/run", headers=_admin())
    assert refused.status_code == 409
    assert "disabled" in refused.json()["error"]["message"]


def test_run_now_while_a_run_is_in_flight_is_refused(console):
    client, engine, _, _ = console
    sid = _create(client)["schedule_id"]
    DownloadSchedules(engine).claim(worker_id="busy-worker")
    refused = client.post(f"/v1/schedules/{sid}/run", headers=_admin())
    assert refused.status_code == 409
    assert "busy-worker" in refused.json()["error"]["message"]


# --- an empty run is not a failure ------------------------------------------

def test_a_run_that_found_nothing_is_shown_as_a_normal_empty_result(console):
    """`090005` reaching an operator, end to end.

    A real exchange with a bank that has nothing, then the JSON and then the
    rendered page. Calling an empty download a success is only worth anything
    if the surface agrees with it: the schedule stays `healthy`, the failing
    panel is absent, and the page says in words that the bank had nothing.
    """
    client, engine, bank_keys, settings = console
    sid = _create(client)["schedule_id"]
    seen: list[bytes] = []
    with serving_bank(no_data_script(bank_keys.authentication, seen)) as url:
        _point_at(engine, url)
        result = _worker(engine, settings).run_once()

    assert result.state == EMPTY
    assert result.return_code == "090005"

    schedule = client.get(f"/v1/schedules/{sid}", headers=_admin()).json()
    assert schedule["health"] == "healthy"
    assert schedule["last_return_code"] == "090005"
    assert schedule["last_error"] is None
    # The window moved: the bank answered for it, and had nothing.
    assert schedule["window"]["covered_through"] is not None
    assert schedule["window"]["behind"] is False

    runs = client.get(f"/v1/schedules/{sid}/runs", headers=_admin()).json()
    assert runs["runs"][0]["state"] == "empty"
    assert runs["runs"][0]["finished"] is True
    assert runs["unfinished"] == []

    page = client.get(f"/ui/schedules/{sid}", headers=_admin(**BROWSER)).text
    assert "the bank had nothing for this window" in page
    assert "which is a normal result" in page
    assert "Failing: nothing is being fetched" not in page
    assert "Runs that did not move the window" not in page

    listing = client.get("/ui/schedules", headers=_admin(**BROWSER)).text
    assert "schedule failing" not in listing
    assert "schedules failing" not in listing


def test_a_failing_schedule_shows_the_banks_return_code_and_report_text(console):
    """The other half. A refusal is loud, and it quotes the bank verbatim."""
    client, engine, bank_keys, settings = console
    sid = _create(client)["schedule_id"]

    def refusing(body: bytes) -> bytes:
        return bank_response(
            "Initialisation", signing_key=bank_keys.authentication,
            return_code="091005",
            report_text="[EBICS_INVALID_ORDER_PARAMS] the order parameters are "
                        "invalid for this subscriber")

    with serving_bank(refusing) as url:
        _point_at(engine, url)
        result = _worker(engine, settings).run_once()

    assert result.state == REFUSED
    schedule = client.get(f"/v1/schedules/{sid}", headers=_admin()).json()
    assert schedule["health"] == "failing"
    assert schedule["last_return_code"] == "091005"
    # The window did **not** move: the days it asked for are asked for again.
    assert schedule["window"]["covered_through"] is None

    runs = client.get(f"/v1/schedules/{sid}/runs", headers=_admin()).json()
    assert len(runs["unfinished"]) == 1
    assert runs["unfinished"][0]["return_code"] == "091005"

    page = client.get(f"/ui/schedules/{sid}", headers=_admin(**BROWSER)).text
    assert "Failing: nothing is being fetched" in page
    assert "091005" in page
    assert "EBICS_INVALID_ORDER_PARAMS" in page
    assert "Runs that did not move the window" in page

    listing = client.get("/ui/schedules", headers=_admin(**BROWSER)).text
    assert "1 schedule failing" in listing


# --- the window ledger ------------------------------------------------------

def test_the_ledger_names_the_days_that_are_outstanding(console):
    client, engine, _, _ = console
    sid = _create(client)["schedule_id"]
    today = _dt.datetime.now(_dt.timezone.utc).date()
    DownloadSchedules(engine)._write(
        sid, fetched_through=(today - _dt.timedelta(days=5)).isoformat())

    window = client.get(f"/v1/schedules/{sid}",
                        headers=_admin()).json()["window"]
    assert window["behind"] is True
    assert window["days_behind"] == 4
    assert window["pending_start"] == (today - _dt.timedelta(days=4)).isoformat()
    assert window["pending_end"] == today.isoformat()

    page = client.get(f"/ui/schedules/{sid}", headers=_admin(**BROWSER)).text
    assert "4 days" in page


def test_a_schedule_that_has_never_run_is_not_reported_as_behind(console):
    """Asking for the last seven days on a first run is the window working.

    If a fresh registration lit the amber panel, an operator would learn to
    scroll past it -- and the one schedule that is genuinely stuck is the one
    they would scroll past.
    """
    client, _, _, _ = console
    sid = _create(client, window_days=7)["schedule_id"]
    window = client.get(f"/v1/schedules/{sid}",
                        headers=_admin()).json()["window"]
    assert window["days_behind"] == 7
    assert window["behind"] is False
    assert "windows outstanding" not in client.get(
        "/ui/schedules", headers=_admin(**BROWSER)).text


def test_an_undated_schedule_has_no_window_and_cannot_be_refetched(console):
    """No `DateRange` means the receipt is what stops a re-serve, not a window."""
    client, _, _, _ = console
    sid = _create(client, window_days=None)["schedule_id"]
    window = client.get(f"/v1/schedules/{sid}",
                        headers=_admin()).json()["window"]
    assert window["dated"] is False
    assert window["pending_start"] is None

    refused = client.post(f"/v1/schedules/{sid}/refetch", headers=_admin(),
                          json={"since": "2026-08-01"})
    assert refused.status_code == 409
    assert "no DateRange" in refused.json()["error"]["message"]

    page = client.get(f"/ui/schedules/{sid}", headers=_admin(**BROWSER)).text
    assert "This schedule sends no <code>DateRange</code>" in page
    assert "Re-fetch a window" not in page


def test_a_refetch_in_the_future_is_refused(console):
    client, _, _, _ = console
    sid = _create(client)["schedule_id"]
    ahead = (_dt.datetime.now(_dt.timezone.utc).date()
             + _dt.timedelta(days=1)).isoformat()
    refused = client.post(f"/v1/schedules/{sid}/refetch", headers=_admin(),
                          json={"since": ahead})
    assert refused.status_code == 409


def test_a_refetch_rewinds_the_mark_and_asks_from_the_day_requested(console):
    client, engine, _, _ = console
    sid = _create(client)["schedule_id"]
    DownloadSchedules(engine)._write(sid, fetched_through="2026-08-25")

    queued = client.post(f"/v1/schedules/{sid}/refetch", headers=_admin(),
                         json={"since": "2026-08-10"})
    assert queued.status_code == 202
    window = queued.json()["window"]
    # The day *before* the one asked for, so `Schedule.window` -- the same code
    # every ordinary run uses -- asks from 2026-08-10.
    assert window["covered_through"] == "2026-08-09"
    assert window["pending_start"] == "2026-08-10"


def test_a_refetch_of_a_window_already_fetched_stores_no_second_statement(console):
    """The property the whole re-fetch control depends on, at the database level.

    Two real downloads of the same document, driven through the worker against
    a stub bank. The second is a deliberate operator re-fetch. What is counted
    is `statement` rows and their ids -- not a return value, and not the
    existence of a constraint.
    """
    client, engine, bank_keys, settings = console
    sid = _create(client)["schedule_id"]
    payload = zipped("camt.052.001.08", "camt.053.001.08")

    first = _run_a_download(engine, settings, bank_keys, payload)
    assert first.state == COMPLETE
    assert first.duplicates == 0
    with engine.connect() as connection:
        after_first = sorted(row[0] for row in connection.execute(
            select(statement.c.statement_id)))
    assert len(after_first) == first.statements

    # The operator asks for the same window back.
    since = (_dt.datetime.now(_dt.timezone.utc).date()
             - _dt.timedelta(days=3)).isoformat()
    assert client.post(f"/v1/schedules/{sid}/refetch", headers=_admin(),
                       json={"since": since}).status_code == 202

    second = _run_a_download(engine, settings, bank_keys, payload)
    assert second.state == COMPLETE
    assert second.duplicates == first.statements
    assert second.statement_ids == ()

    with engine.connect() as connection:
        after_second = sorted(row[0] for row in connection.execute(
            select(statement.c.statement_id)))
    assert after_second == after_first, "a re-fetch created statement rows"

    # And the ledger says a human asked for the second one, which is what makes
    # its duplicate count expected rather than a receipt that never arrived.
    runs = client.get(f"/v1/schedules/{sid}/runs",
                      headers=_admin()).json()["runs"]
    assert runs[0]["requested_by"] == "alice"
    assert runs[0]["duplicates"] == first.statements
    assert runs[1]["requested_by"] is None


def _run_a_download(engine, settings, bank_keys, payload):
    """One real `BTD` against a stub bank, driven by the download worker."""
    seen: list[bytes] = []
    script = download_script(bank_keys.authentication,
                             _subscriber_e002(engine), payload, seen)
    with serving_bank(script) as url:
        _point_at(engine, url)
        return _worker(engine, settings).run_once()


# --- the console ------------------------------------------------------------

def test_a_schedule_is_created_through_the_console(console):
    """The form's cadence is a number and a unit, not a seconds box."""
    client, _, _, _ = console
    response = client.post("/ui/schedules", headers=_admin(**BROWSER), data={
        "connection_id": BANK_CONNECTION_ID, "service_name": "STM",
        "msg_name": "camt.052", "msg_version": "08", "scope": "CH",
        "container": "ZIP", "cadence": "30", "cadence_unit": "minutes",
        "window_days": "3", "description": "Intraday reports"},
        follow_redirects=False)
    assert response.status_code == 303

    listed = client.get("/v1/schedules", headers=_admin()).json()["schedules"]
    assert len(listed) == 1
    assert listed[0]["cadence_seconds"] == 1800
    assert listed[0]["label"] == "STM/camt.052.08"
    assert listed[0]["description"] == "Intraday reports"

    page = client.get(response.headers["location"],
                      headers=_admin(**BROWSER)).text
    assert "The schedule is registered" in page


def test_the_console_cadence_survives_a_round_trip_through_the_edit_form(console):
    """A form that rendered 90 seconds as "1 hour" would change it on save."""
    client, _, _, _ = console
    sid = _create(client, cadence_seconds=90)["schedule_id"]
    page = client.get(f"/ui/schedules/{sid}", headers=_admin(**BROWSER)).text
    # 90 seconds has no whole-unit form, so the form falls back to minutes and
    # the page says what is actually stored rather than what the box shows.
    assert "every 90 seconds" in page

    sid = _create(client, cadence_seconds=21600, msg_name="camt.052",
                  service_name="STM")["schedule_id"]
    page = client.get(f"/ui/schedules/{sid}", headers=_admin(**BROWSER)).text
    assert 'value="6"' in page
    assert '<option value="hours" selected>' in page

    client.post(f"/ui/schedules/{sid}/edit", headers=_admin(**BROWSER), data={
        "service_name": "STM", "msg_name": "camt.052", "msg_version": "08",
        "scope": "CH", "container": "ZIP", "cadence": "6",
        "cadence_unit": "hours", "window_days": "7",
        "description": "Renamed"}, follow_redirects=False)
    changed = client.get(f"/v1/schedules/{sid}", headers=_admin()).json()
    assert changed["cadence_seconds"] == 21600
    assert changed["description"] == "Renamed"


def test_the_console_pauses_resumes_runs_and_refetches(console):
    client, engine, _, _ = console
    sid = _create(client)["schedule_id"]
    DownloadSchedules(engine)._write(sid, fetched_through="2026-08-25")

    client.post(f"/ui/schedules/{sid}/pause", headers=_admin(**BROWSER),
                follow_redirects=False)
    assert client.get(f"/v1/schedules/{sid}",
                      headers=_admin()).json()["enabled"] is False
    page = client.get(f"/ui/schedules/{sid}", headers=_admin(**BROWSER)).text
    assert "Paused" in page

    client.post(f"/ui/schedules/{sid}/resume", headers=_admin(**BROWSER),
                follow_redirects=False)
    assert client.get(f"/v1/schedules/{sid}",
                      headers=_admin()).json()["enabled"] is True

    ran = client.post(f"/ui/schedules/{sid}/run", headers=_admin(**BROWSER),
                      follow_redirects=False)
    assert ran.headers["location"].endswith("?queued=run")
    assert "The schedule is due now" in client.get(
        ran.headers["location"], headers=_admin(**BROWSER)).text

    refetched = client.post(f"/ui/schedules/{sid}/refetch",
                            headers=_admin(**BROWSER),
                            data={"since": "2026-08-10"},
                            follow_redirects=False)
    assert refetched.headers["location"].endswith("?queued=refetch")
    assert client.get(f"/v1/schedules/{sid}", headers=_admin()
                      ).json()["window"]["covered_through"] == "2026-08-09"


def test_the_console_refuses_a_deletion_that_was_not_confirmed(console):
    client, _, _, _ = console
    sid = _create(client)["schedule_id"]
    assert client.post(f"/ui/schedules/{sid}/delete", headers=_admin(**BROWSER),
                       data={"confirm": "yes"}).status_code == 409
    assert client.get(f"/v1/schedules/{sid}", headers=_admin()).status_code == 200

    gone = client.post(f"/ui/schedules/{sid}/delete", headers=_admin(**BROWSER),
                       data={"confirm": "delete"}, follow_redirects=False)
    assert gone.status_code == 303
    assert client.get(f"/v1/schedules/{sid}", headers=_admin()).status_code == 404


def test_an_unknown_console_action_is_a_404_not_a_silent_success(console):
    client, _, _, _ = console
    sid = _create(client)["schedule_id"]
    assert client.post(f"/ui/schedules/{sid}/detonate",
                       headers=_admin(**BROWSER)).status_code == 404


def test_the_nav_offers_schedules_to_a_reader_and_the_button_only_to_a_manager(console):
    """Hiding a control is decoration; the refusal above is the control."""
    client, _, _, _ = console
    _create(client)
    reader = client.get("/ui/schedules", headers=_viewer(**BROWSER)).text
    assert '/ui/schedules' in reader
    assert "Add a schedule" not in reader

    manager = client.get("/ui/schedules", headers=_operator(**BROWSER)).text
    assert "Add a schedule" in manager


def test_the_console_refuses_a_cadence_it_cannot_read(console):
    client, _, _, _ = console
    response = client.post("/ui/schedules", headers=_admin(**BROWSER), data={
        "connection_id": BANK_CONNECTION_ID, "service_name": "EOP",
        "msg_name": "camt.053", "cadence": "soon", "cadence_unit": "hours"})
    assert response.status_code == 409


def test_the_console_refuses_a_cadence_unit_it_does_not_know(console):
    client, _, _, _ = console
    response = client.post("/ui/schedules", headers=_admin(**BROWSER), data={
        "connection_id": BANK_CONNECTION_ID, "service_name": "EOP",
        "msg_name": "camt.053", "cadence": "1", "cadence_unit": "fortnights"})
    assert response.status_code == 409


def test_the_runs_outcome_survives_the_log_redactor(console, caplog):
    """`state` is a redacted field name, and the run's outcome is not a secret.

    One more instance of a collision this service has hit before: a bare
    ``state=`` key is replaced with ``***`` at every nesting depth, so
    `download.finished` was telling an operator nothing about how the download
    ended. The database column keeps its name -- only what is *logged* is
    renamed.
    """
    client, engine, bank_keys, settings = console
    _create(client)
    with caplog.at_level(logging.DEBUG, logger="painfree"):
        _run_a_download(engine, settings, bank_keys, zipped("camt.053.001.08"))

    finished = [record for record in caplog.records
                if record.getMessage() == "download.finished"]
    assert finished, "the run recorded no outcome at all"
    line = JsonFormatter().format(finished[0])
    assert '"run_state": "complete"' in line
    assert '"state"' not in line

    row = _audit_detail(engine, "download.finished")
    assert row["run_state"] == "complete"


def _audit_detail(engine, action: str) -> dict:
    from painfree.schema import audit_log

    with engine.connect() as connection:
        return connection.execute(
            select(audit_log.c.detail)
            .where(audit_log.c.action == action)
            .order_by(audit_log.c.seq.desc()).limit(1)).scalar_one()


# --- the store's own guards -------------------------------------------------

def test_updating_a_field_that_is_not_mutable_is_refused(console):
    """`fetched_through` is not editable through `update`: rewinding a window is
    `refetch`, which records who asked and why."""
    client, engine, _, _ = console
    sid = _create(client)["schedule_id"]
    with pytest.raises(ConflictError):
        DownloadSchedules(engine).update(sid, fetched_through="2026-01-01")


def test_an_edit_revalidates_the_btf_against_the_merged_row(console):
    """Changing one field still has to leave a BTF the bank's schema accepts."""
    client, engine, _, _ = console
    sid = _create(client)["schedule_id"]
    from painfree.ebics3 import RequestError

    with pytest.raises(RequestError):
        DownloadSchedules(engine).update(sid, service_name="EOPX")


def test_the_form_offers_what_the_bank_published(console):
    """The six BTF fields were free text beside a table of what is "common in
    Switzerland". painfree already had the real answer: `HTD` lists every `BTD`
    row this subscriber may fetch, parsed and stored per connection.

    Retyping it is how a `container` ends up empty when the bank published
    `ZIP` -- and that is `091113` hours later rather than a message at the form.
    """
    from painfree.catalogue import Catalogue
    from tests.test_service_catalogue import HTD

    client, engine = console[0], console[1]
    Catalogue(engine).record(BANK_CONNECTION_ID, "HTD", document=HTD)

    page = client.get("/ui/schedules/new", headers=_admin()).text

    assert 'name="published_btf"' in page, "the bank's own list is offered"
    # The whole triplet rides in the value, because a select submits one string
    # -- which is also what makes this work with no script.
    assert f"{BANK_CONNECTION_ID}|" in page
    # And the generic table is gone once the bank has spoken for itself.
    assert "schedule_new.btf_heading" not in page


def test_choosing_a_published_download_fills_every_field(console):
    """One choice, and the connection comes with it."""
    from painfree.catalogue import Catalogue
    from tests.test_service_catalogue import HTD

    client, engine = console[0], console[1]
    Catalogue(engine).record(BANK_CONNECTION_ID, "HTD", document=HTD)

    created = client.post(
        "/ui/schedules",
        data={"published_btf": f"{BANK_CONNECTION_ID}|EOP|CH|camt.053|08|ZIP|",
              "cadence": "6", "cadence_unit": "hours"},
        headers=_admin(), follow_redirects=False)

    assert created.status_code == 303, created.text[:300]
    stored = DownloadSchedules(engine).all()[-1]
    assert (stored.service_name, stored.msg_name, stored.msg_version,
            stored.scope, stored.container) == ("EOP", "camt.053", "08",
                                                "CH", "ZIP")
    assert stored.connection_id == BANK_CONNECTION_ID


def test_a_forged_selection_is_refused_rather_than_guessed(console):
    """The value is a form field, so it is a value the caller writes."""
    client = console[0]
    refused = client.post("/ui/schedules",
                          data={"published_btf": "nonsense", "cadence": "6",
                                "cadence_unit": "hours"},
                          headers=_admin())
    assert refused.status_code >= 400
