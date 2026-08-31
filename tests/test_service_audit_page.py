"""The audit trail as a surface: the filters, the links, and the scope.

The tests worth having here are the ones the page cannot be trusted to show:

**`audit:read` is enforced by the server.** A member holding no connection is
refused, at the API and at the page, with the missing scope named. The scope is
carried by both grant levels and is **scoped to the connections the caller
holds** -- so a member granted one bank reads that bank's trail and nothing
else, which is proved next door in ``tests/test_service_access.py`` where the
attacker is. What is proved here is the surface: the filters, the links, the
cursor, and the refusal.

**A filter that narrows must actually narrow.** A page that quietly ignores an
unrecognised filter and shows everything is worse than one that refuses,
because it looks like an answer.

**A row links to the thing it happened to** -- and only to the things the
reader may open, because `audit:read` does not imply the read scopes.

**Paging is by the append sequence.** A row written while an operator reads
must not push a row off the next page, which is what an offset does.
"""

from __future__ import annotations

import datetime as _dt

import pytest
from fastapi.testclient import TestClient

from painfree.app import create_app
from painfree.audit import FAILURE, Actor, AuditLog
from painfree.ui.rendering import audit_links
from tests.conftest import BANK_CONNECTION_ID, dev_credentials

BROWSER = {"accept": "text/html,application/xhtml+xml"}


def _rows(body: str) -> str:
    """The page below its filter form.

    The `action` and `actor` dropdowns list every value in the table, so a
    naive substring check on the whole page finds a filtered-out action in its
    own filter control and concludes nothing was narrowed.
    """
    return body.rsplit("</form>", 1)[-1]


def _headers(subject: str, roles: str, **extra) -> dict[str, str]:
    return {**dev_credentials(subject, roles), **extra}


@pytest.fixture
def console(prepared_bank, custody_settings):
    engine, connection, _bank_keys = prepared_bank
    app = create_app(custody_settings)
    with TestClient(app) as client:
        yield client, engine


@pytest.fixture
def trail(console):
    """A handful of rows written by the one writer, as the service writes them."""
    client, engine = console
    log = AuditLog(engine)
    log.record("payment.accepted", actor=Actor("user", "alice"),
               connection_id=BANK_CONNECTION_ID, order_id="ord_a",
               idempotency_key="idem-1", detail={"msg_id": "MSG-1"})
    log.record("payment.rejected", actor=Actor("user", "olive"),
               outcome=FAILURE, connection_id=BANK_CONNECTION_ID,
               order_id="ord_b", detail={"order_state": "rejected",
                                         "return_code": "091005"})
    log.record("download_schedule.registered", actor=Actor("user", "olive"),
               connection_id=BANK_CONNECTION_ID,
               detail={"schedule_id": "dsc_1", "service": "EOP/camt.053.08"})
    log.record("webhook.subscription_registered", actor=Actor("client", "robot"),
               detail={"subscription_id": "whs_1", "url": "https://x.test/h"})
    return client, log


# --- the scope --------------------------------------------------------------

@pytest.mark.parametrize("role", ["member", ""])
def test_the_api_refuses_a_caller_without_audit_read(trail, role):
    client, _log = trail
    response = client.get("/v1/audit", headers=_headers("nosy", role))
    assert response.status_code == 403
    assert response.json()["error"]["detail"]["missing_scopes"] == ["audit:read"]


@pytest.mark.parametrize("role", ["member", ""])
def test_the_page_refuses_a_caller_without_audit_read(trail, role):
    """Requested directly, with no page rendered first: hiding the nav link is
    decoration, the refusal is the control."""
    client, _log = trail
    response = client.get("/ui/audit", headers=_headers("nosy", role, **BROWSER))
    assert response.status_code == 403
    assert "audit:read" in response.text


@pytest.mark.parametrize("role", ["admin", "administrator"])
def test_the_roles_that_hold_it_get_the_page(trail, role):
    client, _log = trail
    response = client.get("/ui/audit", headers=_headers("ann", role, **BROWSER))
    assert response.status_code == 200
    assert "payment.accepted" in response.text


# --- filtering --------------------------------------------------------------

def test_filtering_by_action_narrows_the_page(trail):
    client, _log = trail
    body = _rows(client.get("/ui/audit?action=payment.rejected",
                            headers=_headers("ann", "admin", **BROWSER)).text)
    assert "payment.rejected" in body
    assert "payment.accepted" not in body


def test_filtering_by_actor_narrows_the_page(trail):
    client, _log = trail
    body = _rows(client.get("/ui/audit?actor_id=robot",
                            headers=_headers("ann", "admin", **BROWSER)).text)
    assert "webhook.subscription_registered" in body
    assert "payment.accepted" not in body


def test_filtering_by_outcome_finds_only_the_failures(trail):
    client, _log = trail
    events = client.get("/v1/audit?outcome=failure",
                        headers=_headers("ann", "admin")).json()["events"]
    assert [row["action"] for row in events] == ["payment.rejected"]


def test_filtering_by_order_finds_one_order_s_trail(trail):
    client, _log = trail
    events = client.get("/v1/audit?order_id=ord_a",
                        headers=_headers("ann", "admin")).json()["events"]
    assert [row["order_id"] for row in events] == ["ord_a"]


def test_a_date_window_is_inclusive_of_the_day_named(trail):
    """An operator typing today's date and seeing none of today's events would
    reasonably conclude the page is broken."""
    client, _log = trail
    today = _dt.datetime.now(_dt.timezone.utc).date().isoformat()
    body = _rows(client.get(f"/ui/audit?since={today}&until={today}",
                            headers=_headers("ann", "admin", **BROWSER)).text)
    assert "payment.accepted" in body


def test_a_date_that_is_not_a_date_is_refused_by_name(trail):
    client, _log = trail
    response = client.get("/ui/audit?since=last-tuesday",
                          headers=_headers("ann", "admin", **BROWSER))
    assert response.status_code == 409
    assert "the start date" in response.text


def test_an_action_nothing_wrote_returns_an_empty_page_not_everything(trail):
    client, _log = trail
    body = _rows(client.get("/ui/audit?action=nothing.happened",
                            headers=_headers("ann", "admin", **BROWSER)).text)
    assert "No audit event matches this filter" in body
    assert "payment.accepted" not in body


def test_the_filter_options_come_from_the_rows_that_exist(trail):
    """Offering an action nothing ever wrote is a filter that returns nothing
    and teaches an operator to distrust the page."""
    _client, log = trail
    assert "payment.accepted" in log.actions()
    assert "nothing.happened" not in log.actions()
    # `system` is in there too: the prepared connection was registered by the
    # service on its own behalf, which is exactly the kind of row a filter
    # offering only human names would make unreachable.
    assert {"alice", "olive", "robot"} <= set(log.actors())


# --- paging -----------------------------------------------------------------

def test_paging_is_by_sequence_so_a_new_row_cannot_hide_an_old_one(trail):
    client, log = trail
    first = client.get("/v1/audit?limit=2",
                       headers=_headers("ann", "admin")).json()["events"]
    # Somebody does something while the reader is on page one.
    log.record("payment.accepted", actor=Actor("user", "mallory"),
               order_id="ord_c")
    older = client.get(f"/v1/audit?limit=2&before_seq={first[-1]['seq']}",
                       headers=_headers("ann", "admin")).json()["events"]
    assert not {row["seq"] for row in first} & {row["seq"] for row in older}
    assert [row["seq"] for row in older] == sorted(
        (row["seq"] for row in older), reverse=True)
    assert older[0]["seq"] < first[-1]["seq"]


def test_the_page_offers_older_events_only_when_there_are_some(trail):
    client, _log = trail
    headers = _headers("ann", "admin", **BROWSER)
    assert "Older events" in client.get("/ui/audit?limit=1", headers=headers).text
    assert "Older events" not in client.get("/ui/audit?limit=200",
                                            headers=headers).text


# --- the links --------------------------------------------------------------

def test_a_row_links_to_the_thing_it_concerns(trail):
    client, _log = trail
    body = client.get("/ui/audit", headers=_headers("ann", "admin",
                                                    **BROWSER)).text
    assert f'href="/ui/connections/{BANK_CONNECTION_ID}"' in body
    assert 'href="/ui/orders/ord_a"' in body
    assert 'href="/ui/schedules/dsc_1"' in body
    assert 'href="/ui/webhooks/whs_1"' in body


def test_a_link_is_offered_only_where_the_reader_could_follow_it():
    """`audit:read` does not imply the read scopes. A link that 403s is worse
    than no link, and per-connection grants made this case real rather than
    hypothetical: a `viewer` grant carries `audit:read` and not
    `webhooks:read`, so a webhook row on that reader's page carries no link."""
    row = {"connection_id": "acme", "order_id": "ord_a", "job_id": None,
           "action": "payment.accepted", "detail": {"schedule_id": "dsc_1"}}
    everything = audit_links(row, lambda scope: True)
    # A catalogue key rather than a word: what a link is *called* is read by a
    # person and comes from the reader's own locale, while the id beside it is
    # an identifier and is never touched.
    assert [link["label_key"] for link in everything] == [
        "audit.target.connection", "audit.target.order", "audit.target.schedule"]
    only_orders = audit_links(row, lambda scope: scope == "payments:read")
    assert [link["label_key"] for link in only_orders] == ["audit.target.order"]


def test_a_key_job_links_to_the_page_that_shows_it():
    """The one target not addressed by its own id: it lives under a connection."""
    row = {"connection_id": "acme", "job_id": "kj_9", "order_id": None,
           "action": "key.job_finished", "detail": {}}
    links = audit_links(row, lambda scope: True)
    assert {"label_key": "audit.target.key_job", "value": "kj_9",
            "href": "/ui/connections/acme/keys?job=kj_9"} in links


def test_a_row_about_nothing_addressable_offers_no_links():
    row = {"connection_id": None, "order_id": None, "job_id": None,
           "action": "service.started", "detail": {"version": "0.1"}}
    assert audit_links(row, lambda scope: True) == []


# --- the wire shape ---------------------------------------------------------

def test_the_api_returns_every_correlation_id(trail):
    """The point of a correlation column is joining this row to a log line."""
    client, _log = trail
    events = client.get("/v1/audit?order_id=ord_a",
                        headers=_headers("ann", "admin")).json()["events"]
    assert set(events[0]) == {
        "seq", "event_id", "occurred_at", "actor_type", "actor_id", "action",
        "outcome", "request_id", "connection_id", "order_id", "job_id",
        "idempotency_key", "detail"}
    assert events[0]["idempotency_key"] == "idem-1"
