"""The chrome: the app bar, the drawer, the theme toggle and the bell.

These are the claims a screenshot cannot make.

**The layout is the one that was asked for.** The icon is first in the app bar,
the name is next to it, and the right-hand cluster is theme, notifications,
profile -- so that reading it right to left from the edge gives profile,
notifications, theme. It is asserted on the *document order*, because that is
what a screen reader follows and what a screenshot cannot show.

**Navigation is in the drawer and is not in the app bar.**

**Everything but the theme toggle works without JavaScript.** The drawer's
narrow-viewport disclosure is a checkbox and a label; the two app-bar menus are
`<details>`; no form and no link depends on a script. The one script the console
ships is inline, synchronous and in `<head>`, which is what makes the theme
apply before the first paint rather than after it.

**The bell counts the reader's own connections and nothing else.** A member is
never told the number of parked endpoints at a bank they were not granted --
that number is a disclosure that the bank exists and is broken.
"""

from __future__ import annotations

import datetime as _dt
import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from painfree import wrapping
from painfree.app import create_app
from painfree.orders import OrderState
from painfree.schema import download_schedule, webhook_subscription
from painfree.ui import notifications, rendering
from tests.conftest import (BANK_CONNECTION_ID, dev_credentials, grant,
                            payment_body)

BROWSER = {"accept": "text/html,application/xhtml+xml"}

#: A second bank the member is never granted. Everything asserted about what a
#: member cannot see is asserted against this one.
OTHER = "beta-bank"


def _admin(**extra) -> dict[str, str]:
    return {**dev_credentials("alice", "admin"), **BROWSER, **extra}


def _member(**extra) -> dict[str, str]:
    return {**dev_credentials("olive", "member"), **BROWSER, **extra}


def _stranger(**extra) -> dict[str, str]:
    """A member who has signed in and been granted nothing."""
    return {**dev_credentials("mia", "member"), **BROWSER, **extra}


@pytest.fixture
def console(prepared_bank, custody_settings):
    """Two banks. One the member holds, one they do not.

    Both are given something wrong with them, so every assertion about scoping
    is made against a deployment where the unscoped answer would be different
    from the scoped one.
    """
    engine, connection, bank_keys = prepared_bank
    # A webhook secret is sealed to a key only a worker can publish;
    # registering an endpoint needs one on file.
    wrapping.publish(engine, custody_settings.custody_key())
    app = create_app(custody_settings)
    with TestClient(app) as client:
        app.state.connections.register(
            OTHER, host_id="BETACH", partner_id="PARTNER7", user_id="USER7",
            host_url="https://ebics.beta.example/ebicsweb")
        grant(app, "olive", BANK_CONNECTION_ID, "operator")
        yield client, app, engine


def _park_a_webhook(app, connection_id: str) -> None:
    subscription, _ = app.state.webhooks.register(
        "https://receiver.example/hook", ["order.accepted"],
        connection_id=connection_id)
    with app.state.engine.begin() as connection:
        connection.execute(
            update(webhook_subscription)
            .where(webhook_subscription.c.subscription_id
                   == subscription.subscription_id)
            .values(parked_at=_dt.datetime.now(_dt.timezone.utc),
                    consecutive_failures=3))


def _fail_a_schedule(app, connection_id: str) -> None:
    schedule = app.state.schedules.register(
        connection_id, service_name="PSR", msg_name="pain.002",
        msg_version="10", cadence=_dt.timedelta(hours=1))
    with app.state.engine.begin() as connection:
        connection.execute(
            update(download_schedule)
            .where(download_schedule.c.schedule_id == schedule.schedule_id)
            .values(last_run_at=_dt.datetime.now(_dt.timezone.utc),
                    last_return_code="061002",
                    last_error="the bank's host did not answer"))


def _fail_an_order(client, app, key: str) -> str:
    order = client.post(
        f"/v1/connections/{BANK_CONNECTION_ID}/payments", json=payment_body(),
        headers={**dev_credentials("alice", "admin"),
                 "Idempotency-Key": key}).json()
    with app.state.engine.begin() as connection:
        from painfree.schema import payment_order
        connection.execute(
            update(payment_order)
            .where(payment_order.c.order_id == order["order_id"])
            .values(state=OrderState.FAILED.value))
    return order["order_id"]


def _visible(body: str) -> str:
    """The document without its inlined stylesheet and script.

    The console carries its own CSS in a `<style>` element, so a naive
    ``"failing" not in page.text`` would be answered by the `.tag.failing`
    selector rather than by anything the reader can see. Every assertion about
    what a page does *not* say is made against this.
    """
    without_style = re.sub(r"<style>.*?</style>", "", body, flags=re.DOTALL)
    return re.sub(r"<script>.*?</script>", "", without_style, flags=re.DOTALL)


def _page(client, headers) -> str:
    """The bell's contents, read off the page the reader actually gets."""
    page = client.get("/ui/connections", headers=headers)
    assert page.status_code == 200, page.text[:300]
    return _visible(page.text)


# --- the app bar and the drawer ---------------------------------------------

def test_the_app_bar_carries_the_icon_then_the_name_then_the_right_cluster(console):
    client, app, engine = console
    body = client.get("/ui/connections", headers=_admin()).text
    bar = body.split('class="pf-app-bar"')[1].split("</header>")[0]

    logo = bar.index("pf-logo")
    name = bar.index("pf-brand-name")
    theme = bar.index("pf-theme-toggle")
    bell = bar.index("pf-notifications")
    profile = bar.index("pf-profile")

    # The icon is first and the name is beside it; then, left to right,
    # theme -> notifications -> profile, which is profile -> notifications ->
    # theme reading inwards from the right edge.
    assert logo < name < theme < bell < profile


def test_navigation_is_in_the_drawer_and_not_in_the_app_bar(console):
    client, app, engine = console
    body = client.get("/ui/connections", headers=_admin()).text
    bar = body.split('class="pf-app-bar"')[1].split("</header>")[0]
    drawer = body.split('class="pf-drawer"')[1].split("</nav>")[0]

    for href in ("/ui/connections", "/ui/orders", "/ui/statements",
                 "/ui/schedules", "/ui/audit", "/ui/status-codes", "/ui/api",
                 "/ui/access"):
        assert f'href="{href}"' in drawer, href

    # The app bar carries no navigation at all. The two links it does have are
    # account actions inside the profile menu -- what this caller holds, and
    # signing out -- which are not sections of the console.
    nav = bar.split('class="pf-app-bar-actions"')[0]
    assert "href=" not in nav.replace('href="/ui/connections"', "", 1), (
        "only the brand link may be a link in the app bar's left half")
    for href in ("/ui/orders", "/ui/statements", "/ui/schedules", "/ui/audit",
                 "/ui/status-codes", "/ui/access"):
        assert f'href="{href}"' not in bar, href


def test_the_drawer_marks_the_page_you_are_on(console):
    client, app, engine = console
    body = client.get("/ui/audit", headers=_admin()).text
    marked = re.findall(r'href="([^"]+)"[^>]*aria-current="page"', body)
    assert marked == ["/ui/audit"]


def test_the_narrow_viewport_disclosure_needs_no_script(console):
    client, app, engine = console
    body = client.get("/ui/connections", headers=_admin()).text
    # A checkbox and a label for it. Not a button with a handler.
    assert 'type="checkbox" id="pf-nav"' in body
    assert 'for="pf-nav"' in body
    # And the two app-bar menus are real disclosures.
    assert body.count("<details") >= 2
    assert body.count("<summary") >= 2


def test_the_drawer_switch_leaves_the_tab_order_with_its_label():
    """A focusable control nobody can see is a keyboard stop that does nothing.

    Above 900px the drawer is always on screen, so the switch and its label are
    both `display: none` -- which takes the input out of the tab order and out
    of the accessibility tree together. Below 900px both come back.
    """
    css = rendering.STYLESHEET
    assert ".pf-nav-switch { display: none; }" in css
    narrow = css.split("@media (max-width: 899px)")[1]
    assert ".pf-nav-switch { display: block; }" in narrow
    assert ".pf-nav-button { display: inline-flex; }" in narrow


def test_the_drawer_hides_what_the_reader_may_not_open(console):
    client, app, engine = console
    member = client.get("/ui/connections", headers=_member()).text
    drawer = member.split('class="pf-drawer"')[1].split("</nav>")[0]
    # An `operator` grant carries no `admin`, so no Access entry.
    assert 'href="/ui/access"' not in drawer
    # And it does carry the read scopes, so those are offered.
    assert 'href="/ui/orders"' in drawer
    # The two scopeless entries are there for a reader holding nothing at all.
    stranger = client.get("/ui/connections", headers=_stranger()).text
    stranger_drawer = stranger.split('class="pf-drawer"')[1].split("</nav>")[0]
    assert 'href="/ui/connections"' in stranger_drawer
    assert 'href="/ui/api"' in stranger_drawer
    assert 'href="/ui/orders"' not in stranger_drawer


# --- the theme toggle -------------------------------------------------------

def test_the_theme_script_runs_in_head_before_the_body_is_parsed(console):
    client, app, engine = console
    body = client.get("/ui/connections", headers=_admin()).text

    script = body.index("<script>")
    assert script < body.index("</head>"), "the script must be in <head>"
    assert script < body.index("<body>"), "and before any of <body> is parsed"
    # Synchronous. `defer` or `async` would move it after the parse, which is
    # exactly the flash of the wrong theme this ordering exists to prevent.
    opening = body[script:script + 60]
    assert "defer" not in opening and "async" not in opening
    assert "type=" not in opening
    # And it is the *only* script: this console ships one, for one control.
    assert body.count("<script") == 1


def test_the_toggle_offers_exactly_three_states_and_defaults_to_system(console):
    client, app, engine = console
    body = client.get("/ui/connections", headers=_admin()).text
    choices = re.findall(r'data-theme-choice="(\w+)"', body)
    assert choices == ["system", "light", "dark"]
    # The server renders `system` pressed, because `system` is the default and
    # the script has not run yet when this markup is written.
    pressed = re.findall(
        r'data-theme-choice="(\w+)"\s+aria-pressed="true"', body)
    assert pressed == ["system"]


def test_system_is_the_absence_of_a_choice_rather_than_a_third_palette():
    """`system` is `color-scheme: light dark` and no attribute.

    That is what makes the default work with scripting disabled: the browser,
    not the script, is what follows `prefers-color-scheme`.
    """
    css = rendering.STYLESHEET
    assert "color-scheme: light dark;" in css
    assert ':root[data-theme="light"] { color-scheme: light; }' in css
    assert ':root[data-theme="dark"] { color-scheme: dark; }' in css
    # No `@media (prefers-color-scheme: ...)` block redefines the palette --
    # one copy of each colour, resolved by `color-scheme`.
    assert "prefers-color-scheme" not in css


def test_every_colour_role_has_a_plain_value_before_its_light_dark_one():
    """A browser without `light-dark()` gets the light console, not a broken one.

    An unsupported function makes the whole declaration invalid, and a custom
    property with no value is a page with no colours. So every role is declared
    twice: a plain light value, then the `light-dark()` pair that supersedes it
    where it is understood.
    """
    css = (rendering.STATIC / "01-tokens.css").read_text(encoding="utf-8")
    declarations = re.findall(r"^\s*(--pf-[a-z0-9-]+):\s*(.+?);\s*$", css,
                              re.MULTILINE)
    fallbacks: dict[str, str] = {}
    unguarded = []
    for name, value in declarations:
        if "light-dark(" in value:
            if name not in fallbacks:
                unguarded.append(name)
        else:
            fallbacks[name] = value
    assert unguarded == [], unguarded


def test_the_stylesheet_is_condensed_but_intact():
    css = rendering.STYLESHEET
    assert "/*" not in css, "comments are for whoever edits static/, not the wire"
    for selector in (".pf-app-bar", ".pf-drawer-inner", ".pf-nav-item",
                     ".pf-theme-toggle", ".card", ".tag", ".fingerprint",
                     ".letter", "form.stack"):
        assert selector in css, selector
    # And the four files really are all in it, in cascade order.
    assert css.index("--pf-primary:") < css.index(".pf-app-bar")
    assert css.index(".pf-app-bar") < css.index(".steps")


# --- the bell ---------------------------------------------------------------

def test_the_bell_counts_the_five_conditions_an_operator_has_to_act_on(console):
    client, app, engine = console
    _park_a_webhook(app, BANK_CONNECTION_ID)
    _fail_a_schedule(app, BANK_CONNECTION_ID)
    _fail_an_order(client, app, "bell-0001")
    _fail_an_order(client, app, "bell-0002")
    app.state.key_jobs.request(
        OTHER, "create_keys",
        key_state=app.state.connections.get(OTHER).key_state)

    body = _page(client, _admin())
    assert "1 webhook endpoint parked" in body
    assert "1 download schedule failing" in body
    assert "2 orders failed" in body
    # `beta-bank` was registered and never initialised.
    assert "1 bank connection not initialised" in body
    assert "1 key operation in flight" in body
    assert 'class="pf-badge">6<' in body


def test_nothing_ordinary_is_counted(console):
    """A console with nothing wrong with it shows an empty bell.

    The seeded bank is initialised and has no failures, so the only alert is
    the second connection nobody has walked through the key lifecycle. Remove
    that and the count is zero -- a bell that lit up for a healthy deployment
    would be a bell an operator learns to ignore.
    """
    client, app, engine = console
    body = client.get("/ui/connections", headers=_admin()).text
    assert "1 bank connection not initialised" in body

    from painfree.schema import bank_connection
    with app.state.engine.begin() as connection:
        connection.execute(
            update(bank_connection)
            .where(bank_connection.c.connection_id == OTHER)
            .values(key_state="ready"))
    body = client.get("/ui/connections", headers=_admin()).text
    assert 'class="pf-badge"' not in body
    assert "Nothing is parked, failing or waiting on a person" in body


def test_a_member_is_never_counted_a_connection_they_do_not_hold(console):
    """The disclosure a number would be.

    Everything wrong in this deployment is wrong at `beta-bank`, which the
    member was not granted. The administrator sees four things; the member sees
    none, and the *count* is what would otherwise leak that the bank exists.
    """
    client, app, engine = console
    _park_a_webhook(app, OTHER)
    _fail_a_schedule(app, OTHER)
    app.state.key_jobs.request(
        OTHER, "create_keys",
        key_state=app.state.connections.get(OTHER).key_state)

    administrator = _page(client, _admin())
    assert "1 webhook endpoint parked" in administrator
    assert "1 download schedule failing" in administrator
    assert "1 bank connection not initialised" in administrator
    assert "1 key operation in flight" in administrator

    member = _page(client, _member())
    assert 'class="pf-badge"' not in member
    assert "endpoint parked" not in member
    assert "schedule failing" not in member
    assert "not initialised" not in member
    assert "key operation in flight" not in member
    # And the bank's own name never reaches the page, which is the disclosure
    # a bare count would have been the first half of.
    assert OTHER not in member
    assert "Nothing is parked, failing or waiting on a person" in member


def test_a_member_holding_nothing_is_told_nothing(console):
    client, app, engine = console
    _park_a_webhook(app, BANK_CONNECTION_ID)
    _fail_a_schedule(app, BANK_CONNECTION_ID)
    body = _page(client, _stranger())
    assert 'class="pf-badge"' not in body
    assert "Nothing is parked, failing or waiting on a person" in body


def test_a_badge_is_never_offered_for_a_page_the_reader_is_refused(console):
    """`webhooks:read` gates the parked count, not just the Webhooks page.

    A `viewer` grant does not carry it, so that reader is not told a number
    whose only destination answers `403` -- and the `403` is asserted here
    rather than assumed, so the two cannot drift apart.
    """
    client, app, engine = console
    _park_a_webhook(app, BANK_CONNECTION_ID)
    grant(app, "vera", BANK_CONNECTION_ID, "viewer")
    viewer = {**dev_credentials("vera", "member"), **BROWSER}

    assert client.get("/ui/webhooks", headers=viewer).status_code == 403
    body = _page(client, viewer)
    assert "webhook endpoint parked" not in body

    # The `operator` on the same connection does carry it, and is told.
    assert client.get("/ui/webhooks", headers=_member()).status_code == 200
    assert "1 webhook endpoint parked" in client.get(
        "/ui/connections", headers=_member()).text


def test_the_drawer_counts_the_same_things_the_bell_does(console):
    """An alert names a page; the drawer names the section that page is in.

    ``/ui/connections/{id}/keys`` counts against **Connections**, not as an
    entry of its own -- the drawer is the map, the bell is the errand.
    """
    client, app, engine = console
    app.state.key_jobs.request(
        OTHER, "create_keys",
        key_state=app.state.connections.get(OTHER).key_state)
    _fail_an_order(client, app, "sections-0001")

    found = notifications.alerts(
        _FakeRequest(app), _principal(client, _admin()))
    sections = notifications.by_section(found)
    # The uninitialised bank and its queued key job are both Connections.
    assert sections["/ui/connections"] == 2
    assert sections["/ui/orders"] == 1
    assert notifications.total(found) == 3


class _FakeRequest:
    """Just enough of a request for the aggregation: it reads `app.state`."""

    def __init__(self, app) -> None:
        self.app = app


def _principal(client, headers):
    """The principal the server would build for these headers."""
    me = client.get("/auth/me", headers=headers).json()
    from painfree.identity import Level, build_principal
    return build_principal(
        subject=me["subject"], issuer=me["issuer"], method=me["method"],
        roles=me["roles"],
        grants=[(row["connection_id"], Level(row["level"]))
                for row in me["grants"]])


def test_an_aggregation_that_cannot_answer_does_not_break_the_page(console):
    """The bell runs on every render, including the error page.

    A store that raises must cost the count, never the page: a console that
    will not render because its notification count failed is worse than one
    with no count.
    """
    client, app, engine = console

    class Broken:
        def all(self, *args, **kwargs):
            raise RuntimeError("the database is gone")

    original = app.state.webhooks
    app.state.webhooks = Broken()
    try:
        page = client.get("/ui/connections", headers=_admin())
        assert page.status_code == 200
        assert 'class="pf-badge"' not in page.text
    finally:
        app.state.webhooks = original
