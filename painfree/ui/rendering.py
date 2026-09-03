"""Turning a request and some rows into a page.

Three things live here so no view has to think about them.

**The environment.** Jinja, with autoescaping on and ``StrictUndefined``: a
template that names a variable no view passes is a test failure rather than a
silently empty cell, which for a screen whose whole job is showing fingerprints
and return codes is the difference between a bug and a wrong trust decision.

**The stylesheet is inlined.** The four files under ``static/`` are read once at
import, in filename order, and rendered into one ``<style>`` element. Serving
them as static files would mean a mount that the deny-by-default middleware has
to be taught about -- and a public path added for a stylesheet is a public path
added -- so the page carries its own. They are four files rather than one
because they answer four questions: what the design tokens are, what a bare
element looks like, what the frame around a page looks like, and what the things
on a page look like.

**The theme script is inlined too, and for a different reason.** ``theme.js``
runs in ``<head>`` before ``<body>`` is parsed, so the stored theme is on the
root element before the first paint and a reload does not flash the wrong one.
It is the only script this console ships and the only thing that stops working
when scripting is off.

**Which language.** Every page also gets a :class:`~painfree.ui.i18n.Translator`
as ``t`` and a :class:`~painfree.ui.i18n.Formats` as ``fmt``, for the locale
:func:`painfree.ui.i18n.resolve` picked -- an explicit ``?lang=``, the cookie a
previous explicit choice left, or the browser's ``Accept-Language``. When the
choice was explicit it is written back as a cookie here, on the response that
carries the newly translated page, which is why choosing a language needs no
route and works with scripting off. **It is display only**: nothing on the wire
-- an amount in a `pain.001`, a date, a `MsgId`, an error `code` -- knows a
locale exists.

**Who is looking.** Every page gets the :class:`~painfree.identity.Principal`
and a ``may`` helper, so a template asks ``may('payments:submit')`` rather than
reimplementing the scope model. It is presentation only: the server refuses the
request whatever the template drew.

**What is waiting.** Every page also gets the notification alerts of
:mod:`painfree.ui.notifications`, narrowed to the caller's own connections, so
the app bar can say which page an operator should be on from whichever page they
are on.
"""

from __future__ import annotations

import datetime as _dt
import json
import pathlib
import re
from typing import Any

from fastapi import Request
from fastapi.responses import HTMLResponse
from jinja2 import (Environment, FileSystemLoader, StrictUndefined,
                    pass_context, select_autoescape)
from markupsafe import Markup

from painfree import ebics3
from painfree.authn import principal_of
from painfree.config import AuthMode
from painfree.identity import Principal, Scope
from painfree.logging import context
from painfree.ui import i18n, notifications

HERE = pathlib.Path(__file__).parent
TEMPLATES = HERE / "templates"
STATIC = HERE / "static"


def _condense(css: str) -> str:
    """Drop the comments and the indentation on the way into the page.

    The stylesheet is inlined into every response and is never cached, and one
    page in this console re-fetches itself every two seconds while a key job
    runs. The comments are two fifths of it and they are for whoever edits
    ``static/``, not for the browser. Nothing else is touched -- no selector
    rewriting, no property reordering, no colour shortening -- because a
    minifier that is wrong about one declaration is a console that is wrong
    about a colour, and ``tests/test_service_ui_chrome.py`` pins the result.
    """
    without_comments = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    return "\n".join(line.strip() for line in without_comments.splitlines()
                     if line.strip())


#: The stylesheet, concatenated in filename order. The numbers in the names are
#: the cascade: tokens, then bare elements, then the frame, then the contents.
STYLESHEET = _condense("\n".join(
    path.read_text(encoding="utf-8") for path in sorted(STATIC.glob("*.css"))))

#: The theme toggle. Inlined into ``<head>`` ahead of everything, because the
#: attribute it sets has to be on the root element before the first paint.
THEME_SCRIPT = (STATIC / "theme.js").read_text(encoding="utf-8")


def _environment() -> Environment:
    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        autoescape=select_autoescape(["html"]),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters["fingerprint"] = _fingerprint
    environment.filters["moment"] = _moment
    environment.filters["day"] = _day
    environment.filters["cadence"] = _cadence
    environment.filters["amount"] = _amount
    environment.filters["count"] = _count
    environment.filters["pretty_json"] = _pretty_json
    environment.filters["pretty_xml"] = _pretty_xml
    environment.globals["stylesheet"] = Markup(STYLESHEET)
    environment.globals["theme_script"] = Markup(THEME_SCRIPT)
    return environment


def _fingerprint(value: str | None) -> str:
    """64 hex characters as a letter prints them, in pairs.

    The engine's own formatter, not a second one: an operator comparing this
    against paper is comparing against ``ebics-client-php``'s grouping, and a
    console that regrouped it would make two correct values look different.
    """
    if not value:
        return "—"
    try:
        return ebics3.format_fingerprint(value)
    except Exception:
        return value


#: What an audit row's ids point at. The trail says *something happened*; an
#: operator's next move is always to the thing it happened to, and making them
#: copy an id out of a JSON blob into a URL bar is how a trail goes unread.
#:
#: Each entry names where the id lives -- a correlation column, or a key in the
#: detail -- the scope needed to follow it, and how the link is built. The scope
#: is checked because `audit:read` does not imply the read scopes: `auditor`
#: happens to hold them all today, and a link that 403s is worse than no link.
#:
#: The fourth field is a **catalogue key rather than a word**: the label is read
#: by a person and the six catalogues answer for it, while the id beside it is
#: an identifier and is never touched.
AUDIT_TARGETS = (
    ("connection_id", "column", Scope.connections_read, "audit.target.connection",
     "/ui/connections/{value}"),
    ("order_id", "column", Scope.payments_read, "audit.target.order",
     "/ui/orders/{value}"),
    ("schedule_id", "detail", Scope.schedules_read, "audit.target.schedule",
     "/ui/schedules/{value}"),
    ("subscription_id", "detail", Scope.webhooks_read, "audit.target.webhook",
     "/ui/webhooks/{value}"),
    ("statement_id", "detail", Scope.statements_read, "audit.target.statement",
     "/ui/statements/{value}"),
)


def audit_links(row: dict[str, Any], may: Any) -> list[dict[str, str]]:
    """Where an audit row can be followed to, for the caller who is reading it.

    A key job is the one target that is not addressed by its own id: the console
    shows it on the connection's key page, which needs both ids, so it is built
    here rather than added to the table above.
    """
    detail = row.get("detail") or {}
    links: list[dict[str, str]] = []
    for name, where, scope, label, template in AUDIT_TARGETS:
        value = row.get(name) if where == "column" else detail.get(name)
        if not value or not isinstance(value, str) or not may(scope.value):
            continue
        links.append({"label_key": label, "value": value,
                      "href": template.format(value=value)})
    if (row.get("job_id") and row.get("connection_id")
            and str(row.get("action", "")).startswith("key.")
            and may(Scope.connections_read.value)):
        links.append({
            "label_key": "audit.target.key_job", "value": row["job_id"],
            "href": f"/ui/connections/{row['connection_id']}/keys"
                    f"?job={row['job_id']}"})
    return links


# The four filters below are locale-aware, which is why each is a
# ``pass_context`` filter reading ``fmt`` out of the render context rather than
# a plain function: a Jinja environment is built once at import and shared by
# every request, so a filter that closed over a locale would be one request's
# locale shown to the next one's reader.


@pass_context
def _moment(context: Any, value: _dt.datetime | None) -> str:
    """A timestamp, written the way this reader's locale writes a date."""
    return _formats(context).moment(value)


@pass_context
def _day(context: Any, value: Any) -> str:
    """A date, or an ISO date string off a row, as this locale writes it."""
    return _formats(context).date(value)


@pass_context
def _cadence(context: Any, seconds: int | None) -> str:
    """``21600`` as *every 6 hours*, in this locale and its own plural."""
    return _formats(context).cadence(seconds)


@pass_context
def _amount(context: Any, value: Any, currency: str | None = None) -> str:
    """An amount **for a screen**. The wire is `pain001.format_amount`.

    A French operator reads `1 234,56`; the `pain.001` this console is looking
    at carries `1234.56` and is not consulted about it.
    """
    return _formats(context).amount(value, currency)


@pass_context
def _count(context: Any, value: int | None) -> str:
    return _formats(context).number(value)


def _formats(context: Any) -> i18n.Formats:
    """The render context's formatter, or English for a template rendered bare."""
    found = context.get("fmt")
    return found if found is not None else i18n.for_locale(i18n.DEFAULT)[1]


def _pretty_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False,
                      default=str)


def _pretty_xml(value: str | bytes) -> str:
    """Indent a document **for reading only**.

    The `pain.001` this service sends carries no line breaks, deliberately:
    EBICS hashes order data with the OS-specific control characters removed, so
    a document containing them has two defensible digests and the bank refuses
    it. That makes the bytes correct and a single 1100-character line, which is
    not something a person can check a payment in.

    So the console indents it, and says so where it shows it. The two are
    different artefacts and the page must not imply otherwise: what is signed
    is what the download serves, and this is a rendering of it.

    Unparseable input comes back unchanged rather than raising. This is a
    display path, and a preview that will not render is worse than one showing
    an awkward line.
    """
    from lxml import etree

    raw = value.encode() if isinstance(value, str) else value
    try:
        parser = etree.XMLParser(remove_blank_text=True)
        return etree.tostring(etree.fromstring(raw, parser),
                              xml_declaration=True, encoding="UTF-8",
                              pretty_print=True).decode()
    except Exception:                                         # noqa: BLE001
        return raw.decode("utf-8", "replace")


_env = _environment()


def wants_html(request: Request) -> bool:
    """Is this a browser navigating, rather than a client calling an API?

    Read off ``Accept`` rather than off the path alone, so an API client that
    fetches a console URL still gets the JSON envelope it can parse, and a
    ``curl`` in a terminal is not handed a page of markup.
    """
    return "text/html" in request.headers.get("accept", "")


def render(request: Request, template: str, status_code: int = 200,
           **values: Any) -> HTMLResponse:
    """One page. The principal, the request id and the alerts are on every one.

    The alerts are computed here rather than in each view because the app bar is
    on every page and a bell that only counted on the pages somebody remembered
    to wire it into would be worse than no bell.
    """
    principal: Principal | None = getattr(request.state, "principal", None)
    alerts = notifications.alerts(request, principal)
    # On every page for the same reason the bell is: a warning about the one
    # unrecoverable thing in this system, shown only where somebody remembered
    # to wire it in, is a warning the person who inherited the deployment never
    # sees. It reads a key id and a timestamp, and no secret.
    recovery = getattr(request.app.state, "recovery", None)
    unacknowledged = bool(recovery is not None and not recovery.latest())
    # Whether local accounts are this deployment's business at all. Under an
    # identity provider they are the provider's, so the entry goes -- unless
    # some already exist, which means a deployment moved onto a provider and
    # has leftovers only this screen can clear.
    settings = getattr(request.app.state, "settings", None)
    store = getattr(request.app.state, "accounts", None)
    local_accounts = (settings is not None
                      and (settings.auth_mode is not AuthMode.oidc
                           or bool(store is not None and store.all())))
    locale, chosen = i18n.resolve(request)
    translator, formats = i18n.for_locale(locale)
    body = _env.get_template(template).render(
        request=request,
        principal=principal,
        may=may_for(principal),
        may_on=may_on_for(principal),
        request_id=context().get("request_id"),
        alerts=alerts,
        alert_total=notifications.total(alerts),
        alert_sections=notifications.by_section(alerts),
        t=translator,
        fmt=formats,
        locale=locale,
        language_name=i18n.NATIVE_NAMES[locale],
        language_links=i18n.switch_links(request),
        custody_unacknowledged=unacknowledged,
        # On every page, in the drawer, because "which version is
        # running" is asked at exactly the moment somebody cannot get
        # to a shell -- reading a bug report, or on the phone to a bank.
        version=getattr(settings, "version", None),
        git_sha=getattr(settings, "git_sha", None),
        local_accounts=local_accounts,
        **values,
    )
    response = HTMLResponse(body, status_code=status_code)
    # A page whose language was negotiated rather than chosen is a different
    # page for a different `Accept-Language`, and a shared cache in front of
    # this service has to be told so before it hands a German page to a Polish
    # operator. Nothing here is cacheable today; a `Vary` that is only correct
    # while nothing caches is a `Vary` somebody discovers is missing.
    response.headers["vary"] = "Accept-Language, Cookie"
    if chosen:
        # The explicit choice, remembered. Written on the response that carries
        # the page it chose, so the link *is* the whole mechanism: no route to
        # guard, no form to submit, and it works with scripting off.
        response.set_cookie(
            i18n.COOKIE, locale, max_age=i18n.COOKIE_MAX_AGE,
            httponly=True, samesite="lax", path="/")
    return response


def may_for(principal: Principal | None):
    """``may('payments:submit')`` for a template. Presentation, never the check."""
    def check(scope: str) -> bool:
        if principal is None:
            return False
        try:
            return principal.has(Scope(scope))
        except ValueError:  # pragma: no cover - a template naming no real scope
            return False
    return check


def may_on_for(principal: Principal | None):
    """``may_on('payments:submit', id)`` for a template. The narrower question.

    :func:`may_for` asks whether a caller holds a scope *anywhere*, which is the
    right question for a nav entry and the wrong one for a button on one bank's
    page: a member granted `payments:submit` at connection A would be shown the
    button on connection B, press it, and be refused by the route. Hiding is a
    courtesy rather than the control either way -- the route decides -- but a
    courtesy that points somebody at a refusal is not one.
    """
    def check(scope: str, connection_id: str | None) -> bool:
        if principal is None:
            return False
        try:
            return principal.may(Scope(scope), connection_id)
        except ValueError:  # pragma: no cover - a template naming no real scope
            return False
    return check


def principal_or_none(request: Request) -> Principal | None:
    try:
        return principal_of(request)
    except Exception:  # pragma: no cover - the middleware refuses first
        return None


__all__ = ["AUDIT_TARGETS", "STATIC", "STYLESHEET", "TEMPLATES",
           "THEME_SCRIPT", "audit_links", "may_for", "may_on_for",
           "principal_or_none",
           "render", "wants_html"]
