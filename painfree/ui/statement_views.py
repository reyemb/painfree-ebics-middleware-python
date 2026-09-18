"""The statements page: one account, read the way a bank statement is read.

What comes back from the download schedules is documents, and the table that
holds them is a table of documents. But nobody opens this page to look at a
document; they open it to look at an *account* -- what its balance is, what
came in, what went out, and the entries behind those figures. So the page is
the account first and the documents second: a bank and one of its accounts are
picked at the top, the console remembers the pair, and the end-of-day
statements of that account over a period are read as one ledger
(:func:`painfree.ui.ledger.overview`). The document list and the bank
responses are still here, one tab over, for the questions they answer.

**The choice is a cookie, the way the language is.** The pair the reader last
picked is written back on the response that carries the page they picked it
for, and every later visit opens on it, so the page an operator checks each
morning opens where they left it. A cookie names an account and holds nothing
about it; what it names is checked against the accounts the caller may see
before it is obeyed, so a remembered account whose grant has since been
withdrawn is simply not found.

**This is the one list that carries entries, and it is one account's.** The
index of documents shows none, deliberately; this page shows the entries of
the single account the reader chose, which is the same exposure as opening
each of its statements in turn and is exactly what it saves them doing.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

from fastapi import APIRouter, Depends, Request

from painfree import access, reconcile
from painfree.authn import requires
from painfree.identity import Principal, Scope
from painfree.statements import ACCOUNTS, INTRADAY, RESPONSES
from painfree.ui import ledger
from painfree.ui.rendering import render
from painfree.ui.views import PREFIX, _orders, _registry

router = APIRouter(prefix=PREFIX, tags=["console"], include_in_schema=False)

#: The three things the page can be about. The account is the default because
#: it is the question; the other two are the documents behind the answer.
ACCOUNT = "account"
DOCUMENTS = "documents"
VIEWS = (ACCOUNT, DOCUMENTS, RESPONSES)

#: The remembered account: ``<connection_id>|<iban>``. An IBAN has no ``|``,
#: so the split is from the right and a connection id may hold anything.
COOKIE = "pf_account"
COOKIE_MAX_AGE = 365 * 24 * 3600

#: How far back the overview reads, in days. Three fixed choices rather than
#: a date form: the page is a glance, and the documents tab is where a
#: particular day is found.
PERIODS = (30, 90, 365)
DEFAULT_PERIOD = 30


@router.get("/statements")
def statements(request: Request, connection_id: str = "", iban: str = "",
               family: str = ACCOUNT, message_type: str = "",
               period: str = "", show: str = "all",
               principal: Principal = Depends(requires(Scope.statements_read))):
    """The account overview, or one of the two document lists behind it."""
    store = request.app.state.statements
    family = family if family in VIEWS else ACCOUNT
    allowed, possible = access.restrict(principal, connection_id or None)
    common: dict[str, Any] = dict(
        family=family,
        connections=access.held(principal, _registry(request).all()),
        message_types=store.message_types(),
        status_codes=reconcile.STATUS_CODES,
        selected_connection=connection_id, selected_type=message_type,
        counts=store.counts_by_family(connection_ids=allowed,
                                      message_type=message_type or None)
        if possible else {ACCOUNTS: 0, RESPONSES: 0})

    if family == RESPONSES:
        rows = store.responses(connection_ids=allowed,
                               message_type=message_type or None,
                               limit=100) if possible else []
        return render(request, "statements.html", statements=rows, **common)
    if family == DOCUMENTS:
        rows = store.recent(connection_ids=allowed, family=ACCOUNTS,
                            message_type=message_type or None,
                            limit=100) if possible else []
        return render(request, "statements.html", statements=rows, **common)

    # The overview. The picker offers every account the caller may see, and
    # the requested connection narrows the *choice*, never the offer: a
    # connection the caller does not hold matches nothing and the page opens
    # on an account they do.
    visible, _ = access.restrict(principal)
    accounts = store.accounts(connection_ids=visible)
    chosen, source = _choose(accounts, connection_id, iban,
                             request.cookies.get(COOKIE))
    period_days = _period(period)
    since = _now() - _dt.timedelta(days=period_days)
    show = show if show in ledger.SHOWS else "all"

    rows: list[dict[str, Any]] = []
    reports: list[dict[str, Any]] = []
    orders: dict[str, str] = {}
    if chosen:
        rows = store.for_account(chosen["connection_id"], chosen["iban"],
                                 since=since)
        # An entry that settles a payment this service sent is linked to the
        # order, which is a payment fact and needs the payment scope.
        if principal.may(Scope.payments_read, chosen["connection_id"]):
            ids: set[str] = set()
            for row in rows:
                ids |= ledger.message_ids(row["payload"] or {})
            if ids:
                orders = _orders(request).by_message_ids(
                    chosen["connection_id"], ids)
        # What the bank has reported since the newest statement closed.
        reports = store.for_account(
            chosen["connection_id"], chosen["iban"], pattern=INTRADAY,
            since=(rows[0]["to_datetime"] or since) if rows else since)
    book = ledger.overview(rows, orders=orders, show=show, intraday=reports)

    response = render(
        request, "statements.html", accounts=accounts, chosen=chosen,
        source=source, overview=book, period=period_days, periods=PERIODS,
        show=show, since=since,
        # The accounts of the chosen bank, for the second select. The first
        # select changes the bank and lands on that bank's account; no script
        # is needed for the two to agree.
        bank_accounts=[account for account in accounts
                       if chosen and account["connection_id"]
                       == chosen["connection_id"]],
        **common)
    if chosen and source == "chosen":
        response.set_cookie(
            COOKIE, f"{chosen['connection_id']}|{chosen['iban']}",
            max_age=COOKIE_MAX_AGE, httponly=True, samesite="lax", path="/")
    return response


def _choose(accounts: list[dict[str, Any]], connection_id: str, iban: str,
            remembered: str | None) -> tuple[dict[str, Any] | None, str]:
    """Which account the page is about, and why.

    Returns the account and one of ``chosen`` (the request named it, or named
    a bank and this is that bank's account), ``remembered`` (the cookie did)
    or ``first`` (nobody did). Only a choice is written back as the cookie.
    """
    if not accounts:
        return None, "first"
    if connection_id:
        same = [account for account in accounts
                if account["connection_id"] == connection_id]
        if same:
            for account in same:
                if iban and account["iban"] == iban:
                    return account, "chosen"
            return _remembered(same, remembered) or same[0], "chosen"
    found = _remembered(accounts, remembered)
    if found:
        return found, "remembered"
    return accounts[0], "first"


def _remembered(accounts: list[dict[str, Any]],
                cookie: str | None) -> dict[str, Any] | None:
    if not cookie or "|" not in cookie:
        return None
    connection_id, _, iban = cookie.rpartition("|")
    for account in accounts:
        if account["connection_id"] == connection_id and account["iban"] == iban:
            return account
    return None


def _period(value: str) -> int:
    try:
        days = int(value)
    except (TypeError, ValueError):
        return DEFAULT_PERIOD
    return days if days in PERIODS else DEFAULT_PERIOD


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


__all__ = ["COOKIE", "PERIODS", "router"]
