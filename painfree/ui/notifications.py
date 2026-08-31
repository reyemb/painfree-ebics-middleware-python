"""What the app bar's bell counts, and why each entry is a thing to act on.

Five conditions, one row each. They were not invented for the bell: each is a
state some page in this console already leads with, and the bell is the answer
to *which page should I be on*, asked from whichever page an operator happens to
have open.

===========================  ============================================
A parked webhook endpoint    delivery has stopped; events are piling up
A failing schedule           the bank was not reached; the window is stuck
A failed order               this service could not get a payment there
A connection not initialised registered, and it cannot submit anything yet
An unfinished key job         the worker has been asked for a key operation
===========================  ============================================

**Nothing decorative.** A bell that lights up for things that are fine is a
bell an operator learns to ignore, and the one word this console must keep
trustworthy is `failing`. So a download run that found nothing is not counted --
`EBICS_NO_DOWNLOAD_DATA_AVAILABLE` is the ordinary result of a scheduled
download -- and neither is a `rejected` order, which is the bank having
answered rather than this service having failed.

**Every count is the reader's own.** Each source is narrowed by
:func:`painfree.access.restrict` before it is counted, so a member is never told
about a connection they do not hold -- not even as a number, which would be a
disclosure that some other bank exists and is broken. Each is also gated on the
scope its destination page demands, because a badge that opens a `403` is worse
than no badge (and the same reasoning as the audit page's links).

**Nothing here is a sentence.** An alert carries a catalogue key and the values
that go in it, and the app bar asks the reader's own translator for the words.
Building `"3 webhook endpoints parked"` here would have made this module
English-only and would have got Polish wrong twice over -- once for the noun,
once because `3` and `5` take different forms of it.

**It never breaks a page.** The aggregation runs on every render, including the
error page. If a store cannot answer, the failure is logged with its trace and
the bell shows nothing: a console that will not render because its notification
count could not be computed is a worse console than one with no count.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from painfree import access
from painfree.identity import Principal, Scope
from painfree.logging import get_logger

log = get_logger("painfree.ui.notifications")

#: How many rows a source is asked for before the count is reported as "+".
#: A number is only useful if it is true; past this many of anything the exact
#: figure has stopped being the point and the page behind it is.
CAP = 100


@dataclass(frozen=True, slots=True)
class Alert:
    """One condition, the page that fixes it, and what to call it.

    The words are not here. ``title_key`` and ``why_key`` are catalogue keys and
    ``values`` is what fills their placeholders, so the same alert reads as
    `3 Webhook-Endpunkte pausiert` or `3 punkty webhook wstrzymane` without this
    module knowing either language exists.
    """

    key: str
    """Stable name. What the tests assert on, never shown."""

    count: int
    capped: bool
    title_key: str
    why_key: str
    href: str
    tone: str
    """``bad`` -- something has stopped. ``warn`` -- something is waiting."""

    values: Mapping[str, Any] = field(default_factory=dict)
    """What the two keys' placeholders are filled with, ``count`` included."""

    @property
    def label(self) -> str:
        return f"{self.count}+" if self.capped else str(self.count)


def alerts(request: Any, principal: Principal | None) -> tuple[Alert, ...]:
    """Everything this caller should be told about, most urgent first."""
    if principal is None:
        return ()
    try:
        return tuple(_gather(request, principal))
    except Exception:  # pragma: no cover - a store that cannot answer
        log.exception("ui.notifications_failed", subject=principal.subject)
        return ()


def total(found: tuple[Alert, ...]) -> int:
    return sum(alert.count for alert in found)


def by_section(found: tuple[Alert, ...]) -> dict[str, int]:
    """The same counts keyed by the drawer entry that leads to them.

    The section is the first two path segments of the alert's destination, so
    ``/ui/connections/{id}/keys`` counts against **Connections** in the drawer
    rather than becoming an entry of its own. The drawer names sections; an
    alert names the page inside one that fixes it.
    """
    counts: dict[str, int] = {}
    for alert in found:
        section = "/".join(alert.href.split("?")[0].split("/")[:3])
        counts[section] = counts.get(section, 0) + alert.count
    return counts


def _gather(request: Any, principal: Principal):
    state = request.app.state
    allowed, possible = access.restrict(principal)

    if principal.has(Scope.webhooks_read) and possible:
        rows = [row for row in state.webhooks.all(connection_ids=allowed)
                if row.parked]
        if rows:
            yield Alert(
                key="webhooks_parked", count=len(rows), capped=False,
                title_key="alerts.webhooks_parked.title",
                why_key="alerts.webhooks_parked.why",
                values={"count": len(rows)},
                href="/ui/webhooks", tone="bad")

    if principal.has(Scope.schedules_read) and possible:
        rows = [row for row in state.schedules.all(connection_ids=allowed)
                if row.health == "failing"]
        if rows:
            yield Alert(
                key="schedules_failing", count=len(rows), capped=False,
                title_key="alerts.schedules_failing.title",
                why_key="alerts.schedules_failing.why",
                values={"count": len(rows)},
                href="/ui/schedules", tone="bad")

    if principal.has(Scope.payments_read) and possible:
        rows = state.orders.recent(connection_ids=allowed, state="failed",
                                   limit=CAP)
        if rows:
            count = len(rows)
            yield Alert(
                key="orders_failed", count=count, capped=count >= CAP,
                title_key="alerts.orders_failed.title",
                why_key="alerts.orders_failed.why",
                values={"count": count,
                        "shown": f"{count}+" if count >= CAP else str(count)},
                href="/ui/orders?state=failed", tone="bad")

    if principal.has(Scope.connections_read) and possible:
        rows = state.connections.all(allowed)
        waiting = [row for row in rows if not row.initialised]
        if waiting:
            yield Alert(
                key="connections_uninitialised", count=len(waiting),
                capped=False,
                title_key="alerts.connections_uninitialised.title",
                why_key="alerts.connections_uninitialised.why",
                values={"count": len(waiting)},
                href="/ui/connections", tone="warn")

        # One query per connection, the same way the connections page already
        # asks. A deployment has a handful of banks, and a store method for the
        # bell alone would be a second definition of "outstanding".
        jobs = [(row.connection_id, state.key_jobs.outstanding(row.connection_id))
                for row in rows]
        pending = [(connection_id, job) for connection_id, job in jobs if job]
        if pending:
            first = pending[0]
            yield Alert(
                key="key_jobs_unfinished", count=len(pending), capped=False,
                title_key="alerts.key_jobs_unfinished.title",
                # Two sentences, because naming the job is only useful when
                # there is one of it. The `action` and the connection id in it
                # are an audit value and an identifier: neither is translated.
                why_key=("alerts.key_jobs_unfinished.why_one"
                         if len(pending) == 1
                         else "alerts.key_jobs_unfinished.why_many"),
                values={"count": len(pending), "action": first[1].action.value,
                        "connection": first[0]},
                href=f"/ui/connections/{first[0]}/keys", tone="warn")


__all__ = ["Alert", "CAP", "alerts", "by_section", "total"]
