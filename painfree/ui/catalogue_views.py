"""What the bank publishes, on a page, beside what this connection is configured to send.

The one screen this feature exists for. A bank's EBICS parameter sheet is a PDF
that somebody transcribes into a connection's scheme configuration and then
nobody looks at again; ``HTD`` is the same table, from the bank, on demand. Put
the two side by side and "will this payment be accepted" stops being a question
answered by sending one.

**The comparison is shown, never applied.** A bank publishing an upload this
connection is not configured for does not reconfigure anything, and a
configured scheme the bank does not publish is not disabled. Both are drawn for
a person to act on, because the bank's catalogue is evidence about what will be
accepted rather than an instruction about what to send -- and a console that
edited a payment path on the strength of a document it fetched would be doing
the one thing nobody asked it to.

**Nothing here fetches.** The response arrives encrypted to this connection's
own ``E002`` half, which the API process cannot open, so the button appends a
key job and the worker does the round trip -- exactly as ``HPB`` does. This
module reads rows.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from painfree import ebics3
from painfree.catalogue import Catalogue
from painfree.identity import Principal, Scope
from painfree.logging import bind
from painfree.authn import requires_on
from painfree.ui.rendering import render
from painfree.ui.views import PREFIX, _registry

router = APIRouter(prefix=PREFIX, tags=["console"], include_in_schema=False)

#: The order the three are read in, which is the order they are useful in:
#: the catalogue first, then what is waiting, then the bank's own limits.
ORDER_TYPES = ("HTD", "HAA", "HPD")


def _catalogue(request: Request) -> Catalogue:
    return request.app.state.catalogue


def _services(connection) -> list[tuple[str, ebics3.Service]]:
    """This connection's upload services, one per scheme it can actually send.

    An unconfigured instant is left out rather than drawn as *not published*:
    the bank not publishing it and this connection not having it are different
    facts, and only the second one is true here.
    """
    profiles = [("normal", connection.schemes.normal)]
    if connection.schemes.instant_configured:
        profiles.append(("instant", connection.schemes.instant))
    return [
        (name, ebics3.Service(name=profile.service_name, msg_name="pain.001",
                              scope=profile.scope,
                              option=profile.service_option))
        for name, profile in profiles
    ]


@router.get("/connections/{connection_id}/catalogue")
def catalogue(request: Request, connection_id: str,
              principal: Principal = Depends(
                  requires_on(Scope.connections_read))):
    """What the bank last said, and how this connection's schemes compare.

    Readable with `connections:read` alone: it is the bank's published
    catalogue, which is not privileged information, and the person most likely
    to need it during an onboarding is not necessarily the one who may edit the
    connection.
    """
    with bind(connection_id=connection_id):
        row = _registry(request).get(connection_id)
        store = _catalogue(request)
        stored = store.all(connection_id)
        # `offers` is the one implementation of the match, and it answers
        # `None` when no HTD has been fetched -- which the page has to draw
        # differently from a `False`, because "not asked" and "the bank said
        # no" are not the same thing to somebody about to send a payment.
        comparison = [{"scheme": name, "service": service,
                       "published": store.offers(connection_id, service)}
                      for name, service in _services(row)]
        return render(request, "catalogue.html", connection=row,
                      stored=stored, order_types=ORDER_TYPES,
                      comparison=comparison,
                      descriptions=ebics3.ADMIN_DOWNLOADS)


__all__ = ["ORDER_TYPES", "router"]
