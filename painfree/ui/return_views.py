"""Deciding a suspected return: the money came back, or it did not.

A suspected return is raised by a rule that cannot prove what it found, so a
person decides it from the order's page. Confirming writes `returned` with
``matched_by: operator`` and sends ``order.returned``; dismissing closes the
suspicion and sends ``order.return_dismissed``. Both are audited with who
decided.

`orders:replay` is the scope, because it is the operator's other decision about
an order whose payment did not go as planned, granted per connection.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from painfree import access
from painfree.authn import requires
from painfree.errors import NotFoundError
from painfree.identity import Principal, Scope
from painfree.ui.views import PREFIX, _orders, _see

router = APIRouter(prefix=PREFIX, tags=["console"], include_in_schema=False)


@router.post("/orders/{order_id}/return/{decision}")
def decide(request: Request, order_id: str, decision: str,
           principal: Principal = Depends(requires(Scope.orders_replay))):
    order = _orders(request).get(order_id)
    access.require(principal, order.connection_id, Scope.orders_replay,
                   what="order")
    returns = request.app.state.statements.returns
    if decision == "confirm":
        returns.confirm(order_id, actor=principal.actor())
    elif decision == "dismiss":
        returns.dismiss(order_id, actor=principal.actor())
    else:
        raise NotFoundError(f"no such decision: {decision!r}")
    return _see(f"{PREFIX}/orders/{order_id}")


__all__ = ["router"]
