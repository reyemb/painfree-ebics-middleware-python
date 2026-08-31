"""Service errors and the one JSON shape they are rendered in.

Every failure a caller sees is the same envelope, so a client writes one error
path instead of one per endpoint::

    {"error": {"code": "not_ready", "message": "…", "request_id": "…",
               "detail": {…}}}

``request_id`` is in the body as well as the ``X-Request-ID`` header, because
the id is only useful if the person reading a screenshot of a failed response
can quote it.

``detail`` is where the EBICS return code and report text will be surfaced
verbatim once there is an order to fail. It is not populated here, and no
endpoint invents one.

Two rules the handlers in :mod:`painfree.app` enforce:

* An expected failure is a :class:`ServiceError`, converted deliberately to its
  status. It is logged at ``warning`` with its code -- it is not a defect.
* An unexpected exception is logged at ``error`` with a stack trace and becomes
  a bare ``internal_error``. The trace goes to the operator; the caller gets a
  request id to quote and nothing about our internals.
"""

from __future__ import annotations

from typing import Any


class ServiceError(Exception):
    """A failure this service knows how to name."""

    status_code = 500
    code = "internal_error"

    #: Headers the response must carry. A `401` is meaningless to a client
    #: without `WWW-Authenticate`, and the handler cannot invent it.
    headers: dict[str, str] | None = None

    def __init__(self, message: str, *, detail: dict[str, Any] | None = None,
                 headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail or {}
        if headers is not None:
            self.headers = headers


class NotFoundError(ServiceError):
    status_code = 404
    code = "not_found"


class ConflictError(ServiceError):
    """The request is well-formed but contradicts state that already exists.

    The idempotency rule -- a repeated key with a changed payload -- becomes
    this.
    """

    status_code = 409
    code = "conflict"


class UnauthenticatedError(ServiceError):
    """The caller did not prove who they are, or the proof did not hold.

    Deliberately one code for every cause. Which half of a forged token was
    wrong is diagnostic information for the operator -- it is in the log line,
    with a `reason` -- and a hint to the forger.
    """

    status_code = 401
    code = "unauthenticated"
    headers = {"WWW-Authenticate": 'Bearer realm="painfree"'}


class ForbiddenError(ServiceError):
    """The caller is known, and is not allowed to do this.

    Distinct from `401` on purpose: retrying with a different token may fix a
    `401` and will not fix this. The missing scope **is** named -- unlike an
    authentication failure, there is no forger to help here, and a client that
    cannot see which privilege it lacks cannot ask for it.
    """

    status_code = 403
    code = "forbidden"


class NotReadyError(ServiceError):
    """A dependency the request needs is not available."""

    status_code = 503
    code = "not_ready"


def error_body(
    code: str, message: str, *, request_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The envelope, built in one place so every handler agrees on it."""
    error: dict[str, Any] = {"code": code, "message": message}
    if request_id:
        error["request_id"] = request_id
    if detail:
        error["detail"] = detail
    return {"error": error}


__all__ = ["ConflictError", "ForbiddenError", "NotFoundError", "NotReadyError",
           "ServiceError", "UnauthenticatedError", "error_body"]
