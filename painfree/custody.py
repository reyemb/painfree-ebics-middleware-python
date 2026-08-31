"""The custody boundary: where a private key may be opened, and where it may not.

Private keys are decrypted only inside the worker and are never reachable from
the request-handling path. That is a property, and a property that is only a
convention is one an ordinary refactor removes. This module is where it is
enforced.

Three mechanisms, each closing a different way of getting it wrong:

1. **Two surfaces over the same tables.** The request path is handed a
   :class:`painfree.keyring.Keyring`, which has no method that returns private
   material -- not a locked one, not a checked one: none. Opening a key lives on
   :class:`painfree.keyring.KeyCustodian`, a different class in the same module,
   and reading them side by side is the whole review.

2. **The custody key is passed, never fetched.** A ``KeyCustodian`` cannot be
   built without a :class:`painfree.sealing.CustodyKey`, there is no module-level
   one to reach for, and :func:`painfree.app.create_app` builds neither. The
   application stores its settings with the encryption secret stripped
   (:meth:`painfree.config.Settings.without_custody_secret`), so the object
   graph a handler can reach through ``request.app.state`` does not contain the
   secret at all.

3. **Opening is refused inside a request.** :func:`request_path` is entered by
   the correlation middleware for the duration of every HTTP request, and
   :func:`assert_outside_request_path` -- called when a custodian is built and
   again at the single point where a seal is opened -- raises
   :class:`CustodyViolation` if it is set. Context variables follow into the
   thread pool a synchronous route runs in, so a handler cannot escape it by
   being synchronous, and a background task started from a handler cannot
   escape it by being a task.

The third is the one that makes the boundary hold *today*, while the API and
the worker are still one process: even code that assembled a custodian by hand
inside a handler cannot use it. What it does not defend against is a handler
that deliberately reads ``os.environ`` and rebuilds the key from there -- an
in-process boundary cannot, and this is stated rather than papered over.
Running the worker as its own process moves it out of the API process, and then
the secret is absent from the API's environment as well; the checks here stay,
because they are what makes the property visible in review.

A violation is a defect, not an expected failure, so :class:`CustodyViolation`
is deliberately **not** a :class:`~painfree.errors.ServiceError`: it falls to
the application's catch-all, which logs it at ``error`` with a stack trace and
returns an opaque ``internal_error``. The caller learns nothing; the operator
gets the trace and the reason.
"""

from __future__ import annotations

import contextlib
import contextvars
from typing import Iterator

from painfree.logging import get_logger

log = get_logger("painfree.custody")

_in_request: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "painfree_request_path", default=False
)


class CustodyViolation(Exception):
    """Something tried to reach private key material from the request path."""


@contextlib.contextmanager
def request_path() -> Iterator[None]:
    """Mark the enclosed work as request handling. Entered by the middleware."""
    token = _in_request.set(True)
    try:
        yield
    finally:
        _in_request.reset(token)


@contextlib.contextmanager
def worker_context() -> Iterator[None]:
    """Mark the enclosed work as worker work.

    The complement of :func:`request_path`, and the seam the worker needs: a
    job runner that picked its work up from the queue enters this, and the
    custodian's checks pass. It exists as a named entry point rather than as
    "the absence of a request" so a reader of the worker can see the boundary
    being crossed deliberately.

    It does **not** clear an enclosing request context. Wrapping a handler's
    body in it would be exactly the mistake this module exists to catch.
    """
    if _in_request.get():
        raise CustodyViolation(
            "a worker context cannot be opened inside a request; the request "
            "path may not borrow the worker's custody of private keys"
        )
    yield


def in_request_path() -> bool:
    """Whether the current context is handling an HTTP request."""
    return _in_request.get()


def assert_outside_request_path(what: str) -> None:
    """Refuse ``what`` if it is happening inside a request. Logged, then raised."""
    if not _in_request.get():
        return
    # Logged where it is detected, with the operation named, because the
    # traceback alone does not say which key operation was attempted.
    log.error("custody.violation", operation=what,
              reason="private key material is not reachable from the request path")
    raise CustodyViolation(
        f"{what} is not permitted on the request-handling path; private keys "
        f"are opened only in the worker"
    )


__all__ = [
    "CustodyViolation",
    "assert_outside_request_path",
    "in_request_path",
    "request_path",
    "worker_context",
]
