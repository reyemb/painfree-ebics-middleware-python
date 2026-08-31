"""The HTTP transport to a bank. The one thing in this service that opens a socket.

The engine is deliberately transport-agnostic: it produces request documents
and consumes response documents, and knows nothing about sockets, status codes
or timeouts. That leaves exactly one place where EBICS meets HTTP, and this is
it.

**Why there is no retry inside an exchange.** The obvious thing to write here is
"three attempts with backoff", and on an upload it is the wrong thing. An EBICS
upload's *initialisation* request is what makes the bank open a transaction; a
POST that was received but whose response was lost, retried, opens a second
transaction for the same payment. So a failed exchange fails the whole attempt
and the order goes back to the queue, where the retry is a fresh transaction
carrying the **same** ``MsgId`` -- which the bank deduplicates. Backoff belongs
to the order, not to the socket; see :mod:`painfree.queue`.

What is worth distinguishing is whether the request ever reached the bank, and
:attr:`TransportError.sent` carries that: a connection that was refused or never
established is a request the bank certainly did not see, while a timeout after
the body went out is a request it may have. The first is safe to repeat with no
further argument; the second is safe only because of the ``MsgId``. Both are
retried, and the log line says which happened, because that is the difference an
operator wants when a payment appears twice.

Nothing here logs a payload. The body is EBICS-encrypted order data, and the
only fields worth a log line are the URL, the byte count and the outcome.
"""

from __future__ import annotations

import socket
import urllib.error
import urllib.request
from dataclasses import dataclass

from painfree.logging import get_logger

log = get_logger("painfree.transport")

#: What a bank's endpoint is asked to accept, and what every EBICS server sends.
CONTENT_TYPE = "text/xml; charset=utf-8"

#: Generous, because a bank taking twenty seconds over a segment is normal and
#: a client that gives up early turns a slow upload into a retried one.
DEFAULT_TIMEOUT = 60.0

#: A response larger than this is not an EBICS response. The cap exists so a
#: misconfigured `HostURL` pointing at something else cannot exhaust memory.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024


class TransportError(Exception):
    """One HTTP exchange with the bank did not produce a response document.

    ``sent`` is the field that matters: ``False`` means the request provably
    never reached the bank, ``True`` means it may have. Callers do not branch
    on it -- both are retried -- but it is logged, because it is the difference
    between "nothing happened" and "we do not know".
    """

    def __init__(self, message: str, *, sent: bool, status: int | None = None) -> None:
        super().__init__(message)
        self.sent = sent
        self.status = status


@dataclass(frozen=True, slots=True)
class BankTransport:
    """POST a request document to one bank's ``HostURL`` and return its answer."""

    url: str
    timeout: float = DEFAULT_TIMEOUT

    def post(self, document: bytes) -> bytes:
        """One exchange. Raises :class:`TransportError`; never retries."""
        request = urllib.request.Request(
            self.url, data=document,
            headers={"Content-Type": CONTENT_TYPE,
                     "Content-Length": str(len(document))},
            method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
                status = response.status
        except urllib.error.HTTPError as exc:
            # An HTTP error status is still an answer, and some banks return a
            # well-formed EBICS error document with a 500. The body is read
            # rather than discarded so the return code inside it survives.
            body = exc.read(MAX_RESPONSE_BYTES + 1)
            if not body:
                raise TransportError(f"the bank answered HTTP {exc.code} with no body",
                                     sent=True, status=exc.code) from exc
            log.warning("ebics.http_error_with_body", url=self.url,
                        status=exc.code, bytes=len(body))
            return body
        except urllib.error.URLError as exc:
            # `URLError` with an underlying OS error is a connection that was
            # never established: refused, unresolvable, unreachable. The
            # request did not reach the bank.
            sent = not isinstance(exc.reason, (OSError, socket.gaierror))
            raise TransportError(f"the bank at {self.url} could not be reached: "
                                 f"{exc.reason}", sent=sent) from exc
        except (TimeoutError, socket.timeout) as exc:
            raise TransportError(
                f"the bank at {self.url} did not answer within "
                f"{self.timeout:g}s", sent=True) from exc
        except OSError as exc:
            # A connection dropped mid-exchange. The body may have gone out.
            raise TransportError(f"the exchange with {self.url} failed: {exc}",
                                 sent=True) from exc

        if len(body) > MAX_RESPONSE_BYTES:
            raise TransportError(
                f"the bank at {self.url} answered with more than "
                f"{MAX_RESPONSE_BYTES} bytes", sent=True, status=status)
        if not body:
            raise TransportError(f"the bank answered HTTP {status} with no body",
                                 sent=True, status=status)
        return body


__all__ = ["CONTENT_TYPE", "DEFAULT_TIMEOUT", "MAX_RESPONSE_BYTES",
           "BankTransport", "TransportError"]
