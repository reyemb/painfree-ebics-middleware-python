"""The one place EBICS meets HTTP, and the two ways it lied about a bank.

Both were found by standing a deployment up against a real bank, and neither
could have been found any other way -- which is why they are pinned here with a
real socket rather than a mock.

**The header nobody chose.** `urllib` supplies ``User-Agent: Python-urllib/3.x``
unless it is told not to, and St.Galler Kantonalbank's web application firewall
blocks that string: HTTP 400 and a German HTML page, before the EBICS connector
sees the request. The same endpoint answers a request carrying no ``User-Agent``
normally. So the default is to send none.

**The error that pointed at the wrong thing.** That HTML page was handed to the
XML parser, so what an operator saw was `Opening and ending tag mismatch: link
line 9 and head` -- a malformed *document*, when the cause was an HTTP *header*
and the document was never the bank's. Nothing in that message could lead
anybody to a firewall. A body that is not a document is now refused where it
arrives, and the refusal quotes it.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from painfree.transport import BankTransport, TransportError

EBICS = b'<?xml version="1.0" encoding="UTF-8"?><ebicsKeyManagementResponse/>'

#: What the firewall actually answers, in the shape it answers it.
FIREWALL_PAGE = (b'<!DOCTYPE html>\n<html lang="de">\n<head>\n'
                 b'<link rel="stylesheet" href="/style.css">\n'
                 b'<title>Die Anfrage ist leider ung\xc3\xbcltig</title>\n</head>\n'
                 b'<body>St.Galler Kantonalbank AG</body></html>')


class _Bank:
    """A socket that records what arrived and answers what it was told to."""

    def __init__(self, status: int, body: bytes, content_type: str) -> None:
        self.requests: list[dict[str, str]] = []
        bank = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                bank.requests.append(dict(self.headers))
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *arguments: object) -> None:
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_port}/ebicsweb"

    def __enter__(self) -> "_Bank":
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()


# --- the header ---------------------------------------------------------------

def test_no_user_agent_is_sent_by_default():
    """The header that got a deployment refused is not sent at all.

    Asserted against a real socket, because what is under test is what `urllib`
    adds on its own: a unit test of this module's own dictionary would pass
    while the library put the string back.
    """
    with _Bank(200, EBICS, "text/xml") as bank:
        BankTransport(bank.url).post(b"<x/>")

    assert "User-Agent" not in bank.requests[0]


def test_a_configured_user_agent_is_sent():
    """For the bank that wants one. Nothing else changes."""
    with _Bank(200, EBICS, "text/xml") as bank:
        BankTransport(bank.url, user_agent="painfree").post(b"<x/>")

    assert bank.requests[0]["User-Agent"] == "painfree"


def test_an_empty_user_agent_sends_no_header():
    """Unset and empty mean the same thing, so `.env` cannot half-set it."""
    with _Bank(200, EBICS, "text/xml") as bank:
        BankTransport(bank.url, user_agent="").post(b"<x/>")

    assert "User-Agent" not in bank.requests[0]


# --- the body -----------------------------------------------------------------

def test_a_firewall_page_is_refused_where_it_arrives():
    """Not passed on to be parsed as EBICS, which is what made it unfindable."""
    with _Bank(400, FIREWALL_PAGE, "text/html; charset=utf-8") as bank:
        with pytest.raises(TransportError) as refused:
            BankTransport(bank.url).post(b"<x/>")

    message = str(refused.value)
    # The three things that turn this into a five-minute diagnosis: what the
    # status was, what came back instead of a document, and who said so.
    assert "400" in message
    assert "text/html" in message
    assert "Die Anfrage ist leider ung" in message
    assert refused.value.sent is True


def test_the_refusal_says_something_answered_instead_of_the_bank():
    """The sentence has to point at the middlebox, not at the document."""
    with _Bank(400, FIREWALL_PAGE, "text/html") as bank:
        with pytest.raises(TransportError) as refused:
            BankTransport(bank.url).post(b"<x/>")

    assert "in front of it" in str(refused.value)


def test_a_bank_error_document_still_comes_back():
    """The reason this is a sniff and not a status check.

    Some banks answer a well-formed EBICS error with a 500, and the return code
    inside it is the whole point. That must keep working.
    """
    with _Bank(500, EBICS, "text/xml") as bank:
        assert BankTransport(bank.url).post(b"<x/>") == EBICS


def test_a_document_behind_a_byte_order_mark_is_accepted():
    """A BOM is legal in front of an XML declaration; refusing one is a bug."""
    with _Bank(200, b"\xef\xbb\xbf" + EBICS, "text/xml") as bank:
        assert BankTransport(bank.url).post(b"<x/>").endswith(EBICS)
