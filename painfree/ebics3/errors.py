"""Exception hierarchy for the ebics3 engine.

The engine takes bytes and keys and returns bytes; it never knows about HTTP
status codes or database rows. Its errors are therefore about *material* and
*protocol*, and the service layer decides what they mean for a request.

Everything raised by this package derives from :class:`Ebics3Error`, so a caller
that only wants to know "the engine refused" can catch one class.
"""

from __future__ import annotations

__all__ = [
    "Ebics3Error",
    "UnsupportedVersionError",
    "KeyMaterialError",
    "CertificateError",
    "DocumentError",
    "RequestError",
    "TransactionError",
    "BankRefusedError",
    "BankKeyMismatchError",
]


class Ebics3Error(Exception):
    """Base class for every error the engine raises."""


class UnsupportedVersionError(Ebics3Error, ValueError):
    """An EBICS key or signature version this engine does not implement.

    Also a ``ValueError`` because "A007" in a config file is a bad value, and
    callers written against the standard library should be able to catch it.
    """


class KeyMaterialError(Ebics3Error):
    """Key material that cannot be loaded, or is not usable for EBICS.

    Never carries the offending material in its message: an exception string
    ends up in a log line, and key custody says logs record fingerprints, not
    keys.
    """


class CertificateError(Ebics3Error):
    """An X.509 certificate that cannot be parsed or does not match its key."""


class DocumentError(Ebics3Error):
    """An EBICS document that cannot be parsed, or lacks what the protocol needs.

    Raised where the engine is asked to sign or verify a document that is not
    shaped like an EBICS request -- no ``header``, no ``ds:SignedInfo``, a
    prefix that nothing declares. Distinct from a *failed* verification, which
    is a normal outcome and is reported, not raised.
    """


class RequestError(Ebics3Error, ValueError):
    """A request the engine refuses to build, because a bank would reject it.

    Raised for values the H005 schema constrains -- a four-character
    ``ServiceName``, a ``SecurityMedium`` that is not four digits, an
    encryption key handed in where a signature key belongs. Also a
    ``ValueError``, because from a caller's side these are bad arguments.

    Catching them here rather than at the bank is the point: a malformed
    request that is signed and sent comes back as a return code hours later,
    with no indication which of thirty fields was wrong.
    """


class TransactionError(Ebics3Error):
    """A three-phase transaction that cannot continue.

    Two quite different things end up here, and the message says which: the
    bank refused a step -- ``return_code`` and ``report_text`` carry its own
    words for it -- or the exchange stopped making sense, a response arriving
    in a phase the transaction is not in, a segment out of order, a download
    ending before its payload was complete.

    Not raised for a *retryable* condition. Recovery is a normal part of the
    protocol and is handled by the transaction, not reported as an error; what
    reaches a caller here has ended the transaction.
    """

    def __init__(self, message: str, *, return_code: str | None = None,
                 report_text: str | None = None) -> None:
        super().__init__(message)
        self.return_code = return_code
        self.report_text = report_text


class BankRefusedError(TransactionError):
    """The bank answered with a return code the engine classifies as a failure.

    Distinct from the other ``TransactionError`` cases, which are about an
    exchange that stopped making sense. Here the exchange was fine and the
    answer was no, so everything a caller needs to decide what to do next is on
    the exception rather than in its message: the six digits, the symbolic
    name, whether trying again could possibly help, and -- the field an
    operator reads first -- the bank's own ``ReportText``.

    Not raised for a code that is merely non-zero. ``011000`` ends a download,
    ``090005`` means there was nothing to download, ``061101`` offers to resume
    a transfer; none of them is a refusal, and treating them as one is the
    failure mode this class exists to keep narrow.
    """

    def __init__(self, message: str, *, return_code: str | None = None,
                 report_text: str | None = None, name: str | None = None,
                 retryable: bool = False, terminal: bool = True) -> None:
        super().__init__(message, return_code=return_code, report_text=report_text)
        self.name = name
        self.retryable = retryable
        self.terminal = terminal


class BankKeyMismatchError(Ebics3Error):
    """A key the bank sent over ``HPB`` does not match the bank's own letter.

    The one error in this hierarchy that is a *security* event rather than a
    protocol one. Nothing signs an ``HPB`` response -- the H005 key-management
    response schema has no ``AuthSignature`` at all -- so this comparison is the
    only thing standing between a substituted bank key and a client that
    encrypts every payment file it uploads to whoever substituted it.

    Both fingerprints travel on the exception. They are public values over
    public keys, and an operator staring at a mismatch needs to see which two
    strings failed to agree; withholding them here would only mean they get
    printed by hand in a worse place.
    """

    def __init__(self, message: str, *, role: str, expected: str, actual: str,
                 digest: str) -> None:
        super().__init__(f"{message} (expected {expected}, got {actual})")
        self.role = role
        self.expected = expected
        self.actual = actual
        self.digest = digest
