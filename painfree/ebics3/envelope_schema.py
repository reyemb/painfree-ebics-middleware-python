"""The H005 schemas, applied to a request this service built.

**Why this exists.** A bank that refuses an upload answers with a return code
and a sentence of its own. `091113 EBICS_INVALID_REQUEST_CONTENT` --
*"Nachrichteninhalt semantisch nicht EBICS-konform"* -- names no element, so an
operator holding it has no next step inside the product: the refused request is
gone the moment the exchange ends, and the only party who can still see it is
the bank. Diagnosing one has meant reading the source and telephoning.

So the request is kept when it is refused, and checked against the official
schemas here. That answers one of the two questions locally:

* **is the document well-formed EBICS?** -- answerable, and answered here;
* **will this bank accept it?** -- not answerable by any schema, ever.

The second is why a clean result is reported as *the schema found nothing*
rather than as *this request was fine*. A refusal with no schema failure is a
real and useful finding -- it says the disagreement is semantic and points the
conversation with the bank at content rather than at shape -- but it is not the
service being exonerated.

The schemas are vendored (see ``painfree/schemas/H005/README.md``) for the same
reason the `pain.001` one is: this runs in a container, and a validator that
reads a directory next to the repository is a validator that is silently
absent.
"""

from __future__ import annotations

import functools
import pathlib

from lxml import etree

__all__ = ["SCHEMA_DIR", "UMBRELLA", "schema", "schema_failures"]

SCHEMA_DIR = pathlib.Path(__file__).parent.parent / "schemas" / "H005"

#: The one that includes the other four. Compiling it compiles the set.
UMBRELLA = SCHEMA_DIR / "ebics_H005.xsd"


@functools.lru_cache(maxsize=1)
def schema() -> etree.XMLSchema:
    """The compiled H005 schema set, built once.

    Cached because compiling nine files takes long enough to notice and the
    result is immutable -- and because the worker validates on a path that is
    already the unhappy one, where an operator is waiting for an answer.
    """
    return etree.XMLSchema(etree.parse(str(UMBRELLA)))


def schema_failures(document: bytes) -> list[str]:
    """Every way this request fails the official H005 schemas.

    Plain strings rather than :class:`~painfree.sps.RuleFailure`: those name a
    rule this service defined and can explain, and these are the schema's own
    words about a document. Dressing a libxml2 message as a painfree rule would
    claim an understanding this does not have.

    A document that will not parse at all is one failure, not an exception. The
    caller is holding bytes a bank refused, on the path where something has
    already gone wrong, and raising there would lose the very thing being
    diagnosed.
    """
    try:
        parsed = etree.fromstring(document)
    except etree.XMLSyntaxError as exc:
        return [f"not well-formed XML: {exc}"]
    validator = schema()
    if validator.validate(parsed):
        return []
    return [f"line {error.line}: {error.message}"
            for error in validator.error_log]
