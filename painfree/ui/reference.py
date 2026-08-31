"""What the machine-facing side of this service looks like, read off the service.

The developer page has to answer three questions, and every one of them has a
wrong way to answer it that works on the day it is written:

**Which privileges exist, and who holds them?** From
:data:`painfree.identity.ROLE_SCOPES` and
:data:`painfree.identity.LEVEL_SCOPES`, never from a table in a template. When
the roles were collapsed to two, with everything else becoming a per-connection
grant, nothing here was edited to follow except to add the level column,
because the tables were never written down in the first place.

**What does each privilege mean?** From the docstrings already written under
each member of :class:`painfree.identity.Scope`. Python discards those --
a string after an enum member is an expression statement, not
``__doc__`` -- so they are read back out of the source with :mod:`ast`. That
is a real cost, and it buys the property that the explanation an operator
reads is the explanation the next engineer edits. The alternative is a second
copy of every sentence, and a second copy is the one that goes stale.

**Which privilege does this route need?** Off the application object.
:func:`painfree.authn.requires` records what it demands on the dependency it
returns, so :func:`protected_routes` reads the answer out of the running
router rather than restating it. A route added without a scope shows up here as
one, which is the deny-by-default rule made visible rather than trusted.

Nothing here is a check. Every one of these facts is enforced by
:mod:`painfree.authn` on the request; this module only explains it.
"""

from __future__ import annotations

import ast
import functools
import inspect
from typing import Any

from fastapi import FastAPI
from fastapi.routing import APIRoute

from painfree import identity
from painfree.identity import (LEVEL_SCOPES, OVERSIGHT_SCOPES, ROLE_SCOPES,
                               Level, Principal, Role, Scope)

#: Paths that document the API rather than being part of it. They exist because
#: FastAPI mounts them; nothing in this repository routes them, so they are
#: named here rather than discovered.
OPENAPI_DOCUMENTS = (
    ("/docs", "Swagger UI", "Every endpoint, with a form that calls it."),
    ("/redoc", "ReDoc", "The same endpoints, laid out for reading."),
    ("/openapi.json", "OpenAPI 3.1 document",
     "The machine-readable schema. Point a client generator at this."),
)


@functools.cache
def scope_descriptions() -> dict[str, str]:
    """The sentence under each ``Scope`` member, recovered from the source.

    Falls back to an empty mapping when the source is not available -- a
    zipped distribution, a frozen build. The page then shows the scope names
    without their prose, which is degraded rather than wrong.
    """
    try:
        tree = ast.parse(inspect.getsource(identity))
    except (OSError, TypeError, SyntaxError):  # pragma: no cover - no source
        return {}
    described: dict[str, str] = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.ClassDef) and node.name == "Scope"):
            continue
        pending: str | None = None
        for statement in node.body:
            if (isinstance(statement, ast.Assign)
                    and isinstance(statement.targets[0], ast.Name)
                    and isinstance(statement.value, ast.Constant)):
                pending = statement.value.value
                continue
            if (pending and isinstance(statement, ast.Expr)
                    and isinstance(statement.value, ast.Constant)
                    and isinstance(statement.value.value, str)):
                described[pending] = inspect.cleandoc(statement.value.value)
            pending = None
    return described


def scope_catalogue(principal: Principal | None = None) -> list[dict[str, Any]]:
    """Every scope, what it is for, who holds it, and whether *you* do.

    ``levels`` is the column that matters: a scope carried by a level is
    carried **on the connection the grant names**, which is not the same claim
    as holding it. ``oversight`` is the other column, and it reads the other
    way: carried on *every* connection at once, and on the rows that name none.
    A scope in neither column is `admin` only, and that row is the one worth
    being able to read at a glance -- it is the set of things a member cannot
    be given by any grant this deployment has.
    """
    described = scope_descriptions()
    held = principal.scopes if principal else frozenset()
    catalogue = []
    for scope in Scope:
        text = described.get(scope.value, "")
        levels = [level.value for level in Level if scope in LEVEL_SCOPES[level]]
        oversight = scope in OVERSIGHT_SCOPES
        catalogue.append({
            "scope": scope.value,
            "summary": text.split("\n\n")[0] if text else "",
            "detail": "\n\n".join(text.split("\n\n")[1:]) if text else "",
            "roles": [role.value for role in Role if scope in ROLE_SCOPES[role]],
            "levels": levels,
            # Carried by the deployment-wide oversight grant, on every
            # connection at once. Read off
            # :data:`painfree.identity.OVERSIGHT_SCOPES`, which is itself
            # derived from the scope's name, so this column cannot disagree
            # with what the server does.
            "oversight": oversight,
            "admin_only": not levels and not oversight,
            "held": scope in held,
        })
    return catalogue


def role_catalogue() -> list[dict[str, Any]]:
    """Each role and the scopes it grants globally, as the model declares them."""
    return [{"role": role.value,
             "scopes": sorted(scope.value for scope in ROLE_SCOPES[role])}
            for role in Role]


def level_catalogue() -> list[dict[str, Any]]:
    """Each grant level and what it carries on the connection it names."""
    return [{"level": level.value,
             "scopes": sorted(scope.value for scope in LEVEL_SCOPES[level])}
            for level in Level]


def oversight_catalogue() -> list[str]:
    """What deployment-wide oversight carries, as the model derives it.

    A list rather than a table because it has no dimension to tabulate: one
    grant, no level, no connection. It is here so the page can state the set
    positively -- "these, everywhere" -- beside the per-level table that states
    it per connection.
    """
    return sorted(scope.value for scope in OVERSIGHT_SCOPES)


def protected_routes(app: FastAPI,
                     public: frozenset[str] = frozenset()) -> list[dict[str, Any]]:
    """Every documented route with the scopes its dependency demands.

    The console's own routes are excluded: they are pages, they are not part of
    the contract, and ``include_in_schema=False`` already says so.

    ``public`` is :data:`painfree.authn.PUBLIC_PATHS`. A route in it demands no
    scope *and* no credential, and the difference matters on the page: reading
    "any authenticated caller" beside `/auth/login` would be a false statement
    about the one endpoint whose whole purpose is to be reachable before there
    is an identity.

    A route can also demand a **role** rather than a scope, which is what grant
    management does. That is reported too, for the same reason: the first
    rendering of this page listed those routes as reachable by any
    authenticated caller, which was false about the five endpoints that decide
    who may move money.
    """
    rows = []
    for route in _all_routes(app):
        if not isinstance(route, APIRoute) or not route.include_in_schema:
            continue
        scopes = sorted({scope.value for scope in _demanded(route)})
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            rows.append({
                "method": method,
                "path": route.path,
                "summary": route.summary or route.name.replace("_", " "),
                "tag": (route.tags or ["other"])[0],
                "scopes": scopes,
                # The role a route demands outright, where it demands one
                # instead of a scope. Grant management is the case: a privilege
                # a grant could carry is a privilege its holder could grant
                # themselves, so it is not a scope at all.
                "role": _demanded_role(route),
                # Whether the scope is demanded globally or on the connection
                # the path names. Read off the dependency, like the scope
                # itself, so a route converted from one to the other says so
                # here without anybody editing a page.
                "per_connection": _per_connection(route),
                "public": route.path in public,
            })
    return sorted(rows, key=lambda row: (row["tag"], row["path"], row["method"]))


def _all_routes(app: FastAPI) -> list[Any]:
    """Every route, flattened.

    Since FastAPI 0.141 an included router stays nested behind an
    ``_IncludedRouter`` wrapper rather than being spliced into ``app.routes``,
    so a single pass sees three wrappers and misses `/v1` entirely -- and this
    page would have reported, with a straight face, that the API has two
    endpoints and neither needs a privilege. The prefix each router was
    included under is asserted to be empty, because this service mounts its
    prefixes on the routers themselves; a route path is then the whole path.
    """
    found: list[Any] = []
    pending = list(app.routes)
    while pending:
        route = pending.pop()
        found.append(route)
        nested = getattr(route, "routes", None)
        if nested is None:
            included = getattr(route, "original_router", None)
            context = getattr(route, "include_context", None)
            assert not getattr(context, "prefix", ""), (
                "a router was included under a prefix; this page reads paths "
                "off the routes themselves and would report them short")
            nested = getattr(included, "routes", None)
        pending.extend(nested or [])
    return found


def _demanded_role(route: APIRoute) -> str | None:
    """The role a route's dependency tree demands outright, if any."""
    pending = [route.dependant]
    while pending:
        dependant = pending.pop()
        role = getattr(dependant.call, "required_role", None)
        if role:
            return str(role)
        pending.extend(dependant.dependencies)
    return None


def _per_connection(route: APIRoute) -> bool:
    """Does any dependency of this route demand its scope on one connection?"""
    pending = [route.dependant]
    while pending:
        dependant = pending.pop()
        if getattr(dependant.call, "per_connection", False):
            return True
        pending.extend(dependant.dependencies)
    return False


def _demanded(route: APIRoute) -> set[Scope]:
    """The scopes a route's dependency tree demands, however deeply nested."""
    found: set[Scope] = set()
    pending = [route.dependant]
    while pending:
        dependant = pending.pop()
        found |= set(getattr(dependant.call, "required_scopes", ()) or ())
        pending.extend(dependant.dependencies)
    return found


def unprotected(app: FastAPI, public: frozenset[str]) -> list[dict[str, Any]]:
    """Documented routes that demand no scope, minus the ones that cannot.

    The login endpoints and the orchestrator probes are reachable without a
    credential on purpose (:data:`painfree.authn.PUBLIC_PATHS`), and a route
    that demands a role instead of a scope is not scopeless in any sense a
    reader cares about. Anything else in this list is a route an authenticated
    caller reaches whatever they were granted, which is a thing to be able to
    see rather than to assume away.
    """
    return [row for row in protected_routes(app, public)
            if not row["scopes"] and not row["public"] and not row["role"]]


__all__ = ["OPENAPI_DOCUMENTS", "level_catalogue", "oversight_catalogue",
           "protected_routes", "role_catalogue", "scope_catalogue",
           "scope_descriptions", "unprotected"]
