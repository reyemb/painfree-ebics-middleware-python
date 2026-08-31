"""Every audit action this service writes, and the field names it writes them under.

The same defect was found by accident three times over. ``state`` is on
:data:`painfree.logging.SENSITIVE_FIELDS` because it is an OIDC login
parameter, audit details go through the same redaction as the log stream
(``painfree.audit``), and so an audit row written as ``{"state": ...}`` reaches
the operator -- and any webhook consumer, because an event *is* an audit row --
as ``"***"``. It was found in the order writers, then in ``download.finished``,
then in ``key.job_finished`` and ``payment.replayed``.

Nobody found any of those by reading the blocklist. They found them by staring
at a screen showing three asterisks where an outcome should have been. This
module is the thing that should have told them instead.

**How it works.** The audit writers are found statically, by walking the
package's syntax tree rather than by running it: a test that only sees the rows
the suite happens to produce cannot claim to have enumerated the actions, and
the failure has to arrive when the line is *written*, not when a rare path is
finally exercised. :func:`audit_writes` starts from
:meth:`painfree.audit.AuditLog.record` and works outwards to the helpers that
forward a ``detail`` to it, then reads the action name and the detail's field
names off each call site.

**The blocklist is not the part that moves.** It is a security control. When
this test fails, the fix is always to rename the field -- ``order_state``,
``run_state``, ``job_state`` -- and never to shorten
:data:`~painfree.logging.SENSITIVE_FIELDS`.

:func:`test_the_scan_catches_a_collision` is the scanner's own test: it runs
the analyser over a synthetic module that writes a colliding field, so a
refactor that quietly blinds the scan fails here rather than passing
vacuously.
"""

from __future__ import annotations

import ast
import pathlib
from dataclasses import dataclass, field
from typing import Iterable

import pytest

import painfree
from painfree.logging import SENSITIVE_FIELDS

PACKAGE = pathlib.Path(painfree.__file__).parent

#: The engine takes bytes and returns bytes and writes no audit row -- it may
#: not import the service layer at all -- so it is not scanned.
EXCLUDED = ("ebics3",)

#: The one writer, from `painfree.audit`. Everything else is reached from it.
ROOT_SINK = "record"

#: Actions asserted to exist. Not a closed list -- a new one is welcome and does
#: not fail this file -- but if the scan stops finding *these*, it has gone
#: blind and every other assertion here is passing vacuously.
ANCHOR_ACTIONS = frozenset({
    "service.started", "worker.started", "auth.session_established",
    "connection.registered", "connection.updated",
    "connection.key_state_changed", "key.sent", "key.job_requested",
    "key.job_finished", "key.bank_keys_accepted", "key.bank_keys_declined",
    "key.suspended", "payment.accepted", "payment.replayed",
    "payment.submitted", "payment.failed",
    "payment.conflict", "payment.replay_requested", "payment.validation_failed",
    "payment.acknowledged", "payment.rejected", "payment.status_reported",
    "payment.status_ignored", "payment.status_unmatched", "statement.available",
    "download_schedule.registered", "download_schedule.updated",
    "download_schedule.deleted", "download_schedule.run_requested",
    "download_schedule.refetch_requested", "download.finished",
    "webhook.subscription_registered", "webhook.subscription_updated",
    "webhook.subscription_paused", "webhook.subscription_resumed",
    "webhook.subscription_deleted", "webhook.secret_rotated",
    "webhook.previous_secret_retired", "webhook.ping_requested",
})

#: A detail built somewhere else is followed only when the function that builds
#: it says so in its name -- `StatusOutcome.as_detail`. Following *any* call by
#: name resolves `get()` and `_from_row()` too, and the scan then reports every
#: column in the schema as an audit field. The convention is enforced rather
#: than assumed: a detail factory named anything else makes
#: :func:`test_every_audit_write_is_analysable` fail, which is where a reader
#: is told to rename it.
DETAIL_FACTORY_SUFFIX = "detail"


@dataclass(frozen=True, slots=True)
class AuditWrite:
    """One call site that appends an audit row."""

    module: str
    line: int
    actions: tuple[str, ...]
    detail_keys: tuple[str, ...]
    passes_detail: bool

    def where(self) -> str:
        return f"{self.module}:{self.line}"


@dataclass
class _Sink:
    """A function whose ``detail`` ends up in an audit row."""

    name: str
    #: where it is defined. A method is only a sink for its own module, because
    #: `update` and `_settle` are names three unrelated classes here also use.
    module: str = ""
    is_method: bool = False
    params: tuple[str, ...] = ()
    action_index: int | None = None
    detail_index: int | None = None
    #: forwards ``**kwargs`` into the detail, so the call's keyword names are
    #: themselves detail field names (`painfree.api.record_webhook_change`).
    splats_kwargs: bool = False
    returns: list[ast.AST] = field(default_factory=list)


def _sources() -> dict[str, ast.Module]:
    return {
        str(path.relative_to(PACKAGE.parent)): ast.parse(
            path.read_text(encoding="utf-8"))
        for path in sorted(PACKAGE.rglob("*.py"))
        if not set(EXCLUDED) & set(path.relative_to(PACKAGE).parts)
    }


def _definitions(trees: dict[str, ast.Module]) -> list[tuple[str, bool, ast.AST]]:
    """Every function, with its module and whether it is a method."""
    found: list[tuple[str, bool, ast.AST]] = []
    for module, tree in trees.items():
        for holder in ast.walk(tree):
            if not isinstance(holder, ast.ClassDef):
                continue
            for node in holder.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    found.append((module, True, node))
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found.append((module, False, node))
    return found


def _called_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    if isinstance(call.func, ast.Name):
        return call.func.id
    return None


def _is_audit_record(call: ast.Call) -> bool:
    """``self._audit.record(...)``, ``app.state.audit.record(...)``, and no other.

    Matching the bare name ``record`` would sweep in every unrelated method
    called ``record``; requiring the receiver to name the audit log is what
    makes the scan about audit rows rather than about a common verb.
    """
    if not (isinstance(call.func, ast.Attribute) and call.func.attr == ROOT_SINK):
        return False
    receiver = ast.dump(call.func.value).lower()
    return "audit" in receiver


def _signature(module: str, is_method: bool, node: ast.AST) -> _Sink:
    """Positional parameters, minus ``self``, and where ``action``/``detail`` sit."""
    arguments = node.args
    names = [argument.arg for argument in
             (*arguments.posonlyargs, *arguments.args)]
    if is_method and names and names[0] in ("self", "cls"):
        names = names[1:]
    keyword_only = [argument.arg for argument in arguments.kwonlyargs]
    sink = _Sink(name=node.name, module=module, is_method=is_method,
                 params=tuple(names + keyword_only))
    if "action" in names:
        sink.action_index = names.index("action")
    if "detail" in names:
        sink.detail_index = names.index("detail")
    sink.returns = [statement.value for statement in _within(node)
                    if isinstance(statement, ast.Return) and statement.value]
    return sink


def _within(node: ast.AST):
    """Every node in one function, not descending into functions nested in it."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                              ast.ClassDef)) and child is not node:
            continue
        yield child
        yield from _within(child)


def _mentions(node: ast.AST | None, names: Iterable[str],
              scope: dict[str, ast.AST] | None = None) -> bool:
    """Does this expression read one of these names, directly or through a local?

    ``recorded = {..., **(detail or {})}`` followed by
    ``record(action, detail={k: v for k, v in recorded.items()})`` is the shape
    `painfree.queue` uses, and a check that only looked at the expression
    itself would decide that call forwards nothing.
    """
    wanted = set(names)
    reached: set[str] = set()
    frontier = [node] if node is not None else []
    while frontier:
        current = frontier.pop()
        for inner in ast.walk(current):
            if not isinstance(inner, ast.Name) or inner.id in reached:
                continue
            if inner.id in wanted:
                return True
            reached.add(inner.id)
            if scope and inner.id in scope:
                frontier.append(scope[inner.id])
    return False


def _detail_argument(call: ast.Call, sink: _Sink) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg == "detail":
            return keyword.value
    if sink.detail_index is not None and len(call.args) > sink.detail_index:
        return call.args[sink.detail_index]
    return None


def _matches(call: ast.Call, module: str, sink: _Sink) -> bool:
    if sink.name == ROOT_SINK:
        return _is_audit_record(call)
    if sink.is_method:
        return (module == sink.module
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == sink.name
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "self")
    return isinstance(call.func, ast.Name) and call.func.id == sink.name


def _sinks(trees: dict[str, ast.Module]) -> list[_Sink]:
    """:meth:`AuditLog.record`, and every helper that forwards a detail to it.

    A fixed point, because a forwarder may forward to a forwarder. Shallow in
    practice -- one hop, today -- but computing it is cheaper than remembering
    to extend a hand-written list.
    """
    sinks = [_Sink(name=ROOT_SINK, action_index=0)]
    definitions = _definitions(trees)
    while True:
        added = False
        for module, is_method, node in definitions:
            candidate = _signature(module, is_method, node)
            if any(sink.name == candidate.name and sink.module == module
                   for sink in sinks):
                continue
            forwarded = _forwarded_by(node)
            scope = _scope_of(node)
            for call in _within(node):
                if not isinstance(call, ast.Call):
                    continue
                inner = next((sink for sink in sinks
                              if _matches(call, module, sink)), None)
                if inner is None:
                    continue
                argument = _detail_argument(call, inner)
                if not _mentions(argument, forwarded, scope):
                    continue
                candidate.splats_kwargs = bool(
                    node.args.kwarg
                    and _mentions(argument, {node.args.kwarg.arg}, scope))
                sinks.append(candidate)
                added = True
                break
        if not added:
            return sinks


class _Resolver:
    """Turns a detail expression into the field names it will be stored under."""

    def __init__(self, trees: dict[str, ast.Module]) -> None:
        self._returns: dict[str, list[ast.AST]] = {}
        self._scopes: dict[int, dict[str, ast.AST]] = {}
        for module, is_method, node in _definitions(trees):
            signature = _signature(module, is_method, node)
            self._returns.setdefault(node.name, []).extend(signature.returns)
            for returned in signature.returns:
                self._scopes[id(returned)] = _scope_of(node)

    def keys(self, node: ast.AST | None, scope: dict[str, ast.AST],
             seen: frozenset[int] = frozenset()) -> list[str]:
        if node is None or id(node) in seen:
            return []
        seen = seen | {id(node)}
        found: list[str] = []
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if key is None:  # `**other`
                    found += self.keys(value, scope, seen)
                elif isinstance(key, ast.Constant) and isinstance(key.value, str):
                    found.append(key.value)
                    # A nested dict is redacted at every depth, so its own
                    # field names are in scope too.
                    found += self.keys(value, scope, seen)
        elif isinstance(node, ast.Name):
            found += self.keys(scope.get(node.id), scope, seen)
        elif isinstance(node, ast.DictComp):
            # `{k: v for k, v in recorded.items() if ...}` keeps `recorded`'s keys.
            for generator in node.generators:
                iterated = generator.iter
                if (isinstance(iterated, ast.Call)
                        and isinstance(iterated.func, ast.Attribute)
                        and iterated.func.attr == "items"):
                    found += self.keys(iterated.func.value, scope, seen)
        elif isinstance(node, ast.BoolOp):
            for value in node.values:
                found += self.keys(value, scope, seen)
        elif isinstance(node, ast.IfExp):
            found += self.keys(node.body, scope, seen)
            found += self.keys(node.orelse, scope, seen)
        elif isinstance(node, ast.Call):
            # A detail factory -- `outcome.as_detail(statement_id=...)`. Its
            # returned literal, plus what the caller merged in through `**`.
            for keyword in node.keywords:
                if keyword.arg:
                    found.append(keyword.arg)
            name = _called_name(node) or ""
            if name.lower().endswith(DETAIL_FACTORY_SUFFIX):
                for returned in self._returns.get(name, []):
                    found += self.keys(returned, self._scopes[id(returned)], seen)
        return found

    def strings(self, node: ast.AST | None,
                scope: dict[str, ast.AST]) -> list[str]:
        """Every string constant an expression can evaluate to."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node.value]
        if isinstance(node, ast.Name):
            return self.strings(scope.get(node.id), scope)
        if isinstance(node, ast.IfExp):
            return (self.strings(node.body, scope)
                    + self.strings(node.orelse, scope))
        return []


def _scope_of(node: ast.AST) -> dict[str, ast.AST]:
    """Plain local assignments in one function. Last write wins, as it does.

    Nested functions are not descended into: their locals are not this one's,
    and folding them together is how a scan starts resolving a name to a dict
    from somewhere else entirely.
    """
    scope: dict[str, ast.AST] = {}
    for statement in _within(node):
        if (isinstance(statement, ast.Assign) and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)):
            scope[statement.targets[0].id] = statement.value
    return scope


def _forwarded_by(node: ast.AST) -> set[str]:
    """The names this function would forward a caller's detail under."""
    return {"detail"} | ({node.args.kwarg.arg} if node.args.kwarg else set())


def audit_writes(trees: dict[str, ast.Module] | None = None) -> list[AuditWrite]:
    """Every call site that appends an audit row, with what it writes."""
    trees = trees if trees is not None else _sources()
    sinks = _sinks(trees)
    resolver = _Resolver(trees)
    writes: dict[tuple[str, int, int], AuditWrite] = {}
    for module, _is_method, holder in _definitions(trees):
        scope = _scope_of(holder)
        for call in _within(holder):
            if not isinstance(call, ast.Call):
                continue
            sink = next((candidate for candidate in sinks
                         if _matches(call, module, candidate)), None)
            if sink is None or sink.name == holder.name:
                continue
            actions: list[str] = []
            if sink.action_index is not None:
                if len(call.args) > sink.action_index:
                    actions = resolver.strings(call.args[sink.action_index], scope)
                for keyword in call.keywords:
                    if keyword.arg == "action":
                        actions = resolver.strings(keyword.value, scope)
            argument = _detail_argument(call, sink)
            keys = resolver.keys(argument, scope)
            if sink.splats_kwargs:
                keys += [keyword.arg for keyword in call.keywords
                         if keyword.arg and keyword.arg not in sink.params]
            # A forwarder handing its own `detail` parameter on writes no field
            # names of its own; they are read at the outer call sites, which is
            # where they are literals.
            forwards = _mentions(argument, _forwarded_by(holder), scope)
            writes[(module, call.lineno, call.col_offset)] = AuditWrite(
                module=module, line=call.lineno,
                actions=tuple(sorted(set(actions))),
                detail_keys=tuple(sorted(set(keys))),
                passes_detail=argument is not None and not forwards,
            )
    return sorted(writes.values(), key=lambda write: (write.module, write.line))


# --- the tests --------------------------------------------------------------

def test_no_recorded_detail_key_is_redacted() -> None:
    """The one that stops this recurring.

    A field name on the blocklist reaches the operator as `***`. Rename the
    field; the blocklist is a security control and does not move.
    """
    collisions = [
        (write.where(), write.actions or ("<action unresolved>",), key)
        for write in audit_writes()
        for key in write.detail_keys if key.lower() in SENSITIVE_FIELDS
    ]
    assert not collisions, (
        "an audit detail is written under a redacted field name, so an "
        "operator and every webhook consumer will see \"***\" instead of the "
        "value. Rename the field (`state` -> `order_state` / `run_state` / "
        "`job_state`), never shorten SENSITIVE_FIELDS:\n"
        + "\n".join(f"  {where}  {actions}  key={key!r}"
                    for where, actions, key in collisions))


def test_every_audit_write_is_analysable() -> None:
    """The scan must be able to read every write site, or it proves nothing.

    A call this analyser cannot follow is a call whose field names are
    unchecked. That is a reason to write the call differently, not a reason to
    exempt it.
    """
    writes = audit_writes()
    assert writes, "no audit write sites found at all -- the scan is broken"
    unreadable = [write.where() for write in writes
                  if write.passes_detail and not write.detail_keys]
    assert not unreadable, (
        "these audit writes pass a detail this test cannot read, so their "
        "field names are unchecked. Build the detail as a literal, or from a "
        "local that is one:\n  " + "\n  ".join(unreadable))


def test_the_scan_finds_the_actions_this_service_writes() -> None:
    """Anchors, so a scan that silently stopped working fails here."""
    found = {action for write in audit_writes() for action in write.actions}
    missing = sorted(ANCHOR_ACTIONS - found)
    assert not missing, (
        "the scan no longer finds these audit actions, so its other "
        f"assertions are passing vacuously: {missing}")


def test_the_scan_catches_a_collision() -> None:
    """The scanner's own test: give it a collision and it must find it.

    Without this, a refactor that blinds :func:`audit_writes` turns every
    assertion above green.
    """
    module = ast.parse(
        "class Jobs:\n"
        "    def finish(self, job, state):\n"
        "        self._audit.record('key.job_finished',\n"
        "                           detail={'state': state, 'action': job})\n")
    writes = audit_writes({"synthetic.py": module})
    assert [write.actions for write in writes] == [("key.job_finished",)]
    assert set(writes[0].detail_keys) == {"state", "action"}
    assert {key for key in writes[0].detail_keys
            if key.lower() in SENSITIVE_FIELDS} == {"state"}


def test_the_scan_follows_a_forwarding_helper() -> None:
    """`queue._settle`-shaped code: the detail is merged a level away from the write."""
    module = ast.parse(
        "class Orders:\n"
        "    def _settle(self, order_id, state, action, *, detail=None):\n"
        "        recorded = {'order_state': state, **(detail or {})}\n"
        "        self._audit.record(action,\n"
        "                           detail={k: v for k, v in recorded.items()})\n"
        "\n"
        "    def fail(self, order_id):\n"
        "        self._settle(order_id, 'failed', 'payment.failed',\n"
        "                     detail={'password': 'x'})\n")
    writes = {write.line: write for write in audit_writes({"s.py": module})}
    # Two sites, and between them every field name: what the forwarder merges
    # in is read where it is a literal, and what the caller supplies is read
    # at the call. `password` is what would have shipped as `***`.
    assert writes[4].detail_keys == ("order_state",)
    assert writes[8].actions == ("payment.failed",)
    assert writes[8].detail_keys == ("password",)


@pytest.mark.parametrize("action", sorted(ANCHOR_ACTIONS))
def test_each_action_writes_only_publishable_field_names(action: str) -> None:
    """The same assertion, one case per action, so a failure names the action."""
    for write in audit_writes():
        if action not in write.actions:
            continue
        redacted = sorted(key for key in write.detail_keys
                          if key.lower() in SENSITIVE_FIELDS)
        assert not redacted, (
            f"{action} at {write.where()} writes {redacted} -- a redacted "
            f"field name")
