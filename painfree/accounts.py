"""Local accounts: the identity provider a deployment that has none is left with.

This module is one half of the ``basic`` authentication mode -- the half that
answers *who is this* when there is no OIDC issuer to ask. The other half is
:mod:`painfree.authn`, which turns the answer into the same
:class:`~painfree.identity.Principal` a token produces.

**It authenticates, and it does not authorise.** An account carries a subject
and one of the two roles a claim would have carried, and that is the whole of
it. There is no scope column, no level and no connection here: what a Basic
caller may touch comes out of `connection_grant` and `oversight_grant`, read on
every request, exactly as it does for a bearer token. A second authorisation
model reachable only from one credential type would eventually be a second,
more permissive answer.

**Passwords are hashed with Argon2id and nothing here can reverse one.** The
parameters are RFC 9106's second recommended configuration -- 64 MiB, three
passes, four lanes -- and they are deliberately not configuration: raising a
cost is a change to this file, and :func:`Accounts.authenticate` upgrades a
stored hash the next time its owner signs in. :data:`DUMMY_HASH` is what an
unknown account name is verified against, so the work done for a name nobody has
is the work done for a name somebody has and a stopwatch does not enumerate this
deployment's users.

**One thing is cached and it is not the password.** HTTP Basic re-sends the
credential on *every* request, and 64 MiB of Argon2 per request is a denial of
service this service would be performing on itself. So a *successful*
verification is remembered for :data:`VERIFICATION_TTL_SECONDS` under
``HMAC(process pepper, subject || password || the stored hash)``. The pepper is
random per process and never stored, the entry holds no password, and it is
keyed by the stored hash -- so changing a password invalidates every cached
verification of the old one at once, with no expiry to wait for. The account row
itself is still read from the database on every request, which is what keeps
disabling, deleting and locking immediate rather than eventually.

**A failed sign-in is an audit row, and it is bounded by being one.**
Rejected authentications are deliberately kept out of the audit log, because
unauthenticated traffic is unbounded and an append-only table is the wrong
place to absorb it. That reasoning is answered here rather than ignored: the
throttle stops counting -- and therefore stops writing -- once a name or a
source is locked, so what a flood can produce is the threshold in rows, not the
flood in rows. What it produces instead is one ``auth.locked_out`` row and a
lockout an administrator can see and clear.

**Nothing here logs, returns, stores or raises a password.** :class:`Account`
has no field that could hold one, the stored hash never leaves this module, and
every exception below carries a subject and a reason and no credential.
"""

from __future__ import annotations

import datetime as _dt
import hmac
import secrets
import string
import threading
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

import argon2
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import Engine, delete, insert, select, update

from painfree.audit import FAILURE, SUCCESS, Actor, AuditLog
from painfree.errors import ConflictError, NotFoundError
from painfree.identity import Role
from painfree.logging import get_logger
from painfree.schema import basic_account, basic_lockout
from painfree.tokens import AuthenticationFailed

log = get_logger("painfree.accounts")

#: RFC 9106's second recommended configuration. Not a setting: a cost an
#: operator can lower is a cost an operator lowers on the afternoon the console
#: feels slow, and the only reason to raise one is a decision about this
#: service rather than about one deployment.
ARGON2_MEMORY_KIB = 65536
ARGON2_TIME_COST = 3
ARGON2_PARALLELISM = 4

#: The shortest password this service will store. Length is the only property
#: checked, deliberately: composition rules ("one digit, one symbol") shrink the
#: space a guesser has to search and push people towards `Passw0rd!`.
MINIMUM_PASSWORD_LENGTH = 12

#: Longer than any password and short enough that hashing it is not itself the
#: attack. A megabyte-long password is a request to spend 64 MiB and a second,
#: and it is refused before the hasher is reached rather than after.
MAXIMUM_PASSWORD_LENGTH = 1024

#: How long a verified credential is trusted without re-running the hash. Short
#: enough to bound how long a process keeps a derivative of a password in
#: memory; long enough that a browser or a polling client is not re-hashed.
#: Nothing about the *account* is cached for this long -- see the module
#: docstring.
VERIFICATION_TTL_SECONDS = 300.0

#: How many verifications are remembered at once. A bound, so a spray of valid
#: credentials cannot grow the process; the oldest entries go first.
VERIFICATION_CACHE_SIZE = 2048

#: The two things a failure is counted against.
SUBJECT_SCOPE = "subject"
SOURCE_SCOPE = "source"
LOCKOUT_SCOPES = (SUBJECT_SCOPE, SOURCE_SCOPE)

#: The alphabet ``generate_password`` draws from: unambiguous, and every
#: character survives a copy out of a terminal and into a password manager.
_PASSWORD_ALPHABET = string.ascii_letters + string.digits
_PASSWORD_LENGTH = 24

_HASHER = argon2.PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_KIB,
    parallelism=ARGON2_PARALLELISM,
    hash_len=32,
    salt_len=16,
)

#: What a name nobody has is verified against. Generated once at import from a
#: value nobody knows, so verifying against it costs exactly what verifying a
#: real account costs and there is no password that matches it.
DUMMY_HASH = _HASHER.hash(secrets.token_urlsafe(32))

#: Per process, random, never written anywhere. It is what makes the
#: verification cache's keys meaningless outside this process's memory.
_PEPPER = secrets.token_bytes(32)

#: The audit `actor_type` a failed sign-in is written under. Not `user`: the row
#: names who *claimed* to be signing in, and the claim is precisely what did not
#: hold. A trail in which an unverified claim looks like a verified one is worse
#: than one without the row.
UNVERIFIED_ACTOR = "unverified"


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


class PasswordRejected(ConflictError):
    """The proposed password is not one this service will store.

    A `409` rather than a `422`, so it lands in the same envelope as every other
    "well-formed and refused" answer -- and its message says what the rule is
    without ever quoting what was sent.
    """


def generate_password() -> str:
    """A password nobody chose, for ``create-admin`` to print exactly once."""
    return "".join(secrets.choice(_PASSWORD_ALPHABET)
                   for _ in range(_PASSWORD_LENGTH))


def hash_password(password: str) -> str:
    """Argon2id, with its salt and parameters encoded into the result.

    Raises :class:`PasswordRejected` before hashing anything a policy would
    refuse, so a refusal costs nothing and a caller cannot use the endpoint as
    a work generator.
    """
    check_password_policy(password)
    return _HASHER.hash(password)


def check_password_policy(password: str) -> None:
    """Length only, and the message never contains the value."""
    if not isinstance(password, str) or len(password) < MINIMUM_PASSWORD_LENGTH:
        raise PasswordRejected(
            f"a password must be at least {MINIMUM_PASSWORD_LENGTH} characters")
    if len(password) > MAXIMUM_PASSWORD_LENGTH:
        raise PasswordRejected(
            f"a password may be at most {MAXIMUM_PASSWORD_LENGTH} characters")


# --- the verification cache -------------------------------------------------

class _VerificationCache:
    """Successful verifications, by a keyed hash of what was verified.

    Not a session store and not an authorisation cache: it answers exactly one
    question -- *has this exact password already been checked against this exact
    stored hash* -- and every other fact about the account is read from the
    database on the request that asks.
    """

    __slots__ = ("_entries", "_lock", "_ttl", "_size")

    def __init__(self, ttl: float = VERIFICATION_TTL_SECONDS,
                 size: int = VERIFICATION_CACHE_SIZE) -> None:
        self._entries: dict[bytes, float] = {}
        self._lock = threading.Lock()
        self._ttl = ttl
        self._size = size

    @staticmethod
    def key(subject: str, password: str, stored: str) -> bytes:
        """Keyed, and over the stored hash as well as the credential.

        Including the stored hash is what makes a password change take effect
        immediately: the new hash produces a different key, so every entry for
        the old password is unreachable the moment it is replaced.
        """
        material = b"\x00".join((subject.encode("utf-8"),
                                 password.encode("utf-8"),
                                 stored.encode("utf-8")))
        return hmac.new(_PEPPER, material, sha256).digest()

    def holds(self, key: bytes) -> bool:
        now = time.monotonic()
        with self._lock:
            expires = self._entries.get(key)
            if expires is None:
                return False
            if expires <= now:
                self._entries.pop(key, None)
                return False
            return True

    def remember(self, key: bytes) -> None:
        now = time.monotonic()
        with self._lock:
            if len(self._entries) >= self._size:
                # Cheap and bounded: drop everything already expired, and if
                # that was not enough, the oldest insertions. A dict preserves
                # insertion order, so "oldest" needs no second structure.
                self._entries = {k: v for k, v in self._entries.items()
                                 if v > now}
                while len(self._entries) >= self._size:
                    self._entries.pop(next(iter(self._entries)))
            self._entries[key] = now + self._ttl

    def forget_all(self) -> None:
        """Drop every entry. Used when a password or an account changes."""
        with self._lock:
            self._entries.clear()


# --- what a caller sees -----------------------------------------------------

@dataclass(frozen=True, slots=True)
class Account:
    """One local account, without its password hash.

    The hash is not a field here and that is the point: this object is what the
    API renders, what the console lists and what an audit row is built from, and
    a value it does not carry is a value it cannot leak.
    """

    subject: str
    display_name: str | None
    role: Role
    disabled_at: _dt.datetime | None
    created_at: _dt.datetime
    created_by: str
    updated_at: _dt.datetime
    password_changed_at: _dt.datetime

    @property
    def disabled(self) -> bool:
        return self.disabled_at is not None

    def as_response(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "display_name": self.display_name,
            "role": self.role.value,
            "disabled": self.disabled,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "updated_at": self.updated_at.isoformat(),
            "password_changed_at": self.password_changed_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class Lockout:
    """A name or a source that is being throttled, and how far along it is."""

    scope: str
    value: str
    failures: int
    first_failure_at: _dt.datetime
    last_failure_at: _dt.datetime
    locked_until: _dt.datetime | None

    def locked(self, now: _dt.datetime | None = None) -> bool:
        return (self.locked_until is not None
                and self.locked_until > (now or _now()))

    def as_response(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "value": self.value,
            "failures": self.failures,
            "first_failure_at": self.first_failure_at.isoformat(),
            "last_failure_at": self.last_failure_at.isoformat(),
            "locked_until": (self.locked_until.isoformat()
                             if self.locked_until else None),
            "locked": self.locked(),
        }


def _account(row: Any) -> Account:
    return Account(subject=row["subject"], display_name=row["display_name"],
                   role=Role(row["role"]), disabled_at=row["disabled_at"],
                   created_at=row["created_at"], created_by=row["created_by"],
                   updated_at=row["updated_at"],
                   password_changed_at=row["password_changed_at"])


def _lockout(row: Any) -> Lockout:
    return Lockout(scope=row["scope"], value=row["value"],
                   failures=row["failures"],
                   first_failure_at=row["first_failure_at"],
                   last_failure_at=row["last_failure_at"],
                   locked_until=row["locked_until"])


# --- the store --------------------------------------------------------------

class Accounts:
    """Local accounts, their passwords, and the throttle in front of them."""

    def __init__(self, engine: Engine, audit: AuditLog | None = None, *,
                 subject_threshold: int = 5, source_threshold: int = 20,
                 window_minutes: int = 15, lockout_minutes: int = 15) -> None:
        self._engine = engine
        self._audit = audit
        self._subject_threshold = subject_threshold
        self._source_threshold = source_threshold
        self._window = _dt.timedelta(minutes=window_minutes)
        self._lockout = _dt.timedelta(minutes=lockout_minutes)
        self._verified = _VerificationCache()

    # --- reading ------------------------------------------------------------

    def count(self) -> int:
        """How many accounts exist. Zero is the state a fresh deployment is in."""
        with self._engine.connect() as connection:
            return len(connection.execute(
                select(basic_account.c.seq)).all())

    def all(self) -> list[Account]:
        with self._engine.connect() as connection:
            return [_account(row) for row in connection.execute(
                select(basic_account).order_by(basic_account.c.subject)
            ).mappings()]

    def get(self, subject: str) -> Account | None:
        row = self._row(subject)
        return _account(row) if row is not None else None

    def _row(self, subject: str) -> Any:
        with self._engine.connect() as connection:
            return connection.execute(
                select(basic_account).where(
                    basic_account.c.subject == subject)).mappings().first()

    # --- writing ------------------------------------------------------------

    def create(self, subject: str, password: str, *, role: Role = Role.member,
               display_name: str | None = None,
               actor: Actor) -> Account:
        """Add an account. Refuses a name that already exists rather than reusing it.

        A `PUT` that quietly replaced an existing account's password would be
        one typo away from resetting a colleague's credential, so changing one
        is :meth:`set_password` and is a different call.
        """
        subject = _clean_subject(subject)
        hashed = hash_password(password)
        now = _now()
        if self._row(subject) is not None:
            raise ConflictError(
                f"an account named {subject!r} already exists")
        with self._engine.begin() as connection:
            connection.execute(insert(basic_account).values(
                subject=subject, display_name=display_name or None,
                role=role.value, password_hash=hashed, created_at=now,
                created_by=actor.id, updated_at=now, password_changed_at=now))
        self._record("account.created", actor, detail={
            "subject": subject, "account_role": role.value,
            "display_name": display_name or None})
        log.info("account.created", subject=subject, account_role=role.value,
                 created_by=actor.id)
        account = self.get(subject)
        assert account is not None  # written one statement ago
        return account

    def set_password(self, subject: str, password: str, *, actor: Actor) -> Account:
        """Replace a password. Every cached verification of the old one dies with it."""
        hashed = hash_password(password)
        now = _now()
        with self._engine.begin() as connection:
            changed = connection.execute(
                update(basic_account)
                .where(basic_account.c.subject == subject)
                .values(password_hash=hashed, password_changed_at=now,
                        updated_at=now)).rowcount
        if not changed:
            raise NotFoundError(f"no account named {subject!r}")
        # The cache is keyed by the stored hash, so the old entries are already
        # unreachable. Clearing is belt and braces and costs one dictionary.
        self._verified.forget_all()
        self._record("account.password_changed", actor,
                     detail={"subject": subject})
        log.info("account.password_changed", subject=subject,
                 changed_by=actor.id)
        account = self.get(subject)
        assert account is not None
        return account

    def change(self, subject: str, *, role: Role | None = None,
               display_name: str | None = None, disabled: bool | None = None,
               actor: Actor) -> Account:
        """Change what an account *is*. Never what its password is."""
        values: dict[str, Any] = {"updated_at": _now()}
        if role is not None:
            values["role"] = role.value
        if display_name is not None:
            values["display_name"] = display_name or None
        if disabled is not None:
            values["disabled_at"] = _now() if disabled else None
        with self._engine.begin() as connection:
            changed = connection.execute(
                update(basic_account)
                .where(basic_account.c.subject == subject)
                .values(**values)).rowcount
        if not changed:
            raise NotFoundError(f"no account named {subject!r}")
        self._record("account.updated", actor, detail={
            "subject": subject,
            "account_role": role.value if role is not None else None,
            "disabled": disabled})
        log.info("account.updated", subject=subject, changed_by=actor.id,
                 account_role=role.value if role is not None else None,
                 disabled=disabled)
        account = self.get(subject)
        assert account is not None
        return account

    def delete(self, subject: str, *, actor: Actor) -> bool:
        """Remove an account. **Its grants are not removed with it.**

        Deliberately: a grant names a subject and the subject may come back from
        an identity provider later, and a delete that silently revoked a
        person's access to four bank connections would be a decision taken by a
        button labelled something else. The console says so where it offers it.
        """
        with self._engine.begin() as connection:
            removed = bool(connection.execute(
                delete(basic_account).where(
                    basic_account.c.subject == subject)).rowcount)
        if removed:
            self._verified.forget_all()
            self._record("account.deleted", actor, detail={"subject": subject})
            log.info("account.deleted", subject=subject, deleted_by=actor.id)
        return removed

    # --- authenticating -----------------------------------------------------

    def authenticate(self, subject: str, password: str, *,
                     source: str | None = None) -> Account:
        """The one way a Basic credential becomes an identity.

        The order is deliberate and each step is load-bearing:

        1. **Is this name or this source locked?** Checked first, and it is the
           one branch that short-circuits before the hash. That costs a timing
           signal about lockout state and buys the thing a lockout exists for --
           not spending 64 MiB on the ten-thousandth guess. Since an unknown
           name is counted exactly as a real one is, what the signal reveals is
           that somebody has been guessing at this name, not that the name
           exists.
        2. **Read the account row.** Every request, so revoking, disabling or
           deleting takes effect on the next one.
        3. **Verify, against the real hash or against a dummy one.** The
           unknown-name and disabled-account paths do the same Argon2 work the
           ordinary path does, so the response time of a wrong password and the
           response time of a name nobody has are the same measurement.
        4. **Count the failure, or clear the count.**
        """
        now = _now()
        locked = self._locked(subject, source, now)
        if locked is not None:
            log.warning("auth.locked_out", subject=subject,
                        lockout_scope=locked.scope,
                        locked_until=locked.locked_until.isoformat()
                        if locked.locked_until else None,
                        reason="too many failed sign-ins")
            raise AuthenticationFailed(
                "locked_out",
                detail=f"too many failed sign-ins against this {locked.scope}")

        if len(password) > MAXIMUM_PASSWORD_LENGTH:
            # Refused before the hasher, and without touching the counters:
            # a caller sending a megabyte is not guessing a password, and
            # hashing it is the only way this could hurt.
            raise AuthenticationFailed(
                "oversized_credential",
                detail="the presented password is longer than any this service stores")

        row = self._row(subject)
        stored = row["password_hash"] if row is not None else DUMMY_HASH
        verified = self._verify(subject, password, stored)
        # A disabled account is verified and *then* refused, so that "this name
        # is suspended" is not something a stopwatch can read either.
        if verified and row is not None and row["disabled_at"] is None:
            self._succeed(subject, row, password, stored, now)
            return _account(row)

        reason = ("unknown_or_wrong_password" if row is None or verified is False
                  else "account_disabled")
        self._fail(subject, source, reason, now)
        raise AuthenticationFailed(
            "bad_credential",
            detail="the presented account name and password were not accepted")

    def _verify(self, subject: str, password: str, stored: str) -> bool:
        """Argon2id, or the remembered answer for exactly this credential."""
        key = _VerificationCache.key(subject, password, stored)
        if self._verified.holds(key):
            return True
        try:
            _HASHER.verify(stored, password)
        except VerificationError:
            return False
        except InvalidHashError:
            # A stored hash this build cannot parse. Loud, because it means the
            # row was written by something else -- and still a refusal.
            log.error("account.unreadable_hash", subject=subject,
                      reason="the stored password hash is not in a format this "
                             "build can read; the account cannot be used until "
                             "its password is set again")
            return False
        self._verified.remember(key)
        return True

    def _succeed(self, subject: str, row: Any, password: str, stored: str,
                 now: _dt.datetime) -> None:
        """Clear this name's failures, and upgrade the hash if the cost moved."""
        with self._engine.begin() as connection:
            connection.execute(delete(basic_lockout).where(
                basic_lockout.c.scope == SUBJECT_SCOPE,
                basic_lockout.c.value == subject))
        if _HASHER.check_needs_rehash(stored):
            # The parameters in this file moved since this password was set.
            # A sign-in is the only moment the plaintext exists, so it is the
            # only moment the upgrade can happen.
            upgraded = _HASHER.hash(password)
            with self._engine.begin() as connection:
                connection.execute(
                    update(basic_account)
                    .where(basic_account.c.subject == subject)
                    .values(password_hash=upgraded, updated_at=now))
            self._verified.forget_all()
            log.info("account.hash_upgraded", subject=subject,
                     reason="the stored hash used weaker parameters than this "
                            "build uses")

    # --- the throttle -------------------------------------------------------

    def _locked(self, subject: str, source: str | None,
                now: _dt.datetime) -> Lockout | None:
        """The first of the two counters that is currently locked, if either is."""
        pairs = [(SUBJECT_SCOPE, subject)]
        if source:
            pairs.append((SOURCE_SCOPE, source))
        with self._engine.connect() as connection:
            for scope, value in pairs:
                row = connection.execute(select(basic_lockout).where(
                    basic_lockout.c.scope == scope,
                    basic_lockout.c.value == value)).mappings().first()
                if row is not None and row["locked_until"] is not None \
                        and row["locked_until"] > now:
                    return _lockout(row)
        return None

    def _fail(self, subject: str, source: str | None, reason: str,
              now: _dt.datetime) -> None:
        """Count one failure against both scopes, and write the row.

        The audit row is written **here** and not on every rejected request:
        once a counter locks, :meth:`authenticate` refuses before reaching this
        method, so the number of rows a guessing run can append is the threshold
        rather than the run.
        """
        locked_scopes = []
        for scope, value, threshold in (
                (SUBJECT_SCOPE, subject, self._subject_threshold),
                (SOURCE_SCOPE, source, self._source_threshold)):
            if not value:
                continue
            if self._count(scope, value, threshold, now):
                locked_scopes.append(scope)
        self._record("auth.sign_in_failed",
                     Actor(UNVERIFIED_ACTOR, subject or "(none)"),
                     outcome=FAILURE,
                     detail={"subject": subject, "reason": reason,
                             "source": source, "locked": bool(locked_scopes)})
        log.warning("auth.sign_in_failed", subject=subject, reason=reason,
                    source=source, locked=sorted(locked_scopes))
        for scope in locked_scopes:
            self._record("auth.locked_out",
                         Actor(UNVERIFIED_ACTOR, subject or "(none)"),
                         outcome=FAILURE,
                         detail={"lockout_scope": scope, "subject": subject,
                                 "source": source,
                                 "minutes": int(self._lockout.total_seconds() // 60)})

    def _count(self, scope: str, value: str, threshold: int,
               now: _dt.datetime) -> bool:
        """Add one failure to a counter. Returns whether it locked just now.

        Two statements in one transaction rather than an upsert, because the
        two backends spell an upsert differently and this table is written at
        most `threshold` times per window per value. A lost race undercounts by
        one, which the next attempt corrects.
        """
        locked_now = False
        with self._engine.begin() as connection:
            row = connection.execute(select(basic_lockout).where(
                basic_lockout.c.scope == scope,
                basic_lockout.c.value == value)).mappings().first()
            if row is None or row["last_failure_at"] + self._window <= now:
                # No counter, or one whose window has passed: this failure
                # starts a fresh count rather than resuming an old one.
                failures = 1
                locked_until = None
                if row is None:
                    connection.execute(insert(basic_lockout).values(
                        scope=scope, value=value, failures=failures,
                        first_failure_at=now, last_failure_at=now,
                        locked_until=None))
                else:
                    connection.execute(
                        update(basic_lockout)
                        .where(basic_lockout.c.seq == row["seq"])
                        .values(failures=failures, first_failure_at=now,
                                last_failure_at=now, locked_until=None))
            else:
                failures = row["failures"] + 1
                locked_until = row["locked_until"]
                if failures >= threshold and (
                        locked_until is None or locked_until <= now):
                    locked_until = now + self._lockout
                    locked_now = True
                connection.execute(
                    update(basic_lockout)
                    .where(basic_lockout.c.seq == row["seq"])
                    .values(failures=failures, last_failure_at=now,
                            locked_until=locked_until))
        return locked_now

    def lockouts(self, *, only_locked: bool = False) -> list[Lockout]:
        """Every counter, or only the ones that are currently locking somebody out."""
        now = _now()
        with self._engine.connect() as connection:
            rows = [_lockout(row) for row in connection.execute(
                select(basic_lockout).order_by(
                    basic_lockout.c.last_failure_at.desc())).mappings()]
        return [row for row in rows if row.locked(now)] if only_locked else rows

    def clear_lockout(self, scope: str, value: str, *, actor: Actor) -> bool:
        """The administrator's lever. Deletes the counter as well as the lock.

        Deleting rather than back-dating: a cleared lockout that kept its
        failure count would lock again on the next mistyped password, which is
        not what anybody means by clearing one. The record of it is the audit
        row, which is where a record belongs.
        """
        if scope not in LOCKOUT_SCOPES:
            raise NotFoundError(
                f"{scope!r} is not a lockout scope; it is "
                f"{' or '.join(LOCKOUT_SCOPES)}")
        with self._engine.begin() as connection:
            cleared = bool(connection.execute(delete(basic_lockout).where(
                basic_lockout.c.scope == scope,
                basic_lockout.c.value == value)).rowcount)
        if not cleared:
            return False
        self._record("auth.lockout_cleared", actor,
                     detail={"lockout_scope": scope, "value": value})
        log.info("auth.lockout_cleared", lockout_scope=scope, value=value,
                 cleared_by=actor.id)
        return True

    def purge_lockouts(self, *, before: _dt.datetime | None = None) -> int:
        """Drop counters whose window and lock have both passed.

        Called when the lockout list is read, which is enough: the table only
        grows while somebody is guessing, and the guessing is what put a bound
        on it.
        """
        cutoff = before or (_now() - self._window - self._lockout)
        with self._engine.begin() as connection:
            return connection.execute(delete(basic_lockout).where(
                basic_lockout.c.last_failure_at < cutoff)).rowcount

    # --- one place that writes a row ---------------------------------------

    def _record(self, action: str, actor: Actor, *, outcome: str = SUCCESS,
                detail: dict[str, Any]) -> None:
        if self._audit is not None:
            self._audit.record(action, actor=actor, outcome=outcome,
                               detail=detail)


def _clean_subject(subject: str) -> str:
    """A subject is trimmed, non-empty and short enough for the column.

    Nothing more: it is the same string a `sub` claim would have been, it is the
    key every grant names, and inventing a character class here would mean an
    account this deployment can create and a grant it cannot match.
    """
    cleaned = (subject or "").strip()
    if not cleaned:
        raise ConflictError("an account needs a name")
    if len(cleaned) > 255:
        raise ConflictError("an account name may be at most 255 characters")
    return cleaned


__all__ = ["ARGON2_MEMORY_KIB", "ARGON2_PARALLELISM", "ARGON2_TIME_COST",
           "Account", "Accounts", "DUMMY_HASH", "LOCKOUT_SCOPES", "Lockout",
           "MAXIMUM_PASSWORD_LENGTH", "MINIMUM_PASSWORD_LENGTH",
           "PasswordRejected", "SOURCE_SCOPE", "SUBJECT_SCOPE",
           "UNVERIFIED_ACTOR", "VERIFICATION_TTL_SECONDS", "check_password_policy",
           "generate_password", "hash_password"]
