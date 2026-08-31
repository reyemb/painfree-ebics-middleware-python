"""Browser SSO: the authorization-code flow with PKCE, and the session it ends in.

A human logging into the UI is a different problem from a machine presenting a
bearer token (:mod:`painfree.tokens`), and this module is the browser half. What
it has to get right is not the happy path -- the provider does most of that --
but the three ways a code flow is subverted:

**A login the browser did not start.** ``state`` is minted here, sent to the
provider, and required back on the callback *twice*: once in the query, and once
in a cookie the browser was given when the login began. Comparing the query
against a server-side row alone proves the login exists; comparing it against
the cookie is what proves it is **this** browser's. An attacker who can make a
victim's browser follow a callback URL cannot make it present the matching
cookie.

**A code that is not the one this flow asked for.** PKCE (RFC 7636, S256): a
random verifier is generated at login, only its SHA-256 goes to the provider,
and the verifier is presented at the token endpoint. A stolen authorization code
is then worth nothing without the verifier, which never left this service. The
flow does not complete without it -- the token request is built in one place and
that place always sends it.

**A code replayed.** The login row is claimed with a conditional ``UPDATE``, so
the second callback carrying the same ``state`` finds nothing to claim and is
refused before a token request is made.

The ``id_token`` that comes back is verified as strictly as a bearer token --
same JWKS, same allowlist, same issuer and audience checks -- with one addition:
its ``nonce`` has to be the one this login minted. That is what ties the identity
in the token to the flow, rather than to any valid token the provider ever
issued.

**What is stored, and what is not.** No token is kept. The session row holds the
subject, the issuer, the granted roles and an expiry, and the cookie carries a
random id whose SHA-256 is what the row is keyed by -- so neither the database
nor a backup of it contains a value that can be presented as a session. Logout
revokes the row and, where the provider publishes an end-session endpoint, sends
the browser there too, because a local logout that leaves the provider's session
standing is a logout button that does nothing.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import secrets
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from sqlalchemy import Engine, select

from painfree.logging import get_logger
from painfree.schema import oidc_login, user_session
from painfree.tokens import (MAX_DOCUMENT_BYTES, AuthenticationFailed,
                             ProviderUnavailable, fetch_json)

log = get_logger("painfree.oidc")

DISCOVERY_PATH = "/.well-known/openid-configuration"

#: How long a fetched discovery document is trusted before it is fetched again.
METADATA_TTL_SECONDS = 3600.0

#: How long a failed discovery is left alone. Short enough that a provider
#: coming back is noticed quickly, long enough that unauthenticated traffic
#: cannot turn this service into a load generator pointed at it.
FAILURE_COOLDOWN_SECONDS = 5.0

#: RFC 7636 allows 43..128 characters. 64 bytes of randomness, base64url encoded,
#: is 86 -- comfortably inside, and not a number anyone has to think about.
VERIFIER_BYTES = 64

SESSION_COOKIE = "pf_session"
LOGIN_COOKIE = "pf_login"

DEFAULT_TIMEOUT = 10.0


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def digest(value: str) -> str:
    """SHA-256 hex. What a state or a session id is stored as, never the value."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def code_challenge(verifier: str) -> str:
    """The S256 challenge for a PKCE verifier. ``plain`` is not offered."""
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    """The endpoints the discovery document names."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    end_session_endpoint: str | None = None


class ProviderDirectory:
    """The discovery document, fetched once and cached.

    The check that matters is on the way in: the ``issuer`` *inside* the
    document must equal the one this service was configured with. OIDC Discovery
    requires it, and without it a redirected or cached discovery response can
    point authentication at somebody else's endpoints while every later check
    still passes -- because every later check uses the configured issuer, which
    is exactly the value that was just replaced.
    """

    def __init__(self, issuer: str, *, ttl: float = METADATA_TTL_SECONDS,
                 fetch: Callable[[str], Mapping[str, Any]] | None = None,
                 clock: Callable[[], float] | None = None) -> None:
        self.issuer = issuer.rstrip("/")
        self.ttl = ttl
        self._fetch = fetch or (lambda url: fetch_json(url))
        self._clock = clock or _monotonic
        self._lock = threading.Lock()
        self._metadata: ProviderMetadata | None = None
        self._fetched_at: float | None = None
        self._failed_at: float | None = None
        self.fetches = 0

    @property
    def discovery_url(self) -> str:
        return self.issuer + DISCOVERY_PATH

    def metadata(self) -> ProviderMetadata:
        with self._lock:
            now = self._clock()
            if (self._metadata is None or self._fetched_at is None
                    or now - self._fetched_at >= self.ttl):
                if (self._failed_at is not None
                        and now - self._failed_at < FAILURE_COOLDOWN_SECONDS):
                    # A provider that is down stays down for a few seconds. Not
                    # a cache of the failure -- a floor on how often traffic
                    # this service did not ask for can make it call out.
                    raise ProviderUnavailable(
                        f"{self.discovery_url} was unreachable moments ago")
                try:
                    self._metadata = self._load()
                except ProviderUnavailable:
                    self._failed_at = now
                    raise
                self._failed_at = None
                self._fetched_at = now
                self.fetches += 1
            return self._metadata

    def _load(self) -> ProviderMetadata:
        document = self._fetch(self.discovery_url)
        declared = document.get("issuer")
        if declared != self.issuer:
            log.error("oidc.discovery_rejected", url=self.discovery_url,
                      configured=self.issuer, declared=declared,
                      reason="the document names a different issuer")
            raise ProviderUnavailable(
                f"{self.discovery_url} names issuer {declared!r}, but this "
                f"service is configured for {self.issuer!r}")
        missing = [name for name in ("authorization_endpoint", "token_endpoint",
                                     "jwks_uri")
                   if not isinstance(document.get(name), str)]
        if missing:
            raise ProviderUnavailable(
                f"{self.discovery_url} names no " + ", ".join(missing))
        metadata = ProviderMetadata(
            issuer=self.issuer,
            authorization_endpoint=document["authorization_endpoint"],
            token_endpoint=document["token_endpoint"],
            jwks_uri=document["jwks_uri"],
            end_session_endpoint=document.get("end_session_endpoint"),
        )
        log.info("oidc.discovered", issuer=self.issuer,
                 jwks_uri=metadata.jwks_uri,
                 end_session=metadata.end_session_endpoint is not None)
        return metadata


def _monotonic() -> float:
    import time

    return time.monotonic()


# --- the flow ---------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Login:
    """One authorization-code flow in flight, as the browser is sent away."""

    state: str
    nonce: str
    verifier: str
    authorization_url: str


@dataclass(frozen=True, slots=True)
class Session:
    """An established browser session. ``session_id`` is only ever the cookie."""

    session_id: str
    subject: str
    issuer: str
    roles: tuple[str, ...]
    display_name: str | None
    expires_at: _dt.datetime


def safe_redirect(target: str | None) -> str:
    """A relative path, or ``/``.

    Anything with a scheme or a host is discarded rather than sanitised: the
    only thing a ``next`` parameter is allowed to do is choose a page **in this
    application**, and an open redirect on a login endpoint is a phishing page
    with the right domain in the address bar.
    """
    if not target or not target.startswith("/") or target.startswith("//"):
        return "/"
    return target[:512]


class LoginStore:
    """The server-side half of a code flow, and its single-use claim."""

    __slots__ = ("_engine", "_ttl")

    def __init__(self, engine: Engine, *, ttl_seconds: int = 600) -> None:
        self._engine = engine
        self._ttl = ttl_seconds

    def begin(self, *, redirect_to: str | None = None) -> tuple[str, str, str]:
        """Mint a state, a nonce and a PKCE verifier, and record them."""
        state = b64url(secrets.token_bytes(32))
        nonce = b64url(secrets.token_bytes(24))
        verifier = b64url(secrets.token_bytes(VERIFIER_BYTES))
        started = _now()
        with self._engine.begin() as connection:
            connection.execute(oidc_login.insert().values(
                state_hash=digest(state), nonce=nonce, code_verifier=verifier,
                redirect_to=safe_redirect(redirect_to), created_at=started,
                expires_at=started + _dt.timedelta(seconds=self._ttl)))
        return state, nonce, verifier

    def claim(self, state: str) -> dict[str, Any]:
        """Consume the login this state belongs to, exactly once.

        The conditional ``UPDATE`` is the whole replay defence: the second
        callback carrying one state updates no rows, so it never reaches the
        token endpoint at all.
        """
        now = _now()
        with self._engine.begin() as connection:
            claimed = connection.execute(
                oidc_login.update()
                .where(oidc_login.c.state_hash == digest(state),
                       oidc_login.c.consumed_at.is_(None),
                       oidc_login.c.expires_at > now)
                .values(consumed_at=now)
                .returning(oidc_login.c.nonce, oidc_login.c.code_verifier,
                           oidc_login.c.redirect_to)
            ).mappings().first()
        if claimed is None:
            raise AuthenticationFailed(
                "state_unknown",
                detail="no login is in flight for this state, or it was already used")
        return dict(claimed)

    def purge(self, *, before: _dt.datetime | None = None) -> int:
        """Delete expired logins. Nothing reads them; nothing should keep them."""
        cutoff = before or _now()
        with self._engine.begin() as connection:
            return connection.execute(
                oidc_login.delete().where(oidc_login.c.expires_at <= cutoff)
            ).rowcount or 0


class SessionStore:
    """Browser sessions: create, look up, revoke. Keyed by a hash, never the id."""

    __slots__ = ("_engine", "_ttl")

    def __init__(self, engine: Engine, *, ttl_minutes: int = 480) -> None:
        self._engine = engine
        self._ttl = ttl_minutes

    def create(self, *, subject: str, issuer: str, roles: tuple[str, ...],
               display_name: str | None = None) -> Session:
        session_id = b64url(secrets.token_bytes(32))
        started = _now()
        expires = started + _dt.timedelta(minutes=self._ttl)
        with self._engine.begin() as connection:
            connection.execute(user_session.insert().values(
                session_id_hash=digest(session_id), subject=subject,
                issuer=issuer, roles=list(roles), display_name=display_name,
                created_at=started, expires_at=expires, last_seen_at=started))
        log.info("auth.session_established", subject=subject, issuer=issuer,
                 roles=list(roles), expires_at=expires.isoformat())
        return Session(session_id=session_id, subject=subject, issuer=issuer,
                       roles=roles, display_name=display_name,
                       expires_at=expires)

    def lookup(self, session_id: str) -> Session:
        """The live session this cookie names, or :class:`AuthenticationFailed`."""
        now = _now()
        statement = select(user_session).where(
            user_session.c.session_id_hash == digest(session_id))
        with self._engine.begin() as connection:
            row = connection.execute(statement).mappings().first()
            if row is None:
                raise AuthenticationFailed("no_session",
                                           detail="the cookie names no session")
            if row["revoked_at"] is not None:
                raise AuthenticationFailed("session_revoked")
            if row["expires_at"] <= now:
                raise AuthenticationFailed("session_expired")
            connection.execute(
                user_session.update()
                .where(user_session.c.seq == row["seq"])
                .values(last_seen_at=now))
        return Session(session_id=session_id, subject=row["subject"],
                       issuer=row["issuer"], roles=tuple(row["roles"] or ()),
                       display_name=row["display_name"],
                       expires_at=row["expires_at"])

    def revoke(self, session_id: str) -> bool:
        """Revoke this session. Idempotent, and never says whether it existed."""
        with self._engine.begin() as connection:
            return bool(connection.execute(
                user_session.update()
                .where(user_session.c.session_id_hash == digest(session_id),
                       user_session.c.revoked_at.is_(None))
                .values(revoked_at=_now())).rowcount)


def authorization_url(metadata: ProviderMetadata, *, client_id: str,
                      redirect_uri: str, state: str, nonce: str,
                      verifier: str, scopes: str = "openid profile email") -> str:
    """Where the browser is sent. S256 always; ``plain`` is never offered."""
    query = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge(verifier),
        "code_challenge_method": "S256",
    })
    separator = "&" if "?" in metadata.authorization_endpoint else "?"
    return f"{metadata.authorization_endpoint}{separator}{query}"


def exchange_code(metadata: ProviderMetadata, *, code: str, redirect_uri: str,
                  client_id: str, client_secret: str | None, verifier: str,
                  timeout: float = DEFAULT_TIMEOUT,
                  post: Callable[..., Mapping[str, Any]] | None = None,
                  ) -> Mapping[str, Any]:
    """Trade the code for tokens. The verifier always goes with it.

    ``code`` and ``client_secret`` are arguments and never appear in a log line,
    an exception message, or a field name -- including the failure paths, which
    is where a credential usually escapes.
    """
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        # The proof that this is the browser that started the flow. There is no
        # branch here: a token request without it cannot be built.
        "code_verifier": verifier,
    }
    if client_secret:
        form["client_secret"] = client_secret
    return (post or _post_form)(metadata.token_endpoint, form, timeout)


def _post_form(url: str, form: Mapping[str, str],
               timeout: float) -> Mapping[str, Any]:
    body = urllib.parse.urlencode(form).encode("ascii")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read(MAX_DOCUMENT_BYTES + 1)
    except urllib.error.HTTPError as exc:
        # The provider's error body may quote the code back at us. Only the
        # status is kept, and the body is read and dropped.
        exc.read()
        raise ProviderUnavailable(
            f"the token endpoint answered HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise ProviderUnavailable(
            f"the token endpoint could not be reached: {type(exc).__name__}"
        ) from None
    try:
        document = json.loads(payload)
    except ValueError:
        raise ProviderUnavailable("the token endpoint did not answer JSON") from None
    if not isinstance(document, dict):
        raise ProviderUnavailable("the token endpoint did not answer a JSON object")
    return document


def end_session_url(metadata: ProviderMetadata, *, client_id: str,
                    post_logout_redirect_uri: str | None) -> str | None:
    """Where to send the browser so the provider's own session ends too."""
    if not metadata.end_session_endpoint:
        return None
    parameters = {"client_id": client_id}
    if post_logout_redirect_uri:
        parameters["post_logout_redirect_uri"] = post_logout_redirect_uri
    separator = "&" if "?" in metadata.end_session_endpoint else "?"
    return (f"{metadata.end_session_endpoint}{separator}"
            f"{urllib.parse.urlencode(parameters)}")


__all__ = ["DISCOVERY_PATH", "LOGIN_COOKIE", "Login", "LoginStore",
           "ProviderDirectory", "ProviderMetadata", "SESSION_COOKIE", "Session",
           "SessionStore", "authorization_url", "b64url", "code_challenge",
           "digest", "end_session_url", "exchange_code", "safe_redirect"]
