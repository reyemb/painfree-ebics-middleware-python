"""Verifying a JWT bearer token, and the JWKS it is verified against.

The rule this module exists to enforce is one sentence: **an unverified token is
never accepted, and the token never gets to choose how it is verified.** Almost
every JWT vulnerability worth a CVE is a violation of the second half -- the
attacker sets ``alg`` and the library obliges.

The library is **PyJWT 2.11.0**, pinned in ``pyproject.toml``. It does the
signature arithmetic and the time claims; it does not decide the policy, and the
tests in ``tests/test_service_tokens.py`` are written against *this service*
rejecting each attack rather than against PyJWT claiming to.

Five decisions, each closing a specific attack:

**The algorithm allowlist is asymmetric-only, and is checked before anything
else.** ``alg: none`` and ``alg: HS256`` are refused at the header, before a key
is even looked up. That kills the unsigned-token attack and the confusion attack
in the same line: there is no code path in which an RSA public key from the
provider's JWKS is handed to an HMAC verifier, because HMAC is not in the list.

**The key is chosen from the JWKS, and its type decides the algorithms.** ``kid``
selects among keys the provider published and does nothing else -- it is not a
URL, not a file path, and not a way to reach a key of a different kind. Once a
key is chosen, the algorithms passed to the verifier are the ones *that key type*
can perform, so the token cannot influence the choice even indirectly. A JWKS
entry that is symmetric (``kty: oct``) is dropped when the set is parsed: a
provider that publishes one is not going to be the reason this service verifies
a token with a shared secret.

**An unknown ``kid`` does not become a fetch.** A refresh happens at most once
per :data:`MIN_REFRESH_SECONDS`, so a stream of tokens carrying invented key ids
costs one request to the provider, not one per token. That is the difference
between rotation support and a denial-of-service amplifier pointed at the
identity provider.

**Rotation is the same mechanism.** A key published a minute ago is unknown, so
the first token that carries it triggers the one refresh and then verifies. A
key the provider withdrew disappears from the cached set at the next refresh --
the set is *replaced*, never merged, so a revoked key cannot survive in the
cache as a leftover.

**Every rejection has a reason, and the reason is never the token.**
:class:`AuthenticationFailed` carries a short machine-readable ``reason`` for the
log stream and an opaque message for the caller. Nothing in this module puts a
token, or any part of one, into an exception message -- the redaction in
:mod:`painfree.logging` is the net underneath, not the control.
"""

from __future__ import annotations

import datetime as _dt
import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping

import jwt
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from painfree.errors import UnauthenticatedError
from painfree.logging import get_logger

log = get_logger("painfree.tokens")

#: What each key type may verify. The token's ``alg`` has to be in the list its
#: own key's type produces -- so choosing a key never widens the algorithm set.
ALGORITHMS_BY_KEY_TYPE: Mapping[str, tuple[str, ...]] = {
    "RSA": ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512"),
    "EC": ("ES256", "ES384", "ES512"),
}

#: Asymmetric, always. ``none`` is absent because it is not an algorithm, and
#: ``HS*`` is absent because a service verifying against a *published* key must
#: never accept one that is verified with a shared secret.
ACCEPTED_ALGORITHMS = frozenset(
    algorithm
    for algorithms in ALGORITHMS_BY_KEY_TYPE.values()
    for algorithm in algorithms
)

#: Claims a token must carry. ``nbf`` is deliberately not required -- several
#: providers omit it -- but it is *verified* whenever it is present, which is
#: what "reject a not-yet-valid token" actually needs.
REQUIRED_CLAIMS = ("exp", "iat", "iss", "aud", "sub")

#: How long a fetched JWKS is used without asking again.
JWKS_TTL_SECONDS = 300.0

#: The floor between two fetches. An unknown ``kid`` inside this window is
#: rejected without a request, however many tokens carry it.
MIN_REFRESH_SECONDS = 30.0

#: A JWKS larger than this is not a JWKS.
MAX_DOCUMENT_BYTES = 512 * 1024

DEFAULT_TIMEOUT = 10.0


class AuthenticationFailed(UnauthenticatedError):
    """A caller did not prove who they are. ``reason`` is for the operator.

    The message the caller receives is deliberately the same for every reason:
    telling an attacker whether the signature or the audience was wrong is
    telling them which half of their forgery to fix.
    """

    def __init__(self, reason: str, *, detail: str | None = None) -> None:
        super().__init__("the request is not authenticated")
        self.reason = reason
        self.diagnosis = detail or reason


class ProviderUnavailable(Exception):
    """The provider's document could not be fetched or parsed."""


@dataclass(frozen=True, slots=True)
class SigningKey:
    """One key the provider published, and what it is allowed to verify."""

    kid: str
    key_type: str
    key: Any
    algorithms: tuple[str, ...]


def fetch_json(url: str, *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """GET a JSON document. The one place this module opens a socket.

    Failures are converted here, with the URL and the failure kind, because a
    provider that is unreachable and a provider that answered nonsense need
    different operator responses and look identical from a stack trace.
    """
    request = urllib.request.Request(url, method="GET",
                                     headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_DOCUMENT_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise ProviderUnavailable(f"{url} answered HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise ProviderUnavailable(f"{url} could not be reached") from exc
    if len(body) > MAX_DOCUMENT_BYTES:
        raise ProviderUnavailable(f"{url} answered more than {MAX_DOCUMENT_BYTES} bytes")
    try:
        document = json.loads(body)
    except ValueError as exc:
        raise ProviderUnavailable(f"{url} did not answer JSON") from exc
    if not isinstance(document, dict):
        raise ProviderUnavailable(f"{url} did not answer a JSON object")
    return document


def parse_jwks(document: Mapping[str, Any]) -> dict[str, SigningKey]:
    """The usable signing keys out of a JWKS, keyed by ``kid``.

    Everything unusable is dropped with a log line rather than an exception: a
    provider publishing one encryption key beside three signing keys is normal,
    and refusing the whole set over it would take authentication down.
    """
    keys: dict[str, SigningKey] = {}
    for entry in document.get("keys") or ():
        if not isinstance(entry, dict):
            continue
        kid = entry.get("kid")
        key_type = entry.get("kty")
        use = entry.get("use")
        if not isinstance(kid, str) or not kid:
            log.warning("oidc.jwks_key_ignored", reason="no kid", kty=key_type)
            continue
        if key_type not in ALGORITHMS_BY_KEY_TYPE:
            # `oct` lands here, and that is the point: a symmetric key in a
            # JWKS is never a key this service will verify a token with.
            log.warning("oidc.jwks_key_ignored", kid=kid, kty=key_type,
                        reason="key type cannot verify an asymmetric signature")
            continue
        if use is not None and use != "sig":
            log.warning("oidc.jwks_key_ignored", kid=kid, use=use,
                        reason="the key is not published for signatures")
            continue
        allowed = ALGORITHMS_BY_KEY_TYPE[key_type]
        declared = entry.get("alg")
        if isinstance(declared, str):
            if declared not in allowed:
                log.warning("oidc.jwks_key_ignored", kid=kid, alg=declared,
                            reason="the declared algorithm does not match the key type")
                continue
            # A key that names its algorithm is held to it: the provider has
            # already narrowed the choice, and widening it back would be ours.
            allowed = (declared,)
        try:
            algorithm = RSAAlgorithm if key_type == "RSA" else ECAlgorithm
            key = algorithm.from_jwk(json.dumps(entry))
        except Exception as exc:  # a malformed entry, not a reason to fail the set
            log.warning("oidc.jwks_key_ignored", kid=kid, kty=key_type,
                        reason=f"unreadable: {type(exc).__name__}")
            continue
        keys[kid] = SigningKey(kid=kid, key_type=key_type, key=key,
                               algorithms=allowed)
    return keys


class JwksCache:
    """The provider's published signing keys, refreshed on a leash.

    Thread-safe: the API process serves requests from a thread pool, and two
    requests carrying a rotated ``kid`` must not become two fetches.
    """

    def __init__(self, url: str, *, ttl: float = JWKS_TTL_SECONDS,
                 min_refresh: float = MIN_REFRESH_SECONDS,
                 fetch: Callable[[str], Mapping[str, Any]] | None = None,
                 clock: Callable[[], float] | None = None) -> None:
        self.url = url
        self.ttl = ttl
        self.min_refresh = min_refresh
        self._fetch = fetch or (lambda target: fetch_json(target))
        self._clock = clock or _monotonic
        self._lock = threading.Lock()
        self._keys: dict[str, SigningKey] = {}
        self._fetched_at: float | None = None
        self.fetches = 0
        """How many times the provider was actually asked. Read by the test that
        proves an unknown ``kid`` does not become a fetch loop."""

    def get(self, kid: str) -> SigningKey:
        """The key with this id, refreshing at most once if it is not known."""
        with self._lock:
            now = self._clock()
            if self._fetched_at is None or now - self._fetched_at >= self.ttl:
                self._refresh(now)
            key = self._keys.get(kid)
            if key is not None:
                return key
            # Unknown: this is either a rotation or a forgery, and one refresh
            # tells them apart. Outside the window it is assumed to be the
            # second, because the alternative is a fetch per forged token.
            if self._fetched_at is None or now - self._fetched_at >= self.min_refresh:
                self._refresh(now)
                key = self._keys.get(kid)
                if key is not None:
                    log.info("oidc.jwks_rotated", kid=kid, keys=len(self._keys))
                    return key
            raise AuthenticationFailed(
                "unknown_kid", detail=f"no published signing key with kid {kid!r}")

    def _refresh(self, now: float) -> None:
        try:
            document = self._fetch(self.url)
        except ProviderUnavailable:
            log.exception("oidc.jwks_unavailable", url=self.url)
            # The previous set stays usable. A provider blip must not log every
            # holder of a valid token out; the set expires on its own TTL.
            self._fetched_at = now
            return
        self.fetches += 1
        # Replaced, never merged: a key the provider withdrew has to disappear.
        self._keys = parse_jwks(document)
        self._fetched_at = now
        log.info("oidc.jwks_fetched", url=self.url, keys=len(self._keys),
                 kids=sorted(self._keys))


def _monotonic() -> float:
    import time

    return time.monotonic()


def inspect_header(token: str) -> tuple[str, str]:
    """The algorithm and key id, having checked both, and nothing else.

    Split out of :meth:`BearerVerifier.verify` and called by
    :mod:`painfree.authn` *before* a verifier is built, so a forged token is
    refused without the provider being contacted at all. Otherwise an
    unauthenticated stream of ``alg: none`` tokens turns this service into an
    amplifier pointed at the identity provider -- which was visible the first
    time the running service was pointed at an unreachable one: the forgery
    came back `503` instead of `401`, because the discovery fetch happened first.
    """
    if not token or token.count(".") != 2:
        raise AuthenticationFailed("malformed_token",
                                   detail="not a three-part compact JWS")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise AuthenticationFailed(
            "malformed_header", detail=type(exc).__name__) from exc

    algorithm = header.get("alg")
    if algorithm not in ACCEPTED_ALGORITHMS:
        # `none` and `HS256` both end here, before a key exists to confuse.
        raise AuthenticationFailed(
            "algorithm_not_allowed",
            detail=f"the token asks to be verified with {algorithm!r}")

    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        # Required rather than guessed at. Selecting "the only key" works until
        # the provider publishes a second one, and then it fails during a
        # rotation, which is the worst possible moment.
        raise AuthenticationFailed("no_kid",
                                   detail="the token names no signing key")
    return algorithm, kid


class BearerVerifier:
    """Turns a bearer token into verified claims, or refuses to.

    ``issuer`` and ``audience`` are the configured ones, never the token's --
    a verifier that reads the issuer out of the thing it is verifying is not
    verifying anything.
    """

    def __init__(self, jwks: JwksCache, *, issuer: str, audience: str,
                 leeway: float = 60.0) -> None:
        self.jwks = jwks
        self.issuer = issuer
        self.audience = audience
        self.leeway = leeway

    def verify(self, token: str) -> dict[str, Any]:
        """Verified claims, or :class:`AuthenticationFailed`."""
        algorithm, kid = inspect_header(token)
        key = self.jwks.get(kid)
        if algorithm not in key.algorithms:
            raise AuthenticationFailed(
                "algorithm_key_mismatch",
                detail=f"kid {kid!r} is a {key.key_type} key and cannot "
                       f"perform {algorithm!r}")

        try:
            claims = jwt.decode(
                token,
                key=key.key,
                # The key's own algorithms, not the token's. The token has
                # already been held to the allowlist; this makes its `alg`
                # unable to influence the choice at all.
                algorithms=list(key.algorithms),
                issuer=self.issuer,
                audience=self.audience,
                leeway=self.leeway,
                options={"require": list(REQUIRED_CLAIMS),
                         "verify_signature": True, "verify_exp": True,
                         "verify_nbf": True, "verify_iat": True,
                         "verify_aud": True, "verify_iss": True},
            )
        except jwt.InvalidTokenError as exc:
            raise AuthenticationFailed(
                _REASONS.get(type(exc), "invalid_token"),
                detail=type(exc).__name__) from exc
        return dict(claims)


#: PyJWT's exception hierarchy, mapped to the reasons an operator wants in the
#: stream. Every one of these is a separate test.
_REASONS = {
    jwt.ExpiredSignatureError: "expired",
    jwt.ImmatureSignatureError: "not_yet_valid",
    jwt.InvalidIssuerError: "wrong_issuer",
    jwt.InvalidAudienceError: "wrong_audience",
    jwt.InvalidSignatureError: "bad_signature",
    jwt.MissingRequiredClaimError: "missing_claim",
    jwt.InvalidKeyError: "unusable_key",
}


def expiry_of(claims: Mapping[str, Any]) -> _dt.datetime | None:
    """The ``exp`` claim as an aware datetime, for the principal."""
    value = claims.get("exp")
    if not isinstance(value, (int, float)):
        return None
    return _dt.datetime.fromtimestamp(float(value), tz=_dt.timezone.utc)


__all__ = ["ACCEPTED_ALGORITHMS", "ALGORITHMS_BY_KEY_TYPE",
           "AuthenticationFailed", "BearerVerifier", "JwksCache",
           "ProviderUnavailable", "REQUIRED_CLAIMS", "SigningKey", "expiry_of",
           "fetch_json", "inspect_header", "parse_jwks"]
