"""JWT bearer verification, written as an attacker rather than as an author.

There is no reference implementation to diff against here, so nothing in this
file claims a match with one. What it claims is narrower and more useful: for
each known way of getting a JWT accepted that should not be, **this service**
refuses it. That the library says it would is not the assertion -- every attack
below is constructed against `painfree.tokens.BearerVerifier` and driven through
it.

The happy path is one test. The other twenty are forgeries.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json

import jwt
import pytest

from idp import CLIENT_ID, SUBJECT, StubProvider, b64url, now, serving_provider
from painfree import tokens
from painfree.tokens import AuthenticationFailed, BearerVerifier, JwksCache


@pytest.fixture
def provider() -> StubProvider:
    stub = StubProvider()
    stub.issuer = "https://id.example.test/realms/painfree"
    return stub


class CountingFetch:
    """Serves the provider's JWKS and counts how often it was asked."""

    def __init__(self, provider: StubProvider) -> None:
        self.provider = provider
        self.calls = 0

    def __call__(self, url: str) -> dict:
        self.calls += 1
        return self.provider.jwks()


def build(provider: StubProvider, *, ttl: float = 300.0, min_refresh: float = 30.0,
          clock=None) -> tuple[BearerVerifier, CountingFetch]:
    fetch = CountingFetch(provider)
    cache = JwksCache("https://id.example.test/jwks", ttl=ttl,
                      min_refresh=min_refresh, fetch=fetch, clock=clock)
    verifier = BearerVerifier(cache, issuer=provider.issuer, audience=CLIENT_ID)
    return verifier, fetch


def refused(verifier: BearerVerifier, token: str) -> AuthenticationFailed:
    with pytest.raises(AuthenticationFailed) as raised:
        verifier.verify(token)
    return raised.value


# --- the control ------------------------------------------------------------

def test_a_properly_signed_token_verifies(provider):
    """Everything below is a variation on this one, so it has to hold first."""
    verifier, _ = build(provider)
    claims = verifier.verify(provider.token())
    assert claims["sub"] == SUBJECT
    assert claims["iss"] == provider.issuer
    assert claims["roles"] == ["operator"]


def test_an_es256_token_verifies_too(provider):
    """Not every provider is on RSA, and the key type decides the algorithms."""
    provider.add_key("ec1", kind="EC")
    verifier, _ = build(provider)
    assert verifier.verify(provider.token(kid="ec1"))["sub"] == SUBJECT


# --- the two that break the whole model -------------------------------------

def test_an_unsigned_token_is_rejected(provider):
    """`alg: none`. Not "verified against nothing" -- refused at the header."""
    verifier, fetch = build(provider)
    failure = refused(verifier, provider.unsigned_token())
    assert failure.reason == "algorithm_not_allowed"
    assert failure.status_code == 401
    # It never even reached a key: the allowlist is checked before the lookup,
    # so a stream of these costs nothing.
    assert fetch.calls == 0


def test_algorithm_confusion_is_rejected(provider):
    """HS256 signed with the RSA public key as the HMAC secret.

    Everything the attacker needs is public. If the token were allowed to pick
    its algorithm this signature would verify, because the "secret" is the key
    the provider publishes. It is refused because `HS256` is not on the
    allowlist at all -- there is no code path in which an asymmetric key from a
    JWKS reaches an HMAC verifier.
    """
    verifier, _ = build(provider)
    forged = provider.confused_token()
    # The forgery really is well-formed and really does verify as HMAC under
    # the published key -- otherwise this test would pass for the wrong reason.
    import hashlib
    import hmac as _hmac
    header, payload, signature = forged.split(".")
    expected = b64url(_hmac.new(provider.public_pem("k1"),
                                f"{header}.{payload}".encode(),
                                hashlib.sha256).digest())
    assert signature == expected

    failure = refused(verifier, forged)
    assert failure.reason == "algorithm_not_allowed"


def test_a_symmetric_key_in_the_jwks_is_never_usable(provider):
    """A provider that publishes an `oct` key does not get one accepted here."""
    secret = b64url(b"a-shared-secret-that-should-never-verify-anything")
    provider.keys["hs1"] = {"private": None, "alg": "HS256",
                            "jwk": {"kty": "oct", "kid": "hs1", "k": secret,
                                    "use": "sig", "alg": "HS256"}}
    provider.published.append("hs1")

    parsed = tokens.parse_jwks(provider.jwks())
    assert "hs1" not in parsed
    assert "k1" in parsed, "one unusable entry must not discard the whole set"

    header = b64url(json.dumps({"alg": "HS256", "kid": "hs1"}).encode())
    body = b64url(json.dumps(provider.claims()).encode())
    import hashlib
    import hmac as _hmac
    raw = base64.urlsafe_b64decode(secret + "=" * (-len(secret) % 4))
    signature = b64url(_hmac.new(raw, f"{header}.{body}".encode(),
                                 hashlib.sha256).digest())
    verifier, _ = build(provider)
    assert refused(verifier, f"{header}.{body}.{signature}"
                   ).reason == "algorithm_not_allowed"


# --- the time and address claims, each on its own ---------------------------

def test_an_expired_token_is_rejected(provider):
    verifier, _ = build(provider)
    stale = now() - 3600
    assert refused(verifier, provider.token(iat=stale, exp=stale + 60)
                   ).reason == "expired"


def test_a_not_yet_valid_token_is_rejected(provider):
    """`nbf` in the future. Verified whenever it is present, never required."""
    verifier, _ = build(provider)
    assert refused(verifier, provider.token(nbf=now() + 3600)
                   ).reason == "not_yet_valid"


def test_a_token_from_the_wrong_issuer_is_rejected(provider):
    verifier, _ = build(provider)
    assert refused(verifier, provider.token(iss="https://evil.example.test/")
                   ).reason == "wrong_issuer"


def test_a_token_for_the_wrong_audience_is_rejected(provider):
    """A valid token addressed to another service is not a credential here."""
    verifier, _ = build(provider)
    assert refused(verifier, provider.token(aud="some-other-service")
                   ).reason == "wrong_audience"


def test_a_token_missing_a_required_claim_is_rejected(provider):
    verifier, _ = build(provider)
    assert refused(verifier, provider.token(sub=None)).reason == "missing_claim"


def test_the_clock_skew_allowance_is_bounded_and_applied(provider):
    """A token that expired one second ago still verifies inside the leeway."""
    verifier, _ = build(provider)
    verifier.leeway = 60.0
    assert verifier.verify(provider.token(exp=now() - 5))["sub"] == SUBJECT
    assert refused(verifier, provider.token(exp=now() - 600)).reason == "expired"


# --- keys -------------------------------------------------------------------

def test_a_token_signed_by_an_unrelated_key_is_rejected(provider):
    """The signature is real; the key is not one the provider published.

    The forger signs with their own RSA key and reuses a published `kid`, which
    is the only way to get as far as the signature check.
    """
    forger = StubProvider()
    forger.issuer = provider.issuer
    verifier, _ = build(provider)
    assert refused(verifier, forger.token(kid="k1")).reason == "bad_signature"


def test_a_token_naming_no_key_is_rejected(provider):
    verifier, _ = build(provider)
    claims = provider.claims()
    token = jwt.encode(claims, provider.keys["k1"]["private"], algorithm="RS256")
    assert "kid" not in jwt.get_unverified_header(token)
    assert refused(verifier, token).reason == "no_kid"


def test_an_unknown_kid_does_not_become_a_fetch_loop(provider):
    """Forty forged tokens, one extra refresh. The provider is not a target.

    The cooldown runs from the last fetch, so a burst of invented key ids
    against a fresh cache costs nothing at all, and a burst against a stale one
    costs exactly one request -- because the first of them might be a rotation
    and the other thirty-nine cannot be.
    """
    clock_reads = [0.0]
    verifier, fetch = build(provider, ttl=300.0, min_refresh=30.0,
                            clock=lambda: clock_reads[0])
    verifier.verify(provider.token())          # one fetch, to populate the cache
    assert fetch.calls == 1

    for index in range(20):
        # A genuinely signed token naming a key id the provider never
        # published: as far as the verifier can tell, either a rotation it has
        # not seen yet or a forgery.
        forged = jwt.encode(provider.claims(), provider.keys["k1"]["private"],
                            algorithm="RS256",
                            headers={"kid": f"invented-{index}"})
        assert refused(verifier, forged).reason == "unknown_kid"

    # Inside the cooldown, none of them is worth asking about.
    assert fetch.calls == 1, f"{fetch.calls} fetches for 20 forged key ids"

    clock_reads[0] = 100.0        # past the cooldown, still inside the TTL
    for index in range(20, 40):
        forged = jwt.encode(provider.claims(), provider.keys["k1"]["private"],
                            algorithm="RS256",
                            headers={"kid": f"invented-{index}"})
        assert refused(verifier, forged).reason == "unknown_kid"
    assert fetch.calls == 2, f"{fetch.calls} fetches for 40 forged key ids"


def test_a_rotated_key_is_accepted_after_one_refresh(provider):
    """A key published a minute ago verifies, and costs exactly one fetch."""
    verifier, fetch = build(provider, min_refresh=0.0)
    verifier.verify(provider.token())
    assert fetch.calls == 1

    provider.add_key("k2")
    token = provider.token(kid="k2")
    assert verifier.verify(token)["sub"] == SUBJECT
    assert fetch.calls == 2


def test_a_withdrawn_keys_token_stops_verifying(provider):
    """Revocation. The cached set is replaced, never merged."""
    clock_reads = [0.0]
    verifier, fetch = build(provider, ttl=300.0, min_refresh=0.0,
                            clock=lambda: clock_reads[0])
    provider.add_key("k2")
    signed_by_k1 = provider.token(kid="k1")
    assert verifier.verify(signed_by_k1)["sub"] == SUBJECT

    provider.withdraw("k1")
    clock_reads[0] = 1000.0
    # The TTL has passed, so the next verification refetches and `k1` is gone.
    assert refused(verifier, signed_by_k1).reason == "unknown_kid"
    assert verifier.verify(provider.token(kid="k2"))["sub"] == SUBJECT


def test_a_provider_outage_does_not_log_everyone_out(provider):
    """A JWKS that briefly fails to fetch leaves the previous set usable."""
    verifier, fetch = build(provider, ttl=0.0)
    assert verifier.verify(provider.token())["sub"] == SUBJECT

    def broken(url: str) -> dict:
        raise tokens.ProviderUnavailable("the provider is down")

    verifier.jwks._fetch = broken
    assert verifier.verify(provider.token())["sub"] == SUBJECT


# --- what a rejection says --------------------------------------------------

def test_no_rejection_ever_quotes_the_token(provider):
    """Every failure message and reason, across every attack, holds no token."""
    verifier, _ = build(provider)
    forgeries = [
        provider.unsigned_token(),
        provider.confused_token(),
        provider.token(exp=now() - 3600, iat=now() - 3700),
        provider.token(iss="https://evil.example.test/"),
        provider.token(aud="elsewhere"),
        StubProvider().token(kid="k1"),
    ]
    for forged in forgeries:
        failure = refused(verifier, forged)
        rendered = f"{failure.message} {failure.reason} {failure.diagnosis}"
        for part in forged.split("."):
            if len(part) > 8:
                assert part not in rendered
        # The caller is told nothing about which check failed.
        assert failure.message == "the request is not authenticated"


def test_the_reason_is_specific_enough_to_diagnose(provider):
    """The operator's half of the same rule: every failure is distinguishable."""
    verifier, _ = build(provider)
    reasons = {
        refused(verifier, provider.unsigned_token()).reason,
        refused(verifier, provider.token(exp=now() - 3600, iat=now() - 3700)).reason,
        refused(verifier, provider.token(nbf=now() + 600)).reason,
        refused(verifier, provider.token(iss="https://evil.example.test/")).reason,
        refused(verifier, provider.token(aud="elsewhere")).reason,
        refused(verifier, StubProvider().token(kid="k1")).reason,
    }
    assert len(reasons) == 6, reasons


def test_a_token_that_is_not_a_token_is_rejected_without_a_stack_trace(provider):
    verifier, _ = build(provider)
    for rubbish in ("", "not-a-token", "a.b", "a.b.c.d"):
        assert refused(verifier, rubbish).reason in {"malformed_token",
                                                     "malformed_header"}


# --- against a real socket --------------------------------------------------

def test_the_jwks_is_fetched_and_used_over_http(provider):
    """The fetch path itself, not a substituted one."""
    with serving_provider(provider) as issuer:
        cache = JwksCache(f"{issuer}/jwks")
        verifier = BearerVerifier(cache, issuer=issuer, audience=CLIENT_ID)
        assert verifier.verify(provider.token())["sub"] == SUBJECT
        assert provider.jwks_requests == 1


def test_an_unreachable_jwks_is_a_refusal_not_a_crash():
    cache = JwksCache("http://127.0.0.1:1/jwks", ttl=0.0)
    verifier = BearerVerifier(cache, issuer="https://x.test", audience="c")
    with pytest.raises(AuthenticationFailed) as raised:
        verifier.verify("a.b.c")
    assert raised.value.reason in {"malformed_token", "malformed_header",
                                   "unknown_kid"}
