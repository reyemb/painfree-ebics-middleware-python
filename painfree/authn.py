"""How a request acquires an identity, and how a route demands a privilege.

Three things live here, and they are together because they are one rule seen
from three sides.

**Deny by default.** A middleware runs before every route. Unless the path is in
:data:`PUBLIC_PATHS` -- the two orchestrator probes and the three endpoints of
the login flow itself, and nothing else -- the request must carry a credential
that resolves to a :class:`~painfree.identity.Principal`, or it is refused with
`401` before the route is reached. That is deliberately not a per-route
decorator: a decorator forgotten on a new route is a public endpoint, and the
whole point of ``tests/test_service_authz.py`` enumerating every route is to
show that no such endpoint exists. Here, forgetting something makes a route
*inaccessible*, which is a bug that is found immediately.

**One identity, four ways of proving it.** A bearer token
(:mod:`painfree.tokens`), an HTTP Basic credential checked against this
deployment's own accounts (:mod:`painfree.accounts`), a browser session cookie
(:mod:`painfree.oidc`), or -- only in the development mode production refuses to
start with -- a header. All four produce the same ``Principal``, so
authorisation below this line has one code path and cannot be more permissive
for one of them by accident. Which of them is *offered* is decided once, at
startup, by ``PAINFREE_AUTH_MODE``: the service accepts one kind of credential
and never two, because a service that accepts two is a service whose security is
the weaker of them.

**Basic authenticates a browser through a form, and a machine through the
header.** The distinction is the honest answer to a real limitation and not a
convenience: a browser that has answered a native ``WWW-Authenticate: Basic``
dialog re-sends that credential until every window of it is closed, so a *sign
out* button in a console authenticated that way would be a button that lies. So
``GET /auth/login`` renders a form, the form's submission establishes the same
revocable ``user_session`` an OIDC sign-in establishes, and signing out revokes
it and works. The API keeps pure Basic, where there is no logout to get wrong: a
machine holds its credential deliberately. What remains -- a browser that got
the native dialog anyway, by opening a `/v1` URL in the address bar -- is handled
by :data:`SIGNED_OUT_COOKIE` and stated in the ADR rather than papered over.

**Scopes are demanded per route, and connections are demanded per object.**
``Depends(requires(Scope.payments_submit))`` is what separates a `403` from a
`401`: the caller is known, and is not allowed to do this *anywhere*. On a route
that names a connection, ``requires_on(...)`` asks the narrower question -- may
this caller submit a payment **at this bank** -- and on a route that names an
opaque id instead, the handler loads the row and asks
:func:`painfree.access.require` with the connection the row turned out to
belong to. The last of those is the only one that stops a member reaching
another connection's order by guessing its id, because by then the route-level
check has already passed.

Two things are deliberately *not* here. There is no audit row per rejected
authentication -- unauthenticated traffic is unbounded and an append-only table
is not the place to absorb it, so a rejection is a ``warning`` in the log stream
with its reason and the path, and nothing more. And there is no token, code, or
cookie in any line this module emits: what is logged is the *reason*, the
subject where one is known, and a 12-character digest prefix where one value has
to be traceable across two lines.
"""

from __future__ import annotations

import base64
import binascii
import urllib.parse
from typing import Any, Callable

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from painfree import access, accounts, identity, oidc, tokens
from painfree.audit import Actor, AuditLog
from painfree.config import AuthMode, Environment, Settings
from painfree.errors import ForbiddenError, ServiceError, error_body
from painfree.identity import Principal, Scope
from painfree.logging import context, get_logger
from painfree.tokens import AuthenticationFailed

log = get_logger("painfree.authn")

#: Reachable without a credential, and nothing else is. The probes answer an
#: orchestrator, which has no identity provider; the login endpoints are how an
#: identity is obtained, so requiring one would be a loop.
PUBLIC_PATHS = frozenset({
    "/healthz", "/readyz", "/auth/login", "/auth/callback", "/auth/logout",
})

BEARER_PREFIX = "bearer "
BASIC_PREFIX = "basic "

#: Set by ``GET /auth/logout`` in the ``basic`` mode and cleared by the sign-in
#: page. It exists for one case: a browser that answered a native
#: ``WWW-Authenticate: Basic`` dialog -- by opening a `/v1` URL in the address
#: bar, say -- caches the credential and re-sends it, so signing out and being
#: signed straight back in is what would otherwise happen. While this cookie is
#: present a Basic *header* establishes nothing in a browser navigation.
#:
#: It is a marker and not a security boundary, and the signed-out page says so:
#: the browser still holds the password, deleting the cookie is one menu away,
#: and closing the browser is the only thing that actually ends it.
SIGNED_OUT_COOKIE = "pf_signed_out"

#: How long that marker lasts. Long enough to cover a working day on a shared
#: machine; short enough that a cookie nobody cleared does not lock somebody out
#: of an API client that sends a Basic header and keeps a cookie jar.
SIGNED_OUT_MAX_AGE = 12 * 60 * 60

#: Paths a human navigates to rather than a program calls: the operator console
#: (:mod:`painfree.ui`) and the root it redirects from. A `401` on one of these
#: is answered with a redirect into the login flow, because no browser renders a
#: JSON error envelope and a login page is what the person wanted anyway. The
#: `Accept` header decides as well as the path, so a client that fetches a
#: console URL still gets the envelope it can parse.
BROWSER_PREFIXES = ("/ui",)

#: Development mode only. Named so that seeing it in a production log line is
#: itself the alarm -- though production refuses to start in that mode at all.
DEV_PRINCIPAL_HEADER = "X-Painfree-Dev-Principal"
DEV_ROLES_HEADER = "X-Painfree-Dev-Roles"


class Authenticator:
    """Resolves a request to a principal, by whichever means is configured."""

    def __init__(self, settings: Settings, engine: Any, *,
                 audit: AuditLog | None = None,
                 directory: oidc.ProviderDirectory | None = None,
                 jwks: tokens.JwksCache | None = None) -> None:
        self.settings = settings
        self.mode = settings.auth_mode
        # Grants are read here, per request, and never copied into a session
        # row: a revocation has to take effect on the next request rather than
        # the next sign-in. "Grants" is both kinds -- the per-connection ones
        # and the deployment-wide oversight flag -- and `reach_for` returns
        # them together so neither can be forgotten.
        self.grants = access.Grants(engine)
        self.sessions = oidc.SessionStore(
            engine, ttl_minutes=settings.session_ttl_minutes)
        self.logins = oidc.LoginStore(
            engine, ttl_seconds=settings.login_ttl_seconds)
        self.directory = directory
        self.jwks = jwks
        self._bearer: tokens.BearerVerifier | None = None
        self._id_token: tokens.BearerVerifier | None = None
        if self.mode is AuthMode.oidc:
            self.directory = directory or oidc.ProviderDirectory(
                str(settings.oidc_issuer))
        # Built in every mode, not only in `basic`. The store is also the
        # administrative surface -- an operator managing accounts before
        # switching a deployment over to them is a reasonable thing to do -- and
        # what decides whether a password is *accepted* is `resolve` below,
        # which never reaches this object outside the `basic` mode.
        self.accounts = accounts.Accounts(
            engine, audit,
            subject_threshold=settings.basic_lockout_threshold,
            source_threshold=settings.basic_source_lockout_threshold,
            window_minutes=settings.basic_lockout_window_minutes,
            lockout_minutes=settings.basic_lockout_minutes)

    # --- verifiers ----------------------------------------------------------

    def _verifiers(self) -> tuple[tokens.BearerVerifier, tokens.BearerVerifier]:
        """The access-token and `id_token` verifiers, built once, sharing a JWKS.

        Two of them because they check different audiences: an `id_token` is
        addressed to this client by definition, while an access token's audience
        is whatever the provider was told the resource is. One verifier with a
        widened audience would accept an `id_token` as an access token, which is
        the confusion this separation exists to prevent.
        """
        if self._bearer is None or self._id_token is None:
            settings = self.settings
            metadata = self.metadata()
            if self.jwks is None:
                self.jwks = tokens.JwksCache(metadata.jwks_uri)
            self._bearer = tokens.BearerVerifier(
                self.jwks, issuer=metadata.issuer, audience=settings.audience,
                leeway=float(settings.oidc_clock_skew_seconds))
            self._id_token = tokens.BearerVerifier(
                self.jwks, issuer=metadata.issuer,
                audience=str(settings.oidc_client_id),
                leeway=float(settings.oidc_clock_skew_seconds))
        return self._bearer, self._id_token

    def id_token_verifier(self) -> tokens.BearerVerifier:
        """The verifier an `id_token` is held to: audience is the client id."""
        return self._verifiers()[1]

    def metadata(self) -> oidc.ProviderMetadata:
        if self.directory is None:
            raise ServiceError("no identity provider is configured")
        return self.directory.metadata()

    # --- resolution ---------------------------------------------------------

    @property
    def scheme(self) -> str:
        """The one authentication scheme this process accepts, capitalised.

        One, never a list. A `401` that advertised both `Bearer` and `Basic`
        would be telling a caller that either works, and the whole point of
        resolving the mode once at startup is that only one does.
        """
        return "Basic" if self.mode is AuthMode.basic else "Bearer"

    @property
    def challenge(self) -> str:
        """The ``WWW-Authenticate`` value a `401` from this process carries.

        ``charset="UTF-8"`` on the Basic challenge is RFC 7617's only parameter
        besides the realm, and it is the difference between a password with an
        umlaut in it working and working on some clients.
        """
        if self.mode is AuthMode.basic:
            return 'Basic realm="painfree", charset="UTF-8"'
        return 'Bearer realm="painfree"'

    def resolve(self, request: Request) -> Principal:
        """The caller behind this request, or :class:`AuthenticationFailed`.

        Order is fixed: an explicit ``Authorization`` header wins over a cookie,
        so a browser session cannot silently rescue a bearer token that failed.
        The one exception is the signed-out marker, and it only ever *refuses* --
        see :data:`SIGNED_OUT_COOKIE`.
        """
        header = request.headers.get("authorization")
        if header:
            lowered = header.lower()
            if lowered.startswith(BEARER_PREFIX):
                return self.from_bearer(header[len(BEARER_PREFIX):].strip())
            if lowered.startswith(BASIC_PREFIX):
                return self.from_basic(header[len(BASIC_PREFIX):].strip(),
                                       request)
            raise AuthenticationFailed(
                "unsupported_scheme",
                detail=f"only the {self.scheme} scheme is accepted")

        cookie = request.cookies.get(oidc.SESSION_COOKIE)
        if cookie:
            return self.from_session(cookie)

        if self.mode is AuthMode.development:
            return self.from_development(request)

        raise AuthenticationFailed(
            "no_credential",
            detail=f"no {self.scheme} credential and no session cookie")

    def from_basic(self, credential: str, request: Request) -> Principal:
        """An HTTP Basic credential, against this deployment's own accounts.

        Four refusals happen before a password is ever looked at, and the order
        is the order they cost:

        1. **The mode.** A `Basic` header in a deployment authenticated by a
           provider is refused outright rather than falling through to something
           else, for the reason in the module docstring.
        2. **Plaintext.** In production, a request the proxy tells us arrived
           over `http` is refused with its credential unread. The startup
           refusal in :mod:`painfree.config` is the primary control -- this one
           catches the proxy that was reconfigured afterwards, and it can only
           refuse, never admit, so a forged `X-Forwarded-Proto: https` buys
           nothing.
        3. **The signed-out marker**, on a browser navigation only.
        4. **The shape.** Base64 of ``name:password``, one colon, and a name
           that is not empty.
        """
        if self.mode is not AuthMode.basic:
            raise AuthenticationFailed(
                "basic_not_configured",
                detail="this deployment authenticates against an identity "
                       "provider; the Basic scheme is not accepted")
        if self._is_plaintext(request):
            log.error("auth.plaintext_refused", path=request.url.path,
                      reason="a Basic credential arrived over a connection the "
                             "proxy reports as http; it is refused unread, and "
                             "the credential must be treated as disclosed")
            raise AuthenticationFailed(
                "plaintext_refused",
                detail="a Basic credential must not cross a plaintext hop")
        if (SIGNED_OUT_COOKIE in request.cookies
                and is_browser_navigation(request)):
            raise AuthenticationFailed(
                "signed_out",
                detail="this browser signed out; the credential it is still "
                       "sending establishes nothing until it signs in again")
        subject, password = decode_basic(credential)
        account = self.accounts.authenticate(
            subject, password, source=source_of(request, self.settings))
        return self.principal_for(account, method=identity.BASIC)

    def principal_for(self, account: accounts.Account, *,
                      method: str) -> Principal:
        """One local account, as the same principal a token would have produced.

        The account decides the *role* -- which is exactly what a provider's
        roles claim decides -- and everything else comes from the grants, read
        here on this request. There is no branch below this line that knows a
        password was involved.
        """
        reach = self.grants.reach_for(account.subject)
        # Deliberately *not* mapped through `admin_role_names`. That setting
        # says what somebody else's directory calls an administrator; a local
        # account's role is this service's own enum value, written by
        # `create-admin`. A deployment that renames the directory group would
        # otherwise demote every account it issued itself.
        return identity.build_principal(
            subject=account.subject, issuer=identity.LOCAL_ISSUER,
            method=method, roles=(account.role.value,),
            grants=reach.grants, oversight=reach.oversight,
            display_name=account.display_name)

    def _is_plaintext(self, request: Request) -> bool:
        """Does the proxy in front say this request arrived over `http`?

        Only meaningful when there *is* a proxy in front, which is the thing
        ``PAINFREE_TLS_TERMINATED_UPSTREAM`` asserts. Absent header, absent
        answer: this returns ``False`` and the startup refusal is what stands.
        """
        if (self.settings.environment is not Environment.production
                or not self.settings.tls_terminated_upstream):
            return False
        forwarded = request.headers.get("x-forwarded-proto", "")
        # A proxy chain appends, so the scheme the *nearest* one saw is the last
        # entry. Anything but https, stated, is a refusal.
        scheme = forwarded.split(",")[-1].strip().lower()
        return bool(scheme) and scheme != "https"

    def from_bearer(self, token: str) -> Principal:
        if self.mode is not AuthMode.oidc:
            raise AuthenticationFailed(
                "bearer_not_configured",
                detail="no identity provider is configured to verify a token against")
        # Before the provider is consulted: an unsigned or HMAC token, or one
        # naming no key, is refused here and costs no outbound request.
        tokens.inspect_header(token)
        verifier, _ = self._verifiers()
        claims = verifier.verify(token)
        return self.principal_from_claims(claims, method=identity.BEARER)

    def from_session(self, session_id: str) -> Principal:
        session = self.sessions.lookup(session_id)
        reach = self.grants.reach_for(session.subject)
        return identity.build_principal(
            subject=session.subject, issuer=session.issuer,
            method=identity.SESSION, roles=session.roles,
            grants=reach.grants, oversight=reach.oversight,
            admin_names=self.settings.admin_role_names,
            expires_at=session.expires_at, display_name=session.display_name)

    def from_development(self, request: Request) -> Principal:
        """The development story: a header, and never in production.

        It is still an *authentication step* -- a request with no header is
        refused, exactly as one with no token would be -- so the deny-by-default
        property being tested is the same property that holds in production.
        """
        subject = (request.headers.get(DEV_PRINCIPAL_HEADER)
                   or "").strip() or None
        roles_header = request.headers.get(DEV_ROLES_HEADER)
        if subject is None:
            raise AuthenticationFailed(
                "no_credential",
                detail=f"development mode expects a {DEV_PRINCIPAL_HEADER} header")
        roles = identity.string_list(roles_header if roles_header is not None
                                     else self.settings.dev_roles)
        # The grants come out of the database, not out of a header. Development
        # mode fabricates an *identity*; access is this deployment's own data
        # and reading it from anywhere else would leave the per-connection half
        # of the model untested by everything that runs in this mode. The same
        # goes for oversight, which is why no header confers it either.
        reach = self.grants.reach_for(subject)
        return identity.build_principal(
            subject=subject, issuer="painfree-development",
            method=identity.DEVELOPMENT, roles=roles,
            grants=reach.grants, oversight=reach.oversight,
            admin_names=self.settings.admin_role_names)

    def principal_from_claims(self, claims: dict[str, Any], *,
                              method: str) -> Principal:
        """Verified claims to privileges. See :mod:`painfree.identity` for the rule."""
        settings = self.settings
        raw_roles = identity.claim_at(claims, settings.oidc_roles_claim)
        claimed = identity.string_list(raw_roles)
        # The door. Everything downstream -- the principal, the session row, the
        # audit trail -- sees only the names this deployment maps, and the rest
        # survives as a count. See `identity.recognised_roles`.
        roles, unrecognised = identity.recognised_roles(
            claimed, settings.known_role_names)
        raw_scopes = identity.claim_at(claims, settings.oidc_scope_claim)
        requested = (identity.string_list(raw_scopes)
                     if raw_scopes is not None else None)
        subject = str(claims.get("sub"))
        if not claimed:
            # Nothing at all, which is the most likely first-run outcome and
            # had been the quietest. Keycloak's realm-roles mapper ships with
            # "Add to ID token" *off*, and this service reads the id_token for
            # browser sessions -- so a correctly assigned administrator signs
            # in holding nothing, successfully, with no line to read. The claim
            # path is configuration, so it can be quoted back: an operator who
            # sees it named against a token that did not carry it knows to look
            # at the mapper rather than at their directory.
            log.warning(
                "auth.no_roles_in_token", claim=settings.oidc_roles_claim,
                subject=subject,
                present=raw_roles is not None,
                reason="the configured roles claim carried no names, so this "
                       "caller is a member holding nothing; a provider must "
                       "put roles in the id_token, and Keycloak keeps realm "
                       "roles out of it unless the realm roles mapper has "
                       "'Add to ID token' enabled")
        elif not roles:
            # The directory answered, and none of it was ours. This is the case
            # that actually indicates a misconfigured role name, so it is the
            # one that keeps `warning`.
            log.warning("auth.unmapped_roles", subject=subject,
                        claim=settings.oidc_roles_claim,
                        unrecognised_role_count=unrecognised,
                        known=sorted(settings.known_role_names),
                        reason="the provider granted names, none of which this "
                               "deployment maps; this caller is a member "
                               "holding nothing")
        elif unrecognised:
            # A shared realm carrying somebody else's roles alongside ours is
            # the ordinary case, not a fault, and a warning on every login is
            # not a diagnostic. Info, and a count.
            log.info("auth.unmapped_roles", subject=subject,
                     unrecognised_role_count=unrecognised,
                     reason="names this deployment does not map travelled with "
                            "ones it does; they grant nothing and are not kept")
        reach = self.grants.reach_for(subject)
        principal = identity.build_principal(
            subject=subject,
            issuer=str(claims.get("iss")),
            method=method,
            roles=roles,
            grants=reach.grants,
            oversight=reach.oversight,
            requested=requested,
            unrecognised_roles=unrecognised,
            admin_names=self.settings.admin_role_names,
            token_id=claims.get("jti"),
            expires_at=tokens.expiry_of(claims),
            display_name=claims.get("name") or claims.get("preferred_username"),
        )
        if principal.narrowed:
            # The grants said one thing and the token said less. Legitimate --
            # that is what a narrowed token is for -- and worth a line either
            # way, because the symptom of an accidental one is a correct grant
            # and an empty console with nothing to read.
            log.info("auth.scopes_narrowed", subject=subject,
                     claim=settings.oidc_scope_claim,
                     scopes=sorted(scope.value for scope in principal.scopes),
                     reason="the token's scope claim named scopes of this "
                            "service and this caller holds only those, which "
                            "is fewer than its grants carry")
        return principal


# --- reading a Basic credential ---------------------------------------------

def decode_basic(credential: str) -> tuple[str, str]:
    """``base64(name:password)`` as its two halves, or a refusal.

    Every failure here is the same :class:`AuthenticationFailed` a wrong
    password is, so a caller probing the header's shape gets the sentence a
    caller probing a password gets. The value is never quoted back, in the
    exception, in a log line or in the traceback that carries either.

    The password half may contain colons and is taken verbatim -- RFC 7617
    splits on the *first* one -- and it may be empty, which is an ordinary wrong
    password and is refused by the hash comparison like any other.
    """
    try:
        raw = base64.b64decode(credential, validate=True)
        decoded = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        raise AuthenticationFailed(
            "malformed_credential",
            detail="the Basic credential is not base64-encoded UTF-8") from None
    if ":" not in decoded:
        raise AuthenticationFailed(
            "malformed_credential",
            detail="a Basic credential is a name, a colon and a password")
    subject, _, password = decoded.partition(":")
    subject = subject.strip()
    if not subject:
        raise AuthenticationFailed(
            "malformed_credential", detail="the Basic credential names nobody")
    return subject, password


def source_of(request: Request, settings: Settings) -> str | None:
    """Which address this request is throttled against.

    The forwarded address is trusted **only** where the deployment has said
    there is a proxy in front of it, because otherwise the header is a field the
    caller writes -- and a per-source lockout keyed on a value the source chooses
    is not a lockout. A chain appends, so the nearest proxy's view of the client
    is the last entry.
    """
    if settings.tls_terminated_upstream:
        nearest = request.headers.get("x-forwarded-for", "").split(",")[-1].strip()
        if nearest:
            return nearest[:255]
    return request.client.host[:255] if request.client else None


# --- the middleware ---------------------------------------------------------

def is_public(path: str) -> bool:
    return path in PUBLIC_PATHS


def install_authentication(app: Any, settings: Settings) -> None:
    """Add the deny-by-default middleware. Called by :func:`painfree.app.create_app`."""

    @app.middleware("http")
    async def authenticate(request: Request, call_next: Any) -> Any:
        if is_public(request.url.path):
            return await call_next(request)
        authenticator: Authenticator = request.app.state.authenticator
        try:
            principal = authenticator.resolve(request)
        except AuthenticationFailed as exc:
            return _refused(request, exc)
        except (ServiceError, tokens.ProviderUnavailable) as exc:
            # The provider is unreachable, or its discovery document does not
            # name the issuer this service was configured for. Neither is the
            # caller's fault and neither is a `401`: a `503` is what an
            # orchestrator and an operator can both act on.
            log.exception("auth.unavailable", path=request.url.path,
                          reason=str(exc))
            return JSONResponse(
                status_code=503,
                content=error_body("not_ready",
                                   "authentication is not available",
                                   request_id=context().get("request_id")))
        request.state.principal = principal
        log.debug("auth.accepted", subject=principal.subject,
                  method=principal.method, path=request.url.path)
        return await call_next(request)


def is_browser_navigation(request: Request) -> bool:
    """Would this request be better answered with a page than with JSON?"""
    path = request.url.path
    return ("text/html" in request.headers.get("accept", "")
            and (path == "/" or path.startswith(BROWSER_PREFIXES)))


def _refused(request: Request, exc: AuthenticationFailed) -> Response:
    """One log line with everything needed to diagnose it, and no credential."""
    authenticator: Authenticator | None = getattr(
        request.app.state, "authenticator", None)
    log.warning("auth.rejected", reason=exc.reason, detail=exc.diagnosis,
                method=request.method, path=request.url.path,
                scheme_present="authorization" in request.headers,
                session_cookie_present=oidc.SESSION_COOKIE in request.cookies)
    if request.method == "GET" and is_browser_navigation(request):
        # Not a weaker check: the request is still refused. It is refused with
        # the one thing a browser can act on. `safe_redirect` on the way back
        # keeps `next` a relative path, so this is not an open redirect.
        target = urllib.parse.quote(oidc.safe_redirect(
            request.url.path + (f"?{request.url.query}" if request.url.query else "")),
            safe="/?=&")
        return RedirectResponse(f"/auth/login?next={target}", status_code=303)
    headers = dict(exc.headers or {})
    if authenticator is not None:
        # The scheme a caller should retry with is the one this process
        # actually accepts. A `401` advertising `Bearer` to a client that has
        # only a password is a client that never works out why.
        headers["WWW-Authenticate"] = authenticator.challenge
    return JSONResponse(
        status_code=exc.status_code,
        content=error_body(exc.code, exc.message,
                           request_id=context().get("request_id")),
        headers=headers,
    )


# --- demanding a privilege --------------------------------------------------

def principal_of(request: Request) -> Principal:
    """The principal the middleware resolved. A dependency in its own right."""
    principal = getattr(request.state, "principal", None)
    if principal is None:  # pragma: no cover - the middleware refuses first
        raise AuthenticationFailed("no_principal")
    return principal


def requires(*scopes: Scope) -> Callable[[Request], Principal]:
    """A dependency that demands these scopes and returns the principal.

    The scopes are hung on the returned callable as ``required_scopes`` so the
    developer page can read the privilege each route needs off the application
    itself (:func:`painfree.ui.reference.protected_routes`). A hand-written
    table of "which scope does this endpoint need" is a table that is wrong the
    first time a route is added, and the question it answers -- *why did I get
    a 403* -- is one an operator asks about the route they were refused.
    """

    def dependency(request: Request) -> Principal:
        principal = principal_of(request)
        missing = [scope for scope in scopes if not principal.has(scope)]
        if missing:
            names = sorted(scope.value for scope in missing)
            log.warning("auth.forbidden", subject=principal.subject,
                        method=principal.method, path=request.url.path,
                        roles=list(principal.roles), missing=names)
            raise ForbiddenError(
                "the caller does not hold the privilege this needs",
                detail={"missing_scopes": names,
                        "held_scopes": sorted(s.value for s in principal.scopes)})
        return principal

    dependency.required_scopes = tuple(scopes)  # type: ignore[attr-defined]
    return dependency


def requires_on(*scopes: Scope, what: str = "bank connection"
                ) -> Callable[[Request], Principal]:
    """Demand these scopes **on the connection this route names**.

    For a route whose path carries ``{connection_id}``. It is the same question
    :func:`requires` asks, narrowed to one bank: a member holding
    `payments:submit` at one connection passes ``requires`` on every payment
    route and must still be refused at every other bank.

    The refusal is :func:`painfree.access.require`'s: `404` when the caller
    holds no grant on the connection, `403` naming the scope when they hold the
    connection and not the privilege. A caller who was never given a bank is
    told nothing about it, including whether it exists.
    """

    def dependency(request: Request) -> Principal:
        principal = principal_of(request)
        connection_id = request.path_params.get("connection_id")
        access.require(principal, connection_id, *scopes, what=what)
        return principal

    dependency.required_scopes = tuple(scopes)  # type: ignore[attr-defined]
    # Read by the developer page, so the privilege table says *on that
    # connection* rather than implying the scope is held globally.
    dependency.per_connection = True  # type: ignore[attr-defined]
    return dependency


# --- the login flow ---------------------------------------------------------

router = APIRouter(prefix="/auth", tags=["authentication"])


def _authenticator(request: Request) -> Authenticator:
    return request.app.state.authenticator


def _set_session_cookie(response: Response, session: oidc.Session,
                        settings: Settings) -> None:
    response.set_cookie(
        oidc.SESSION_COOKIE, session.session_id, httponly=True,
        secure=settings.cookies_are_secure, samesite="lax", path="/",
        max_age=settings.session_ttl_minutes * 60)


def _sign_in_page(request: Request, *, target: str, error: str | None,
                  status_code: int = 200) -> Response:
    """The console's own sign-in form. Imported late, to keep one direction.

    :mod:`painfree.ui.rendering` imports this module for `principal_of`, so the
    import goes the other way here rather than at the top. The same shape
    :func:`painfree.app._service_error` uses for the console's error page.
    """
    from painfree.ui.rendering import render

    authenticator = _authenticator(request)
    return render(
        request, "sign_in.html", status_code=status_code, next=target,
        error=error,
        # Said out loud on purpose. A deployment that has migrated and never run
        # `create-admin` refuses every credential offered to it, and an operator
        # staring at a form that rejects everything should be told that no
        # account exists rather than left to guess at a password nobody set.
        # It discloses that this deployment is not bootstrapped yet, and there
        # is nothing to do with that fact: no credential works either way.
        accounts_exist=authenticator.accounts.count() > 0)


def _established(request: Request, principal: Principal,
                 target: str, *, mode: str) -> Response:
    """One verified identity, as the session the browser carries from here on.

    The same ``user_session`` row an OIDC sign-in creates, revocable in the same
    way and by the same endpoint. That is what makes signing out of the console
    mean something under a scheme that has no logout of its own.
    """
    authenticator = _authenticator(request)
    settings: Settings = request.app.state.settings
    session = authenticator.sessions.create(
        subject=principal.subject, issuer=principal.issuer,
        roles=principal.roles, display_name=principal.display_name)
    request.app.state.audit.record(
        "auth.session_established", actor=principal.actor(),
        detail={"mode": mode, "roles": list(principal.roles),
                "scopes": sorted(scope.value for scope in principal.scopes)})
    response = RedirectResponse(target, status_code=303)
    _set_session_cookie(response, session, settings)
    response.delete_cookie(SIGNED_OUT_COOKIE, path="/")
    return response


@router.get("/login", summary="Begin browser sign-in")
def login(request: Request, next: str = "/") -> Response:
    """Send the browser to the provider, ask it for a password, or wave it in."""
    authenticator = _authenticator(request)
    settings: Settings = request.app.state.settings
    target = oidc.safe_redirect(next)

    if authenticator.mode is AuthMode.basic:
        signed_out = SIGNED_OUT_COOKIE in request.cookies
        header = request.headers.get("authorization", "")
        if header.lower().startswith(BASIC_PREFIX) and not signed_out:
            # A caller that presented the credential without being asked: a
            # command-line client, or a browser that answered a native dialog
            # somewhere else in this service. Both get the same session.
            principal = authenticator.principal_for(
                authenticator.accounts.authenticate(
                    *decode_basic(header[len(BASIC_PREFIX):].strip()),
                    source=source_of(request, settings)),
                method=identity.SESSION)
            return _established(request, principal, target, mode="basic")
        response = _sign_in_page(request, target=target, error=None)
        if signed_out:
            # Asking to sign in is the end of having signed out. Cleared on the
            # response that carries the form, so the next submission is honoured
            # even though the browser is still sending the old credential.
            response.delete_cookie(SIGNED_OUT_COOKIE, path="/")
        return response

    if authenticator.mode is AuthMode.development:
        # The development story has to work in a browser too, or the UI is only
        # testable against a live provider. Production never reaches this line:
        # it refuses to start in this mode.
        roles = identity.string_list(settings.dev_roles)
        session = authenticator.sessions.create(
            subject=settings.dev_subject, issuer="painfree-development",
            roles=roles, display_name=settings.dev_subject)
        request.app.state.audit.record(
            "auth.session_established",
            actor=Actor(identity.ACTOR_TYPES[identity.DEVELOPMENT],
                        settings.dev_subject),
            detail={"mode": "development", "roles": list(roles)})
        response = RedirectResponse(target, status_code=303)
        _set_session_cookie(response, session, settings)
        return response

    state, nonce, verifier = authenticator.logins.begin(redirect_to=target)
    url = oidc.authorization_url(
        authenticator.metadata(), client_id=str(settings.oidc_client_id),
        redirect_uri=str(settings.oidc_redirect_uri), state=state, nonce=nonce,
        verifier=verifier)
    log.info("auth.login_started", state_digest=oidc.digest(state)[:12],
             redirect_to=target)
    response = RedirectResponse(url, status_code=303)
    # The browser-binding half of the state check. Short-lived, and cleared on
    # the callback whatever the outcome.
    response.set_cookie(oidc.LOGIN_COOKIE, state, httponly=True,
                        secure=settings.cookies_are_secure, samesite="lax",
                        path="/auth", max_age=settings.login_ttl_seconds)
    return response


@router.post("/login", summary="Sign in with an account name and a password")
async def sign_in(request: Request) -> Response:
    """The console's sign-in form, and the reason there is a form at all.

    ``async``, so the body can be read; the database work underneath it is one
    Argon2 verification and two small statements, which is the same shape the
    OIDC callback already has.

    A refusal re-renders the form with `401` and the same sentence for every
    cause. There is no ``WWW-Authenticate`` on it: the browser must not be
    offered a native dialog here, because a credential cached in one is a
    credential this service cannot make it forget.
    """
    authenticator = _authenticator(request)
    settings: Settings = request.app.state.settings
    if authenticator.mode is not AuthMode.basic:
        raise ForbiddenError(
            "this deployment signs in through its identity provider",
            detail={"auth_mode": authenticator.mode.value})

    body = await request.body()
    form = dict(urllib.parse.parse_qsl(
        body.decode("utf-8", "replace")[:4096], keep_blank_values=True))
    target = oidc.safe_redirect(form.get("next") or "/")
    try:
        account = authenticator.accounts.authenticate(
            (form.get("subject") or "").strip(), form.get("password") or "",
            source=source_of(request, settings))
    except AuthenticationFailed as exc:
        # Logged the way every other rejection is, with the reason for the
        # operator and the same sentence for whoever is at the keyboard.
        log.warning("auth.rejected", reason=exc.reason, detail=exc.diagnosis,
                    method=request.method, path=request.url.path,
                    scheme_present=False, session_cookie_present=False)
        return _sign_in_page(request, target=target, error=exc.reason,
                             status_code=exc.status_code)
    principal = authenticator.principal_for(account, method=identity.SESSION)
    return _established(request, principal, target, mode="basic")


@router.get("/callback", summary="Finish browser sign-in")
def callback(request: Request, code: str | None = None, state: str | None = None,
             error: str | None = None) -> Response:
    """Validate the state, exchange the code with PKCE, verify the `id_token`."""
    authenticator = _authenticator(request)
    settings: Settings = request.app.state.settings

    if error:
        log.warning("auth.rejected", reason="provider_error", detail=error,
                    path=request.url.path)
        raise AuthenticationFailed("provider_error", detail=error)
    if not code or not state:
        raise AuthenticationFailed(
            "incomplete_callback", detail="the callback carried no code or no state")

    cookie_state = request.cookies.get(oidc.LOGIN_COOKIE)
    if not cookie_state or not _constant_equal(cookie_state, state):
        # The browser that is finishing the flow is not the one that started it.
        log.warning("auth.rejected", reason="state_mismatch",
                    detail="the callback state does not match the login cookie",
                    path=request.url.path,
                    query_state_digest=oidc.digest(state)[:12],
                    cookie_present=cookie_state is not None)
        raise AuthenticationFailed("state_mismatch")

    claimed = authenticator.logins.claim(state)
    id_token_verifier = authenticator.id_token_verifier()
    tokens_response = oidc.exchange_code(
        authenticator.metadata(), code=code,
        redirect_uri=str(settings.oidc_redirect_uri),
        client_id=str(settings.oidc_client_id),
        client_secret=(settings.oidc_client_secret.get_secret_value()
                       if settings.oidc_client_secret else None),
        verifier=claimed["code_verifier"])

    raw_id_token = tokens_response.get("id_token")
    if not isinstance(raw_id_token, str) or not raw_id_token:
        raise AuthenticationFailed(
            "no_id_token", detail="the token endpoint returned no id_token")
    claims = id_token_verifier.verify(raw_id_token)
    if not _constant_equal(str(claims.get("nonce") or ""), claimed["nonce"]):
        # A valid token that belongs to a different login is still not this
        # login's answer. Without this check any `id_token` the provider ever
        # issued for this client would complete any flow.
        log.warning("auth.rejected", reason="nonce_mismatch",
                    detail="the id_token does not echo this login's nonce",
                    subject=claims.get("sub"))
        raise AuthenticationFailed("nonce_mismatch")

    principal = authenticator.principal_from_claims(claims, method=identity.SESSION)
    session = authenticator.sessions.create(
        subject=principal.subject, issuer=principal.issuer,
        roles=principal.roles, display_name=principal.display_name)
    audit: AuditLog = request.app.state.audit
    # `principal.roles` is already narrowed to what this deployment maps, so
    # the row the trail never prunes carries this service's own model and a
    # count of the rest -- not a copy of the directory's.
    audit.record("auth.session_established", actor=principal.actor(),
                 detail={"mode": "oidc", "roles": list(principal.roles),
                         "unrecognised_role_count": principal.unrecognised_roles,
                         "scopes": sorted(s.value for s in principal.scopes)})

    response = RedirectResponse(oidc.safe_redirect(claimed["redirect_to"]),
                                status_code=303)
    _set_session_cookie(response, session, settings)
    response.delete_cookie(oidc.LOGIN_COOKIE, path="/auth")
    return response


@router.get("/logout", summary="End the browser session")
def logout(request: Request) -> Response:
    """Revoke the session here, then end it at the provider where it can be."""
    authenticator = _authenticator(request)
    settings: Settings = request.app.state.settings
    cookie = request.cookies.get(oidc.SESSION_COOKIE)
    subject = None
    if cookie:
        try:
            subject = authenticator.sessions.lookup(cookie).subject
        except AuthenticationFailed:
            subject = None
        authenticator.sessions.revoke(cookie)
        log.info("auth.logged_out", subject=subject)

    if authenticator.mode is AuthMode.basic:
        # There is no provider to end a session at, and there is one thing this
        # service genuinely cannot do: make a browser forget a credential it
        # cached from a native dialog. The page says so rather than redirecting
        # into a login that would silently sign the person back in.
        from painfree.ui.rendering import render

        response = render(request, "signed_out.html")
        response.delete_cookie(oidc.SESSION_COOKIE, path="/")
        response.delete_cookie(oidc.LOGIN_COOKIE, path="/auth")
        response.set_cookie(
            SIGNED_OUT_COOKIE, "1", httponly=True,
            secure=settings.cookies_are_secure, samesite="lax", path="/",
            max_age=SIGNED_OUT_MAX_AGE)
        return response

    target = "/"
    if authenticator.mode is AuthMode.oidc:
        target = oidc.end_session_url(
            authenticator.metadata(), client_id=str(settings.oidc_client_id),
            post_logout_redirect_uri=None) or "/"
    response = RedirectResponse(target, status_code=303)
    response.delete_cookie(oidc.SESSION_COOKIE, path="/")
    response.delete_cookie(oidc.LOGIN_COOKIE, path="/auth")
    return response


@router.get("/me", summary="The authenticated caller")
def me(principal: Principal = Depends(principal_of)) -> dict[str, Any]:
    """Who this request is, and what it may do. Never a token, never a session id."""
    return principal.as_response()


def _constant_equal(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


__all__ = ["Authenticator", "BASIC_PREFIX", "BEARER_PREFIX",
           "BROWSER_PREFIXES", "DEV_PRINCIPAL_HEADER", "DEV_ROLES_HEADER",
           "PUBLIC_PATHS", "SIGNED_OUT_COOKIE", "SIGNED_OUT_MAX_AGE",
           "decode_basic", "install_authentication", "is_browser_navigation",
           "is_public", "principal_of", "requires", "requires_on", "router",
           "source_of"]
