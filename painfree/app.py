"""The FastAPI application: lifespan, correlation, error handling, health.

What this module is responsible for, and why each piece is where it is:

**Lifespan.** Configuration is resolved and logged once, the engine is built,
the schema is brought to head, and the start is written to the audit log. If any
of that fails the process does not start -- a container that comes up on an
unusable database and fails one request at a time is harder to diagnose than one
that refuses to boot.

**Correlation.** One middleware owns ``request_id``: it takes the caller's
``X-Request-ID`` if there is one (so a trace spans the caller and us) and
otherwise mints one, binds it for the duration of the request, echoes it in the
response header, and puts it in every error body. Everything logged underneath
-- ours, SQLAlchemy's, the engine's -- carries it without being asked.

**Error handling.** Five handlers, and no bare ``except``. A
:class:`~painfree.errors.ServiceError` is a named failure converted to its
status; an ``HTTPException`` is reshaped into the same envelope; a validation
failure is a 422 that names the failing field; an identity provider that cannot
be reached is a `503`, because it is a dependency and not a defect; anything
else is logged with a stack trace and becomes an opaque ``internal_error``
carrying the request id.
The catch-all lives in the middleware rather than in a handler so that it runs
*inside* the bound correlation context -- a 500 whose log line has no request id
is the one line an operator most needs to join.

**Custody.** The application is built without the ability to open a private key
and cannot acquire one: the settings it stores have the encryption secret
removed, ``app.state`` carries only the public
:class:`~painfree.keyring.Keyring`, and the correlation middleware marks every
request so that :mod:`painfree.custody` refuses a decryption attempted anywhere
underneath it.

There is a fourth thing, and it is the one that closes the gap the other three
could not: ``PAINFREE_ROLE=api`` refuses to *start* with
``PAINFREE_KEY_ENCRYPTION_SECRET`` in the environment, so a handler that reads
``os.environ`` directly -- the attack the in-process boundary cannot stop --
finds nothing to read. The uploads happen in :mod:`painfree.worker`, in another
process. ``create_app`` correspondingly refuses to build an application for a
``worker`` process: a worker serves no HTTP, and an application object it never
mounts would be a place for the secret to leak back in.

**Authentication.** A second middleware, *inside* the correlation one so its
rejections carry a request id, resolves every request to a
:class:`~painfree.identity.Principal` -- from a bearer token, an HTTP Basic
credential, a session cookie, or the development header -- and refuses the
request with `401` if it cannot. Which of those is offered is
``PAINFREE_AUTH_MODE``, resolved once at startup and reported in the log line
below the configuration, because a mode that was *derived* rather than set is
otherwise a thing an operator has to read source code to explain. It is
deny-by-default: a path not in :data:`painfree.authn.PUBLIC_PATHS` is protected
whether or not anyone remembered to protect it. Scopes are demanded per route
with ``Depends(requires(...))``, which is the difference between `401` and
`403`.

**Routes.** ``/v1`` is the caller's API and arrives as a router
(:mod:`painfree.api`); ``/ui`` is the operator console (:mod:`painfree.ui`), and
is protected exactly as ``/v1`` is -- it is in this application rather than
beside it, which is also why it can perform no key operation and asks the worker
instead. The operational endpoints below stay outside both, unversioned and
unauthenticated, because an orchestrator's probe should not depend on an API
version or on an identity provider. ``/auth`` is the browser login flow, and is
public for the same reason: it is how an identity is obtained.

Two of the error handlers answer a browser differently from a client. A `403`
or a `404` on a console page becomes an HTML page carrying the same code,
message and request id the JSON body would; the decision is made on the
``Accept`` header *and* the path, so a client fetching a console URL still gets
the envelope it can parse. The `401` equivalent lives in
:mod:`painfree.authn`, where the rejection happens.

**Health.** ``/healthz`` answers whether the process is alive and says nothing
about its dependencies. ``/readyz`` answers whether it can do work: the database
answers *and* its schema is the one this code was written against. Keeping them
separate is what stops an orchestrator restarting a healthy process because the
database blinked.
"""

from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from painfree import access_api, api, authn, custody, ui
from painfree.access import Grants
from painfree.audit import AuditLog
from painfree.config import (AuthMode, ConfigurationError, Settings,
                             load_settings)
from painfree.connections import ConnectionRegistry
from painfree.db import build_engine, check_ready, migrate
from painfree.errors import ServiceError, error_body
from painfree.identity import Scope
from painfree.keyjobs import KeyJobStore
from painfree.recovery import CustodyRecovery
from painfree.keyring import Keyring
from painfree.logging import bind, configure_logging, context, get_logger
from painfree.catalogue import Catalogue
from painfree.orders import OrderStore
from painfree.schedule import DownloadSchedules
from painfree.statements import StatementStore
from painfree.tokens import ProviderUnavailable
from painfree.webhooks import WebhookSubscriptions

log = get_logger("painfree.app")

REQUEST_ID_HEADER = "X-Request-ID"

#: Endpoints an orchestrator polls constantly. Logged at debug so a readiness
#: probe every two seconds does not bury the events that matter; a failing probe
#: still logs at warning, from the handler.
PROBE_PATHS = frozenset({"/healthz", "/readyz"})


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    configure_logging(settings.log_level)

    # The startup line an operator needs: version, git sha, and the whole resolved
    # configuration with the database password removed.
    log.info(
        "service.starting",
        version=settings.version,
        git_sha=settings.git_sha,
        # Resolved, not raw: what this deployment calls an administrator is a
        # question an operator should be able to answer from the log rather than
        # by reading source and guessing which default is in force.
        admin_roles=sorted(settings.admin_role_names),
        member_roles=sorted(settings.member_role_names),
        config=app.state.resolved_config,
    )

    engine = build_engine(settings)
    app.state.engine = engine
    app.state.audit = AuditLog(engine)
    # Both of these are the *public* surfaces. There is no `KeyCustodian` on
    # `app.state` and no custody key to build one with -- see `painfree.custody`.
    app.state.connections = ConnectionRegistry(engine, app.state.audit)
    app.state.keyring = Keyring(engine)
    # Who may touch which connection. Read on every authenticated request by
    # `authn.Authenticator`, which builds its own reader; this one is the writer
    # the grant routes and the console use, so the audit log is wired to it and
    # every grant and revocation is a row.
    app.state.grants = Grants(engine, app.state.audit)
    # The submission path. It validates, builds a `pain.001` and records an
    # order; it neither signs nor uploads, and needs no key to do any of it.
    app.state.orders = OrderStore(engine, app.state.audit, app.state.connections)
    # What the bank last published about itself. Read by the console, written
    # only by the worker, which is the half that can open the response.
    app.state.catalogue = Catalogue(engine)
    app.state.statements = StatementStore(engine, app.state.audit)
    # What the console asks the worker for. It appends rows and reads them back;
    # it holds no key and performs no key operation.
    app.state.key_jobs = KeyJobStore(engine, app.state.audit)
    # Reads which custody key the sealed rows name and whether anybody has
    # said they hold a copy of it. Holds no secret and cannot: this process
    # is refused the custody secret and would not have started with one.
    app.state.recovery = CustodyRecovery(engine, app.state.audit)
    # Webhook subscriptions, with **no custody key**. This surface can register
    # an endpoint, seal its secret to the worker's published public half and
    # show it to the registering caller once -- and cannot open a stored one,
    # here or anywhere else in this process.
    app.state.webhooks = WebhookSubscriptions(engine)
    # Download schedules. Registering, editing and asking for a run are all row
    # writes; the download itself needs the connection's `E002` private half and
    # therefore happens in the worker, which is why "run now" makes a schedule
    # due rather than fetching anything here.
    app.state.schedules = DownloadSchedules(engine, app.state.audit)
    # Built here rather than in `create_app` because it needs the engine: a
    # browser session and a login in flight are rows, not process state, so two
    # replicas behind a load balancer share them.
    app.state.authenticator = authn.Authenticator(settings, engine,
                                                  audit=app.state.audit)
    # The local account store, and the same object the authenticator verifies
    # against, so a password changed through the API is the password the next
    # request is checked with.
    app.state.accounts = app.state.authenticator.accounts
    try:
        if settings.migrate_on_startup:
            revision = migrate(engine)
        else:
            revision = None
            log.info("database.migration_skipped", reason="migrate_on_startup=false")
        app.state.audit.record(
            "service.started",
            detail={
                "version": settings.version,
                "git_sha": settings.git_sha,
                "environment": settings.environment.value,
                "role": settings.role.value,
                "dialect": settings.dialect,
                "schema_revision": revision,
                "custody_key_id": app.state.custody_key_id,
                "auth_mode": settings.auth_mode.value,
            },
        )
    except Exception:
        log.exception("service.start_failed")
        engine.dispose()
        raise

    log.info("service.started", version=settings.version, dialect=settings.dialect)
    _report_authentication(app, settings)
    try:
        yield
    finally:
        log.info("service.stopping")
        engine.dispose()
        log.info("service.stopped")


def _report_authentication(app: FastAPI, settings: Settings) -> None:
    """Say, at startup, how this process authenticates and why.

    The mode is derived when it is not set (`painfree.config`), and a derived
    value nobody can see the reasoning for is a value an operator ends up
    reading source code to understand.

    The second line is the one that matters on a fresh deployment. A `basic`
    process with no accounts refuses every credential presented to it, which
    from the outside is indistinguishable from a broken password — so it says
    so, at `warning`, with the command that fixes it. It does **not** refuse to
    start: a container that crash-loops until somebody exec's into it is worse
    than one that runs and says what it is waiting for, and there is deliberately
    no account it could have created for itself.
    """
    log.info("auth.mode_selected", auth_mode=settings.auth_mode.value,
             reason=settings.auth_mode_reason,
             tls_terminated_upstream=settings.tls_terminated_upstream)
    if settings.auth_mode is not AuthMode.basic:
        return
    try:
        count = app.state.accounts.count()
    except Exception:  # pragma: no cover - the schema check already failed
        log.exception("auth.accounts_unreadable")
        return
    if count:
        log.info("auth.accounts_ready", accounts=count)
        return
    log.warning(
        "auth.no_accounts", accounts=0,
        reason="this deployment authenticates with HTTP Basic and has no "
               "accounts, so every credential presented to it is refused. No "
               "default account is created, ever. Create the first "
               "administrator with `python -m painfree create-admin <name>`")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application. Configuration is resolved here, not per request."""
    settings = settings or load_settings()
    if not settings.role.serves_http:
        raise ConfigurationError(
            f"PAINFREE_ROLE is {settings.role.value}; a worker process serves "
            f"no HTTP and has no application")
    app = FastAPI(
        title="painfree",
        version=settings.version,
        summary="JSON in, EBICS out.",
        lifespan=lifespan,
    )
    # The configuration is rendered for the startup line *before* the secret is
    # dropped, so the line still says a custody key is configured and names its
    # id -- and then the object the request path can reach no longer carries the
    # secret at all. One of the three mechanisms in `painfree.custody`.
    app.state.resolved_config = settings.redacted()
    app.state.custody_key_id = settings.custody_key_id
    app.state.settings = settings.without_custody_secret()
    _install_middleware(app)
    _install_error_handlers(app)
    _install_routes(app)
    return app


# --- correlation ------------------------------------------------------------

def _install_middleware(app: FastAPI) -> None:
    # Added first, so it is the *inner* of the two: Starlette runs the
    # last-registered middleware outermost. A `401` therefore happens inside the
    # bound correlation context and its log line carries the request id, which
    # is the whole reason the ordering is written down rather than left to luck.
    authn.install_authentication(app, app.state.settings)

    @app.middleware("http")
    async def correlate(request: Request, call_next: Any) -> Any:
        request_id = request.headers.get(REQUEST_ID_HEADER) or uuid.uuid4().hex
        started = time.perf_counter()
        # `custody.request_path` is entered here and nowhere else: everything
        # underneath -- including a synchronous route, which runs in a thread
        # pool the context follows into -- is then refused a private key.
        with bind(request_id=request_id), custody.request_path():
            request.state.request_id = request_id
            try:
                response = await call_next(request)
            except Exception:
                # The catch-all, inside the bound context so the line carries
                # the id. Logged where it is caught, with the trace, then
                # converted deliberately -- never swallowed.
                elapsed = (time.perf_counter() - started) * 1000
                log.exception(
                    "request.failed",
                    method=request.method,
                    path=request.url.path,
                    duration_ms=round(elapsed, 2),
                )
                response = JSONResponse(
                    status_code=500,
                    content=error_body(
                        "internal_error",
                        "the request could not be completed",
                        request_id=request_id,
                    ),
                )
            else:
                elapsed = (time.perf_counter() - started) * 1000
                emit = log.debug if request.url.path in PROBE_PATHS else log.info
                emit(
                    "request.completed",
                    method=request.method,
                    path=request.url.path,
                    status=response.status_code,
                    duration_ms=round(elapsed, 2),
                )
            response.headers[REQUEST_ID_HEADER] = request_id
            return response


# --- error handling ---------------------------------------------------------

def _install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ServiceError)
    async def _service_error(request: Request, exc: ServiceError) -> JSONResponse:
        log.warning(
            "request.rejected",
            code=exc.code,
            status=exc.status_code,
            path=request.url.path,
            reason=exc.message,
        )
        if authn.is_browser_navigation(request):
            # Same code, same message, same request id -- as a page, because the
            # console is the only part of this service a human reads directly.
            return ui.render(request, "error.html", status_code=exc.status_code,
                             code=exc.code, message=exc.message,
                             status=exc.status_code, detail=exc.detail or None)
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(
                exc.code, exc.message,
                request_id=context().get("request_id"), detail=exc.detail,
            ),
            # A `401` without `WWW-Authenticate` is a status a client cannot act
            # on; the error carries its own headers rather than the handler
            # guessing from the status.
            headers=dict(exc.headers) if exc.headers else None,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = "not_found" if exc.status_code == 404 else "http_error"
        log.warning(
            "request.rejected",
            code=code, status=exc.status_code, path=request.url.path,
            reason=str(exc.detail),
        )
        if authn.is_browser_navigation(request):
            return ui.render(request, "error.html", status_code=exc.status_code,
                             code=code, message=str(exc.detail),
                             status=exc.status_code, detail=None)
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(code, str(exc.detail),
                               request_id=context().get("request_id")),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(ProviderUnavailable)
    async def _provider_unavailable(
        request: Request, exc: ProviderUnavailable
    ) -> JSONResponse:
        """The identity provider is a dependency, and `503` is what says so.

        Reached from the login endpoints, which are public and therefore run
        outside the authentication middleware that converts this everywhere
        else. A `500` here would send an operator looking for a defect in this
        service when the answer is that the provider is down or misconfigured.
        """
        log.exception("auth.unavailable", path=request.url.path, reason=str(exc))
        return JSONResponse(
            status_code=503,
            content=error_body("not_ready", "authentication is not available",
                               request_id=context().get("request_id")),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # The failing rule is named rather than folded into "invalid request".
        # The API contract requires that of pain.001 validation; holding the
        # request body to the same standard costs nothing.
        failures = [
            {"location": ".".join(str(part) for part in item.get("loc", [])),
             "rule": item.get("type", "invalid"),
             "message": item.get("msg", "invalid")}
            for item in exc.errors()
        ]
        log.warning(
            "request.rejected",
            code="validation_failed", status=422, path=request.url.path,
            failures=failures,
        )
        return JSONResponse(
            status_code=422,
            content=error_body(
                "validation_failed", "the request body is not valid",
                request_id=context().get("request_id"),
                detail={"failures": failures},
            ),
        )


# --- routes -----------------------------------------------------------------

def _install_routes(app: FastAPI) -> None:
    # Everything under `/v1`. The operational endpoints below are
    # deliberately outside it: unversioned, and answerable without auth.
    app.include_router(api.router)
    # The same `/v1` prefix, a different concern: who may use this deployment
    # rather than what it does. Split out of `painfree.api` at the cap.
    app.include_router(access_api.router)
    app.include_router(authn.router)
    # The operator console. Every one of its routes carries a scope, and none of
    # them is in `PUBLIC_PATHS` -- the deny-by-default middleware treats them
    # exactly as it treats `/v1`.
    for console in ui.ROUTERS:
        app.include_router(console)

    @app.get("/", include_in_schema=False, summary="The operator console")
    def root(principal: Any = Depends(
            authn.requires(Scope.connections_read))) -> RedirectResponse:
        """Where a browser lands. Protected like everything else."""
        return RedirectResponse(f"{ui.views.PREFIX}/connections", status_code=303)

    @app.get("/healthz", tags=["operations"], summary="Liveness")
    def healthz() -> dict[str, Any]:
        """Alive. Deliberately checks nothing else -- see the module docstring."""
        settings: Settings = app.state.settings
        return {
            "status": "ok",
            "version": settings.version,
            "git_sha": settings.git_sha,
        }

    @app.get("/readyz", tags=["operations"], summary="Readiness")
    def readyz() -> JSONResponse:
        """Able to work: the database answers and its schema is current."""
        database = check_ready(app.state.engine)
        if not database.get("ready"):
            log.warning("readiness.failed", **database)
            return JSONResponse(
                status_code=503,
                content=error_body(
                    "not_ready", "a dependency is not available",
                    request_id=context().get("request_id"),
                    detail={"database": database},
                ),
            )
        return JSONResponse(
            status_code=200,
            content={"status": "ready", "checks": {"database": database}},
        )


__all__ = ["REQUEST_ID_HEADER", "create_app", "lifespan"]
