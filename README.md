# painfree

**JSON in, EBICS out.** A self-hosted middleware that accepts authenticated HTTP
requests and submits them to your banks over EBICS 3.0, so payment files stop
being something a human uploads by hand.

```
your system  ──JSON/HTTPS──▶  painfree  ──EBICS 3.0 (H005)──▶  bank A
                (OIDC)         │                                bank B
                               │                                bank C
                               └──webhook──▶  your system
```

You POST a payment instruction as JSON. painfree validates it, builds a
compliant `pain.001`, signs and encrypts it per the EBICS protocol, uploads it
to the right bank connection, tracks the order to acknowledgement, and calls
your webhook when the status changes. It also runs the other direction:
scheduled downloads of `camt.052/053/054` and `pain.002`, normalised to JSON.

A web UI at `/ui` handles everything that is not a payment: bank connections,
EBICS initialisation, key management, order history, replaying failed jobs.

## Why it exists

Every EBICS client we found is a library, so you still build the service
yourself.
The maintained ones are Ruby, PHP and Java, and Swiss banks are on EBICS 3.0
with mandatory X.509 certificates, so H004-only clients are a dead end. We need
Python, and a running service rather than a library.

## Scope

**In scope:** multiple bank connections · payment submission via JSON API and a
UI form · webhooks · OIDC (browser SSO, JWT bearer for machines) or local
accounts over HTTP Basic where there is no provider · scheduled
downloads normalised to JSON · key lifecycle in the UI (INI/HIA, a printable INI
letter, HPB with hash verification, renewal, suspension) · audit log.

**Out of scope:** accounting, ledgers and reconciliation (we emit normalised
events, matching belongs upstream) · being a payment service provider ·
non-EBICS bank channels, for now.

## Status

**Early.** Not in production. Not suitable for anyone else's money.

## Layout

| Path | What |
|---|---|
| `painfree/ebics3/` | protocol engine: EBICS 3.0 (H005), standalone, no service concerns |
| `painfree/` | FastAPI service: API, UI, workers, scheduler |
| `painfree/migrations/` | Alembic history; one schema for SQLite and PostgreSQL |
| `painfree/schemas/` | vendored ISO 20022 XSDs, validated against at runtime |
| `tests/` | the suite, run against SQLite and PostgreSQL both |
| `deploy/` | the compose stack, the backup and restore scripts |

There is one importable package, `painfree`; the engine is the subpackage
`painfree/ebics3/`. `painfree.ebics3` must not import from any other part of
`painfree`. The engine takes bytes and keys and returns bytes; anything that
knows about HTTP status codes, Postgres or webhooks belongs in the service
layer. That dependency direction is strictly one-way, which is what keeps the
engine splittable into its own permissively licensed package later.

## Installing

Two ways to run it, depending on whether you want to change it.

```bash
pip install painfree                       # the published package
podman run ghcr.io/reyemb/painfree:latest   # or the published image
```

The image is the deployment target and is what the compose stack in
`compose.yaml` runs; see [Deployment](#deployment). The package is there for
anyone who would rather run the service under their own process supervisor, or
who wants `painfree.ebics3` as a library. The engine imports with nothing but
`lxml` and `cryptography` present, and pulls in none of the service layer.

A release is a `v<version>` tag. The tag has to match the version in
`painfree/__init__.py`, and the release refuses to publish anything if it does
not: `scripts/check_release_tag.py` is what refuses, and it runs before
anything is built.

## Getting started

Working on it, rather than running it:

```bash
uv sync --extra dev
uv run python -m painfree          # serves on http://127.0.0.1:8000
```

Requires Python 3.11+ and `uv`. Nothing else: development defaults to SQLite in
a file, migrated at startup.

```bash
curl localhost:8000/healthz        # alive
curl localhost:8000/readyz         # database reachable and schema current
```

Those two are the only unauthenticated endpoints, along with the three
`/auth/*` login endpoints. Everything else answers `401` without a credential,
including `/docs` and `/openapi.json`.

Submitting a payment, once a bank connection is registered and initialised:

```bash
curl -X POST localhost:8000/v1/connections/acme-ubs/payments \
     -H 'X-Painfree-Dev-Principal: you' -H 'X-Painfree-Dev-Roles: operator' \
     -H 'Idempotency-Key: caller-idem-0001' \
     -H 'Content-Type: application/json' -d @payment.json
```

`202 Accepted` with an `order_id` to poll at `/v1/orders/{order_id}`. It means
the payment was accepted **for processing**, not that the bank has it. The
instruction is validated against the ISO 20022 schema *and* the Swiss Payment
Standards rules before anything is signed, so a malformed QR reference comes
back immediately, naming the field, rather than from the bank two hours later.
The request body and the idempotency rules are in the OpenAPI document the
service serves, and on `/ui/api` in the console.

### Instant payments

A payment carries a `scheme`: `normal`, `instant`, or `instant_or_normal`, the
last of which tries instant and sends an ordinary transfer if the bank
definitively refuses. It can
be set per submission, per transaction, or left to the connection's default.
Which BTF and which ISO 20022 codes a given bank means by each scheme is
per-connection configuration you edit in the console, not a constant in a
release.

`instant_or_normal` builds **both** messages when the payment is accepted, each
with its own `MsgId` and each validated against the schema, and holds the
ordinary one in reserve. It is sent only when the bank answered, the answer
parsed, its return code is on that connection's whitelist of codes meaning
*instant unavailable*, and the bank had acknowledged receipt of nothing. A
timeout, a dropped connection or a response that will not parse is an unknown
outcome, not a refusal: the order is retried carrying the message it already
had. One idempotency key stays one order, and the order can end accepted at
most once. `fall_back` in `painfree/queue.py` is the rule, and every condition
that stops it.

## Authentication

One authorisation model, reached by one of two credentials. **A deployment
either has an identity provider or it does not, and both are supported.** The
second is not a development mode with the safety catch filed off.
`PAINFREE_AUTH_MODE` picks, and left unset in production it is derived: an OIDC
issuer configured means `oidc`, none means `basic`. A process accepts **one**
kind of credential and never two.

### With an identity provider

**Machines** present `Authorization: Bearer <jwt>`, verified against the
identity provider's JWKS: asymmetric algorithms only, so `alg: none` and the
RSA-public-key-as-HMAC-secret confusion are both refused at the header, before a
key is looked up and before the provider is contacted. `iss`, `aud`, `exp`,
`iat` and, when present, `nbf` are checked, key rotation is handled, and an
unknown `kid` costs at most one JWKS refresh however many tokens carry it.

**Humans** go through `GET /auth/login`: the authorization-code flow with PKCE
(S256), a `state` bound to the browser by a cookie as well as to a server-side
row, a `nonce` the `id_token` has to echo, and a login that can be claimed
exactly once. The session that comes out stores **no token**: a row keyed by
the SHA-256 of a random cookie value, and nothing else.

### With none: HTTP Basic against accounts this deployment owns

`Authorization: Basic base64(name:password)` for a program; a sign-in form for a
browser. Argon2id at RFC 9106's second recommended cost, and:

- **it refuses to run over plaintext.** A production process serving HTTP in
  this mode does not start unless `PAINFREE_TLS_TERMINATED_UPSTREAM` says
  something in front of it terminates TLS. `compose.yaml` sets it, because the
  Caddy service is what makes it true;
- **no default credential exists, ever.** The migration writes no rows and
  nothing bootstraps an account. `python -m painfree create-admin <name>`
  creates the first one, reading the password from a terminal, from standard
  input, or generating it. A deployment that has not run it refuses every
  credential and says so on every start;
- **a wrong password and a name nobody has cost the same**, measured rather than
  asserted: an unknown name is verified against a dummy hash;
- **failures are throttled** per account name and per source address, audited,
  and cleared by an administrator from `/ui/accounts` or by
  `python -m painfree unlock` from a shell;
- **signing out of the console works**, because the browser signs in through a
  form and carries a session cookie rather than answering a native `Basic`
  dialog. What that cannot do is stated on the page rather than papered over.

### Either way, the same model

**Whichever says who a caller is, painfree says which bank connections they
may touch.** There are two roles: `admin`, which is everything everywhere and
the only role that may grant access, and `member`, which is a working login and
nothing else. Everything a member holds is a **grant**: a row naming a subject,
a bank connection and a level.

| Level | Carries, on that connection only |
|---|---|
| `viewer` | `connections:read`, `payments:read`, `statements:read`, `schedules:read`, `audit:read` |
| `operator` | the above, plus `payments:submit`, `orders:replay`, `schedules:manage`, `webhooks:read` |

Submitting a payment and reading one back are different privileges, which is why
a grant carries a level rather than being a boolean: *can see this bank* and
*can move money at this bank* stay separable. `connections:write` and
`webhooks:manage` are carried by no level at all: they are `admin` only, which
is also what makes it impossible for a member to register the webhook
subscription that would receive every connection's payment events. A `scope`
claim still only ever narrows.

One grant names **no** connection: an admin-issued **oversight** grant, which
carries every scope named `:read` on every connection plus the audit rows that
name none (the sign-ins, the service starts and the grant changes), and **no
write scope at all**, including no grant management. It is what lets somebody
review who can move money at which bank without being able to do either. It is
not a third role: reach is data this deployment owns and can revoke.

Grants of both kinds are read from the database on **every request**, so
revoking somebody's access to a bank takes effect on their next request rather
than their next sign-in. A connection a caller holds no grant on answers `404`,
identical to a connection that was never registered.

Nothing is public unless it is on a five-entry list, so a route added without a
dependency is inaccessible rather than anonymous.

**There is no painfree-issued API token.** Every machine credential comes from
the configured provider, so there is one place to revoke when somebody leaves.
The console
says so on `/ui/api`, which also links the OpenAPI documents, shows the caller
their own role, their grants and their effective scopes, and renders the scope
model, the grant levels and the privilege every endpoint demands. All of those
tables are generated from `painfree/identity.py` and from the router rather than
written down, so they cannot drift. That is how they followed the move to
per-connection grants, and the oversight grant after it, without a new source of
truth.

```bash
# with a provider
PAINFREE_AUTH_MODE=oidc \
PAINFREE_OIDC_ISSUER=https://id.example.com/realms/painfree \
PAINFREE_OIDC_CLIENT_ID=painfree \
PAINFREE_OIDC_REDIRECT_URI=https://painfree.example.com/auth/callback \
    uv run python -m painfree serve

# with none: create the first administrator, then serve
uv run python -m painfree migrate
uv run python -m painfree create-admin alice --generate
PAINFREE_AUTH_MODE=basic uv run python -m painfree serve
```

Development defaults to `PAINFREE_AUTH_MODE=development`, which authenticates
from `X-Painfree-Dev-Principal` and `X-Painfree-Dev-Roles` so a checkout runs
and a test suite passes with no provider to point at. It is still an
authentication step, since a request with neither header nor cookie is refused,
and **production refuses to start in it**, the same way it refuses a custody
secret to an API process.

## The worker

Uploads *and* scheduled downloads happen in a **second process**, which is where
the keys are opened:

```bash
PAINFREE_ROLE=worker PAINFREE_KEY_ENCRYPTION_SECRET=... \
    uv run python -m painfree worker
```

One process, four kinds of loop: it claims queued payments, it claims download
schedules that have come due, it delivers webhooks, and it performs the key
operations the console asked for. A download is decrypted with our own `E002`
private half, a webhook is signed with a secret sealed under the same custody
key, and every step of a key lifecycle needs a private key, so all four need
the same keys and the same boundary.

That split is the security boundary rather than a scaling one. Only the worker's
environment carries `PAINFREE_KEY_ENCRYPTION_SECRET`; an `api` process handed it
refuses to start, and production refuses to run both halves in one process, so
a request-handling process has nothing to derive a key from, deliberately or
otherwise. In development the default role is `combined` and one process does
both.

## The operator console

`/ui` is a server-rendered console for everything that is not a payment API
call. Registering connections, walking a subscriber through INI → HIA → HPB,
printing the INI letter, reading order history, replaying a failed job, reading
ingested statements, operating the webhook endpoints, managing the download
schedules, reading the audit trail, and finding the API. Material Design 3, a
left navigation drawer, an app bar carrying the profile, a notification count
and a three-state theme toggle. No build step, no bundler and no `node_modules`;
one inlined stylesheet and one inline script, which is the toggle. Every page
renders and every form submits with scripting off.

Every route carries a scope, exactly as `/v1` does, and hiding a control the
caller may not use is a courtesy rather than the control, since the server
refuses the request either way. The one exception is `/ui/api`, which is
authenticated and deliberately unprivileged: it is the page the caller who
holds nothing reads to find out what they would have needed.

**The audit trail is a page.** `/ui/audit` needs `audit:read`, which an operator
does not hold and this page does not widen. It filters by connection, actor,
action, outcome, order and a date window, and every row links to the order,
connection, schedule, subscription, statement or key job it happened to, but
only where the reader holds the scope to follow it.

**The console performs no key operation.** It runs in the API process, which by
construction has no custody secret, so a click appends a row to `key_job` and
the worker fulfils it. A browser session cannot cause a private key to be
decrypted in the process that answered the click.

Two screens are deliberately awkward, because they should be:

- **The HPB comparison** is its own page. The EBICS key-management response
  carries no signature, so an operator holding the bank's letter and typing both
  fingerprints is the entire trust decision. Nothing is pre-filled, declining is
  as easy as accepting, and a connection whose bank keys have not been compared
  is refused a payment.
- **Replay** is confirmed on a page that names the connection, the `MsgId`, the
  transaction count and the total. It re-queues the existing order, with the
  same stored `pain.001` and the same `MsgId`, and creates no second payment.

One screen exists to be read rather than clicked. **The schedules page** says
what is fetched from each bank, how far each window got and how the last run
ended, and it draws a hard line between two things that look alike: a run that
found nothing (`EBICS_NO_DOWNLOAD_DATA_AVAILABLE`) is a neutral `empty`, because
that is what a scheduled download finds most days, while a schedule that could
not talk to its bank is `failing` in red with the bank's return code and report
text. A console that painted the first one red would teach an operator to ignore
red. An operator may run a schedule at once rather than waiting for its cadence,
and ask a bank for a window it never answered for; both make the schedule due
and let the worker download, and re-fetching is safe because a re-served
statement hits the ingestion constraint rather than becoming a second row.

## Webhooks

Register an endpoint and painfree pushes every state change to it: a payment
accepted, submitted, rejected or given up on, and a statement downloaded:

```jsonc
{"version": 1, "event_id": "5056b591-…", "event_type": "order.rejected",
 "occurred_at": "2026-08-29T23:07:48.418Z", "connection_id": "acme-ubs",
 "order_id": "ord_f709e079…", "idempotency_key": "caller-idem-0001",
 "data": {"state": "rejected", "return_code": "091002",
          "report_text": "[EBICS_INVALID_ORDER_IDENTIFIER] refused"}}
```

Each request carries `X-Painfree-Signature: v1=<hex>`, an HMAC-SHA256 over
`"<timestamp>.<raw body>"` with the subscription's own secret, the timestamp
inside the MAC so a replay cannot be re-dated. Verify over the bytes you
received, not over a re-serialisation of your parse.

Delivery is **at-least-once**: the event is written in the same database
transaction as the fact it reports, so a crash between the two cannot lose it,
and a redelivery carries the same `event_id`: deduplicate on that. Events for
one subscription arrive in order, failures back off and are eventually parked
rather than retried for ever, and a slow or dead consumer never delays another
one. The envelope is transcribed in `tests/test_service_webhooks.py`, which
checks what this service sends against it rather than against its own code.

## Configuration

Environment variables, all prefixed `PAINFREE_`, validated at startup. An
unrecognised `PAINFREE_*` name is a configuration error rather than a default
quietly winning.

Any of them can be read from a **file** instead: `PAINFREE_X_FILE` names a path
whose contents become `PAINFREE_X`, which is how a Docker Compose or podman
secret reaches the process without passing through an environment anything can
inspect. Setting both forms of one setting is refused rather than resolved by
precedence.

| Variable | Default | What |
|---|---|---|
| `PAINFREE_ENVIRONMENT` | `development` | `production` refuses a SQLite URL, refuses `PAINFREE_ROLE=combined`, and refuses `PAINFREE_AUTH_MODE=development` |
| `PAINFREE_ROLE` | `combined` | `api`, `worker` or `combined`. An `api` process refuses to start holding the custody secret; a `worker` refuses to start without it |
| `PAINFREE_DATABASE_URL` | `sqlite+pysqlite:///painfree.db` | SQLAlchemy URL; PostgreSQL in production |
| `PAINFREE_KEY_ENCRYPTION_SECRET` | none | seals every stored EBICS private key; **required of a production worker**, min 32 chars, and **refused for an `api` process**. Generate with `python -m painfree new-secret`. Losing it loses the keyring, and no database backup brings it back |
| `PAINFREE_PREVIOUS_KEY_ENCRYPTION_SECRET` | none | set beside the new one for the length of a `python -m painfree rekey` run, then removed. Refused for an `api` process for the same reason as the one above |
| `PAINFREE_MIGRATE_ON_STARTUP` | `true` | otherwise run `python -m painfree migrate` |
| `PAINFREE_AUTH_MODE` | derived | `oidc`, `basic`, or `development`, the last of which **production refuses to start in**. Unset outside production means `development`; unset in production means `oidc` where an issuer is configured and `basic` where none is |
| `PAINFREE_TLS_TERMINATED_UPSTREAM` | `false` | something in front of this process terminates TLS. `basic` in production refuses to start without it; a worker is exempt because it serves no HTTP |
| `PAINFREE_BASIC_LOCKOUT_THRESHOLD` / `_SOURCE_LOCKOUT_THRESHOLD` | `5` / `20` | failed sign-ins against one account name, and from one source address, before each locks |
| `PAINFREE_BASIC_LOCKOUT_WINDOW_MINUTES` / `PAINFREE_BASIC_LOCKOUT_MINUTES` | `15` / `15` | how far back failures are counted, and how long a lockout lasts |
| `PAINFREE_OIDC_ISSUER` / `_CLIENT_ID` / `_REDIRECT_URI` | none | all three required for `oidc`; the issuer must be https in production |
| `PAINFREE_OIDC_CLIENT_SECRET` | none | optional; PKCE is used with or without it |
| `PAINFREE_OIDC_AUDIENCE` | client id | what a bearer token's `aud` must contain |
| `PAINFREE_OIDC_ROLES_CLAIM` / `_SCOPE_CLAIM` | `roles` / `scope` | dotted paths, so `realm_access.roles` needs no code |
| `PAINFREE_OIDC_CLOCK_SKEW_SECONDS` | `60` | leeway on `exp`, `nbf` and `iat`; capped at 300 |
| `PAINFREE_SESSION_TTL_MINUTES` / `PAINFREE_LOGIN_TTL_SECONDS` | `480` / `600` | browser session, and how long a code flow may take |
| `PAINFREE_DEV_SUBJECT` / `PAINFREE_DEV_ROLES` | `developer` / `admin` | development mode only |
| `PAINFREE_LOG_LEVEL` | `INFO` | |
| `PAINFREE_HTTP_HOST` / `PAINFREE_HTTP_PORT` | `127.0.0.1` / `8000` | |
| `PAINFREE_GIT_SHA` | `unknown` | set by the image build; appears in the startup line |

Logs are one JSON object per line on stdout. The startup line names the *id* of
the custody key in use, never the secret.

No token, authorization code, session id or client secret reaches the stream --
a rejected authentication is logged with a `reason` and nothing else.

Private keys are decrypted only outside the request-handling path, and the
application is built without the ability to do it at all.

## Deployment

Four lines, against the published image. Nothing is built.

```bash
cp deploy/production.env.example .env    # pinned to the published image
deploy/init-secrets.sh                   # four secret files, generated once
docker compose up -d                     # db, api, worker, TLS proxy
docker compose exec api python -m painfree create-admin you    # no OIDC only
```

Then open the address in `.env`. Set `PAINFREE_SITE_ADDRESS` to
`https://painfree.localhost` to run it on a machine with no DNS: the proxy
issues that certificate from its own local CA. `podman-compose` works
identically, and `deploy/build-image.sh` builds the image yourself if you would
rather not run someone else's.

One image, two roles: `api` serves HTTP and is refused the custody secret,
`worker` holds it. The image is pinned to its base by digest, installs every
dependency from a hash-pinned lock file, runs as a non-root user and records its
own version and git sha in the startup line.

**Persistence is two things.** The database volume, which `deploy/backup.sh`
dumps and `deploy/restore.sh` restores; and `PAINFREE_KEY_ENCRYPTION_SECRET`,
which is in no backup and which nothing recovers. Lose it and every sealed key
is unreadable by anyone, and each bank connection has to be re-keyed on paper.
Rotating it is `python -m painfree rekey`, run with both secrets present, which
re-seals every row and fails loudly on any it could not move.

The scripts that carry it out are `deploy/backup.sh`, `deploy/restore.sh` and
`deploy/verify-keys.py`, which checks a restored database can still open every
sealed key.

## Documentation

The service documents itself. `/ui/api` renders the scope model, the grant
levels and the privilege every endpoint demands, generated from the router and
from `painfree/identity.py` rather than written down, so it cannot drift, and
it links the OpenAPI documents beside them.

The two contracts this service owns are transcribed in the suite rather than
asserted from its own code: the webhook envelope in
`tests/test_service_webhooks.py`, and the normalised statement shape that
`camt.052/053/054` and `pain.002` are turned into in
`tests/test_service_camt.py`.

## Licence

**MIT.** Copyright (c) 2026 reyemb. The full text is in
[LICENSE](https://github.com/reyemb/painfree-ebics-middleware-python/blob/main/LICENSE).

The EBICS 3.0 engine in `painfree/ebics3/` is a Python port of
[`ebics-api/ebics-client-php`](https://github.com/ebics-api/ebics-client-php),
which is MIT too. Its notice is reproduced in full in
[NOTICE](https://github.com/reyemb/painfree-ebics-middleware-python/blob/main/NOTICE),
which is where the provenance of this distribution is recorded and which every
copy has to keep, because MIT obliges it, and both files ship inside the wheel,
the source distribution and the container image.
