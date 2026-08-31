# painfree

**JSON in, EBICS out.** Self-hosted middleware that accepts authenticated HTTP
requests and submits them to your banks over EBICS 3.0, so payment files stop
being something a human uploads by hand.

```
your system  ──JSON/HTTPS──▶  painfree  ──EBICS 3.0 (H005)──▶   bank A
                (OIDC)         │                                bank B
                               │                                bank C
                               └──webhook──▶  your system
```

POST a payment as JSON. painfree validates it, builds a compliant `pain.001`,
signs and encrypts it per the EBICS protocol, uploads it to the right bank
connection, tracks the order to acknowledgement, and calls your webhook when the
status changes. It runs the other direction too: scheduled downloads of
`camt.052/053/054` and `pain.002`, normalised to JSON.

A console at `/ui` handles everything that is not a payment: bank connections,
EBICS initialisation, key management, order history, replay, audit.

## Status

**Early.** Not in production. Not suitable for anyone else's money.

## Run it

Four lines, against the published image. Nothing is built.

```bash
cp deploy/production.env.example .env    # pinned to ghcr.io/reyemb/painfree
deploy/init-secrets.sh                   # four secret files, generated once
docker compose up -d                     # db, api, worker, TLS proxy
docker compose exec api python -m painfree create-admin you    # no OIDC only
```

Open the address in `.env`. Set
`PAINFREE_SITE_ADDRESS=https://painfree.localhost` to run it on a machine with
no DNS: the proxy issues that certificate from its own local CA.
`podman-compose` works identically, and `deploy/build-image.sh` builds the
image yourself if you would rather not run someone else's.

Everything that is not secret lives in `.env`. Every secret is a file under
`deploy/secrets/`, generated once, mounted at runtime, and never baked into the
image or committed.

## Submitting a payment

```bash
curl -X POST https://painfree.localhost/v1/connections/acme-ubs/payments \
     -u you:the-password-you-set \
     -H 'Idempotency-Key: caller-idem-0001' \
     -H 'Content-Type: application/json' -d @payment.json
```

`202 Accepted` with an `order_id` to poll at `/v1/orders/{order_id}`. Accepted
means accepted **for processing**, not that the bank has it. The instruction is
validated against the ISO 20022 schema *and* the Swiss Payment Standards rules
before anything is signed, so a malformed QR reference comes back immediately
naming the field, rather than from the bank two hours later.

One idempotency key stays one order, and an order can end accepted at most once.

**Payment schemes.** A payment carries `normal`, `instant`, or
`instant_or_normal`, which tries instant and sends an ordinary transfer if the
bank definitively refuses. A timeout, a dropped connection or an answer that
will not parse is an unknown outcome rather than a refusal: the order is
retried carrying the message it already had, so nothing is sent twice.

`/ui/api` renders the request body, every endpoint and the privilege it demands,
generated from the router rather than written down, and links the OpenAPI
documents beside it.

## How it works

**Two processes, one image.** `api` serves HTTP and is refused the custody
secret. `worker` holds it, and does every upload, download and key operation. An
`api` process handed the secret does not start, and production refuses to run
both halves in one process. That is a security boundary rather than a scaling
one: the process answering requests has nothing to decrypt a private key with.

**Authentication.** OIDC where you have a provider (browser SSO with PKCE, JWT
bearer for machines), and HTTP Basic against local accounts where you do not.
Production refuses to start in development mode. A process accepts one kind of
credential and never two.

**Authorisation.** Two roles: `admin`, which may grant access, and `member`,
which may not. Everything a member holds is a grant naming a subject, a bank
connection and a level. `viewer` reads; `operator` also submits payments,
replays orders and manages schedules. Grants are read from the database on
every request, so revoking somebody takes effect on their next request. A
connection a caller holds no grant on answers `404`, exactly like one that was
never registered.

**Webhooks.** At-least-once. The event is written in the same transaction as
the fact it reports, so a crash cannot lose it, and a redelivery carries the
same `event_id`: deduplicate on that. Each request is signed
`X-Painfree-Signature: v1=<hex>`, an HMAC-SHA256 over `"<timestamp>.<raw
body>"` with the subscription's own secret. Verify over the bytes you received,
not over a re-serialisation.

**Keys.** INI, HIA and HPB from the console, with a printable INI letter,
renewal and suspension. The bank's keys are trusted only once you have compared
their fingerprints against the letter the bank sent, on a page where nothing is
pre-filled and declining is as easy as accepting.

## Configuration

Every setting is an environment variable, and any of them can be read from a
file instead by setting `PAINFREE_X_FILE`. The ones a deployment sets are in
`deploy/production.env.example`; the rest are documented where they are
defined, in `painfree/config.py`.

| Variable | Default | What |
|---|---|---|
| `PAINFREE_ENVIRONMENT` | `development` | `production` refuses SQLite, `combined`, and development auth |
| `PAINFREE_ROLE` | `combined` | `api`, `worker` or `combined` |
| `PAINFREE_DATABASE_URL` | SQLite file | PostgreSQL in production |
| `PAINFREE_KEY_ENCRYPTION_SECRET` | none | seals every stored private key; required of a worker, refused for an `api` |
| `PAINFREE_AUTH_MODE` | derived | `oidc`, `basic`, or `development`, which production refuses |
| `PAINFREE_TLS_TERMINATED_UPSTREAM` | `false` | `basic` in production will not start without it |
| `PAINFREE_OIDC_ISSUER` / `_CLIENT_ID` / `_REDIRECT_URI` | none | all three required for `oidc` |

Logs are one JSON object per line on stdout. No token, authorization code,
session id or client secret ever reaches the stream.

## Backup, and the one thing no backup covers

`deploy/backup.sh` dumps the database and `deploy/restore.sh` restores it. That
covers the sealed keys, the order history, the idempotency ledger and the audit
trail.

It does not cover `PAINFREE_KEY_ENCRYPTION_SECRET`, which is in no backup and
which nothing recovers. Lose it and every sealed key is unreadable by anyone,
and each bank connection has to be re-keyed on paper. Rotating it is `python -m
painfree rekey`, run with both secrets present, which re-seals every row and
fails loudly on any it could not move.

## Develop

```bash
uv sync --extra dev
uv run python -m painfree     # SQLite, migrated at startup, on :8000
uv run pytest
```

Development mode authenticates from `X-Painfree-Dev-Principal` and
`X-Painfree-Dev-Roles`, so a checkout runs and the suite passes with no provider
to point at. It is still an authentication step, and production refuses to start
in it.

There is one importable package, `painfree`; the EBICS 3.0 engine is the
subpackage `painfree/ebics3/`, which imports nothing from the service around it
and needs only `lxml` and `cryptography`.

## Licence

**MIT.** Copyright (c) 2026 reyemb. The full text is in
[LICENSE](https://github.com/reyemb/painfree-ebics-middleware-python/blob/main/LICENSE).

The EBICS 3.0 engine in `painfree/ebics3/` is a Python port of
[`ebics-api/ebics-client-php`](https://github.com/ebics-api/ebics-client-php),
which is MIT too. Its notice is reproduced in full in
[NOTICE](https://github.com/reyemb/painfree-ebics-middleware-python/blob/main/NOTICE),
which every copy has to keep, and both files ship inside the wheel, the
source distribution and the container image.
