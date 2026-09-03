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

It comes up on `https://painfree.localhost:8443`, on loopback: a rootless
engine may not publish a port below 1024, so the defaults are above it. A
deployment on a real hostname sets `PAINFREE_HTTP_PORT`, `PAINFREE_HTTPS_PORT`
and the two `_BIND` variables to 80 and 443, which is what ACME needs anyway.

Two things that machine needs, both once:

```bash
echo "127.0.0.1  painfree.localhost" | sudo tee -a /etc/hosts
curl -k https://painfree.localhost:8443/local-ca.crt -o painfree-local-ca.crt
```

glibc resolves `localhost` and nothing else under it, so `.localhost` names do
not resolve on Debian, Ubuntu or WSL even though the stack is healthy and the
certificate is valid. The second line fetches the local CA's public root, which
the proxy serves unauthenticated; import it and the browser warning goes away.
Neither is needed once `PAINFREE_SITE_ADDRESS` is a real hostname with a real
certificate.

`podman-compose` works identically, and `deploy/build-image.sh` builds the image
yourself if you would rather not run someone else's.

Everything that is not secret lives in `.env`. Every secret is a file under
`deploy/secrets/`, generated once, mounted at runtime, and never baked into the
image or committed. Everything that survives a restart is a directory under
`state/`, so the deployment is this folder and no compose command can delete
any of it.

## Backups, and moving to another server

```bash
deploy/snapshot.sh --encrypt-to age1…    # one encrypted archive, restores anywhere
```

That is the whole move: one file, and the machine it came from can be thrown
away.

**If you deployed from the published image, you have no `deploy/` directory.**
The scripts are inside the image; take them out of it:

```bash
podman run --rm ghcr.io/reyemb/painfree:0.4.0 deploy-scripts | tar x
```

That writes `deploy/` into the current directory — seven scripts, matching the
image you are running rather than whatever `main` looks like today. `docker run`
works identically.

### Why not `tar czf everything.tar.gz .`

`state/db` is owned by a uid inside the container's user namespace, so `tar` and
`cp -r` run as you will skip it, keep going, and exit 0. The archive that comes
out holds the custody secret and the certificates but not the database — it
looks complete and restores to nothing. `snapshot.sh` takes the database as a
`pg_dump` from inside the container that can read it, and refuses to write
anything if that dump comes back empty.

### Encrypting it — not optional, and not a step afterwards

The archive contains the custody secret **and** the sealed keys that secret
opens. Everything else in this project keeps those two apart; a snapshot is the
one artefact that deliberately puts them together, because a move needs both.
Anyone who reads the file can start your stack elsewhere and sign payments from
your accounts.

So `snapshot.sh` has no default. It takes one of three answers and refuses to
write anything without one:

| | |
|---|---|
| `--encrypt-to age1…` | a public key. Nothing secret is typed or stored on this host |
| `--encrypt-to keys.txt` | a file of public keys, for more than one recipient |
| `--passphrase` | prompts twice. Fine for a move you complete today |
| `--plaintext` | no encryption, said out loud. Prints how to encrypt it afterwards |

Make a key pair once, on the machine that will *receive* the backup:

```bash
age-keygen -o painfree-backup.key      # prints the public key; keep the file safe
```

Give the public key to `--encrypt-to`. Keep `painfree-backup.key` anywhere other
than the host being backed up — a key stored beside its own ciphertext is a
filename, not a key.

The tar is piped straight into `age`, so the plaintext never becomes a file. It
cannot be left behind by an interrupted run and cannot be recovered from free
space afterwards.

Without `age` installed (`apt install age`, `brew install age`,
`nix profile install nixpkgs#age`):

```bash
deploy/snapshot.sh --plaintext
openssl enc -aes-256-ctr -pbkdf2 -iter 600000 -salt \
    -in backups/painfree-….tar.gz -out backups/painfree-….tar.gz.enc
shred -u backups/painfree-….tar.gz
```

That leaves the plaintext on disk between the two commands, which is why it is
the fallback and not the recommendation.

### Restoring on the new machine

The new host needs podman or docker and nothing else — no Python, no `uv`, no
database.

```bash
age -d -i painfree-backup.key painfree-….tar.gz.age | tar xz
cd painfree-…

mkdir -p deploy && mv secrets deploy/secrets
chmod 700 deploy/secrets && chmod 444 deploy/secrets/*

podman-compose up -d                 # empty stack, schema migrates
deploy/restore.sh painfree.dump      # checks the custody key before it starts
podman-compose exec -T worker python - < deploy/verify-keys.py
```

**Those two `chmod` lines are load-bearing.** The secret files are bind-mounted
into containers that run as an unprivileged uid of their own, which is not your
uid, so the files have to be readable by *other* — `0444`. The `0700` directory
around them is what keeps them private; that is where the protection lives, not
in the file bits. A `0600` file owned by you is a stack whose `api` and `worker`
restart-loop on:

```
{"level": "error", "event": "service.misconfigured", "reason":
 "PAINFREE_DATABASE_URL_FILE is '/run/secrets/painfree_database_url',
  which could not be read: Permission denied"}
```

`init-secrets.sh` sets these modes for you; a hand-unpacked archive is the one
path that does not go through it.

`restore.sh` compares the custody key id the restored rows name against the one
this deployment holds and exits 2 rather than letting you discover a mismatch at
the next payment. `verify-keys.py` then opens every sealed key and signs a real
`HPB` request — hand that document to an independent EBICS implementation if you
want the proof to mean something.

Two settings usually change with the address: the four port variables in `.env`
(80 and 443 on a real hostname, which is what ACME needs), and
`PAINFREE_OIDC_REDIRECT_URI`, which must also be registered with your identity
provider or nobody can sign in to the console afterwards.

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

### `payment.json`, an ordinary transfer

One debit account, one execution date, and the transfers to make. Everything
ISO 20022 needs and this service can derive — the message id, the timestamp,
the transaction count, the control sum — is derived rather than demanded,
because a field the caller has to compute is a field the caller computes
wrongly.

```json
{
  "debtor": {
    "name": "MUSTER AG",
    "postal_address": {"town": "SELDWYLA", "country": "CH"}
  },
  "debtor_iban": "CH5604835012345678009",
  "requested_execution_date": "2026-09-30",
  "transactions": [
    {
      "amount": "3949.75",
      "currency": "CHF",
      "creditor": {
        "name": "Robert Schneider AG",
        "postal_address": {
          "street": "Rue du Lac", "building_number": "1268",
          "postal_code": "2501", "town": "Biel", "country": "CH"
        }
      },
      "creditor_iban": "CH4431999123000889012",
      "reference": {"type": "QRR", "reference": "210000000003139471430009017"}
    }
  ]
}
```

`reference.type` is `QRR` for a Swiss QR reference, `SCOR` for an ISO 11649
creditor reference, or `NONE`. Which one is allowed depends on the account —
a QR reference belongs to a QR-IBAN — and the pair is checked before anything
is built. Use `remittance_information` instead for unstructured text; a
structured reference and free text together is refused.

### `payment.json`, an instant transfer

The same body with `scheme` added. It is the only difference:

```json
{
  "scheme": "instant_or_normal",
  "debtor": {"name": "MUSTER AG"},
  "debtor_iban": "CH5604835012345678009",
  "requested_execution_date": "2026-09-30",
  "transactions": [
    {
      "amount": "42.00",
      "currency": "CHF",
      "creditor": {"name": "Robert Schneider AG"},
      "creditor_iban": "CH4821966000009613388",
      "remittance_information": "Invoice 2026-114"
    }
  ]
}
```

**Payment schemes.** A payment carries `normal`, `instant`, or
`instant_or_normal`, which tries instant and sends an ordinary transfer if the
bank definitively refuses. A timeout, a dropped connection or an answer that
will not parse is an unknown outcome rather than a refusal: the order is
retried carrying the message it already had, so nothing is sent twice.
`scheme` may also be set per transfer, but every transfer in one message has to
end up on the same scheme: one upload carries one BTF.

**Instant needs a profile your bank actually publishes, and the default is a
guess.** An instant upload is announced with a BTF triplet, and the one shipped
here is the EPC SEPA convention — service option `INST`, `SvcLvl/Cd` `SEPA`,
`LclInstrm/Cd` `INST`. That is the *euro* scheme. A Swiss bank on SIC instant
publishes its own triplet and may use `LclInstrm/Prtry` instead, and plenty of
banks publish none at all, because their EBICS catalogue has one upload row and
it is `pain.001`.

So check your bank's EBICS parameter sheet before asking for `instant`, and set
the profile on the connection to whatever it lists. If the bank has no instant
row, clear the instant profile in the console: with it left populated, `instant`
fails at the bank with `091112 EBICS_INVALID_ORDER_PARAMS` and
`instant_or_normal` spends a wasted round trip on every payment before falling
back. With it cleared, both are decided locally — `instant` is refused before
anything is signed, and `instant_or_normal` goes out as an ordinary transfer
first time.

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
| `PAINFREE_EBICS_USER_AGENT` | none | unset sends no `User-Agent` at all, which is what a bank expects; one firewall refuses Python's default |
| `PAINFREE_OIDC_ISSUER` / `_CLIENT_ID` / `_REDIRECT_URI` | none | all three required for `oidc` |
| `PAINFREE_OIDC_ADMIN_ROLE` / `_MEMBER_ROLE` | `admin,administrator` / `member,operator,viewer,auditor` | what your directory calls these, comma-separated; both resolved values appear in the startup line |

Logs are one JSON object per line on stdout. No token, authorization code,
session id or client secret ever reaches the stream.

## Backup, and the one thing no backup covers

Three scripts, and which is for what:

| | contains | for |
|---|---|---|
| `deploy/backup.sh` | the database only | the running backup. **Refuses to copy the custody secret** |
| `deploy/backup-secrets.sh` | `deploy/secrets/` and the local CA, ~4 KB | the copy that goes into your password manager, off this host |
| `deploy/snapshot.sh` | **both**, plus the config and certificates | moving to another machine |

The separation that matters is between the first two: the lock and the key, kept
in different places. `snapshot.sh` deliberately holds both, because a move needs
both — which is why it will not write itself unencrypted. See
[Backups, and moving to another server](#backups-and-moving-to-another-server).

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
