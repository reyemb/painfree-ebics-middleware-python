# Behind your own reverse proxy

painfree ships a proxy — Caddy, in `compose.yaml` — that terminates TLS and
publishes the console on loopback. That is the whole deployment when painfree is
the only thing on the host.

It usually is not. If you already run Traefik, nginx or Caddy in front of
everything, painfree goes behind it and stops terminating TLS itself. This is
how, and what breaks if you skip a step.

## The short version

```bash
PAINFREE_SITE_ADDRESS=:8080                                   # plain HTTP, no certificate
PAINFREE_TLS_TERMINATED_UPSTREAM=true                         # not optional -- see below
PAINFREE_OIDC_REDIRECT_URI=https://painfree.example.com/auth/callback
```

Then either publish nothing and let your proxy reach the container over the
container network, or keep `PAINFREE_HTTP_BIND=127.0.0.1:8080` and point your
proxy at loopback. Publishing nothing is better: this host holds bank keys, and
a port that does not exist cannot be reached by mistake.

## Keep the bundled proxy, or drop it?

**Keep it.** It is one variable either way, and it carries five response headers
you would otherwise have to reproduce:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: same-origin
-Server
```

Dropping Caddy and pointing your proxy straight at `api:8000` works and silently
loses all five. If you do it anyway, set them in your proxy.

With `PAINFREE_SITE_ADDRESS=:8080` Caddy stops asking for a certificate and
serves plain HTTP on 8080 — `http_port` follows `PAINFREE_HTTP_PORT`, so the
ports stay one decision in one place. The HTTPS port is then unused; comment it
out rather than publishing a port nothing listens on.

`/local-ca.crt` and `state/caddy-data/` become irrelevant. They cost nothing and
are worth keeping until you are sure you are not going back.

## `PAINFREE_TLS_TERMINATED_UPSTREAM` is not cosmetic

It decides whether painfree believes `X-Forwarded-For`:

```python
if settings.tls_terminated_upstream:
    nearest = request.headers.get("x-forwarded-for", "").split(",")[-1].strip()
```

Leave it off and every request looks like it came from your proxy's address. The
per-source sign-in lockout then counts one attacker's failures against
*everybody* and locks the office out. Turn it on only when it is true: with
nothing in front, the header is written by the caller, and a lockout keyed on a
value the caller chooses is not a lockout.

In `basic` auth mode painfree refuses to start in production without it, because
HTTP Basic puts a reversible credential in every request. In `oidc` mode it
starts either way — the lockout is the thing that quietly goes wrong.

## The redirect URI is configuration, and it locks you out

```bash
PAINFREE_OIDC_REDIRECT_URI=https://painfree.example.com/auth/callback
```

The path is `/auth/callback`, **not** `/ui/auth/callback`. Register the same
value with your identity provider as a valid redirect URI.

Get this wrong and sign-in fails after the move, with the provider refusing the
redirect. painfree deliberately never derives this from the `Host` header — a
forged `Host` would otherwise choose where a login comes back to — so it does
not adapt to the new address on its own. It has to be told.

## A caveat worth knowing

The bundled Caddy sets `X-Forwarded-Proto` from the scheme *it* was addressed
on:

```
reverse_proxy api:8000 {
    header_up X-Forwarded-Proto {scheme}
}
```

Behind your proxy that is `http`, so it overwrites the `https` your proxy
correctly set. Nothing in painfree reads this header today — the redirect URI is
configuration, the session cookie's `Secure` flag comes from
`PAINFREE_ENVIRONMENT`, and no absolute URL is built from a request — so the
value is currently unused rather than wrong-and-acted-on.

If you want it accurate, tell Caddy which peer to trust and it will preserve the
incoming headers instead of replacing them:

```
{
    servers {
        trusted_proxies static <your proxy's network>
    }
}
```

That range is specific to your deployment, which is why it is not in the shipped
file.

## What does not change

- **Nothing about EBICS.** painfree always dials out to the bank; the bank never
  connects to painfree. A reverse proxy changes how *you* reach the console, not
  how payments reach the bank. No inbound reachability is needed for EBICS at
  all.
- **Webhooks** also go outward, to a URL you configure. See
  [webhooks.md](webhooks.md).
- **`PAINFREE_ENVIRONMENT=production`** still drives the `Secure` flag on session
  cookies. Keep it set.
