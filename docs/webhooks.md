# Webhooks

painfree pushes an event to your endpoint when something happens to an order or
a statement. This is the contract: what arrives, how to verify it came from
your deployment, and what the delivery guarantees are.

painfree emits **normalised events**. Matching them against your ledgers is
yours to do.

## Envelope

```jsonc
{
  "version": 1,                      // envelope version; fields may be added within it
  "event_id": "5056b591-efd5-46bb-8ba9-a50a48155ab2",
  "event_type": "order.rejected",
  "occurred_at": "2026-08-29T23:07:48.418Z",
  "connection_id": "acme-ubs",       // present when the event belongs to one
  "order_id": "ord_f709e079…",       // present on every order.* event
  "idempotency_key": "caller-idem-0001",  // present when the event came from a submission
  "data": { }                        // event-type specific
}
```

The four correlation fields sit at the top level so you can route on them
without knowing the type. **An id that is not known is absent, never `null`** —
a `null` invites a lookup that silently matches nothing.

`event_id` is stable across redeliveries. It is also the id of the audit row
that recorded the fact, so the value you deduplicate on is the value an operator
greps in the audit trail and in the container logs.

## Event types

| Type | Fires when | `data` carries |
|---|---|---|
| `order.accepted` | validated and enqueued | `msg_id`, `message_type`, `transactions`, `currency`, and the four scheme fields |
| `order.submitted` | the bank returned an `OrderID` | `order_state`, `bank_order_id`, `return_code` |
| `order.rejected` | **the bank** refused — at submission, or in a `pain.002` | `order_state`, then either `return_code`, `return_code_name`, `report_text` or `source`, `status`, `status_name`, `reason_code`, `reason_text`, `statement_id`, `msg_id` |
| `order.failed` | painfree gave up after the retry ceiling | `order_state`, `attempts`, `reason` |
| `order.acknowledged` | a `pain.002` naming the order's `MsgId` says the bank took the payment | `order_state`, `source`, `status`, `status_name`, `statement_id`, `msg_id`, and where the bank gave them `reason_code`, `reason_text`, `transactions_accepted`, `transactions_rejected` |
| `statement.available` | a scheduled download produced a new document | `statement_id`, `message_type`, `kind`, `entries`, `run_id` |
| `webhook.ping` | an operator asked for a test delivery | `subscription_id`, `requested_by`, `message` |

Five things the table cannot say in a cell.

**`webhook.ping` is not subscribable.** No bank event produces one. Your
endpoint receives one only because somebody aimed a test at that subscription,
and it travels the ordinary path — same queue, same signature, same retries — so
what it proves is what a real event would do. Answer it `2xx` and ignore the
body.

**`order.rejected` is the bank and only the bank.** A payment that fails local
validation never becomes an order, and a reused idempotency key is a caller bug
against an order that still stands. Neither emits anything.

**Two events have two writers.** `order.rejected` and `order.acknowledged` come
either from the upload worker — the bank refusing the *transfer*, with an EBICS
return code — or from the reconciler reading a `pain.002` — the bank answering
about the *payment*, with an ISO 20022 status. Two different vocabularies, and
`data.source` says which one is in front of you: `"pain.002"` on the
status-report path, absent on the submission path.

`status` is the bank's group status verbatim (`ACSP`, `PART`, `RJCT`, …) and
`status_name` is its ISO name. `transactions_accepted` / `transactions_rejected`
appear when the report itemised transactions — a `PART` is an acknowledgement
with a non-zero `transactions_rejected`, and the accepted part of that batch has
been executed. `statement_id` is the stored status report; fetch it from
painfree.

**An interim `pain.002` emits nothing.** A `PDNG` changes no state, so there is
no event. Nor does a report for an order that is already terminal, nor one
naming a `MsgId` this deployment never sent. Events report changes, and none of
those three is one.

**Every order event carries the payment scheme.** `data` on all five `order.*`
events carries `scheme` (what was actually sent), `requested_scheme` (what you
asked for), `scheme_downgraded` and `scheme_reason`. There is deliberately no
new event type: if you asked for an instant payment and it went normal, you
learn that on an event you already receive rather than by subscribing to
something you did not know existed. `scheme_reason` is one of `requested`,
`connection_default`, `preflight.instant_not_configured`,
`preflight.amount_above_instant_ceiling`, or
`bank_refused_instant:<six-digit EBICS code>` — the last meaning the bank
definitively refused instant before acknowledging receipt, and the ordinary
message painfree had already built went instead. It is still one order under one
idempotency key; the fallback is a second attempt at it, with its own `MsgId`,
and the order can end accepted at most once.

**The field is `order_state`, not `state`.** `state` is on painfree's
log-redaction blocklist — it is an OIDC login parameter — so a value written
under that name would reach you as `"***"`.

## What an event does not carry

**Never payment or statement content, and never key material.** A `camt` entry
is somebody's payment — a counterparty, an amount, a reference — and it is
decrypted order data like any other. `statement.available` therefore tells you
*which* statement is available and how big it is; you fetch the content from
painfree.

That is a deliberate reading of "enough to act without calling back": for an
order event you chose the `idempotency_key` and hold your own copy of what you
submitted, so the correlation fields are enough. For a statement, acting *is*
fetching it.

## Verifying the signature

Every request carries an HMAC over the exact bytes of the body, with the
subscription's own secret.

| Header | Value |
|---|---|
| `X-Painfree-Event` | the event type |
| `X-Painfree-Event-Id` | the `event_id`, also in the body |
| `X-Painfree-Delivery` | this delivery's id; the same across its retries |
| `X-Painfree-Attempt` | 1-based attempt number |
| `X-Painfree-Timestamp` | Unix seconds, **inside the MAC** |
| `X-Painfree-Signature` | comma-separated `v1=<hex>` — one entry ordinarily, two during a rotation |

```
signature = "v1=" + HMAC_SHA256(secret, timestamp + "." + raw_request_body)
```

To verify: **split the header on `,`**, and for each entry split on `=`; refuse
a scheme you do not know; recompute over the **raw bytes you received** — not
over a re-serialisation of your own parse — and compare in constant time.
**Accept if any entry verifies.** Then check the timestamp against your own
clock and refuse anything older than your replay window; the timestamp is
covered by the MAC, so it cannot be re-dated.

The list is what makes a rotation survivable at your end. **A consumer that
reads only the first entry works today and breaks the first time somebody
rotates.**

```php
$expected = hash_hmac("sha256", $ts . "." . $body, $secret);   // PHP
```
```ruby
expected = OpenSSL::HMAC.hexdigest("SHA256", secret, "#{ts}.#{body}")   # Ruby
```
```python
expected = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
```

The body is serialised with sorted keys and no whitespace, so a redelivery is
byte-identical to the first attempt and verifies under the same signature.

### The secret

Generated when you register the subscription and returned in that response
**only** — or supplied by you, if your receiver is configured first. painfree
then seals it to a key the API process holds no private half for, so it cannot
show you the value again. That is a property of where the key material lives,
not a route that declines.

### Rotating it

A lost or leaked secret is replaced, not re-registered: re-registering would
start a subscription with an empty queue and drop everything the old one was
owed.

1. `POST /v1/webhooks/{id}/secret` returns a new secret, once. The old one
   **keeps signing**: every delivery now carries two entries in
   `X-Painfree-Signature`, the new one first.
2. Configure the new value in your receiver. Nothing is refused meanwhile — you
   verify on the old entry until you hold the new one, and on the new entry
   afterwards.
3. `DELETE /v1/webhooks/{id}/secret/previous` ends the overlap.

`secret_generation` tells you which value is current without repeating the
value, and `secret_rotating` says whether step 3 is outstanding. A second
rotation before step 3 is `409` — it would discard the value your endpoint is
actually using.

## Delivery

- **At-least-once.** Duplicates are the price of never losing an event.
  Deduplicate on `event_id`.
- **Persisted before the first attempt**, in the same transaction as the fact it
  reports. A crash between "it happened" and "we told you" cannot lose it.
- **Ordered per subscription.** One event is in flight at a time and nothing
  later is sent while something earlier is still owed, including during a
  backoff. So `order.accepted` always precedes `order.submitted`.
- **Retried with backoff** — 10 s, 1 min, 5 min, 30 min, then the delivery is
  `failed`. A `2xx` is success; anything else, including a redirect, is not.
- **Parked, not retried for ever.** Three consecutive exhausted deliveries park
  the subscription: nothing more is attempted, the queued events are kept, and
  an operator resumes it once your endpoint is fixed. A parked endpoint never
  blocks another one.
- **Answer promptly.** The timeout is 15 seconds, and a slow consumer delays its
  own next event. Acknowledge with `2xx` first and do the work afterwards.

## Subscriptions

One endpoint, the event types it wants, and optionally one `connection_id` to
scope it to — omit it and the subscription receives every connection's events.

Register over HTTP at `POST /v1/webhooks` (scope `webhooks:manage`) or in the
operator console at `/ui/webhooks`, which also shows each endpoint's health, its
recent deliveries, and the controls to pause, resume, un-park, test and rotate
it.

**A paused endpoint keeps what it is owed** — `enabled: false` stops delivery
and stops new events being created for it, and nothing is lost. **A deleted one
does not**: the events still queued go with it, and the response says how many.
An endpoint that is coming back is paused, not deleted.
