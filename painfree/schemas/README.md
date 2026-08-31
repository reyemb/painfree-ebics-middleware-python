# Vendored schemas

`pain.001.001.09.xsd` is the ISO 20022 *CustomerCreditTransferInitiationV09*
schema — Standards Editor output, `targetNamespace
urn:iso:std:iso:20022:tech:xsd:pain.001.001.09` — copied verbatim from
[`ebics-api/ebics-client-php`](https://github.com/ebics-api/ebics-client-php)
(MIT), `doc/schema/pain.001.001.09.xsd`.

sha256 `05440a7e84f695e7dbc6677082f43623cd7393881b76a5e8d648ae21d7d728e3`.

It is vendored rather than read from a sibling checkout because it is used at
**runtime**: every generated `pain.001` is validated against it before the order
is recorded, and a validator that depends on a directory next to the repository
is a validator that is silently absent in a container.

It is not edited. The Swiss restrictions (`pain.001.001.09.ch.03`) are a
narrower schema than this one and are not vendored here; they are implemented as
an explicit rule set in `painfree/sps.py`, where a failure can name the rule it
broke.
