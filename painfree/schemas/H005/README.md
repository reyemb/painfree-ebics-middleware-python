# Vendored EBICS 3.0 (H005) schemas

The nine files beside this one are the official EBICS 3.0 schema set,
`targetNamespace urn:org:ebics:H005`, copied verbatim from
[`ebics-api/ebics-client-php`](https://github.com/ebics-api/ebics-client-php)
(MIT), `doc/schema/H005/`.

```
cf9d5d29fac0950f810c2a0018312fe476ab3415d804f5fc00cd4e3aa216136e  ebics_H005.xsd
7165cd441a0c68f6e93c384de743f97d0d768ac444d1adc6daf89d0e1edb0505  ebics_keymgmt_request_H005.xsd
9671ccf4282df1a4089f5d61a86378fa78e38d80292550a34422e15aa802ef3f  ebics_keymgmt_response_H005.xsd
ce19f0e0b8cdfa05678a9e2123e09634f131107e08552e7a1371e6dbbf82e2f1  ebics_orders_H005.xsd
48838ffd60275549849a7054223085154746b920e5f438cd16878fc62004d874  ebics_request_H005.xsd
19226688cd598581b37a7b32cb1df874c525aac710f68dbcc10e11b820eabd4d  ebics_response_H005.xsd
6fcee44bdb80d656e05f11da86303bb25de2cf545203eef30dffbd6c662f8d93  ebics_signature_S002.xsd
0c94813782e725b7698449f117a8f2e6e47d6560b3df83ca53a720d6f6fc4351  ebics_types_H005.xsd
43f97eddd32ca6df482ff1757cd55d784054fa36cb35d882ddc1e52669a37af6  xmldsig-core-schema.xsd
```

They are **vendored rather than read from a sibling checkout for the same
reason `pain.001.001.09.xsd` is: they are used at runtime.** A request the bank
refuses is validated against them where the refusal happens, in the worker, and
a validator that depends on a directory next to the repository is a validator
that is silently absent in a container.

`ebics_H005.xsd` is the umbrella and includes the other four EBICS files; those
in turn include the types, the signature schema and the W3C `xmldsig` core. All
nine are needed to compile the umbrella, so all nine are here.

They are not edited, and nothing here tries to answer what a schema cannot: a
request these accept may still be refused by a bank, because well-formed and
acceptable are different questions and only the first one is decidable locally.
