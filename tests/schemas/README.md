# Schemas the downloaded-document fixtures are held to

These are **test** schemas, not runtime ones. Nothing in `painfree/` loads them,
and a `camt` document a bank sends is *not* validated against a schema before it
is ingested: refusing a statement on a schema quibble is worse than
storing it.

What they are for is the other direction: the fixtures in `tests/fixtures/` are
written in this repository, so without an independent schema they would prove
only that the parser reads documents shaped the way the parser expects. Every
fixture is validated against the official XSD for its own message version before
any assertion is made about what was parsed out of it.

| File | Provenance | sha256 |
|---|---|---|
| `camt.052.001.08.xsd` | [`ebics-api/ebics-client-php`](https://github.com/ebics-api/ebics-client-php) (MIT), `doc/schema/camt.052.001.08.xsd` | `589b55980dd6e553de78ba036eb733308da201bda4c3158e10b22cb003911e8f` |
| `camt.053.001.08.xsd` | the same, `doc/schema/camt.053.001.08.xsd` | `ca0b135cc8e2dde5b2f99af6b6c514a8f29d6e7c6cf98e9ea84d247189868ff5` |
| `camt.054.001.09.xsd` | [`rust-iso/rust_iso20022`](https://github.com/rust-iso/rust_iso20022) (Apache-2.0), `xsds/camt.054.001.09.xsd` | `4a8c8b27f6966846e3c847d0e56c138bd8ee034d021f61efde49d6827627bf1a` |
| `pain.002.001.10.xsd` | the same, `xsds/pain.002.001.10.xsd` | `2f9f8d0e9891fa9f31ccf0576397afe501614384d688ae6e43ba694b3d24b0cf` |

All four are ISO 20022 Standards Editor output, unedited, each with the
`targetNamespace` its file name says.

Two notes on the provenance, because a vendored schema is worth what its source
is worth:

- **`pain.002.001.10.xsd` was cross-checked against a second, unrelated source.**
  [`altasoft/geo-iso20022`](https://github.com/altasoft/geo-iso20022)'s copy is
  identical to this one modulo whitespace. Two independent publishers agreeing
  character for character is the closest thing to the ISO 20022 site available
  from this environment, which cannot reach it.
- **`camt.054` is at `.09`, not `.08`, and that is not a preference.** No copy of
  `camt.054.001.08.xsd` could be found from here — not in either reference
  project and not in any public repository reachable from this environment — and
  a schema is not something to reconstruct by hand. So the `camt.054` fixture is
  written at the version whose schema exists. That the four fixtures span three
  ISO versions is useful in itself: the parser reads by local name, and this is
  what proves it.
