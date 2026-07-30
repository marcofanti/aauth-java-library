# Progress Log

Status of each phase from [PLAN.md](PLAN.md). Updated as work lands.

| Phase | Scope | Status |
|---|---|---|
| 1 | Scaffolding: POMs, quality gates, docs, git | in progress |
| 2 | aauth-signing: keys (keypairs, JWK, thumbprints, JWKS) | pending |
| 3 | aauth-signing: RFC 9421 core | pending |
| 4 | aauth-signing: Signature-Key + signer/verifier | pending |
| 5 | aauth: errors, identifiers, HTTP abstraction | pending |
| 6 | aauth: tokens | pending |
| 7 | aauth: headers | pending |
| 8 | aauth: metadata | pending |
| 9 | aauth: deferred + agent role | pending |
| 10 | aauth: resource role | pending |
| 11 | interop + docs + review | pending |

## Decision log

- **2026-07-30 — Toolchain**: local JDK is Corretto 26; compiling with `--release 17`.
  All dependency versions looked up on Maven Central at scaffold time (Nimbus 10.3,
  structured-fields 0.4, Jackson 2.19.0, JUnit BOM 6.1.2, AssertJ 3.27.7).
- **2026-07-30 — Error Prone / NullAway deferred**: on JDK 26 they require fragile
  `--add-exports` wiring into the compiler fork. Baseline warnings policy is enforced via
  `-Xlint:all,-serial,-processing -Werror` instead. Revisit once the port is complete.
- **2026-07-30 — WireMock dropped**: test HTTP servers use the JDK's built-in
  `com.sun.net.httpserver.HttpServer` — zero extra dependencies and no JUnit-major
  compatibility risk.
- **2026-07-30 — JUnit 6.1.2**: current stable line; validated with a toolchain smoke test
  in phase 1.

## Deviations from the Python library

(none yet — recorded here as they arise)
