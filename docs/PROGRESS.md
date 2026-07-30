# Progress Log

Status of each phase from [PLAN.md](PLAN.md). Updated as work lands.

| Phase | Scope | Status |
|---|---|---|
| 1 | Scaffolding: POMs, quality gates, docs, git | done |
| 2 | aauth-signing: keys (keypairs, JWK, thumbprints, JWKS) | done — RFC 7638/8037 vectors pass |
| 3 | aauth-signing: RFC 9421 core | done — signature base, headers, RFC 9530 digest vector |
| 4 | aauth-signing: Signature-Key + signer/verifier | done — all 4 schemes round-trip; 75 tests |
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

- **Signature header base64 flavor preserved**: the Python library base64url-encodes the
  `Signature` header value (RFC 9421 §4.2 specifies sf-binary, i.e. standard base64).
  We mirror the Python behavior for interop; both parsers only accept the urlsafe alphabet.
- **`KeyPair` instead of bare private key**: Java cannot derive an Ed25519 public key from
  an `EdECPrivateKey`, so signing APIs take `java.security.KeyPair` where Python takes
  `private_key` and calls `.public_key()`.
- **Single `JwksFetcher` shape**: Python probes the fetcher with 3/2/1-argument calls for
  backward compatibility. Java defines one functional interface
  `fetch(id, dwk, kid)`; callers ignore arguments they don't need.
- **Agent tokens live in the `aauth` module only**: Python duplicates
  `tokens/agent_token.py` in both packages but does not export it from `aauth_signing`.
- **One exception hierarchy**: Python defines `AAuthError` twice (once per package).
  Java has a single base in `aauth-signing` that the `aauth` module extends.

### Additional decisions (2026-07-30, start of phase 2)

- **Nimbus JOSE+JWT dropped**: its Ed25519 signer requires Google Tink; JDK 17 has native
  EdDSA. JWTs in this protocol are plain compact EdDSA/ES256/ES384/RS256 tokens — a small
  internal codec (`Jwts`) on JDK crypto + Jackson covers create/parse/verify.
- **greenbytes structured-fields dropped**: the Python library hand-rolls its RFC 8941
  parsing (including tolerance for a legacy inner-list `Signature-Key` form). Porting those
  parsers verbatim gives wire-format parity a strict SF library would not.
- Net dependency footprint: `aauth-signing` → Jackson only; `aauth` → `aauth-signing` + Jackson.
