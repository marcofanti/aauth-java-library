# Progress Log

Status of each phase from [PLAN.md](PLAN.md). Updated as work lands.

| Phase | Scope | Status |
|---|---|---|
| 1 | Scaffolding: POMs, quality gates, docs, git | done |
| 2 | aauth-signing: keys (keypairs, JWK, thumbprints, JWKS) | done — RFC 7638/8037 vectors pass |
| 3 | aauth-signing: RFC 9421 core | done — signature base, headers, RFC 9530 digest vector |
| 4 | aauth-signing: Signature-Key + signer/verifier | done — all 4 schemes round-trip; 75 tests |
| 5 | aauth: errors, identifiers, HTTP abstraction | done |
| 6 | aauth: tokens | done |
| 7 | aauth: headers | done |
| 8 | aauth: metadata | done |
| 9 | aauth: deferred + agent role | done — poller state machine, PS token exchange vs local HTTP server |
| 10 | aauth: resource role | done — includes full challenge→sign→verify protocol loop test |
| 11 | interop + docs + review | done — 4 Java↔Python interop tests pass both directions; README; reviewed |

## Decision log

- **2026-07-30 — Java baseline raised to 26** (user request, mid-implementation): compiler
  `--release 26`, enforcer requires Java 26+. Code written against the 17 baseline compiles
  unchanged; newer language features may be used from here on.

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

## Final review (2026-07-30)

A security-focused review (java-reviewer agent) of the finished port found 4 issues, all fixed
with regression tests in the same session:

1. **HIGH** — `RequestVerifier` accepted an empty/whitespace `scope` claim as satisfying
   `requireAuthToken` (Python's truthiness check rejects it). Fixed: blank scopes yield no
   scope list, and the gate now rejects empty lists.
2. **MEDIUM** — `Poller` fired interaction/clarification callbacks on empty-string
   `code`/`clarification` values where Python skips them. Fixed with non-empty checks.
3. **LOW** — `Identifiers` lowercase check used the default locale; now `Locale.ROOT`.
4. **LOW** — scope splitting used single-space split; now whitespace-collapsing
   (`strip().split("\\s+")`), matching Python's `str.split()`.

All crypto/verification paths (signature schemes, token verification order, Ed25519 point
encoding, P1363/DER handling, JWKS discovery) were confirmed equivalent to the Python
reference with no findings.

## Post-completion (2026-07-30, after initial push)

- Repo published at https://github.com/marcofanti/aauth-java-library (pushed by the user).
- **CI added** (PR #1): GitHub Actions workflow running `mvn verify` on JDK 26 (Temurin),
  actions SHA-pinned, `persist-credentials: false`, read-only permissions; validated with
  actionlint and zizmor. Interop tests self-skip in CI (no Python checkout).
- **prek hooks added**: whitespace/EOF/YAML/merge-conflict/large-file checks + local
  `spotless:check`; installed via `prek install`.
- **CI portability fix**: live-socket tests resolve `*.uma.lab` hostnames only when they map
  to loopback (see `TestHosts`); CI runners fall back to `127.0.0.1`. First CI run failed on
  unresolvable lab hostnames; second run green.

- **Maven Central plumbing added (2026-08-02)**: `<scm>` metadata plus a `release` profile
  (sources/javadoc jars, GPG signing, central-publishing-maven-plugin). Manual steps
  (Portal signup, GPG key) documented in RELEASING.md. Normal builds unaffected.

- **HTTP/1.1 pinned for library-constructed clients (2026-08-02)**: downstream use against
  uvicorn/h11-based servers (the AAuth Person Server) showed the JDK HttpClient's default
  h2c upgrade makes h11 reject requests (400) or silently drop POST bodies. Both
  library-constructed defaults (`DefaultHttpClient`, `TokenExchange.Exchange`) now set
  `HttpClient.Version.HTTP_1_1`; caller-injected clients are untouched.

## Test fixtures

Per user request (2026-07-30), test fixtures and examples use the local UMA lab hostnames
instead of `localhost`/`*.example`: `gateway.uma.lab` (resource), `alice-as.uma.lab` (auth
server), `ps.uma.lab` (person server), `portal.uma.lab` (agent server), `grafana.uma.lab` /
`keycloak.uma.lab` (miscellaneous). These resolve to 127.0.0.1 on this machine, so the
live-socket tests (JDK HttpServer) bind locally and use the lab names in URLs. The single
`http://localhost:8080` in `MetadataTest` is intentional — it tests the spec's
localhost-only HTTP carve-out itself.

## Deviations from the Python library

- **Content-Digest is enforced in the resource role (2026-08-02)**: both this library's
  low-level `SignatureVerifier` and the Python reference only sign/verify the
  `Content-Digest` *header*, so a tampered body with an intact header passes the HTTP
  signature. `RequestVerifier.verifyRequest` now recomputes the RFC 9530 digest from the
  body whenever both header and body are present and fails with
  `content-digest mismatch` on divergence. The low-level `SignatureVerifier` is unchanged
  for wire-format parity. Since 2026-08-02 the check parses the header as an RFC 9530
  dictionary: sha-256 and sha-512 are both verified (every recognized member must match),
  and a header carrying only unrecognized algorithms fails with
  `unsupported content-digest algorithm` (fail closed).
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
