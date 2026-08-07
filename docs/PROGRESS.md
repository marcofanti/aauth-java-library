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

- **2026-08-07 — Releases 0.2.2 and 0.2.3**: 0.2.2 shipped the loose `ps`-claim
  validation (#16 — `Identifiers.validateServerUrl`: token verification accepts any
  well-formed http(s) `ps` URL, so non-TLS dev/demo origins like
  `http://ps.uma.lab:8765` verify; HTTPS-in-production is deployment policy, not a
  token check) plus the DEMO.md repoint to aauth-full-java-demo (#14). It was tagged
  before the EdDSA JWK tolerance (#15) merged, so 0.2.3 followed immediately from main
  with #15 included — downstream consumers should pin **0.2.3** and skip 0.2.2.
- **2026-08-06 — JWK alg EdDSA tolerated on Ed25519 keys**: `Jwk.requireConsistentAlg`
  now accepts the legacy polymorphic `EdDSA` when the key is `OKP/Ed25519` (rejected on
  any other shape). Rationale: the pre-draft-10 ecosystem — including the Python
  reference's clients — emits `alg: EdDSA` in JWKS, and the 0.2.x hard reject broke
  Java-verifies-Python resource tokens (found live: the person server's mode-3 interop
  script failed with "Forbidden or unsupported JWK alg: EdDSA"). This matches the
  token-header transition policy (accepts `Ed25519` and legacy `EdDSA`); both tolerances
  flip to strict together once the ecosystem is on draft-10.

- **2026-07-30 — Java baseline raised to 26** (user request, mid-implementation): compiler
  `--release 26`, enforcer requires Java 26+. Code written against the 17 baseline compiles
  unchanged; newer language features may be used from here on.

- **2026-07-30 — Toolchain**: local JDK is Corretto 26; compiling with `--release 17`.
  All dependency versions looked up on Maven Central at scaffold time (Nimbus 10.3,
  structured-fields 0.4, Jackson 2.19.0, JUnit BOM 6.1.2, AssertJ 3.27.7).
- **2026-07-30 — Error Prone / NullAway deferred**: on JDK 26 they require fragile
  `--add-exports` wiring into the compiler fork. Baseline warnings policy is enforced via
  `-Xlint:all,-serial,-processing -Werror` instead. Revisit once the port is complete.
- **2026-08-02 — Error Prone + NullAway enabled** (deferral closed): Error Prone 2.50.0 runs
  on main sources of both modules (tests compile plain); the jdk.compiler exports/opens live
  in `.mvn/jvm.config`. All findings fixed except `ArrayRecordComponent`, suppressed with
  justification on records carrying raw `byte[]` crypto/HTTP bytes. NullAway 0.13.8 runs in
  `OnlyNullMarked` mode with JSpecify annotations: `aauth-signing` is fully `@NullMarked`
  (nullable params/returns annotated; builders validate before constructing records).
  **Next increment**: `@NullMarked` the `aauth` module package by package.
- **2026-07-30 — WireMock dropped**: test HTTP servers use the JDK's built-in
  `com.sun.net.httpserver.HttpServer` — zero extra dependencies and no JUnit-major
  compatibility risk.
- **2026-07-30 — JUnit 6.1.2**: current stable line; validated with a toolchain smoke test
  in phase 1.

## STRICT draft-10 alg — STAGED, NOT MERGED (branch `strict-alg-draft10`)

A branch that flips the transition tolerances to strict draft-10, prepared **ahead of the
ecosystem** and deliberately **not merged**:

- `Jwts` / `TokenSupport`: token headers must be `Ed25519`; legacy `EdDSA` is rejected.
- `Jwk.requireConsistentAlg`: legacy polymorphic `EdDSA` in a JWK is rejected (falls through
  to unsupported-alg). Absent `alg` is still tolerated — the draft-10 "MUST reject absent
  alg" rule is intentionally left for merge time, aligned with the ecosystem's actual JWK
  emission (it reorders `toPublicKey` error semantics and is the most likely detail to change).
- Tests updated to assert strict rejection; `PythonInteropTest.pythonAuthTokenVerifiesInJava`
  now asserts the Python (EdDSA) token is **rejected** — flip back to positive verification
  when Python emits `Ed25519`.

**Gate to merge:** the Python reference library (and the rest of the ecosystem — person
server, demo) must be on draft-10 (emit `Ed25519`). As of 2026-08-07 the Python lib is still
pre-10 (`aauth 0.3.5`, emits/verifies `EdDSA`, last upstream commit 2026-06-16). Merging
before then breaks all Python interop, including the demo's polyglot step. Rebase this branch
onto main and re-validate against Python's actual draft-10 wire format when the gate opens.

## AAuth draft-10 compliance (2026-08-06)

Protocol draft **-10** and Signature-Keys draft **-08** introduced normative changes (driven
by RFC 9864). Strategy: **compliant emission, tolerant verification** — the Python reference
library has not yet updated, so we emit the new wire format while still accepting the old.

- Every emitted JWK carries a fully-specified `alg` (`Ed25519`/`ES256`/`ES384`), including
  `cnf.jwk` and the inline `hwk` Signature-Key parameters. `Jwk.toPublicKey` validates `alg`
  when present (rejects `EdDSA`, `none`, HS*, kty/crv mismatch) but tolerates its absence.
- Token headers now use `alg: Ed25519`; verification accepts `Ed25519` and legacy `EdDSA`.
- New error codes `unsupported_scheme` / `cache_miss` and the `Accept-Signature-Scheme` /
  `Accept-Signature-Alg` response headers (build/parse).
- New `account` claim on resource and auth tokens (authorization-endpoint account selection,
  draft-10 §12.3); new `parent_agent` claim on agent tokens with the §5.2.4 verification
  steps (`ps` and `parent_agent` identifier validation).
- Interop: Python→Java directions still pass; the Java→Python token test asserts structural
  parsing and auto-heals to full verification once upstream reaches draft-10.

**Follow-ups**: flip to strict `alg`-required verification once the Python library and the
person server are on draft-10; phase B for the new sigkey-08 schemes (`jwks`, `self-jwt`,
`cached`, direct x509) and the AAuth §12.8.2 `scheme=jwt`-only rule.

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
- **Mission binding helpers and coverage enforcement (2026-08-06)**: new
  `MissionBinding` utility (`s256` per the PS reference: unpadded base64url SHA-256 of the
  mission JSON; `matchesDocument` / `matchesClaim`). `RequestVerifier` now surfaces the
  parsed `AAuth-Mission` header in its `Result` and — stricter than the Python reference —
  rejects requests that carry `AAuth-Mission` without covering `aauth-mission` in the
  signature (an uncovered header could be swapped after signing). Mission lifecycle/state
  remains person-server territory.
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
