# AAuth Java Library — Implementation Plan

Approved 2026-07-30. Port of [aauth-python-library](../../aauth-python-library) — the AAuth
protocol ([github.com/dickhardt/AAuth](https://github.com/dickhardt/AAuth)): agent-to-resource
authorization built on HTTP Message Signatures (RFC 9421), the `Signature-Key` header extension
(draft-hardt-httpbis-signature-key), and JWT-based proof-of-possession tokens.

## Coordinates and layout

Multi-module Maven project, JDK 17 baseline.

| Module | Coordinates | Java package | Responsibility |
|---|---|---|---|
| `aauth-signing` | `io.github.marcofanti:aauth-signing` | `io.github.marcofanti.aauth.signing` | RFC 9421 signing/verification + `Signature-Key` header (`hwk`, `jkt-jwt`, `jwks_uri`, `jwt` schemes). Standalone. |
| `aauth` | `io.github.marcofanti:aauth` | `io.github.marcofanti.aauth` | Full protocol: errors, identifiers, tokens, AAuth headers, metadata, deferred responses, agent + resource roles. Depends on `aauth-signing`. |

## Design decisions

- **kwargs → builders/records.** Python keyword-heavy functions become builders plus a sealed
  `SignatureScheme` interface (`Hwk`, `JktJwt`, `JwksUri`, `Jwt` records) so invalid
  scheme/parameter combinations are unrepresentable.
- **Framework-agnostic HTTP.** Core operates on method/URI/headers/body values. JDK
  `java.net.http.HttpClient` behind small interfaces for JWKS/metadata fetching and polling.
- **Immutable value types** (records) for parsed headers, claims, verification and polling results.
- **Default signature coverage:** `@method`, `@authority`, `@path`, `signature-key`
  (+ `@query` when present). Body/`content-digest` coverage opt-in.

## Dependencies

| Need | Library |
|---|---|
| JWT/JWK/JWKS, RFC 7638 thumbprints | Nimbus JOSE+JWT (Ed25519 via JDK-native EdDSA) |
| RFC 8941 structured fields | `org.greenbytes.http:structured-fields` |
| RFC 9421 signature base | hand-rolled in `aauth-signing` |
| HTTP client | JDK `java.net.http` |
| JSON | Jackson databind |
| Tests | JUnit + AssertJ; JDK `com.sun.net.httpserver` for test servers |

## Phases

1. **Scaffolding + guardrails** — parent POM, modules, Spotless, JaCoCo 80% gate, enforcer, git.
2. **`aauth-signing`: keys** — Ed25519/EC keypairs, JWK conversion, RFC 7638 thumbprints, JWKS.
3. **`aauth-signing`: RFC 9421 core** — signature base, `Signature-Input`/`Signature` headers,
   algorithms registry. Tested against RFC 9421 test vectors.
4. **`aauth-signing`: Signature-Key + signer/verifier** — four schemes, end-to-end sign/verify.
5. **`aauth` core** — exception hierarchy + error codes, identifier validation, HTTP abstraction.
6. **Tokens** — agent/auth/resource token create/verify/parse with `cnf`/`jkt` binding.
7. **Headers** — AAuth header family: 7 requirement levels (pseudonym → claims), challenges,
   `AAuth-Error`, `Accept-Signature`, capabilities/access/mission.
8. **Metadata** — build + fetch the four `.well-known` documents.
9. **Deferred + agent role** — 202/Location helpers, interaction codes, sync/async poller,
   `AgentRequestSigner`, `ChallengeHandler`, token exchange.
10. **Resource role** — `RequestVerifier`, `ChallengeBuilder`, `ResourceTokenIssuer`.
11. **Interop + docs** — cross-implementation tests against the Python library, README parity,
    final review.

Each phase is TDD-ordered: port the corresponding Python tests first, then implement.

Progress and deviations are tracked in [PROGRESS.md](PROGRESS.md).
