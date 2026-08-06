# Library State & Integration Contract for AAuth Consumers

**Audience:** the `aauth-java-person-server` and `aauth-full-java-demo` projects (and any
consumer of this library). This document states what the library currently provides and how
to build against it — it is the integration contract, not a demo plan. Library repo:
<https://github.com/marcofanti/aauth-java-library>.

The live demo itself lives in **[`aauth-full-java-demo`](https://github.com/marcofanti/aauth-full-java-demo)**
(browser UI → backend → supply-chain agent → market-analysis agent over A2A, 8 run modes
including consent, edge verification and missions). Its run-of-show, modes and flows are
documented there — `docs/PLAN.md`, `docs/MODES.md`, `docs/CONSENT_FLOW.md`,
`docs/MISSIONS.md`. Do not duplicate that plan here; this file only records the library-side
contract those projects depend on.

---

## 1. Library state as of 2026-08-06

Coordinates: `io.github.marcofanti:aauth` and `io.github.marcofanti:aauth-signing`.
`0.2.1` (Apache-2.0) is the current release; `main` is `0.3.0-SNAPSHOT`. Java 26+, Jackson is
the only third-party runtime dependency. 213 tests, CI green.

### Implemented today (2026-08-06)

**AAuth protocol draft -10 / Signature-Keys draft -08 compliance** (PR #10) — strategy:
*compliant emission, tolerant verification* (the Python reference is still pre-10):

- **Fully-specified `alg` (RFC 9864)**: every JWK the library emits carries `alg`
  (`Ed25519` for OKP, `ES256`/`ES384` for EC) — including `cnf.jwk` in tokens and the
  inline `hwk` Signature-Key parameters. `Jwk.requireConsistentAlg` runs inside every
  `Jwk.toPublicKey`: a JWK with `alg` present but polymorphic (`EdDSA`), symmetric
  (`HS*`), `none`, unknown, or disagreeing with `kty`/`crv` is rejected. An **absent**
  `alg` is still tolerated (legacy peers) — this flips to strict once the ecosystem is
  on -10.
- **Token headers sign as `alg: Ed25519`** (was `EdDSA`). Verification accepts both
  `Ed25519` and legacy `EdDSA` during the transition.
- **New error codes**: `ErrorCodes.ERROR_UNSUPPORTED_SCHEME` (`unsupported_scheme`),
  `ErrorCodes.ERROR_CACHE_MISS` (`cache_miss`), alongside the existing
  `unsupported_algorithm`.
- **New response headers**: `AAuthHeaders.HEADER_ACCEPT_SIGNATURE_SCHEME` /
  `HEADER_ACCEPT_SIGNATURE_ALG` with `buildAcceptListHeader` / `parseAcceptListHeader`
  (comma-separated token lists, e.g. `Ed25519, ES256`).
- **`account` claim** (draft-10 §12.3, multi-account resources):
  `ResourceTokens.Spec` gained a 10th component `account`;
  `AuthTokens.Spec.builder(...).account(...)`. The resource echoes the authorization
  request's `account` parameter into the resource token; **the PS copies it into the
  auth token**.
- **Agent token verification steps (draft-10 §5.2.4)**: `AgentTokens.verify` now
  validates `ps` (must be a valid HTTPS server identifier) and the new `parent_agent`
  claim (must be a valid `aauth:local@domain` agent identifier; marks a sub-agent token —
  **the PS enforces the single-level sub-agent rule**). Both claims are creatable via
  `AgentTokens.Spec.builder(...).ps(...)/.parentAgent(...)`.
- Interop: Python→Java tests unchanged and green; the Java→Python token test asserts
  structural parsing and auto-heals to full verification when the Python library reaches
  -10.

**Mission binding helpers + coverage enforcement** (PR #9, also today):

- `MissionBinding` (package `io.github.marcofanti.aauth.headers`):
  - `s256(byte[] missionDocument)` — unpadded base64url SHA-256, byte-identical to the
    Python PS reference (`ps/impl/mission_utils.py::s256_hash_bytes`).
  - `matchesDocument(AAuthHeaders.Mission, byte[])` — header ↔ mission JSON hash check.
  - `matchesClaim(AAuthHeaders.Mission, Map missionClaim)` — header ↔ token `mission`
    claim (`approver` and `s256` must both match).
- `RequestVerifier.Result` now carries `result.mission()` — the parsed `AAuth-Mission`
  header, guaranteed signature-covered: a request bearing `AAuth-Mission` whose
  Signature-Input does **not** list `aauth-mission` is rejected with
  `aauth-mission header not covered by signature`.
- Division of responsibility: mission *lifecycle* (creation, approval, storage, canonical
  mission-JSON construction, termination, `mission_terminated`) is **person-server
  territory**; the library provides the wire primitives and binding checks above.

**Docs** (PR #11): README "Sibling implementations" section (TypeScript reference
`aauth-dev/packages-js`, Python `christian-posta/aauth-python-library`, PHP
`clawdreyhepburn/aauth-php`, this library).

### Recent behavior the PS must know about (2026-08-02)

- **HTTP/1.1 pinned** in every library-constructed `HttpClient` (JWKS/metadata fetch,
  `TokenExchange`) — the JDK's h2c upgrade breaks h11/uvicorn servers. Caller-injected
  clients are untouched. A Java PS on the JDK HTTP server is unaffected either way.
- **RFC 9530 body-digest enforcement**: `RequestVerifier` recomputes `Content-Digest`
  (sha-256 and sha-512, parsed as a dictionary) from the body and rejects mismatches
  (`content-digest mismatch`) and unknown-only algorithms
  (`unsupported content-digest algorithm`). Stricter than the Python reference.
- Scope hardening: blank `scope` claims don't satisfy `requireAuthToken`; scope splitting
  collapses whitespace.
- Error Prone + NullAway are enforced at build time; `aauth-signing` is fully
  `@NullMarked` (JSpecify).

---

## 2. The demo

The live demo is **[`aauth-full-java-demo`](https://github.com/marcofanti/aauth-full-java-demo)** —
a multi-agent A2A system (browser UI → backend → supply-chain agent → market-analysis
agent) where every hop is signed via this library, with 8 run modes (`hwk`, `jwt`,
`auth-token`, `consent`, the `edge*` variants, `missions`). Its cast, topology, run modes and
flows are documented in that repo (`docs/PLAN.md`, `docs/MODES.md`, `docs/CONSENT_FLOW.md`,
`docs/MISSIONS.md`); this file does not restate them.

This section records only what the demo and the **`aauth-java-person-server`** consume from
the library.

### Person-server integration checklist

The PS is the non-trivial consumer. Endpoint by endpoint, with the library APIs to use:

1. **Metadata**: serve `/.well-known/aauth-person.json` with `issuer`, `token_endpoint`,
   `jwks_uri` (+ `interaction_endpoint`). The library's `Metadata.personServer(...)` and
   `Metadata.fetchPersonServer(...)` define the shape; the agent falls back to
   `{aud}/token` if metadata is unreachable.
2. **Token endpoint** (POST, JSON `{"resource_token": ...}`):
   - Verify the HTTP signature (`scheme=jwt` carrying the agent token) — use
     `SignatureVerifier`/`RequestVerifier` with a `JwksFetcher`.
   - Verify the resource token with `ResourceTokens.verify(token, fetcher, psId,
     agentId, agentJkt)`.
   - Immediate grant → `200 {"auth_token": ..., "expires_in": ...}` via
     `DeferredResponses.buildSuccessResponse`.
   - Deferred → `202` with `Location` + `Retry-After` + interaction requirement via
     `DeferredResponses.buildPendingResponseHeaders/Body` (`PendingSpec.builder(location)
     .require("interaction").code(...).url(...)`); codes from
     `DeferredResponses.generateInteractionCode()`.
3. **Pending URL** (GET, signed): `202` while pending / `200` + auth token when approved /
   `403` + `{"error": "denied"}` on denial (`DeferredResponses.buildPollingErrorBody`).
   Honor `Retry-After`; the library poller handles 429/503 slow-down automatically.
4. **Interaction page**: human-visible approval showing agent identity, requested scope,
   and the code (the poller appends `?code=` to the URL from the `AAuth-Requirement`
   header).
5. **Auth token issuance**: `AuthTokens.Spec.builder(psId, resourceId, agentId)
   .cnfJwk(agentCnfJwk).signingKey(psKey, kid).act(Map.of("sub", agentId))
   .scope(...).account(...).dwk("aauth-person.json").build()` — the library already
   emits draft-10 (`alg: Ed25519`, `alg` inside `cnf.jwk`).
6. **Draft-10 posture**: publish PS JWKS with `alg` members (automatic if built with
   `Jwk.publicKeyToJwk`); reject unsupported algs with `Signature-Error:
   error=unsupported_algorithm` + `Accept-Signature-Alg: Ed25519` (use
   `AAuthHeaders.buildAcceptListHeader(List.of("Ed25519"))`).
7. **Mission binding**: verify an inbound `AAuth-Mission` against a token's `mission` claim
   with `MissionBinding.matchesClaim(...)` / `matchesDocument(...)`; `RequestVerifier`
   already enforces that the header is signature-covered. Mission *lifecycle* (approval,
   storage, canonical mission-JSON, termination) is the PS's own concern.

### Known transition caveat

The Python reference library is still pre-draft-10: it verifies our **HTTP signatures**
(the `hwk` parser ignores the extra `alg` param) but rejects our **tokens** (`Ed25519` vs
`EdDSA`). Any cross-implementation step against Python demonstrates HTTP-signature interop,
not token interop, until upstream updates. `x509` and the new sigkey-08 schemes (`jwks`,
`self-jwt`, `cached`) are not implemented (phase B; tracked in PROGRESS.md).
