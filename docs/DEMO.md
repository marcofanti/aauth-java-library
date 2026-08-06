# AAuth Live Demo Plan — and Library State for `aauth-java-person-server`

**Audience:** the `aauth-java-person-server` project (and anyone building the demo). This
document is the contract between the library, the person server, and the demo. Library
repo: <https://github.com/marcofanti/aauth-java-library>. Written 2026-08-06.

---

## 1. Library state as of 2026-08-06

Coordinates: `io.github.marcofanti:aauth` and `io.github.marcofanti:aauth-signing`.
`0.1.1` is on Maven Central; everything below is on `main` and ships as **0.2.0**
(recommend releasing before the demo: `./release.sh 0.2.0`). Java 26+, Jackson is the only
third-party runtime dependency. 213 tests, CI green.

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

## 2. Live demo plan

**Concept:** "An AI agent buys access to your data the right way" — the full three-party
AAuth flow, all-Java, on the lab hostnames, ending with attacks that bounce off.
Target: ~12 minutes live.

### Cast and topology

All `*.uma.lab` names resolve to 127.0.0.1 on the demo machine.

| Host | Role | Built from |
|---|---|---|
| `portal.uma.lab:8445` | **Agent** — CLI runner + serves `/.well-known/aauth-agent.json` + JWKS | library: `AgentRequestSigner`, `TokenExchange`, `Poller`, `AgentTokens` |
| `gateway.uma.lab:8444` | **Resource** — tiny API: `GET /api/balance` (scope `balance.read`) + `/.well-known/aauth-resource.json` + JWKS | library: `RequestVerifier`, `ChallengeBuilder`, `ResourceTokenIssuer`, `Metadata` |
| `ps.uma.lab:8443` | **Person Server** — token endpoint, interaction page, Alice's approval UI, `/.well-known/aauth-person.json` | **`aauth-java-person-server`** |
| `keycloak.uma.lab` | optional: Alice's login at the PS | existing lab service |
| `grafana.uma.lab` | optional: live request-log dashboard | existing lab service |

Screen: tmux with three panes (agent / resource logs / PS logs) + one browser window.

### Script — six beats

| # | Beat | What happens | Library APIs on stage |
|---|---|---|---|
| 1 | **Anonymous agent** (1 min) | Plain `curl` → `401` + `Accept-Signature: sig=(...);sigkey=jkt`. Point: the resource *tells* the agent how to authenticate. | `ChallengeBuilder.Spec.pseudonym()` |
| 2 | **Pseudonymous isn't enough** (1.5 min) | Agent signs `hwk` → `401 AAuth-Requirement: requirement=auth-token; resource-token="…"`. Decode the resource token live: `agent_jkt` binding, `aud` = PS, draft-10 `alg: Ed25519`. | `AgentRequestSigner`, `ChallengeBuilder.Spec.authToken(...)`, `ResourceTokenIssuer` |
| 3 | **Three-party exchange — the money shot** (3 min) | `TokenExchange.exchangeResourceToken` → PS `202` + Location + interaction code → poller waits visibly → browser: Alice sees *which agent wants which scope*, approves → poller pane flips to the issued auth token. Decode: `cnf.jwk` (with `alg`), `act`, `scope`, `account`. | `TokenExchange`, `Poller` (`onInteraction` callback), `DeferredResponses` on the PS side |
| 4 | **Authorized access** (1 min) | Retry with `scheme=jwt` → `200` balance JSON. Resource log shows extracted agent id + scopes. | `AgentRequestSigner` (jwt scheme), `RequestVerifier` |
| 5 | **Attacks that fail** (3 min) | (a) replay a captured request 90 s later → rejected (60 s `created` window); (b) tamper the body, keep headers → `content-digest mismatch`; (c) inject `AAuth-Mission` after signing → `aauth-mission header not covered by signature`; (d) re-run exchange, Alice **denies** → clean `403 denied` through the poller. | `SignatureVerifier`, `RequestVerifier`, `Poller` |
| 6 | **Polyglot close** (1.5 min) | Verify the same signed request with the Python library in one `uv run` line — live cross-implementation interop — then show the Maven Central artifact and the sibling-implementations list. | interop pattern from `PythonInteropTest` |

### What the demo needs from `aauth-java-person-server`

The PS is the only non-trivial dependency. Checklist:

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
7. **For beat 5c/5d**: nothing extra — denial is just the `403 denied` path; the mission
   and digest rejections happen at the resource.

### Prep checklist

- [ ] Release the library as **0.2.0** (`./release.sh 0.2.0`) so the demo pins a public
      Central artifact, not a snapshot.
- [ ] Scaffold `aauth-java-demo` (separate repo; mirrors the role of
      `christian-posta/aauth-full-demo`): `DemoAgent`, `DemoResource`, tmux launcher,
      `preflight.sh`, a `jwtdecode` helper.
- [ ] `preflight.sh`: build, start all three services, curl the three `.well-known`
      docs, run beats 1–4 headlessly. Run it 10 minutes before going live.
- [ ] Fallbacks: asciinema recording of each beat; one pre-issued auth token in case the
      PS misbehaves mid-demo.
- [ ] Rehearse the deny path **last** — it changes Alice's consent state.

### Known transition caveats (honest-demo notes)

- The Python library (beat 6) is still pre-draft-10: it verifies our **HTTP signatures**
  (hwk ignores the extra `alg` param) but rejects our **tokens** (`Ed25519` vs `EdDSA`).
  Beat 6 therefore demos HTTP-signature interop, not token interop — say so out loud.
- `x509` scheme and the four new sigkey-08 schemes (`jwks`, `self-jwt`, `cached`) are
  not implemented (phase B; tracked in PROGRESS.md).
