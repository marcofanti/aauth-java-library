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

## 1. Library state as of 2026-10-13

Coordinates: `io.github.marcofanti:aauth` and `io.github.marcofanti:aauth-signing`.
`0.2.2` (Apache-2.0) is the current release. Branch `draft11` (to be released as `0.3.0`)
ports AAuth protocol **draft-11** / Signature-Key **draft-09** from the Python reference
`aauth` 0.5.0 / `aauth-signing` 0.2.0. Java 26+; Jackson is the only third-party runtime
dependency. 353 tests, including two-way Java↔Python -11 interop.

### Breaking changes from 0.2.x that consumers must handle

- **Strict verification, same as the reference.** Only `Ed25519`, `ES256` and `ES384`
  (`EdDSA` and RSA are rejected). Every JWK must carry a matching `alg`. Token `iss`, `aud`
  and `ps` must be lowercase HTTPS origins with no port, on verification as well as
  emission. **Every server identifier in a deployment must be `https://host`**, including
  local development. Plain `http://` and `:port` identifiers are refused.
- **Token model (draft-11):**
  - New person tokens (`aa-person+jwt`, `PersonTokens`), issued by the PS at
    `person_token_endpoint`.
  - Resource and auth tokens drop `agent`/`act`. They carry the person as `(iss, sub)`, plus
    `ps`, `presented_jti` and optional `mission_s256`/`tenant`.
  - Revocation is `{jti, exp}` (`revocation` package).
- **Resource role:**
  - `RequestVerifier.builder(authorities, fetcher)` accepts only the `jwt` Signature-Key
    scheme.
  - Checks per-request `Requirements` (`identity()`, `personToken()`,
    `authToken(scopes...)`, `sessionToken()`).
  - Failures report `Result.errorCode()` (e.g. `insufficient_scope`, `revoked_jwt`).
  - The `AAuth-Mission` header is gone; missions travel as the `mission_s256` claim.
- **Challenges:** `AAuth-Requirement` is parsed as a strict RFC 8941 dictionary. Requirement
  levels are `agent-token`, `person-token` and `auth-token` (with `resource-token`), plus
  the deferred `interaction`/`approval`/`clarification`/`claims`.
- **Metadata:**
  - The PS document needs `issuer`, `jwks_uri`, `auth_token_endpoint` and
    `person_token_endpoint`. `token_endpoint` is gone, and there is no fallback location.
  - Agents fetch only `{ps}/.well-known/aauth-person.json`, and `issuer` must equal the PS
    identifier.
  - Generators validate their output.
- **Egress:**
  - The library's own default HTTP clients admit only public HTTPS URLs and do not follow
    redirects.
  - Against a loopback or private PS (local demo), inject a client:
    `TokenExchange.Agent.builder(...).transport(HttpTransport.jdk(client))`,
    `new CachingJwksFetcher(new DefaultHttpClient(client), ...)`, or the `httpClient`
    argument of `Revocations.send`.
- **Bodies:** error bodies use `detail` (was `error_description`). A `202` claims
  requirement header is just `requirement=claims`, with the claims in the body.

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

### Person-server integration checklist (draft-11)

1. **Metadata**: build `/.well-known/aauth-person.json` with
   `Metadata.personServer(ps, personTokenEndpoint, authTokenEndpoint, jwksUri)`, then add
   optional fields with `.with(...)` (`interaction_endpoint`, `mission_endpoint`,
   `revocation_endpoint`, ...). Publish the JWKS with `alg` members (`Jwk.publicKeyToJwk`).
2. **Person token endpoint** (POST, signed with the agent token, JSON body with `resource`,
   and optionally `mission_s256`, `subagent_token`, `upstream_token`):
   - Verify the HTTP signature (`jwt` scheme) and the agent token
     (`AgentTokens.verify(token, fetcher, expectedAud)`).
   - Issue the token with `PersonTokens.create(PersonTokens.Spec.builder(ps, resource, sub,
     agentCnfJwk, psKey, kid).agentExp(agentExp)...)`. Return `200 {"person_token": ...}`.
3. **Auth token endpoint** (POST, JSON with `resource_token` and `presented_token`, and
   optionally `subagent_token`/`upstream_token`):
   - Verify the resource token with `ResourceTokens.verify(token, fetcher,
     ResourceTokens.VerifyOptions(...))`.
   - Issue the auth token with `AuthTokens.Spec.builder(ps, resource, sub, ps).cnfJwk(...)
     .signingKey(...).dwk(AuthTokens.DWK_PERSON).bounds(agentExp, presentedExp)`. Return
     `200 {"auth_token": ..., "expires_in": ...}` (`DeferredResponses.buildSuccessResponse`).
   - Deferred: answer `202` with `DeferredResponses.buildPendingResponseHeaders/Body`
     (`PendingSpec.builder(location).require("interaction").code(...).url(...)`).
4. **Pending URL** (GET, signed): `202` while pending, `200` + token when approved, `403`
   with `DeferredResponses.buildPollingErrorBody("denied", ...)` (`detail`) on denial. The
   Location must stay on the same origin; the poller enforces this.
5. **Revocation**: `RevocationManager` plus `Revocations.send` for cascading `{jti, exp}`
   revocations to resources and access servers.
6. **Missions**: `Missions.buildApproval`/`parseApproval`/`missionRequest`. Mission
   lifecycle (approval UI, storage, termination) remains the PS's concern; tokens carry
   `mission_s256`.

### Interop status

The Python reference (`aauth` 0.5.0) is on draft-11, and `PythonInteropTest` exercises
tokens and HTTP signatures in both directions. Set `AAUTH_PYTHON_LIB` to a 0.5.x checkout to
run it locally; CI skips it when no checkout is present.
