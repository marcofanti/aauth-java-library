# AAuth draft-11 Migration Plan

Target: `draft-hardt-oauth-aauth-protocol-11` (2026-09-25) + `draft-hardt-httpbis-signature-key-09`
(2026-09-13). The library currently implements **-10 / sigkey-08**.

Authoritative upstream migration guide: <https://github.com/dickhardt/AAuth/tree/main/upgrade-10-to-11>
(role-by-role, with tracked checklist IDs). This plan maps the **agent** (`AG-*`/`AP-*`) and
**resource** (`RS-*`) checklist items — the only two roles this library implements — to concrete
library changes. PS and AS roles are out of scope (person-server territory).

## Upstream state (gate) — SUPERSEDED 2026-10-12

> **Update 2026-10-12:** the Python reference shipped a full draft-11 implementation upstream
> (`christian-posta/aauth-python-library` `1273992`/`fa3547a`, aauth **0.5.0**, aauth-signing
> **0.2.0**). Phases A–C below were written spec-first while Python was on -10; from Phase D on the
> work is a **port of the reference -11**, per the "Reference port (D1–D7)" section at the end. The
> decisions there override the tolerance strategy described next.

*(Original, now historical:)* The Python reference library (0.3.5) was still on draft-10, so the
strategy was compliant emission with tolerant verification and no -11 interop.

## Headline changes (what -11 does)

1. **Person token (`aa-person+jwt`), new.** PS issues it per resource; the agent presents it *instead
   of its agent token* at the resource authorization endpoint. The resource verifies it before
   issuing a resource token. New `requirement=person-token` 401 challenge.
2. **`presented_token` / `presented_jti`.** The agent sends the token it presented alongside the
   resource token; the resource token carries `presented_jti`; PS/AS cross-check the pair.
3. **`agent` and `act` removed** from resource tokens *and* auth tokens. The person is identified by
   `(iss, sub)`. Resource token gains `ps`, `sub`, `presented_jti`.
4. **Missions: `mission_s256`** replaces the `AAuth-Mission` header and the `{approver, s256}`
   object; the mission now rides inside the person token.
5. **Renames:** `token_endpoint` → `auth_token_endpoint`; `access_mode` value `aauth-access-token`
   → `session-token`. Metadata gains `person_token_endpoint`.
6. **Revocation reworked:** request body `{jti, exp}` signed under `jwks_uri`; cascade; no 404; new
   `revoked_jwt` / `clock_skew` signature errors.
7. **Ed25519 MUST for every party** (unblocks the staged strict-alg flip); agent `local` part may
   contain `A-Z` (exact, case-sensitive compare).
8. **Third-Party Login (`login_endpoint`) removed entirely.**
9. **JWT checks tightened:** `exp` no skew tolerance; `exp − iat ≤ 1h` for person/auth tokens; `iat`
   no longer a validity check.
10. **Call chaining:** a resource calling downstream is its own agent provider, routes through the
    upstream token's PS.

## Phased implementation

Each phase lands on `draft11` behind `mvn verify` (tests + JaCoCo 80% + Spotless). Nothing merges to
`main` until the person-server and demo are ready to move together (cross-repo sync lesson).

### Phase A — Foundation: PersonTokens + token-claim changes + renames
*(this increment)*

- [ ] **New `tokens/PersonTokens.java`** — `aa-person+jwt`, `dwk = aauth-person.json`. `create(Spec)`
  with claims `iss, sub, aud, dwk, jti, iat, exp, cnf.jwk`, optional `mission_s256`, `tenant`,
  `account`, `scope`, `capabilities`. `verify(...)` per RS-10/§7.1.4: `typ`, `dwk`, `aud` = resource,
  `cnf.jwk` present & structurally complete, `exp` in future (no skew), `exp − iat ≤ 3600`, identity
  `(iss, sub)`. (AG-10..12, RS-10..13)
- [ ] **`ResourceTokens.Spec`** — drop `agent`, drop `mission` object; add REQUIRED `ps`, `sub`,
  `presentedJti`; add OPTIONAL `missionS256`, `tenant`, `loginHint`. Keep `iss, aud, dwk, jti, iat,
  exp, agentJkt, scope, account`. Emit accordingly. `verify` drops the `agent` check, requires the
  new claims. (RS-30..34, AG-22)
- [ ] **`AuthTokens.Spec`** — drop `agent`, drop `act`; `sub` becomes REQUIRED; mission becomes
  `missionS256`. `verifyToken` drops `agent`/`act`/"sub-or-scope" checks, requires `sub`, identifies
  by `(iss, sub)`, adds `ps`. (RS-40..42, AG-23)
- [ ] **Metadata** — add `person_token_endpoint`; rename auth-server `token_endpoint` →
  `auth_token_endpoint` (keep reading the old name as a tolerant fallback); drop `login_endpoint`
  from the documented optional fields; add `session-token` to `access_mode` values. (AG-01/02,
  RS-01/02, AP-04)
- [ ] **`TokenSupport.verifySignatureViaIssuer`** — unchanged interface; still Ed25519 + legacy
  EdDSA tolerant (strict flip is Phase D).

### Phase B — Resource role: person-token challenge + verifier rewrite — DONE

- [x] **`ChallengeBuilder`** — added a `personToken()` spec emitting `AAuth-Requirement:
  requirement=person-token` (no params). (RS-11, RS-20)
- [x] **`RequestVerifier`** — `Result` dropped `act`; mission comes from the presented token's
  `mission_s256`, not the header; stopped reading `AAuth-Mission` and the `aauth-mission` covered
  component; surfaces the person `sub`. (RS-10, RS-30, RS-33, RS-40)
- [x] **`ResourceTokenIssuer`** — issues from a `Grant` whose `aud` is the person token's `iss`
  (three-party) or the AS (four-party), not the agent token's `ps`; copies `sub`, `presented_jti`,
  `mission_s256`, `tenant`. (RS-31, RS-32)
- [x] **Retired `MissionBinding` matching + `AAuth-Mission`** (replace, don't deprecate); kept the
  still-valid `MissionBinding.s256` hash + a `matches` helper. (RS-33, AG-30)

### Phase C — Agent role: person-token flow + presented_token + new responses — DONE (core)

- [x] `TokenExchange.requestPersonToken` — discovers `person_token_endpoint`, POSTs `resource`
  (+ `mission_s256`, `capabilities`) under the agent token, handles 200 and 202 + polling.
  Presenting it is `AgentRequestSigner.withToken(personToken)` with the `jwt` scheme. (AG-10, AG-12,
  AG-20)
- [x] `PersonTokenCache` — one per resource and per mission; evicts inside the five-minute margin;
  `clear()` on key rotation; `needsRefresh(jwt, now)` applies the margin to any token. (AG-11,
  AG-70)
- [x] `presented_token` sent to `auth_token_endpoint` with the resource token when supplied
  (omitted for pre-draft-11 servers). (AG-21)
- [x] `ChallengeHandler` answers `requirement=person-token` with `jwt` (person or auth token) and
  errors when the agent holds neither, instead of falling back to `hwk`. (AG-12)
- [x] `ErrorCodes`: `revoked_jwt`, `clock_skew`, `expired_presented_token`,
  `revoked_presented_token`, `revoked_resource_token`, `as_unreachable`, `user_unreachable`,
  `invalid_subagent_token`, `invalid_account`, `mission_not_found`, polling `revoked`; removed
  `invalid_agent_token` / `expired_agent_token`. (AG-60..62, AG-34)
- [x] PS requests with a body cover `content-type` + `content-digest`. (AG-50)
- [x] `AAuth-Mission` gone (Phase B); `mission_s256` named on the person-token request. (AG-30)
- [ ] **Remaining** — `requirement=auth-token` delivered as 202 at the resource (AG-26: building
  blocks exist — `extractResourceToken` reads the headers, `Poller` polls the pending URL — but no
  end-to-end helper); `presented_token` on a clarification `updated_request` (AG-25); mission
  approval-response parsing and `{mission_endpoint}/{mission_s256}` completion/update (AG-32..36);
  sub-agent person-token flow (AG-40); top-down refresh orchestration (AG-70 policy).

## Reference port (D1–D7) — replaces the spec-first Phase D/E

Source of truth: Python aauth **0.5.0** / aauth-signing **0.2.0** (`fa3547a`), checked out at
`../aauth-python-library` (`main`). Port module by module; where Phase A–C diverged from the
reference, the reference wins. Acceptance gate: `mvn verify` green **and** Java↔Python -11 interop
tests (rewritten against the 0.5.0 API).

**Decisions (user, 2026-10-12):**
- **Fully strict, like the reference.** JWT and JWK `alg` ∈ {`Ed25519`, `ES256`, `ES384`};
  `EdDSA` and a missing JWK `alg` are rejected; RSA dropped from JWK→key. Every token needs `iat` and
  `exp` (`exp > now`, no skew; `exp > iat`). `iss`/`aud`/`ps` must be lowercase HTTPS origins without
  port/path (`validateServerUrl`, the http-tolerant variant, is removed). Consequence: the
  person-server and demo must serve their identifiers over HTTPS without ports to interoperate.
- The `strict-alg-draft10` branch is superseded by D1 (delete it once D1 lands).

### D1 — aauth-signing (signing/verifier.py, signer.py, signature_*.py, keys/jwk.py, tokens/common.py) — DONE
- [x] `Jwk.validateAlgorithm(jwk, expectedAlg)` — strict alg set; `unsupported_algorithm` vs
  `invalid_key` codes; drop RSA from `toPublicKey`/`publicKeyToJwk` (thumbprint keeps RSA).
- [x] `Jwts` — strict verify: `kid` required, exactly one JWKS key with that `kid`, key `alg` ==
  header `alg`, `iat`/`exp` required, `exp > now`, `exp > iat`; `Ed25519` only (no `EdDSA`).
- [x] `SignatureInputHeader` — strict SF parse: one label, inner list of strings, no duplicates,
  integer `created`/`expires`.
- [x] `SignatureBase` — `authorization` component; arbitrary header components; empty body is a body.
- [x] `RequestSigner` — auto-cover `authorization`; always recompute `Content-Digest`; default
  `Content-Type: application/octet-stream`; dedupe components; `hwk` key carries `alg`.
- [x] `SignatureVerifier` — required components (+`authorization`), `created` window with
  `clock_skew`, `expires`, content-digest verified against the body when covered, `keyid` must match
  the Signature-Key, strict `jwt`/`jkt-jwt`/`hwk`/`jwks_uri` key validation, error codes surfaced.

### D2 — tokens (tokens/common.py, agent_token.py, person_token.py, auth_token.py, resource_token.py, delegation.py; identifiers.py) — DONE
- [x] Generic `verifyToken` (typ→dwk table, server identifiers, required claims, 1-hour cap for
  person/auth, PS-issued auth `ps == iss`, `mission_s256` format, `scope` type, `cnf.jwk` thumbprint,
  revocation checker → `revoked_jwt`, wire error codes).
- [x] Agent tokens: strict `iss`/`sub` (agent identifier)/`ps`/`parent_agent`; sub-agent issuance.
- [x] Person tokens: `exp` bounded by agent/mission/upstream expirations; drop `account`/`scope`/
  `capabilities` (not in the reference).
- [x] Auth tokens: bounded by agent/presented/upstream/mission; `dwk` ∈ {person, access} rules.
- [x] Resource tokens: issuance verifies the presented token and derives `ps`/`sub`/`presented_jti`/
  `mission_s256`/`tenant`; verification re-checks the binding; 300 s default lifetime.
- [x] Delegation: `verifySubagentToken`, `verifyUpstreamToken`.
- [x] `Identifiers`: uppercase `local`, strict domain regex, credentials/ASCII checks; remove
  `validateServerUrl`.

### D3 — revocation.py, missions.py — DONE
- [x] Revocation body/sign/send, `RevocationStore`, `RevocationManager` (cascade, `handle_request`).
- [x] Missions: approval build/parse, `missionRequest`, `tokenNeedsRefresh`.

### D4 — resource role (resource/verifier.py, challenge_builder.py, token_issuer.py) — DONE
- [x] `RequestVerifier`: jwt scheme only (`unsupported_scheme`), trusted AS/PS issuers, token verified with the
  resource as audience, revocation, required scopes (`insufficient_scope`), bound session tokens.
- [x] `ChallengeBuilder` / `ResourceTokenIssuer` (landed with D2).
### D5 — agent role (agent/token_exchange.py, poller.py, challenge_handler.py, signer.py)
### D6 — headers/aauth_header.py, metadata/*, keys/jwks.py, http/deferred.py
### D7 — interop + docs
- [x] Rewrite `PythonInteropTest` for the 0.5.0 API; `AAUTH_PYTHON_LIB` env override (9 two-way tests, done with D2).
- [ ] PROGRESS decision log; README; DEMO integration contract (HTTPS identifiers).

## Cross-repo sequencing

1. Library `draft11` branch — port the reference -11 (D1–D7). No release yet.
2. Person-server + demo move to -11 (and HTTPS identifiers) against a library SNAPSHOT.
3. Release the library once the three repos interoperate on -11.

## Docs to update on completion

- `docs/PROGRESS.md` — a draft-11 section mirroring the draft-10 one, with the decision log entry.
- `CLAUDE.md` — bump the "mirrors aauth-python-library" note if the Java lib leads on -11.
- `README.md` / `docs/DEMO.md` — the integration contract version strings.
