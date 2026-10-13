# aauth-java-library

[![CI](https://github.com/marcofanti/aauth-java-library/actions/workflows/ci.yml/badge.svg)](https://github.com/marcofanti/aauth-java-library/actions/workflows/ci.yml)

Java implementation of the [AAuth protocol](https://github.com/dickhardt/AAuth) — an
authorization protocol for agent-to-resource access built on HTTP Message Signatures
(RFC 9421) and JWT-based proof-of-possession tokens.

This is a port of [aauth-python-library](https://github.com/christian-posta/aauth-python-library)
with wire-format parity: requests signed by one library verify in the other (covered by
cross-language interop tests).

Implements protocol draft **-11** and Signature-Key draft **-09**, ported module by module from
the Python reference `aauth` 0.5.0 / `aauth-signing` 0.2.0. Verification is as strict as the
reference: only `Ed25519`, `ES256` and `ES384` (RFC 9864; `EdDSA` is rejected), every JWK must
carry its `alg`, and `iss`/`aud`/`ps` must be lowercase HTTPS origins without a port. See
[docs/PROGRESS.md](docs/PROGRESS.md) for the decision log.

## Modules

| Module | Coordinates | Package | Responsibility |
|---|---|---|---|
| `aauth-signing` | `io.github.marcofanti:aauth-signing` | `io.github.marcofanti.aauth.signing` | HTTP Message Signatures (RFC 9421) + `Signature-Key` header (`hwk`, `jkt-jwt`, `jwks_uri`, `jwt` schemes) — standalone, no AAuth dependency |
| `aauth` | `io.github.marcofanti:aauth` | `io.github.marcofanti.aauth` | Full AAuth protocol: tokens, headers, metadata, deferred responses, agent/resource roles |

`aauth-signing` is the low-level signing layer, usable on its own. `aauth` depends on it.
The only third-party runtime dependency is Jackson; all cryptography is JDK-native
(Ed25519 via JEP 339, ECDSA). Requires **Java 26+**.

## Building

```bash
mvn verify            # build, tests, coverage gate, format check
mvn spotless:apply    # format sources (Palantir Java Format)
```

## Quick start

```java
import io.github.marcofanti.aauth.signing.*;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;

// Generate an Ed25519 key pair
var keyPair = KeyPairs.generateEd25519();

// Sign a request (pseudonymous — public key embedded in the Signature-Key header)
Map<String, String> signedHeaders = RequestSigner.sign(
        SignRequest.builder("GET", "https://gateway.uma.lab/api/data")
                .keyPair(keyPair)
                .scheme(new SignatureScheme.Hwk())
                .build());

// Sign with agent identity (JWKS-backed)
Map<String, String> identityHeaders = RequestSigner.sign(
        SignRequest.builder("POST", "https://gateway.uma.lab/api/data")
                .headers(Map.of("Content-Type", "application/json"))
                .body(bodyBytes)
                .keyPair(keyPair)
                .scheme(new SignatureScheme.JwksUri("https://portal.uma.lab", "aauth-agent.json", "key-1"))
                .build());

// Sign with an auth token
Map<String, String> tokenHeaders = RequestSigner.sign(
        SignRequest.builder("GET", "https://gateway.uma.lab/api/data")
                .keyPair(keyPair)
                .scheme(new SignatureScheme.Jwt(authToken))
                .build());
```

The returned map contains `Signature-Input`, `Signature`, `Signature-Key` (and
`Content-Digest`/`Content-Type` when body components are covered) — add them to the outgoing
request. Unlike the Python library, the caller's header map is never mutated.

**What the signature covers by default:** `@method`, `@authority`, `@path`, `signature-key`,
plus `@query` when a query string is present, `authorization` when that header is sent, and
`content-digest` when there is a body (an empty body counts). `Content-Digest` is always
recomputed from the body when signing, and checked against the body when verifying.

> **HTTP client defaults:** every HTTP client the library constructs itself (JWKS/metadata
> fetching, token exchange, revocation) is pinned to **HTTP/1.1**, because the JDK's default
> h2c upgrade breaks h11-based servers. These clients also apply the reference's egress
> policy (`Egress.admitPublicUrl`): HTTPS only, no credentials or fragment, and every resolved
> address must be public. They do not follow redirects. Clients you inject are used as-is, so
> you set their egress policy. That includes local development against loopback servers.

## Signature verification

```java
boolean valid = SignatureVerifier.verify(
        VerifyRequest.builder(request.method(), request.targetUri())
                .headers(request.headers())
                .body(requestBody)
                .signatureHeaders(
                        request.getHeader("Signature-Input"),
                        request.getHeader("Signature"),
                        request.getHeader("Signature-Key"))
                .jwksFetcher((id, dwk, kid) -> myJwksFetcher.fetch(id, kid, dwk)) // jwks_uri/jwt schemes
                .build());
```

## Token creation

```java
import io.github.marcofanti.aauth.tokens.*;

// Person token (person server → agent), bounded by the agent token's exp
String personToken = PersonTokens.create(PersonTokens.Spec.builder(
                "https://ps.uma.lab", "https://gateway.uma.lab", "person-1",
                agentCnfJwk, psPrivateKey, "ps-key-1")
        .agentExp(agentTokenExp)
        .build());

// Resource token (resource → PS/AS): verifies the presented token and derives
// ps, sub, presented_jti, mission_s256 and tenant from it
String resourceToken = ResourceTokens.create(ResourceTokens.Spec.builder(
                "https://gateway.uma.lab", "https://ps.uma.lab", agentThumbprint,
                resourcePrivateKey, "resource-key-1")
        .presentedToken(personToken, jwksFetcher)
        .scope("data.read")
        .build());

// Auth token (PS → agent): iss, aud (resource), sub (person), ps
String authToken = AuthTokens.create(AuthTokens.Spec.builder(
                "https://ps.uma.lab", "https://gateway.uma.lab", "person-1", "https://ps.uma.lab")
        .cnfJwk(agentCnfJwk)
        .signingKey(psPrivateKey, "ps-key-1")
        .dwk(AuthTokens.DWK_PERSON)
        .bounds(agentTokenExp, personTokenExp)
        .scope("data.read")
        .build());

// Parse token claims (no verification)
Map<String, Object> claims = AuthTokens.parseTokenClaims(token);
```

## AAuth challenge headers

```java
import io.github.marcofanti.aauth.headers.AAuthHeaders;

// Parse an AAuth-Requirement header (a strict RFC 8941 dictionary)
var challenge = AAuthHeaders.parseSignatureRequirement(
        "requirement=auth-token; resource-token=\"...\"");

// Build challenges
String authTokenChallenge = AAuthHeaders.buildAuthTokenRequirement(resourceToken);
String interaction = AAuthHeaders.buildInteractionRequirement("https://ps.uma.lab/i", "ABCD1234");
```

## High-level agent and resource APIs

```java
import io.github.marcofanti.aauth.agent.*;
import io.github.marcofanti.aauth.resource.*;

// Agent-side request signer (jwt scheme with the agent, person or auth token)
AgentRequestSigner signer = AgentRequestSigner.builder(keyPair).agentToken(agentToken).build();
Map<String, String> headers = signer.signRequest(
        "GET", "https://gateway.uma.lab/api/data", Map.of(), null);

// Resource-side request verifier (only the jwt Signature-Key scheme is accepted)
RequestVerifier verifier = RequestVerifier.builder(List.of("gateway.uma.lab"), jwksFetcher)
        .resourceId("https://gateway.uma.lab")
        .trustedPersonServers(Set.of("https://ps.uma.lab"))
        .build();
RequestVerifier.Result result = verifier.verifyRequest(
        method, targetUri, requestHeaders, requestBody, RequestVerifier.Requirements.authToken("data.read"));
if (result.valid()) {
    System.out.println("Person: " + result.userSub() + ", Scopes: " + result.scopes());
} else {
    System.out.println(result.errorCode() + ": " + result.error());
}

// Resource-side challenges: agent-token, person-token, or auth-token with a resource token
ChallengeBuilder challenges = new ChallengeBuilder(
        "https://gateway.uma.lab", resourcePrivateKey, "resource-key-1", "https://ps.uma.lab", jwksFetcher);
var challenge = challenges.buildChallenge(
        ChallengeBuilder.Spec.authToken(presentedToken, agentPublicKey, "data.read"));
response.setHeader(challenge.headerName(), challenge.headerValue());
```

## Deferred responses and polling

Any endpoint may answer 202 Accepted with a `Location` header (spec §10). The agent polls
until a terminal response, honoring `Retry-After`, slow-down (429) and interaction /
clarification requirements:

```java
Poller.PollingResult result = Poller.poll(Poller.Request.builder(pendingUrl, mySignedGet)
        .onInteraction((url, code) -> showUser(url, code))
        .build());
```

The agent's person-server calls are one call each. Every token they return is verified
before it is handed back:

```java
TokenExchange.Agent agent = TokenExchange.Agent.builder(keyPair, agentJwt, jwksFetcher)
        .onInteraction((url, code) -> showUser(url, code))
        .build();

// Person token for a resource (person_token_endpoint)
String personToken = TokenExchange.requestPersonToken(
        agent, "https://ps.uma.lab", "https://gateway.uma.lab", null, Map.of());

// Resource token → auth token (auth_token_endpoint), presenting the person token
String authToken = TokenExchange.exchangeResourceToken(agent, TokenExchange.AuthTokenRequest.of(
        resourceToken, personToken, "https://gateway.uma.lab", "https://ps.uma.lab"));
```

Revocation (`revocation.Revocations`, `RevocationManager`) and missions (`missions.Missions`)
mirror the reference's `revocation` and `missions` modules.

## Package structure

```
aauth-signing/                       io.github.marcofanti.aauth.signing
├── RequestSigner / SignRequest      sign_request — builds Signature-Input/Signature/Signature-Key
├── SignatureVerifier / VerifyRequest verify_signature — validates RFC 9421 signatures
├── SignatureScheme / SignatureKeyHeader  hwk/jwks_uri/jwt/jkt-jwt schemes
├── SignatureBase, SignatureInputHeader, SignatureHeader, SigningAlgorithms
├── StructuredFields                 RFC 8941 dictionary parser
├── Jwts                             minimal compact JWT codec (JDK crypto)
└── keys/                            KeyPairs, Jwk (RFC 7638 thumbprints, JWKS)

aauth/                               io.github.marcofanti.aauth
├── ErrorCodes, Identifiers, exceptions
├── http/                            HttpTransport, Egress, AAuthRequest/AAuthResponse, DeferredResponses
├── keys/                            CachingJwksFetcher, JwksCache, JsonHttpClient, DefaultHttpClient
├── tokens/                          AgentTokens, PersonTokens, AuthTokens, ResourceTokens, TokenVerifier, Delegation
├── revocation/                      Revocations, RevocationManager, RevocationStore
├── missions/                        Missions (approval, mission requests, refresh)
├── headers/                         AAuthHeaders, AcceptSignatureHeader, SignatureErrorHeader, MissionBinding
├── metadata/                        Metadata (.well-known build + fetch)
├── agent/                           AgentRequestSigner, ChallengeHandler, TokenExchange, Poller, PersonTokenCache
└── resource/                        RequestVerifier, ChallengeBuilder, ResourceTokenIssuer
```

## Testing

```bash
mvn verify                                        # all unit tests + gates
mvn test -pl aauth -am -Dtest=PythonInteropTest \
    -Dsurefire.failIfNoSpecifiedTests=false       # cross-language interop (needs uv + aauth 0.5.x)
# The Python checkout defaults to ../aauth-python-library; override with AAUTH_PYTHON_LIB=/path.
```

## Sibling implementations

- **TypeScript:** [`aauth-dev/packages-js`](https://github.com/aauth-dev/packages-js) — Dick Hardt's reference implementation
- **Python:** [`christian-posta/aauth-python-library`](https://github.com/christian-posta/aauth-python-library) (`aauth` on PyPI) — the reference this port tracks; end-to-end demo at [`aauth-full-demo`](https://github.com/christian-posta/aauth-full-demo)
- **PHP:** [`clawdreyhepburn/aauth-php`](https://github.com/clawdreyhepburn/aauth-php) — request verification for shared hosting
- **Java:** this repo — `io.github.marcofanti:aauth` / `aauth-signing` on Maven Central

Cross-implementation compatibility is tested live: our interop suite signs in Java and
verifies with the Python library (and vice versa) on every run that has the Python
checkout available.

## Protocol

- Spec: [github.com/dickhardt/AAuth](https://github.com/dickhardt/AAuth)
- Demo: [blog.christianposta.com/aauth-full-demo](https://blog.christianposta.com/aauth-full-demo/)
- Site: [aauth.dev](https://www.aauth.dev)
- Reference implementation: [aauth-python-library](https://github.com/christian-posta/aauth-python-library)

Implementation plan and progress log: [docs/PLAN.md](docs/PLAN.md), [docs/PROGRESS.md](docs/PROGRESS.md).
Publishing to Maven Central: [RELEASING.md](RELEASING.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). This library is a port of
the MIT-licensed [aauth-python-library](https://github.com/christian-posta/aauth-python-library);
the upstream attribution is preserved in NOTICE.
