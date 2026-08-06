# aauth-java-library

[![CI](https://github.com/marcofanti/aauth-java-library/actions/workflows/ci.yml/badge.svg)](https://github.com/marcofanti/aauth-java-library/actions/workflows/ci.yml)

Java implementation of the [AAuth protocol](https://github.com/dickhardt/AAuth) — an
authorization protocol for agent-to-resource access built on HTTP Message Signatures
(RFC 9421) and JWT-based proof-of-possession tokens.

This is a port of [aauth-python-library](https://github.com/christian-posta/aauth-python-library)
with wire-format parity: requests signed by one library verify in the other (covered by
cross-language interop tests).

## Modules

| Module | Coordinates | Package | Responsibility |
|---|---|---|---|
| `aauth-signing` | `io.github.marcofanti:aauth-signing` | `io.github.marcofanti.aauth.signing` | HTTP Message Signatures (RFC 9421) + `Signature-Key` header (`hwk`, `jkt-jwt`, `jwks_uri`, `jwt` schemes) — standalone, no AAuth dependency |
| `aauth` | `io.github.marcofanti:aauth` | `io.github.marcofanti.aauth` | Full AAuth protocol: tokens, headers, metadata, deferred responses, agent/resource roles |

`aauth-signing` is the low-level signing layer, usable on its own. `aauth` depends on it.
The only third-party runtime dependency is Jackson; all cryptography is JDK-native
(Ed25519 via JEP 339, ECDSA, RSA). Requires **Java 26+**.

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

**What the signature covers by default:** `@method`, `@authority`, `@path`, `signature-key`
(plus `@query` when a query string is present). Body signing is opt-in via
`additionalComponents(List.of("content-digest"))`.

> **HTTP client defaults:** every HTTP client the library constructs itself (JWKS/metadata
> fetching, token exchange) is pinned to **HTTP/1.1** — the JDK's default h2c upgrade breaks
> h11-based servers (uvicorn/FastAPI person servers reject requests or drop bodies).
> Clients you inject yourself are used as-is.

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

// Resource token (resource → auth server)
String resourceToken = ResourceTokens.create(new ResourceTokens.Spec(
        "https://gateway.uma.lab", "https://alice-as.uma.lab",
        "aauth:agent@portal.uma.lab", agentThumbprint, "data.read data.write",
        resourcePrivateKey, "resource-key-1", null, null));

// Auth token (auth server → agent)
String authToken = AuthTokens.create(AuthTokens.Spec.builder(
                "https://alice-as.uma.lab", "https://gateway.uma.lab", "aauth:agent@portal.uma.lab")
        .cnfJwk(agentJwk)
        .signingKey(authPrivateKey, "auth-key-1")
        .act(Map.of("sub", "aauth:agent@portal.uma.lab"))
        .scope("data.read")
        .build());

// Parse token claims (no verification)
Map<String, Object> claims = AuthTokens.parseTokenClaims(token);
```

## AAuth challenge headers

```java
import io.github.marcofanti.aauth.headers.AAuthHeaders;

// Parse an AAuth challenge from a resource's 401 response
var challenge = AAuthHeaders.parseAAuthHeader(
        "requirement=auth-token; resource-token=\"...\"");

// Build challenges
String authTokenChallenge = AAuthHeaders.buildAuthTokenRequirement(resourceToken);
String interaction = AAuthHeaders.buildInteractionRequirement("https://ps.uma.lab/i", "ABCD1234");
```

## High-level agent and resource APIs

```java
import io.github.marcofanti.aauth.agent.*;
import io.github.marcofanti.aauth.resource.*;

// Agent-side request signer
AgentRequestSigner signer = AgentRequestSigner.builder(keyPair)
        .agentId("https://portal.uma.lab")
        .agentToken(agentToken)
        .build();
Map<String, String> headers = signer.signRequest(
        "GET", "https://gateway.uma.lab/api/data", Map.of(), null, "jwt");

// Resource-side request verifier
RequestVerifier verifier = new RequestVerifier(
        List.of("gateway.uma.lab:443"), myJwksFetcher);
RequestVerifier.Result result = verifier.verifyRequest(
        method, targetUri, requestHeaders, requestBody,
        /* requireIdentity */ true, /* requireAuthToken */ true);
if (result.valid()) {
    System.out.println("Agent: " + result.agentId() + ", Scopes: " + result.scopes());
}
// Mission-aware requests: verifyRequest rejects an AAuth-Mission header that isn't covered
// by the signature, and surfaces the parsed header via result.mission(). Use MissionBinding
// to check it against a mission document (s256) or a token's mission claim.
// When a request carries both a Content-Digest header and a body, verifyRequest recomputes
// the RFC 9530 digest from the body and rejects mismatches ("content-digest mismatch") —
// stricter than the Python reference, which only verifies the header value. sha-256 and
// sha-512 are supported; headers with only unrecognized algorithms are rejected.

// Resource-side challenge building (401 responses)
ChallengeBuilder challenges = new ChallengeBuilder(
        "https://gateway.uma.lab", resourcePrivateKey, "resource-key-1", "https://alice-as.uma.lab");
var challenge = challenges.buildChallenge(
        ChallengeBuilder.Spec.authToken(agentId, agentPublicKey, "data.read"));
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

The three-party exchange (resource token → auth token via the person server) is one call:

```java
String authToken = TokenExchange.exchangeResourceToken(
        TokenExchange.Exchange.builder(resourceToken, keyPair, agentJwt).build());
```

## Package structure

```
aauth-signing/                       io.github.marcofanti.aauth.signing
├── RequestSigner / SignRequest      sign_request — builds Signature-Input/Signature/Signature-Key
├── SignatureVerifier / VerifyRequest verify_signature — validates RFC 9421 signatures
├── SignatureScheme / SignatureKeyHeader  hwk/jwks_uri/jwt/jkt-jwt schemes
├── SignatureBase, SignatureInputHeader, SignatureHeader, SigningAlgorithms
├── Jwts                             minimal compact JWT codec (JDK crypto)
└── keys/                            KeyPairs, Jwk (RFC 7638 thumbprints, JWKS)

aauth/                               io.github.marcofanti.aauth
├── ErrorCodes, Identifiers, exceptions
├── http/                            AAuthRequest/AAuthResponse, DeferredResponses (202 + polling)
├── keys/                            CachingJwksFetcher, JwksCache, JsonHttpClient
├── tokens/                          AgentTokens, AuthTokens, ResourceTokens
├── headers/                         AAuthHeaders, AcceptSignatureHeader, SignatureErrorHeader
├── metadata/                        Metadata (.well-known build + fetch)
├── agent/                           AgentRequestSigner, ChallengeHandler, TokenExchange, Poller
└── resource/                        RequestVerifier, ChallengeBuilder, ResourceTokenIssuer
```

## Testing

```bash
mvn verify                                        # all unit tests + gates
mvn test -pl aauth -am -Dtest=PythonInteropTest \
    -Dsurefire.failIfNoSpecifiedTests=false       # cross-language interop (needs uv + ../aauth-python-library)
```

## Protocol

- Spec: [github.com/dickhardt/AAuth](https://github.com/dickhardt/AAuth)
- Demo: [blog.christianposta.com/aauth-full-demo](https://blog.christianposta.com/aauth-full-demo/)
- Site: [aauth.dev](https://www.aauth.dev)
- Reference implementation: [aauth-python-library](https://github.com/christian-posta/aauth-python-library)

Implementation plan and progress log: [docs/PLAN.md](docs/PLAN.md), [docs/PROGRESS.md](docs/PROGRESS.md).
Publishing to Maven Central: [RELEASING.md](RELEASING.md).

## License

MIT
