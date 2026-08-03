package io.github.marcofanti.aauth.resource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.ChallengeException;
import io.github.marcofanti.aauth.agent.AgentRequestSigner;
import io.github.marcofanti.aauth.headers.AAuthHeaders;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import io.github.marcofanti.aauth.tokens.AuthTokens;
import io.github.marcofanti.aauth.tokens.ResourceTokens;
import java.security.KeyPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Resource-role tests, including the full challenge → sign → verify protocol loop. */
class ResourceRoleTest {

    private static final String RESOURCE_ID = "https://gateway.uma.lab";
    private static final String AUTH_SERVER = "https://alice-as.uma.lab";
    private static final String AGENT_ID = "aauth:agent@portal.uma.lab";
    private static final String TARGET = "https://gateway.uma.lab/api/data";

    private final KeyPair resourceKeys = KeyPairs.generateEd25519();
    private final KeyPair agentKeys = KeyPairs.generateEd25519();
    private final KeyPair authServerKeys = KeyPairs.generateEd25519();

    private final RequestVerifier verifier = new RequestVerifier(List.of("gateway.uma.lab"), (id, dwk, kid) -> {
        if ("https://portal.uma.lab".equals(id)) {
            return Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(agentKeys.getPublic(), "key-1")));
        }
        if (AUTH_SERVER.equals(id)) {
            return Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(authServerKeys.getPublic(), "as-key-1")));
        }
        return null;
    });

    private Map<String, String> withSignatureHeaders(Map<String, String> signed) {
        return new LinkedHashMap<>(signed);
    }

    @Test
    void pseudonymousRequestVerifies() {
        AgentRequestSigner signer = AgentRequestSigner.builder(agentKeys).build();
        Map<String, String> headers = withSignatureHeaders(signer.signRequest("GET", TARGET, Map.of(), null, "hwk"));

        RequestVerifier.Result result = verifier.verifyRequest("GET", TARGET, headers, null, false, false);

        assertThat(result.valid()).isTrue();
        assertThat(result.agentId()).isNull();
    }

    @Test
    void identityRequestCarriesAgentIdFromJwksUriScheme() {
        AgentRequestSigner signer = AgentRequestSigner.builder(agentKeys)
                .agentId("https://portal.uma.lab")
                .build();
        Map<String, String> headers =
                withSignatureHeaders(signer.signRequest("GET", TARGET, Map.of(), null, "jwks_uri"));

        RequestVerifier.Result result = verifier.verifyRequest("GET", TARGET, headers, null, true, false);

        assertThat(result.valid()).isTrue();
        assertThat(result.agentId()).isEqualTo("https://portal.uma.lab");
    }

    @Test
    void fullAuthTokenFlowFromChallengeToVerifiedScopes() {
        // 1. Resource challenges the agent with an embedded resource token.
        ChallengeBuilder challengeBuilder =
                new ChallengeBuilder(RESOURCE_ID, resourceKeys.getPrivate(), "r-key-1", AUTH_SERVER);
        ChallengeBuilder.Challenge challenge = challengeBuilder.buildChallenge(
                ChallengeBuilder.Spec.authToken(AGENT_ID, agentKeys.getPublic(), "data.read"));

        assertThat(challenge.headerName()).isEqualTo(AAuthHeaders.HEADER_AAUTH_REQUIREMENT);
        String resourceToken =
                AAuthHeaders.parseAAuthHeader(challenge.headerValue()).resourceToken();
        assertThat(resourceToken).isNotNull();

        // 2. The auth server verifies the resource token (agent key binding included).
        Map<String, Object> agentJwk = Jwk.publicKeyToJwk(agentKeys.getPublic(), null);
        Map<String, Object> resourceClaims = ResourceTokens.verify(
                resourceToken,
                iss -> Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(resourceKeys.getPublic(), "r-key-1"))),
                AUTH_SERVER,
                AGENT_ID,
                Jwk.thumbprint(agentJwk));
        assertThat(resourceClaims).containsEntry("scope", "data.read");

        // 3. The auth server issues an auth token bound to the agent's key.
        String authToken = AuthTokens.create(AuthTokens.Spec.builder(AUTH_SERVER, RESOURCE_ID, AGENT_ID)
                .cnfJwk(agentJwk)
                .signingKey(authServerKeys.getPrivate(), "as-key-1")
                .act(Map.of("sub", AGENT_ID))
                .scope("data.read")
                .build());

        // 4. The agent signs the retry with the jwt scheme carrying the auth token.
        AgentRequestSigner signer =
                AgentRequestSigner.builder(agentKeys).agentToken(authToken).build();
        Map<String, String> headers = withSignatureHeaders(signer.signRequest("GET", TARGET, Map.of(), null, "jwt"));

        // 5. The resource verifies the signature and extracts the authorization context.
        RequestVerifier.Result result = verifier.verifyRequest("GET", TARGET, headers, null, true, true);

        assertThat(result.valid()).isTrue();
        assertThat(result.agentId()).isEqualTo(AGENT_ID);
        assertThat(result.scopes()).containsExactly("data.read");
        assertThat(result.act()).containsEntry("sub", AGENT_ID);
    }

    @Test
    void emptyScopeClaimDoesNotSatisfyAuthTokenRequirement() {
        // Regression: a validly signed auth token with scope "" must not pass requireAuthToken.
        Map<String, Object> agentJwk = Jwk.publicKeyToJwk(agentKeys.getPublic(), null);
        Map<String, Object> header =
                new LinkedHashMap<>(Map.of("typ", "aa-auth+jwt", "alg", "EdDSA", "kid", "as-key-1"));
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", AUTH_SERVER);
        payload.put("agent", AGENT_ID);
        payload.put("cnf", Map.of("jwk", agentJwk));
        payload.put("scope", "  ");
        payload.put("exp", java.time.Instant.now().getEpochSecond() + 300);
        String emptyScopeToken =
                io.github.marcofanti.aauth.signing.Jwts.signEdDsa(header, payload, authServerKeys.getPrivate());

        AgentRequestSigner signer = AgentRequestSigner.builder(agentKeys)
                .agentToken(emptyScopeToken)
                .build();
        Map<String, String> headers = withSignatureHeaders(signer.signRequest("GET", TARGET, Map.of(), null, "jwt"));

        RequestVerifier.Result result = verifier.verifyRequest("GET", TARGET, headers, null, false, true);

        assertThat(result.valid()).isFalse();
        assertThat(result.error()).contains("Auth token required");
    }

    @Test
    void scopeSplittingCollapsesWhitespace() {
        Map<String, Object> agentJwk = Jwk.publicKeyToJwk(agentKeys.getPublic(), null);
        String authToken = AuthTokens.create(AuthTokens.Spec.builder(AUTH_SERVER, RESOURCE_ID, AGENT_ID)
                .cnfJwk(agentJwk)
                .signingKey(authServerKeys.getPrivate(), "as-key-1")
                .act(Map.of("sub", AGENT_ID))
                .scope("data.read  data.write")
                .build());
        AgentRequestSigner signer =
                AgentRequestSigner.builder(agentKeys).agentToken(authToken).build();
        Map<String, String> headers = withSignatureHeaders(signer.signRequest("GET", TARGET, Map.of(), null, "jwt"));

        RequestVerifier.Result result = verifier.verifyRequest("GET", TARGET, headers, null, false, true);

        assertThat(result.valid()).isTrue();
        assertThat(result.scopes()).containsExactly("data.read", "data.write");
    }

    @Test
    void bodyWithMatchingContentDigestPasses() {
        byte[] body = "{\"amount\": 100}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        // The low-level signer covers content-digest via additionalComponents.
        Map<String, String> headers = withSignatureHeaders(io.github.marcofanti.aauth.signing.RequestSigner.sign(
                io.github.marcofanti.aauth.signing.SignRequest.builder("POST", TARGET)
                        .keyPair(agentKeys)
                        .scheme(new io.github.marcofanti.aauth.signing.SignatureScheme.Hwk())
                        .body(body)
                        .additionalComponents(List.of("content-digest"))
                        .build()));

        RequestVerifier.Result result = verifier.verifyRequest("POST", TARGET, headers, body, false, false);

        assertThat(result.valid()).isTrue();
    }

    @Test
    void tamperedBodyWithIntactContentDigestIsRejected() {
        byte[] body = "{\"amount\": 100}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Map<String, String> headers = withSignatureHeaders(io.github.marcofanti.aauth.signing.RequestSigner.sign(
                io.github.marcofanti.aauth.signing.SignRequest.builder("POST", TARGET)
                        .keyPair(agentKeys)
                        .scheme(new io.github.marcofanti.aauth.signing.SignatureScheme.Hwk())
                        .body(body)
                        .additionalComponents(List.of("content-digest"))
                        .build()));
        byte[] tamperedBody = "{\"amount\": 999999}".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        RequestVerifier.Result result = verifier.verifyRequest("POST", TARGET, headers, tamperedBody, false, false);

        assertThat(result.valid()).isFalse();
        assertThat(result.error()).isEqualTo("content-digest mismatch");
    }

    private Map<String, String> signedWithProvidedDigest(byte[] body, String contentDigest) {
        // The signer returns only headers it adds, so a caller-supplied Content-Digest must be
        // merged back into the wire headers alongside the signature headers.
        Map<String, String> headers = withSignatureHeaders(io.github.marcofanti.aauth.signing.RequestSigner.sign(
                io.github.marcofanti.aauth.signing.SignRequest.builder("POST", TARGET)
                        .keyPair(agentKeys)
                        .scheme(new io.github.marcofanti.aauth.signing.SignatureScheme.Hwk())
                        .body(body)
                        .headers(Map.of("Content-Digest", contentDigest))
                        .additionalComponents(List.of("content-digest"))
                        .build()));
        headers.put("Content-Digest", contentDigest);
        return headers;
    }

    @Test
    void sha512ContentDigestIsAccepted() {
        byte[] body = "{\"amount\": 100}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Map<String, String> headers = signedWithProvidedDigest(
                body, io.github.marcofanti.aauth.signing.SignatureBase.contentDigest(body, "sha-512"));

        RequestVerifier.Result result = verifier.verifyRequest("POST", TARGET, headers, body, false, false);

        assertThat(result.valid()).isTrue();
    }

    @Test
    void unknownOnlyContentDigestAlgorithmIsRejected() {
        byte[] body = "{\"amount\": 100}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Map<String, String> headers = signedWithProvidedDigest(body, "unixsum=:AAAA:");

        RequestVerifier.Result result = verifier.verifyRequest("POST", TARGET, headers, body, false, false);

        assertThat(result.valid()).isFalse();
        assertThat(result.error()).isEqualTo("unsupported content-digest algorithm");
    }

    @Test
    void bodyWithoutContentDigestHeaderIsUnaffected() {
        AgentRequestSigner signer = AgentRequestSigner.builder(agentKeys).build();
        byte[] body = "{\"note\": \"no digest coverage\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Map<String, String> headers = withSignatureHeaders(signer.signRequest("POST", TARGET, Map.of(), body, "hwk"));

        RequestVerifier.Result result = verifier.verifyRequest("POST", TARGET, headers, body, false, false);

        assertThat(result.valid()).isTrue();
    }

    @Test
    void missingSignatureHeadersFailCleanly() {
        RequestVerifier.Result result = verifier.verifyRequest("GET", TARGET, Map.of(), null, false, false);

        assertThat(result.valid()).isFalse();
        assertThat(result.error()).contains("Missing signature headers");
    }

    @Test
    void unknownAuthorityIsRejected() {
        AgentRequestSigner signer = AgentRequestSigner.builder(agentKeys).build();
        String otherTarget = "https://grafana.uma.lab/api";
        Map<String, String> headers =
                withSignatureHeaders(signer.signRequest("GET", otherTarget, Map.of(), null, "hwk"));

        RequestVerifier.Result result = verifier.verifyRequest("GET", otherTarget, headers, null, false, false);

        assertThat(result.valid()).isFalse();
        assertThat(result.error()).contains("canonical authorities");
    }

    @Test
    void requirementsAreEnforced() {
        AgentRequestSigner signer = AgentRequestSigner.builder(agentKeys).build();
        Map<String, String> headers = withSignatureHeaders(signer.signRequest("GET", TARGET, Map.of(), null, "hwk"));

        assertThat(verifier.verifyRequest("GET", TARGET, headers, null, true, false)
                        .error())
                .contains("identity required");
        assertThat(verifier.verifyRequest("GET", TARGET, headers, null, false, true)
                        .error())
                .contains("Auth token required");
    }

    @Test
    void tamperedSignatureFailsVerification() {
        AgentRequestSigner signer = AgentRequestSigner.builder(agentKeys).build();
        Map<String, String> headers = withSignatureHeaders(signer.signRequest("GET", TARGET, Map.of(), null, "hwk"));
        headers.put("Signature", headers.get("Signature").replaceFirst("sig=:.", "sig=:A"));

        RequestVerifier.Result result = verifier.verifyRequest("GET", TARGET, headers, null, false, false);

        assertThat(result.valid()).isFalse();
    }

    @Test
    void challengeBuilderEmitsAcceptSignatureLevels() {
        ChallengeBuilder challengeBuilder =
                new ChallengeBuilder(RESOURCE_ID, resourceKeys.getPrivate(), "r-key-1", AUTH_SERVER);

        ChallengeBuilder.Challenge pseudonym = challengeBuilder.buildChallenge(ChallengeBuilder.Spec.pseudonym());
        assertThat(pseudonym.headerName()).isEqualTo(AAuthHeaders.HEADER_ACCEPT_SIGNATURE);
        assertThat(pseudonym.headerValue()).contains("sigkey=jkt");

        ChallengeBuilder.Challenge identity = challengeBuilder.buildChallenge(ChallengeBuilder.Spec.identity());
        assertThat(identity.headerValue()).contains("sigkey=uri");
    }

    @Test
    void authTokenChallengeRequiresAgentDetails() {
        ChallengeBuilder challengeBuilder =
                new ChallengeBuilder(RESOURCE_ID, resourceKeys.getPrivate(), "r-key-1", AUTH_SERVER);

        assertThatThrownBy(() -> challengeBuilder.buildChallenge(
                        new ChallengeBuilder.Spec(false, true, null, null, null, null, null)))
                .isInstanceOf(ChallengeException.class)
                .hasMessageContaining("agentId");
    }

    @Test
    void issuerProducesVerifiableResourceTokens() {
        ResourceTokenIssuer issuer =
                new ResourceTokenIssuer(RESOURCE_ID, resourceKeys.getPrivate(), "r-key-1", AUTH_SERVER);

        String token = issuer.issueToken(AGENT_ID, agentKeys.getPublic(), "data.write", null);

        Map<String, Object> claims = ResourceTokens.verify(
                token,
                iss -> Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(resourceKeys.getPublic(), "r-key-1"))),
                AUTH_SERVER,
                AGENT_ID,
                null);
        assertThat(claims).containsEntry("scope", "data.write");
    }
}
