package io.github.marcofanti.aauth.resource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.agent.AgentRequestSigner;
import io.github.marcofanti.aauth.headers.AAuthHeaders;
import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import io.github.marcofanti.aauth.tokens.AuthTokens;
import io.github.marcofanti.aauth.tokens.PersonTokens;
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
    private static final String PS = "https://ps.uma.lab";
    private static final String PERSON_SUB = "person-sub-1";
    private static final String TARGET = "https://gateway.uma.lab/api/data";

    private final KeyPair resourceKeys = KeyPairs.generateEd25519();
    private final KeyPair agentKeys = KeyPairs.generateEd25519();
    private final KeyPair authServerKeys = KeyPairs.generateEd25519();
    private final KeyPair psKeys = KeyPairs.generateEd25519();
    private final Map<String, Object> agentJwk = Jwk.publicKeyToJwk(agentKeys.getPublic(), null);

    /** Resolves the PS and resource JWKS, as a PS or AS would. */
    private final JwksFetcher issuerJwks = (id, dwk, kid) -> {
        if (PS.equals(id)) {
            return Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(psKeys.getPublic(), "ps-key-1")));
        }
        if (RESOURCE_ID.equals(id)) {
            return Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(resourceKeys.getPublic(), "r-key-1")));
        }
        return null;
    };

    private long now() {
        return java.time.Instant.now().getEpochSecond();
    }

    /** A person token the PS issued to the agent for this resource. */
    private String personToken() {
        return PersonTokens.create(
                PersonTokens.Spec.builder(PS, RESOURCE_ID, PERSON_SUB, agentJwk, psKeys.getPrivate(), "ps-key-1")
                        .agentExp(now() + 600)
                        .build());
    }

    private ChallengeBuilder challengeBuilder() {
        return new ChallengeBuilder(RESOURCE_ID, resourceKeys.getPrivate(), "r-key-1", PS, issuerJwks);
    }

    private AuthTokens.Spec.Builder authToken(String scope) {
        return AuthTokens.Spec.builder(AUTH_SERVER, RESOURCE_ID, PERSON_SUB, PS)
                .cnfJwk(agentJwk)
                .signingKey(authServerKeys.getPrivate(), "as-key-1")
                .bounds(now() + 600, now() + 600)
                .scope(scope);
    }

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
        // 1. The agent presented a person token; the resource challenges with an embedded
        //    resource token bound to it (draft-11 §6.7).
        String presented = personToken();
        ChallengeBuilder.Challenge challenge = challengeBuilder()
                .buildChallenge(ChallengeBuilder.Spec.authToken(presented, agentKeys.getPublic(), "data.read"));

        assertThat(challenge.headerName()).isEqualTo(AAuthHeaders.HEADER_AAUTH_REQUIREMENT);
        String resourceToken =
                AAuthHeaders.parseAAuthHeader(challenge.headerValue()).resourceToken();
        assertThat(resourceToken).isNotNull();

        // 2. The PS verifies the resource token and its binding to the presented person token.
        Map<String, Object> resourceClaims = ResourceTokens.verify(
                resourceToken,
                issuerJwks,
                new ResourceTokens.VerifyOptions(presented, PS, RESOURCE_ID, PS, Jwk.thumbprint(agentJwk), null, null));
        assertThat(resourceClaims)
                .containsEntry("scope", "data.read")
                .containsEntry("sub", PERSON_SUB)
                .containsEntry("ps", PS);

        // 3. The auth server issues an auth token bound to the agent's key.
        String authToken = AuthTokens.create(authToken("data.read").build());

        // 4. The agent signs the retry with the jwt scheme carrying the auth token.
        AgentRequestSigner signer =
                AgentRequestSigner.builder(agentKeys).agentToken(authToken).build();
        Map<String, String> headers = withSignatureHeaders(signer.signRequest("GET", TARGET, Map.of(), null, "jwt"));

        // 5. The resource verifies the signature and extracts the authorization context.
        RequestVerifier.Result result = verifier.verifyRequest("GET", TARGET, headers, null, false, true);

        assertThat(result.valid()).isTrue();
        assertThat(result.userSub()).isEqualTo(PERSON_SUB);
        assertThat(result.scopes()).containsExactly("data.read");
    }

    @Test
    void emptyScopeClaimDoesNotSatisfyAuthTokenRequirement() {
        // Regression: a validly signed auth token with scope "" must not pass requireAuthToken.
        Map<String, Object> agentJwk = Jwk.publicKeyToJwk(agentKeys.getPublic(), null);
        Map<String, Object> header =
                new LinkedHashMap<>(Map.of("typ", "aa-auth+jwt", "alg", "Ed25519", "kid", "as-key-1"));
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", AUTH_SERVER);
        payload.put("dwk", "aauth-access.json");
        payload.put("sub", PERSON_SUB);
        payload.put("ps", PS);
        payload.put("cnf", Map.of("jwk", agentJwk));
        payload.put("scope", "  ");
        payload.put("iat", java.time.Instant.now().getEpochSecond());
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
        String authToken = AuthTokens.create(authToken("data.read  data.write").build());
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

        // Draft-11: a covered Content-Digest is checked against the body by the signature layer.
        assertThat(result.valid()).isFalse();
        assertThat(result.error()).isEqualTo("Signature verification failed");
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
    void missionS256IsSurfacedFromPresentedToken() {
        // Draft-11: the mission reaches the resource as mission_s256 inside the presented token,
        // not as an AAuth-Mission header.
        String mission = "m".repeat(43);
        String authToken =
                AuthTokens.create(authToken("data.read").missionS256(mission).build());
        AgentRequestSigner signer =
                AgentRequestSigner.builder(agentKeys).agentToken(authToken).build();
        Map<String, String> headers = withSignatureHeaders(signer.signRequest("GET", TARGET, Map.of(), null, "jwt"));

        RequestVerifier.Result result = verifier.verifyRequest("GET", TARGET, headers, null, false, true);

        assertThat(result.valid()).isTrue();
        assertThat(result.missionS256()).isEqualTo(mission);
    }

    @Test
    void missionS256IsNullWithoutMission() {
        AgentRequestSigner signer = AgentRequestSigner.builder(agentKeys).build();
        Map<String, String> headers = withSignatureHeaders(signer.signRequest("GET", TARGET, Map.of(), null, "hwk"));

        RequestVerifier.Result result = verifier.verifyRequest("GET", TARGET, headers, null, false, false);

        assertThat(result.valid()).isTrue();
        assertThat(result.missionS256()).isNull();
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
    void challengesAreAlwaysAAuthRequirements() {
        // Draft-11: agent-token by default; never a pseudonymous Accept-Signature fallback.
        ChallengeBuilder.Challenge agent = challengeBuilder().buildChallenge(ChallengeBuilder.Spec.agentToken());
        assertThat(agent.headerName()).isEqualTo(AAuthHeaders.HEADER_AAUTH_REQUIREMENT);
        assertThat(agent.headerValue()).isEqualTo("requirement=agent-token");

        ChallengeBuilder.Challenge person = challengeBuilder().buildChallenge(ChallengeBuilder.Spec.personToken());
        assertThat(person.headerValue()).isEqualTo("requirement=person-token");
    }

    @Test
    void authTokenChallengeWithoutPresentedTokenAsksForAPersonToken() {
        ChallengeBuilder.Challenge challenge = challengeBuilder()
                .buildChallenge(new ChallengeBuilder.Spec(false, true, null, null, "data.read", null));

        assertThat(challenge.headerValue()).isEqualTo("requirement=person-token");
        assertThatThrownBy(() -> challengeBuilder()
                        .buildChallenge(new ChallengeBuilder.Spec(false, true, personToken(), null, null, null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("agentPublicKey");
    }

    @Test
    void issuerRequiresAVerifiedPresentedToken() {
        ResourceTokenIssuer issuer =
                new ResourceTokenIssuer(RESOURCE_ID, resourceKeys.getPrivate(), "r-key-1", PS, issuerJwks, null);
        String presented = personToken();

        String token = issuer.issueToken(presented, agentKeys.getPublic(), "data.write", null, b -> b.account("alice"));

        Map<String, Object> claims =
                ResourceTokens.verify(token, issuerJwks, ResourceTokens.VerifyOptions.of(presented));
        assertThat(claims)
                .containsEntry("scope", "data.write")
                .containsEntry("sub", PERSON_SUB)
                .containsEntry("account", "alice");
        assertThatThrownBy(() ->
                        issuer.issueToken(presented, KeyPairs.generateEd25519().getPublic(), "data.write", null, null))
                .isInstanceOf(TokenException.class)
                .extracting(e -> ((TokenException) e).errorCode())
                .isEqualTo("invalid_presented_token");
    }
}
