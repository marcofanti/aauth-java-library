package io.github.marcofanti.aauth.tokens;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import java.security.KeyPair;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class TokensTest {

    private static final String AGENT_SERVER = "https://portal.uma.lab";
    private static final String AUTH_SERVER = "https://alice-as.uma.lab";
    private static final String RESOURCE = "https://gateway.uma.lab";
    private static final String PS = "https://ps.uma.lab";
    private static final String PERSON_SUB = "person-sub-1";

    private final KeyPair issuerKeys = KeyPairs.generateEd25519();
    private final KeyPair delegateKeys = KeyPairs.generateEd25519();
    private final Map<String, Object> delegateJwk = Jwk.publicKeyToJwk(delegateKeys.getPublic(), null);
    private final Function<String, Map<String, Object>> issuerJwksFetcher =
            iss -> Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(issuerKeys.getPublic(), "key-1")));

    // --- Agent tokens ---

    private String agentToken() {
        return AgentTokens.create(
                AgentTokens.Spec.builder(AGENT_SERVER, "delegate-1", delegateJwk, issuerKeys.getPrivate(), "key-1")
                        .ps(PS)
                        .build());
    }

    @Test
    void agentTokenRoundTrips() {
        Map<String, Object> claims = AgentTokens.verify(agentToken(), issuerJwksFetcher, null);

        assertThat(claims)
                .containsEntry("iss", AGENT_SERVER)
                .containsEntry("sub", "delegate-1")
                .containsEntry("dwk", "aauth-agent.json")
                .containsEntry("ps", PS)
                .containsKeys("jti", "iat", "exp", "cnf");
    }

    @Test
    void agentTokenAudienceIsEnforced() {
        String token = AgentTokens.create(
                AgentTokens.Spec.builder(AGENT_SERVER, "delegate-1", delegateJwk, issuerKeys.getPrivate(), "key-1")
                        .aud(AUTH_SERVER)
                        .build());

        assertThat(AgentTokens.verify(token, issuerJwksFetcher, AUTH_SERVER)).containsEntry("aud", AUTH_SERVER);
        assertThatThrownBy(() -> AgentTokens.verify(token, issuerJwksFetcher, "https://grafana.uma.lab"))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("audience");
    }

    @Test
    void agentTokenRejectsWrongTypeAndTamperedSignature() {
        String token = agentToken();
        assertThatThrownBy(() -> AgentTokens.verify(token + "x", issuerJwksFetcher, null))
                .isInstanceOf(TokenException.class);

        KeyPair otherKeys = KeyPairs.generateEd25519();
        Function<String, Map<String, Object>> wrongJwks =
                iss -> Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(otherKeys.getPublic(), "key-1")));
        assertThatThrownBy(() -> AgentTokens.verify(token, wrongJwks, null))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("signature");
    }

    @Test
    void agentTokenRejectsExpired() {
        String token = AgentTokens.create(
                AgentTokens.Spec.builder(AGENT_SERVER, "delegate-1", delegateJwk, issuerKeys.getPrivate(), "key-1")
                        .exp(Instant.now().getEpochSecond() - 10)
                        .build());

        assertThatThrownBy(() -> AgentTokens.verify(token, issuerJwksFetcher, null))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("expired");
    }

    // --- Person tokens (draft-11) ---

    private String personToken(String aud) {
        return PersonTokens.create(new PersonTokens.Spec(
                PS,
                PERSON_SUB,
                aud,
                delegateJwk,
                issuerKeys.getPrivate(),
                "key-1",
                null,
                null,
                null,
                null,
                null,
                null));
    }

    @Test
    void personTokenRoundTrips() {
        Map<String, Object> claims = PersonTokens.verify(personToken(RESOURCE), issuerJwksFetcher, RESOURCE);

        assertThat(claims)
                .containsEntry("iss", PS)
                .containsEntry("sub", PERSON_SUB)
                .containsEntry("aud", RESOURCE)
                .containsEntry("dwk", "aauth-person.json")
                .containsKeys("jti", "iat", "exp", "cnf");
    }

    @Test
    void personTokenRejectsWrongAudience() {
        assertThatThrownBy(() -> PersonTokens.verify(personToken(RESOURCE), issuerJwksFetcher, "https://other.uma.lab"))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("audience");
    }

    @Test
    void personTokenRejectsOverlongLifetime() {
        String token = PersonTokens.create(new PersonTokens.Spec(
                PS,
                PERSON_SUB,
                RESOURCE,
                delegateJwk,
                issuerKeys.getPrivate(),
                "key-1",
                Instant.now().getEpochSecond() + 7200,
                null,
                null,
                null,
                null,
                null));

        assertThatThrownBy(() -> PersonTokens.verify(token, issuerJwksFetcher, RESOURCE))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("lifetime");
    }

    @Test
    void personTokenCarriesMissionS256() {
        String token = PersonTokens.create(new PersonTokens.Spec(
                PS,
                PERSON_SUB,
                RESOURCE,
                delegateJwk,
                issuerKeys.getPrivate(),
                "key-1",
                null,
                "abc123",
                null,
                null,
                null,
                null));

        assertThat(PersonTokens.verify(token, issuerJwksFetcher, RESOURCE)).containsEntry("mission_s256", "abc123");
    }

    // --- Auth tokens ---

    private AuthTokens.Spec.Builder authTokenSpec() {
        return AuthTokens.Spec.builder(AUTH_SERVER, RESOURCE, PERSON_SUB, PS)
                .cnfJwk(delegateJwk)
                .signingKey(issuerKeys.getPrivate(), "key-1")
                .scope("data.read");
    }

    @Test
    void authTokenRoundTripsWithFullVerification() {
        String token = AuthTokens.create(authTokenSpec().build());

        Map<String, Object> claims = AuthTokens.verifyToken(
                token,
                issuerJwksFetcher,
                new AuthTokens.VerifyOptions(AuthTokens.TYPE, AUTH_SERVER, RESOURCE, delegateJwk));

        assertThat(claims)
                .containsEntry("sub", PERSON_SUB)
                .containsEntry("ps", PS)
                .containsEntry("scope", "data.read")
                .containsEntry("dwk", "aauth-access.json")
                .doesNotContainKeys("agent", "act");
    }

    @Test
    void authTokenRequiresSub() {
        assertThatThrownBy(() -> AuthTokens.Spec.builder(AUTH_SERVER, RESOURCE, null, PS)
                        .cnfJwk(delegateJwk)
                        .signingKey(issuerKeys.getPrivate(), "key-1")
                        .scope("x")
                        .build())
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("sub");
    }

    @Test
    void authTokenVerificationRequiresSub() {
        // A token without 'sub' (legacy shape) must fail -11 verification.
        Map<String, Object> header =
                new LinkedHashMap<>(Map.of("typ", AuthTokens.TYPE, "alg", "Ed25519", "kid", "key-1"));
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", AUTH_SERVER);
        payload.put("jti", "x");
        payload.put("cnf", Map.of("jwk", delegateJwk));
        payload.put("scope", "data.read");
        payload.put("exp", Instant.now().getEpochSecond() + 300);
        String noSub = Jwts.signEdDsa(header, payload, issuerKeys.getPrivate());

        assertThatThrownBy(() -> AuthTokens.verifyToken(
                        noSub, issuerJwksFetcher, AuthTokens.VerifyOptions.forType(AuthTokens.TYPE)))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("sub");
    }

    @Test
    void authTokenRejectsCnfMismatch() {
        String token = AuthTokens.create(authTokenSpec().build());
        Map<String, Object> otherJwk =
                Jwk.publicKeyToJwk(KeyPairs.generateEd25519().getPublic(), null);

        assertThatThrownBy(() -> AuthTokens.verifyToken(
                        token, issuerJwksFetcher, new AuthTokens.VerifyOptions(AuthTokens.TYPE, null, null, otherJwk)))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("cnf.jwk");
    }

    @Test
    void tokensCarryFullySpecifiedEd25519Alg() {
        Map<String, Object> parsed = AuthTokens.parseTokenClaims(agentToken());
        assertThat(((Map<?, ?>) parsed.get("header")).get("alg")).isEqualTo("Ed25519");
    }

    @Test
    void legacyEdDsaSignedTokenStillVerifies() {
        // Transition tolerance: pre-draft-10 peers (the Python reference) sign with "EdDSA".
        Map<String, Object> header =
                new LinkedHashMap<>(Map.of("typ", AgentTokens.TYPE, "alg", "EdDSA", "kid", "key-1"));
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", AGENT_SERVER);
        payload.put("sub", "delegate-1");
        payload.put("jti", "legacy-1");
        payload.put("cnf", Map.of("jwk", delegateJwk));
        payload.put("exp", Instant.now().getEpochSecond() + 300);
        String legacyToken = Jwts.signEdDsa(header, payload, issuerKeys.getPrivate());

        assertThat(AgentTokens.verify(legacyToken, issuerJwksFetcher, null)).containsEntry("sub", "delegate-1");
    }

    @Test
    void agentTokenValidatesPsAndParentAgentWhenPresent() {
        String valid = AgentTokens.create(
                AgentTokens.Spec.builder(AGENT_SERVER, "delegate-1", delegateJwk, issuerKeys.getPrivate(), "key-1")
                        .ps(PS)
                        .parentAgent("aauth:parent@portal.uma.lab")
                        .build());
        assertThat(AgentTokens.verify(valid, issuerJwksFetcher, null))
                .containsEntry("parent_agent", "aauth:parent@portal.uma.lab");

        // Non-TLS dev/demo origins for ps are accepted (http + port), not rejected.
        String httpDevPs = AgentTokens.create(
                AgentTokens.Spec.builder(AGENT_SERVER, "delegate-1", delegateJwk, issuerKeys.getPrivate(), "key-1")
                        .ps("http://ps.uma.lab:8765")
                        .build());
        assertThat(AgentTokens.verify(httpDevPs, issuerJwksFetcher, null))
                .containsEntry("ps", "http://ps.uma.lab:8765");

        // A malformed ps (no scheme/host) is still rejected.
        String badPs = AgentTokens.create(
                AgentTokens.Spec.builder(AGENT_SERVER, "delegate-1", delegateJwk, issuerKeys.getPrivate(), "key-1")
                        .ps("not-a-url")
                        .build());
        assertThatThrownBy(() -> AgentTokens.verify(badPs, issuerJwksFetcher, null))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("'ps'");

        String badParent = AgentTokens.create(
                AgentTokens.Spec.builder(AGENT_SERVER, "delegate-1", delegateJwk, issuerKeys.getPrivate(), "key-1")
                        .parentAgent("not-an-agent-id")
                        .build());
        assertThatThrownBy(() -> AgentTokens.verify(badParent, issuerJwksFetcher, null))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("parent_agent");
    }

    @Test
    void accountClaimRoundTripsOnBothTokenTypes() {
        String authToken = AuthTokens.create(
                authTokenSpec().account("alice@gateway.uma.lab").build());
        Map<String, Object> authClaims =
                AuthTokens.verifyToken(authToken, issuerJwksFetcher, AuthTokens.VerifyOptions.forType(AuthTokens.TYPE));
        assertThat(authClaims).containsEntry("account", "alice@gateway.uma.lab");

        String resourceToken = ResourceTokens.create(new ResourceTokens.Spec(
                RESOURCE,
                PS,
                "jkt",
                "data.read",
                PS,
                PERSON_SUB,
                "presented-1",
                issuerKeys.getPrivate(),
                "key-1",
                null,
                null,
                null,
                null,
                "alice@gateway.uma.lab"));
        assertThat(ResourceTokens.verify(resourceToken, issuerJwksFetcher, null, null))
                .containsEntry("account", "alice@gateway.uma.lab");
    }

    @Test
    void parseTokenClaimsExposesHeaderAndPayload() {
        Map<String, Object> parsed =
                AuthTokens.parseTokenClaims(AuthTokens.create(authTokenSpec().build()));

        assertThat(parsed).containsKeys("header", "payload");
        assertThat(((Map<?, ?>) parsed.get("header")).get("typ")).isEqualTo(AuthTokens.TYPE);
    }

    // --- Resource tokens ---

    private String resourceToken() {
        return ResourceTokens.create(new ResourceTokens.Spec(
                RESOURCE,
                PS,
                Jwk.thumbprint(delegateJwk),
                "data.read data.write",
                PS,
                PERSON_SUB,
                "presented-1",
                issuerKeys.getPrivate(),
                "key-1",
                null,
                null,
                null,
                null,
                null));
    }

    @Test
    void resourceTokenRoundTrips() {
        Map<String, Object> claims =
                ResourceTokens.verify(resourceToken(), issuerJwksFetcher, PS, Jwk.thumbprint(delegateJwk));

        assertThat(claims)
                .containsEntry("iss", RESOURCE)
                .containsEntry("dwk", "aauth-resource.json")
                .containsEntry("ps", PS)
                .containsEntry("sub", PERSON_SUB)
                .containsEntry("presented_jti", "presented-1")
                .containsEntry("scope", "data.read data.write")
                .doesNotContainKey("agent");
    }

    @Test
    void resourceTokenRejectsAgentJktMismatch() {
        assertThatThrownBy(() -> ResourceTokens.verify(resourceToken(), issuerJwksFetcher, null, "WRONG_THUMBPRINT"))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("agent_jkt");
    }

    @Test
    void resourceTokenRejectsExpired() {
        String token = ResourceTokens.create(new ResourceTokens.Spec(
                RESOURCE,
                PS,
                "jkt",
                "s",
                PS,
                PERSON_SUB,
                "presented-1",
                issuerKeys.getPrivate(),
                "key-1",
                Instant.now().getEpochSecond() - 5,
                null,
                null,
                null,
                null));

        assertThatThrownBy(() -> ResourceTokens.verify(token, issuerJwksFetcher, null, null))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void resourceTokenCarriesMissionS256() {
        String token = ResourceTokens.create(new ResourceTokens.Spec(
                RESOURCE,
                PS,
                "jkt",
                "s",
                PS,
                PERSON_SUB,
                "presented-1",
                issuerKeys.getPrivate(),
                "key-1",
                null,
                "abc123",
                null,
                null,
                null));

        Map<String, Object> claims = ResourceTokens.verify(token, issuerJwksFetcher, null, null);
        assertThat(claims).containsEntry("mission_s256", "abc123");
    }
}
