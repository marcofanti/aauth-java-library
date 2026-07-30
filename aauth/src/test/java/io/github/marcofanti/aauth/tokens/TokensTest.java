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
    private static final String AGENT_ID = "aauth:agent@portal.uma.lab";

    private final KeyPair issuerKeys = KeyPairs.generateEd25519();
    private final KeyPair delegateKeys = KeyPairs.generateEd25519();
    private final Map<String, Object> delegateJwk = Jwk.publicKeyToJwk(delegateKeys.getPublic(), null);
    private final Function<String, Map<String, Object>> issuerJwksFetcher =
            iss -> Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(issuerKeys.getPublic(), "key-1")));

    // --- Agent tokens ---

    private String agentToken() {
        return AgentTokens.create(
                AgentTokens.Spec.builder(AGENT_SERVER, "delegate-1", delegateJwk, issuerKeys.getPrivate(), "key-1")
                        .ps("https://ps.uma.lab")
                        .build());
    }

    @Test
    void agentTokenRoundTrips() {
        Map<String, Object> claims = AgentTokens.verify(agentToken(), issuerJwksFetcher, null);

        assertThat(claims)
                .containsEntry("iss", AGENT_SERVER)
                .containsEntry("sub", "delegate-1")
                .containsEntry("dwk", "aauth-agent.json")
                .containsEntry("ps", "https://ps.uma.lab")
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

    // --- Auth tokens ---

    private AuthTokens.Spec.Builder authTokenSpec() {
        return AuthTokens.Spec.builder(AUTH_SERVER, RESOURCE, AGENT_ID)
                .cnfJwk(delegateJwk)
                .signingKey(issuerKeys.getPrivate(), "key-1")
                .act(Map.of("sub", AGENT_ID))
                .scope("data.read");
    }

    @Test
    void authTokenRoundTripsWithFullVerification() {
        String token = AuthTokens.create(authTokenSpec().build());

        Map<String, Object> claims = AuthTokens.verifyToken(
                token,
                issuerJwksFetcher,
                new AuthTokens.VerifyOptions(AuthTokens.TYPE, AUTH_SERVER, RESOURCE, AGENT_ID, delegateJwk));

        assertThat(claims)
                .containsEntry("agent", AGENT_ID)
                .containsEntry("scope", "data.read")
                .containsEntry("dwk", "aauth-access.json");
    }

    @Test
    void authTokenRequiresAgentAndSubOrScope() {
        assertThatThrownBy(() -> AuthTokens.Spec.builder(AUTH_SERVER, RESOURCE, null)
                        .cnfJwk(delegateJwk)
                        .signingKey(issuerKeys.getPrivate(), "key-1")
                        .act(Map.of("sub", AGENT_ID))
                        .scope("x")
                        .build())
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("agent");

        assertThatThrownBy(() -> authTokenSpec().scope(null).build())
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("sub");
    }

    @Test
    void authTokenRejectsCnfMismatch() {
        String token = AuthTokens.create(authTokenSpec().build());
        Map<String, Object> otherJwk =
                Jwk.publicKeyToJwk(KeyPairs.generateEd25519().getPublic(), null);

        assertThatThrownBy(() -> AuthTokens.verifyToken(
                        token,
                        issuerJwksFetcher,
                        new AuthTokens.VerifyOptions(AuthTokens.TYPE, null, null, null, otherJwk)))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("cnf.jwk");
    }

    @Test
    void authTokenRejectsActSubMismatch() {
        String token = AuthTokens.create(authTokenSpec()
                .act(Map.of("sub", "aauth:other@keycloak.uma.lab"))
                .build());

        assertThatThrownBy(() -> AuthTokens.verifyToken(
                        token,
                        issuerJwksFetcher,
                        new AuthTokens.VerifyOptions(AuthTokens.TYPE, null, null, AGENT_ID, null)))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("act.sub");
    }

    @Test
    void authTokenRejectsFutureIat() {
        Map<String, Object> header =
                new LinkedHashMap<>(Map.of("typ", AuthTokens.TYPE, "alg", "EdDSA", "kid", "key-1"));
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", AUTH_SERVER);
        payload.put("jti", "x");
        payload.put("agent", AGENT_ID);
        payload.put("act", Map.of("sub", AGENT_ID));
        payload.put("scope", "data.read");
        payload.put("iat", Instant.now().getEpochSecond() + 600);
        String token = Jwts.signEdDsa(header, payload, issuerKeys.getPrivate());

        assertThatThrownBy(() -> AuthTokens.verifyToken(
                        token, issuerJwksFetcher, AuthTokens.VerifyOptions.forType(AuthTokens.TYPE)))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("iat");
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
                AUTH_SERVER,
                AGENT_ID,
                Jwk.thumbprint(delegateJwk),
                "data.read data.write",
                issuerKeys.getPrivate(),
                "key-1",
                null,
                null));
    }

    @Test
    void resourceTokenRoundTrips() {
        Map<String, Object> claims = ResourceTokens.verify(
                resourceToken(), issuerJwksFetcher, AUTH_SERVER, AGENT_ID, Jwk.thumbprint(delegateJwk));

        assertThat(claims)
                .containsEntry("iss", RESOURCE)
                .containsEntry("dwk", "aauth-resource.json")
                .containsEntry("scope", "data.read data.write");
    }

    @Test
    void resourceTokenRejectsAgentJktMismatch() {
        assertThatThrownBy(
                        () -> ResourceTokens.verify(resourceToken(), issuerJwksFetcher, null, null, "WRONG_THUMBPRINT"))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("agent_jkt");
    }

    @Test
    void resourceTokenRejectsExpired() {
        String token = ResourceTokens.create(new ResourceTokens.Spec(
                RESOURCE,
                AUTH_SERVER,
                AGENT_ID,
                "jkt",
                "s",
                issuerKeys.getPrivate(),
                "key-1",
                Instant.now().getEpochSecond() - 5,
                null));

        assertThatThrownBy(() -> ResourceTokens.verify(token, issuerJwksFetcher, null, null, null))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void resourceTokenCarriesMission() {
        String token = ResourceTokens.create(new ResourceTokens.Spec(
                RESOURCE,
                AUTH_SERVER,
                AGENT_ID,
                "jkt",
                "s",
                issuerKeys.getPrivate(),
                "key-1",
                null,
                Map.of("approver", "https://ps.uma.lab", "s256", "abc")));

        Map<String, Object> claims = ResourceTokens.verify(token, issuerJwksFetcher, null, null, null);
        assertThat(((Map<?, ?>) claims.get("mission")).get("approver")).isEqualTo("https://ps.uma.lab");
    }
}
