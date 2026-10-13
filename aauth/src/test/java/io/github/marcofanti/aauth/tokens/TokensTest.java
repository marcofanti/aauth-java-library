package io.github.marcofanti.aauth.tokens;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** Draft-11 token issuance and adversarial verification (mirrors the reference test_draft11). */
class TokensTest {

    private static final String RESOURCE = "https://gateway.uma.lab";
    private static final String PS = "https://ps.uma.lab";
    private static final String AP = "https://portal.uma.lab";
    private static final String AGENT_ID = "aauth:Agent@portal.uma.lab";
    private static final String MISSION = "m".repeat(43);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final long now = Instant.now().getEpochSecond();
    private final KeyPair agentKeys = KeyPairs.generateEd25519();
    private final KeyPair issuerKeys = KeyPairs.generateEd25519();
    private final Map<String, Object> agentJwk = Jwk.publicKeyToJwk(agentKeys.getPublic(), null);
    private final String agentJkt = Jwk.thumbprint(agentJwk);
    private final JwksFetcher fetch =
            (id, dwk, kid) -> Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(issuerKeys.getPublic(), "issuer-1")));

    // --- Independent minting: test the wire format, not the library's encoder ---------------

    private Map<String, Object> claims(String typ) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("iss", PS);
        p.put("aud", RESOURCE);
        p.put("sub", "person-1");
        p.put("ps", PS);
        p.put("dwk", "aauth-person.json");
        p.put("jti", "token-1");
        p.put("iat", now);
        p.put("exp", now + 600);
        p.put("cnf", Map.of("jwk", agentJwk));
        p.put("scope", "read");
        if (AgentTokens.TYPE.equals(typ)) {
            p.put("iss", AP);
            p.put("sub", AGENT_ID);
            p.put("dwk", "aauth-agent.json");
            p.remove("ps");
            p.remove("aud");
        }
        if (PersonTokens.TYPE.equals(typ)) {
            p.remove("ps");
            p.remove("scope");
        }
        return p;
    }

    private String mint(Map<String, Object> payload, String typ, String alg) throws Exception {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", alg);
        header.put("kid", "issuer-1");
        header.put("typ", typ);
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        String data = enc.encodeToString(MAPPER.writeValueAsBytes(header)) + "."
                + enc.encodeToString(MAPPER.writeValueAsBytes(payload));
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(issuerKeys.getPrivate());
        signer.update(data.getBytes(StandardCharsets.US_ASCII));
        return data + "." + enc.encodeToString(signer.sign());
    }

    private String mint(Map<String, Object> payload, String typ) throws Exception {
        return mint(payload, typ, "Ed25519");
    }

    private static void assertCode(ThrowingCallable call, String code) {
        assertThatThrownBy(call)
                .isInstanceOf(TokenException.class)
                .extracting(e -> ((TokenException) e).errorCode())
                .isEqualTo(code);
    }

    private TokenVerifier.Options authOptions() {
        return TokenVerifier.Options.forType(AuthTokens.TYPE).withAudience(RESOURCE);
    }

    // --- Generic verification ----------------------------------------------------------------

    @Test
    void currentAuthTokenVerifiesWithoutAgentOrAct() throws Exception {
        Map<String, Object> p =
                TokenVerifier.verify(mint(claims(AuthTokens.TYPE), AuthTokens.TYPE), fetch, authOptions());

        assertThat(p).containsEntry("sub", "person-1").containsEntry("ps", PS).doesNotContainKeys("agent", "act");
    }

    static Stream<Arguments> invalidAuthChanges() {
        return Stream.of(
                Arguments.of("aud", "https://other.uma.lab"),
                Arguments.of("aud", "http://gateway.uma.lab"),
                Arguments.of("iss", "https://ps.uma.lab:8443"),
                Arguments.of("exp", null),
                Arguments.of("iat", null),
                Arguments.of("jti", null),
                Arguments.of("dwk", "aauth-agent.json"),
                Arguments.of("sub", null),
                Arguments.of("ps", null),
                Arguments.of("ps", "https://other-ps.uma.lab"),
                Arguments.of("exp", true),
                Arguments.of("mission_s256", "short"),
                Arguments.of("scope", 42));
    }

    @ParameterizedTest
    @MethodSource("invalidAuthChanges")
    void resourceRejectsInvalidAuthContext(String claim, Object value) throws Exception {
        Map<String, Object> p = claims(AuthTokens.TYPE);
        if (value == null) {
            p.remove(claim);
        } else {
            p.put(claim, value);
        }
        String token = mint(p, AuthTokens.TYPE);

        assertThatThrownBy(() -> TokenVerifier.verify(token, fetch, authOptions()))
                .isInstanceOf(TokenException.class);
    }

    @Test
    void lifetimeOverOneHourIsRejectedForPersonAndAuthTokens() throws Exception {
        for (String typ : List.of(AuthTokens.TYPE, PersonTokens.TYPE)) {
            Map<String, Object> p = claims(typ);
            p.put("exp", now + 3601);
            p.put("iat", now);
            assertCode(
                    () -> TokenVerifier.verify(mint(p, typ), fetch, TokenVerifier.Options.forType(typ)), "invalid_jwt");
        }
    }

    @Test
    void polymorphicAndSymmetricAlgorithmsAreRejected() throws Exception {
        String eddsa = mint(claims(AuthTokens.TYPE), AuthTokens.TYPE, "EdDSA");
        assertCode(() -> TokenVerifier.verify(eddsa, fetch, authOptions()), "unsupported_algorithm");
        String hs256 = mint(claims(AuthTokens.TYPE), AuthTokens.TYPE, "HS256");
        assertCode(() -> TokenVerifier.verify(hs256, fetch, authOptions()), "unsupported_algorithm");
    }

    @Test
    void confirmationKeyAlgorithmIsRequiredAndBound() throws Exception {
        Map<String, Object> noAlg = new LinkedHashMap<>(agentJwk);
        noAlg.remove("alg");
        Map<String, Object> p = claims(AuthTokens.TYPE);
        p.put("cnf", Map.of("jwk", noAlg));
        String token = mint(p, AuthTokens.TYPE);
        assertCode(() -> TokenVerifier.verify(token, fetch, authOptions()), "unsupported_algorithm");

        Map<String, Object> otherJwk =
                Jwk.publicKeyToJwk(KeyPairs.generateEd25519().getPublic(), null);
        String valid = mint(claims(AuthTokens.TYPE), AuthTokens.TYPE);
        assertCode(
                () -> TokenVerifier.verify(valid, fetch, authOptions().withRequestSigningJwk(otherJwk)), "invalid_key");
        assertThat(TokenVerifier.verify(valid, fetch, authOptions().withRequestSigningJwk(agentJwk)))
                .containsEntry("sub", "person-1");
    }

    @Test
    void authTokenWithoutScopeIsStillAnAuthToken() throws Exception {
        Map<String, Object> p = claims(AuthTokens.TYPE);
        p.remove("scope");
        assertThat(TokenVerifier.verify(mint(p, AuthTokens.TYPE), fetch, authOptions()))
                .doesNotContainKey("scope");
    }

    @Test
    void psIssuedAuthTokenRequiresPsEqualIss() throws Exception {
        Map<String, Object> p = claims(AuthTokens.TYPE);
        p.put("ps", "https://other-ps.uma.lab");
        assertCode(() -> TokenVerifier.verify(mint(p, AuthTokens.TYPE), fetch, authOptions()), "invalid_jwt");

        p.put("dwk", "aauth-access.json");
        assertThat(TokenVerifier.verify(mint(p, AuthTokens.TYPE), fetch, authOptions()))
                .containsEntry("ps", "https://other-ps.uma.lab");
    }

    @Test
    void revokedTokenFailsWithRevokedJwt() throws Exception {
        String token = mint(claims(AuthTokens.TYPE), AuthTokens.TYPE);
        assertCode(
                () -> TokenVerifier.verify(
                        token,
                        fetch,
                        authOptions().withRevocationChecker((iss, jti) -> PS.equals(iss) && "token-1".equals(jti))),
                "revoked_jwt");
    }

    @Test
    void expectedTypAndIssuerAreEnforced() throws Exception {
        String person = mint(claims(PersonTokens.TYPE), PersonTokens.TYPE);
        assertCode(() -> TokenVerifier.verify(person, fetch, authOptions()), "invalid_jwt");
        assertCode(
                () -> TokenVerifier.verify(
                        person, fetch, TokenVerifier.Options.forType(null).withIssuer(AP)),
                "invalid_jwt");
        assertCode(() -> TokenVerifier.verify("not.a.jwt", fetch, authOptions()), "invalid_jwt");
        assertCode(
                () -> TokenVerifier.verify(mint(claims(PersonTokens.TYPE), "JWT"), fetch, authOptions()),
                "invalid_jwt");
    }

    @Test
    void unavailableJwksIsUnknownKey() throws Exception {
        String token = mint(claims(AuthTokens.TYPE), AuthTokens.TYPE);
        assertCode(() -> TokenVerifier.verify(token, (id, dwk, kid) -> null, authOptions()), "unknown_key");
    }

    // --- Agent tokens --------------------------------------------------------------------

    private AgentTokens.Spec.Builder agentSpec(String sub) {
        return AgentTokens.Spec.builder(AP, sub, agentJwk, issuerKeys.getPrivate(), "issuer-1");
    }

    @Test
    void agentTokenRoundTripsWithUppercaseLocalAndFullySpecifiedAlg() {
        String token = AgentTokens.create(agentSpec(AGENT_ID).ps(PS).build());

        assertThat(AuthTokens.parseTokenClaims(token).get("header"))
                .isEqualTo(Map.of("typ", AgentTokens.TYPE, "alg", "Ed25519", "kid", "issuer-1"));
        assertThat(AgentTokens.verify(token, fetch, null))
                .containsEntry("iss", AP)
                .containsEntry("sub", AGENT_ID)
                .containsEntry("dwk", "aauth-agent.json")
                .containsEntry("ps", PS)
                .containsKeys("jti", "iat", "exp", "cnf");
    }

    @Test
    void agentTokenIssuanceRejectsInvalidClaims() {
        assertThatThrownBy(() -> AgentTokens.create(agentSpec("delegate-1").build()))
                .isInstanceOf(TokenException.class);
        assertThatThrownBy(() -> AgentTokens.create(
                        agentSpec(AGENT_ID).ps("http://ps.uma.lab:8765").build()))
                .isInstanceOf(TokenException.class);
        assertThatThrownBy(() ->
                        AgentTokens.create(agentSpec(AGENT_ID).exp(now - 1).build()))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("expiration");
        assertThatThrownBy(() -> AgentTokens.create(agentSpec(AGENT_ID)
                        .parentAgent("aauth:other@portal.uma.lab")
                        .build()))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("verified parent token");
    }

    @Test
    void agentTokenAudienceAndExpiryAreEnforced() throws Exception {
        String token = AgentTokens.create(
                agentSpec(AGENT_ID).aud(List.of(PS, RESOURCE)).build());
        assertThat(AgentTokens.verify(token, fetch, RESOURCE)).containsKey("aud");
        assertCode(() -> AgentTokens.verify(token, fetch, "https://grafana.uma.lab"), "invalid_jwt");

        Map<String, Object> expired = claims(AgentTokens.TYPE);
        expired.put("iat", now - 600);
        expired.put("exp", now - 1);
        assertCode(() -> AgentTokens.verify(mint(expired, AgentTokens.TYPE), fetch, null), "expired_jwt");
    }

    @Test
    void agentTokenRejectsNonIdentifierSubAndSelfParent() throws Exception {
        Map<String, Object> badSub = claims(AgentTokens.TYPE);
        badSub.put("sub", "delegate-1");
        assertCode(() -> AgentTokens.verify(mint(badSub, AgentTokens.TYPE), fetch, null), "invalid_jwt");

        Map<String, Object> selfParent = claims(AgentTokens.TYPE);
        selfParent.put("parent_agent", AGENT_ID);
        assertCode(() -> AgentTokens.verify(mint(selfParent, AgentTokens.TYPE), fetch, null), "invalid_jwt");
    }

    @Test
    void subAgentIssuanceAndVerification() {
        String parent = AgentTokens.create(agentSpec(AGENT_ID).build());
        Map<String, Object> childJwk =
                Jwk.publicKeyToJwk(KeyPairs.generateEd25519().getPublic(), null);
        String child = AgentTokens.create(AgentTokens.Spec.builder(
                        AP, "aauth:Agent+task1@portal.uma.lab", childJwk, issuerKeys.getPrivate(), "issuer-1")
                .parentToken(parent, fetch)
                .build());

        assertThat(Delegation.verifySubagentToken(parent, child, fetch)).containsEntry("parent_agent", AGENT_ID);

        // The child must extend the parent's local part, use its own key, and the parent must be top-level.
        assertThatThrownBy(() -> AgentTokens.create(AgentTokens.Spec.builder(
                                AP, "aauth:other+x@portal.uma.lab", childJwk, issuerKeys.getPrivate(), "issuer-1")
                        .parentToken(parent, fetch)
                        .build()))
                .hasMessageContaining("discriminator");
        assertThatThrownBy(() -> AgentTokens.create(AgentTokens.Spec.builder(
                                AP, "aauth:Agent+x@portal.uma.lab", agentJwk, issuerKeys.getPrivate(), "issuer-1")
                        .parentToken(parent, fetch)
                        .build()))
                .hasMessageContaining("own key");
        assertThatThrownBy(() -> AgentTokens.create(AgentTokens.Spec.builder(
                                AP, "aauth:Agent+task1+y@portal.uma.lab", agentJwk, issuerKeys.getPrivate(), "issuer-1")
                        .parentToken(child, fetch)
                        .build()))
                .hasMessageContaining("top-level");
        assertCode(() -> Delegation.verifySubagentToken(child, parent, fetch), "invalid_subagent_token");
    }

    // --- Person tokens -------------------------------------------------------------------

    private PersonTokens.Spec.Builder personSpec() {
        return PersonTokens.Spec.builder(PS, RESOURCE, "person-1", agentJwk, issuerKeys.getPrivate(), "issuer-1");
    }

    @Test
    void personTokenIssuanceAndLifetimeCaps() {
        String token = PersonTokens.create(personSpec()
                .agentExp(now + 500)
                .upstreamExp(now + 300)
                .mission(MISSION, now + 200)
                .tenant("tenant-1")
                .build());

        Map<String, Object> p = PersonTokens.verify(
                token,
                fetch,
                TokenVerifier.Options.forType(null).withAudience(RESOURCE).withRequestSigningJwk(agentJwk));
        assertThat(((Number) p.get("exp")).longValue()).isEqualTo(now + 200);
        assertThat(p)
                .containsEntry("mission_s256", MISSION)
                .containsEntry("tenant", "tenant-1")
                .containsEntry("dwk", "aauth-person.json")
                .doesNotContainKeys("agent", "act", "scope", "account");
    }

    @Test
    void personTokenIssuanceRules() {
        assertThatThrownBy(() -> personSpec().build()).hasMessageContaining("agent expiration");
        assertCode(() -> PersonTokens.create(personSpec().agentExp(now - 1).build()), "expired_jwt");
        assertThatThrownBy(() -> PersonTokens.create(new PersonTokens.Spec(
                        PS,
                        RESOURCE,
                        "person-1",
                        agentJwk,
                        issuerKeys.getPrivate(),
                        "issuer-1",
                        now + 600,
                        null,
                        MISSION,
                        null,
                        null,
                        null)))
                .hasMessageContaining("Mission expiration");
        assertCode(
                () -> PersonTokens.create(personSpec()
                        .agentExp(now + 600)
                        .mission("short", now + 600)
                        .build()),
                "invalid_jwt");
        assertCode(
                () -> PersonTokens.create(PersonTokens.Spec.builder(
                                PS, "http://gateway.uma.lab", "person-1", agentJwk, issuerKeys.getPrivate(), "issuer-1")
                        .agentExp(now + 600)
                        .build()),
                "invalid_jwt");
    }

    // --- Auth tokens ---------------------------------------------------------------------

    private AuthTokens.Spec.Builder authSpec() {
        return AuthTokens.Spec.builder(PS, RESOURCE, "person-1", PS)
                .cnfJwk(agentJwk)
                .signingKey(issuerKeys.getPrivate(), "issuer-1")
                .dwk(AuthTokens.DWK_PERSON);
    }

    @Test
    void authCreationCapsDependenciesAndEmitsNewClaims() {
        String token = AuthTokens.create(authSpec()
                .bounds(now + 500, now + 400)
                .upstreamExp(now + 300)
                .tenant("tenant-1")
                .account("alice@gateway.uma.lab")
                .scope("data.read")
                .build());

        Map<String, Object> p = TokenVerifier.verify(token, fetch, authOptions());
        assertThat(((Number) p.get("exp")).longValue()).isEqualTo(now + 300);
        assertThat(p)
                .containsEntry("tenant", "tenant-1")
                .containsEntry("account", "alice@gateway.uma.lab")
                .containsEntry("dwk", "aauth-person.json")
                .doesNotContainKeys("agent", "act");
    }

    @Test
    void authTokenIssuanceRules() {
        assertThatThrownBy(() -> authSpec().build()).hasMessageContaining("expirations");
        assertThatThrownBy(() ->
                        AuthTokens.create(AuthTokens.Spec.builder(PS, RESOURCE, "person-1", "https://other-ps.uma.lab")
                                .cnfJwk(agentJwk)
                                .signingKey(issuerKeys.getPrivate(), "issuer-1")
                                .dwk(AuthTokens.DWK_PERSON)
                                .bounds(now + 600, now + 600)
                                .build()))
                .hasMessageContaining("issuer/dwk");
        assertThatThrownBy(() -> AuthTokens.create(authSpec()
                        .bounds(now + 600, now + 600)
                        .missionS256(MISSION)
                        .build()))
                .hasMessageContaining("mission expiration");
        assertThatThrownBy(() -> AuthTokens.create(AuthTokens.Spec.builder(PS, RESOURCE, "", PS)
                        .cnfJwk(agentJwk)
                        .signingKey(issuerKeys.getPrivate(), "issuer-1")
                        .bounds(now + 600, now + 600)
                        .build()))
                .hasMessageContaining("directed sub");
        assertCode(() -> AuthTokens.create(authSpec().bounds(now + 600, now - 1).build()), "expired_jwt");

        // An AS-issued token (dwk aauth-access.json) may name another PS.
        String asIssued =
                AuthTokens.create(AuthTokens.Spec.builder("https://alice-as.uma.lab", RESOURCE, "person-1", PS)
                        .cnfJwk(agentJwk)
                        .signingKey(issuerKeys.getPrivate(), "issuer-1")
                        .bounds(now + 600, now + 600)
                        .missionS256(MISSION)
                        .build());
        assertThat(TokenVerifier.verify(asIssued, fetch, authOptions())).containsEntry("dwk", "aauth-access.json");
    }

    // --- Resource tokens -----------------------------------------------------------------

    private String presentedPerson(Consumer<Map<String, Object>> change) throws Exception {
        Map<String, Object> p = claims(PersonTokens.TYPE);
        p.put("mission_s256", MISSION);
        p.put("tenant", "tenant-1");
        change.accept(p);
        return mint(p, PersonTokens.TYPE);
    }

    private String resourceToken(String presented) {
        return ResourceTokens.create(
                ResourceTokens.Spec.builder(RESOURCE, PS, agentJkt, issuerKeys.getPrivate(), "issuer-1")
                        .presentedToken(presented, fetch)
                        .scope("read")
                        .build());
    }

    private ResourceTokens.VerifyOptions resourceOptions(String presented) {
        return new ResourceTokens.VerifyOptions(presented, PS, null, PS, agentJkt, null, s -> true);
    }

    @Test
    void resourceTokenBindsVerifiedPresentedToken() throws Exception {
        String presented = presentedPerson(p -> {});
        Map<String, Object> rt = ResourceTokens.verify(resourceToken(presented), fetch, resourceOptions(presented));

        assertThat(rt)
                .containsEntry("presented_jti", "token-1")
                .containsEntry("ps", PS)
                .containsEntry("sub", "person-1")
                .containsEntry("mission_s256", MISSION)
                .containsEntry("tenant", "tenant-1")
                .containsEntry("agent_jkt", agentJkt)
                .doesNotContainKey("agent");
        assertThat(((Number) rt.get("exp")).longValue() - ((Number) rt.get("iat")).longValue())
                .isLessThanOrEqualTo(300);

        String other = presentedPerson(p -> p.put("jti", "other"));
        assertCode(
                () -> ResourceTokens.verify(resourceToken(presented), fetch, resourceOptions(other)),
                "invalid_resource_token");
    }

    @Test
    void resourceTokenIssuanceRejectsBadPresentedTokens() throws Exception {
        String presented = presentedPerson(p -> {});
        String agentToken = mint(claims(AgentTokens.TYPE), AgentTokens.TYPE);
        assertCode(() -> resourceToken(agentToken), "invalid_presented_token");
        assertCode(
                () -> resourceToken(presentedPerson(p -> p.put("aud", "https://other.uma.lab"))),
                "invalid_presented_token");
        assertCode(
                () -> resourceToken(presentedPerson(p -> {
                    p.put("iat", now - 600);
                    p.put("exp", now - 1);
                })),
                "expired_presented_token");
        assertCode(
                () -> ResourceTokens.create(
                        ResourceTokens.Spec.builder(RESOURCE, PS, agentJkt, issuerKeys.getPrivate(), "issuer-1")
                                .presentedToken(presented, fetch)
                                .revocationChecker((iss, jti) -> true)
                                .build()),
                "revoked_presented_token");
        assertCode(
                () -> ResourceTokens.create(
                        ResourceTokens.Spec.builder(RESOURCE, PS, "wrong-jkt", issuerKeys.getPrivate(), "issuer-1")
                                .presentedToken(presented, fetch)
                                .build()),
                "invalid_presented_token");
    }

    static Stream<Arguments> strippedOrSubstituted() {
        return Stream.of(
                Arguments.of("ps", "https://other-ps.uma.lab"),
                Arguments.of("sub", "person-2"),
                Arguments.of("presented_jti", "other"),
                Arguments.of("mission_s256", null),
                Arguments.of("mission_s256", "n".repeat(43)),
                Arguments.of("tenant", null),
                Arguments.of("tenant", "tenant-2"));
    }

    @ParameterizedTest
    @MethodSource("strippedOrSubstituted")
    void resourceTokenContextCannotBeStrippedOrSubstituted(String claim, Object value) throws Exception {
        String presented = presentedPerson(p -> {});
        Map<String, Object> payload = new LinkedHashMap<>(
                castMap(AuthTokens.parseTokenClaims(resourceToken(presented)).get("payload")));
        if (value == null) {
            payload.remove(claim);
        } else {
            payload.put(claim, value);
        }
        String bad = mint(payload, ResourceTokens.TYPE);

        assertThatThrownBy(() -> ResourceTokens.verify(bad, fetch, resourceOptions(presented)))
                .isInstanceOf(TokenException.class);
    }

    @Test
    void psMustConfirmTheMissionIsActive() throws Exception {
        String presented = presentedPerson(p -> {});
        String rt = resourceToken(presented);
        assertCode(
                () -> ResourceTokens.verify(
                        rt, fetch, new ResourceTokens.VerifyOptions(presented, PS, null, PS, null, null, null)),
                "mission_terminated");
        assertCode(
                () -> ResourceTokens.verify(
                        rt, fetch, new ResourceTokens.VerifyOptions(presented, PS, null, PS, null, null, s -> false)),
                "mission_terminated");
        // An AS (aud != ps) does not judge mission state.
        assertThat(ResourceTokens.verify(
                        rt, fetch, new ResourceTokens.VerifyOptions(presented, PS, null, null, null, null, null)))
                .containsEntry("mission_s256", MISSION);
    }

    @Test
    void resourceTokenErrorsAreRecoded() throws Exception {
        String presented = presentedPerson(p -> {});
        String rt = resourceToken(presented);
        assertCode(
                () -> ResourceTokens.verify(
                        rt,
                        fetch,
                        new ResourceTokens.VerifyOptions(
                                presented, PS, null, PS, null, (iss, jti) -> RESOURCE.equals(iss), s -> true)),
                "revoked_resource_token");
        assertCode(
                () -> ResourceTokens.verify(
                        rt,
                        fetch,
                        new ResourceTokens.VerifyOptions(
                                presented, "https://alice-as.uma.lab", null, null, null, null, null)),
                "invalid_resource_token");
        assertCode(
                () -> ResourceTokens.verify(
                        rt,
                        fetch,
                        new ResourceTokens.VerifyOptions(presented, PS, null, PS, "other-jkt", null, s -> true)),
                "invalid_resource_token");
    }

    @Test
    void upstreamTokenMustNameThePsAndTheIntermediary() throws Exception {
        String intermediary = AgentTokens.create(AgentTokens.Spec.builder(
                        RESOURCE, "aauth:resource@gateway.uma.lab", agentJwk, issuerKeys.getPrivate(), "issuer-1")
                .build());
        String upstream = presentedPerson(p -> {});

        assertThat(Delegation.verifyUpstreamToken(upstream, fetch, Delegation.UpstreamOptions.of(intermediary, PS)))
                .containsEntry("sub", "person-1");
        assertCode(
                () -> Delegation.verifyUpstreamToken(
                        upstream, fetch, Delegation.UpstreamOptions.of(intermediary, "https://other-ps.uma.lab")),
                "invalid_upstream_token");
        String agent = mint(claims(AgentTokens.TYPE), AgentTokens.TYPE);
        assertCode(
                () -> Delegation.verifyUpstreamToken(agent, fetch, Delegation.UpstreamOptions.of(intermediary, PS)),
                "invalid_upstream_token");
        String expired = presentedPerson(p -> {
            p.put("iat", now - 600);
            p.put("exp", now - 1);
        });
        assertCode(
                () -> Delegation.verifyUpstreamToken(expired, fetch, Delegation.UpstreamOptions.of(intermediary, PS)),
                "expired_upstream_token");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Object value) {
        return (Map<String, Object>) value;
    }
}
