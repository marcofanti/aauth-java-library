package io.github.marcofanti.aauth.resource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.headers.AAuthHeaders;
import io.github.marcofanti.aauth.revocation.RevocationStore;
import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.signing.RequestSigner;
import io.github.marcofanti.aauth.signing.SignRequest;
import io.github.marcofanti.aauth.signing.SignatureBase;
import io.github.marcofanti.aauth.signing.SignatureHeader;
import io.github.marcofanti.aauth.signing.SignatureKeyHeader;
import io.github.marcofanti.aauth.signing.SignatureScheme;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import io.github.marcofanti.aauth.tokens.AgentTokens;
import io.github.marcofanti.aauth.tokens.AuthTokens;
import io.github.marcofanti.aauth.tokens.PersonTokens;
import io.github.marcofanti.aauth.tokens.ResourceTokens;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/** Draft-11 resource role: request verification and challenges (mirrors the reference test_draft11). */
class ResourceRoleTest {

    private static final String RESOURCE = "https://gateway.uma.lab";
    private static final String PS = "https://ps.uma.lab";
    private static final String AP = "https://portal.uma.lab";
    private static final String TARGET = RESOURCE + "/data";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final long now = Instant.now().getEpochSecond();
    private final KeyPair agentKeys = KeyPairs.generateEd25519();
    private final KeyPair issuerKeys = KeyPairs.generateEd25519();
    private final KeyPair resourceKeys = KeyPairs.generateEd25519();
    private final Map<String, Object> agentJwk = Jwk.publicKeyToJwk(agentKeys.getPublic(), null);
    private final Map<String, Object> issuerJwk = Jwk.publicKeyToJwk(issuerKeys.getPublic(), "issuer-1");
    private final JwksFetcher fetch = (id, dwk, kid) -> RESOURCE.equals(id)
            ? Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(resourceKeys.getPublic(), "r-key-1")))
            : Jwk.generateJwks(List.of(issuerJwk));

    private RequestVerifier verifier() {
        return RequestVerifier.builder(List.of("gateway.uma.lab"), fetch)
                .trustedAuthServers(Set.of(PS))
                .resourceId(RESOURCE)
                .build();
    }

    // --- Independent minting and signing (wire format, not the library's encoder) ----------

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
            p.put("sub", "aauth:Agent@portal.uma.lab");
            p.put("dwk", "aauth-agent.json");
            p.remove("aud");
        }
        if (PersonTokens.TYPE.equals(typ)) {
            p.remove("ps");
            p.remove("scope");
        }
        return p;
    }

    private Map<String, Object> claims() {
        return claims(AuthTokens.TYPE);
    }

    private String mint(Map<String, Object> payload, String typ, String alg) throws Exception {
        Map<String, Object> header = new LinkedHashMap<>(Map.of("alg", alg, "kid", "issuer-1", "typ", typ));
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

    private String mint(Map<String, Object> payload) throws Exception {
        return mint(payload, AuthTokens.TYPE);
    }

    /** Signs with the library signer under the jwt scheme. */
    private Map<String, String> signed(String token, Map<String, String> headers) {
        Map<String, String> all = new LinkedHashMap<>(headers);
        all.putAll(RequestSigner.sign(SignRequest.builder("GET", TARGET)
                .headers(headers)
                .keyPair(agentKeys)
                .scheme(new SignatureScheme.Jwt(token))
                .build()));
        return all;
    }

    private Map<String, String> signed(String token) {
        return signed(token, Map.of());
    }

    /** Builds a signature with exactly the given components and parameters. */
    private Map<String, String> signedRaw(String token, List<String> components, String params) throws Exception {
        String signatureKey = SignatureKeyHeader.build(new SignatureScheme.Jwt(token), "sig", agentKeys.getPublic());
        String base = SignatureBase.build(
                "GET", "gateway.uma.lab", "/data", null, Map.of(), null, signatureKey, components, params);
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(agentKeys.getPrivate());
        signer.update(base.getBytes(StandardCharsets.UTF_8));
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Signature-Key", signatureKey);
        headers.put("Signature-Input", "sig=" + params);
        headers.put("Signature", SignatureHeader.build(signer.sign(), "sig"));
        return headers;
    }

    private RequestVerifier.Result verifyAuth(Map<String, String> headers) {
        return verifier().verifyRequest("GET", TARGET, headers, null, RequestVerifier.Requirements.authToken());
    }

    // --- Request verification ------------------------------------------------------------

    @Test
    void currentAuthTokenAcceptedWithoutAgentOrAct() throws Exception {
        RequestVerifier.Result result = verifyAuth(signed(mint(claims())));

        assertThat(result.valid()).as(result.error()).isTrue();
        assertThat(result.tokenType()).isEqualTo(AuthTokens.TYPE);
        assertThat(result.userSub()).isEqualTo("person-1");
        assertThat(result.agentId()).isNull();
        assertThat(result.personServer()).isEqualTo(PS);
        assertThat(result.scopes()).containsExactly("read");
    }

    static Stream<Arguments> invalidAuthContexts() {
        return Stream.of(
                Arguments.of("aud", "https://other.uma.lab"),
                Arguments.of("iss", "https://untrusted.uma.lab"),
                Arguments.of("exp", null),
                Arguments.of("iat", null),
                Arguments.of("jti", null),
                Arguments.of("dwk", "aauth-agent.json"),
                Arguments.of("sub", null),
                Arguments.of("ps", null),
                Arguments.of("exp", true));
    }

    @ParameterizedTest
    @MethodSource("invalidAuthContexts")
    void resourceRejectsInvalidAuthContext(String claim, Object value) throws Exception {
        Map<String, Object> p = claims();
        if (value == null) {
            p.remove(claim);
        } else {
            p.put(claim, value);
        }
        assertThat(verifyAuth(signed(mint(p))).valid()).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"aa-person+jwt", "aa-agent+jwt", "unrelated+jwt"})
    void otherTokenTypesCannotAuthorize(String typ) throws Exception {
        assertThat(verifyAuth(signed(mint(claims(typ), typ))).valid()).isFalse();
    }

    static Stream<Arguments> badCoverage() {
        long now = Instant.now().getEpochSecond();
        List<String> full = List.of("@method", "@authority", "@path", "signature-key");
        String fullParams = "(\"@method\" \"@authority\" \"@path\" \"signature-key\")";
        return Stream.of(
                Arguments.of(List.of("@method"), "(\"@method\");created=" + now),
                Arguments.of(full, fullParams),
                Arguments.of(full, fullParams + ";created=1"),
                Arguments.of(full, fullParams + ";created=" + now + ";expires=1"));
    }

    @ParameterizedTest
    @MethodSource("badCoverage")
    void signatureRejectsMissingCoverageFreshnessAndExpiry(List<String> components, String params) throws Exception {
        assertThat(verifyAuth(signedRaw(mint(claims()), components, params)).valid())
                .isFalse();
    }

    @Test
    void digestCheckedAgainstActualBody() throws Exception {
        byte[] body = "{\"scope\":\"read\"}".getBytes(StandardCharsets.UTF_8);
        Map<String, String> headers = new LinkedHashMap<>(Map.of("Content-Type", "application/json"));
        headers.putAll(RequestSigner.sign(SignRequest.builder("GET", TARGET)
                .headers(headers)
                .body(body)
                .additionalComponents(List.of("content-digest", "content-type"))
                .keyPair(agentKeys)
                .scheme(new SignatureScheme.Jwt(mint(claims())))
                .build()));

        RequestVerifier verifier = verifier();
        assertThat(verifier.verifyRequest("GET", TARGET, headers, body, RequestVerifier.Requirements.authToken())
                        .valid())
                .isTrue();
        byte[] tampered = "{\"scope\":\"admin\"}".getBytes(StandardCharsets.UTF_8);
        assertThat(verifier.verifyRequest("GET", TARGET, headers, tampered, RequestVerifier.Requirements.authToken())
                        .valid())
                .isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"EdDSA", "HS256", "none"})
    void polymorphicAndSymmetricAlgorithmsRejected(String alg) throws Exception {
        assertThat(verifyAuth(signed(mint(claims(), AuthTokens.TYPE, alg))).valid())
                .isFalse();
    }

    @Test
    void confirmationAlgorithmRequiredAndBound() throws Exception {
        for (String alg : new String[] {null, "ES256"}) {
            Map<String, Object> jwk = new LinkedHashMap<>(agentJwk);
            if (alg == null) {
                jwk.remove("alg");
            } else {
                jwk.put("alg", alg);
            }
            Map<String, Object> p = claims();
            p.put("cnf", Map.of("jwk", jwk));
            assertThat(verifyAuth(signed(mint(p))).valid())
                    .as(String.valueOf(alg))
                    .isFalse();
        }
    }

    @Test
    void authTokenWithoutScopeIsStillAnAuthToken() throws Exception {
        Map<String, Object> p = claims();
        p.remove("scope");
        RequestVerifier.Result result = verifyAuth(signed(mint(p)));
        assertThat(result.valid()).isTrue();
        assertThat(result.scopes()).isEmpty();
    }

    @Test
    void requiredScopesAreEnforced() throws Exception {
        Map<String, String> headers = signed(mint(claims()));
        assertThat(verifier()
                        .verifyRequest("GET", TARGET, headers, null, RequestVerifier.Requirements.authToken("read"))
                        .valid())
                .isTrue();
        RequestVerifier.Result insufficient =
                verifier().verifyRequest("GET", TARGET, headers, null, RequestVerifier.Requirements.authToken("admin"));
        assertThat(insufficient.valid()).isFalse();
        assertThat(insufficient.errorCode()).isEqualTo("insufficient_scope");
    }

    @Test
    void personTokenIsNotAuthorizationEvenWithScope() throws Exception {
        Map<String, Object> p = claims(PersonTokens.TYPE);
        p.put("scope", "admin");
        String token = mint(p, PersonTokens.TYPE);
        assertThat(verifyAuth(signed(token)).valid()).isFalse();

        RequestVerifier.Result person = verifier()
                .verifyRequest("GET", TARGET, signed(token), null, RequestVerifier.Requirements.personToken());
        assertThat(person.valid()).isTrue();
        assertThat(person.userSub()).isEqualTo("person-1");
        assertThat(person.personServer()).isEqualTo(PS);
    }

    @Test
    void agentTokenIdentifiesTheAgent() throws Exception {
        Map<String, Object> p = claims(AgentTokens.TYPE);
        p.put("ps", PS);
        String token = mint(p, AgentTokens.TYPE);
        RequestVerifier.Result result =
                verifier().verifyRequest("GET", TARGET, signed(token), null, RequestVerifier.Requirements.identity());

        assertThat(result.valid()).isTrue();
        assertThat(result.agentId()).isEqualTo("aauth:Agent@portal.uma.lab");
        assertThat(result.userSub()).isNull();
        assertThat(result.personServer()).isEqualTo(PS);
        assertThat(verifyAuth(signed(token)).valid()).isFalse();
    }

    @Test
    void untrustedPersonTokenIssuerIsRejected() throws Exception {
        Map<String, Object> p = claims(PersonTokens.TYPE);
        p.put("iss", "https://rogue-ps.uma.lab");
        RequestVerifier.Result result = verifier()
                .verifyRequest(
                        "GET", TARGET, signed(mint(p, PersonTokens.TYPE)), null, RequestVerifier.Requirements.none());
        assertThat(result.valid()).isFalse();
        assertThat(result.error()).contains("Untrusted person token issuer");
    }

    @Test
    void sessionCredentialSignedAndBound() throws Exception {
        String token = mint(claims(AgentTokens.TYPE), AgentTokens.TYPE);
        Map<String, String> headers = signed(token, Map.of("Authorization", "AAuth session-value"));
        assertThat(headers.get("Signature-Input")).contains("\"authorization\"");
        RequestVerifier verifier = RequestVerifier.builder(List.of("gateway.uma.lab"), fetch)
                .resourceId(RESOURCE)
                .sessionTokenVerifier((session, jkt) -> "session-value".equals(session)
                        && Jwk.thumbprint(agentJwk).equals(jkt))
                .build();

        RequestVerifier.Result result =
                verifier.verifyRequest("GET", TARGET, headers, null, RequestVerifier.Requirements.sessionToken());
        assertThat(result.valid()).isTrue();
        assertThat(result.sessionToken()).isEqualTo("session-value");

        Map<String, String> different = new LinkedHashMap<>(headers);
        different.put("Authorization", "AAuth different");
        assertThat(verifier.verifyRequest("GET", TARGET, different, null, RequestVerifier.Requirements.sessionToken())
                        .valid())
                .isFalse();
    }

    @Test
    void unboundSessionFailsClosed() throws Exception {
        String token = mint(claims(AgentTokens.TYPE), AgentTokens.TYPE);
        Map<String, String> headers = signed(token, Map.of("Authorization", "AAuth session"));
        assertThat(verifier()
                        .verifyRequest("GET", TARGET, headers, null, RequestVerifier.Requirements.sessionToken())
                        .valid())
                .isFalse();
        assertThat(verifier()
                        .verifyRequest("GET", TARGET, signed(token), null, RequestVerifier.Requirements.sessionToken())
                        .error())
                .contains("Session token required");
    }

    @Test
    void emptyBodyAndExtraComponentCoverage() throws Exception {
        Map<String, String> headers =
                new LinkedHashMap<>(Map.of("X-Request-Id", "request-1", "Content-Type", "application/json"));
        headers.putAll(RequestSigner.sign(SignRequest.builder("GET", TARGET)
                .headers(headers)
                .body(new byte[0])
                .additionalComponents(List.of("content-digest", "content-type", "x-request-id"))
                .keyPair(agentKeys)
                .scheme(new SignatureScheme.Jwt(mint(claims())))
                .build()));
        RequestVerifier verifier = RequestVerifier.builder(List.of("gateway.uma.lab"), fetch)
                .trustedAuthServers(Set.of(PS))
                .additionalSignatureComponents(List.of("x-request-id"))
                .build();

        assertThat(verifier.verifyRequest("GET", TARGET, headers, new byte[0], RequestVerifier.Requirements.authToken())
                        .valid())
                .isTrue();
        headers.put("X-Request-Id", "changed");
        assertThat(verifier.verifyRequest("GET", TARGET, headers, new byte[0], RequestVerifier.Requirements.authToken())
                        .valid())
                .isFalse();
    }

    @Test
    void keyidConflictRejected() throws Exception {
        String params =
                "(\"@method\" \"@authority\" \"@path\" \"signature-key\");created=" + now + ";keyid=\"other-key\"";
        RequestVerifier.Result result = verifyAuth(
                signedRaw(mint(claims()), List.of("@method", "@authority", "@path", "signature-key"), params));
        assertThat(result.valid()).isFalse();
        assertThat(result.errorCode()).isEqualTo("invalid_key");
    }

    @Test
    void selectedJwksKeyDoesNotRequireUnrelatedAlgorithms() throws Exception {
        RequestVerifier verifier = RequestVerifier.builder(
                        List.of("gateway.uma.lab"),
                        (id, dwk, kid) -> Map.of(
                                "keys",
                                List.of(Map.of("kid", "future", "kty", "ML-DSA", "alg", "ML-DSA-65"), issuerJwk)))
                .trustedAuthServers(Set.of(PS))
                .build();

        assertThat(verifier.verifyRequest(
                                "GET", TARGET, signed(mint(claims())), null, RequestVerifier.Requirements.authToken())
                        .valid())
                .isTrue();
    }

    @Test
    void revokedJwtRejectedAfterSignatureVerification() throws Exception {
        RevocationStore store = new RevocationStore();
        store.record(PS, "token-1", now + 600);
        RequestVerifier verifier = RequestVerifier.builder(List.of("gateway.uma.lab"), fetch)
                .trustedAuthServers(Set.of(PS))
                .resourceId(RESOURCE)
                .revocationChecker(store)
                .build();

        RequestVerifier.Result result = verifier.verifyRequest(
                "GET", TARGET, signed(mint(claims())), null, RequestVerifier.Requirements.authToken());
        assertThat(result.valid()).isFalse();
        assertThat(result.errorCode()).isEqualTo("revoked_jwt");
    }

    @ParameterizedTest
    @ValueSource(strings = {"hwk", "jwks_uri"})
    void agentsMustUseTheJwtScheme(String scheme) {
        SignatureScheme signatureScheme = "hwk".equals(scheme)
                ? new SignatureScheme.Hwk()
                : new SignatureScheme.JwksUri(AP, "aauth-agent.json", "key-1");
        Map<String, String> headers = RequestSigner.sign(SignRequest.builder("GET", TARGET)
                .keyPair(agentKeys)
                .scheme(signatureScheme)
                .build());

        RequestVerifier.Result result =
                verifier().verifyRequest("GET", TARGET, headers, null, RequestVerifier.Requirements.none());
        assertThat(result.valid()).isFalse();
        assertThat(result.errorCode()).isEqualTo("unsupported_scheme");
    }

    @Test
    void nonCanonicalAuthorityMissingHeadersAndMissingFetcherAreRejected() throws Exception {
        assertThat(verifier()
                        .verifyRequest(
                                "GET",
                                "https://grafana.uma.lab/data",
                                signed(mint(claims())),
                                null,
                                RequestVerifier.Requirements.none())
                        .error())
                .contains("not canonical");
        RequestVerifier.Result missing =
                verifier().verifyRequest("GET", TARGET, Map.of(), null, RequestVerifier.Requirements.none());
        assertThat(missing.valid()).isFalse();
        assertThat(missing.errorCode()).isNotNull();
        RequestVerifier noFetcher =
                RequestVerifier.builder(List.of("gateway.uma.lab"), null).build();
        String agentToken = mint(claims(AgentTokens.TYPE), AgentTokens.TYPE);
        assertThat(noFetcher
                        .verifyRequest("GET", TARGET, signed(agentToken), null, RequestVerifier.Requirements.none())
                        .error())
                .contains("JWKS fetcher");
    }

    // --- Challenges and resource tokens --------------------------------------------------

    private String personToken() {
        return PersonTokens.create(
                PersonTokens.Spec.builder(PS, RESOURCE, "person-1", agentJwk, issuerKeys.getPrivate(), "issuer-1")
                        .agentExp(now + 600)
                        .build());
    }

    private ChallengeBuilder challengeBuilder() {
        return new ChallengeBuilder(RESOURCE, resourceKeys.getPrivate(), "r-key-1", PS, fetch);
    }

    @Test
    void fullFlowFromPersonTokenChallengeToVerifiedAuthToken() {
        // 1. The agent presented a person token; the resource answers with an embedded resource token.
        String presented = personToken();
        ChallengeBuilder.Challenge challenge = challengeBuilder()
                .buildChallenge(ChallengeBuilder.Spec.authToken(presented, agentKeys.getPublic(), "read"));
        assertThat(challenge.headerName()).isEqualTo(AAuthHeaders.HEADER_AAUTH_REQUIREMENT);
        String resourceToken =
                AAuthHeaders.parseAAuthHeader(challenge.headerValue()).resourceToken();
        assertThat(resourceToken).isNotNull();

        // 2. The PS verifies the resource token and its binding to the presented token.
        Map<String, Object> rt = ResourceTokens.verify(
                resourceToken,
                fetch,
                new ResourceTokens.VerifyOptions(presented, PS, RESOURCE, PS, Jwk.thumbprint(agentJwk), null, null));
        assertThat(rt).containsEntry("scope", "read").containsEntry("sub", "person-1");

        // 3. The PS issues an auth token; the agent signs the retry with it.
        String authToken = AuthTokens.create(AuthTokens.Spec.builder(PS, RESOURCE, "person-1", PS)
                .cnfJwk(agentJwk)
                .signingKey(issuerKeys.getPrivate(), "issuer-1")
                .bounds(now + 600, now + 600)
                .dwk(AuthTokens.DWK_PERSON)
                .scope("read")
                .build());

        RequestVerifier.Result result = verifyAuth(signed(authToken));
        assertThat(result.valid()).as(result.error()).isTrue();
        assertThat(result.userSub()).isEqualTo("person-1");
        assertThat(result.scopes()).containsExactly("read");
    }

    @Test
    void challengesAreAlwaysAAuthRequirements() {
        // Draft-11: agent-token by default; never a pseudonymous Accept-Signature fallback.
        ChallengeBuilder.Challenge agent = challengeBuilder().buildChallenge(ChallengeBuilder.Spec.agentToken());
        assertThat(agent.headerName()).isEqualTo(AAuthHeaders.HEADER_AAUTH_REQUIREMENT);
        assertThat(agent.headerValue()).isEqualTo("requirement=agent-token");
        assertThat(challengeBuilder()
                        .buildChallenge(ChallengeBuilder.Spec.personToken())
                        .headerValue())
                .isEqualTo("requirement=person-token");
    }

    @Test
    void authTokenChallengeWithoutPresentedTokenAsksForAPersonToken() {
        assertThat(challengeBuilder()
                        .buildChallenge(new ChallengeBuilder.Spec(false, true, null, null, "read", null))
                        .headerValue())
                .isEqualTo("requirement=person-token");
        assertThatThrownBy(() -> challengeBuilder()
                        .buildChallenge(new ChallengeBuilder.Spec(false, true, personToken(), null, null, null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("agentPublicKey");
    }

    @Test
    void issuerRequiresAVerifiedPresentedToken() {
        ResourceTokenIssuer issuer =
                new ResourceTokenIssuer(RESOURCE, resourceKeys.getPrivate(), "r-key-1", PS, fetch, null);
        String presented = personToken();

        String token = issuer.issueToken(presented, agentKeys.getPublic(), "write", null, b -> b.account("alice"));
        assertThat(ResourceTokens.verify(token, fetch, ResourceTokens.VerifyOptions.of(presented)))
                .containsEntry("scope", "write")
                .containsEntry("account", "alice");
        assertThatThrownBy(() ->
                        issuer.issueToken(presented, KeyPairs.generateEd25519().getPublic(), "write", null, null))
                .isInstanceOf(TokenException.class)
                .extracting(e -> ((TokenException) e).errorCode())
                .isEqualTo("invalid_presented_token");
    }
}
