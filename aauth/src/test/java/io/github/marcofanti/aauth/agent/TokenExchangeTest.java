package io.github.marcofanti.aauth.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.marcofanti.aauth.MetadataException;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.http.AAuthResponse;
import io.github.marcofanti.aauth.http.HttpTransport;
import io.github.marcofanti.aauth.metadata.Metadata;
import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.signing.SignatureKeyHeader;
import io.github.marcofanti.aauth.signing.SignatureVerifier;
import io.github.marcofanti.aauth.signing.VerifyRequest;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import io.github.marcofanti.aauth.tokens.AgentTokens;
import io.github.marcofanti.aauth.tokens.AuthTokens;
import io.github.marcofanti.aauth.tokens.PersonTokens;
import io.github.marcofanti.aauth.tokens.ResourceTokens;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/** Agent-side person-token, auth-token and deferred flows (mirrors the reference test_draft11_exchange). */
class TokenExchangeTest {

    private static final String RESOURCE = "https://gateway.uma.lab";
    private static final String PS = "https://ps.uma.lab";
    private static final String AS = "https://alice-as.uma.lab";
    private static final String AP = "https://portal.uma.lab";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    private final long now = Instant.now().getEpochSecond();
    private final KeyPair agentKeys = KeyPairs.generateEd25519();
    private final KeyPair issuerKeys = KeyPairs.generateEd25519();
    private final Map<String, Object> agentJwk = Jwk.publicKeyToJwk(agentKeys.getPublic(), null);
    private final JwksFetcher fetch =
            (id, dwk, kid) -> Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(issuerKeys.getPublic(), "issuer-1")));

    /** One request the transport saw. */
    private record Call(String method, String url, Map<String, String> headers, byte[] body) {}

    private final List<Call> calls = new CopyOnWriteArrayList<>();

    private HttpTransport transport(Function<Call, AAuthResponse> handler) {
        return (method, url, headers, body) -> {
            Call call = new Call(method, url, headers, body == null ? new byte[0] : body);
            calls.add(call);
            return handler.apply(call);
        };
    }

    private static AAuthResponse json(int status, Object body, Map<String, String> headers) {
        try {
            Map<String, String> all = new LinkedHashMap<>(headers);
            all.put("Content-Type", "application/json");
            return new AAuthResponse(status, all, MAPPER.writeValueAsBytes(body));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static AAuthResponse json(int status, Object body) {
        return json(status, body, Map.of());
    }

    private static Map<String, Object> metadata() {
        return Metadata.personServer(PS, PS + "/identity", PS + "/authorize", PS + "/jwks")
                .build();
    }

    private TokenExchange.Agent agent(String agentToken, HttpTransport transport) {
        return TokenExchange.Agent.builder(agentKeys, agentToken, fetch)
                .transport(transport)
                .sleeper(seconds -> {})
                .build();
    }

    /** The PS checks every POST: jwt-scheme signature with the body covered. */
    private void validatePost(Call call) {
        assertThat(call.method()).isEqualTo("POST");
        Map<String, String> h = call.headers();
        assertThat(SignatureVerifier.verify(VerifyRequest.builder("POST", call.url())
                        .headers(h)
                        .body(call.body())
                        .signatureHeaders(h.get("Signature-Input"), h.get("Signature"), h.get("Signature-Key"))
                        .jwksFetcher(fetch)
                        .requiredComponents(List.of(
                                "@method", "@authority", "@path", "signature-key", "content-digest", "content-type"))
                        .build()))
                .isTrue();
    }

    private static Map<String, Object> body(Call call) {
        try {
            return MAPPER.readValue(call.body(), MAP_TYPE);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    // --- Flow fixtures -------------------------------------------------------------------

    private record Flow(String agent, String person, String resource, String auth) {}

    private Flow flow(String audience) {
        String agent = AgentTokens.create(AgentTokens.Spec.builder(
                        AP, "aauth:Agent@portal.uma.lab", agentJwk, issuerKeys.getPrivate(), "issuer-1")
                .exp(now + 600)
                .ps(PS)
                .build());
        String person = PersonTokens.create(
                PersonTokens.Spec.builder(PS, RESOURCE, "person-1", agentJwk, issuerKeys.getPrivate(), "issuer-1")
                        .agentExp(now + 600)
                        .build());
        String resource = ResourceTokens.create(ResourceTokens.Spec.builder(
                        RESOURCE, audience, Jwk.thumbprint(agentJwk), issuerKeys.getPrivate(), "issuer-1")
                .presentedToken(person, fetch)
                .scope("read")
                .loginHint("user@example.com")
                .build());
        String auth = AuthTokens.create(AuthTokens.Spec.builder(audience, RESOURCE, "person-1", PS)
                .cnfJwk(agentJwk)
                .signingKey(issuerKeys.getPrivate(), "issuer-1")
                .bounds(now + 600, now + 600)
                .dwk(PS.equals(audience) ? AuthTokens.DWK_PERSON : AuthTokens.DWK_ACCESS)
                .build());
        return new Flow(agent, person, resource, auth);
    }

    private String mint(Map<String, Object> payload, String typ) throws Exception {
        Map<String, Object> header = new LinkedHashMap<>(Map.of("alg", "Ed25519", "kid", "issuer-1", "typ", typ));
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        String data = enc.encodeToString(MAPPER.writeValueAsBytes(header)) + "."
                + enc.encodeToString(MAPPER.writeValueAsBytes(payload));
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(issuerKeys.getPrivate());
        signer.update(data.getBytes(StandardCharsets.US_ASCII));
        return data + "." + enc.encodeToString(signer.sign());
    }

    private Map<String, Object> authClaims() {
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
        return p;
    }

    // --- Auth-token exchange ---------------------------------------------------------------

    static Stream<Arguments> audiencesAndDeferral() {
        return Stream.of(
                Arguments.of(PS, false), Arguments.of(PS, true), Arguments.of(AS, false), Arguments.of(AS, true));
    }

    @ParameterizedTest
    @MethodSource("audiencesAndDeferral")
    void verifiedExchangeUsesOwnPsAndNewEndpoint(String audience, boolean deferred) {
        Flow flow = flow(audience);
        List<List<String>> interactions = new ArrayList<>();
        HttpTransport transport = transport(call -> {
            if (call.url().equals(PS + "/.well-known/aauth-person.json")) {
                return json(200, metadata());
            }
            if (call.url().equals(PS + "/authorize")) {
                validatePost(call);
                Map<String, Object> data = body(call);
                assertThat(data)
                        .containsEntry("resource_token", flow.resource())
                        .containsEntry("presented_token", flow.person())
                        .containsEntry("login_hint", "user@example.com");
                if (deferred) {
                    return json(
                            202,
                            Map.of("status", "pending"),
                            Map.of(
                                    "Location",
                                    "/pending/1",
                                    "Retry-After",
                                    "0",
                                    "AAuth-Requirement",
                                    "requirement=interaction; url=\"https://ps.uma.lab/interaction\"; code=\"ABCD1234\""));
                }
                return json(200, Map.of("auth_token", flow.auth()));
            }
            assertThat(call.url()).isEqualTo(PS + "/pending/1");
            assertThat(call.method()).isEqualTo("GET");
            return json(200, Map.of("auth_token", flow.auth()));
        });
        TokenExchange.Agent agent = TokenExchange.Agent.builder(agentKeys, flow.agent(), fetch)
                .transport(transport)
                .onInteraction((url, code) -> interactions.add(List.of(url, code)))
                .sleeper(seconds -> {})
                .build();

        String result = TokenExchange.exchangeResourceToken(
                agent, TokenExchange.AuthTokenRequest.of(flow.resource(), flow.person(), RESOURCE, PS));

        assertThat(result).isEqualTo(flow.auth());
        assertThat(calls).allSatisfy(call -> assertThat(call.url()).startsWith(PS + "/"));
        assertThat(interactions).hasSize(deferred ? 1 : 0);
    }

    static Stream<Arguments> wrongReturnedContexts() {
        return Stream.of(
                Arguments.of("aud", "https://other.uma.lab"),
                Arguments.of("iss", "https://wrong.uma.lab"),
                Arguments.of("sub", "other-person"),
                Arguments.of("ps", "https://wrong.uma.lab"),
                Arguments.of("exp", Instant.now().getEpochSecond() + 3599));
    }

    @ParameterizedTest
    @MethodSource("wrongReturnedContexts")
    void exchangeRejectsWrongReturnedContext(String claim, Object value) throws Exception {
        Flow flow = flow(PS);
        Map<String, Object> claims = authClaims();
        claims.put(claim, value);
        String bad = mint(claims, AuthTokens.TYPE);
        HttpTransport transport = transport(
                call -> "GET".equals(call.method()) ? json(200, metadata()) : json(200, Map.of("auth_token", bad)));

        assertThatThrownBy(() -> TokenExchange.exchangeResourceToken(
                        agent(flow.agent(), transport),
                        TokenExchange.AuthTokenRequest.of(flow.resource(), flow.person(), RESOURCE, PS)))
                .isInstanceOf(TokenException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "https://evil.uma.lab/pending", "https://ps.uma.lab:8443/pending"})
    void exchangeRejectsMissingOrForeignLocation(String location) {
        Flow flow = flow(PS);
        HttpTransport transport = transport(call -> "GET".equals(call.method())
                ? json(200, metadata())
                : json(202, Map.of("status", "pending"), location.isEmpty() ? Map.of() : Map.of("Location", location)));

        assertThatThrownBy(() -> TokenExchange.exchangeResourceToken(
                        agent(flow.agent(), transport),
                        TokenExchange.AuthTokenRequest.of(flow.resource(), flow.person(), RESOURCE, PS)))
                .isInstanceOf(TokenException.class);
        assertThat(calls).hasSize(2);
    }

    @ParameterizedTest
    @MethodSource("badMetadata")
    void discoveryIdentityFailureNeverFallsBack(Map<String, Object> document) {
        Flow flow = flow(PS);
        HttpTransport transport = transport(call -> json(200, document));

        assertThatThrownBy(() -> TokenExchange.exchangeResourceToken(
                        agent(flow.agent(), transport),
                        TokenExchange.AuthTokenRequest.of(flow.resource(), flow.person(), RESOURCE, PS)))
                .isInstanceOf(MetadataException.class);
        assertThat(calls).hasSize(1);
    }

    static Stream<Map<String, Object>> badMetadata() {
        Map<String, Object> wrongIssuer = new LinkedHashMap<>(metadata());
        wrongIssuer.put("issuer", "https://wrong.uma.lab");
        Map<String, Object> missingEndpoint = new LinkedHashMap<>(metadata());
        missingEndpoint.remove("person_token_endpoint");
        Map<String, Object> httpEndpoint = new LinkedHashMap<>(metadata());
        httpEndpoint.put("auth_token_endpoint", "http://ps.uma.lab/authorize");
        return Stream.of(Map.of(), wrongIssuer, missingEndpoint, httpEndpoint);
    }

    @Test
    void invalidResourceChallengeRejectedBeforeNetwork() throws Exception {
        Flow flow = flow(PS);
        String[] parts = flow.resource().split("\\.");
        Map<String, Object> payload = MAPPER.readValue(Base64.getUrlDecoder().decode(parts[1]), MAP_TYPE);
        payload.put("aud", "https://evil.uma.lab");
        parts[1] = Base64.getUrlEncoder().withoutPadding().encodeToString(MAPPER.writeValueAsBytes(payload));
        HttpTransport transport = transport(call -> {
            throw new AssertionError("Unexpected network call");
        });

        assertThatThrownBy(() -> TokenExchange.exchangeResourceToken(
                        agent(flow.agent(), transport),
                        TokenExchange.AuthTokenRequest.of(String.join(".", parts), flow.person(), RESOURCE, PS)))
                .isInstanceOf(TokenException.class);
        assertThat(calls).isEmpty();
    }

    @Test
    void psRefusalCarriesItsErrorCode() {
        Flow flow = flow(PS);
        HttpTransport transport = transport(call -> "GET".equals(call.method())
                ? json(200, metadata())
                : json(400, Map.of("error", "expired_presented_token", "detail", "presented token expired")));

        assertThatThrownBy(() -> TokenExchange.exchangeResourceToken(
                        agent(flow.agent(), transport),
                        TokenExchange.AuthTokenRequest.of(flow.resource(), flow.person(), RESOURCE, PS)))
                .isInstanceOf(TokenException.class)
                .hasMessage("presented token expired")
                .extracting(e -> ((TokenException) e).errorCode())
                .isEqualTo("expired_presented_token");
    }

    @Test
    void psNonObjectErrorBodyIsReportedAsTokenError() {
        Flow flow = flow(PS);
        HttpTransport transport = transport(call -> json(400, List.of()));

        assertThatThrownBy(() -> TokenExchange.postPs(PS + "/auth", Map.of(), agent(flow.agent(), transport)))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("PS request failed")
                .extracting(e -> ((TokenException) e).errorCode())
                .isEqualTo("server_error");
        HttpTransport array = transport(call -> json(200, List.of()));
        assertThatThrownBy(() -> TokenExchange.postPs(PS + "/auth", Map.of(), agent(flow.agent(), array)))
                .hasMessageContaining("not a JSON object");
    }

    @Test
    void subAgentsCannotRequestDirectly() {
        // The parent is bound to another key; the sub-agent token is bound to the signing key.
        Map<String, Object> parentJwk =
                Jwk.publicKeyToJwk(KeyPairs.generateEd25519().getPublic(), null);
        String parent = AgentTokens.create(AgentTokens.Spec.builder(
                        AP, "aauth:Agent@portal.uma.lab", parentJwk, issuerKeys.getPrivate(), "issuer-1")
                .exp(now + 600)
                .build());
        String child = childAgentToken(agentJwk, parent);
        Flow flow = flow(PS);
        HttpTransport transport = transport(call -> {
            throw new AssertionError("Unexpected network call");
        });

        assertThatThrownBy(() -> TokenExchange.exchangeResourceToken(
                        agent(child, transport),
                        TokenExchange.AuthTokenRequest.of(flow.resource(), flow.person(), RESOURCE, PS)))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("cannot request authorization directly");
        assertThatThrownBy(
                        () -> TokenExchange.requestPersonToken(agent(child, transport), PS, RESOURCE, null, Map.of()))
                .hasMessageContaining("parent-mediated");
        assertThat(calls).isEmpty();
    }

    private String childAgentToken(Map<String, Object> childJwk, String parent) {
        return AgentTokens.create(AgentTokens.Spec.builder(
                        AP, "aauth:Agent+child@portal.uma.lab", childJwk, issuerKeys.getPrivate(), "issuer-1")
                .exp(now + 600)
                .parentToken(parent, fetch)
                .build());
    }

    @Test
    void parentMediatedExchangeBindsTheChildKey() {
        KeyPair childKeys = KeyPairs.generateEd25519();
        Map<String, Object> childJwk = Jwk.publicKeyToJwk(childKeys.getPublic(), null);
        String parent = flow(PS).agent();
        String child = childAgentToken(childJwk, parent);
        String person = PersonTokens.create(
                PersonTokens.Spec.builder(PS, RESOURCE, "person-1", childJwk, issuerKeys.getPrivate(), "issuer-1")
                        .agentExp(now + 600)
                        .build());
        String rt = ResourceTokens.create(
                ResourceTokens.Spec.builder(RESOURCE, PS, Jwk.thumbprint(childJwk), issuerKeys.getPrivate(), "issuer-1")
                        .presentedToken(person, fetch)
                        .build());
        String auth = AuthTokens.create(AuthTokens.Spec.builder(PS, RESOURCE, "person-1", PS)
                .cnfJwk(childJwk)
                .signingKey(issuerKeys.getPrivate(), "issuer-1")
                .bounds(now + 600, now + 600)
                .dwk(AuthTokens.DWK_PERSON)
                .build());
        HttpTransport transport = transport(call -> {
            if ("GET".equals(call.method())) {
                return json(200, metadata());
            }
            validatePost(call);
            assertThat(body(call)).containsEntry("subagent_token", child);
            return json(200, Map.of("auth_token", auth));
        });

        String result = TokenExchange.exchangeResourceToken(
                agent(parent, transport),
                new TokenExchange.AuthTokenRequest(rt, person, RESOURCE, PS, child, null, Map.of()));

        assertThat(result).isEqualTo(auth);
    }

    // --- Person tokens ---------------------------------------------------------------------

    @Test
    void personTokenAcquisition() {
        Flow flow = flow(PS);
        HttpTransport transport = transport(call -> {
            if ("GET".equals(call.method())) {
                return json(200, metadata());
            }
            validatePost(call);
            assertThat(call.url()).isEqualTo(PS + "/identity");
            assertThat(body(call))
                    .containsEntry("resource", RESOURCE)
                    .containsEntry("capabilities", List.of("interaction"));
            return json(200, Map.of("person_token", flow.person(), "expires_in", 600));
        });

        String token = TokenExchange.requestPersonToken(
                agent(flow.agent(), transport), PS, RESOURCE, null, Map.of("capabilities", List.of("interaction")));

        assertThat(token).isEqualTo(flow.person());
    }

    @Test
    void personTokenMustMatchTheRequestedMission() {
        Flow flow = flow(PS);
        HttpTransport transport = transport(call ->
                "GET".equals(call.method()) ? json(200, metadata()) : json(200, Map.of("person_token", flow.person())));

        assertThatThrownBy(() -> TokenExchange.requestPersonToken(
                        agent(flow.agent(), transport), PS, RESOURCE, null, Map.of("mission_s256", "m".repeat(43))))
                .hasMessageContaining("context or lifetime mismatch");
        HttpTransport missing = transport(
                call -> "GET".equals(call.method()) ? json(200, metadata()) : json(200, Map.of("expires_in", 600)));
        assertThatThrownBy(() ->
                        TokenExchange.requestPersonToken(agent(flow.agent(), missing), PS, RESOURCE, null, Map.of()))
                .hasMessageContaining("missing person_token");
    }

    // --- Deferred resource requests --------------------------------------------------------

    @Test
    void deferredResourceInvocationIsNotRepeated() {
        Flow flow = flow(PS);
        AAuthResponse initial = new AAuthResponse(
                202,
                Map.of(
                        "Location", "/pending/result",
                        "Retry-After", "0",
                        "AAuth-Requirement", "requirement=auth-token; resource-token=\"" + flow.resource() + "\""),
                "{\"status\":\"pending\"}".getBytes(StandardCharsets.UTF_8));
        HttpTransport transport = transport(call -> {
            if (call.url().equals(PS + "/.well-known/aauth-person.json")) {
                return json(200, metadata());
            }
            if (call.url().equals(PS + "/authorize")) {
                return json(200, Map.of("auth_token", flow.auth()));
            }
            assertThat(call.method()).isEqualTo("GET");
            assertThat(call.url()).isEqualTo(RESOURCE + "/pending/result");
            assertThat(SignatureKeyHeader.parse(call.headers().get("Signature-Key"))
                            .params())
                    .containsEntry("jwt", flow.auth());
            assertThat(call.body()).isEmpty();
            return new AAuthResponse(201, Map.of(), "invocation result".getBytes(StandardCharsets.UTF_8));
        });

        Poller.PollingResult result = TokenExchange.completeDeferredResourceRequest(
                agent(flow.agent(), transport),
                new TokenExchange.DeferredRequest(initial, RESOURCE + "/submit", flow.person(), RESOURCE, PS));

        assertThat(result.success()).isTrue();
        assertThat(result.statusCode()).isEqualTo(201);
        assertThat(result.response()).isNotNull();
        assertThat(new String(result.response().raw(), StandardCharsets.UTF_8)).isEqualTo("invocation result");
        assertThat(calls)
                .extracting(call -> call.method() + " " + call.url())
                .containsExactly(
                        "GET " + PS + "/.well-known/aauth-person.json",
                        "POST " + PS + "/authorize",
                        "GET " + RESOURCE + "/pending/result");
    }

    @Test
    void deferredRequestRequiresA202WithAResourceToken() {
        Flow flow = flow(PS);
        TokenExchange.Agent agent = agent(flow.agent(), transport(call -> json(200, Map.of())));
        AAuthResponse ok = new AAuthResponse(200, Map.of(), new byte[0]);
        AAuthResponse noToken = new AAuthResponse(202, Map.of("Location", "/p"), new byte[0]);

        assertThatThrownBy(() -> TokenExchange.completeDeferredResourceRequest(
                        agent, new TokenExchange.DeferredRequest(ok, RESOURCE + "/x", flow.person(), RESOURCE, PS)))
                .hasMessageContaining("Expected a deferred");
        assertThatThrownBy(() -> TokenExchange.completeDeferredResourceRequest(
                        agent,
                        new TokenExchange.DeferredRequest(noToken, RESOURCE + "/x", flow.person(), RESOURCE, PS)))
                .hasMessageContaining("missing resource token");
    }

    @Test
    void extractsResourceTokenFromChallengeHeaders() {
        assertThat(TokenExchange.extractResourceToken(
                        Map.of("AAuth-Requirement", "requirement=auth-token; resource-token=\"rt.jwt\"")))
                .isEqualTo("rt.jwt");
        assertThat(TokenExchange.extractResourceToken(Map.of())).isNull();
        assertThat(TokenExchange.extractResourceToken(Map.of("AAuth-Requirement", "garbage")))
                .isNull();
    }
}
