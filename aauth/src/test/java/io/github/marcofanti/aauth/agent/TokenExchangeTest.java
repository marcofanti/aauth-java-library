package io.github.marcofanti.aauth.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Token exchange against a fake person server on the JDK HttpServer. */
class TokenExchangeTest {

    private HttpServer server;
    private String base;
    private final KeyPair agentKeys = KeyPairs.generateEd25519();
    private final KeyPair psKeys = KeyPairs.generateEd25519();

    @BeforeEach
    void startServer() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.start();
        base = "http://" + io.github.marcofanti.aauth.TestHosts.loopbackHost("ps.uma.lab") + ":"
                + server.getAddress().getPort();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    private String resourceToken() {
        Map<String, Object> header = new LinkedHashMap<>(Map.of("typ", "aa-resource+jwt", "alg", "EdDSA"));
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", "https://gateway.uma.lab");
        payload.put("aud", base);
        return Jwts.signEdDsa(header, payload, psKeys.getPrivate());
    }

    private static void respondJson(HttpExchange exchange, int status, String json, Map<String, String> headers)
            throws IOException {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        headers.forEach((k, v) -> exchange.getResponseHeaders().set(k, v));
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private void addMetadataEndpoint() {
        server.createContext(
                "/.well-known/aauth-person.json",
                exchange -> respondJson(
                        exchange,
                        200,
                        "{\"issuer\": \"" + base + "\", \"token_endpoint\": \"" + base + "/ps-token\","
                                + " \"jwks_uri\": \"" + base + "/jwks.json\"}",
                        Map.of()));
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

    @Test
    void immediateSuccessReturnsAuthToken() {
        addMetadataEndpoint();
        server.createContext("/ps-token", exchange -> {
            assertThat(exchange.getRequestHeaders().getFirst("Signature-Key")).contains("jwt=");
            respondJson(exchange, 200, "{\"auth_token\": \"issued.auth.token\"}", Map.of());
        });

        String authToken = TokenExchange.exchangeResourceToken(
                TokenExchange.Exchange.builder(resourceToken(), agentKeys, "agent.token.jwt")
                        .build());

        assertThat(authToken).isEqualTo("issued.auth.token");
    }

    @Test
    void fallsBackToDefaultTokenEndpointWithoutMetadata() {
        server.createContext(
                "/token", exchange -> respondJson(exchange, 200, "{\"auth_token\": \"fallback.token\"}", Map.of()));

        String authToken = TokenExchange.exchangeResourceToken(
                TokenExchange.Exchange.builder(resourceToken(), agentKeys, "agent.token.jwt")
                        .build());

        assertThat(authToken).isEqualTo("fallback.token");
    }

    @Test
    void deferredExchangePollsUntilTokenIssued() {
        addMetadataEndpoint();
        AtomicInteger polls = new AtomicInteger();
        server.createContext(
                "/ps-token",
                exchange -> respondJson(
                        exchange,
                        202,
                        "{\"status\": \"pending\", \"location\": \"" + base + "/pending/1\"}",
                        Map.of("Location", base + "/pending/1", "Retry-After", "0")));
        server.createContext("/pending/1", exchange -> {
            if (polls.incrementAndGet() < 3) {
                respondJson(exchange, 202, "{\"status\": \"pending\"}", Map.of("Retry-After", "0"));
            } else {
                respondJson(exchange, 200, "{\"auth_token\": \"deferred.token\"}", Map.of());
            }
        });

        String authToken = TokenExchange.exchangeResourceToken(
                TokenExchange.Exchange.builder(resourceToken(), agentKeys, "agent.token.jwt")
                        .sleeper(seconds -> {})
                        .build());

        assertThat(authToken).isEqualTo("deferred.token");
        assertThat(polls.get()).isEqualTo(3);
    }

    @Test
    void deniedDeferredExchangeThrows() {
        addMetadataEndpoint();
        server.createContext(
                "/ps-token",
                exchange -> respondJson(
                        exchange,
                        202,
                        "{\"status\": \"pending\"}",
                        Map.of("Location", base + "/pending/2", "Retry-After", "0")));
        server.createContext("/pending/2", exchange -> respondJson(exchange, 403, "{\"error\": \"denied\"}", Map.of()));

        assertThatThrownBy(() -> TokenExchange.exchangeResourceToken(
                        TokenExchange.Exchange.builder(resourceToken(), agentKeys, "agent.token.jwt")
                                .sleeper(seconds -> {})
                                .build()))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("denied");
    }

    @Test
    void hardErrorFromTokenEndpointThrows() {
        addMetadataEndpoint();
        server.createContext(
                "/ps-token",
                exchange -> respondJson(exchange, 400, "{\"error\": \"invalid_resource_token\"}", Map.of()));

        assertThatThrownBy(() -> TokenExchange.exchangeResourceToken(
                        TokenExchange.Exchange.builder(resourceToken(), agentKeys, "agent.token.jwt")
                                .build()))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("HTTP 400");
    }

    @Test
    void malformedResourceTokenIsRejected() {
        assertThatThrownBy(() -> TokenExchange.exchangeResourceToken(
                        TokenExchange.Exchange.builder("not-a-jwt", agentKeys, "agent.token.jwt")
                                .build()))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("decode");
    }

    // --- draft-11: presented_token + person tokens ---

    private static final com.fasterxml.jackson.databind.ObjectMapper MAPPER =
            new com.fasterxml.jackson.databind.ObjectMapper();

    private static Map<String, Object> readJsonBody(HttpExchange exchange) throws IOException {
        byte[] bytes = exchange.getRequestBody().readAllBytes();
        return MAPPER.readValue(bytes, new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
    }

    private void addDraft11MetadataEndpoint() {
        server.createContext(
                "/.well-known/aauth-person.json",
                exchange -> respondJson(
                        exchange,
                        200,
                        "{\"issuer\": \"" + base + "\", \"person_token_endpoint\": \"" + base + "/ps-person\","
                                + " \"auth_token_endpoint\": \"" + base + "/ps-auth\","
                                + " \"jwks_uri\": \"" + base + "/jwks.json\"}",
                        Map.of()));
    }

    @Test
    void presentedTokenIsSentWithResourceToken() {
        addDraft11MetadataEndpoint();
        Map<String, Object> received = new java.util.concurrent.ConcurrentHashMap<>();
        server.createContext("/ps-auth", exchange -> {
            received.putAll(readJsonBody(exchange));
            respondJson(exchange, 200, "{\"auth_token\": \"issued.auth.token\"}", Map.of());
        });
        String resourceToken = resourceToken();

        String authToken = TokenExchange.exchangeResourceToken(
                TokenExchange.Exchange.builder(resourceToken, agentKeys, "agent.token.jwt")
                        .presentedToken("person.token.jwt")
                        .build());

        assertThat(authToken).isEqualTo("issued.auth.token");
        assertThat(received)
                .containsEntry("resource_token", resourceToken)
                .containsEntry("presented_token", "person.token.jwt");
    }

    @Test
    void psRequestBodyIsCoveredBySignature() {
        // Draft-11 §11.3.3 (AG-50): content-digest and content-type are covered on PS requests.
        addDraft11MetadataEndpoint();
        Map<String, String> seen = new java.util.concurrent.ConcurrentHashMap<>();
        server.createContext("/ps-person", exchange -> {
            byte[] body = exchange.getRequestBody().readAllBytes();
            seen.put("signature-input", exchange.getRequestHeaders().getFirst("Signature-Input"));
            seen.put("content-digest", exchange.getRequestHeaders().getFirst("Content-Digest"));
            seen.put(
                    "expected-digest", io.github.marcofanti.aauth.signing.SignatureBase.contentDigest(body, "sha-256"));
            respondJson(exchange, 200, "{\"person_token\": \"person.jwt\"}", Map.of());
        });

        TokenExchange.requestPersonToken(personTokenRequest(null, null));

        assertThat(seen.get("signature-input")).contains("\"content-type\"").contains("\"content-digest\"");
        assertThat(seen.get("content-digest")).isEqualTo(seen.get("expected-digest"));
    }

    @Test
    void presentedTokenIsOmittedWhenAbsent() {
        addMetadataEndpoint();
        Map<String, Object> received = new java.util.concurrent.ConcurrentHashMap<>();
        server.createContext("/ps-token", exchange -> {
            received.putAll(readJsonBody(exchange));
            respondJson(exchange, 200, "{\"auth_token\": \"legacy.token\"}", Map.of());
        });

        TokenExchange.exchangeResourceToken(
                TokenExchange.Exchange.builder(resourceToken(), agentKeys, "agent.token.jwt")
                        .build());

        assertThat(received).containsKey("resource_token").doesNotContainKey("presented_token");
    }

    private TokenExchange.PersonTokenRequest personTokenRequest(String missionS256, java.util.List<String> caps) {
        return new TokenExchange.PersonTokenRequest(
                base,
                "https://gateway.uma.lab",
                agentKeys,
                "agent.token.jwt",
                missionS256,
                caps,
                null,
                null,
                0,
                seconds -> {});
    }

    @Test
    void personTokenRequestDiscoversEndpointAndReturnsToken() {
        addDraft11MetadataEndpoint();
        Map<String, Object> received = new java.util.concurrent.ConcurrentHashMap<>();
        server.createContext("/ps-person", exchange -> {
            assertThat(exchange.getRequestHeaders().getFirst("Signature-Key")).contains("jwt=");
            received.putAll(readJsonBody(exchange));
            respondJson(exchange, 200, "{\"person_token\": \"person.jwt\", \"expires_in\": 3600}", Map.of());
        });

        TokenExchange.PersonTokenResponse response =
                TokenExchange.requestPersonToken(personTokenRequest("abc123", java.util.List.of("interaction")));

        assertThat(response.personToken()).isEqualTo("person.jwt");
        assertThat(response.expiresIn()).isEqualTo(3600L);
        assertThat(received)
                .containsEntry("resource", "https://gateway.uma.lab")
                .containsEntry("mission_s256", "abc123")
                .containsEntry("capabilities", java.util.List.of("interaction"));
    }

    @Test
    void personTokenRequestFallsBackWithoutMetadataAndOmitsOptionalFields() {
        Map<String, Object> received = new java.util.concurrent.ConcurrentHashMap<>();
        server.createContext("/person-token", exchange -> {
            received.putAll(readJsonBody(exchange));
            respondJson(exchange, 200, "{\"person_token\": \"fallback.person\"}", Map.of());
        });

        TokenExchange.PersonTokenResponse response = TokenExchange.requestPersonToken(personTokenRequest(null, null));

        assertThat(response.personToken()).isEqualTo("fallback.person");
        assertThat(response.expiresIn()).isNull();
        assertThat(received).containsOnlyKeys("resource");
    }

    @Test
    void deferredPersonTokenRequestPollsUntilIssued() {
        addDraft11MetadataEndpoint();
        AtomicInteger polls = new AtomicInteger();
        server.createContext(
                "/ps-person",
                exchange -> respondJson(
                        exchange,
                        202,
                        "{\"status\": \"pending\"}",
                        Map.of("Location", base + "/pending/p", "Retry-After", "0")));
        server.createContext("/pending/p", exchange -> {
            if (polls.incrementAndGet() < 2) {
                respondJson(exchange, 202, "{\"status\": \"pending\"}", Map.of("Retry-After", "0"));
            } else {
                respondJson(exchange, 200, "{\"person_token\": \"deferred.person\"}", Map.of());
            }
        });

        TokenExchange.PersonTokenResponse response = TokenExchange.requestPersonToken(personTokenRequest(null, null));

        assertThat(response.personToken()).isEqualTo("deferred.person");
        assertThat(polls.get()).isEqualTo(2);
    }

    @Test
    void personTokenRequestErrorsThrow() {
        addDraft11MetadataEndpoint();
        server.createContext(
                "/ps-person", exchange -> respondJson(exchange, 400, "{\"error\": \"invalid_request\"}", Map.of()));

        assertThatThrownBy(() -> TokenExchange.requestPersonToken(personTokenRequest(null, null)))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("HTTP 400");
    }

    @Test
    void personTokenResponseWithoutTokenThrows() {
        server.createContext("/person-token", exchange -> respondJson(exchange, 200, "{\"expires_in\": 60}", Map.of()));

        assertThatThrownBy(() -> TokenExchange.requestPersonToken(personTokenRequest(null, null)))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("person_token");
    }

    @Test
    void personTokenRequestRequiresCoreFields() {
        assertThatThrownBy(() -> new TokenExchange.PersonTokenRequest(
                        base, null, agentKeys, "agent.token.jwt", null, null, null, null, 0, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("resource");
    }

    @Test
    void resourceTokenWithoutAudIsRejected() {
        String tokenWithoutAud =
                Jwts.signEdDsa(Map.of("alg", "EdDSA"), Map.of("iss", "https://gateway.uma.lab"), psKeys.getPrivate());

        assertThatThrownBy(() -> TokenExchange.exchangeResourceToken(
                        TokenExchange.Exchange.builder(tokenWithoutAud, agentKeys, "agent.token.jwt")
                                .build()))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("aud");
    }
}
