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
        base = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    private String resourceToken() {
        Map<String, Object> header = new LinkedHashMap<>(Map.of("typ", "aa-resource+jwt", "alg", "EdDSA"));
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", "https://resource.example");
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

    @Test
    void resourceTokenWithoutAudIsRejected() {
        String tokenWithoutAud =
                Jwts.signEdDsa(Map.of("alg", "EdDSA"), Map.of("iss", "https://resource.example"), psKeys.getPrivate());

        assertThatThrownBy(() -> TokenExchange.exchangeResourceToken(
                        TokenExchange.Exchange.builder(tokenWithoutAud, agentKeys, "agent.token.jwt")
                                .build()))
                .isInstanceOf(TokenException.class)
                .hasMessageContaining("aud");
    }
}
