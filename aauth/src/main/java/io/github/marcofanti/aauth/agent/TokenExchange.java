package io.github.marcofanti.aauth.agent;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.headers.AAuthHeaders;
import io.github.marcofanti.aauth.keys.DefaultHttpClient;
import io.github.marcofanti.aauth.metadata.Metadata;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.RequestSigner;
import io.github.marcofanti.aauth.signing.SignRequest;
import io.github.marcofanti.aauth.signing.SignatureScheme;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import org.jspecify.annotations.Nullable;

/** Three-party token exchange with the person server (spec §4.1.3). */
public final class TokenExchange {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    private TokenExchange() {}

    /**
     * Extracts the {@code resource_token} from a 401 AAuth challenge response's headers.
     * Returns {@code null} when no challenge header carries one.
     */
    public static @Nullable String extractResourceToken(Map<String, String> headers) {
        String raw = AAuthHeaders.getChallengeHeaderValue(headers);
        if (raw.isEmpty()) {
            return null;
        }
        try {
            return AAuthHeaders.parseAAuthHeader(raw).resourceToken();
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * Parameters for {@link #exchangeResourceToken(Exchange)}.
     *
     * @param resourceToken the resource token from the 401 challenge
     * @param keyPair the agent's signing key pair
     * @param agentJwt the agent token ({@code aa-agent+jwt}) for the Signature-Key header
     * @param httpClient HTTP client; {@code null} uses a default with a 30s timeout pinned to
     *     HTTP/1.1 (the JDK's h2c upgrade breaks h11-based person servers such as
     *     uvicorn/FastAPI). Caller-injected clients are used as-is.
     * @param onInteraction callback invoked with (interactionUrl, code) when the PS requires
     *     human interaction
     * @param onClarification callback invoked with (pendingUrl, question); returns the answer
     * @param maxPolls maximum polling attempts (default 60)
     * @param sleeper poll sleep implementation (injectable for tests)
     */
    public record Exchange(
            String resourceToken,
            KeyPair keyPair,
            String agentJwt,
            HttpClient httpClient,
            @Nullable BiConsumer<String, String> onInteraction,
            @Nullable BiFunction<String, String, String> onClarification,
            int maxPolls,
            Poller.@Nullable Sleeper sleeper) {

        public Exchange {
            if (resourceToken == null || keyPair == null || agentJwt == null) {
                throw new IllegalArgumentException("resourceToken, keyPair and agentJwt are required");
            }
            httpClient = httpClient == null ? defaultHttpClient() : httpClient;
            maxPolls = maxPolls <= 0 ? 60 : maxPolls;
        }

        private static HttpClient defaultHttpClient() {
            return HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .connectTimeout(Duration.ofSeconds(30))
                    .build();
        }

        public static Builder builder(String resourceToken, KeyPair keyPair, String agentJwt) {
            return new Builder(resourceToken, keyPair, agentJwt);
        }

        /** Builder for {@link Exchange}. */
        public static final class Builder {
            private final String resourceToken;
            private final KeyPair keyPair;
            private final String agentJwt;
            private @Nullable HttpClient httpClient;
            private @Nullable BiConsumer<String, String> onInteraction;
            private @Nullable BiFunction<String, String, String> onClarification;
            private int maxPolls = 60;
            private Poller.@Nullable Sleeper sleeper;

            private Builder(String resourceToken, KeyPair keyPair, String agentJwt) {
                this.resourceToken = resourceToken;
                this.keyPair = keyPair;
                this.agentJwt = agentJwt;
            }

            public Builder httpClient(@Nullable HttpClient httpClient) {
                this.httpClient = httpClient;
                return this;
            }

            public Builder onInteraction(@Nullable BiConsumer<String, String> onInteraction) {
                this.onInteraction = onInteraction;
                return this;
            }

            public Builder onClarification(@Nullable BiFunction<String, String, String> onClarification) {
                this.onClarification = onClarification;
                return this;
            }

            public Builder maxPolls(int maxPolls) {
                this.maxPolls = maxPolls;
                return this;
            }

            public Builder sleeper(Poller.@Nullable Sleeper sleeper) {
                this.sleeper = sleeper;
                return this;
            }

            public Exchange build() {
                return new Exchange(
                        resourceToken,
                        keyPair,
                        agentJwt,
                        httpClient == null ? defaultHttpClient() : httpClient,
                        onInteraction,
                        onClarification,
                        maxPolls,
                        sleeper);
            }
        }
    }

    /**
     * Exchanges a resource token for an auth token via the person server:
     *
     * <ol>
     *   <li>decode the resource token's {@code aud} claim to locate the PS
     *   <li>discover the PS {@code token_endpoint} via {@code /.well-known/aauth-person.json}
     *       (falls back to {@code {aud}/token})
     *   <li>POST the resource token, signed with the {@code jwt} scheme (agent token)
     *   <li>on 200 return the auth token; on 202 poll the Location URL until terminal
     * </ol>
     *
     * @return the auth token ({@code aa-auth+jwt}) issued by the PS
     * @throws TokenException on malformed tokens, non-recoverable PS errors, or exhausted polling
     */
    public static String exchangeResourceToken(Exchange exchange) {
        // Step 1: locate the PS via the resource token's aud claim.
        Jwts.Decoded resourceToken;
        try {
            resourceToken = Jwts.parse(exchange.resourceToken());
        } catch (IllegalArgumentException e) {
            throw new TokenException(
                    "Cannot decode resource_token JWT: " + e.getMessage(), "aa-resource+jwt", null, null, e);
        }
        String aud = resourceToken.claim("aud");
        if (aud == null) {
            throw new TokenException("resource_token missing 'aud' claim — cannot locate PS", "aa-resource+jwt");
        }

        // Step 2: discover the token endpoint, defaulting to {aud}/token.
        String psBase = aud.endsWith("/") ? aud.substring(0, aud.length() - 1) : aud;
        String tokenEndpoint = psBase + "/token";
        try {
            Map<String, Object> metadata =
                    Metadata.fetchPersonServer(psBase, new DefaultHttpClient(exchange.httpClient()));
            Object discovered = metadata.get("token_endpoint");
            if (discovered != null && !discovered.toString().isEmpty()) {
                tokenEndpoint = discovered.toString();
            }
        } catch (RuntimeException e) {
            // Metadata fetch failed — keep the fallback endpoint.
        }

        // Step 3: sign and POST the resource token.
        byte[] body = toJsonBytes(Map.of("resource_token", exchange.resourceToken()));
        HttpJson response = postJson(exchange, tokenEndpoint, body);

        // Step 4a: immediate success.
        if (response.status() == 200) {
            Object authToken = response.body().get("auth_token");
            if (authToken == null) {
                throw new TokenException(
                        "PS response missing 'auth_token'; response keys: "
                                + response.body().keySet(),
                        "aa-auth+jwt");
            }
            return authToken.toString();
        }

        // Step 4b: deferred — poll the Location URL.
        if (response.status() == 202) {
            String location = response.header("location");
            if (location == null) {
                throw new TokenException("PS returned 202 but no Location header — cannot poll", "aa-auth+jwt");
            }

            Poller.Request.Builder pollRequest = Poller.Request.builder(location, url -> {
                        Map<String, String> headers = signedHeaders(exchange, "GET", url, Map.of());
                        HttpJson polled = send(exchange, request(url).GET(), headers);
                        return new Poller.PollResponse(polled.status(), polled.body(), polled.headers());
                    })
                    .maxPolls(exchange.maxPolls())
                    .onInteraction(exchange.onInteraction())
                    .sleeper(exchange.sleeper());
            if (exchange.onClarification() != null) {
                pollRequest.onClarification(exchange.onClarification()).signedPost((url, postBodyMap) -> {
                    byte[] postBody = toJsonBytes(postBodyMap);
                    Map<String, String> headers = new LinkedHashMap<>(Map.of("Content-Type", "application/json"));
                    headers.putAll(signedHeaders(exchange, "POST", url, headers));
                    HttpJson posted = send(
                            exchange, request(url).POST(HttpRequest.BodyPublishers.ofByteArray(postBody)), headers);
                    return new Poller.PollResponse(posted.status(), posted.body(), posted.headers());
                });
            }

            Poller.PollingResult result = Poller.poll(pollRequest.build());
            if (!result.success()) {
                throw new TokenException(
                        "PS deferred exchange failed: " + result.error() + " — " + result.errorDescription(),
                        "aa-auth+jwt");
            }
            if (result.authToken() == null) {
                throw new TokenException("PS polling succeeded but response missing 'auth_token'", "aa-auth+jwt");
            }
            return result.authToken();
        }

        throw new TokenException(
                "PS token_endpoint returned HTTP " + response.status() + ": " + response.rawBodyPreview(),
                "aa-auth+jwt");
    }

    // --- HTTP helpers --------------------------------------------------------------------------

    private record HttpJson(int status, Map<String, Object> body, Map<String, String> headers, String raw) {
        @Nullable
        String header(String name) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(name)) {
                    return entry.getValue();
                }
            }
            return null;
        }

        String rawBodyPreview() {
            return raw.length() > 500 ? raw.substring(0, 500) : raw;
        }
    }

    private static Map<String, String> signedHeaders(
            Exchange exchange, String method, String url, Map<String, String> headers) {
        // The Python reference signs these requests without body coverage.
        return RequestSigner.sign(SignRequest.builder(method, url)
                .headers(headers)
                .keyPair(exchange.keyPair())
                .scheme(new SignatureScheme.Jwt(exchange.agentJwt()))
                .build());
    }

    private static HttpJson postJson(Exchange exchange, String url, byte[] body) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.putAll(signedHeaders(exchange, "POST", url, headers));
        return send(exchange, request(url).POST(HttpRequest.BodyPublishers.ofByteArray(body)), headers);
    }

    private static HttpRequest.Builder request(String url) {
        return HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(30));
    }

    private static HttpJson send(Exchange exchange, HttpRequest.Builder builder, Map<String, String> headers) {
        for (Map.Entry<String, String> header : headers.entrySet()) {
            builder.header(header.getKey(), header.getValue());
        }
        HttpResponse<String> response;
        try {
            response = exchange.httpClient().send(builder.build(), HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new TokenException(
                    "PS token_endpoint request failed: " + e.getMessage(), "aa-auth+jwt", null, null, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TokenException("Interrupted during PS token exchange", "aa-auth+jwt", null, null, e);
        }

        Map<String, Object> body = Map.of();
        String raw = response.body() == null ? "" : response.body();
        if (!raw.isEmpty()) {
            try {
                body = MAPPER.readValue(raw, MAP_TYPE);
            } catch (IOException e) {
                body = Map.of();
            }
        }
        Map<String, String> flatHeaders = new LinkedHashMap<>();
        response.headers().map().forEach((name, values) -> {
            if (!values.isEmpty()) {
                flatHeaders.put(name, values.get(0));
            }
        });
        return new HttpJson(response.statusCode(), body, flatHeaders, raw);
    }

    private static byte[] toJsonBytes(Map<String, Object> value) {
        try {
            return MAPPER.writeValueAsString(value).getBytes(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new TokenException(
                    "Failed to serialize request body: " + e.getMessage(), "aa-auth+jwt", null, null, e);
        }
    }
}
