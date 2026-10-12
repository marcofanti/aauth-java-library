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
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import org.jspecify.annotations.Nullable;

/**
 * Agent ↔ person server token requests (draft-11): person tokens from
 * {@code person_token_endpoint} (§7.1) and auth tokens from {@code auth_token_endpoint} in
 * exchange for a resource token plus the {@code presented_token} (§7.2).
 */
public final class TokenExchange {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final String PERSON_TOKEN_TYPE = "aa-person+jwt";
    private static final List<String> BODY_COMPONENTS = List.of("content-type", "content-digest");

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
     * @param presentedToken the token the agent presented to the resource that issued the resource
     *     token — the person token on the first challenge, or the auth token on a step-up
     *     (draft-11 §7.2.1, REQUIRED); {@code null} omits it for pre-draft-11 person servers
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
            @Nullable String presentedToken,
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
            private @Nullable String presentedToken;
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

            /** The token presented to the resource (person token, or auth token on step-up). */
            public Builder presentedToken(@Nullable String presentedToken) {
                this.presentedToken = presentedToken;
                return this;
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
                        presentedToken,
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
     *   <li>discover the PS {@code auth_token_endpoint} (legacy {@code token_endpoint}) via
     *       {@code /.well-known/aauth-person.json} (falls back to {@code {aud}/token})
     *   <li>POST the resource token and {@code presented_token}, signed with the {@code jwt}
     *       scheme (agent token) with the body covered
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
            // Draft-11 renamed the PS endpoint to auth_token_endpoint; fall back to the
            // legacy token_endpoint so pre-draft-11 person servers still resolve.
            Object discovered = metadata.get("auth_token_endpoint");
            if (discovered == null || discovered.toString().isEmpty()) {
                discovered = metadata.get("token_endpoint");
            }
            if (discovered != null && !discovered.toString().isEmpty()) {
                tokenEndpoint = discovered.toString();
            }
        } catch (RuntimeException e) {
            // Metadata fetch failed — keep the fallback endpoint.
        }

        // Step 3: sign and POST the resource token. Draft-11 §7.2.1 requires presented_token
        // alongside it; omitted for pre-draft-11 person servers when the caller has none.
        Map<String, Object> bodyMap = new LinkedHashMap<>();
        bodyMap.put("resource_token", exchange.resourceToken());
        if (exchange.presentedToken() != null) {
            bodyMap.put("presented_token", exchange.presentedToken());
        }
        byte[] body = toJsonBytes(bodyMap);
        Caller caller = new Caller(exchange.httpClient(), exchange.keyPair(), exchange.agentJwt());
        HttpJson response = postJson(caller, tokenEndpoint, body);

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
            Poller.PollingResult result = pollDeferred(
                    caller,
                    response,
                    exchange.maxPolls(),
                    exchange.onInteraction(),
                    exchange.onClarification(),
                    exchange.sleeper());
            if (result.authToken() == null) {
                throw new TokenException("PS polling succeeded but response missing 'auth_token'", "aa-auth+jwt");
            }
            return result.authToken();
        }

        throw new TokenException(
                "PS auth_token_endpoint returned HTTP " + response.status() + ": " + response.rawBodyPreview(),
                "aa-auth+jwt");
    }

    // --- Person tokens (draft-11 §7.1) ---------------------------------------------------------

    /**
     * Parameters for {@link #requestPersonToken(PersonTokenRequest)}.
     *
     * @param personServer the agent's person server identifier (its {@code ps})
     * @param resource the resource identifier the person token is for (REQUIRED)
     * @param keyPair the agent's signing key pair
     * @param agentJwt the agent token ({@code aa-agent+jwt}), presented under the {@code jwt} scheme
     * @param missionS256 optional mission binding to carry into the person token
     * @param capabilities optional agent capabilities; without them a PS that must reach the person
     *     answers {@code user_unreachable} (AG-10)
     * @param httpClient HTTP client; {@code null} uses the HTTP/1.1-pinned default
     * @param onInteraction callback for a deferred response requiring interaction
     * @param maxPolls maximum polling attempts on a 202 (default 60)
     * @param sleeper poll sleep implementation (injectable for tests)
     */
    public record PersonTokenRequest(
            String personServer,
            String resource,
            KeyPair keyPair,
            String agentJwt,
            @Nullable String missionS256,
            @Nullable List<String> capabilities,
            @Nullable HttpClient httpClient,
            @Nullable BiConsumer<String, String> onInteraction,
            int maxPolls,
            Poller.@Nullable Sleeper sleeper) {

        public PersonTokenRequest {
            if (personServer == null || resource == null || keyPair == null || agentJwt == null) {
                throw new IllegalArgumentException("personServer, resource, keyPair and agentJwt are required");
            }
            maxPolls = maxPolls <= 0 ? 60 : maxPolls;
        }
    }

    /** A person token and its lifetime as returned by the PS. */
    public record PersonTokenResponse(
            String personToken, @Nullable Long expiresIn) {}

    /**
     * Requests a person token ({@code aa-person+jwt}) for one resource from the PS's
     * {@code person_token_endpoint} (draft-11 §7.1, AG-10):
     *
     * <ol>
     *   <li>discover {@code person_token_endpoint} via {@code /.well-known/aauth-person.json}
     *       (falls back to {@code {ps}/person-token})
     *   <li>POST {@code resource} (+ {@code mission_s256}, {@code capabilities}), signed with the
     *       agent token under the {@code jwt} scheme
     *   <li>on 200 return {@code {person_token, expires_in}}; on 202 poll until terminal
     * </ol>
     *
     * @throws TokenException on PS errors, a malformed response, or exhausted polling
     */
    public static PersonTokenResponse requestPersonToken(PersonTokenRequest request) {
        HttpClient requestedClient = request.httpClient();
        HttpClient httpClient = requestedClient != null ? requestedClient : Exchange.defaultHttpClient();
        Caller caller = new Caller(httpClient, request.keyPair(), request.agentJwt());

        String psBase = stripTrailingSlash(request.personServer());
        String endpoint = discoverEndpoint(psBase, httpClient, "person_token_endpoint", psBase + "/person-token");

        Map<String, Object> bodyMap = new LinkedHashMap<>();
        bodyMap.put("resource", request.resource());
        String missionS256 = request.missionS256();
        if (missionS256 != null) {
            bodyMap.put("mission_s256", missionS256);
        }
        List<String> capabilities = request.capabilities();
        if (capabilities != null && !capabilities.isEmpty()) {
            bodyMap.put("capabilities", capabilities);
        }
        HttpJson response = postJson(caller, endpoint, toJsonBytes(bodyMap));

        Map<String, Object> result;
        if (response.status() == 200) {
            result = response.body();
        } else if (response.status() == 202) {
            result = pollDeferred(
                            caller, response, request.maxPolls(), request.onInteraction(), null, request.sleeper())
                    .responseBody();
        } else {
            throw new TokenException(
                    "PS person_token_endpoint returned HTTP " + response.status() + ": " + response.rawBodyPreview(),
                    PERSON_TOKEN_TYPE);
        }
        return personTokenResponse(result);
    }

    private static PersonTokenResponse personTokenResponse(Map<String, Object> body) {
        Object personToken = body.get("person_token");
        if (personToken == null) {
            throw new TokenException(
                    "PS response missing 'person_token'; response keys: " + body.keySet(), PERSON_TOKEN_TYPE);
        }
        Long expiresIn = body.get("expires_in") instanceof Number n ? n.longValue() : null;
        return new PersonTokenResponse(personToken.toString(), expiresIn);
    }

    private static String discoverEndpoint(String psBase, HttpClient httpClient, String field, String fallback) {
        try {
            Map<String, Object> metadata = Metadata.fetchPersonServer(psBase, new DefaultHttpClient(httpClient));
            Object discovered = metadata.get(field);
            if (discovered != null && !discovered.toString().isEmpty()) {
                return discovered.toString();
            }
        } catch (RuntimeException e) {
            // Metadata fetch failed — use the fallback endpoint.
        }
        return fallback;
    }

    private static String stripTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    /**
     * Polls a 202 deferred response's {@code Location} until terminal, signing each request as the
     * agent. Throws when polling ends unsuccessfully.
     */
    private static Poller.PollingResult pollDeferred(
            Caller caller,
            HttpJson accepted,
            int maxPolls,
            @Nullable BiConsumer<String, String> onInteraction,
            @Nullable BiFunction<String, String, String> onClarification,
            Poller.@Nullable Sleeper sleeper) {
        String location = accepted.header("location");
        if (location == null) {
            throw new TokenException("PS returned 202 but no Location header — cannot poll", "aa-auth+jwt");
        }

        Poller.Request.Builder pollRequest = Poller.Request.builder(location, url -> {
                    Map<String, String> headers = signedHeaders(caller, "GET", url, Map.of());
                    HttpJson polled = send(caller, request(url).GET(), headers);
                    return new Poller.PollResponse(polled.status(), polled.body(), polled.headers());
                })
                .maxPolls(maxPolls)
                .onInteraction(onInteraction)
                .sleeper(sleeper);
        if (onClarification != null) {
            pollRequest.onClarification(onClarification).signedPost((url, postBodyMap) -> {
                HttpJson posted = postJson(caller, url, toJsonBytes(postBodyMap));
                return new Poller.PollResponse(posted.status(), posted.body(), posted.headers());
            });
        }

        Poller.PollingResult result = Poller.poll(pollRequest.build());
        if (!result.success()) {
            throw new TokenException(
                    "PS deferred request failed: " + result.error() + " — " + result.errorDescription(), "aa-auth+jwt");
        }
        return result;
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

    /** Minimal signing/transport context shared by the resource-token and person-token flows. */
    private record Caller(HttpClient httpClient, KeyPair keyPair, String agentJwt) {}

    /** Signs a body-less request (polling GETs) as the agent under the {@code jwt} scheme. */
    private static Map<String, String> signedHeaders(
            Caller caller, String method, String url, Map<String, String> headers) {
        return RequestSigner.sign(SignRequest.builder(method, url)
                .headers(headers)
                .keyPair(caller.keyPair())
                .scheme(new SignatureScheme.Jwt(caller.agentJwt()))
                .build());
    }

    /**
     * Signs a request carrying a body. Draft-11 §11.3.3 (AG-50) requires {@code content-digest}
     * and {@code content-type} coverage on every PS/AS request with a body; the signer computes
     * and returns the {@code Content-Digest} header.
     */
    private static Map<String, String> signedBodyHeaders(
            Caller caller, String url, Map<String, String> headers, byte[] body) {
        return RequestSigner.sign(SignRequest.builder("POST", url)
                .headers(headers)
                .body(body)
                .additionalComponents(BODY_COMPONENTS)
                .keyPair(caller.keyPair())
                .scheme(new SignatureScheme.Jwt(caller.agentJwt()))
                .build());
    }

    private static HttpJson postJson(Caller caller, String url, byte[] body) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.putAll(signedBodyHeaders(caller, url, headers, body));
        return send(caller, request(url).POST(HttpRequest.BodyPublishers.ofByteArray(body)), headers);
    }

    private static HttpRequest.Builder request(String url) {
        return HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(30));
    }

    private static HttpJson send(Caller caller, HttpRequest.Builder builder, Map<String, String> headers) {
        for (Map.Entry<String, String> header : headers.entrySet()) {
            builder.header(header.getKey(), header.getValue());
        }
        HttpResponse<String> response;
        try {
            response = caller.httpClient().send(builder.build(), HttpResponse.BodyHandlers.ofString());
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
