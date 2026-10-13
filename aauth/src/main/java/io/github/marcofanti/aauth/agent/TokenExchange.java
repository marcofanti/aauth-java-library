package io.github.marcofanti.aauth.agent;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.marcofanti.aauth.Identifiers;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.headers.AAuthHeaders;
import io.github.marcofanti.aauth.http.AAuthResponse;
import io.github.marcofanti.aauth.http.HttpTransport;
import io.github.marcofanti.aauth.keys.JsonHttpClient;
import io.github.marcofanti.aauth.metadata.Metadata;
import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.signing.RequestSigner;
import io.github.marcofanti.aauth.signing.SignRequest;
import io.github.marcofanti.aauth.signing.SignatureScheme;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.tokens.AgentTokens;
import io.github.marcofanti.aauth.tokens.AuthTokens;
import io.github.marcofanti.aauth.tokens.Delegation;
import io.github.marcofanti.aauth.tokens.PersonTokens;
import io.github.marcofanti.aauth.tokens.ResourceTokens;
import io.github.marcofanti.aauth.tokens.TokenVerifier;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import org.jspecify.annotations.Nullable;

/**
 * Person-token acquisition, verified resource challenges and PS token exchange (draft-11 §7,
 * mirrors the reference {@code agent/token_exchange}).
 *
 * <p>Every token is verified before it is used or returned: the agent's own token against its
 * signing key, the resource token's binding to the presented token, and the person or auth token
 * the PS returns (issuer, audience, person, mission, tenant and lifetime). PS endpoints are
 * discovered only from {@code {ps}/.well-known/aauth-person.json}. Requests to the PS are signed
 * under the {@code jwt} scheme with {@code content-digest} and {@code content-type} covered.
 */
public final class TokenExchange {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final List<String> BODY_COMPONENTS = List.of("content-digest", "content-type");

    private TokenExchange() {}

    /**
     * Extracts the {@code resource-token} from a challenge response's headers, or {@code null}
     * when no challenge header carries one.
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
     * The agent's signing context.
     *
     * @param keyPair the agent's signing key pair
     * @param agentJwt the agent token, presented under the {@code jwt} scheme
     * @param jwksFetcher resolves token issuers' JWKS from {@code (iss, dwk, kid)}
     * @param transport sends HTTP requests
     * @param onInteraction invoked with (interaction URL, code) when the PS needs the person
     * @param onClarification invoked with (pending URL, question); returns the answer
     * @param maxPolls maximum polls plus clarification replies on a deferred response
     * @param sleeper poll sleep implementation (injectable for tests)
     */
    public record Agent(
            KeyPair keyPair,
            String agentJwt,
            JwksFetcher jwksFetcher,
            HttpTransport transport,
            @Nullable BiConsumer<String, String> onInteraction,
            @Nullable BiFunction<String, String, String> onClarification,
            int maxPolls,
            Poller.@Nullable Sleeper sleeper) {

        public static Builder builder(KeyPair keyPair, String agentJwt, JwksFetcher jwksFetcher) {
            return new Builder(keyPair, agentJwt, jwksFetcher);
        }

        /** Builder for {@link Agent}; the transport defaults to {@link HttpTransport#defaultTransport()}. */
        public static final class Builder {
            private final KeyPair keyPair;
            private final String agentJwt;
            private final JwksFetcher jwksFetcher;
            private @Nullable HttpTransport transport;
            private @Nullable BiConsumer<String, String> onInteraction;
            private @Nullable BiFunction<String, String, String> onClarification;
            private int maxPolls = 60;
            private Poller.@Nullable Sleeper sleeper;

            private Builder(KeyPair keyPair, String agentJwt, JwksFetcher jwksFetcher) {
                this.keyPair = keyPair;
                this.agentJwt = agentJwt;
                this.jwksFetcher = jwksFetcher;
            }

            public Builder transport(HttpTransport transport) {
                this.transport = transport;
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

            public Agent build() {
                return new Agent(
                        keyPair,
                        agentJwt,
                        jwksFetcher,
                        transport != null ? transport : HttpTransport.defaultTransport(),
                        onInteraction,
                        onClarification,
                        maxPolls,
                        sleeper);
            }
        }
    }

    // --- Person tokens (§7.1) ------------------------------------------------------------------

    /**
     * Requests a person token for {@code resourceId} from the agent's PS (AG-10).
     *
     * @param subagentToken a sub-agent's token, for parent-mediated issuance bound to its key, or
     *     {@code null}
     * @param options further request parameters, e.g. {@code mission_s256}, {@code capabilities},
     *     {@code login_hint}, {@code upstream_token} (whose mission is inherited)
     * @return the verified person token
     * @throws TokenException if a token fails verification, the PS refuses, or the returned token
     *     outlives the agent token or names another mission
     * @throws io.github.marcofanti.aauth.MetadataException if PS discovery fails
     */
    public static String requestPersonToken(
            Agent agent,
            String personServer,
            String resourceId,
            @Nullable String subagentToken,
            Map<String, Object> options) {
        Identifiers.validateServerIdentifier(personServer);
        Identifiers.validateServerIdentifier(resourceId);
        Map<String, Object> params = new LinkedHashMap<>(options);
        Map<String, Object> key = signingJwk(agent);
        Map<String, Object> agentClaims = verifyAgent(agent, key, "Sub-agent must use parent-mediated authorization");
        long limit = number(agentClaims.get("exp"));
        if (subagentToken != null) {
            Map<String, Object> child =
                    Delegation.verifySubagentToken(agent.agentJwt(), subagentToken, agent.jwksFetcher());
            key = confirmationJwk(child);
            limit = Math.min(limit, number(child.get("exp")));
            params.put("subagent_token", subagentToken);
        }
        Map<String, Object> upstream = null;
        if (params.get("upstream_token") instanceof String upstreamToken) {
            upstream = Delegation.verifyUpstreamToken(
                    upstreamToken, agent.jwksFetcher(), upstreamOptions(agent, personServer));
            if (upstream.get("mission_s256") != null) {
                params.put("mission_s256", upstream.get("mission_s256"));
            }
        }
        Map<String, Object> metadata = Metadata.fetchPersonServer(personServer, jsonClient(agent.transport()));
        params.put("resource", resourceId);
        Map<String, Object> data = postPs(String.valueOf(metadata.get("person_token_endpoint")), params, agent);
        if (!(data.get("person_token") instanceof String token) || token.isEmpty()) {
            throw new TokenException("PS response missing person_token", PersonTokens.TYPE);
        }
        Map<String, Object> claims = TokenVerifier.verify(
                token,
                agent.jwksFetcher(),
                new TokenVerifier.Options(PersonTokens.TYPE, personServer, resourceId, key, null));
        if (number(claims.get("exp")) > limit
                || !Objects.equals(claims.get("mission_s256"), params.get("mission_s256"))) {
            throw new TokenException("Person token context or lifetime mismatch", PersonTokens.TYPE);
        }
        if (upstream != null && number(claims.get("exp")) > number(upstream.get("exp"))) {
            throw new TokenException("Person token outlives upstream token", PersonTokens.TYPE);
        }
        return token;
    }

    // --- Auth tokens (§7.2) --------------------------------------------------------------------

    /**
     * An auth-token request: the resource's challenge and the context it was issued in.
     *
     * @param resourceToken the resource token from the challenge
     * @param presentedToken the person or auth token the agent presented to the resource
     * @param resourceId the resource identifier
     * @param personServer the agent's PS
     * @param subagentToken a sub-agent's token, for parent-mediated exchange, or {@code null}
     * @param upstreamToken the upstream token when chaining a call, or {@code null}
     * @param options further request parameters
     */
    public record AuthTokenRequest(
            String resourceToken,
            String presentedToken,
            String resourceId,
            String personServer,
            @Nullable String subagentToken,
            @Nullable String upstreamToken,
            Map<String, Object> options) {

        public AuthTokenRequest {
            options = Map.copyOf(options);
        }

        public static AuthTokenRequest of(
                String resourceToken, String presentedToken, String resourceId, String personServer) {
            return new AuthTokenRequest(resourceToken, presentedToken, resourceId, personServer, null, null, Map.of());
        }
    }

    /**
     * Exchanges a resource token for an auth token at the agent's PS {@code auth_token_endpoint}
     * (AG-20, AG-21), sending {@code presented_token} with it.
     *
     * @return the verified auth token
     * @throws TokenException if a token fails verification (the resource token is checked before
     *     any network call), the PS refuses, or the returned token does not match the challenge
     * @throws io.github.marcofanti.aauth.MetadataException if PS discovery fails
     */
    public static String exchangeResourceToken(Agent agent, AuthTokenRequest request) {
        Identifiers.validateServerIdentifier(request.personServer());
        Map<String, Object> key = signingJwk(agent);
        Map<String, Object> agentClaims = verifyAgent(agent, key, "Sub-agents cannot request authorization directly");
        List<Long> limits = new ArrayList<>(List.of(number(agentClaims.get("exp"))));
        String subagentToken = request.subagentToken();
        if (subagentToken != null) {
            Map<String, Object> child =
                    Delegation.verifySubagentToken(agent.agentJwt(), subagentToken, agent.jwksFetcher());
            key = confirmationJwk(child);
            limits.add(number(child.get("exp")));
        }
        Map<String, Object> upstream = null;
        String upstreamToken = request.upstreamToken();
        if (upstreamToken != null) {
            upstream = Delegation.verifyUpstreamToken(
                    upstreamToken, agent.jwksFetcher(), upstreamOptions(agent, request.personServer()));
        }
        Map<String, Object> rt = ResourceTokens.verify(
                request.resourceToken(),
                agent.jwksFetcher(),
                new ResourceTokens.VerifyOptions(
                        request.presentedToken(),
                        null,
                        request.resourceId(),
                        request.personServer(),
                        Jwk.thumbprint(key),
                        null,
                        null));
        Map<String, Object> params = new LinkedHashMap<>(request.options());
        params.put("resource_token", request.resourceToken());
        params.put("presented_token", request.presentedToken());
        if (rt.get("login_hint") != null) {
            params.put("login_hint", rt.get("login_hint"));
        }
        if (subagentToken != null) {
            params.put("subagent_token", subagentToken);
        }
        if (upstreamToken != null) {
            params.put("upstream_token", upstreamToken);
        }
        Map<String, Object> metadata =
                Metadata.fetchPersonServer(request.personServer(), jsonClient(agent.transport()));
        Map<String, Object> data = postPs(String.valueOf(metadata.get("auth_token_endpoint")), params, agent);
        if (!(data.get("auth_token") instanceof String token) || token.isEmpty()) {
            throw new TokenException("PS response missing auth_token", AuthTokens.TYPE);
        }
        verifyReturnedAuthToken(agent, request, rt, key, token, limits, upstream);
        return token;
    }

    private static void verifyReturnedAuthToken(
            Agent agent,
            AuthTokenRequest request,
            Map<String, Object> rt,
            Map<String, Object> key,
            String token,
            List<Long> limits,
            @Nullable Map<String, Object> upstream) {
        Map<String, Object> claims = TokenVerifier.verify(
                token,
                agent.jwksFetcher(),
                new TokenVerifier.Options(
                        AuthTokens.TYPE, String.valueOf(rt.get("aud")), request.resourceId(), key, null));
        if (!Objects.equals(claims.get("sub"), rt.get("sub"))
                || !request.personServer().equals(claims.get("ps"))) {
            throw new TokenException("Returned auth token person binding mismatch", AuthTokens.TYPE);
        }
        if (!Objects.equals(claims.get("mission_s256"), rt.get("mission_s256"))
                || !Objects.equals(claims.get("tenant"), rt.get("tenant"))) {
            throw new TokenException("Returned auth token context mismatch", AuthTokens.TYPE);
        }
        Map<String, Object> presented = TokenVerifier.verify(
                request.presentedToken(), agent.jwksFetcher(), TokenVerifier.Options.forType(null));
        limits.add(number(presented.get("exp")));
        if (upstream != null) {
            limits.add(number(upstream.get("exp")));
            if (!Objects.equals(claims.get("mission_s256"), upstream.get("mission_s256"))) {
                throw new TokenException("Downstream mission does not match upstream context", AuthTokens.TYPE);
            }
        }
        if (number(claims.get("exp")) > Collections.min(limits)) {
            throw new TokenException("Auth token outlives dependency", AuthTokens.TYPE);
        }
    }

    // --- Deferred resource requests (§6.5.1, AG-26) --------------------------------------------

    /**
     * A resource's {@code 202} auth-token challenge to complete.
     *
     * @param response the resource's 202 response (with {@code Location} and the challenge)
     * @param requestUri the URI of the original request (base for {@code Location})
     * @param presentedToken the token the agent presented with the original request
     * @param resourceId the resource identifier
     * @param personServer the agent's PS
     */
    public record DeferredRequest(
            AAuthResponse response, String requestUri, String presentedToken, String resourceId, String personServer) {}

    /**
     * Resolves a resource's {@code 202} auth-token challenge without repeating its invocation: obtain
     * an auth token through the PS, then poll the same-origin pending URL presenting it.
     *
     * @return the polling result; its response is the resource's answer to the held invocation
     * @throws TokenException if the response is not a deferred challenge or the exchange fails
     */
    public static Poller.PollingResult completeDeferredResourceRequest(Agent agent, DeferredRequest request) {
        AAuthResponse response = request.response();
        if (response.statusCode() != 202) {
            throw new TokenException("Expected a deferred resource response", null);
        }
        String location = Poller.pendingLocation(response.getHeader("location"), request.requestUri());
        String resourceToken = extractResourceToken(response.headers());
        if (resourceToken == null) {
            throw new TokenException("Deferred auth challenge missing resource token", null);
        }
        String authToken = exchangeResourceToken(
                agent,
                AuthTokenRequest.of(
                        resourceToken, request.presentedToken(), request.resourceId(), request.personServer()));
        return Poller.poll(Poller.Request.builder(location, url -> send(agent, "GET", url, null, authToken))
                .initialResponse(pollResponse(response))
                .maxPolls(agent.maxPolls())
                .onInteraction(agent.onInteraction())
                .sleeper(agent.sleeper())
                .build());
    }

    // --- PS requests -----------------------------------------------------------------------------

    /**
     * POSTs signed parameters to a PS endpoint, polling a 202 until terminal.
     *
     * @return the PS's JSON object response
     * @throws TokenException with the PS's {@code error} code (default {@code server_error}) when it
     *     refuses, or when polling fails or the response is not a JSON object
     */
    static Map<String, Object> postPs(String endpoint, Map<String, Object> params, Agent agent) {
        Poller.PollResponse response = post(agent, endpoint, params);
        if (response.statusCode() == 202) {
            String location = Poller.pendingLocation(
                    response.headers().entrySet().stream()
                            .filter(e -> e.getKey().equalsIgnoreCase("location"))
                            .map(Map.Entry::getValue)
                            .findFirst()
                            .orElse(null),
                    endpoint);
            Poller.PollingResult result =
                    Poller.poll(Poller.Request.builder(location, url -> send(agent, "GET", url, null, agent.agentJwt()))
                            .initialResponse(response)
                            .maxPolls(agent.maxPolls())
                            .onInteraction(agent.onInteraction())
                            .onClarification(agent.onClarification())
                            .signedPost((url, body) -> post(agent, url, body))
                            .sleeper(agent.sleeper())
                            .build());
            Poller.PollResponse terminal = result.response();
            if (!result.success() || terminal == null) {
                throw new TokenException(
                        "PS deferred exchange failed: " + result.error() + ": " + result.errorDescription(), null);
            }
            response = terminal;
        }
        Map<String, Object> data = jsonObject(response.raw());
        if (response.statusCode() != 200) {
            Map<String, Object> error = data == null ? Map.of() : data;
            String code = error.get("error") instanceof String value ? value : "server_error";
            String detail = error.get("detail") instanceof String value ? value : "PS request failed";
            throw new TokenException(detail, null, code, null, null);
        }
        if (data == null) {
            throw new TokenException("PS response is not a JSON object", null);
        }
        return data;
    }

    private static Poller.PollResponse post(Agent agent, String url, Map<String, Object> params) {
        byte[] body;
        try {
            body = MAPPER.writeValueAsBytes(params);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to serialize PS request", e);
        }
        return send(agent, "POST", url, body, agent.agentJwt());
    }

    private static Poller.PollResponse send(
            Agent agent, String method, String url, byte @Nullable [] body, String token) {
        Map<String, String> headers = new LinkedHashMap<>();
        SignRequest.Builder sign =
                SignRequest.builder(method, url).keyPair(agent.keyPair()).scheme(new SignatureScheme.Jwt(token));
        if (body != null) {
            headers.put("Content-Type", "application/json");
            sign.headers(headers).body(body).additionalComponents(BODY_COMPONENTS);
        }
        headers.putAll(RequestSigner.sign(sign.build()));
        try {
            return pollResponse(agent.transport().send(method, url, headers, body));
        } catch (IOException e) {
            throw new UncheckedIOException(method + " " + url + " failed: " + e.getMessage(), e);
        }
    }

    // --- Helpers ---------------------------------------------------------------------------------

    private static Map<String, Object> signingJwk(Agent agent) {
        return Jwk.publicKeyToJwk(agent.keyPair().getPublic(), null);
    }

    /** Verifies the agent's own token against its signing key; sub-agents are refused. */
    private static Map<String, Object> verifyAgent(Agent agent, Map<String, Object> key, String subAgentMessage) {
        Map<String, Object> claims = TokenVerifier.verify(
                agent.agentJwt(),
                agent.jwksFetcher(),
                TokenVerifier.Options.forType(AgentTokens.TYPE).withRequestSigningJwk(key));
        if (claims.containsKey("parent_agent")) {
            throw new TokenException(subAgentMessage, AgentTokens.TYPE);
        }
        return claims;
    }

    private static Delegation.UpstreamOptions upstreamOptions(Agent agent, String personServer) {
        return new Delegation.UpstreamOptions(agent.agentJwt(), personServer, Set.of(), "as", null);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> confirmationJwk(Map<String, Object> claims) {
        if (claims.get("cnf") instanceof Map<?, ?> cnf && cnf.get("jwk") instanceof Map<?, ?> jwk) {
            return (Map<String, Object>) jwk;
        }
        throw new TokenException("Missing cnf.jwk", null, "invalid_jwt", null, null);
    }

    private static long number(@Nullable Object value) {
        if (value instanceof Number n) {
            return n.longValue();
        }
        throw new TokenException("Missing or invalid exp", null, "invalid_jwt", null, null);
    }

    static Poller.PollResponse pollResponse(AAuthResponse response) {
        Map<String, Object> body = jsonObject(response.body());
        return new Poller.PollResponse(
                response.statusCode(), body == null ? Map.of() : body, response.headers(), response.body());
    }

    private static @Nullable Map<String, Object> jsonObject(byte[] raw) {
        if (raw.length == 0) {
            return null;
        }
        try {
            JsonNode node = MAPPER.readTree(raw);
            return node != null && node.isObject() ? MAPPER.convertValue(node, MAP_TYPE) : null;
        } catch (IOException e) {
            return null;
        }
    }

    /** Adapts a transport to metadata discovery: a GET whose 2xx JSON object body is returned. */
    private static JsonHttpClient jsonClient(HttpTransport transport) {
        return url -> {
            AAuthResponse response;
            try {
                response = transport.send("GET", url, Map.of("Accept", "application/json"), null);
            } catch (IOException e) {
                throw new UncheckedIOException("GET " + url + " failed: " + e.getMessage(), e);
            }
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new IllegalStateException("GET " + url + " returned HTTP " + response.statusCode());
            }
            Map<String, Object> body = jsonObject(response.body());
            if (body == null) {
                throw new IllegalStateException("GET " + url + " did not return a JSON object");
            }
            return body;
        };
    }
}
