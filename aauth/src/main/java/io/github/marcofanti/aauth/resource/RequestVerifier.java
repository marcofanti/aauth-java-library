package io.github.marcofanti.aauth.resource;

import io.github.marcofanti.aauth.Identifiers;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.headers.AAuthHeaders;
import io.github.marcofanti.aauth.signing.AAuthException;
import io.github.marcofanti.aauth.signing.HttpSignatureException;
import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.SignatureKeyHeader;
import io.github.marcofanti.aauth.signing.SignatureVerifier;
import io.github.marcofanti.aauth.signing.VerifyRequest;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.tokens.AgentTokens;
import io.github.marcofanti.aauth.tokens.AuthTokens;
import io.github.marcofanti.aauth.tokens.PersonTokens;
import io.github.marcofanti.aauth.tokens.RevocationChecker;
import io.github.marcofanti.aauth.tokens.TokenVerifier;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiPredicate;
import org.jspecify.annotations.Nullable;

/**
 * Resource authentication and request-context binding for draft-11 (mirrors the reference
 * {@code resource/verifier}).
 *
 * <p>AAuth agents sign with the {@code jwt} scheme, presenting an agent, person or auth token. The
 * HTTP signature is verified (with the required components), then the presented token is verified
 * with this resource as its audience. Auth and person tokens must come from trusted issuers.
 */
public final class RequestVerifier {

    private static final Set<String> REQUEST_TOKEN_TYPES = Set.of(AgentTokens.TYPE, PersonTokens.TYPE, AuthTokens.TYPE);
    private static final List<String> BASE_COMPONENTS = List.of("@method", "@authority", "@path", "signature-key");

    private final List<String> canonicalAuthorities;
    private final @Nullable JwksFetcher jwksFetcher;
    private final @Nullable String resourceId;
    private final Set<String> trustedAuthServers;
    private final Set<String> trustedPersonServers;
    private final @Nullable BiPredicate<String, String> sessionTokenVerifier;
    private final List<String> additionalSignatureComponents;
    private final long signatureWindow;
    private final @Nullable RevocationChecker revocationChecker;

    private RequestVerifier(Builder builder) {
        this.canonicalAuthorities = List.copyOf(builder.canonicalAuthorities);
        this.jwksFetcher = builder.jwksFetcher;
        String id = builder.resourceId;
        this.resourceId = id == null ? null : Identifiers.validateServerIdentifier(id);
        this.trustedAuthServers = Set.copyOf(builder.trustedAuthServers);
        this.trustedPersonServers = Set.copyOf(
                builder.trustedPersonServers != null ? builder.trustedPersonServers : builder.trustedAuthServers);
        this.sessionTokenVerifier = builder.sessionTokenVerifier;
        this.additionalSignatureComponents = List.copyOf(builder.additionalSignatureComponents);
        this.signatureWindow = builder.signatureWindow;
        this.revocationChecker = builder.revocationChecker;
    }

    /**
     * Starts configuring a verifier.
     *
     * @param canonicalAuthorities canonical authorities ({@code host[:port]}) this resource accepts
     * @param jwksFetcher resolves token issuers' JWKS from {@code (iss, dwk, kid)}
     */
    public static Builder builder(List<String> canonicalAuthorities, @Nullable JwksFetcher jwksFetcher) {
        return new Builder(canonicalAuthorities, jwksFetcher);
    }

    /** Configuration for {@link RequestVerifier}. */
    public static final class Builder {
        private final List<String> canonicalAuthorities;
        private final @Nullable JwksFetcher jwksFetcher;
        private @Nullable String resourceId;
        private Set<String> trustedAuthServers = Set.of();
        private @Nullable Set<String> trustedPersonServers;
        private @Nullable BiPredicate<String, String> sessionTokenVerifier;
        private List<String> additionalSignatureComponents = List.of();
        private long signatureWindow = VerifyRequest.DEFAULT_SIGNATURE_WINDOW;
        private @Nullable RevocationChecker revocationChecker;

        private Builder(List<String> canonicalAuthorities, @Nullable JwksFetcher jwksFetcher) {
            this.canonicalAuthorities = canonicalAuthorities;
            this.jwksFetcher = jwksFetcher;
        }

        /** This resource's identifier; defaults to the request's origin. */
        public Builder resourceId(String resourceId) {
            this.resourceId = resourceId;
            return this;
        }

        /** Issuers whose auth tokens are accepted (also person-token issuers unless set separately). */
        public Builder trustedAuthServers(Set<String> trustedAuthServers) {
            this.trustedAuthServers = trustedAuthServers;
            return this;
        }

        /** Issuers whose person tokens are accepted; defaults to the trusted auth servers. */
        public Builder trustedPersonServers(Set<String> trustedPersonServers) {
            this.trustedPersonServers = trustedPersonServers;
            return this;
        }

        /** Checks an {@code Authorization: AAuth} session token against the signing key thumbprint. */
        public Builder sessionTokenVerifier(BiPredicate<String, String> sessionTokenVerifier) {
            this.sessionTokenVerifier = sessionTokenVerifier;
            return this;
        }

        /** Components the signature must cover beyond {@code @method @authority @path signature-key}. */
        public Builder additionalSignatureComponents(List<String> additionalSignatureComponents) {
            this.additionalSignatureComponents = additionalSignatureComponents;
            return this;
        }

        public Builder signatureWindow(long signatureWindow) {
            this.signatureWindow = signatureWindow;
            return this;
        }

        public Builder revocationChecker(RevocationChecker revocationChecker) {
            this.revocationChecker = revocationChecker;
            return this;
        }

        public RequestVerifier build() {
            return new RequestVerifier(this);
        }
    }

    /**
     * What a request must carry.
     *
     * @param requireIdentity an agent token (agent identity access)
     * @param requireAuthToken an auth token
     * @param requirePersonToken a person token
     * @param requireSessionToken an {@code Authorization: AAuth} session token
     * @param requiredScopes scopes the token must grant
     */
    public record Requirements(
            boolean requireIdentity,
            boolean requireAuthToken,
            boolean requirePersonToken,
            boolean requireSessionToken,
            List<String> requiredScopes) {

        public Requirements {
            requiredScopes = List.copyOf(requiredScopes);
        }

        public static Requirements none() {
            return new Requirements(false, false, false, false, List.of());
        }

        public static Requirements identity() {
            return new Requirements(true, false, false, false, List.of());
        }

        public static Requirements authToken(String... scopes) {
            return new Requirements(false, true, false, false, Arrays.asList(scopes));
        }

        public static Requirements personToken() {
            return new Requirements(false, false, true, false, List.of());
        }

        public static Requirements sessionToken() {
            return new Requirements(false, false, false, true, List.of());
        }
    }

    /**
     * Outcome of request verification. On failure only {@code error} and {@code errorCode} are set.
     *
     * @param valid whether the request is authenticated and meets the requirements
     * @param tokenType the presented token's {@code typ}
     * @param claims the verified token claims
     * @param agentId the agent identifier, for agent tokens
     * @param userSub the person identifier, for person and auth tokens
     * @param personServer the person's PS ({@code ps}, or a person token's {@code iss})
     * @param scopes the token's scopes
     * @param sessionToken the verified session token, if presented
     * @param error a description of the failure
     * @param errorCode the wire error code of the failure
     */
    public record Result(
            boolean valid,
            @Nullable String tokenType,
            Map<String, Object> claims,
            @Nullable String agentId,
            @Nullable String userSub,
            @Nullable String personServer,
            List<String> scopes,
            @Nullable String sessionToken,
            @Nullable String error,
            @Nullable String errorCode) {

        static Result failure(String error, @Nullable String errorCode) {
            return new Result(false, null, Map.of(), null, null, null, List.of(), null, error, errorCode);
        }
    }

    /**
     * Verifies an incoming request.
     *
     * @param body the request body, or {@code null}
     * @return the result; failures carry the wire error code (default {@code invalid_jwt})
     */
    public Result verifyRequest(
            String method,
            String targetUri,
            Map<String, String> headers,
            byte @Nullable [] body,
            Requirements requirements) {
        try {
            return verify(method, targetUri, headers, body, requirements);
        } catch (AAuthException e) {
            String code = e.errorCode();
            return Result.failure(String.valueOf(e.getMessage()), code != null ? code : "invalid_jwt");
        } catch (RuntimeException e) {
            return Result.failure(String.valueOf(e.getMessage()), "invalid_jwt");
        }
    }

    private Result verify(
            String method,
            String targetUri,
            Map<String, String> headers,
            byte @Nullable [] body,
            Requirements requirements) {
        URI uri = URI.create(targetUri);
        String authority = uri.getRawAuthority();
        if (!canonicalAuthorities.contains(authority)) {
            throw new TokenException("Request authority is not canonical: " + authority, null);
        }
        String resource = resourceId != null
                ? resourceId
                : Identifiers.validateServerIdentifier(uri.getScheme() + "://" + authority);
        SignatureKeyHeader.Parsed key = SignatureKeyHeader.parse(header(headers, "signature-key"));
        if (!"jwt".equals(key.scheme())) {
            throw new HttpSignatureException("AAuth agents must use jwt", "unsupported_scheme", null, null);
        }
        String token = String.valueOf(key.params().get("jwt"));
        String typ = requestTokenType(token);
        JwksFetcher fetcher = jwksFetcher;
        if (fetcher == null) {
            throw new TokenException("JWKS fetcher is required", typ);
        }
        verifySignature(method, targetUri, headers, body, fetcher);
        Map<String, Object> claims = TokenVerifier.verify(
                token, fetcher, new TokenVerifier.Options(typ, null, resource, null, revocationChecker));
        requireTokenType(typ, requirements);

        List<String> scopes = scopes(claims);
        if (!scopes.containsAll(requirements.requiredScopes())) {
            return Result.failure("Insufficient scope", "insufficient_scope");
        }
        String session = verifiedSession(headers, claims, requirements);
        boolean agent = AgentTokens.TYPE.equals(typ);
        Object sub = claims.get("sub");
        Object personServer = agent ? claims.get("ps") : claims.getOrDefault("ps", claims.get("iss"));
        return new Result(
                true,
                typ,
                claims,
                agent ? String.valueOf(sub) : null,
                agent ? null : String.valueOf(sub),
                personServer == null ? null : personServer.toString(),
                scopes,
                session,
                null,
                null);
    }

    /** The presented token must be an AAuth request token from a trusted issuer. */
    private String requestTokenType(String token) {
        Jwts.Decoded jwt;
        try {
            jwt = Jwts.parse(token);
        } catch (IllegalArgumentException e) {
            throw new TokenException("Cannot decode JWT", null, "invalid_jwt", null, e);
        }
        Object typ = jwt.header().get("typ");
        if (!(typ instanceof String type) || !REQUEST_TOKEN_TYPES.contains(type)) {
            throw new TokenException("Unexpected request token type", null, "invalid_jwt", null, null);
        }
        Object iss = jwt.payload().get("iss");
        if (AuthTokens.TYPE.equals(type) && !trustedAuthServers.contains(iss)) {
            throw new TokenException("Untrusted auth token issuer", type, "invalid_jwt", null, null);
        }
        if (PersonTokens.TYPE.equals(type) && !trustedPersonServers.contains(iss)) {
            throw new TokenException("Untrusted person token issuer", type, "invalid_jwt", null, null);
        }
        return type;
    }

    private void verifySignature(
            String method, String targetUri, Map<String, String> headers, byte @Nullable [] body, JwksFetcher fetcher) {
        List<String> required = new ArrayList<>(BASE_COMPONENTS);
        required.addAll(additionalSignatureComponents);
        VerifyRequest.Builder request = VerifyRequest.builder(method, targetUri)
                .headers(headers)
                .signatureHeaders(
                        header(headers, "signature-input"),
                        header(headers, "signature"),
                        header(headers, "signature-key"))
                .jwksFetcher(fetcher)
                .requiredComponents(required)
                .signatureWindow(signatureWindow);
        if (body != null) {
            request.body(body);
        }
        if (!SignatureVerifier.verify(request.build())) {
            throw new HttpSignatureException("Signature verification failed");
        }
    }

    private static void requireTokenType(String typ, Requirements requirements) {
        if (requirements.requireAuthToken() && !AuthTokens.TYPE.equals(typ)) {
            throw new TokenException("Auth token required", typ);
        }
        if (requirements.requirePersonToken() && !PersonTokens.TYPE.equals(typ)) {
            throw new TokenException("Person token required", typ);
        }
        if (requirements.requireIdentity() && !AgentTokens.TYPE.equals(typ)) {
            throw new TokenException("Agent token required for agent identity", typ);
        }
    }

    /** An {@code Authorization: AAuth} session token must be bound to the signing key. */
    private @Nullable String verifiedSession(
            Map<String, String> headers, Map<String, Object> claims, Requirements requirements) {
        String session = AAuthHeaders.parseAuthorizationAAuthHeader(header(headers, "authorization"));
        if (requirements.requireSessionToken() && session == null) {
            throw new TokenException("Session token required", null);
        }
        if (session != null) {
            BiPredicate<String, String> verifier = sessionTokenVerifier;
            Map<String, Object> cnf = claims.get("cnf") instanceof Map<?, ?> map ? castMap(map) : Map.of();
            Map<String, Object> jwk = cnf.get("jwk") instanceof Map<?, ?> map ? castMap(map) : Map.of();
            if (verifier == null || !verifier.test(session, Jwk.thumbprint(jwk))) {
                throw new TokenException("Invalid or unbound session token", null);
            }
        }
        return session;
    }

    private static List<String> scopes(Map<String, Object> claims) {
        String scope = claims.get("scope") instanceof String value ? value.strip() : "";
        return scope.isEmpty() ? List.of() : List.of(scope.split("\\s+"));
    }

    private static String header(Map<String, String> headers, String name) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return "";
    }

    private static Map<String, Object> castMap(Map<?, ?> map) {
        Map<String, Object> result = new java.util.LinkedHashMap<>();
        map.forEach((k, v) -> result.put(String.valueOf(k), v));
        return result;
    }
}
