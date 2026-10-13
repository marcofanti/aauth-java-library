package io.github.marcofanti.aauth.tokens;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import java.security.PrivateKey;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import org.jspecify.annotations.Nullable;

/**
 * Resource token ({@code aa-resource+jwt}) issuance and verification per AAuth draft-11 §6.7
 * (mirrors the reference {@code tokens/resource_token}).
 *
 * <p>A resource token is bound to the verified person or auth token that prompted it: issuance
 * verifies the presented token and copies {@code ps}, {@code sub}, {@code presented_jti},
 * {@code mission_s256} and {@code tenant} from it; verification re-checks that binding.
 */
public final class ResourceTokens {

    public static final String TYPE = "aa-resource+jwt";
    public static final String DWK = "aauth-resource.json";

    /** Default resource-token lifetime in seconds. */
    private static final long DEFAULT_LIFETIME_SECONDS = 300;

    private ResourceTokens() {}

    /**
     * Parameters for {@link #create(Spec)}.
     *
     * @param iss resource identifier (server identifier)
     * @param aud the PS (three-party) or the AS (four-party) the token is for
     * @param agentJkt JWK thumbprint of the agent's signing key; must match the presented token's
     *     {@code cnf.jwk}
     * @param privateKey resource's signing key (Ed25519, P-256 or P-384)
     * @param kid key ID for the signing key
     * @param presentedToken the person or auth token the agent presented — REQUIRED
     * @param jwksFetcher resolves the presented token issuer's JWKS from {@code (iss, dwk, kid)}
     * @param scope optional requested scopes
     * @param exp expiration (Unix seconds); {@code null} defaults to five minutes from now
     * @param account optional account at the resource
     * @param loginHint optional login hint the PS MAY honor
     * @param interaction optional interaction value, copied verbatim
     * @param revocationChecker consulted for the presented token
     */
    public record Spec(
            String iss,
            String aud,
            String agentJkt,
            PrivateKey privateKey,
            String kid,
            String presentedToken,
            JwksFetcher jwksFetcher,
            @Nullable String scope,
            @Nullable Long exp,
            @Nullable String account,
            @Nullable String loginHint,
            @Nullable Object interaction,
            @Nullable RevocationChecker revocationChecker) {

        public static Builder builder(String iss, String aud, String agentJkt, PrivateKey privateKey, String kid) {
            return new Builder(iss, aud, agentJkt, privateKey, kid);
        }

        /** Builder for {@link Spec}; {@link #presentedToken(String, JwksFetcher)} is required. */
        public static final class Builder {
            private final String iss;
            private final String aud;
            private final String agentJkt;
            private final PrivateKey privateKey;
            private final String kid;
            private @Nullable String presentedToken;
            private @Nullable JwksFetcher jwksFetcher;
            private @Nullable String scope;
            private @Nullable Long exp;
            private @Nullable String account;
            private @Nullable String loginHint;
            private @Nullable Object interaction;
            private @Nullable RevocationChecker revocationChecker;

            private Builder(String iss, String aud, String agentJkt, PrivateKey privateKey, String kid) {
                this.iss = iss;
                this.aud = aud;
                this.agentJkt = agentJkt;
                this.privateKey = privateKey;
                this.kid = kid;
            }

            public Builder presentedToken(String presentedToken, JwksFetcher jwksFetcher) {
                this.presentedToken = presentedToken;
                this.jwksFetcher = jwksFetcher;
                return this;
            }

            public Builder scope(@Nullable String scope) {
                this.scope = scope;
                return this;
            }

            public Builder exp(@Nullable Long exp) {
                this.exp = exp;
                return this;
            }

            public Builder account(String account) {
                this.account = account;
                return this;
            }

            public Builder loginHint(String loginHint) {
                this.loginHint = loginHint;
                return this;
            }

            public Builder interaction(Object interaction) {
                this.interaction = interaction;
                return this;
            }

            public Builder revocationChecker(@Nullable RevocationChecker revocationChecker) {
                this.revocationChecker = revocationChecker;
                return this;
            }

            public Spec build() {
                if (presentedToken == null || jwksFetcher == null) {
                    throw new IllegalArgumentException("presentedToken and jwksFetcher are required");
                }
                return new Spec(
                        iss,
                        aud,
                        agentJkt,
                        privateKey,
                        kid,
                        presentedToken,
                        jwksFetcher,
                        scope,
                        exp,
                        account,
                        loginHint,
                        interaction,
                        revocationChecker);
            }
        }
    }

    /**
     * Creates a resource token after verifying the presented person or auth token.
     *
     * @throws TokenException {@code invalid_presented_token} / {@code expired_presented_token} /
     *     {@code revoked_presented_token} when the presented token fails, or on invalid parameters
     */
    public static String create(Spec spec) {
        TokenSupport.checkServer(spec.aud());
        Presented presented = presented(
                spec.presentedToken(), spec.jwksFetcher(), spec.iss(), spec.agentJkt(), spec.revocationChecker());
        long now = TokenSupport.nowEpochSeconds();
        Long requestedExp = spec.exp();
        long exp = requestedExp != null ? requestedExp : now + DEFAULT_LIFETIME_SECONDS;
        if (exp <= now) {
            throw new TokenException("Invalid resource token expiration", TYPE);
        }
        Map<String, Object> claims = TokenSupport.baseClaims(spec.iss(), DWK, exp);
        claims.put("aud", spec.aud());
        claims.put("ps", presented.ps());
        claims.put("sub", presented.claims().get("sub"));
        claims.put("presented_jti", presented.claims().get("jti"));
        claims.put("agent_jkt", spec.agentJkt());
        for (String name : List.of("mission_s256", "tenant")) {
            Object value = presented.claims().get(name);
            if (value != null) {
                claims.put(name, value);
            }
        }
        putIfPresent(claims, "scope", spec.scope());
        putIfPresent(claims, "account", spec.account());
        putIfPresent(claims, "login_hint", spec.loginHint());
        putIfPresent(claims, "interaction", spec.interaction());
        return Jwts.encode(claims, spec.privateKey(), spec.kid(), TYPE);
    }

    /**
     * Verification expectations for {@link #verify}.
     *
     * @param presentedToken the token the agent presented with the resource token — REQUIRED
     * @param expectedAud the verifier's own identifier (PS or AS)
     * @param expectedIss the expected resource
     * @param expectedPs the expected person server
     * @param expectedAgentJkt thumbprint of the key that signed the request
     * @param revocationChecker consulted for both tokens
     * @param missionChecker when the token carries {@code mission_s256} and the verifier is the PS
     *     ({@code expectedAud == expectedPs}), must accept the mission as active
     */
    public record VerifyOptions(
            String presentedToken,
            @Nullable String expectedAud,
            @Nullable String expectedIss,
            @Nullable String expectedPs,
            @Nullable String expectedAgentJkt,
            @Nullable RevocationChecker revocationChecker,
            @Nullable Predicate<String> missionChecker) {

        public static VerifyOptions of(String presentedToken) {
            return new VerifyOptions(presentedToken, null, null, null, null, null, null);
        }
    }

    /**
     * Verifies a resource token and its binding to the presented token.
     *
     * @return the verified resource-token claims
     * @throws TokenException {@code invalid_resource_token} / {@code expired_resource_token} /
     *     {@code revoked_resource_token}, the presented-token codes, or {@code mission_terminated}
     */
    public static Map<String, Object> verify(String token, JwksFetcher jwksFetcher, VerifyOptions options) {
        Map<String, Object> claims;
        try {
            claims = TokenVerifier.verify(
                    token,
                    jwksFetcher,
                    new TokenVerifier.Options(
                            TYPE, options.expectedIss(), options.expectedAud(), null, options.revocationChecker()));
        } catch (TokenException e) {
            throw TokenSupport.recode(e, "expired_resource_token", "revoked_resource_token", "invalid_resource_token");
        }
        String agentJkt = String.valueOf(claims.get("agent_jkt"));
        String expectedAgentJkt = options.expectedAgentJkt();
        if (expectedAgentJkt != null && !expectedAgentJkt.equals(agentJkt)) {
            throw invalid("agent_jkt mismatch");
        }
        Presented presented = presented(
                options.presentedToken(),
                jwksFetcher,
                String.valueOf(claims.get("iss")),
                agentJkt,
                options.revocationChecker());
        String expectedPs = options.expectedPs();
        if (expectedPs != null && !expectedPs.equals(claims.get("ps"))) {
            throw invalid("PS mismatch");
        }
        if (!presented.ps().equals(claims.get("ps"))
                || !Objects.equals(claims.get("sub"), presented.claims().get("sub"))
                || !Objects.equals(
                        claims.get("presented_jti"), presented.claims().get("jti"))) {
            throw invalid("Presented token binding mismatch");
        }
        for (String name : List.of("mission_s256", "tenant")) {
            if (!Objects.equals(claims.get(name), presented.claims().get(name))) {
                throw invalid(name + " binding mismatch");
            }
        }
        requireActiveMission(claims, options);
        return claims;
    }

    private static void requireActiveMission(Map<String, Object> claims, VerifyOptions options) {
        Object mission = claims.get("mission_s256");
        if (mission == null || !Objects.equals(options.expectedAud(), options.expectedPs())) {
            return;
        }
        Predicate<String> checker = options.missionChecker();
        if (checker == null || !checker.test(mission.toString())) {
            throw new TokenException("Mission is not active", TYPE, "mission_terminated", null, null);
        }
    }

    /** A verified presented token and the PS it names. */
    private record Presented(Map<String, Object> claims, String ps) {}

    private static Presented presented(
            String token,
            JwksFetcher fetcher,
            String resource,
            String agentJkt,
            @Nullable RevocationChecker revocationChecker) {
        Object typ = TokenSupport.parse(token).header().get("typ");
        if (!PersonTokens.TYPE.equals(typ) && !AuthTokens.TYPE.equals(typ)) {
            throw new TokenException(
                    "Expected person or auth presented_token", TYPE, "invalid_presented_token", null, null);
        }
        try {
            Map<String, Object> claims = TokenVerifier.verify(
                    token,
                    fetcher,
                    TokenVerifier.Options.forType(null)
                            .withAudience(resource)
                            .withRevocationChecker(revocationChecker));
            Map<String, Object> cnfJwk = TokenSupport.confirmationJwk(claims);
            if (cnfJwk == null || !Jwk.thumbprint(cnfJwk).equals(agentJkt)) {
                throw new TokenException("Presented confirmation key mismatch", TYPE);
            }
            Object ps = PersonTokens.TYPE.equals(typ) ? claims.get("iss") : claims.get("ps");
            return new Presented(claims, String.valueOf(ps));
        } catch (TokenException e) {
            throw TokenSupport.recode(
                    e, "expired_presented_token", "revoked_presented_token", "invalid_presented_token");
        }
    }

    private static TokenException invalid(String message) {
        return new TokenException(message, TYPE, "invalid_resource_token", null, null);
    }

    private static void putIfPresent(Map<String, Object> claims, String name, @Nullable Object value) {
        if (value != null) {
            claims.put(name, value);
        }
    }
}
