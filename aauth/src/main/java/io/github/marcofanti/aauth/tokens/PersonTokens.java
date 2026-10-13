package io.github.marcofanti.aauth.tokens;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.signing.Jwts;
import java.security.PrivateKey;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Person token ({@code aa-person+jwt}) issuance and verification per AAuth draft-11 §7.1 (mirrors
 * the reference {@code tokens/person_token}).
 *
 * <p>The person server issues a person token that identifies the person to one resource. The
 * agent presents it at the resource's authorization endpoint in place of its agent token. The
 * person is identified by {@code (iss, sub)}; {@code sub} is opaque and directed. A person token
 * MUST NOT carry {@code scope} or {@code account} (§7.1.2).
 */
public final class PersonTokens {

    public static final String TYPE = "aa-person+jwt";
    public static final String DWK = "aauth-person.json";

    private PersonTokens() {}

    /**
     * Parameters for {@link #create(Spec)}.
     *
     * @param iss person server identifier (server identifier)
     * @param aud resource identifier (server identifier)
     * @param sub directed person identifier
     * @param cnfJwk the agent's public signing key (JWK with a fully-specified {@code alg})
     * @param privateKey person server's signing key (Ed25519, P-256 or P-384)
     * @param kid key ID for the signing key
     * @param agentExp {@code exp} of the verified agent token the request was signed with — REQUIRED;
     *     the person token never outlives it
     * @param exp requested expiration, or {@code null} for one hour; capped by every bound
     * @param missionS256 optional mission binding (43-character unpadded base64url SHA-256)
     * @param missionExp the mission's expiration; REQUIRED with {@code missionS256}
     * @param upstreamExp the upstream token's expiration when issued for call chaining
     * @param tenant optional organization context (not part of the identifier)
     */
    public record Spec(
            String iss,
            String aud,
            String sub,
            Map<String, Object> cnfJwk,
            PrivateKey privateKey,
            String kid,
            long agentExp,
            @Nullable Long exp,
            @Nullable String missionS256,
            @Nullable Long missionExp,
            @Nullable Long upstreamExp,
            @Nullable String tenant) {

        public static Builder builder(
                String iss, String aud, String sub, Map<String, Object> cnfJwk, PrivateKey privateKey, String kid) {
            return new Builder(iss, aud, sub, cnfJwk, privateKey, kid);
        }

        /** Builder for {@link Spec}; {@link #agentExp(long)} is required. */
        public static final class Builder {
            private final String iss;
            private final String aud;
            private final String sub;
            private final Map<String, Object> cnfJwk;
            private final PrivateKey privateKey;
            private final String kid;
            private @Nullable Long agentExp;
            private @Nullable Long exp;
            private @Nullable String missionS256;
            private @Nullable Long missionExp;
            private @Nullable Long upstreamExp;
            private @Nullable String tenant;

            private Builder(
                    String iss, String aud, String sub, Map<String, Object> cnfJwk, PrivateKey privateKey, String kid) {
                this.iss = iss;
                this.aud = aud;
                this.sub = sub;
                this.cnfJwk = cnfJwk;
                this.privateKey = privateKey;
                this.kid = kid;
            }

            public Builder agentExp(long agentExp) {
                this.agentExp = agentExp;
                return this;
            }

            public Builder exp(long exp) {
                this.exp = exp;
                return this;
            }

            /** Binds the token to a mission; {@code missionExp} bounds the token's lifetime. */
            public Builder mission(String missionS256, long missionExp) {
                this.missionS256 = missionS256;
                this.missionExp = missionExp;
                return this;
            }

            public Builder upstreamExp(long upstreamExp) {
                this.upstreamExp = upstreamExp;
                return this;
            }

            public Builder tenant(String tenant) {
                this.tenant = tenant;
                return this;
            }

            public Spec build() {
                if (agentExp == null) {
                    throw new TokenException("Verified agent expiration is required", TYPE);
                }
                return new Spec(
                        iss,
                        aud,
                        sub,
                        cnfJwk,
                        privateKey,
                        kid,
                        agentExp,
                        exp,
                        missionS256,
                        missionExp,
                        upstreamExp,
                        tenant);
            }
        }
    }

    /**
     * Creates a signed person token.
     *
     * @throws TokenException if a claim is invalid or a dependency has expired ({@code expired_jwt})
     */
    public static String create(Spec spec) {
        TokenSupport.checkServer(spec.aud());
        TokenSupport.validateAlgorithm(spec.cnfJwk());
        if (spec.sub().isEmpty()) {
            throw new TokenException("Person token requires directed sub", TYPE);
        }
        if (spec.missionS256() != null && spec.missionExp() == null) {
            throw new TokenException("Mission expiration bound is required", TYPE);
        }
        long now = TokenSupport.nowEpochSeconds();
        long exp = TokenSupport.boundedExp(now, spec.exp(), spec.agentExp(), spec.missionExp(), spec.upstreamExp());
        Map<String, Object> claims = TokenSupport.baseClaims(spec.iss(), DWK, exp);
        claims.put("aud", spec.aud());
        claims.put("sub", spec.sub());
        claims.put("cnf", Map.of("jwk", spec.cnfJwk()));
        if (spec.missionS256() != null) {
            claims.put("mission_s256", TokenSupport.checkHash(spec.missionS256()));
        }
        if (spec.tenant() != null) {
            claims.put("tenant", spec.tenant());
        }
        return Jwts.encode(claims, spec.privateKey(), spec.kid(), TYPE);
    }

    /**
     * Verifies a person token (§7.1.4) and returns its claims; the caller identifies the person by
     * {@code (iss, sub)}.
     *
     * @param options expectations — typically the resource as {@code expectedAud}, the request's
     *     signing key, and a revocation checker; {@code expectedTyp} is forced to {@link #TYPE}
     * @throws TokenException with the wire error code if the token is invalid
     */
    public static Map<String, Object> verify(String token, JwksFetcher jwksFetcher, TokenVerifier.Options options) {
        return TokenVerifier.verify(token, jwksFetcher, options.withType(TYPE));
    }
}
