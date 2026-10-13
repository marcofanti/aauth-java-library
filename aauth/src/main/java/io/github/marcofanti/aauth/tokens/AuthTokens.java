package io.github.marcofanti.aauth.tokens;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.signing.Jwts;
import java.security.PrivateKey;
import java.util.LinkedHashMap;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Auth token ({@code aa-auth+jwt}) issuance per AAuth draft-11 §9 (mirrors the reference
 * {@code tokens/auth_token}). Draft-11 auth tokens carry person identity and authorization but no
 * {@code agent}/{@code act}; the person is identified by {@code (iss, sub)}. Verify them with
 * {@link TokenVerifier#verify} and {@code expectedTyp} {@link #TYPE}.
 */
public final class AuthTokens {

    public static final String TYPE = "aa-auth+jwt";
    public static final String DWK_PERSON = "aauth-person.json";
    public static final String DWK_ACCESS = "aauth-access.json";

    private AuthTokens() {}

    /**
     * Parameters for {@link #create(Spec)}.
     *
     * @param iss issuer: the PS (three-party, {@code dwk aauth-person.json}) or the AS (four-party)
     * @param aud resource identifier (server identifier)
     * @param cnfJwk the agent's public signing key (JWK with a fully-specified {@code alg})
     * @param privateKey issuer's signing key (Ed25519, P-256 or P-384)
     * @param kid key ID for the signing key
     * @param ps the person's person server (server identifier); equals {@code iss} when PS-issued
     * @param sub directed person identifier
     * @param agentExp {@code exp} of the verified agent token — REQUIRED lifetime bound
     * @param presentedExp {@code exp} of the verified presented token — REQUIRED lifetime bound
     * @param scope optional authorized scopes
     * @param exp requested expiration, or {@code null} for one hour; capped by every bound
     * @param missionS256 optional mission binding
     * @param missionExp the mission's expiration; REQUIRED with a mission when PS-issued
     * @param upstreamExp the upstream token's expiration when issued for call chaining
     * @param tenant optional organization context
     * @param account optional account at the resource
     * @param dwk {@link #DWK_ACCESS} (default) or {@link #DWK_PERSON}
     */
    public record Spec(
            String iss,
            String aud,
            Map<String, Object> cnfJwk,
            PrivateKey privateKey,
            String kid,
            String ps,
            String sub,
            long agentExp,
            long presentedExp,
            @Nullable String scope,
            @Nullable Long exp,
            @Nullable String missionS256,
            @Nullable Long missionExp,
            @Nullable Long upstreamExp,
            @Nullable String tenant,
            @Nullable String account,
            String dwk) {

        public static Builder builder(String iss, String aud, String sub, String ps) {
            return new Builder(iss, aud, sub, ps);
        }

        /** Builder for {@link Spec}; the key, {@code agentExp} and {@code presentedExp} are required. */
        public static final class Builder {
            private final String iss;
            private final String aud;
            private final String sub;
            private final String ps;
            private @Nullable Map<String, Object> cnfJwk;
            private @Nullable PrivateKey privateKey;
            private @Nullable String kid;
            private @Nullable Long agentExp;
            private @Nullable Long presentedExp;
            private @Nullable String scope;
            private @Nullable Long exp;
            private @Nullable String missionS256;
            private @Nullable Long missionExp;
            private @Nullable Long upstreamExp;
            private @Nullable String tenant;
            private @Nullable String account;
            private String dwk = DWK_ACCESS;

            private Builder(String iss, String aud, String sub, String ps) {
                this.iss = iss;
                this.aud = aud;
                this.sub = sub;
                this.ps = ps;
            }

            public Builder cnfJwk(Map<String, Object> cnfJwk) {
                this.cnfJwk = cnfJwk;
                return this;
            }

            public Builder signingKey(PrivateKey privateKey, String kid) {
                this.privateKey = privateKey;
                this.kid = kid;
                return this;
            }

            /** Lifetime bounds from the verified agent token and presented token. */
            public Builder bounds(long agentExp, long presentedExp) {
                this.agentExp = agentExp;
                this.presentedExp = presentedExp;
                return this;
            }

            public Builder scope(String scope) {
                this.scope = scope;
                return this;
            }

            public Builder exp(long exp) {
                this.exp = exp;
                return this;
            }

            public Builder missionS256(String missionS256) {
                this.missionS256 = missionS256;
                return this;
            }

            public Builder missionExp(long missionExp) {
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

            public Builder account(String account) {
                this.account = account;
                return this;
            }

            public Builder dwk(String dwk) {
                this.dwk = dwk;
                return this;
            }

            public Spec build() {
                if (cnfJwk == null || privateKey == null || kid == null) {
                    throw new IllegalArgumentException("cnfJwk and signingKey are required");
                }
                if (agentExp == null || presentedExp == null) {
                    throw new TokenException("Verified agent and presented expirations are required", TYPE);
                }
                return new Spec(
                        iss,
                        aud,
                        cnfJwk,
                        privateKey,
                        kid,
                        ps,
                        sub,
                        agentExp,
                        presentedExp,
                        scope,
                        exp,
                        missionS256,
                        missionExp,
                        upstreamExp,
                        tenant,
                        account,
                        dwk);
            }
        }
    }

    /**
     * Creates a signed auth token.
     *
     * @throws TokenException if a claim is invalid or a dependency has expired ({@code expired_jwt})
     */
    public static String create(Spec spec) {
        TokenSupport.checkServer(spec.aud());
        TokenSupport.checkServer(spec.ps());
        TokenSupport.validateAlgorithm(spec.cnfJwk());
        if (spec.sub().isEmpty()) {
            throw new TokenException("Auth token requires directed sub", TYPE);
        }
        boolean psIssued = DWK_PERSON.equals(spec.dwk());
        if ((!psIssued && !DWK_ACCESS.equals(spec.dwk()))
                || (psIssued && !spec.iss().equals(spec.ps()))) {
            throw new TokenException("Invalid issuer/dwk for auth token", TYPE);
        }
        if (spec.missionS256() != null && psIssued && spec.missionExp() == null) {
            throw new TokenException("PS must provide mission expiration bound", TYPE);
        }
        long now = TokenSupport.nowEpochSeconds();
        long exp = TokenSupport.boundedExp(
                now, spec.exp(), spec.agentExp(), spec.presentedExp(), spec.upstreamExp(), spec.missionExp());
        Map<String, Object> claims = TokenSupport.baseClaims(spec.iss(), spec.dwk(), exp);
        claims.put("aud", spec.aud());
        claims.put("ps", spec.ps());
        claims.put("sub", spec.sub());
        claims.put("cnf", Map.of("jwk", spec.cnfJwk()));
        if (spec.scope() != null) {
            claims.put("scope", spec.scope());
        }
        if (spec.missionS256() != null) {
            claims.put("mission_s256", TokenSupport.checkHash(spec.missionS256()));
        }
        if (spec.tenant() != null) {
            claims.put("tenant", spec.tenant());
        }
        if (spec.account() != null) {
            claims.put("account", spec.account());
        }
        return Jwts.encode(claims, spec.privateKey(), spec.kid(), TYPE);
    }

    /** Parses token header and payload without verification (for inspection). */
    public static Map<String, Object> parseTokenClaims(String token) {
        Jwts.Decoded jwt = TokenSupport.parse(token);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("header", jwt.header());
        result.put("payload", jwt.payload());
        return result;
    }
}
