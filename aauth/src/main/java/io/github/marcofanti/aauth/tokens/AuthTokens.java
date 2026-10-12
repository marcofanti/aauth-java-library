package io.github.marcofanti.aauth.tokens;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.signing.Jwts;
import java.security.PrivateKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import org.jspecify.annotations.Nullable;

/** Auth token ({@code aa-auth+jwt}) creation and verification per AAuth draft-11 §9.1. */
public final class AuthTokens {

    public static final String TYPE = "aa-auth+jwt";

    private AuthTokens() {}

    /**
     * Parameters for {@link #create(Spec)}.
     *
     * <p>Draft-11 removed the {@code agent} and {@code act} claims; the person is identified by
     * {@code (iss, sub)} and {@code sub} is REQUIRED. {@code ps} names the person's person server.
     *
     * @param iss auth server identifier (HTTPS URL)
     * @param aud resource identifier
     * @param sub person identifier — REQUIRED
     * @param ps person server identifier
     * @param cnfJwk agent's public signing key (JWK) — required
     * @param privateKey auth server's Ed25519 signing key
     * @param kid key ID for the signing key
     * @param scope optional authorized scopes
     * @param exp expiration (Unix seconds); {@code null} defaults to one hour from now
     * @param missionS256 optional mission binding when issued in mission context
     * @param dwk metadata document for key discovery; defaults to {@code aauth-access.json}
     * @param account optional account identifier
     */
    public record Spec(
            String iss,
            String aud,
            String sub,
            String ps,
            Map<String, Object> cnfJwk,
            PrivateKey privateKey,
            String kid,
            @Nullable String scope,
            @Nullable Long exp,
            @Nullable String missionS256,
            String dwk,
            @Nullable String account) {

        public Spec {
            if (sub == null || sub.isEmpty()) {
                throw new TokenException("'sub' claim is required in auth token", TYPE);
            }
            if (iss == null || aud == null || ps == null || cnfJwk == null || privateKey == null || kid == null) {
                throw new IllegalArgumentException("iss, aud, ps, cnfJwk, privateKey and kid are required");
            }
            dwk = dwk == null ? "aauth-access.json" : dwk;
        }

        public static Builder builder(String iss, String aud, String sub, String ps) {
            return new Builder(iss, aud, sub, ps);
        }

        /** Builder for {@link Spec}. */
        public static final class Builder {
            private final String iss;
            private final String aud;
            private final String sub;
            private final String ps;
            private @Nullable Map<String, Object> cnfJwk;
            private @Nullable PrivateKey privateKey;
            private @Nullable String kid;
            private @Nullable String scope;
            private @Nullable Long exp;
            private @Nullable String missionS256;
            private @Nullable String dwk;
            private @Nullable String account;

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

            public Builder scope(String scope) {
                this.scope = scope;
                return this;
            }

            public Builder exp(Long exp) {
                this.exp = exp;
                return this;
            }

            public Builder missionS256(String missionS256) {
                this.missionS256 = missionS256;
                return this;
            }

            public Builder dwk(String dwk) {
                this.dwk = dwk;
                return this;
            }

            public Builder account(String account) {
                this.account = account;
                return this;
            }

            public Spec build() {
                if (cnfJwk == null || privateKey == null || kid == null) {
                    throw new IllegalArgumentException("cnfJwk, privateKey and kid are required");
                }
                return new Spec(
                        iss,
                        aud,
                        sub,
                        ps,
                        cnfJwk,
                        privateKey,
                        kid,
                        scope,
                        exp,
                        missionS256,
                        dwk == null ? "aauth-access.json" : dwk,
                        account);
            }
        }
    }

    /** Creates a signed auth token ({@code aa-auth+jwt}). */
    public static String create(Spec spec) {
        long now = TokenSupport.nowEpochSeconds();
        Long requestedExp = spec.exp();
        long exp = requestedExp != null ? requestedExp : now + 3600;

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", TYPE);
        header.put("alg", "Ed25519");
        header.put("kid", spec.kid());

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", spec.iss());
        payload.put("aud", spec.aud());
        payload.put("sub", spec.sub());
        payload.put("ps", spec.ps());
        payload.put("dwk", spec.dwk());
        payload.put("jti", UUID.randomUUID().toString());
        payload.put("cnf", Map.of("jwk", spec.cnfJwk()));
        payload.put("iat", now);
        payload.put("exp", exp);
        if (spec.scope() != null) {
            payload.put("scope", spec.scope());
        }
        if (spec.missionS256() != null) {
            payload.put("mission_s256", spec.missionS256());
        }
        if (spec.account() != null) {
            payload.put("account", spec.account());
        }

        return Jwts.signEdDsa(header, payload, spec.privateKey());
    }

    /** Parses token header and payload without verification (for inspection). */
    public static Map<String, Object> parseTokenClaims(String token) {
        Jwts.Decoded jwt = Jwts.parse(token);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("header", jwt.header());
        result.put("payload", jwt.payload());
        return result;
    }

    /** Expectations for {@link #verifyToken}. All fields optional. */
    public record VerifyOptions(
            @Nullable String expectedTyp,
            @Nullable String expectedIss,
            @Nullable String expectedAud,
            @Nullable Map<String, Object> requestSigningJwk) {

        public static VerifyOptions forType(@Nullable String expectedTyp) {
            return new VerifyOptions(expectedTyp, null, null, null);
        }
    }

    /**
     * Verifies a JWT token's signature and claims per draft-11 §9.4.3.
     *
     * @param token the JWT
     * @param jwksFetcher resolves the issuer's JWKS from its identifier ({@code iss})
     * @param options expected claim values; checks are skipped for {@code null} fields
     * @return the verified payload claims
     * @throws TokenException if the token is invalid
     */
    public static Map<String, Object> verifyToken(
            String token, Function<String, Map<String, Object>> jwksFetcher, VerifyOptions options) {
        String tokenType = options.expectedTyp() != null ? options.expectedTyp() : "jwt";
        Jwts.Decoded jwt = TokenSupport.parseOrThrow(token, tokenType);
        long now = TokenSupport.nowEpochSeconds();

        // Step 1: typ.
        if (options.expectedTyp() != null) {
            Object typ = jwt.header().get("typ");
            if (!options.expectedTyp().equals(typ)) {
                throw new TokenException(
                        "Invalid token type: expected " + options.expectedTyp() + ", got " + typ,
                        options.expectedTyp());
            }
        }

        // Step 3: exp (no clock-skew tolerance in draft-11).
        Long exp = jwt.numericClaim("exp");
        if (exp != null && now >= exp) {
            throw new TokenException("Token has expired", tokenType);
        }

        // Step 4: iss.
        String iss = jwt.claim("iss");
        if (options.expectedIss() != null && !options.expectedIss().equals(iss)) {
            throw new TokenException("Invalid issuer: expected " + options.expectedIss() + ", got " + iss, tokenType);
        }

        // Step 5: aud.
        Object aud = jwt.payload().get("aud");
        if (options.expectedAud() != null) {
            boolean matches = aud instanceof List<?> list
                    ? list.contains(options.expectedAud())
                    : options.expectedAud().equals(aud);
            if (!matches) {
                throw new TokenException(
                        "Invalid audience: expected " + options.expectedAud() + ", got " + aud, tokenType);
            }
        }

        if (!jwt.payload().containsKey("jti")) {
            throw new TokenException("Token missing required 'jti' claim", tokenType);
        }

        // Step 7: cnf.jwk matches the key that signed the HTTP request.
        if (options.requestSigningJwk() != null) {
            Object cnf = jwt.payload().get("cnf");
            if (!(cnf instanceof Map<?, ?> cnfMap) || !(cnfMap.get("jwk") instanceof Map<?, ?> tokenJwk)) {
                throw new TokenException("Token missing 'cnf.jwk' claim", tokenType);
            }
            for (String field : List.of("kty", "crv", "x", "y", "n", "e")) {
                Object expected = options.requestSigningJwk().get(field);
                Object actual = tokenJwk.get(field);
                boolean bothAbsent = expected == null && actual == null;
                if (!bothAbsent && (expected == null || !expected.equals(actual))) {
                    throw new TokenException(
                            "cnf.jwk does not match request signing key (field: " + field + ")", tokenType);
                }
            }
        }

        // draft-11 §9.4.3: auth tokens require 'sub'; the person is identified by (iss, sub).
        // The 'agent', 'act' and "at least one of sub or scope" checks are gone.
        if (TYPE.equals(options.expectedTyp()) && jwt.claim("sub") == null) {
            throw new TokenException("Auth token missing required 'sub' claim", TYPE);
        }

        // Step 2 (last, matching the reference implementation): JWKS discovery + signature.
        TokenSupport.verifySignatureViaIssuer(jwt, token, jwksFetcher, tokenType);

        return jwt.payload();
    }
}
