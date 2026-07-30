package io.github.marcofanti.aauth.tokens;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.signing.Jwts;
import java.security.PrivateKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

/** Auth token ({@code aa-auth+jwt}) creation and verification per AAuth spec §9.1. */
public final class AuthTokens {

    public static final String TYPE = "aa-auth+jwt";

    private AuthTokens() {}

    /**
     * Parameters for {@link #create(Spec)}.
     *
     * @param iss auth server identifier (HTTPS URL)
     * @param aud resource identifier, or agent identifier for self-access
     * @param agent agent identifier ({@code aauth:local@domain}) — required
     * @param cnfJwk agent's public signing key (JWK) — required
     * @param privateKey auth server's Ed25519 signing key
     * @param kid key ID for the signing key
     * @param act actor claim per RFC 8693 §4.1 — required (e.g. {@code {"sub": agentId}})
     * @param scope authorized scopes (at least one of scope or sub must be present)
     * @param sub user identifier (at least one of scope or sub must be present)
     * @param exp expiration (Unix seconds); {@code null} defaults to one hour from now
     * @param mission optional mission object when issued in mission context
     * @param dwk metadata document for key discovery; defaults to {@code aauth-access.json}
     */
    public record Spec(
            String iss,
            String aud,
            String agent,
            Map<String, Object> cnfJwk,
            PrivateKey privateKey,
            String kid,
            Map<String, Object> act,
            String scope,
            String sub,
            Long exp,
            Map<String, Object> mission,
            String dwk) {

        public Spec {
            if (agent == null || agent.isEmpty()) {
                throw new TokenException("'agent' claim is required in auth token", TYPE);
            }
            if ((sub == null || sub.isEmpty()) && (scope == null || scope.isEmpty())) {
                throw new TokenException("At least one of 'sub' or 'scope' must be present in auth token", TYPE);
            }
            if (iss == null || aud == null || cnfJwk == null || privateKey == null || kid == null || act == null) {
                throw new IllegalArgumentException("iss, aud, cnfJwk, privateKey, kid and act are required");
            }
            dwk = dwk == null ? "aauth-access.json" : dwk;
        }

        public static Builder builder(String iss, String aud, String agent) {
            return new Builder(iss, aud, agent);
        }

        /** Builder for {@link Spec}. */
        public static final class Builder {
            private final String iss;
            private final String aud;
            private final String agent;
            private Map<String, Object> cnfJwk;
            private PrivateKey privateKey;
            private String kid;
            private Map<String, Object> act;
            private String scope;
            private String sub;
            private Long exp;
            private Map<String, Object> mission;
            private String dwk;

            private Builder(String iss, String aud, String agent) {
                this.iss = iss;
                this.aud = aud;
                this.agent = agent;
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

            public Builder act(Map<String, Object> act) {
                this.act = act;
                return this;
            }

            public Builder scope(String scope) {
                this.scope = scope;
                return this;
            }

            public Builder sub(String sub) {
                this.sub = sub;
                return this;
            }

            public Builder exp(Long exp) {
                this.exp = exp;
                return this;
            }

            public Builder mission(Map<String, Object> mission) {
                this.mission = mission;
                return this;
            }

            public Builder dwk(String dwk) {
                this.dwk = dwk;
                return this;
            }

            public Spec build() {
                return new Spec(iss, aud, agent, cnfJwk, privateKey, kid, act, scope, sub, exp, mission, dwk);
            }
        }
    }

    /** Creates a signed auth token ({@code aa-auth+jwt}). */
    public static String create(Spec spec) {
        long now = TokenSupport.nowEpochSeconds();
        long exp = spec.exp() != null ? spec.exp() : now + 3600;

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", TYPE);
        header.put("alg", "EdDSA");
        header.put("kid", spec.kid());

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", spec.iss());
        payload.put("aud", spec.aud());
        payload.put("dwk", spec.dwk());
        payload.put("jti", UUID.randomUUID().toString());
        payload.put("agent", spec.agent());
        payload.put("cnf", Map.of("jwk", spec.cnfJwk()));
        payload.put("act", spec.act());
        payload.put("iat", now);
        payload.put("exp", exp);
        if (spec.sub() != null) {
            payload.put("sub", spec.sub());
        }
        if (spec.scope() != null) {
            payload.put("scope", spec.scope());
        }
        if (spec.mission() != null) {
            payload.put("mission", spec.mission());
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
            String expectedTyp,
            String expectedIss,
            String expectedAud,
            String expectedAgent,
            Map<String, Object> requestSigningJwk) {

        public static VerifyOptions forType(String expectedTyp) {
            return new VerifyOptions(expectedTyp, null, null, null, null);
        }
    }

    /**
     * Verifies a JWT token's signature and claims per spec §Auth Token Verification.
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

        // Step 3: exp and iat (60s clock skew allowance for iat).
        Long exp = jwt.numericClaim("exp");
        if (exp != null && now >= exp) {
            throw new TokenException("Token has expired", tokenType);
        }
        Long iat = jwt.numericClaim("iat");
        if (iat != null && iat > now + 60) {
            throw new TokenException("Token iat is in the future", tokenType);
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

        // Step 6: agent matches the request signing context.
        if (options.expectedAgent() != null) {
            String agent = jwt.claim("agent");
            if (!options.expectedAgent().equals(agent)) {
                throw new TokenException(
                        "Invalid agent: expected " + options.expectedAgent() + ", got " + agent, tokenType);
            }
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

        // Step 8: act claim (required for auth tokens).
        if (TYPE.equals(options.expectedTyp())) {
            Object act = jwt.payload().get("act");
            if (!(act instanceof Map<?, ?> actMap)) {
                throw new TokenException("Auth token missing required 'act' claim", TYPE);
            }
            if (options.expectedAgent() != null && !options.expectedAgent().equals(actMap.get("sub"))) {
                throw new TokenException(
                        "act.sub does not match agent: expected " + options.expectedAgent() + ", got "
                                + actMap.get("sub"),
                        TYPE);
            }
            // Step 9: at least one of sub or scope.
            if (jwt.claim("sub") == null && jwt.claim("scope") == null) {
                throw new TokenException("Auth token must contain at least one of 'sub' or 'scope'", TYPE);
            }
        }

        // Step 2 (last, matching the reference implementation): JWKS discovery + signature.
        TokenSupport.verifySignatureViaIssuer(jwt, token, jwksFetcher, tokenType);

        return jwt.payload();
    }
}
