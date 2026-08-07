package io.github.marcofanti.aauth.tokens;

import io.github.marcofanti.aauth.Identifiers;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.signing.Jwts;
import java.security.PrivateKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import org.jspecify.annotations.Nullable;

/** Agent token ({@code aa-agent+jwt}) creation and verification per AAuth spec §7.1 / §16.2.1. */
public final class AgentTokens {

    public static final String TYPE = "aa-agent+jwt";

    private AgentTokens() {}

    /**
     * Parameters for {@link #create(Spec)}.
     *
     * @param iss agent server identifier (HTTPS URL) — also the agent identifier
     * @param sub agent delegate identifier (persists across key rotations)
     * @param cnfJwk agent delegate's public signing key (JWK)
     * @param privateKey agent server's Ed25519 signing key
     * @param kid key ID of the agent server's signing key
     * @param exp expiration (Unix seconds); {@code null} defaults to one hour from now
     * @param aud optional audience restriction (String or List)
     * @param audSub optional user identifier hint for the auth server
     * @param ps optional HTTPS URL of the agent's person server
     */
    public record Spec(
            String iss,
            String sub,
            Map<String, Object> cnfJwk,
            PrivateKey privateKey,
            String kid,
            @Nullable Long exp,
            @Nullable Object aud,
            @Nullable String audSub,
            @Nullable String ps,
            @Nullable String parentAgent) {

        public Spec {
            if (iss == null || sub == null || cnfJwk == null || privateKey == null || kid == null) {
                throw new IllegalArgumentException("iss, sub, cnfJwk, privateKey and kid are required");
            }
        }

        public static Builder builder(String iss, String sub, Map<String, Object> cnfJwk, PrivateKey key, String kid) {
            return new Builder(iss, sub, cnfJwk, key, kid);
        }

        /** Builder for optional claims. */
        public static final class Builder {
            private final String iss;
            private final String sub;
            private final Map<String, Object> cnfJwk;
            private final PrivateKey privateKey;
            private final String kid;
            private @Nullable Long exp;
            private @Nullable Object aud;
            private @Nullable String audSub;
            private @Nullable String ps;
            private @Nullable String parentAgent;

            private Builder(String iss, String sub, Map<String, Object> cnfJwk, PrivateKey privateKey, String kid) {
                this.iss = iss;
                this.sub = sub;
                this.cnfJwk = cnfJwk;
                this.privateKey = privateKey;
                this.kid = kid;
            }

            public Builder exp(Long exp) {
                this.exp = exp;
                return this;
            }

            public Builder aud(Object aud) {
                this.aud = aud;
                return this;
            }

            public Builder audSub(String audSub) {
                this.audSub = audSub;
                return this;
            }

            public Builder ps(String ps) {
                this.ps = ps;
                return this;
            }

            public Builder parentAgent(String parentAgent) {
                this.parentAgent = parentAgent;
                return this;
            }

            public Spec build() {
                return new Spec(iss, sub, cnfJwk, privateKey, kid, exp, aud, audSub, ps, parentAgent);
            }
        }
    }

    /** Creates a signed agent token ({@code aa-agent+jwt}). */
    public static String create(Spec spec) {
        long now = TokenSupport.nowEpochSeconds();
        long exp = spec.exp() != null ? spec.exp() : now + 3600;

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", TYPE);
        header.put("alg", "Ed25519");
        header.put("kid", spec.kid());

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", spec.iss());
        payload.put("sub", spec.sub());
        payload.put("dwk", "aauth-agent.json");
        payload.put("jti", UUID.randomUUID().toString());
        payload.put("cnf", Map.of("jwk", spec.cnfJwk()));
        payload.put("iat", now);
        payload.put("exp", exp);
        if (spec.aud() != null) {
            payload.put("aud", spec.aud());
        }
        if (spec.audSub() != null) {
            payload.put("aud_sub", spec.audSub());
        }
        if (spec.ps() != null) {
            payload.put("ps", spec.ps());
        }
        if (spec.parentAgent() != null) {
            payload.put("parent_agent", spec.parentAgent());
        }

        return Jwts.signEdDsa(header, payload, spec.privateKey());
    }

    /**
     * Verifies an agent token per AAuth spec §16.2.1 and returns its payload claims.
     *
     * @param token the agent token
     * @param jwksFetcher resolves the agent server's JWKS from its identifier ({@code iss})
     * @param expectedAud optional expected audience
     * @throws TokenException if the token is invalid
     */
    public static Map<String, Object> verify(
            String token, Function<String, Map<String, Object>> jwksFetcher, String expectedAud) {
        Jwts.Decoded jwt = TokenSupport.parseOrThrow(token, TYPE);

        Object typ = jwt.header().get("typ");
        if (!TYPE.equals(typ)) {
            throw new TokenException("Invalid token type: expected " + TYPE + ", got " + typ, TYPE);
        }
        if (jwt.header().get("kid") == null) {
            throw new TokenException("Token header missing 'kid'", TYPE);
        }
        if (jwt.claim("iss") == null) {
            throw new TokenException("Token payload missing 'iss'", TYPE);
        }
        if (!jwt.payload().containsKey("jti")) {
            throw new TokenException("Token missing required 'jti' claim", TYPE);
        }
        if (jwt.claim("sub") == null) {
            throw new TokenException("Token missing 'sub' claim (agent delegate identifier)", TYPE);
        }

        TokenSupport.verifySignatureViaIssuer(jwt, token, jwksFetcher, TYPE);

        Long exp = jwt.numericClaim("exp");
        if (exp == null) {
            throw new TokenException("Token missing 'exp' claim", TYPE);
        }
        if (TokenSupport.nowEpochSeconds() >= exp) {
            throw new TokenException("Token has expired", TYPE);
        }

        Object aud = jwt.payload().get("aud");
        if (aud != null && expectedAud != null) {
            boolean matches = aud instanceof List<?> list ? list.contains(expectedAud) : aud.equals(expectedAud);
            if (!matches) {
                throw new TokenException("Invalid audience: expected " + expectedAud + ", got " + aud, TYPE);
            }
        }

        Object cnf = jwt.payload().get("cnf");
        if (!(cnf instanceof Map<?, ?> cnfMap)) {
            throw new TokenException("Token missing 'cnf' claim", TYPE);
        }
        if (!(cnfMap.get("jwk") instanceof Map)) {
            throw new TokenException("Token missing 'cnf.jwk' claim", TYPE);
        }

        // Draft-10 §5.2.4 steps 6-7: validate ps and parent_agent when present. The ps claim is
        // checked as a well-formed http(s) server URL (not strict-HTTPS) so non-TLS dev/demo
        // origins verify; enforcing HTTPS-in-production is a deployment policy, not a token check.
        String ps = jwt.claim("ps");
        if (ps != null) {
            try {
                Identifiers.validateServerUrl(ps);
            } catch (IllegalArgumentException e) {
                throw new TokenException("Invalid 'ps' claim: " + e.getMessage(), TYPE, null, null, e);
            }
        }
        String parentAgent = jwt.claim("parent_agent");
        if (parentAgent != null) {
            try {
                Identifiers.validateAgentIdentifier(parentAgent);
            } catch (IllegalArgumentException e) {
                throw new TokenException("Invalid 'parent_agent' claim: " + e.getMessage(), TYPE, null, null, e);
            }
        }

        return jwt.payload();
    }
}
