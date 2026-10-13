package io.github.marcofanti.aauth.tokens;

import io.github.marcofanti.aauth.Identifiers;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import java.security.PrivateKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.jspecify.annotations.Nullable;

/**
 * Agent token ({@code aa-agent+jwt}) issuance and verification per AAuth draft-11 §5 (mirrors the
 * reference {@code aauth_signing.tokens.agent_token}).
 */
public final class AgentTokens {

    public static final String TYPE = "aa-agent+jwt";
    public static final String DWK = "aauth-agent.json";

    private AgentTokens() {}

    /**
     * Parameters for {@link #create(Spec)}.
     *
     * @param iss agent provider identifier (server identifier)
     * @param sub agent identifier ({@code aauth:local@domain})
     * @param cnfJwk the agent's public signing key (JWK with a fully-specified {@code alg})
     * @param privateKey agent provider's signing key (Ed25519, P-256 or P-384)
     * @param kid key ID of the agent provider's signing key
     * @param exp expiration (Unix seconds); {@code null} defaults to one hour from now
     * @param aud optional audience restriction ({@code String} or {@code List})
     * @param audSub optional user identifier hint
     * @param ps optional person server identifier (server identifier)
     * @param parentAgent optional parent agent identifier; requires {@code parentToken}
     * @param parentToken verified parent agent token, for sub-agent issuance (§10.2.1)
     * @param jwksFetcher resolves the parent token issuer's JWKS; required with {@code parentToken}
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
            @Nullable String parentAgent,
            @Nullable String parentToken,
            @Nullable JwksFetcher jwksFetcher) {

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
            private @Nullable String parentToken;
            private @Nullable JwksFetcher jwksFetcher;

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

            /** Names the parent agent explicitly; it must equal the verified parent token's {@code sub}. */
            public Builder parentAgent(String parentAgent) {
                this.parentAgent = parentAgent;
                return this;
            }

            /** Issues a sub-agent token under the verified top-level {@code parentToken}. */
            public Builder parentToken(String parentToken, JwksFetcher jwksFetcher) {
                this.parentToken = parentToken;
                this.jwksFetcher = jwksFetcher;
                return this;
            }

            public Spec build() {
                return new Spec(
                        iss, sub, cnfJwk, privateKey, kid, exp, aud, audSub, ps, parentAgent, parentToken, jwksFetcher);
            }
        }
    }

    /**
     * Creates a signed agent token.
     *
     * @throws TokenException if a claim is invalid or a sub-agent binding rule is violated
     */
    public static String create(Spec spec) {
        TokenSupport.checkServer(spec.iss());
        agentIdentifier(spec.sub());
        TokenSupport.validateAlgorithm(spec.cnfJwk());
        long now = TokenSupport.nowEpochSeconds();
        Long requestedExp = spec.exp();
        long exp = requestedExp != null ? requestedExp : now + TokenSupport.MAX_LIFETIME_SECONDS;
        if (exp <= now) {
            throw new TokenException("Invalid agent token expiration", TYPE);
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", spec.iss());
        payload.put("sub", spec.sub());
        payload.put("dwk", DWK);
        payload.put("jti", UUID.randomUUID().toString());
        payload.put("iat", now);
        payload.put("exp", exp);
        payload.put("cnf", Map.of("jwk", spec.cnfJwk()));
        if (spec.ps() != null) {
            payload.put("ps", TokenSupport.checkServer(spec.ps()));
        }
        if (spec.parentAgent() != null || spec.parentToken() != null) {
            payload.put("parent_agent", verifiedParentAgent(spec));
        }
        if (spec.aud() != null) {
            payload.put("aud", spec.aud());
        }
        if (spec.audSub() != null) {
            payload.put("aud_sub", spec.audSub());
        }
        return Jwts.encode(payload, spec.privateKey(), spec.kid(), TYPE);
    }

    /**
     * Sub-agent rules (§10.2.1): the parent is a verified top-level agent under the same issuer,
     * the child's local part is the parent's plus a {@code +discriminator} in the same domain, and
     * the child has its own key.
     */
    private static String verifiedParentAgent(Spec spec) {
        String parentToken = spec.parentToken();
        JwksFetcher fetcher = spec.jwksFetcher();
        if (parentToken == null || fetcher == null) {
            throw new TokenException("Sub-agent issuance requires a verified parent token", TYPE);
        }
        Map<String, Object> parent = TokenVerifier.verifyAgentClaims(parentToken, fetcher, null);
        String parentSub = String.valueOf(parent.get("sub"));
        String namedParent = spec.parentAgent();
        String parentAgent = agentIdentifier(namedParent != null ? namedParent : parentSub);
        if (parent.containsKey("parent_agent")
                || !spec.iss().equals(parent.get("iss"))
                || !parentSub.equals(parentAgent)) {
            throw new TokenException("Sub-agent parent must be a top-level agent under the same issuer", TYPE);
        }
        Identifiers.AgentIdentifier parentId = Identifiers.parseAgentIdentifier(parentAgent);
        Identifiers.AgentIdentifier childId = Identifiers.parseAgentIdentifier(spec.sub());
        if (!childId.domain().equals(parentId.domain())
                || !childId.local().startsWith(parentId.local() + "+")
                || childId.local().length() <= parentId.local().length() + 1) {
            throw new TokenException("Sub-agent identifier requires parent local part plus discriminator", TYPE);
        }
        Map<String, Object> parentJwk = TokenSupport.confirmationJwk(parent);
        if (parentJwk != null && Jwk.thumbprint(spec.cnfJwk()).equals(Jwk.thumbprint(parentJwk))) {
            throw new TokenException("Sub-agent requires its own key", TYPE);
        }
        return parentAgent;
    }

    /**
     * Verifies an agent token and returns its claims.
     *
     * @param jwksFetcher resolves the agent provider's JWKS from {@code (iss, dwk, kid)}
     * @param expectedAud optional expected audience (checked when the token carries {@code aud})
     * @throws TokenException with the wire error code if the token is invalid
     */
    public static Map<String, Object> verify(String token, JwksFetcher jwksFetcher, @Nullable String expectedAud) {
        return TokenVerifier.verify(
                token, jwksFetcher, TokenVerifier.Options.forType(TYPE).withAudience(expectedAud));
    }

    private static String agentIdentifier(String identifier) {
        try {
            return Identifiers.validateAgentIdentifier(identifier);
        } catch (IllegalArgumentException e) {
            throw new TokenException(
                    "Invalid agent identifier: " + identifier, TYPE, TokenSupport.INVALID_JWT, null, e);
        }
    }
}
