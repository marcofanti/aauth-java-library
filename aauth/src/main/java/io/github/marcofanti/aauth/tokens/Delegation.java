package io.github.marcofanti.aauth.tokens;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * Parent and upstream token bindings for draft-11 delegation (mirrors the reference
 * {@code tokens/delegation}).
 */
public final class Delegation {

    private Delegation() {}

    /**
     * Verifies a sub-agent token against its parent (§10.2.1): the parent is top-level, the child
     * names it as {@code parent_agent}, both share an issuer, and the child has its own key.
     *
     * @return the verified sub-agent token claims
     * @throws TokenException {@code invalid_subagent_token} on a binding violation, or the token
     *     verification code
     */
    public static Map<String, Object> verifySubagentToken(
            String parentToken, String subagentToken, JwksFetcher jwksFetcher) {
        Map<String, Object> parent =
                TokenVerifier.verify(parentToken, jwksFetcher, TokenVerifier.Options.forType(AgentTokens.TYPE));
        Map<String, Object> child =
                TokenVerifier.verify(subagentToken, jwksFetcher, TokenVerifier.Options.forType(AgentTokens.TYPE));
        if (parent.containsKey("parent_agent")
                || !Objects.equals(child.get("parent_agent"), parent.get("sub"))
                || !Objects.equals(child.get("iss"), parent.get("iss"))) {
            throw subagent("Invalid single-level parent/issuer binding");
        }
        Map<String, Object> childJwk = TokenSupport.confirmationJwk(child);
        Map<String, Object> parentJwk = TokenSupport.confirmationJwk(parent);
        if (childJwk != null && parentJwk != null && Jwk.thumbprint(childJwk).equals(Jwk.thumbprint(parentJwk))) {
            throw subagent("Sub-agent requires its own signing key");
        }
        return child;
    }

    /**
     * Expectations for {@link #verifyUpstreamToken}.
     *
     * @param intermediaryAgentToken the intermediary's own agent token; the upstream token's
     *     audience must be its issuer
     * @param personServer the PS the upstream token must name
     * @param trustedAccessServers access servers whose auth tokens this PS federated
     * @param recipientRole {@code ps} (default) or {@code as}
     * @param revocationChecker consulted for the upstream token
     */
    public record UpstreamOptions(
            String intermediaryAgentToken,
            String personServer,
            Set<String> trustedAccessServers,
            String recipientRole,
            @Nullable RevocationChecker revocationChecker) {

        public UpstreamOptions {
            trustedAccessServers = Set.copyOf(trustedAccessServers);
        }

        public static UpstreamOptions of(String intermediaryAgentToken, String personServer) {
            return new UpstreamOptions(intermediaryAgentToken, personServer, Set.of(), "ps", null);
        }
    }

    /**
     * Verifies an upstream person or auth token presented for call chaining (§10.1.1).
     *
     * @return the verified upstream token claims
     * @throws TokenException {@code invalid_upstream_token} / {@code expired_upstream_token} /
     *     {@code revoked_upstream_token}
     */
    public static Map<String, Object> verifyUpstreamToken(
            String token, JwksFetcher jwksFetcher, UpstreamOptions options) {
        Object typ = TokenSupport.parse(token).header().get("typ");
        if (!PersonTokens.TYPE.equals(typ) && !AuthTokens.TYPE.equals(typ)) {
            throw upstream("Expected person or auth upstream token");
        }
        Map<String, Object> intermediary = TokenVerifier.verify(
                options.intermediaryAgentToken(), jwksFetcher, TokenVerifier.Options.forType(AgentTokens.TYPE));
        Map<String, Object> claims;
        try {
            claims = TokenVerifier.verify(
                    token,
                    jwksFetcher,
                    TokenVerifier.Options.forType(null)
                            .withAudience(String.valueOf(intermediary.get("iss")))
                            .withRevocationChecker(options.revocationChecker()));
        } catch (TokenException e) {
            throw TokenSupport.recode(e, "expired_upstream_token", "revoked_upstream_token", "invalid_upstream_token");
        }
        Object ps = PersonTokens.TYPE.equals(typ) ? claims.get("iss") : claims.get("ps");
        String role = options.recipientRole();
        if (!options.personServer().equals(ps) || !("ps".equals(role) || "as".equals(role))) {
            throw upstream("Upstream PS mismatch");
        }
        if ("ps".equals(role)
                && AuthTokens.TYPE.equals(typ)
                && !options.personServer().equals(claims.get("iss"))
                && !options.trustedAccessServers().contains(claims.get("iss"))) {
            throw upstream("Upstream issuer was not federated by this PS");
        }
        return claims;
    }

    private static TokenException subagent(String message) {
        return new TokenException(message, AgentTokens.TYPE, "invalid_subagent_token", null, null);
    }

    private static TokenException upstream(String message) {
        return new TokenException(message, null, "invalid_upstream_token", null, null);
    }
}
