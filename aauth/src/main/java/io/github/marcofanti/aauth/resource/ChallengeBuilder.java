package io.github.marcofanti.aauth.resource;

import io.github.marcofanti.aauth.headers.AAuthHeaders;
import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.tokens.ResourceTokens;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.function.UnaryOperator;
import org.jspecify.annotations.Nullable;

/**
 * Builds draft-11 credential requirements for the resource role (mirrors the reference
 * {@code resource/challenge_builder}). Every challenge is an {@code AAuth-Requirement} header:
 * {@code agent-token} by default, {@code person-token} when the resource needs the person, and
 * {@code auth-token} — embedding a resource token — once a person or auth token was presented.
 */
public final class ChallengeBuilder {

    private final ResourceTokenIssuer tokenIssuer;

    /**
     * @param resourceId resource identifier
     * @param resourcePrivateKey resource's signing key
     * @param resourceKid resource's key ID
     * @param authServer the resource token's audience (PS or AS)
     * @param jwksFetcher resolves presented-token issuers' JWKS
     */
    public ChallengeBuilder(
            String resourceId,
            PrivateKey resourcePrivateKey,
            String resourceKid,
            String authServer,
            JwksFetcher jwksFetcher) {
        this.tokenIssuer =
                new ResourceTokenIssuer(resourceId, resourcePrivateKey, resourceKid, authServer, jwksFetcher, null);
    }

    /** A challenge as (header name, header value). */
    public record Challenge(String headerName, String headerValue) {}

    /**
     * Parameters for {@link #buildChallenge(Spec)}.
     *
     * @param requirePersonToken require a person token (draft-11 §6.4)
     * @param requireAuthToken require an auth token; without a presented token this degrades to a
     *     person-token requirement
     * @param presentedToken the person or auth token the agent presented, or {@code null}
     * @param agentPublicKey the key that signed the request — required with a presented token
     * @param scope requested scopes for the embedded resource token, or {@code null}
     * @param options sets optional resource-token claims, or {@code null}
     */
    public record Spec(
            boolean requirePersonToken,
            boolean requireAuthToken,
            @Nullable String presentedToken,
            @Nullable PublicKey agentPublicKey,
            @Nullable String scope,
            @Nullable UnaryOperator<ResourceTokens.Spec.Builder> options) {

        /** An agent-token challenge (the default). */
        public static Spec agentToken() {
            return new Spec(false, false, null, null, null, null);
        }

        /** A person-token challenge. */
        public static Spec personToken() {
            return new Spec(true, false, null, null, null, null);
        }

        /** An auth-token challenge for a request that presented {@code presentedToken}. */
        public static Spec authToken(String presentedToken, PublicKey agentPublicKey, @Nullable String scope) {
            return new Spec(false, true, presentedToken, agentPublicKey, scope, null);
        }
    }

    /**
     * Builds the challenge for a 401 response.
     *
     * @throws io.github.marcofanti.aauth.TokenException if the presented token fails verification
     * @throws IllegalArgumentException if a presented token comes without the agent's key
     */
    public Challenge buildChallenge(Spec spec) {
        if (spec.requireAuthToken()) {
            String presentedToken = spec.presentedToken();
            if (presentedToken == null || presentedToken.isEmpty()) {
                return requirement(AAuthHeaders.buildPersonTokenRequirement());
            }
            PublicKey agentPublicKey = spec.agentPublicKey();
            if (agentPublicKey == null) {
                throw new IllegalArgumentException("agentPublicKey is required with a presented token");
            }
            String resourceToken =
                    tokenIssuer.issueToken(presentedToken, agentPublicKey, spec.scope(), null, spec.options());
            return requirement(AAuthHeaders.buildAuthTokenRequirement(resourceToken));
        }
        if (spec.requirePersonToken()) {
            return requirement(AAuthHeaders.buildPersonTokenRequirement());
        }
        return requirement(AAuthHeaders.buildAgentTokenRequirement());
    }

    private static Challenge requirement(String value) {
        return new Challenge(AAuthHeaders.HEADER_AAUTH_REQUIREMENT, value);
    }
}
