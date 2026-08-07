package io.github.marcofanti.aauth.resource;

import io.github.marcofanti.aauth.ChallengeException;
import io.github.marcofanti.aauth.headers.AAuthHeaders;
import io.github.marcofanti.aauth.headers.AcceptSignatureHeader;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import org.jspecify.annotations.Nullable;

/**
 * Builds AAuth challenges for the resource role.
 *
 * <p>Returns {@link Challenge} (header name + value) so callers know which response header to
 * set: pseudonym/identity levels use {@code Accept-Signature}, the auth-token level uses
 * {@code AAuth-Requirement} with an embedded resource token.
 */
public final class ChallengeBuilder {

    private final ResourceTokenIssuer tokenIssuer;

    public ChallengeBuilder(String resourceId, PrivateKey resourcePrivateKey, String resourceKid, String authServer) {
        this.tokenIssuer = new ResourceTokenIssuer(resourceId, resourcePrivateKey, resourceKid, authServer);
    }

    /** A challenge as (header name, header value). */
    public record Challenge(String headerName, String headerValue) {}

    /**
     * Parameters for {@link #buildChallenge(Spec)}.
     *
     * @param requireIdentity require verified agent identity
     * @param requireAuthToken require an authorization token (embeds a resource token)
     * @param agentId agent identifier — required for auth-token challenges
     * @param agentPublicKey agent's public key — required for auth-token challenges
     * @param scope required scope — required for auth-token challenges
     * @param components covered components for {@code Accept-Signature}, or {@code null}
     * @param algs acceptable algorithms for {@code Accept-Signature}, or {@code null}
     */
    public record Spec(
            boolean requireIdentity,
            boolean requireAuthToken,
            @Nullable String agentId,
            @Nullable PublicKey agentPublicKey,
            @Nullable String scope,
            @Nullable List<String> components,
            @Nullable List<String> algs) {

        /** A pseudonym-level challenge (signature required, no identity). */
        public static Spec pseudonym() {
            return new Spec(false, false, null, null, null, null, null);
        }

        /** An identity-level challenge. */
        public static Spec identity() {
            return new Spec(true, false, null, null, null, null, null);
        }

        /** An auth-token-level challenge embedding a resource token for the given agent. */
        public static Spec authToken(String agentId, PublicKey agentPublicKey, String scope) {
            return new Spec(false, true, agentId, agentPublicKey, scope, null, null);
        }
    }

    /**
     * Builds the AAuth challenge for a 401 response.
     *
     * @throws ChallengeException if an auth-token challenge lacks agent details
     */
    public Challenge buildChallenge(Spec spec) {
        if (spec.requireAuthToken()) {
            if (spec.agentId() == null || spec.agentPublicKey() == null || spec.scope() == null) {
                throw new ChallengeException(
                        "agentId, agentPublicKey, and scope required for auth-token challenge",
                        AAuthHeaders.REQUIRE_AUTH_TOKEN);
            }
            String resourceToken = tokenIssuer.issueToken(spec.agentId(), spec.agentPublicKey(), spec.scope(), null);
            return new Challenge(
                    AAuthHeaders.HEADER_AAUTH_REQUIREMENT, AAuthHeaders.buildAuthTokenRequirement(resourceToken));
        }

        String sigkey = spec.requireIdentity() ? AcceptSignatureHeader.SIGKEY_URI : AcceptSignatureHeader.SIGKEY_JKT;
        return new Challenge(
                AAuthHeaders.HEADER_ACCEPT_SIGNATURE,
                AcceptSignatureHeader.build(sigkey, spec.components(), spec.algs()));
    }
}
