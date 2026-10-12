package io.github.marcofanti.aauth.resource;

import io.github.marcofanti.aauth.ChallengeException;
import io.github.marcofanti.aauth.headers.AAuthHeaders;
import io.github.marcofanti.aauth.headers.AcceptSignatureHeader;
import java.security.PrivateKey;
import java.util.List;
import org.jspecify.annotations.Nullable;

/**
 * Builds AAuth challenges for the resource role.
 *
 * <p>Returns {@link Challenge} (header name + value) so callers know which response header to
 * set: pseudonym/identity levels use {@code Accept-Signature}; the person-token and auth-token
 * levels use {@code AAuth-Requirement} (the auth-token level embeds a resource token).
 */
public final class ChallengeBuilder {

    private final ResourceTokenIssuer tokenIssuer;

    public ChallengeBuilder(String resourceId, PrivateKey resourcePrivateKey, String resourceKid) {
        this.tokenIssuer = new ResourceTokenIssuer(resourceId, resourcePrivateKey, resourceKid);
    }

    /** A challenge as (header name, header value). */
    public record Challenge(String headerName, String headerValue) {}

    /**
     * Parameters for {@link #buildChallenge(Spec)}.
     *
     * @param requireIdentity require verified agent identity
     * @param requirePersonToken require a person token (draft-11 §6.4)
     * @param requireAuthToken require an authorization token (embeds a resource token)
     * @param grant resource-token issuance context — required for auth-token challenges
     * @param components covered components for {@code Accept-Signature}, or {@code null}
     * @param algs acceptable algorithms for {@code Accept-Signature}, or {@code null}
     */
    public record Spec(
            boolean requireIdentity,
            boolean requirePersonToken,
            boolean requireAuthToken,
            ResourceTokenIssuer.@Nullable Grant grant,
            @Nullable List<String> components,
            @Nullable List<String> algs) {

        /** A pseudonym-level challenge (signature required, no identity). */
        public static Spec pseudonym() {
            return new Spec(false, false, false, null, null, null);
        }

        /** An identity-level challenge. */
        public static Spec identity() {
            return new Spec(true, false, false, null, null, null);
        }

        /** A person-token-level challenge (draft-11 §6.4). */
        public static Spec personToken() {
            return new Spec(false, true, false, null, null, null);
        }

        /** An auth-token-level challenge embedding a resource token built from {@code grant}. */
        public static Spec authToken(ResourceTokenIssuer.Grant grant) {
            return new Spec(false, false, true, grant, null, null);
        }
    }

    /**
     * Builds the AAuth challenge for a 401 response.
     *
     * @throws ChallengeException if an auth-token challenge lacks its grant
     */
    public Challenge buildChallenge(Spec spec) {
        if (spec.requirePersonToken()) {
            return new Challenge(AAuthHeaders.HEADER_AAUTH_REQUIREMENT, AAuthHeaders.buildPersonTokenRequirement());
        }
        if (spec.requireAuthToken()) {
            ResourceTokenIssuer.Grant grant = spec.grant();
            if (grant == null) {
                throw new ChallengeException(
                        "grant required for auth-token challenge", AAuthHeaders.REQUIRE_AUTH_TOKEN);
            }
            String resourceToken = tokenIssuer.issueToken(grant);
            return new Challenge(
                    AAuthHeaders.HEADER_AAUTH_REQUIREMENT, AAuthHeaders.buildAuthTokenRequirement(resourceToken));
        }

        String sigkey = spec.requireIdentity() ? AcceptSignatureHeader.SIGKEY_URI : AcceptSignatureHeader.SIGKEY_JKT;
        return new Challenge(
                AAuthHeaders.HEADER_ACCEPT_SIGNATURE,
                AcceptSignatureHeader.build(sigkey, spec.components(), spec.algs()));
    }
}
