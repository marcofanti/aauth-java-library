package io.github.marcofanti.aauth.resource;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.tokens.ResourceTokens;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Issues resource tokens ({@code aa-resource+jwt}) for agents (resource role), draft-11 §6.7.
 *
 * <p>A resource token is issued only after the resource has verified a person token (at the
 * authorization endpoint) or an auth token (on a step-up). The {@link Grant} carries the context
 * drawn from that verified token: its audience ({@code ps}), the person identifier ({@code sub}),
 * and its {@code jti} ({@code presentedJti}).
 */
public final class ResourceTokenIssuer {

    private final String resourceId;
    private final PrivateKey resourcePrivateKey;
    private final String resourceKid;

    /**
     * @param resourceId resource identifier (HTTPS URL)
     * @param resourcePrivateKey resource's Ed25519 signing key
     * @param resourceKid resource's key ID
     */
    public ResourceTokenIssuer(String resourceId, PrivateKey resourcePrivateKey, String resourceKid) {
        this.resourceId = resourceId;
        this.resourcePrivateKey = resourcePrivateKey;
        this.resourceKid = resourceKid;
    }

    /**
     * Context for a resource-token issuance, drawn from the verified presented token.
     *
     * @param agentPublicKey agent's public signing key (bound as {@code agent_jkt})
     * @param scope space-separated scope values
     * @param aud audience: the PS that issued the person token (three-party) or the AS (four-party)
     * @param ps person server identifier (the person token's {@code iss})
     * @param sub person identifier copied from the presented token
     * @param presentedJti {@code jti} of the token the agent presented
     * @param exp expiration (Unix seconds), or {@code null} for the 10-minute default
     * @param missionS256 mission binding copied from the presented token, or {@code null}
     * @param tenant organization context copied from the presented token, or {@code null}
     */
    public record Grant(
            PublicKey agentPublicKey,
            String scope,
            String aud,
            String ps,
            String sub,
            String presentedJti,
            @Nullable Long exp,
            @Nullable String missionS256,
            @Nullable String tenant) {}

    /**
     * Issues a resource token binding the agent's key thumbprint to the requested scope.
     *
     * @throws TokenException if token creation fails
     */
    public String issueToken(Grant grant) {
        try {
            Map<String, Object> agentJwk = Jwk.publicKeyToJwk(grant.agentPublicKey(), null);
            String agentJkt = Jwk.thumbprint(agentJwk);
            return ResourceTokens.create(new ResourceTokens.Spec(
                    resourceId,
                    grant.aud(),
                    agentJkt,
                    grant.scope(),
                    grant.ps(),
                    grant.sub(),
                    grant.presentedJti(),
                    resourcePrivateKey,
                    resourceKid,
                    grant.exp(),
                    grant.missionS256(),
                    grant.tenant(),
                    null,
                    null));
        } catch (TokenException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new TokenException(
                    "Failed to issue resource token: " + e.getMessage(), ResourceTokens.TYPE, null, null, e);
        }
    }
}
