package io.github.marcofanti.aauth.resource;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.tokens.ResourceTokens;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

/** Issues resource tokens ({@code aa-resource+jwt}) for agents (resource role). */
public final class ResourceTokenIssuer {

    private final String resourceId;
    private final PrivateKey resourcePrivateKey;
    private final String resourceKid;
    private final String authServer;

    /**
     * @param resourceId resource identifier (HTTPS URL)
     * @param resourcePrivateKey resource's Ed25519 signing key
     * @param resourceKid resource's key ID
     * @param authServer auth server identifier the token is addressed to ({@code aud})
     */
    public ResourceTokenIssuer(
            String resourceId, PrivateKey resourcePrivateKey, String resourceKid, String authServer) {
        this.resourceId = resourceId;
        this.resourcePrivateKey = resourcePrivateKey;
        this.resourceKid = resourceKid;
        this.authServer = authServer;
    }

    /**
     * Issues a resource token binding the agent's key thumbprint to the requested scope.
     *
     * @param agentId agent identifier
     * @param agentPublicKey agent's public signing key
     * @param scope space-separated scope values
     * @param exp expiration (Unix seconds), or {@code null} for the 10-minute default
     * @throws TokenException if token creation fails
     */
    public String issueToken(String agentId, PublicKey agentPublicKey, String scope, Long exp) {
        try {
            Map<String, Object> agentJwk = Jwk.publicKeyToJwk(agentPublicKey, null);
            String agentJkt = Jwk.thumbprint(agentJwk);
            return ResourceTokens.create(new ResourceTokens.Spec(
                    resourceId, authServer, agentId, agentJkt, scope, resourcePrivateKey, resourceKid, exp, null));
        } catch (TokenException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new TokenException(
                    "Failed to issue resource token: " + e.getMessage(), ResourceTokens.TYPE, null, null, e);
        }
    }
}
