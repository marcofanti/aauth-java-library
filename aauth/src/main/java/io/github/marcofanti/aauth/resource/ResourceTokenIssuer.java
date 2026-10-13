package io.github.marcofanti.aauth.resource;

import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.tokens.ResourceTokens;
import io.github.marcofanti.aauth.tokens.RevocationChecker;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.function.UnaryOperator;
import org.jspecify.annotations.Nullable;

/**
 * Issues resource tokens ({@code aa-resource+jwt}) for the resource role (draft-11 §6.7, mirrors
 * the reference {@code resource/token_issuer}). Issuance requires the verified person or auth token
 * the agent presented; its binding claims are derived from that token.
 */
public final class ResourceTokenIssuer {

    private final String resourceId;
    private final PrivateKey resourcePrivateKey;
    private final String resourceKid;
    private final String authServer;
    private final JwksFetcher jwksFetcher;
    private final @Nullable RevocationChecker revocationChecker;

    /**
     * @param resourceId resource identifier (server identifier)
     * @param resourcePrivateKey resource's signing key
     * @param resourceKid resource's key ID
     * @param authServer the token's audience: the PS (three-party) or the AS (four-party)
     * @param jwksFetcher resolves presented-token issuers' JWKS from {@code (iss, dwk, kid)}
     * @param revocationChecker consulted for the presented token, or {@code null}
     */
    public ResourceTokenIssuer(
            String resourceId,
            PrivateKey resourcePrivateKey,
            String resourceKid,
            String authServer,
            JwksFetcher jwksFetcher,
            @Nullable RevocationChecker revocationChecker) {
        this.resourceId = resourceId;
        this.resourcePrivateKey = resourcePrivateKey;
        this.resourceKid = resourceKid;
        this.authServer = authServer;
        this.jwksFetcher = jwksFetcher;
        this.revocationChecker = revocationChecker;
    }

    /**
     * Issues a resource token bound to the agent's key and the presented token.
     *
     * @param presentedToken the person or auth token the agent presented
     * @param agentPublicKey the key that signed the agent's request
     * @param scope requested scopes, or {@code null}
     * @param exp expiration (Unix seconds), or {@code null} for the five-minute default
     * @param options sets optional claims ({@code account}, {@code login_hint},
     *     {@code interaction}), or {@code null}
     * @throws io.github.marcofanti.aauth.TokenException if the presented token fails verification
     */
    public String issueToken(
            String presentedToken,
            PublicKey agentPublicKey,
            @Nullable String scope,
            @Nullable Long exp,
            @Nullable UnaryOperator<ResourceTokens.Spec.Builder> options) {
        ResourceTokens.Spec.Builder builder = ResourceTokens.Spec.builder(
                        resourceId,
                        authServer,
                        Jwk.thumbprint(Jwk.publicKeyToJwk(agentPublicKey, null)),
                        resourcePrivateKey,
                        resourceKid)
                .presentedToken(presentedToken, jwksFetcher)
                .scope(scope)
                .exp(exp)
                .revocationChecker(revocationChecker);
        return ResourceTokens.create((options == null ? builder : options.apply(builder)).build());
    }
}
