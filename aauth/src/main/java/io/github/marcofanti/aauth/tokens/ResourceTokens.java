package io.github.marcofanti.aauth.tokens;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.signing.Jwts;
import java.security.PrivateKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import org.jspecify.annotations.Nullable;

/** Resource token ({@code aa-resource+jwt}) creation and verification per AAuth draft-11 §6.7. */
public final class ResourceTokens {

    public static final String TYPE = "aa-resource+jwt";
    public static final String DWK = "aauth-resource.json";

    private ResourceTokens() {}

    /**
     * Parameters for {@link #create(Spec)}.
     *
     * <p>Draft-11 removed {@code agent} and the {@code mission} object; the person is now named by
     * {@code (ps, sub)} and the mission rides as {@code mission_s256}. {@code presentedJti} is the
     * {@code jti} of the token (person or auth) the agent presented to obtain this resource token.
     *
     * @param iss resource identifier (HTTPS URL)
     * @param aud audience: the PS that issued the person token (three-party) or the AS (four-party)
     * @param agentJkt JWK thumbprint of the agent's signing key
     * @param scope space-separated scope values
     * @param ps the person server — the {@code iss} of the person token, or the auth token's
     *     {@code ps}
     * @param sub the person identifier copied from the presented token
     * @param presentedJti {@code jti} of the token the agent presented
     * @param privateKey resource's Ed25519 signing key
     * @param kid key ID for the signing key
     * @param exp expiration (Unix seconds); {@code null} defaults to ten minutes from now
     * @param missionS256 optional mission binding; REQUIRED when the presented token carried one
     * @param tenant optional organization context copied from the presented token
     * @param loginHint optional login hint for the authorization server
     * @param account optional account identifier at the resource (draft-11 §12.3)
     */
    public record Spec(
            String iss,
            String aud,
            String agentJkt,
            String scope,
            String ps,
            String sub,
            String presentedJti,
            PrivateKey privateKey,
            String kid,
            @Nullable Long exp,
            @Nullable String missionS256,
            @Nullable String tenant,
            @Nullable String loginHint,
            @Nullable String account) {

        public Spec {
            if (iss == null
                    || aud == null
                    || agentJkt == null
                    || scope == null
                    || ps == null
                    || sub == null
                    || presentedJti == null
                    || privateKey == null
                    || kid == null) {
                throw new IllegalArgumentException(
                        "iss, aud, agentJkt, scope, ps, sub, presentedJti, privateKey and kid are required");
            }
        }
    }

    /** Creates a signed resource token ({@code aa-resource+jwt}). */
    public static String create(Spec spec) {
        long now = TokenSupport.nowEpochSeconds();
        Long requestedExp = spec.exp();
        long exp = requestedExp != null ? requestedExp : now + 600;

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", TYPE);
        header.put("alg", "Ed25519");
        header.put("kid", spec.kid());

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", spec.iss());
        payload.put("aud", spec.aud());
        payload.put("dwk", DWK);
        payload.put("jti", UUID.randomUUID().toString());
        payload.put("ps", spec.ps());
        payload.put("sub", spec.sub());
        payload.put("agent_jkt", spec.agentJkt());
        payload.put("presented_jti", spec.presentedJti());
        payload.put("scope", spec.scope());
        payload.put("iat", now);
        payload.put("exp", exp);
        if (spec.missionS256() != null) {
            payload.put("mission_s256", spec.missionS256());
        }
        if (spec.tenant() != null) {
            payload.put("tenant", spec.tenant());
        }
        if (spec.loginHint() != null) {
            payload.put("login_hint", spec.loginHint());
        }
        if (spec.account() != null) {
            payload.put("account", spec.account());
        }

        return Jwts.signEdDsa(header, payload, spec.privateKey());
    }

    /**
     * Verifies a resource token per draft-11 §6.7.3 and §9.4.
     *
     * @param token the resource token
     * @param jwksFetcher resolves the resource's JWKS from its identifier ({@code iss})
     * @param expectedAud optional expected audience (PS or AS identifier)
     * @param expectedAgentJkt optional expected JWK thumbprint of the agent's signing key
     * @return the verified payload claims
     * @throws TokenException if the token is invalid
     */
    public static Map<String, Object> verify(
            String token,
            Function<String, Map<String, Object>> jwksFetcher,
            @Nullable String expectedAud,
            @Nullable String expectedAgentJkt) {
        Jwts.Decoded jwt = TokenSupport.parseOrThrow(token, TYPE);
        long now = TokenSupport.nowEpochSeconds();

        Object typ = jwt.header().get("typ");
        if (!TYPE.equals(typ)) {
            throw new TokenException("Invalid token type: expected " + TYPE + ", got " + typ, TYPE);
        }

        String dwk = jwt.claim("dwk");
        if (!DWK.equals(dwk)) {
            throw new TokenException("Invalid dwk: expected " + DWK + ", got " + dwk, TYPE);
        }

        Long exp = jwt.numericClaim("exp");
        if (exp == null) {
            throw new TokenException("Resource token missing 'exp' claim", TYPE);
        }
        if (now >= exp) {
            throw new TokenException("Resource token has expired", TYPE);
        }

        if (expectedAud != null && !expectedAud.equals(jwt.claim("aud"))) {
            throw new TokenException("Invalid audience: expected " + expectedAud + ", got " + jwt.claim("aud"), TYPE);
        }
        if (expectedAgentJkt != null && !expectedAgentJkt.equals(jwt.claim("agent_jkt"))) {
            throw new TokenException(
                    "agent_jkt mismatch: expected " + expectedAgentJkt + ", got " + jwt.claim("agent_jkt"), TYPE);
        }

        for (String claim : List.of("jti", "iss", "aud", "ps", "sub", "agent_jkt", "presented_jti", "scope")) {
            if (!jwt.payload().containsKey(claim)) {
                throw new TokenException("Resource token missing required '" + claim + "' claim", TYPE);
            }
        }

        TokenSupport.verifySignatureViaIssuer(jwt, token, jwksFetcher, TYPE);

        return jwt.payload();
    }
}
