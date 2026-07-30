package io.github.marcofanti.aauth.tokens;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.signing.Jwts;
import java.security.PrivateKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

/** Resource token ({@code aa-resource+jwt}) creation and verification per AAuth spec §8.1. */
public final class ResourceTokens {

    public static final String TYPE = "aa-resource+jwt";
    public static final String DWK = "aauth-resource.json";

    private ResourceTokens() {}

    /**
     * Parameters for {@link #create(Spec)}.
     *
     * @param iss resource identifier (HTTPS URL)
     * @param aud auth server identifier (HTTPS URL)
     * @param agent agent identifier
     * @param agentJkt JWK thumbprint of the agent's signing key
     * @param scope space-separated scope values
     * @param privateKey resource's Ed25519 signing key
     * @param kid key ID for the signing key
     * @param exp expiration (Unix seconds); {@code null} defaults to ten minutes from now
     * @param mission optional {@code {"approver": url, "s256": hash}} when mission-aware
     */
    public record Spec(
            String iss,
            String aud,
            String agent,
            String agentJkt,
            String scope,
            PrivateKey privateKey,
            String kid,
            Long exp,
            Map<String, Object> mission) {

        public Spec {
            if (iss == null
                    || aud == null
                    || agent == null
                    || agentJkt == null
                    || scope == null
                    || privateKey == null
                    || kid == null) {
                throw new IllegalArgumentException("iss, aud, agent, agentJkt, scope, privateKey and kid are required");
            }
        }
    }

    /** Creates a signed resource token ({@code aa-resource+jwt}). */
    public static String create(Spec spec) {
        long now = TokenSupport.nowEpochSeconds();
        long exp = spec.exp() != null ? spec.exp() : now + 600;

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", TYPE);
        header.put("alg", "EdDSA");
        header.put("kid", spec.kid());

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", spec.iss());
        payload.put("aud", spec.aud());
        payload.put("dwk", DWK);
        payload.put("jti", UUID.randomUUID().toString());
        payload.put("agent", spec.agent());
        payload.put("agent_jkt", spec.agentJkt());
        payload.put("scope", spec.scope());
        payload.put("iat", now);
        payload.put("exp", exp);
        if (spec.mission() != null) {
            payload.put("mission", spec.mission());
        }

        return Jwts.signEdDsa(header, payload, spec.privateKey());
    }

    /**
     * Verifies a resource token per spec §Resource Token Verification.
     *
     * @param token the resource token
     * @param jwksFetcher resolves the resource's JWKS from its identifier ({@code iss})
     * @param expectedAud optional expected audience (PS or AS identifier)
     * @param expectedAgent optional expected agent identifier
     * @param expectedAgentJkt optional expected JWK thumbprint of the agent's signing key
     * @return the verified payload claims
     * @throws TokenException if the token is invalid
     */
    public static Map<String, Object> verify(
            String token,
            Function<String, Map<String, Object>> jwksFetcher,
            String expectedAud,
            String expectedAgent,
            String expectedAgentJkt) {
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
        Long iat = jwt.numericClaim("iat");
        if (iat != null && iat > now + 60) {
            throw new TokenException("Resource token iat is in the future", TYPE);
        }

        if (expectedAud != null && !expectedAud.equals(jwt.claim("aud"))) {
            throw new TokenException("Invalid audience: expected " + expectedAud + ", got " + jwt.claim("aud"), TYPE);
        }
        if (expectedAgent != null && !expectedAgent.equals(jwt.claim("agent"))) {
            throw new TokenException("Invalid agent: expected " + expectedAgent + ", got " + jwt.claim("agent"), TYPE);
        }
        if (expectedAgentJkt != null && !expectedAgentJkt.equals(jwt.claim("agent_jkt"))) {
            throw new TokenException(
                    "agent_jkt mismatch: expected " + expectedAgentJkt + ", got " + jwt.claim("agent_jkt"), TYPE);
        }

        for (String claim : List.of("jti", "iss", "aud", "agent", "agent_jkt", "scope")) {
            if (!jwt.payload().containsKey(claim)) {
                throw new TokenException("Resource token missing required '" + claim + "' claim", TYPE);
            }
        }

        TokenSupport.verifySignatureViaIssuer(jwt, token, jwksFetcher, TYPE);

        return jwt.payload();
    }
}
