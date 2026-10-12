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

/**
 * Person token ({@code aa-person+jwt}) creation and verification per AAuth draft-11 §7.1.
 *
 * <p>New in draft-11: the person server issues a person token that identifies the person to one
 * resource. The agent presents it (in {@code Signature-Key}, {@code sig=jwt}) at the resource's
 * authorization endpoint in place of its agent token, and the resource verifies it before issuing a
 * resource token. The person is identified by the {@code (iss, sub)} pair; {@code sub} is opaque and
 * MUST NOT be matched across issuers.
 */
public final class PersonTokens {

    public static final String TYPE = "aa-person+jwt";
    public static final String DWK = "aauth-person.json";

    /** Maximum lifetime of a person token ({@code exp - iat}), draft-11 §7.1.4. */
    private static final long MAX_LIFETIME_SECONDS = 3600;

    private PersonTokens() {}

    /**
     * Parameters for {@link #create(Spec)}.
     *
     * @param iss person server identifier (HTTPS URL)
     * @param sub opaque person identifier at this PS (stable across the person's agents)
     * @param aud resource identifier the token is scoped to
     * @param cnfJwk agent's public signing key (JWK) bound to the token
     * @param privateKey person server's Ed25519 signing key
     * @param kid key ID for the signing key
     * @param exp expiration (Unix seconds); {@code null} defaults to one hour from now
     * @param missionS256 optional mission binding (unpadded base64url SHA-256 of the mission blob)
     * @param tenant optional organization context (not part of the identifier)
     * @param account optional account selection echoed to the resource
     * @param scope optional space-separated requested scopes
     * @param capabilities optional capability values the agent declared
     */
    public record Spec(
            String iss,
            String sub,
            String aud,
            Map<String, Object> cnfJwk,
            PrivateKey privateKey,
            String kid,
            @Nullable Long exp,
            @Nullable String missionS256,
            @Nullable String tenant,
            @Nullable String account,
            @Nullable String scope,
            @Nullable List<String> capabilities) {

        public Spec {
            if (iss == null || sub == null || aud == null || cnfJwk == null || privateKey == null || kid == null) {
                throw new IllegalArgumentException("iss, sub, aud, cnfJwk, privateKey and kid are required");
            }
        }
    }

    /** Creates a signed person token ({@code aa-person+jwt}). */
    public static String create(Spec spec) {
        long now = TokenSupport.nowEpochSeconds();
        Long requestedExp = spec.exp();
        long exp = requestedExp != null ? requestedExp : now + MAX_LIFETIME_SECONDS;

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", TYPE);
        header.put("alg", "Ed25519");
        header.put("kid", spec.kid());

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", spec.iss());
        payload.put("sub", spec.sub());
        payload.put("aud", spec.aud());
        payload.put("dwk", DWK);
        payload.put("jti", UUID.randomUUID().toString());
        payload.put("cnf", Map.of("jwk", spec.cnfJwk()));
        payload.put("iat", now);
        payload.put("exp", exp);
        if (spec.missionS256() != null) {
            payload.put("mission_s256", spec.missionS256());
        }
        if (spec.tenant() != null) {
            payload.put("tenant", spec.tenant());
        }
        if (spec.account() != null) {
            payload.put("account", spec.account());
        }
        if (spec.scope() != null) {
            payload.put("scope", spec.scope());
        }
        if (spec.capabilities() != null) {
            payload.put("capabilities", spec.capabilities());
        }

        return Jwts.signEdDsa(header, payload, spec.privateKey());
    }

    /**
     * Verifies a person token per draft-11 §7.1.4 / RS-10 and returns its payload claims.
     *
     * <p>Checks {@code typ}, {@code dwk}, audience, lifetime bound, and {@code cnf.jwk} presence,
     * then verifies the signature against the issuer's JWKS. The caller identifies the person by the
     * returned {@code (iss, sub)} pair.
     *
     * @param token the person token
     * @param jwksFetcher resolves the PS's JWKS from its identifier ({@code iss})
     * @param expectedAud the verifying resource's identifier
     * @throws TokenException if the token is invalid
     */
    public static Map<String, Object> verify(
            String token, Function<String, Map<String, Object>> jwksFetcher, String expectedAud) {
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

        for (String claim : List.of("iss", "sub", "aud", "jti", "iat", "exp")) {
            if (!jwt.payload().containsKey(claim)) {
                throw new TokenException("Person token missing required '" + claim + "' claim", TYPE);
            }
        }

        // draft-11 §7.1.4: exp has no clock-skew tolerance.
        Long exp = jwt.numericClaim("exp");
        if (exp == null || now >= exp) {
            throw new TokenException("Person token has expired", TYPE);
        }
        Long iat = jwt.numericClaim("iat");
        if (iat != null && exp - iat > MAX_LIFETIME_SECONDS) {
            throw new TokenException("Person token lifetime exceeds one hour", TYPE);
        }

        if (!expectedAud.equals(jwt.claim("aud"))) {
            throw new TokenException("Invalid audience: expected " + expectedAud + ", got " + jwt.claim("aud"), TYPE);
        }

        Object cnf = jwt.payload().get("cnf");
        if (!(cnf instanceof Map<?, ?> cnfMap) || !(cnfMap.get("jwk") instanceof Map)) {
            throw new TokenException("Person token missing 'cnf.jwk' claim", TYPE);
        }

        TokenSupport.verifySignatureViaIssuer(jwt, token, jwksFetcher, TYPE);

        return jwt.payload();
    }
}
