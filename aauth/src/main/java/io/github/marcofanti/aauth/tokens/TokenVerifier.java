package io.github.marcofanti.aauth.tokens;

import io.github.marcofanti.aauth.Identifiers;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.signing.JoseException;
import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Draft-11 token verification for every AAuth token type (mirrors the reference
 * {@code tokens/common.verify_token}). Failures throw {@link TokenException} carrying the wire
 * error code ({@code invalid_jwt}, {@code expired_jwt}, {@code unknown_key}, {@code invalid_key},
 * {@code unsupported_algorithm}, {@code revoked_jwt}).
 */
public final class TokenVerifier {

    /** Accepted {@code dwk} values per token type. */
    private static final Map<String, List<String>> DWKS = Map.of(
            AgentTokens.TYPE, List.of("aauth-agent.json"),
            PersonTokens.TYPE, List.of("aauth-person.json"),
            AuthTokens.TYPE, List.of("aauth-person.json", "aauth-access.json"),
            ResourceTokens.TYPE, List.of("aauth-resource.json"));

    private TokenVerifier() {}

    /**
     * Verification expectations; every field is optional.
     *
     * @param expectedTyp required {@code typ}, or {@code null} to accept any AAuth token type
     * @param expectedIss required {@code iss}
     * @param expectedAud required {@code aud} (for agent tokens: must be among {@code aud})
     * @param requestSigningJwk the HTTP request's signing key; {@code cnf.jwk} must have its thumbprint
     * @param revocationChecker consulted with {@code (iss, jti)}; a hit fails with {@code revoked_jwt}
     */
    public record Options(
            @Nullable String expectedTyp,
            @Nullable String expectedIss,
            @Nullable String expectedAud,
            @Nullable Map<String, Object> requestSigningJwk,
            @Nullable RevocationChecker revocationChecker) {

        /** Expect only the given {@code typ}. */
        public static Options forType(@Nullable String expectedTyp) {
            return new Options(expectedTyp, null, null, null, null);
        }

        public Options withAudience(@Nullable String aud) {
            return new Options(expectedTyp, expectedIss, aud, requestSigningJwk, revocationChecker);
        }

        public Options withIssuer(@Nullable String iss) {
            return new Options(expectedTyp, iss, expectedAud, requestSigningJwk, revocationChecker);
        }

        public Options withRequestSigningJwk(@Nullable Map<String, Object> jwk) {
            return new Options(expectedTyp, expectedIss, expectedAud, jwk, revocationChecker);
        }

        public Options withRevocationChecker(@Nullable RevocationChecker checker) {
            return new Options(expectedTyp, expectedIss, expectedAud, requestSigningJwk, checker);
        }

        Options withType(String typ) {
            return new Options(typ, expectedIss, expectedAud, requestSigningJwk, revocationChecker);
        }
    }

    /**
     * Verifies an AAuth token (agent, person, auth or resource) and returns its claims.
     *
     * @param jwksFetcher resolves the issuer's JWKS from {@code (iss, dwk, kid)}
     * @throws TokenException with the wire error code on any failure
     */
    public static Map<String, Object> verify(String token, JwksFetcher jwksFetcher, Options options) {
        Jwts.Decoded jwt = TokenSupport.parse(token);
        String typ = jwt.header().get("typ") instanceof String value ? value : null;
        String expectedTyp = options.expectedTyp();
        List<String> dwks = typ == null ? null : DWKS.get(typ);
        if (typ == null || dwks == null || (expectedTyp != null && !expectedTyp.equals(typ))) {
            throw new TokenException("Unexpected token type: " + typ, typ, TokenSupport.INVALID_JWT, null, null);
        }
        if (!dwks.contains(jwt.payload().get("dwk"))) {
            throw new TokenException("Invalid dwk for token type", typ, TokenSupport.INVALID_JWT, null, null);
        }
        String iss = TokenSupport.checkServer(jwt.payload().get("iss"));
        String expectedIss = options.expectedIss();
        if (expectedIss != null && !expectedIss.equals(iss)) {
            throw new TokenException("Issuer mismatch", typ, TokenSupport.INVALID_JWT, null, null);
        }

        Map<String, Object> claims = AgentTokens.TYPE.equals(typ)
                ? verifyAgentClaims(token, jwksFetcher, options.expectedAud())
                : verifyIssuedClaims(token, jwt, typ, jwksFetcher, options.expectedAud());

        String jti = TokenSupport.string(claims, "jti");
        if (jti == null || jti.isEmpty()) {
            throw new TokenException("Missing jti", typ, TokenSupport.INVALID_JWT, null, null);
        }
        if (claims.containsKey("mission_s256")) {
            TokenSupport.checkHash(claims.get("mission_s256"));
        }
        if (claims.containsKey("scope") && !(claims.get("scope") instanceof String)) {
            throw new TokenException("Invalid scope", typ, TokenSupport.INVALID_JWT, null, null);
        }
        if (!ResourceTokens.TYPE.equals(typ)) {
            verifyConfirmation(claims, typ, options.requestSigningJwk());
        }
        RevocationChecker checker = options.revocationChecker();
        if (checker != null && checker.isRevoked(iss, jti)) {
            throw new TokenException("Token was revoked", typ, "revoked_jwt", null, null);
        }
        return claims;
    }

    /** Person, auth and resource tokens: signature via the issuer's JWKS, then claim rules. */
    private static Map<String, Object> verifyIssuedClaims(
            String token, Jwts.Decoded jwt, String typ, JwksFetcher fetcher, @Nullable String expectedAud) {
        Map<String, Object> claims = verifyJwt(token, jwt, fetcher, typ);
        String aud = TokenSupport.checkServer(claims.get("aud"));
        if (expectedAud != null && !expectedAud.equals(aud)) {
            throw new TokenException("Audience mismatch", typ, TokenSupport.INVALID_JWT, null, null);
        }
        List<String> required =
                ResourceTokens.TYPE.equals(typ) ? List.of("ps", "sub", "presented_jti", "agent_jkt") : List.of("sub");
        for (String name : required) {
            String value = TokenSupport.string(claims, name);
            if (value == null || value.isEmpty()) {
                throw new TokenException("Missing or invalid " + name, typ, TokenSupport.INVALID_JWT, null, null);
            }
        }
        if (AuthTokens.TYPE.equals(typ) || ResourceTokens.TYPE.equals(typ)) {
            String ps = TokenSupport.checkServer(claims.get("ps"));
            if (AuthTokens.TYPE.equals(typ)
                    && "aauth-person.json".equals(claims.get("dwk"))
                    && !ps.equals(claims.get("iss"))) {
                throw new TokenException(
                        "PS-issued auth token ps must equal iss", typ, TokenSupport.INVALID_JWT, null, null);
            }
        }
        // Jwts.verify guarantees numeric iat and exp.
        if ((AuthTokens.TYPE.equals(typ) || PersonTokens.TYPE.equals(typ))
                && claims.get("exp") instanceof Number exp
                && claims.get("iat") instanceof Number iat
                && exp.longValue() - iat.longValue() > TokenSupport.MAX_LIFETIME_SECONDS) {
            throw new TokenException("Token lifetime exceeds one hour", typ, TokenSupport.INVALID_JWT, null, null);
        }
        return claims;
    }

    private static void verifyConfirmation(
            Map<String, Object> claims, String typ, @Nullable Map<String, Object> requestSigningJwk) {
        Map<String, Object> cnfJwk = TokenSupport.confirmationJwk(claims);
        if (cnfJwk == null) {
            throw new TokenException("Missing cnf.jwk", typ, TokenSupport.INVALID_JWT, null, null);
        }
        TokenSupport.validateAlgorithm(cnfJwk);
        if (requestSigningJwk != null && !Jwk.thumbprint(cnfJwk).equals(Jwk.thumbprint(requestSigningJwk))) {
            throw new TokenException("Confirmation key mismatch", typ, "invalid_key", null, null);
        }
    }

    /**
     * Verifies an agent token's claims and signature (mirrors the reference
     * {@code verify_agent_claims}).
     */
    static Map<String, Object> verifyAgentClaims(String token, JwksFetcher fetcher, @Nullable String expectedAud) {
        String typ = AgentTokens.TYPE;
        Jwts.Decoded jwt = TokenSupport.parse(token);
        if (!typ.equals(jwt.header().get("typ"))
                || !"aauth-agent.json".equals(jwt.payload().get("dwk"))) {
            throw new TokenException("Invalid agent token type or dwk", typ, TokenSupport.INVALID_JWT, null, null);
        }
        TokenSupport.checkServer(jwt.payload().get("iss"));
        String sub = agentIdentifier(jwt.payload().get("sub"));
        String jti = jwt.claim("jti");
        if (jti == null || jti.isEmpty()) {
            throw new TokenException("Agent token missing jti", typ, TokenSupport.INVALID_JWT, null, null);
        }
        if (jwt.payload().containsKey("ps")) {
            TokenSupport.checkServer(jwt.payload().get("ps"));
        }
        if (jwt.payload().containsKey("parent_agent")
                && sub.equals(agentIdentifier(jwt.payload().get("parent_agent")))) {
            throw new TokenException(
                    "Sub-agent cannot name itself as parent", typ, TokenSupport.INVALID_JWT, null, null);
        }
        Map<String, Object> claims = verifyJwt(token, jwt, fetcher, typ);
        Map<String, Object> cnfJwk = TokenSupport.confirmationJwk(claims);
        if (cnfJwk == null) {
            throw new TokenException("Missing cnf.jwk", typ, TokenSupport.INVALID_JWT, null, null);
        }
        TokenSupport.validateAlgorithm(cnfJwk);
        Object aud = claims.get("aud");
        if (aud != null && expectedAud != null) {
            boolean matches = aud instanceof List<?> list ? list.contains(expectedAud) : expectedAud.equals(aud);
            if (!matches) {
                throw new TokenException("Agent token audience mismatch", typ, TokenSupport.INVALID_JWT, null, null);
            }
        }
        return claims;
    }

    private static Map<String, Object> verifyJwt(String token, Jwts.Decoded jwt, JwksFetcher fetcher, String typ) {
        Object kid = jwt.header().get("kid");
        Map<String, Object> jwks = fetcher.fetch(
                String.valueOf(jwt.payload().get("iss")), jwt.claim("dwk"), kid == null ? null : kid.toString());
        try {
            return Jwts.verify(token, jwks == null ? Map.of() : jwks);
        } catch (JoseException e) {
            throw TokenSupport.fromJose(e, typ);
        }
    }

    private static String agentIdentifier(@Nullable Object value) {
        if (!(value instanceof String identifier)) {
            throw new TokenException(
                    "Invalid agent identifier", AgentTokens.TYPE, TokenSupport.INVALID_JWT, null, null);
        }
        try {
            return Identifiers.validateAgentIdentifier(identifier);
        } catch (IllegalArgumentException e) {
            throw new TokenException(
                    "Invalid agent identifier: " + identifier, AgentTokens.TYPE, TokenSupport.INVALID_JWT, null, e);
        }
    }
}
