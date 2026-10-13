package io.github.marcofanti.aauth.tokens;

import io.github.marcofanti.aauth.Identifiers;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.signing.JoseException;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import org.jspecify.annotations.Nullable;

/** Draft-11 claim validation and dependency lifetime bounds (mirrors the reference tokens/common). */
final class TokenSupport {

    static final String INVALID_JWT = "invalid_jwt";
    static final String EXPIRED_JWT = "expired_jwt";

    /** Maximum lifetime of person and auth tokens, and the default lifetime cap, in seconds. */
    static final long MAX_LIFETIME_SECONDS = 3600;

    private static final Pattern MISSION_HASH = Pattern.compile("[A-Za-z0-9_-]{43}");

    private TokenSupport() {}

    static long nowEpochSeconds() {
        return java.time.Instant.now().getEpochSecond();
    }

    /** Requires a draft-11 server identifier (lowercase HTTPS origin, no port or path). */
    static String checkServer(@Nullable Object value) {
        if (!(value instanceof String url)) {
            throw new TokenException("Invalid server identifier", null, INVALID_JWT, null, null);
        }
        try {
            return Identifiers.validateServerIdentifier(url);
        } catch (IllegalArgumentException e) {
            throw new TokenException("Invalid server identifier: " + url, null, INVALID_JWT, null, e);
        }
    }

    /** Requires a {@code mission_s256}: 43 base64url characters (unpadded SHA-256). */
    static String checkHash(@Nullable Object value) {
        if (!(value instanceof String hash) || !MISSION_HASH.matcher(hash).matches()) {
            throw new TokenException("Invalid mission_s256", null, INVALID_JWT, null, null);
        }
        return hash;
    }

    /**
     * Bounds an expiration by one hour from now and every dependency's expiration: the result is
     * the earliest of them, and must still be in the future.
     *
     * @throws TokenException {@code expired_jwt} when a dependency has already expired
     */
    static long boundedExp(long now, @Nullable Long exp, @Nullable Long... bounds) {
        long result = Math.min(now + MAX_LIFETIME_SECONDS, exp != null ? exp : now + MAX_LIFETIME_SECONDS);
        for (Long bound : bounds) {
            if (bound != null) {
                result = Math.min(result, bound);
            }
        }
        if (result <= now) {
            throw new TokenException("Dependency has expired", null, EXPIRED_JWT, null, null);
        }
        return result;
    }

    /** Common claims: {@code iss} (validated), {@code dwk}, a fresh {@code jti}, {@code iat}, {@code exp}. */
    static Map<String, Object> baseClaims(String iss, String dwk, long exp) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", checkServer(iss));
        claims.put("dwk", dwk);
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("iat", nowEpochSeconds());
        claims.put("exp", exp);
        return claims;
    }

    /** Validates a confirmation key's fully-specified {@code alg} and key material. */
    static void validateAlgorithm(Map<String, Object> jwk) {
        try {
            Jwk.validateAlgorithm(jwk, null);
        } catch (JoseException e) {
            throw fromJose(e, null);
        }
    }

    static Jwts.Decoded parse(String token) {
        try {
            return Jwts.parse(token);
        } catch (IllegalArgumentException e) {
            throw new TokenException("Cannot decode JWT", null, INVALID_JWT, null, e);
        }
    }

    static TokenException fromJose(JoseException e, @Nullable String tokenType) {
        return new TokenException(String.valueOf(e.getMessage()), tokenType, e.errorCode(), null, e);
    }

    /** Re-codes a token failure: {@code expired_jwt}/{@code revoked_jwt} map to specific codes. */
    static TokenException recode(TokenException e, String expiredCode, String revokedCode, String fallback) {
        String code = e.errorCode();
        String mapped = EXPIRED_JWT.equals(code) ? expiredCode : "revoked_jwt".equals(code) ? revokedCode : fallback;
        return new TokenException(String.valueOf(e.getMessage()), e.tokenType(), mapped, null, e);
    }

    static @Nullable String string(Map<String, Object> claims, String name) {
        return claims.get(name) instanceof String value ? value : null;
    }

    @SuppressWarnings("unchecked")
    static @Nullable Map<String, Object> confirmationJwk(Map<String, Object> claims) {
        if (claims.get("cnf") instanceof Map<?, ?> cnf && cnf.get("jwk") instanceof Map<?, ?> jwk) {
            return (Map<String, Object>) jwk;
        }
        return null;
    }
}
