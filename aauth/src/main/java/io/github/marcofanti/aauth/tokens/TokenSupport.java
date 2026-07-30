package io.github.marcofanti.aauth.tokens;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.keys.CachingJwksFetcher;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import java.security.PublicKey;
import java.util.Map;
import java.util.function.Function;

/** Shared helpers for token creation and verification. */
final class TokenSupport {

    private TokenSupport() {}

    static Jwts.Decoded parseOrThrow(String token, String tokenType) {
        try {
            return Jwts.parse(token);
        } catch (IllegalArgumentException e) {
            throw new TokenException("Failed to parse " + tokenType + ": " + e.getMessage(), tokenType, null, null, e);
        }
    }

    /**
     * Verifies a token's EdDSA signature against its issuer's JWKS (looked up by {@code iss},
     * key selected by header {@code kid}).
     */
    static void verifySignatureViaIssuer(
            Jwts.Decoded jwt, String token, Function<String, Map<String, Object>> jwksFetcher, String tokenType) {
        Object kid = jwt.header().get("kid");
        if (kid == null) {
            throw new TokenException("Token header missing 'kid'", tokenType);
        }
        if (!"EdDSA".equals(jwt.header().get("alg"))) {
            throw new TokenException(
                    "Unsupported token alg: expected EdDSA, got " + jwt.header().get("alg"), tokenType);
        }

        String iss = jwt.claim("iss");
        Map<String, Object> jwks = jwksFetcher.apply(iss);
        if (jwks == null) {
            throw new TokenException(
                    "Failed to fetch JWKS from " + iss, tokenType, null, Map.of("iss", String.valueOf(iss)), null);
        }

        Map<String, Object> signingKey = CachingJwksFetcher.getKeyByKid(jwks, kid.toString());
        if (signingKey == null) {
            throw new TokenException(
                    "Signing key with kid=" + kid + " not found in JWKS",
                    tokenType,
                    null,
                    Map.of("kid", kid.toString(), "iss", String.valueOf(iss)),
                    null);
        }

        PublicKey publicKey;
        try {
            publicKey = Jwk.toPublicKey(signingKey);
        } catch (IllegalArgumentException e) {
            throw new TokenException("Failed to load signing key: " + e.getMessage(), tokenType, null, null, e);
        }
        if (!Jwts.verifySignature(jwt, publicKey)) {
            throw new TokenException("JWT signature verification failed", tokenType);
        }
    }

    static long nowEpochSeconds() {
        return java.time.Instant.now().getEpochSecond();
    }
}
