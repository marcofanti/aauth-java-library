package io.github.marcofanti.aauth.tokens;

/**
 * Answers whether a token was revoked, keyed by its issuer and {@code jti} (never {@code jti}
 * alone). A revoked token fails verification with {@code revoked_jwt} (draft-11 §11.12.5).
 */
@FunctionalInterface
public interface RevocationChecker {

    /** Returns {@code true} when the token {@code (issuer, jti)} has been revoked. */
    boolean isRevoked(String issuer, String jti);
}
