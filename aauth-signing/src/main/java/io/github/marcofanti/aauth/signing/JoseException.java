package io.github.marcofanti.aauth.signing;

import org.jspecify.annotations.Nullable;

/**
 * A JWT or JWK failed AAuth draft-11 validation (mirrors the reference {@code TokenError} raised by
 * {@code validate_algorithm} / {@code verify_jwt}). {@link #errorCode()} is the wire error code to
 * report, one of the constants below.
 */
public class JoseException extends AAuthException {

    /** {@code alg} missing or not a supported fully-specified algorithm. */
    public static final String UNSUPPORTED_ALGORITHM = "unsupported_algorithm";

    /** Key material, {@code kty}/{@code crv}, or confirmation key does not match. */
    public static final String INVALID_KEY = "invalid_key";

    /** No (or an ambiguous) issuer key for the token's {@code kid}. */
    public static final String UNKNOWN_KEY = "unknown_key";

    /** Malformed token, bad signature, or missing/invalid claims. */
    public static final String INVALID_JWT = "invalid_jwt";

    /** The token's {@code exp} has passed. */
    public static final String EXPIRED_JWT = "expired_jwt";

    public JoseException(String message, String errorCode) {
        this(message, errorCode, null);
    }

    public JoseException(String message, String errorCode, @Nullable Throwable cause) {
        super(message, errorCode, null, cause);
    }
}
