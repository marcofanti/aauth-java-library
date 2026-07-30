package io.github.marcofanti.aauth.signing;

import java.util.Map;

/**
 * Base exception for AAuth-related errors.
 *
 * <p>Mirrors {@code AAuthError} in the Python reference implementation. Carries an optional
 * protocol error code (for the {@code AAuth-Error} / {@code Signature-Error} headers) and a
 * free-form details map for diagnostic context.
 */
public class AAuthException extends RuntimeException {

    private final String errorCode;
    private final Map<String, Object> details;

    public AAuthException(String message) {
        this(message, null, null, null);
    }

    public AAuthException(String message, Throwable cause) {
        this(message, null, null, cause);
    }

    public AAuthException(String message, String errorCode, Map<String, Object> details, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        this.details = details == null ? Map.of() : Map.copyOf(details);
    }

    /** Protocol error code, or {@code null} when the error has no wire representation. */
    public String errorCode() {
        return errorCode;
    }

    /** Diagnostic context; never {@code null}. */
    public Map<String, Object> details() {
        return details;
    }
}
