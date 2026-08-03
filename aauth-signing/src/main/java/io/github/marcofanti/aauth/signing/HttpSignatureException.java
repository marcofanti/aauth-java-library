package io.github.marcofanti.aauth.signing;

import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * HTTP signature validation or creation error.
 *
 * <p>Mirrors {@code SignatureError} in the Python reference implementation: the error code
 * defaults to {@code invalid_signature} (per draft-hardt-httpbis-signature-key).
 */
public class HttpSignatureException extends AAuthException {

    /** Signature-Error header code for 401 responses. */
    public static final String ERROR_INVALID_SIGNATURE = "invalid_signature";

    public HttpSignatureException(String message) {
        this(message, null, null, null);
    }

    public HttpSignatureException(String message, @Nullable Throwable cause) {
        this(message, null, null, cause);
    }

    public HttpSignatureException(
            String message,
            @Nullable String errorCode,
            @Nullable Map<String, Object> details,
            @Nullable Throwable cause) {
        super(message, errorCode == null ? ERROR_INVALID_SIGNATURE : errorCode, details, cause);
    }
}
