package io.github.marcofanti.aauth;

import io.github.marcofanti.aauth.signing.AAuthException;
import java.util.Map;

/** Token validation or creation error. */
public class TokenException extends AAuthException {

    private final String tokenType;

    public TokenException(String message, String tokenType) {
        this(message, tokenType, null, null, null);
    }

    public TokenException(
            String message, String tokenType, String errorCode, Map<String, Object> details, Throwable cause) {
        super(message, errorCode, details, cause);
        this.tokenType = tokenType;
    }

    /** The token media type this error relates to (e.g. {@code aa-agent+jwt}), or {@code null}. */
    public String tokenType() {
        return tokenType;
    }
}
