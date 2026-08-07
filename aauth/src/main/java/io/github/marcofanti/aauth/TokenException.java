package io.github.marcofanti.aauth;

import io.github.marcofanti.aauth.signing.AAuthException;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/** Token validation or creation error. */
public class TokenException extends AAuthException {

    private final @Nullable String tokenType;

    public TokenException(String message, @Nullable String tokenType) {
        this(message, tokenType, null, null, null);
    }

    public TokenException(
            String message,
            @Nullable String tokenType,
            @Nullable String errorCode,
            @Nullable Map<String, Object> details,
            @Nullable Throwable cause) {
        super(message, errorCode, details, cause);
        this.tokenType = tokenType;
    }

    /** The token media type this error relates to (e.g. {@code aa-agent+jwt}), or {@code null}. */
    public @Nullable String tokenType() {
        return tokenType;
    }
}
