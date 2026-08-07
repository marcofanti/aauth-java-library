package io.github.marcofanti.aauth;

import io.github.marcofanti.aauth.signing.AAuthException;
import org.jspecify.annotations.Nullable;

/** JWKS fetching or parsing error. */
public class JwksException extends AAuthException {

    private final @Nullable String jwksUri;

    public JwksException(String message) {
        this(message, null, null);
    }

    public JwksException(String message, @Nullable String jwksUri, @Nullable Throwable cause) {
        super(message, cause);
        this.jwksUri = jwksUri;
    }

    /** The JWKS or metadata URL that failed, or {@code null}. */
    public @Nullable String jwksUri() {
        return jwksUri;
    }
}
