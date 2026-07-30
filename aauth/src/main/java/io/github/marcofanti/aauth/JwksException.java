package io.github.marcofanti.aauth;

import io.github.marcofanti.aauth.signing.AAuthException;

/** JWKS fetching or parsing error. */
public class JwksException extends AAuthException {

    private final String jwksUri;

    public JwksException(String message) {
        this(message, null, null);
    }

    public JwksException(String message, String jwksUri, Throwable cause) {
        super(message, cause);
        this.jwksUri = jwksUri;
    }

    /** The JWKS or metadata URL that failed, or {@code null}. */
    public String jwksUri() {
        return jwksUri;
    }
}
