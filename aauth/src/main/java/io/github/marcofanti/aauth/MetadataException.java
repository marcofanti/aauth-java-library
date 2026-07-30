package io.github.marcofanti.aauth;

import io.github.marcofanti.aauth.signing.AAuthException;

/** Metadata discovery or parsing error. */
public class MetadataException extends AAuthException {

    private final String metadataUrl;

    public MetadataException(String message) {
        this(message, null, null);
    }

    public MetadataException(String message, String metadataUrl, Throwable cause) {
        super(message, cause);
        this.metadataUrl = metadataUrl;
    }

    /** The metadata URL that failed, or {@code null}. */
    public String metadataUrl() {
        return metadataUrl;
    }
}
