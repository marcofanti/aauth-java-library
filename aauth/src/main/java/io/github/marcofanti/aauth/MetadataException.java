package io.github.marcofanti.aauth;

import io.github.marcofanti.aauth.signing.AAuthException;
import org.jspecify.annotations.Nullable;

/** Metadata discovery or parsing error. */
public class MetadataException extends AAuthException {

    private final @Nullable String metadataUrl;

    public MetadataException(String message) {
        this(message, null, null);
    }

    public MetadataException(String message, @Nullable String metadataUrl, @Nullable Throwable cause) {
        super(message, cause);
        this.metadataUrl = metadataUrl;
    }

    /** The metadata URL that failed, or {@code null}. */
    public @Nullable String metadataUrl() {
        return metadataUrl;
    }
}
