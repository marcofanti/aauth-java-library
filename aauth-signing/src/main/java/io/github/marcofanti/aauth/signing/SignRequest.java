package io.github.marcofanti.aauth.signing;

import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Parameters for {@link RequestSigner#sign(SignRequest)}.
 *
 * @param method HTTP method
 * @param targetUri absolute target URI
 * @param headers request headers already set on the request (not modified)
 * @param body request body, or {@code null}
 * @param keyPair the signing key pair (Ed25519 or EC); the public half is needed for {@code hwk}
 * @param scheme the Signature-Key scheme
 * @param additionalComponents extra covered components required by the resource (only
 *     {@code content-type} / {@code content-digest} are honored, and only when a body is present)
 * @param created signature creation time in Unix seconds; {@code null} uses the current time
 */
// byte[] body is intentional: raw request bytes; record equality is never used.
@SuppressWarnings("ArrayRecordComponent")
public record SignRequest(
        String method,
        String targetUri,
        Map<String, String> headers,
        byte @Nullable [] body,
        KeyPair keyPair,
        SignatureScheme scheme,
        List<String> additionalComponents,
        @Nullable Long created) {

    public SignRequest {
        if (method == null || method.isEmpty()) {
            throw new IllegalArgumentException("method is required");
        }
        if (targetUri == null || targetUri.isEmpty()) {
            throw new IllegalArgumentException("targetUri is required");
        }
        if (keyPair == null) {
            throw new IllegalArgumentException("keyPair is required");
        }
        if (scheme == null) {
            throw new IllegalArgumentException("scheme is required");
        }
        headers = headers == null ? Map.of() : Map.copyOf(headers);
        additionalComponents = additionalComponents == null ? List.of() : List.copyOf(additionalComponents);
    }

    public static Builder builder(String method, String targetUri) {
        return new Builder(method, targetUri);
    }

    /** Builder for {@link SignRequest}. */
    public static final class Builder {
        private final String method;
        private final String targetUri;
        private @Nullable Map<String, String> headers;
        private byte @Nullable [] body;
        private @Nullable KeyPair keyPair;
        private SignatureScheme scheme = new SignatureScheme.Hwk();
        private @Nullable List<String> additionalComponents;
        private @Nullable Long created;

        private Builder(String method, String targetUri) {
            this.method = method;
            this.targetUri = targetUri;
        }

        public Builder headers(Map<String, String> headers) {
            this.headers = headers;
            return this;
        }

        public Builder body(byte[] body) {
            this.body = body;
            return this;
        }

        public Builder keyPair(KeyPair keyPair) {
            this.keyPair = keyPair;
            return this;
        }

        public Builder scheme(SignatureScheme scheme) {
            this.scheme = scheme;
            return this;
        }

        public Builder additionalComponents(List<String> additionalComponents) {
            this.additionalComponents = additionalComponents;
            return this;
        }

        public Builder created(Long created) {
            this.created = created;
            return this;
        }

        public SignRequest build() {
            if (keyPair == null) {
                throw new IllegalArgumentException("keyPair is required");
            }
            return new SignRequest(
                    method,
                    targetUri,
                    headers == null ? Map.of() : headers,
                    body,
                    keyPair,
                    scheme,
                    additionalComponents == null ? List.of() : additionalComponents,
                    created);
        }
    }
}
