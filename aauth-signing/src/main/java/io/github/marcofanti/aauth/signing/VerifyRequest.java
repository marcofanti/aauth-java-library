package io.github.marcofanti.aauth.signing;

import java.security.PublicKey;
import java.time.Clock;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Parameters for {@link SignatureVerifier#verify(VerifyRequest)}.
 *
 * @param method HTTP method
 * @param targetUri absolute target URI as received
 * @param headers request headers (looked up case-insensitively)
 * @param body request body, or {@code null}
 * @param signatureInput the {@code Signature-Input} header value
 * @param signature the {@code Signature} header value
 * @param signatureKey the {@code Signature-Key} header value
 * @param publicKey optional pre-resolved public key (used by the {@code hwk} scheme)
 * @param jwksFetcher key discovery callback, required for {@code jwks_uri} / {@code jwt}
 * @param clock clock used for the created-timestamp window; defaults to the system clock
 */
// byte[] body is intentional: raw request bytes; record equality is never used.
@SuppressWarnings("ArrayRecordComponent")
public record VerifyRequest(
        String method,
        String targetUri,
        Map<String, String> headers,
        byte @Nullable [] body,
        String signatureInput,
        String signature,
        String signatureKey,
        @Nullable PublicKey publicKey,
        @Nullable JwksFetcher jwksFetcher,
        Clock clock) {

    public VerifyRequest {
        if (method == null || targetUri == null) {
            throw new IllegalArgumentException("method and targetUri are required");
        }
        if (signatureInput == null || signature == null || signatureKey == null) {
            throw new IllegalArgumentException(
                    "Signature-Input, Signature and Signature-Key header values are required");
        }
        headers = headers == null ? Map.of() : Map.copyOf(headers);
        clock = clock == null ? Clock.systemUTC() : clock;
    }

    public static Builder builder(String method, String targetUri) {
        return new Builder(method, targetUri);
    }

    /** Builder for {@link VerifyRequest}. */
    public static final class Builder {
        private final String method;
        private final String targetUri;
        private @Nullable Map<String, String> headers;
        private byte @Nullable [] body;
        private @Nullable String signatureInput;
        private @Nullable String signature;
        private @Nullable String signatureKey;
        private @Nullable PublicKey publicKey;
        private @Nullable JwksFetcher jwksFetcher;
        private @Nullable Clock clock;

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

        /** Sets the three signature headers from the request in one call. */
        public Builder signatureHeaders(String signatureInput, String signature, String signatureKey) {
            this.signatureInput = signatureInput;
            this.signature = signature;
            this.signatureKey = signatureKey;
            return this;
        }

        public Builder publicKey(PublicKey publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        public Builder jwksFetcher(JwksFetcher jwksFetcher) {
            this.jwksFetcher = jwksFetcher;
            return this;
        }

        public Builder clock(Clock clock) {
            this.clock = clock;
            return this;
        }

        public VerifyRequest build() {
            if (signatureInput == null || signature == null || signatureKey == null) {
                throw new IllegalArgumentException(
                        "Signature-Input, Signature and Signature-Key header values are required");
            }
            return new VerifyRequest(
                    method,
                    targetUri,
                    headers == null ? Map.of() : headers,
                    body,
                    signatureInput,
                    signature,
                    signatureKey,
                    publicKey,
                    jwksFetcher,
                    clock == null ? Clock.systemUTC() : clock);
        }
    }
}
