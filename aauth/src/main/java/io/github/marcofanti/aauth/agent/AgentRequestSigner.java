package io.github.marcofanti.aauth.agent;

import io.github.marcofanti.aauth.signing.HttpSignatureException;
import io.github.marcofanti.aauth.signing.RequestSigner;
import io.github.marcofanti.aauth.signing.SignRequest;
import io.github.marcofanti.aauth.signing.SignatureScheme;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Agent request signing under the AAuth {@code jwt} profile (draft-11, mirrors the reference
 * {@code agent/signer}). AAuth agents always sign with the {@code jwt} scheme, presenting the
 * token the recipient needs: the agent token by default, or a person/auth token.
 */
public final class AgentRequestSigner {

    /** Who receives the request; PS, AS and revocation endpoints require body coverage. */
    public enum RecipientRole {
        RESOURCE,
        PS,
        AS,
        REVOCATION
    }

    private final KeyPair keyPair;
    private final @Nullable String agentToken;

    private AgentRequestSigner(KeyPair keyPair, @Nullable String agentToken) {
        this.keyPair = keyPair;
        this.agentToken = agentToken;
    }

    public static Builder builder(KeyPair keyPair) {
        return new Builder(keyPair);
    }

    /** Builder for {@link AgentRequestSigner}. */
    public static final class Builder {
        private final KeyPair keyPair;
        private @Nullable String agentToken;

        private Builder(KeyPair keyPair) {
            this.keyPair = keyPair;
        }

        /** The default token presented under the {@code jwt} scheme. */
        public Builder agentToken(@Nullable String agentToken) {
            this.agentToken = agentToken;
            return this;
        }

        public AgentRequestSigner build() {
            return new AgentRequestSigner(keyPair, agentToken);
        }
    }

    /** Returns a signer identical to this one but presenting {@code token} by default. */
    public AgentRequestSigner withToken(String token) {
        return new AgentRequestSigner(keyPair, token);
    }

    /**
     * Per-request signing options.
     *
     * @param token the token to present instead of the default, or {@code null}
     * @param recipientRole who receives the request
     * @param additionalComponents further components to cover
     */
    public record Options(@Nullable String token, RecipientRole recipientRole, List<String> additionalComponents) {

        public Options {
            additionalComponents = List.copyOf(additionalComponents);
        }

        public static Options defaults() {
            return new Options(null, RecipientRole.RESOURCE, List.of());
        }

        /** Present {@code token} instead of the default token. */
        public static Options presenting(String token) {
            return new Options(token, RecipientRole.RESOURCE, List.of());
        }

        public static Options to(RecipientRole recipientRole) {
            return new Options(null, recipientRole, List.of());
        }
    }

    /**
     * Signs a request to a resource with the default token.
     *
     * @return the headers to add to the request
     * @throws HttpSignatureException if no token is configured or signing fails
     */
    public Map<String, String> signRequest(
            String method, String targetUri, Map<String, String> headers, byte @Nullable [] body) {
        return signRequest(method, targetUri, headers, body, Options.defaults());
    }

    /**
     * Signs a request. A body sent to a PS, AS or revocation endpoint is covered with
     * {@code content-digest} and {@code content-type}.
     *
     * @return the headers to add to the request
     * @throws HttpSignatureException if no token is available or signing fails
     */
    public Map<String, String> signRequest(
            String method, String targetUri, Map<String, String> headers, byte @Nullable [] body, Options options) {
        String token = options.token() != null ? options.token() : agentToken;
        if (token == null || token.isEmpty()) {
            throw new HttpSignatureException("A token is required");
        }
        List<String> components = new ArrayList<>(options.additionalComponents());
        if (body != null && options.recipientRole() != RecipientRole.RESOURCE) {
            components.add("content-digest");
            components.add("content-type");
        }
        SignRequest.Builder request = SignRequest.builder(method, targetUri)
                .headers(headers)
                .keyPair(keyPair)
                .scheme(new SignatureScheme.Jwt(token))
                .additionalComponents(components);
        if (body != null) {
            request.body(body);
        }
        return RequestSigner.sign(request.build());
    }
}
