package io.github.marcofanti.aauth.agent;

import io.github.marcofanti.aauth.signing.HttpSignatureException;
import io.github.marcofanti.aauth.signing.RequestSigner;
import io.github.marcofanti.aauth.signing.SignRequest;
import io.github.marcofanti.aauth.signing.SignatureScheme;
import java.security.KeyPair;
import java.util.Map;

/**
 * High-level request signer for the agent role.
 *
 * <p>Wraps {@link RequestSigner} with the agent's long-lived configuration (key pair, identity,
 * agent token) so call sites choose only the scheme per request.
 */
public final class AgentRequestSigner {

    private final KeyPair keyPair;
    private final String agentId;
    private final String agentToken;
    private final String kid;
    private final String dwk;

    private AgentRequestSigner(Builder builder) {
        if (builder.keyPair == null) {
            throw new IllegalArgumentException("keyPair is required");
        }
        this.keyPair = builder.keyPair;
        this.agentId = builder.agentId;
        this.agentToken = builder.agentToken;
        this.kid = builder.kid;
        this.dwk = builder.dwk;
    }

    public static Builder builder(KeyPair keyPair) {
        return new Builder(keyPair);
    }

    /** Builder; {@code kid} defaults to {@code key-1}, {@code dwk} to {@code aauth-agent.json}. */
    public static final class Builder {
        private final KeyPair keyPair;
        private String agentId;
        private String agentToken;
        private String kid = "key-1";
        private String dwk = "aauth-agent.json";

        private Builder(KeyPair keyPair) {
            this.keyPair = keyPair;
        }

        /** Agent identifier (HTTPS URL) — required for the {@code jwks_uri} scheme. */
        public Builder agentId(String agentId) {
            this.agentId = agentId;
            return this;
        }

        /** Agent token (JWT) — required for the {@code jwt} scheme. */
        public Builder agentToken(String agentToken) {
            this.agentToken = agentToken;
            return this;
        }

        public Builder kid(String kid) {
            this.kid = kid;
            return this;
        }

        public Builder dwk(String dwk) {
            this.dwk = dwk;
            return this;
        }

        public AgentRequestSigner build() {
            return new AgentRequestSigner(this);
        }
    }

    /** Returns a signer identical to this one but using {@code agentToken} (e.g. an auth token). */
    public AgentRequestSigner withToken(String token) {
        return builder(keyPair)
                .agentId(agentId)
                .agentToken(token)
                .kid(kid)
                .dwk(dwk)
                .build();
    }

    /**
     * Signs an HTTP request with the given scheme name ({@code hwk}, {@code jwks_uri} or
     * {@code jwt}).
     *
     * @return the headers to add to the request
     * @throws HttpSignatureException if the scheme's configuration is missing or signing fails
     */
    public Map<String, String> signRequest(
            String method, String targetUri, Map<String, String> headers, byte[] body, String sigScheme) {
        return RequestSigner.sign(SignRequest.builder(method, targetUri)
                .headers(headers)
                .body(body)
                .keyPair(keyPair)
                .scheme(schemeFor(sigScheme))
                .build());
    }

    private SignatureScheme schemeFor(String sigScheme) {
        return switch (sigScheme == null ? "hwk" : sigScheme) {
            case "jwks_uri" -> {
                if (agentId == null) {
                    throw new HttpSignatureException("agentId required for jwks_uri scheme");
                }
                yield new SignatureScheme.JwksUri(agentId, dwk, kid);
            }
            case "jwt" -> {
                if (agentToken == null) {
                    throw new HttpSignatureException("agentToken required for jwt scheme");
                }
                yield new SignatureScheme.Jwt(agentToken);
            }
            default -> new SignatureScheme.Hwk();
        };
    }
}
