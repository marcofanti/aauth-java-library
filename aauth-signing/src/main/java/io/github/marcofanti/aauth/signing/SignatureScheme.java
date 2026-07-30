package io.github.marcofanti.aauth.signing;

/**
 * Signature-Key scheme per draft-hardt-httpbis-signature-key.
 *
 * <p>Each scheme is a record carrying exactly the parameters that scheme requires, so invalid
 * combinations are unrepresentable:
 *
 * <ul>
 *   <li>{@link Hwk} — inline public key (pseudonymous); the key comes from the signing key pair
 *   <li>{@link JktJwt} — self-issued key delegation from a hardware-backed enclave key
 *   <li>{@link JwksUri} — JWKS discovery via {@code {id}/.well-known/{dwk}} (identity)
 *   <li>{@link Jwt} — JWT containing the public key in its {@code cnf} claim (identity)
 *   <li>{@link X509} — X.509 certificate reference (building only; verification unimplemented)
 * </ul>
 */
public sealed interface SignatureScheme {

    /** The scheme token as it appears on the wire. */
    String wireName();

    /** Inline public key ({@code hwk}); the JWK is derived from the signing key pair. */
    record Hwk() implements SignatureScheme {
        @Override
        public String wireName() {
            return "hwk";
        }
    }

    /** Self-issued key delegation JWT ({@code jkt-jwt}). */
    record JktJwt(String jwt) implements SignatureScheme {
        public JktJwt {
            require(jwt, "jkt-jwt", "jwt");
        }

        @Override
        public String wireName() {
            return "jkt-jwt";
        }
    }

    /** JWKS URI discovery ({@code jwks_uri}); {@code kid} defaults to {@code key-1}. */
    record JwksUri(String id, String dwk, String kid) implements SignatureScheme {
        public JwksUri {
            require(id, "jwks_uri", "id");
            require(dwk, "jwks_uri", "dwk");
            if (kid == null || kid.isEmpty()) {
                kid = "key-1";
            }
        }

        @Override
        public String wireName() {
            return "jwks_uri";
        }
    }

    /** JWT confirmation key ({@code jwt}). */
    record Jwt(String jwt) implements SignatureScheme {
        public Jwt {
            require(jwt, "jwt", "jwt");
        }

        @Override
        public String wireName() {
            return "jwt";
        }
    }

    /** X.509 certificate reference ({@code x509}); {@code x5t} is a base64 SHA-256 thumbprint. */
    record X509(String x5u, String x5t) implements SignatureScheme {
        public X509 {
            require(x5u, "x509", "x5u");
            require(x5t, "x509", "x5t");
        }

        @Override
        public String wireName() {
            return "x509";
        }
    }

    private static void require(String value, String scheme, String param) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("scheme=" + scheme + " requires '" + param + "' parameter");
        }
    }
}
