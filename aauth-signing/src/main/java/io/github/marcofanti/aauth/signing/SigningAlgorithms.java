package io.github.marcofanti.aauth.signing;

import java.util.List;

/**
 * Signature algorithm identifiers supported by AAuth (spec §10.2).
 *
 * <p>{@code ed25519} is REQUIRED; the others MAY be supported.
 */
public final class SigningAlgorithms {

    public static final String ED25519 = "ed25519";
    public static final String RSA_PSS_SHA512 = "rsa-pss-sha512";
    public static final String RSA_PSS_SHA256 = "rsa-pss-sha256";
    public static final String ECDSA_P256_SHA256 = "ecdsa-p256-sha256";
    public static final String ECDSA_P384_SHA384 = "ecdsa-p384-sha384";

    public static final String REQUIRED_ALGORITHM = ED25519;

    public static final List<String> SUPPORTED_ALGORITHMS =
            List.of(ED25519, RSA_PSS_SHA512, RSA_PSS_SHA256, ECDSA_P256_SHA256, ECDSA_P384_SHA384);

    private SigningAlgorithms() {}

    /** Returns whether {@code algorithm} is supported (case-insensitive). */
    public static boolean isSupported(String algorithm) {
        if (algorithm == null) {
            return false;
        }
        return SUPPORTED_ALGORITHMS.stream().anyMatch(a -> a.equalsIgnoreCase(algorithm));
    }
}
