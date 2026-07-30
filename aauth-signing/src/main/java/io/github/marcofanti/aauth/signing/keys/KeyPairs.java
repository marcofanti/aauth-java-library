package io.github.marcofanti.aauth.signing.keys;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;

/** Key pair generation for aauth-signing (Ed25519 and EC P-256/P-384). */
public final class KeyPairs {

    private KeyPairs() {}

    /** Generates a new Ed25519 key pair. */
    public static KeyPair generateEd25519() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JDK is missing Ed25519 support (requires Java 15+)", e);
        }
    }

    /** Generates a new EC P-256 (secp256r1) key pair. */
    public static KeyPair generateEcP256() {
        return generateEc("secp256r1");
    }

    /** Generates a new EC P-384 (secp384r1) key pair. */
    public static KeyPair generateEcP384() {
        return generateEc("secp384r1");
    }

    private static KeyPair generateEc(String curveName) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(curveName));
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("JDK is missing EC support for curve " + curveName, e);
        }
    }
}
