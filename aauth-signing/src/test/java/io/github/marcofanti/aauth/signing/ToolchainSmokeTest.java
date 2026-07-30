package io.github.marcofanti.aauth.signing;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import org.junit.jupiter.api.Test;

/** Validates the toolchain assumptions the signing module depends on. */
class ToolchainSmokeTest {

    @Test
    void jdkProvidesNativeEd25519() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = generator.generateKeyPair();

        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(keyPair.getPrivate());
        signer.update("hello".getBytes());
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(keyPair.getPublic());
        verifier.update("hello".getBytes());
        assertThat(verifier.verify(signature)).isTrue();
    }

    @Test
    void jdkProvidesEcdsaP256() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        assertThat(generator.generateKeyPair().getPublic().getAlgorithm()).isEqualTo("EC");
    }
}
