package io.github.marcofanti.aauth.signing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Tests for Signature-Input / Signature header building and parsing, and algorithms. */
class SignatureHeadersTest {

    @Test
    void buildsSignatureInputHeader() {
        String header = SignatureInputHeader.build(List.of("@method", "@authority"), "sig", 1700000000L);

        assertThat(header).isEqualTo("sig=(\"@method\" \"@authority\");created=1700000000");
    }

    @Test
    void buildUsesCurrentTimeWhenCreatedOmitted() {
        long before = System.currentTimeMillis() / 1000;
        String header = SignatureInputHeader.build(List.of("@method"), "sig", null);
        long after = System.currentTimeMillis() / 1000;

        SignatureInputHeader.Parsed parsed = SignatureInputHeader.parse(header);
        long created = Long.parseLong(parsed.params().get("created"));
        assertThat(created).isBetween(before, after);
    }

    @Test
    void parseRoundTripsComponentsAndParams() {
        String header = SignatureInputHeader.build(
                List.of("@method", "@authority", "@path", "signature-key"), "sig", 1700000000L);

        SignatureInputHeader.Parsed parsed = SignatureInputHeader.parse(header);

        assertThat(parsed.components()).containsExactly("@method", "@authority", "@path", "signature-key");
        assertThat(parsed.params()).containsEntry("created", "1700000000");
    }

    @Test
    void parseRejectsInvalidFormat() {
        assertThatThrownBy(() -> SignatureInputHeader.parse("not a header"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Signature-Input");
    }

    @Test
    void signatureHeaderRoundTripsBytes() {
        byte[] signature = {1, 2, 3, (byte) 250, (byte) 255, 0, 42};

        String header = SignatureHeader.build(signature, "sig");
        assertThat(header).startsWith("sig=:").endsWith(":");

        assertThat(SignatureHeader.parse(header, "sig")).isEqualTo(signature);
        assertThat(SignatureHeader.parse(header, null)).isEqualTo(signature);
    }

    @Test
    void signatureHeaderParseRejectsLabelMismatch() {
        String header = SignatureHeader.build(new byte[] {1}, "sig1");

        assertThatThrownBy(() -> SignatureHeader.parse(header, "sig"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Label mismatch");
    }

    @Test
    void signatureHeaderParseRejectsGarbage() {
        assertThatThrownBy(() -> SignatureHeader.parse("garbage", "sig"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid Signature format");
    }

    @Test
    void algorithmsListEd25519AsRequired() {
        assertThat(SigningAlgorithms.REQUIRED_ALGORITHM).isEqualTo("ed25519");
        assertThat(SigningAlgorithms.SUPPORTED_ALGORITHMS)
                .containsExactly(
                        "ed25519", "rsa-pss-sha512", "rsa-pss-sha256", "ecdsa-p256-sha256", "ecdsa-p384-sha384");
    }

    @Test
    void algorithmSupportIsCaseInsensitive() {
        assertThat(SigningAlgorithms.isSupported("Ed25519")).isTrue();
        assertThat(SigningAlgorithms.isSupported("ECDSA-P256-SHA256")).isTrue();
        assertThat(SigningAlgorithms.isSupported("hmac-sha256")).isFalse();
        assertThat(SigningAlgorithms.isSupported(null)).isFalse();
    }
}
