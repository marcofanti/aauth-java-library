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
        assertThat(parsed.integerParam("created")).isBetween(before, after);
    }

    @Test
    void parseRoundTripsComponentsAndParams() {
        String header = SignatureInputHeader.build(
                List.of("@method", "@authority", "@path", "signature-key"), "sig", 1700000000L);

        SignatureInputHeader.Parsed parsed = SignatureInputHeader.parse(header);

        assertThat(parsed.label()).isEqualTo("sig");
        assertThat(parsed.components()).containsExactly("@method", "@authority", "@path", "signature-key");
        assertThat(parsed.params()).containsEntry("created", 1700000000L);
    }

    @Test
    void parseReadsTypedParameters() {
        SignatureInputHeader.Parsed parsed = SignatureInputHeader.parse(
                "sig1=(\"@method\" \"content-digest\");created=1700000000;expires=1700000060;keyid=\"k1\";"
                        + "alg=ed25519;x=1.5;flag;neg=?0;bytes=:AAEC:");

        assertThat(parsed.label()).isEqualTo("sig1");
        assertThat(parsed.integerParam("created")).isEqualTo(1700000000L);
        assertThat(parsed.integerParam("expires")).isEqualTo(1700000060L);
        assertThat(parsed.stringParam("keyid")).isEqualTo("k1");
        assertThat(parsed.params())
                .containsEntry("alg", "ed25519")
                .containsEntry("x", new java.math.BigDecimal("1.5"))
                .containsEntry("flag", Boolean.TRUE)
                .containsEntry("neg", Boolean.FALSE)
                .containsEntry("bytes", "AAEC");
        // A quoted created is a string, not an integer — the verifier rejects it.
        assertThat(SignatureInputHeader.parse("sig=(\"@method\");created=\"1700000000\"")
                        .integerParam("created"))
                .isNull();
    }

    @Test
    void parseRejectsInvalidFormat() {
        for (String invalid : List.of(
                "not a header",
                "sig=(@method)",
                "sig=(\"@method\" \"@method\")",
                "sig=(\"@method\"),sig2=(\"@path\")",
                "sig=(\"@method\"",
                "Sig=(\"@method\")",
                "sig=(\"a\"\"b\")",
                "sig=(\"@method\");created=",
                "sig=(\"@method\");x=?2",
                "sig=(\"bad\\q\")",
                "sig=(\"@method\");n=1234567890123456")) {
            assertThatThrownBy(() -> SignatureInputHeader.parse(invalid))
                    .as(invalid)
                    .isInstanceOf(IllegalArgumentException.class);
        }
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
