package io.github.marcofanti.aauth.signing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;

class SignatureKeyHeaderTest {

    @Test
    void buildsAndParsesHwkForEd25519() {
        KeyPair keyPair = KeyPairs.generateEd25519();

        String header = SignatureKeyHeader.build(new SignatureScheme.Hwk(), "sig", keyPair.getPublic());
        assertThat(header).startsWith("sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"");

        SignatureKeyHeader.Parsed parsed = SignatureKeyHeader.parse(header);
        assertThat(parsed.label()).isEqualTo("sig");
        assertThat(parsed.scheme()).isEqualTo("hwk");
        assertThat(parsed.params()).containsEntry("kty", "OKP").containsEntry("crv", "Ed25519");
    }

    @Test
    void buildsHwkWithYCoordinateForEc() {
        KeyPair keyPair = KeyPairs.generateEcP256();

        String header = SignatureKeyHeader.build(new SignatureScheme.Hwk(), "sig", keyPair.getPublic());

        SignatureKeyHeader.Parsed parsed = SignatureKeyHeader.parse(header);
        assertThat(parsed.params()).containsKeys("kty", "crv", "x", "y");
        assertThat(parsed.params()).containsEntry("crv", "P-256");
    }

    @Test
    void buildRequiresPublicKeyForHwk() {
        assertThatThrownBy(() -> SignatureKeyHeader.build(new SignatureScheme.Hwk(), "sig", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("public key");
    }

    @Test
    void buildsAndParsesJwksUri() {
        String header = SignatureKeyHeader.build(
                new SignatureScheme.JwksUri("https://agent.example", "aauth-agent.json", "key-1"), "sig", null);

        assertThat(header)
                .isEqualTo("sig=jwks_uri;id=\"https://agent.example\";dwk=\"aauth-agent.json\";kid=\"key-1\"");

        SignatureKeyHeader.Parsed parsed = SignatureKeyHeader.parse(header);
        assertThat(parsed.scheme()).isEqualTo("jwks_uri");
        assertThat(parsed.params())
                .containsEntry("id", "https://agent.example")
                .containsEntry("dwk", "aauth-agent.json")
                .containsEntry("kid", "key-1");
    }

    @Test
    void jwksUriDefaultsKid() {
        SignatureScheme.JwksUri scheme = new SignatureScheme.JwksUri("https://a.example", "aauth-agent.json", null);
        assertThat(scheme.kid()).isEqualTo("key-1");
    }

    @Test
    void schemeParametersAreValidatedAtConstruction() {
        assertThatThrownBy(() -> new SignatureScheme.JwksUri(null, "dwk.json", "key-1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("id");
        assertThatThrownBy(() -> new SignatureScheme.Jwt("")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SignatureScheme.JktJwt(null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new SignatureScheme.X509("https://x.example/cert", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("x5t");
    }

    @Test
    void buildsAndParsesJwtScheme() {
        String header = SignatureKeyHeader.build(new SignatureScheme.Jwt("aaa.bbb.ccc"), "sig", null);

        assertThat(header).isEqualTo("sig=jwt;jwt=\"aaa.bbb.ccc\"");
        assertThat(SignatureKeyHeader.parse(header).params()).containsEntry("jwt", "aaa.bbb.ccc");
    }

    @Test
    void buildsX509WithByteSequenceThumbprint() {
        String header = SignatureKeyHeader.build(
                new SignatureScheme.X509("https://x.example/chain.pem", "dGh1bWI="), "sig", null);

        assertThat(header).isEqualTo("sig=x509;x5u=\"https://x.example/chain.pem\";x5t=:dGh1bWI=:");
    }

    @Test
    void escapesQuotesAndBackslashesInParams() {
        String header = SignatureKeyHeader.build(new SignatureScheme.Jwt("a\"b\\c"), "sig", null);

        SignatureKeyHeader.Parsed parsed = SignatureKeyHeader.parse(header);
        assertThat(parsed.params()).containsEntry("jwt", "a\"b\\c");
    }

    @Test
    void parsesLegacyInnerListForm() {
        SignatureKeyHeader.Parsed parsed =
                SignatureKeyHeader.parse("sig=(scheme=hwk kty=\"OKP\" crv=\"Ed25519\" x=\"abc\")");

        assertThat(parsed.label()).isEqualTo("sig");
        assertThat(parsed.scheme()).isEqualTo("hwk");
        assertThat(parsed.params()).containsEntry("x", "abc");
    }

    @Test
    void parseRejectsMissingScheme() {
        assertThatThrownBy(() -> SignatureKeyHeader.parse("sig="))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("scheme");
    }

    @Test
    void parseRejectsGarbage() {
        assertThatThrownBy(() -> SignatureKeyHeader.parse("###"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid Signature-Key");
    }
}
