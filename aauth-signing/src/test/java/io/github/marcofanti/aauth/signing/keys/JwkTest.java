package io.github.marcofanti.aauth.signing.keys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class JwkTest {

    @Test
    void thumbprintMatchesRfc8037Ed25519Vector() {
        Map<String, Object> jwk = Map.of(
                "kty", "OKP",
                "crv", "Ed25519",
                "x", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");

        assertThat(Jwk.thumbprint(jwk)).isEqualTo("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    }

    @Test
    void thumbprintMatchesRfc7638RsaVector() {
        Map<String, Object> jwk = Map.of(
                "kty",
                "RSA",
                "n",
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e",
                "AQAB");

        assertThat(Jwk.thumbprint(jwk)).isEqualTo("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    @Test
    void ed25519RoundTripsThroughJwk() {
        KeyPair keyPair = KeyPairs.generateEd25519();

        Map<String, Object> jwk = Jwk.publicKeyToJwk(keyPair.getPublic(), "key-1");
        assertThat(jwk)
                .containsEntry("kty", "OKP")
                .containsEntry("crv", "Ed25519")
                .containsEntry("kid", "key-1");
        assertThat(jwk).containsKey("x");

        PublicKey restored = Jwk.toPublicKey(jwk);
        assertThat(Jwk.publicKeyToJwk(restored, "key-1")).isEqualTo(jwk);
    }

    @Test
    void ecP256RoundTripsThroughJwk() {
        KeyPair keyPair = KeyPairs.generateEcP256();

        Map<String, Object> jwk = Jwk.publicKeyToJwk(keyPair.getPublic(), null);
        assertThat(jwk).containsEntry("kty", "EC").containsEntry("crv", "P-256");
        assertThat(jwk).containsKeys("x", "y").doesNotContainKey("kid");

        PublicKey restored = Jwk.toPublicKey(jwk);
        assertThat(Jwk.publicKeyToJwk(restored, null)).isEqualTo(jwk);
    }

    @Test
    void ecP384RoundTripsThroughJwk() {
        KeyPair keyPair = KeyPairs.generateEcP384();

        Map<String, Object> jwk = Jwk.publicKeyToJwk(keyPair.getPublic(), null);
        assertThat(jwk).containsEntry("kty", "EC").containsEntry("crv", "P-384");

        PublicKey restored = Jwk.toPublicKey(jwk);
        assertThat(Jwk.publicKeyToJwk(restored, null)).isEqualTo(jwk);
    }

    @Test
    void rsaJwkConvertsToPublicKey() {
        Map<String, Object> jwk = Map.of(
                "kty",
                "RSA",
                "n",
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e",
                "AQAB");

        assertThat(Jwk.toPublicKey(jwk).getAlgorithm()).isEqualTo("RSA");
    }

    @Test
    void unsupportedKtyIsRejected() {
        assertThatThrownBy(() -> Jwk.toPublicKey(Map.of("kty", "oct", "k", "secret")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("oct");
    }

    @Test
    void unsupportedOkpCurveIsRejected() {
        assertThatThrownBy(() -> Jwk.toPublicKey(Map.of("kty", "OKP", "crv", "X25519", "x", "AAAA")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("X25519");
    }

    @Test
    void thumbprintRejectsUnsupportedKty() {
        assertThatThrownBy(() -> Jwk.thumbprint(Map.of("kty", "oct", "k", "secret")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void thumbprintSupportsSha512ForJktS512() {
        Map<String, Object> jwk = Map.of(
                "kty", "OKP",
                "crv", "Ed25519",
                "x", "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");

        String sha512 = Jwk.thumbprint(jwk, "SHA-512");
        assertThat(sha512).isNotEqualTo(Jwk.thumbprint(jwk));
        // 64-byte digest → 86 base64url chars, no padding.
        assertThat(sha512).hasSize(86).doesNotContain("=");
    }

    @Test
    void thumbprintRejectsUnknownHashAlgorithm() {
        Map<String, Object> jwk = Map.of("kty", "OKP", "crv", "Ed25519", "x", "abc");
        assertThatThrownBy(() -> Jwk.thumbprint(jwk, "SHA-3-999"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("SHA-3-999");
    }

    @Test
    void generateJwksWrapsKeys() {
        Map<String, Object> jwk = Map.of("kty", "OKP", "crv", "Ed25519", "x", "abc");
        Map<String, Object> jwks = Jwk.generateJwks(List.of(jwk));

        assertThat(jwks).containsOnlyKeys("keys");
        assertThat(jwks.get("keys")).isEqualTo(List.of(jwk));
    }
}
