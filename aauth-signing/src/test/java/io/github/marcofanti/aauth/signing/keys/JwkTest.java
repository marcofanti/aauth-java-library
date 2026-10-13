package io.github.marcofanti.aauth.signing.keys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.signing.JoseException;
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
    void rsaJwkIsNotAcceptedForKeyConversion() {
        // Draft-11 accepts only Ed25519 / ES256 / ES384 keys; RSA survives only in thumbprints.
        Map<String, Object> jwk = Map.of("kty", "RSA", "n", "0vx7", "e", "AQAB", "alg", "RS256");

        assertThatThrownBy(() -> Jwk.toPublicKey(jwk))
                .isInstanceOf(JoseException.class)
                .extracting(e -> ((JoseException) e).errorCode())
                .isEqualTo(JoseException.UNSUPPORTED_ALGORITHM);
    }

    @Test
    void unsupportedKtyIsRejected() {
        assertThatThrownBy(() -> Jwk.toPublicKey(Map.of("kty", "oct", "k", "secret", "alg", "HS256")))
                .isInstanceOf(JoseException.class)
                .hasMessageContaining("HS256");
    }

    @Test
    void unsupportedOkpCurveIsRejectedAsInvalidKey() {
        assertThatThrownBy(() -> Jwk.toPublicKey(Map.of("kty", "OKP", "crv", "X25519", "x", "AAAA", "alg", "Ed25519")))
                .isInstanceOf(JoseException.class)
                .hasMessageContaining("X25519")
                .extracting(e -> ((JoseException) e).errorCode())
                .isEqualTo(JoseException.INVALID_KEY);
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
    void emittedJwksCarryFullySpecifiedAlg() {
        // AAuth draft-10 / RFC 9864: every emitted JWK MUST carry a fully-specified alg.
        assertThat(Jwk.publicKeyToJwk(KeyPairs.generateEd25519().getPublic(), null))
                .containsEntry("alg", "Ed25519");
        assertThat(Jwk.publicKeyToJwk(KeyPairs.generateEcP256().getPublic(), null))
                .containsEntry("alg", "ES256");
        assertThat(Jwk.publicKeyToJwk(KeyPairs.generateEcP384().getPublic(), null))
                .containsEntry("alg", "ES384");
    }

    @Test
    void validateAlgorithmIsStrict() {
        Map<String, Object> base = Jwk.publicKeyToJwk(KeyPairs.generateEd25519().getPublic(), null);
        assertThat(Jwk.validateAlgorithm(base, null)).isEqualTo("Ed25519");
        assertThat(Jwk.validateAlgorithm(base, "Ed25519")).isEqualTo("Ed25519");
        assertThat(Jwk.toPublicKey(base).getAlgorithm()).isEqualTo("EdDSA");

        // A missing alg, the polymorphic EdDSA and symmetric algs are unsupported.
        Map<String, Object> withoutAlg = new java.util.LinkedHashMap<>(base);
        withoutAlg.remove("alg");
        assertCode(withoutAlg, null, JoseException.UNSUPPORTED_ALGORITHM);
        assertCode(withAlg(base, "EdDSA"), null, JoseException.UNSUPPORTED_ALGORITHM);
        assertCode(withAlg(base, "HS256"), null, JoseException.UNSUPPORTED_ALGORITHM);

        // A supported alg on the wrong key shape, or not the expected (header) alg, is invalid_key.
        assertCode(withAlg(base, "ES256"), null, JoseException.INVALID_KEY);
        assertCode(base, "ES256", JoseException.INVALID_KEY);

        // Corrupt key material is invalid_key.
        Map<String, Object> badX = new java.util.LinkedHashMap<>(base);
        badX.put("x", "AAAA");
        assertCode(badX, null, JoseException.INVALID_KEY);
    }

    private static Map<String, Object> withAlg(Map<String, Object> jwk, String alg) {
        Map<String, Object> copy = new java.util.LinkedHashMap<>(jwk);
        copy.put("alg", alg);
        return copy;
    }

    private static void assertCode(Map<String, Object> jwk, String expectedAlg, String code) {
        assertThatThrownBy(() -> Jwk.validateAlgorithm(jwk, expectedAlg))
                .isInstanceOf(JoseException.class)
                .extracting(e -> ((JoseException) e).errorCode())
                .isEqualTo(code);
    }

    @Test
    void generateJwksWrapsKeys() {
        Map<String, Object> jwk = Map.of("kty", "OKP", "crv", "Ed25519", "x", "abc");
        Map<String, Object> jwks = Jwk.generateJwks(List.of(jwk));

        assertThat(jwks).containsOnlyKeys("keys");
        assertThat(jwks.get("keys")).isEqualTo(List.of(jwk));
    }
}
