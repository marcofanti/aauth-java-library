package io.github.marcofanti.aauth.signing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** End-to-end sign → verify tests across all Signature-Key schemes. */
class SignVerifyRoundTripTest {

    private static final String TARGET = "https://resource.example/api/data";

    private static Map<String, String> sign(SignRequest request) {
        return RequestSigner.sign(request);
    }

    private static VerifyRequest.Builder verifyRequest(String method, String target, Map<String, String> signed) {
        return VerifyRequest.builder(method, target)
                .headers(signed)
                .signatureHeaders(signed.get("Signature-Input"), signed.get("Signature"), signed.get("Signature-Key"));
    }

    @Test
    void hwkEd25519RoundTrip() {
        KeyPair keyPair = KeyPairs.generateEd25519();
        Map<String, String> signed = sign(SignRequest.builder("GET", TARGET)
                .keyPair(keyPair)
                .scheme(new SignatureScheme.Hwk())
                .build());

        assertThat(signed).containsKeys("Signature-Input", "Signature", "Signature-Key");
        assertThat(SignatureVerifier.verify(verifyRequest("GET", TARGET, signed).build()))
                .isTrue();
    }

    @Test
    void hwkEcP256RoundTrip() {
        KeyPair keyPair = KeyPairs.generateEcP256();
        Map<String, String> signed = sign(SignRequest.builder("GET", TARGET)
                .keyPair(keyPair)
                .scheme(new SignatureScheme.Hwk())
                .build());

        assertThat(SignatureVerifier.verify(verifyRequest("GET", TARGET, signed).build()))
                .isTrue();
    }

    @Test
    void hwkEcP384RoundTrip() {
        KeyPair keyPair = KeyPairs.generateEcP384();
        Map<String, String> signed = sign(SignRequest.builder("GET", TARGET)
                .keyPair(keyPair)
                .scheme(new SignatureScheme.Hwk())
                .build());

        assertThat(SignatureVerifier.verify(verifyRequest("GET", TARGET, signed).build()))
                .isTrue();
    }

    @Test
    void queryStringIsCoveredAndTamperingDetected() {
        KeyPair keyPair = KeyPairs.generateEd25519();
        String target = TARGET + "?a=1&b=2";
        Map<String, String> signed = sign(SignRequest.builder("GET", target)
                .keyPair(keyPair)
                .scheme(new SignatureScheme.Hwk())
                .build());

        assertThat(signed.get("Signature-Input")).contains("@query");
        assertThat(SignatureVerifier.verify(verifyRequest("GET", target, signed).build()))
                .isTrue();
        assertThat(SignatureVerifier.verify(
                        verifyRequest("GET", TARGET + "?a=1&b=TAMPERED", signed).build()))
                .isFalse();
    }

    @Test
    void methodTamperingIsDetected() {
        KeyPair keyPair = KeyPairs.generateEd25519();
        Map<String, String> signed = sign(SignRequest.builder("GET", TARGET)
                .keyPair(keyPair)
                .scheme(new SignatureScheme.Hwk())
                .build());

        assertThat(SignatureVerifier.verify(
                        verifyRequest("DELETE", TARGET, signed).build()))
                .isFalse();
    }

    @Test
    void staleCreatedTimestampIsRejected() {
        KeyPair keyPair = KeyPairs.generateEd25519();
        Map<String, String> signed = sign(SignRequest.builder("GET", TARGET)
                .keyPair(keyPair)
                .scheme(new SignatureScheme.Hwk())
                .created(Instant.now().getEpochSecond() - 300)
                .build());

        assertThat(SignatureVerifier.verify(verifyRequest("GET", TARGET, signed).build()))
                .isFalse();
    }

    @Test
    void bodyCoverageComputesContentDigest() {
        KeyPair keyPair = KeyPairs.generateEd25519();
        byte[] body = "{\"hello\": \"world\"}".getBytes(StandardCharsets.UTF_8);

        Map<String, String> signed = sign(SignRequest.builder("POST", TARGET)
                .keyPair(keyPair)
                .scheme(new SignatureScheme.Hwk())
                .body(body)
                .additionalComponents(List.of("content-digest"))
                .build());

        assertThat(signed).containsKey("Content-Digest");
        assertThat(signed.get("Signature-Input")).contains("content-digest");

        assertThat(SignatureVerifier.verify(
                        verifyRequest("POST", TARGET, signed).body(body).build()))
                .isTrue();
    }

    @Test
    void aauthMissionHeaderIsCoveredWhenPresent() {
        KeyPair keyPair = KeyPairs.generateEd25519();
        Map<String, String> headers = Map.of("AAuth-Mission", "jwt=aaa.bbb.ccc");

        Map<String, String> signed = sign(SignRequest.builder("POST", TARGET)
                .keyPair(keyPair)
                .scheme(new SignatureScheme.Hwk())
                .headers(headers)
                .build());

        assertThat(signed.get("Signature-Input")).contains("aauth-mission");

        Map<String, String> allHeaders = new LinkedHashMap<>(headers);
        allHeaders.putAll(signed);
        assertThat(SignatureVerifier.verify(VerifyRequest.builder("POST", TARGET)
                        .headers(allHeaders)
                        .signatureHeaders(
                                signed.get("Signature-Input"), signed.get("Signature"), signed.get("Signature-Key"))
                        .build()))
                .isTrue();
    }

    @Test
    void jwksUriSchemeResolvesKeyThroughFetcher() {
        KeyPair keyPair = KeyPairs.generateEd25519();
        Map<String, Object> jwks = Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(keyPair.getPublic(), "key-1")));

        Map<String, String> signed = sign(SignRequest.builder("GET", TARGET)
                .keyPair(keyPair)
                .scheme(new SignatureScheme.JwksUri("https://agent.example", "aauth-agent.json", "key-1"))
                .build());

        assertThat(SignatureVerifier.verify(verifyRequest("GET", TARGET, signed)
                        .jwksFetcher((id, dwk, kid) -> {
                            assertThat(id).isEqualTo("https://agent.example");
                            assertThat(dwk).isEqualTo("aauth-agent.json");
                            return jwks;
                        })
                        .build()))
                .isTrue();
    }

    @Test
    void jwksUriSchemeFailsWhenKidUnknown() {
        KeyPair keyPair = KeyPairs.generateEd25519();
        Map<String, Object> jwks = Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(keyPair.getPublic(), "other-key")));

        Map<String, String> signed = sign(SignRequest.builder("GET", TARGET)
                .keyPair(keyPair)
                .scheme(new SignatureScheme.JwksUri("https://agent.example", "aauth-agent.json", "key-1"))
                .build());

        assertThat(SignatureVerifier.verify(verifyRequest("GET", TARGET, signed)
                        .jwksFetcher((id, dwk, kid) -> jwks)
                        .build()))
                .isFalse();
    }

    @Test
    void jwksUriSchemeRequiresFetcher() {
        KeyPair keyPair = KeyPairs.generateEd25519();
        Map<String, String> signed = sign(SignRequest.builder("GET", TARGET)
                .keyPair(keyPair)
                .scheme(new SignatureScheme.JwksUri("https://agent.example", "aauth-agent.json", "key-1"))
                .build());

        assertThatThrownBy(() -> SignatureVerifier.verify(
                        verifyRequest("GET", TARGET, signed).build()))
                .isInstanceOf(HttpSignatureException.class)
                .hasMessageContaining("jwksFetcher");
    }

    @Test
    void jwtSchemeExtractsConfirmationKey() {
        KeyPair issuerKeyPair = KeyPairs.generateEd25519();
        KeyPair agentKeyPair = KeyPairs.generateEd25519();

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", "aa-auth+jwt");
        header.put("alg", "EdDSA");
        header.put("kid", "auth-key-1");
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", "https://auth.example");
        payload.put("dwk", "aauth-server.json");
        payload.put("cnf", Map.of("jwk", Jwk.publicKeyToJwk(agentKeyPair.getPublic(), null)));
        payload.put("exp", Instant.now().getEpochSecond() + 300);
        String authToken = Jwts.signEdDsa(header, payload, issuerKeyPair.getPrivate());

        Map<String, Object> issuerJwks =
                Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(issuerKeyPair.getPublic(), "auth-key-1")));

        Map<String, String> signed = sign(SignRequest.builder("GET", TARGET)
                .keyPair(agentKeyPair)
                .scheme(new SignatureScheme.Jwt(authToken))
                .build());

        assertThat(SignatureVerifier.verify(verifyRequest("GET", TARGET, signed)
                        .jwksFetcher((id, dwk, kid) -> "https://auth.example".equals(id) ? issuerJwks : null)
                        .build()))
                .isTrue();
    }

    @Test
    void jwtSchemeRejectsExpiredToken() {
        KeyPair issuerKeyPair = KeyPairs.generateEd25519();
        KeyPair agentKeyPair = KeyPairs.generateEd25519();

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "EdDSA");
        header.put("kid", "auth-key-1");
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", "https://auth.example");
        payload.put("cnf", Map.of("jwk", Jwk.publicKeyToJwk(agentKeyPair.getPublic(), null)));
        payload.put("exp", Instant.now().getEpochSecond() - 10);
        String expiredToken = Jwts.signEdDsa(header, payload, issuerKeyPair.getPrivate());

        Map<String, String> signed = sign(SignRequest.builder("GET", TARGET)
                .keyPair(agentKeyPair)
                .scheme(new SignatureScheme.Jwt(expiredToken))
                .build());

        assertThat(SignatureVerifier.verify(verifyRequest("GET", TARGET, signed)
                        .jwksFetcher((id, dwk, kid) -> null)
                        .build()))
                .isFalse();
    }

    @Test
    void jktJwtSchemeVerifiesSelfIssuedDelegation() {
        KeyPair enclaveKeyPair = KeyPairs.generateEd25519();
        KeyPair ephemeralKeyPair = KeyPairs.generateEd25519();

        Map<String, Object> enclaveJwk = Jwk.publicKeyToJwk(enclaveKeyPair.getPublic(), null);
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", "jkt-s256+jwt");
        header.put("alg", "EdDSA");
        header.put("jwk", enclaveJwk);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", "urn:jkt:sha-256:" + Jwk.thumbprint(enclaveJwk));
        payload.put("iat", Instant.now().getEpochSecond());
        payload.put("exp", Instant.now().getEpochSecond() + 300);
        payload.put("cnf", Map.of("jwk", Jwk.publicKeyToJwk(ephemeralKeyPair.getPublic(), null)));
        String delegationJwt = Jwts.signEdDsa(header, payload, enclaveKeyPair.getPrivate());

        Map<String, String> signed = sign(SignRequest.builder("GET", TARGET)
                .keyPair(ephemeralKeyPair)
                .scheme(new SignatureScheme.JktJwt(delegationJwt))
                .build());

        assertThat(SignatureVerifier.verify(verifyRequest("GET", TARGET, signed).build()))
                .isTrue();
    }

    @Test
    void jktJwtSchemeRejectsIssMismatch() {
        KeyPair enclaveKeyPair = KeyPairs.generateEd25519();
        KeyPair ephemeralKeyPair = KeyPairs.generateEd25519();

        Map<String, Object> enclaveJwk = Jwk.publicKeyToJwk(enclaveKeyPair.getPublic(), null);
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", "jkt-s256+jwt");
        header.put("alg", "EdDSA");
        header.put("jwk", enclaveJwk);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", "urn:jkt:sha-256:WRONG");
        payload.put("iat", Instant.now().getEpochSecond());
        payload.put("cnf", Map.of("jwk", Jwk.publicKeyToJwk(ephemeralKeyPair.getPublic(), null)));
        String delegationJwt = Jwts.signEdDsa(header, payload, enclaveKeyPair.getPrivate());

        Map<String, String> signed = sign(SignRequest.builder("GET", TARGET)
                .keyPair(ephemeralKeyPair)
                .scheme(new SignatureScheme.JktJwt(delegationJwt))
                .build());

        assertThat(SignatureVerifier.verify(verifyRequest("GET", TARGET, signed).build()))
                .isFalse();
    }

    @Test
    void tamperedSignatureIsRejected() {
        KeyPair keyPair = KeyPairs.generateEd25519();
        Map<String, String> signed = sign(SignRequest.builder("GET", TARGET)
                .keyPair(keyPair)
                .scheme(new SignatureScheme.Hwk())
                .build());

        Map<String, String> tampered = new LinkedHashMap<>(signed);
        tampered.put("Signature", SignatureHeader.build(new byte[64], "sig"));

        assertThat(SignatureVerifier.verify(VerifyRequest.builder("GET", TARGET)
                        .headers(tampered)
                        .signatureHeaders(
                                tampered.get("Signature-Input"),
                                tampered.get("Signature"),
                                tampered.get("Signature-Key"))
                        .build()))
                .isFalse();
    }

    @Test
    void labelMismatchAcrossHeadersIsRejected() {
        KeyPair keyPair = KeyPairs.generateEd25519();
        Map<String, String> signed = sign(SignRequest.builder("GET", TARGET)
                .keyPair(keyPair)
                .scheme(new SignatureScheme.Hwk())
                .build());

        String relabeledSignature = signed.get("Signature").replaceFirst("^sig=", "sig9=");

        assertThat(SignatureVerifier.verify(VerifyRequest.builder("GET", TARGET)
                        .headers(signed)
                        .signatureHeaders(
                                signed.get("Signature-Input"), relabeledSignature, signed.get("Signature-Key"))
                        .build()))
                .isFalse();
    }

    @Test
    void unknownSchemeInHeaderThrows() {
        KeyPair keyPair = KeyPairs.generateEd25519();
        Map<String, String> signed = sign(SignRequest.builder("GET", TARGET)
                .keyPair(keyPair)
                .scheme(new SignatureScheme.Hwk())
                .build());

        String bogusKeyHeader = "sig=quantum;x=\"y\"";

        assertThatThrownBy(() -> SignatureVerifier.verify(VerifyRequest.builder("GET", TARGET)
                        .headers(signed)
                        .signatureHeaders(signed.get("Signature-Input"), signed.get("Signature"), bogusKeyHeader)
                        .build()))
                .isInstanceOf(HttpSignatureException.class)
                .hasMessageContaining("Unknown signature scheme");
    }

    @Test
    void ecdsaP1363SignatureIsAcceptedOnVerify() throws Exception {
        // Simulate a Web Crypto signer: ES256 over the same signature base, P1363 encoding.
        KeyPair keyPair = KeyPairs.generateEcP256();
        Map<String, String> signed = sign(SignRequest.builder("GET", TARGET)
                .keyPair(keyPair)
                .scheme(new SignatureScheme.Hwk())
                .build());

        // Re-sign the same base in P1363 and substitute the Signature header.
        SignatureInputHeader.Parsed input = SignatureInputHeader.parse(signed.get("Signature-Input"));
        String params = signed.get("Signature-Input").substring("sig=".length());
        String base = SignatureBase.build(
                "GET",
                "resource.example",
                "/api/data",
                null,
                signed,
                null,
                signed.get("Signature-Key"),
                input.components(),
                params);
        java.security.Signature p1363 = java.security.Signature.getInstance("SHA256withECDSAinP1363Format");
        p1363.initSign(keyPair.getPrivate());
        p1363.update(base.getBytes(StandardCharsets.UTF_8));
        Map<String, String> substituted = new LinkedHashMap<>(signed);
        substituted.put("Signature", SignatureHeader.build(p1363.sign(), "sig"));

        assertThat(SignatureVerifier.verify(
                        verifyRequest("GET", TARGET, substituted).build()))
                .isTrue();
    }
}
