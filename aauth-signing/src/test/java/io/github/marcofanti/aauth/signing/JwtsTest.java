package io.github.marcofanti.aauth.signing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import java.security.KeyPair;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class JwtsTest {

    private final KeyPair keyPair = KeyPairs.generateEd25519();
    private final Map<String, Object> jwks = Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(keyPair.getPublic(), "k1")));

    private static long now() {
        return Instant.now().getEpochSecond();
    }

    private String token(Map<String, Object> header, Map<String, Object> payload) {
        return Jwts.signEdDsa(header, payload, keyPair.getPrivate());
    }

    private String validToken() {
        return token(header("Ed25519", "k1"), times(now() - 10, now() + 300));
    }

    private static Map<String, Object> header(String alg, String kid) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", alg);
        if (kid != null) {
            header.put("kid", kid);
        }
        return header;
    }

    private static Map<String, Object> times(Long iat, Long exp) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", "https://portal.uma.lab");
        if (iat != null) {
            payload.put("iat", iat);
        }
        if (exp != null) {
            payload.put("exp", exp);
        }
        return payload;
    }

    private static void assertCode(Runnable call, String code) {
        assertThatThrownBy(call::run)
                .isInstanceOf(JoseException.class)
                .extracting(e -> ((JoseException) e).errorCode())
                .isEqualTo(code);
    }

    @Test
    void signParseVerifyRoundTrip() {
        Map<String, Object> header = new LinkedHashMap<>(Map.of("alg", "Ed25519", "typ", "aa-agent+jwt"));
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", "https://portal.uma.lab");
        payload.put("exp", 4102444800L);

        Jwts.Decoded decoded = Jwts.parse(token(header, payload));

        assertThat(decoded.header()).containsEntry("alg", "Ed25519").containsEntry("typ", "aa-agent+jwt");
        assertThat(decoded.claim("iss")).isEqualTo("https://portal.uma.lab");
        assertThat(decoded.numericClaim("exp")).isEqualTo(4102444800L);
        assertThat(decoded.claim("missing")).isNull();
        assertThat(decoded.numericClaim("iss")).isNull();
        assertThat(Jwts.verifySignature(decoded, keyPair.getPublic())).isTrue();
    }

    @Test
    void polymorphicEdDsaIsRejected() {
        // RFC 9864 / AAuth draft-11: the fully-specified Ed25519 is required.
        String legacy = token(header("EdDSA", "k1"), times(now(), now() + 300));
        assertThat(Jwts.verifySignature(Jwts.parse(legacy), keyPair.getPublic()))
                .isFalse();
        assertCode(() -> Jwts.verify(legacy, jwks), JoseException.UNSUPPORTED_ALGORITHM);
    }

    @Test
    void verifyFailsWithWrongKey() {
        KeyPair other = KeyPairs.generateEd25519();
        assertThat(Jwts.verifySignature(Jwts.parse(validToken()), other.getPublic()))
                .isFalse();

        Map<String, Object> otherJwks = Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(other.getPublic(), "k1")));
        assertCode(() -> Jwts.verify(validToken(), otherJwks), JoseException.INVALID_JWT);
    }

    @Test
    void verifyFailsForUnknownOrMissingAlg() {
        String hs256 = token(Map.of("alg", "HS256"), Map.of());
        assertThat(Jwts.verifySignature(Jwts.parse(hs256), keyPair.getPublic())).isFalse();

        String noAlg = token(Map.of("typ", "JWT"), Map.of());
        assertThat(Jwts.verifySignature(Jwts.parse(noAlg), keyPair.getPublic())).isFalse();
        assertCode(() -> Jwts.verify(noAlg, jwks), JoseException.UNSUPPORTED_ALGORITHM);
    }

    @Test
    void verifyReturnsPayloadForValidToken() {
        assertThat(Jwts.verify(validToken(), jwks)).containsEntry("iss", "https://portal.uma.lab");
    }

    @Test
    void verifyRequiresKidSelectingExactlyOneKey() {
        assertCode(
                () -> Jwts.verify(token(header("Ed25519", null), times(now(), now() + 300)), jwks),
                JoseException.INVALID_JWT);
        assertCode(
                () -> Jwts.verify(token(header("Ed25519", "nope"), times(now(), now() + 300)), jwks),
                JoseException.UNKNOWN_KEY);

        Map<String, Object> key = Jwk.publicKeyToJwk(keyPair.getPublic(), "k1");
        assertCode(() -> Jwts.verify(validToken(), Jwk.generateJwks(List.of(key, key))), JoseException.UNKNOWN_KEY);
        assertCode(() -> Jwts.verify(validToken(), Map.of("keys", "not-a-list")), JoseException.UNKNOWN_KEY);
    }

    @Test
    void verifyEmbeddedEnforcesTimes() {
        Map<String, Object> key = Jwk.publicKeyToJwk(keyPair.getPublic(), "k1");
        assertCode(
                () -> Jwts.verifyEmbedded(token(header("Ed25519", "k1"), times(null, now() + 300)), key),
                JoseException.INVALID_JWT);
        assertCode(
                () -> Jwts.verifyEmbedded(token(header("Ed25519", "k1"), times(now(), null)), key),
                JoseException.INVALID_JWT);
        assertCode(
                () -> Jwts.verifyEmbedded(token(header("Ed25519", "k1"), times(now() - 600, now() - 1)), key),
                JoseException.EXPIRED_JWT);
        assertCode(
                () -> Jwts.verifyEmbedded(token(header("Ed25519", "k1"), times(now() + 900, now() + 600)), key),
                JoseException.INVALID_JWT);
    }

    @Test
    void verifyEmbeddedRequiresKeyAlgToMatchHeader() {
        Map<String, Object> ecKey = Jwk.publicKeyToJwk(KeyPairs.generateEcP256().getPublic(), "k1");
        assertCode(() -> Jwts.verifyEmbedded(validToken(), ecKey), JoseException.INVALID_KEY);
    }

    @Test
    void verifyRejectsMalformedToken() {
        assertCode(() -> Jwts.verify("only.two", jwks), JoseException.INVALID_JWT);
    }

    @Test
    void parseRejectsMalformedTokens() {
        assertThatThrownBy(() -> Jwts.parse("only.two")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Jwts.parse("not-base64!.x.y")).isInstanceOf(IllegalArgumentException.class);
    }
}
