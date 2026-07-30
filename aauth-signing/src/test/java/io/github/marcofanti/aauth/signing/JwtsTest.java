package io.github.marcofanti.aauth.signing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import java.security.KeyPair;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class JwtsTest {

    @Test
    void signParseVerifyRoundTrip() {
        KeyPair keyPair = KeyPairs.generateEd25519();
        Map<String, Object> header = new LinkedHashMap<>(Map.of("alg", "EdDSA", "typ", "aa-agent+jwt"));
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", "https://agent.example");
        payload.put("exp", 4102444800L);

        String token = Jwts.signEdDsa(header, payload, keyPair.getPrivate());
        Jwts.Decoded decoded = Jwts.parse(token);

        assertThat(decoded.header()).containsEntry("alg", "EdDSA").containsEntry("typ", "aa-agent+jwt");
        assertThat(decoded.claim("iss")).isEqualTo("https://agent.example");
        assertThat(decoded.numericClaim("exp")).isEqualTo(4102444800L);
        assertThat(decoded.claim("missing")).isNull();
        assertThat(decoded.numericClaim("iss")).isNull();

        assertThat(Jwts.verifySignature(decoded, keyPair.getPublic())).isTrue();
    }

    @Test
    void verifyFailsWithWrongKey() {
        KeyPair signer = KeyPairs.generateEd25519();
        KeyPair other = KeyPairs.generateEd25519();
        String token = Jwts.signEdDsa(Map.of("alg", "EdDSA"), Map.of("iss", "x"), signer.getPrivate());

        assertThat(Jwts.verifySignature(Jwts.parse(token), other.getPublic())).isFalse();
    }

    @Test
    void verifyFailsForUnknownOrMissingAlg() {
        KeyPair keyPair = KeyPairs.generateEd25519();
        String token = Jwts.signEdDsa(Map.of("alg", "HS256"), Map.of(), keyPair.getPrivate());
        assertThat(Jwts.verifySignature(Jwts.parse(token), keyPair.getPublic())).isFalse();

        String noAlg = Jwts.signEdDsa(Map.of("typ", "JWT"), Map.of(), keyPair.getPrivate());
        assertThat(Jwts.verifySignature(Jwts.parse(noAlg), keyPair.getPublic())).isFalse();
    }

    @Test
    void parseRejectsMalformedTokens() {
        assertThatThrownBy(() -> Jwts.parse("only.two")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Jwts.parse("not-base64!.x.y")).isInstanceOf(IllegalArgumentException.class);
    }
}
