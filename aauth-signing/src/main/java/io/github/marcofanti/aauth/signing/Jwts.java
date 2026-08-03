package io.github.marcofanti.aauth.signing;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Minimal compact JWT codec on JDK crypto.
 *
 * <p>AAuth tokens are plain compact JWTs (EdDSA-signed in practice; ES256/ES384/RS256 accepted on
 * verification). This codec avoids a JOSE library dependency: the JDK provides all required
 * signature algorithms natively on Java 17+.
 */
public final class Jwts {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DECODER = Base64.getUrlDecoder();

    private Jwts() {}

    /**
     * A parsed compact JWT. {@code signingInput} is the {@code header.payload} portion whose
     * signature is verified.
     */
    // byte[] components are intentional: raw signature bytes; record equality is never used.
    @SuppressWarnings("ArrayRecordComponent")
    public record Decoded(
            Map<String, Object> header, Map<String, Object> payload, byte[] signature, byte[] signingInput) {

        /** Convenience accessor for a string claim from the payload; {@code null} when absent. */
        public @Nullable String claim(String name) {
            Object value = payload.get(name);
            return value == null ? null : value.toString();
        }

        /** Convenience accessor for a numeric claim from the payload; {@code null} when absent. */
        public @Nullable Long numericClaim(String name) {
            Object value = payload.get(name);
            return value instanceof Number number ? number.longValue() : null;
        }
    }

    /**
     * Parses a compact JWT without verifying its signature.
     *
     * @throws IllegalArgumentException if the token is not a three-part compact JWT
     */
    public static Decoded parse(String token) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid compact JWT: expected 3 parts, got " + parts.length);
        }
        try {
            Map<String, Object> header = MAPPER.readValue(B64URL_DECODER.decode(parts[0]), MAP_TYPE);
            Map<String, Object> payload = MAPPER.readValue(B64URL_DECODER.decode(parts[1]), MAP_TYPE);
            byte[] signature = B64URL_DECODER.decode(parts[2]);
            byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
            return new Decoded(header, payload, signature, signingInput);
        } catch (IOException | IllegalArgumentException e) {
            throw new IllegalArgumentException("Failed to parse JWT: " + e.getMessage(), e);
        }
    }

    /**
     * Creates an EdDSA-signed compact JWT from the given header and payload maps.
     *
     * <p>Key order in the maps is preserved in the serialized JSON.
     */
    public static String signEdDsa(Map<String, Object> header, Map<String, Object> payload, PrivateKey privateKey) {
        try {
            String headerPart = B64URL.encodeToString(MAPPER.writeValueAsBytes(header));
            String payloadPart = B64URL.encodeToString(MAPPER.writeValueAsBytes(payload));
            byte[] signingInput = (headerPart + "." + payloadPart).getBytes(StandardCharsets.US_ASCII);

            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(privateKey);
            signer.update(signingInput);
            return headerPart + "." + payloadPart + "." + B64URL.encodeToString(signer.sign());
        } catch (IOException | GeneralSecurityException e) {
            throw new AAuthException("Failed to sign JWT: " + e.getMessage(), e);
        }
    }

    /**
     * Verifies the signature of a parsed JWT against a public key, dispatching on the
     * {@code alg} header (EdDSA, ES256, ES384, RS256).
     *
     * @return {@code true} when the signature is valid; {@code false} on any failure
     */
    public static boolean verifySignature(Decoded jwt, PublicKey publicKey) {
        Object alg = jwt.header().get("alg");
        if (alg == null) {
            return false;
        }
        String jdkAlgorithm =
                switch (alg.toString()) {
                    case "EdDSA" -> "Ed25519";
                    case "ES256" -> "SHA256withECDSAinP1363Format";
                    case "ES384" -> "SHA384withECDSAinP1363Format";
                    case "RS256" -> "SHA256withRSA";
                    default -> null;
                };
        if (jdkAlgorithm == null) {
            return false;
        }
        try {
            Signature verifier = Signature.getInstance(jdkAlgorithm);
            verifier.initVerify(publicKey);
            verifier.update(jwt.signingInput());
            return verifier.verify(jwt.signature());
        } catch (GeneralSecurityException e) {
            return false;
        }
    }
}
