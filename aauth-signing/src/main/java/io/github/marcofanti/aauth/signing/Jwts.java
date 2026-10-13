package io.github.marcofanti.aauth.signing;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Minimal compact JWT codec on JDK crypto.
 *
 * <p>AAuth tokens are plain compact JWTs signed with a fully-specified algorithm ({@code Ed25519},
 * {@code ES256} or {@code ES384}). This codec avoids a JOSE library dependency: the JDK provides
 * all required signature algorithms natively.
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
     * Encodes and signs a compact JWT with header {@code {typ, alg, kid}}, deriving the
     * fully-specified {@code alg} from the key: {@code Ed25519} for an EdDSA key, {@code ES256} /
     * {@code ES384} for an EC P-256 / P-384 key (mirrors the reference {@code encode_jwt}).
     *
     * @throws AAuthException if the key type is unsupported or signing fails
     */
    public static String encode(Map<String, Object> payload, PrivateKey privateKey, String kid, String typ) {
        String alg = algFor(privateKey);
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", typ);
        header.put("alg", alg);
        header.put("kid", kid);
        try {
            String headerPart = B64URL.encodeToString(MAPPER.writeValueAsBytes(header));
            String payloadPart = B64URL.encodeToString(MAPPER.writeValueAsBytes(payload));
            byte[] signingInput = (headerPart + "." + payloadPart).getBytes(StandardCharsets.US_ASCII);
            Signature signer = Signature.getInstance(jdkAlgorithm(alg));
            signer.initSign(privateKey);
            signer.update(signingInput);
            return headerPart + "." + payloadPart + "." + B64URL.encodeToString(signer.sign());
        } catch (IOException | GeneralSecurityException e) {
            throw new AAuthException("Failed to sign JWT: " + e.getMessage(), e);
        }
    }

    private static String algFor(PrivateKey privateKey) {
        if (privateKey instanceof java.security.interfaces.EdECPrivateKey) {
            return "Ed25519";
        }
        if (privateKey instanceof java.security.interfaces.ECPrivateKey ecKey) {
            int fieldSize = ecKey.getParams().getCurve().getField().getFieldSize();
            if (fieldSize == 256) {
                return "ES256";
            }
            if (fieldSize == 384) {
                return "ES384";
            }
        }
        throw new AAuthException("Unsupported JWT signing key: " + privateKey.getAlgorithm());
    }

    private static String jdkAlgorithm(String alg) {
        return switch (alg) {
            case "ES256" -> "SHA256withECDSAinP1363Format";
            case "ES384" -> "SHA384withECDSAinP1363Format";
            default -> "Ed25519";
        };
    }

    /**
     * Verifies the signature of a parsed JWT against a public key, dispatching on the
     * fully-specified {@code alg} header ({@code Ed25519}, {@code ES256}, {@code ES384}). The
     * polymorphic {@code EdDSA} and every other algorithm are rejected (RFC 9864, AAuth draft-11).
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
                    case "Ed25519" -> "Ed25519";
                    case "ES256" -> "SHA256withECDSAinP1363Format";
                    case "ES384" -> "SHA384withECDSAinP1363Format";
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

    /**
     * Verifies a JWT against its issuer's JWKS (mirrors the reference {@code verify_jwt}): the
     * header {@code alg} must be fully specified, {@code kid} is required and must select exactly
     * one key, then {@link #verifyEmbedded(String, Map)} applies.
     *
     * @return the verified payload
     * @throws JoseException with the wire error code on any failure
     */
    public static Map<String, Object> verify(String token, Map<String, Object> jwks) {
        Decoded jwt = parseOrThrow(token);
        Object alg = jwt.header().get("alg");
        if (!Jwk.isSupportedAlg(alg == null ? null : alg.toString())) {
            throw new JoseException("Unsupported JWT algorithm: " + alg, JoseException.UNSUPPORTED_ALGORITHM);
        }
        if (!(jwt.header().get("kid") instanceof String kid) || kid.isEmpty()) {
            throw new JoseException("JWT missing kid", JoseException.INVALID_JWT);
        }
        if (!(jwks.get("keys") instanceof List<?> keys)) {
            throw new JoseException("Invalid JWKS", JoseException.UNKNOWN_KEY);
        }
        // Inspect only the selected key, so unrelated algorithms in the JWKS are allowed.
        List<Map<String, Object>> matches = new ArrayList<>();
        for (Object key : keys) {
            if (key instanceof Map<?, ?> map && kid.equals(map.get("kid"))) {
                matches.add(stringKeyed(map));
            }
        }
        if (matches.size() != 1) {
            throw new JoseException("Missing or ambiguous issuer key for kid " + kid, JoseException.UNKNOWN_KEY);
        }
        return verifyEmbedded(token, matches.get(0));
    }

    /**
     * Verifies a JWT against a single JWK (mirrors the reference {@code verify_embedded_jwt}):
     * the key must validate for the header {@code alg}, the signature must verify, {@code iat}
     * and {@code exp} must be numbers with {@code exp > now} (no clock-skew tolerance) and
     * {@code exp > iat}.
     *
     * @return the verified payload
     * @throws JoseException with the wire error code on any failure
     */
    public static Map<String, Object> verifyEmbedded(String token, Map<String, Object> key) {
        Decoded jwt = parseOrThrow(token);
        Object alg = jwt.header().get("alg");
        Jwk.validateAlgorithm(key, alg == null ? null : alg.toString());
        if (!verifySignature(jwt, Jwk.toPublicKey(key))) {
            throw new JoseException("JWT signature verification failed", JoseException.INVALID_JWT);
        }
        // JSON booleans decode to Boolean, never Number, so no separate boolean guard is needed.
        if (!(jwt.payload().get("iat") instanceof Number iat)
                || !(jwt.payload().get("exp") instanceof Number exp)
                || !Double.isFinite(iat.doubleValue())
                || !Double.isFinite(exp.doubleValue())) {
            throw new JoseException("JWT missing or invalid iat/exp", JoseException.INVALID_JWT);
        }
        if (exp.doubleValue() <= System.currentTimeMillis() / 1000.0) {
            throw new JoseException("Token has expired", JoseException.EXPIRED_JWT);
        }
        if (exp.doubleValue() <= iat.doubleValue()) {
            throw new JoseException("Invalid token lifetime", JoseException.INVALID_JWT);
        }
        return jwt.payload();
    }

    private static Decoded parseOrThrow(String token) {
        try {
            return parse(token);
        } catch (IllegalArgumentException e) {
            throw new JoseException("Cannot decode JWT", JoseException.INVALID_JWT, e);
        }
    }

    private static Map<String, Object> stringKeyed(Map<?, ?> map) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            result.put(String.valueOf(entry.getKey()), entry.getValue());
        }
        return result;
    }
}
