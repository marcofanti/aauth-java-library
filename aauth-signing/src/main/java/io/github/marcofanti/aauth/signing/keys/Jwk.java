package io.github.marcofanti.aauth.signing.keys;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * JWK (JSON Web Key) operations: conversion between {@link PublicKey} and JWK maps, RFC 7638
 * thumbprints, and JWKS documents.
 *
 * <p>JWKs are represented as {@code Map<String, Object>} with string values, matching the JSON
 * shape used on the wire and in the Python reference implementation.
 */
public final class Jwk {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DECODER = Base64.getUrlDecoder();

    private Jwk() {}

    /**
     * Converts a public key to JWK format (Ed25519 or EC P-256/P-384).
     *
     * @param publicKey the key to convert
     * @param kid optional key ID; omitted from the JWK when {@code null}
     * @return JWK as an immutable ordered map
     * @throws IllegalArgumentException if the key type or curve is unsupported
     */
    public static Map<String, Object> publicKeyToJwk(PublicKey publicKey, String kid) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        if (publicKey instanceof EdECPublicKey edKey) {
            jwk.put("kty", "OKP");
            jwk.put("crv", "Ed25519");
            jwk.put("x", B64URL.encodeToString(ed25519ToRaw(edKey)));
        } else if (publicKey instanceof ECPublicKey ecKey) {
            int fieldBytes = (ecKey.getParams().getCurve().getField().getFieldSize() + 7) / 8;
            String crv =
                    switch (fieldBytes) {
                        case 32 -> "P-256";
                        case 48 -> "P-384";
                        default ->
                            throw new IllegalArgumentException(
                                    "Unsupported EC curve with field size " + fieldBytes * 8 + " bits");
                    };
            jwk.put("kty", "EC");
            jwk.put("crv", crv);
            jwk.put("x", B64URL.encodeToString(toFixedLength(ecKey.getW().getAffineX(), fieldBytes)));
            jwk.put("y", B64URL.encodeToString(toFixedLength(ecKey.getW().getAffineY(), fieldBytes)));
        } else {
            throw new IllegalArgumentException(
                    "Unsupported key type: " + publicKey.getClass().getName());
        }
        if (kid != null) {
            jwk.put("kid", kid);
        }
        // Map.copyOf would lose insertion order; JWKs are conventionally emitted kty-first.
        return java.util.Collections.unmodifiableMap(jwk);
    }

    /**
     * Converts a JWK to a {@link PublicKey} (Ed25519, EC P-256/P-384, or RSA).
     *
     * @throws IllegalArgumentException if the JWK uses an unsupported key type or curve
     */
    public static PublicKey toPublicKey(Map<String, Object> jwk) {
        String kty = str(jwk, "kty");
        try {
            if ("OKP".equals(kty)) {
                String crv = str(jwk, "crv");
                if (!"Ed25519".equals(crv)) {
                    throw new IllegalArgumentException("Unsupported OKP curve: " + crv);
                }
                return ed25519FromRaw(B64URL_DECODER.decode(str(jwk, "x")));
            }
            if ("EC".equals(kty)) {
                String crv = str(jwk, "crv");
                String curveName =
                        switch (crv == null ? "" : crv) {
                            case "P-256" -> "secp256r1";
                            case "P-384" -> "secp384r1";
                            default -> throw new IllegalArgumentException("Unsupported EC curve: " + crv);
                        };
                BigInteger x = new BigInteger(1, B64URL_DECODER.decode(str(jwk, "x")));
                BigInteger y = new BigInteger(1, B64URL_DECODER.decode(str(jwk, "y")));
                AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
                params.init(new ECGenParameterSpec(curveName));
                ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
                return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
            }
            if ("RSA".equals(kty)) {
                BigInteger n = new BigInteger(1, B64URL_DECODER.decode(str(jwk, "n")));
                BigInteger e = new BigInteger(1, B64URL_DECODER.decode(str(jwk, "e")));
                return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Failed to convert JWK to public key: " + e.getMessage(), e);
        }
        throw new IllegalArgumentException("Unsupported JWK kty: " + kty);
    }

    /**
     * Calculates the JWK thumbprint per RFC 7638 using SHA-256.
     *
     * @return base64url-encoded SHA-256 hash of the canonical JWK JSON (no padding)
     */
    public static String thumbprint(Map<String, Object> jwk) {
        return thumbprint(jwk, "SHA-256");
    }

    /**
     * Calculates the JWK thumbprint per RFC 7638 using the given hash algorithm.
     *
     * @param hashAlgorithm a {@link MessageDigest} algorithm name, e.g. "SHA-256" or "SHA-512"
     */
    public static String thumbprint(Map<String, Object> jwk, String hashAlgorithm) {
        String kty = str(jwk, "kty");
        // RFC 7638 §3.2: only the required members, lexicographically sorted. All values are
        // base64url or curve-name strings, so the canonical JSON can be assembled directly.
        String canonical =
                switch (kty == null ? "" : kty) {
                    case "OKP", "EC" -> canonicalEcOrOkp(jwk, kty);
                    case "RSA" -> "{\"e\":\"" + str(jwk, "e") + "\",\"kty\":\"RSA\",\"n\":\"" + str(jwk, "n") + "\"}";
                    default -> throw new IllegalArgumentException("Unsupported kty for thumbprint: " + kty);
                };
        try {
            MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
            return B64URL.encodeToString(digest.digest(canonical.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Unsupported hash algorithm: " + hashAlgorithm, e);
        }
    }

    /** Builds a JWKS document from a list of JWKs. */
    public static Map<String, Object> generateJwks(List<Map<String, Object>> keys) {
        return Map.of("keys", List.copyOf(keys));
    }

    private static String canonicalEcOrOkp(Map<String, Object> jwk, String kty) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"crv\":\"").append(str(jwk, "crv")).append("\",\"kty\":\"").append(kty);
        sb.append("\",\"x\":\"").append(str(jwk, "x")).append('"');
        if ("EC".equals(kty)) {
            sb.append(",\"y\":\"").append(str(jwk, "y")).append('"');
        }
        return sb.append('}').toString();
    }

    private static String str(Map<String, Object> jwk, String key) {
        Object value = jwk.get(key);
        return value == null ? null : value.toString();
    }

    // --- Ed25519 point encoding (RFC 8032 §5.1.2): 32 bytes little-endian y, MSB = x parity ---

    private static byte[] ed25519ToRaw(EdECPublicKey key) {
        EdECPoint point = key.getPoint();
        byte[] bigEndian = point.getY().toByteArray();
        byte[] raw = new byte[32];
        // Copy least-significant bytes reversed into little-endian order.
        int copy = Math.min(bigEndian.length, 32);
        for (int i = 0; i < copy; i++) {
            raw[i] = bigEndian[bigEndian.length - 1 - i];
        }
        if (point.isXOdd()) {
            raw[31] |= (byte) 0x80;
        }
        return raw;
    }

    private static PublicKey ed25519FromRaw(byte[] raw) throws GeneralSecurityException {
        if (raw.length != 32) {
            throw new IllegalArgumentException("Ed25519 public key must be 32 bytes, got " + raw.length);
        }
        byte[] littleEndian = raw.clone();
        boolean xOdd = (littleEndian[31] & 0x80) != 0;
        littleEndian[31] &= 0x7F;
        byte[] bigEndian = new byte[32];
        for (int i = 0; i < 32; i++) {
            bigEndian[i] = littleEndian[31 - i];
        }
        BigInteger y = new BigInteger(1, bigEndian);
        EdECPublicKeySpec spec = new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(xOdd, y));
        return KeyFactory.getInstance("Ed25519").generatePublic(spec);
    }

    private static byte[] toFixedLength(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) {
            return bytes;
        }
        byte[] fixed = new byte[length];
        if (bytes.length > length) {
            // Strip leading sign byte(s).
            System.arraycopy(bytes, bytes.length - length, fixed, 0, length);
        } else {
            System.arraycopy(bytes, 0, fixed, length - bytes.length, bytes.length);
        }
        return fixed;
    }
}
