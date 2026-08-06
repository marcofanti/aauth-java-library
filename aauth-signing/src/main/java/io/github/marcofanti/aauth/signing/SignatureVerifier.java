package io.github.marcofanti.aauth.signing;

import io.github.marcofanti.aauth.signing.keys.Jwk;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jspecify.annotations.Nullable;

/**
 * HTTP signature verification per RFC 9421 and draft-hardt-httpbis-signature-key.
 *
 * <p>Returns {@code false} for signatures that fail verification and throws
 * {@link HttpSignatureException} for structural problems (missing fetcher, unknown scheme,
 * malformed headers), mirroring the Python reference implementation.
 */
public final class SignatureVerifier {

    /** Maximum allowed skew for the {@code created} parameter, per AAuth spec (60 seconds). */
    private static final long CREATED_WINDOW_SECONDS = 60;

    private static final Pattern LABEL_PREFIX = Pattern.compile("(\\w+)=");

    private SignatureVerifier() {}

    /**
     * Verifies an HTTP message signature.
     *
     * @return {@code true} if the signature is valid, {@code false} otherwise
     * @throws HttpSignatureException on invalid format or unusable configuration
     */
    public static boolean verify(VerifyRequest request) {
        try {
            SignatureInputHeader.Parsed input = SignatureInputHeader.parse(request.signatureInput());

            String createdParam = input.params().get("created");
            if (createdParam != null) {
                long created = Long.parseLong(createdParam);
                long now = request.clock().instant().getEpochSecond();
                if (Math.abs(now - created) > CREATED_WINDOW_SECONDS) {
                    return false;
                }
            }

            SignatureKeyHeader.Parsed signatureKey = SignatureKeyHeader.parse(request.signatureKey());

            // Label consistency across all three headers (SIG-KEY §3.1).
            String inputLabel = labelOf(request.signatureInput());
            String signatureLabel = labelOf(request.signature());
            if (inputLabel == null || signatureLabel == null) {
                return false;
            }
            if (!inputLabel.equals(signatureLabel) || !inputLabel.equals(signatureKey.label())) {
                return false;
            }

            PublicKey publicKey = resolvePublicKey(request, signatureKey);
            if (publicKey == null) {
                return false;
            }

            URI uri = URI.create(request.targetUri());
            String authority = uri.getRawAuthority();
            String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
            String query = uri.getRawQuery();

            String prefix = signatureKey.label() + "=";
            String signatureParams = request.signatureInput().startsWith(prefix)
                    ? request.signatureInput().substring(prefix.length())
                    : request.signatureInput();
            if (signatureParams.isEmpty()) {
                return false;
            }

            String signatureBase = SignatureBase.build(
                    request.method(),
                    authority,
                    path,
                    query,
                    request.headers(),
                    request.body(),
                    request.signatureKey(),
                    input.components(),
                    signatureParams);

            byte[] signatureBytes = SignatureHeader.parse(request.signature(), signatureKey.label());
            return verifyWithKey(publicKey, signatureBytes, signatureBase.getBytes(StandardCharsets.UTF_8));
        } catch (HttpSignatureException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new HttpSignatureException("Signature verification failed: " + e.getMessage(), e);
        }
    }

    // --- Scheme dispatch -------------------------------------------------------------------

    private static @Nullable PublicKey resolvePublicKey(VerifyRequest request, SignatureKeyHeader.Parsed signatureKey) {
        Map<String, String> params = signatureKey.params();
        return switch (signatureKey.scheme()) {
            case "hwk" -> request.publicKey() != null ? request.publicKey() : hwkKey(params);
            case "jwks_uri" -> jwksUriKey(request, params);
            case "jkt-jwt" -> jktJwtKey(params, request);
            case "jwt" -> jwtKey(request, params);
            case "x509" -> throw new HttpSignatureException("scheme=x509 is not yet implemented");
            default -> throw new HttpSignatureException("Unknown signature scheme: " + signatureKey.scheme());
        };
    }

    /** SIG-KEY §3.3: inline JWK parameters. */
    private static PublicKey hwkKey(Map<String, String> params) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        putIfPresent(jwk, params, "kty");
        putIfPresent(jwk, params, "crv");
        putIfPresent(jwk, params, "x");
        putIfPresent(jwk, params, "y");
        putIfPresent(jwk, params, "n");
        putIfPresent(jwk, params, "e");
        putIfPresent(jwk, params, "alg");
        return Jwk.toPublicKey(jwk);
    }

    /** SIG-KEY §3.5: JWKS URI discovery via {@code {id}/.well-known/{dwk}}. */
    private static @Nullable PublicKey jwksUriKey(VerifyRequest request, Map<String, String> params) {
        JwksFetcher fetcher = request.jwksFetcher();
        if (fetcher == null) {
            throw new HttpSignatureException("scheme=jwks_uri requires jwksFetcher");
        }
        String id = requireParam(params, "id", "jwks_uri");
        String dwk = requireParam(params, "dwk", "jwks_uri");
        String kid = requireParam(params, "kid", "jwks_uri");

        Map<String, Object> jwks = fetcher.fetch(id, dwk, kid);
        if (jwks == null) {
            return null;
        }
        Map<String, Object> signingKey = findKeyByKid(jwks, kid);
        return signingKey == null ? null : Jwk.toPublicKey(signingKey);
    }

    /** SIG-KEY §3.4: self-issued key delegation from a hardware-backed enclave key. */
    private static @Nullable PublicKey jktJwtKey(Map<String, String> params, VerifyRequest request) {
        String token = params.get("jwt");
        if (token == null || token.isEmpty()) {
            return null;
        }
        Jwts.Decoded jwt;
        try {
            jwt = Jwts.parse(token);
        } catch (IllegalArgumentException e) {
            return null;
        }

        Object typ = jwt.header().get("typ");
        @Nullable
        String hashAlgorithm =
                switch (typ == null ? "" : typ.toString()) {
                    case "jkt-s256+jwt" -> "SHA-256";
                    case "jkt-s512+jwt" -> "SHA-512";
                    default -> null;
                };
        if (hashAlgorithm == null) {
            return null;
        }
        String hashName = "SHA-256".equals(hashAlgorithm) ? "sha-256" : "sha-512";

        Object headerJwk = jwt.header().get("jwk");
        if (!(headerJwk instanceof Map<?, ?> headerJwkMap)) {
            return null;
        }
        Map<String, Object> enclaveJwk = castJwk(headerJwkMap);

        String expectedIss;
        try {
            expectedIss = "urn:jkt:" + hashName + ":" + Jwk.thumbprint(enclaveJwk, hashAlgorithm);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (!expectedIss.equals(jwt.claim("iss"))) {
            return null;
        }

        try {
            PublicKey enclaveKey = Jwk.toPublicKey(enclaveJwk);
            if (!Jwts.verifySignature(jwt, enclaveKey)) {
                return null;
            }
        } catch (IllegalArgumentException e) {
            return null;
        }

        Long exp = jwt.numericClaim("exp");
        long now = request.clock().instant().getEpochSecond();
        if (exp != null && now >= exp) {
            return null;
        }
        if (jwt.numericClaim("iat") == null) {
            return null;
        }

        return confirmationKey(jwt);
    }

    /** SIG-KEY §3.6: JWT confirmation key. Token-type validation belongs to the protocol layer. */
    private static @Nullable PublicKey jwtKey(VerifyRequest request, Map<String, String> params) {
        JwksFetcher fetcher = request.jwksFetcher();
        if (fetcher == null) {
            throw new HttpSignatureException("scheme=jwt requires jwksFetcher");
        }
        String token = params.get("jwt");
        if (token == null || token.isEmpty()) {
            return null;
        }
        Jwts.Decoded jwt;
        try {
            jwt = Jwts.parse(token);
        } catch (IllegalArgumentException e) {
            return null;
        }

        Long exp = jwt.numericClaim("exp");
        long now = request.clock().instant().getEpochSecond();
        if (exp != null && now >= exp) {
            return null;
        }

        Object cnf = jwt.payload().get("cnf");
        if (!(cnf instanceof Map<?, ?> cnfMap) || !(cnfMap.get("jwk") instanceof Map)) {
            return null;
        }

        String iss = jwt.claim("iss");
        if (iss == null) {
            return null;
        }
        String dwk = jwt.claim("dwk");
        Object kidHeader = jwt.header().get("kid");
        if (kidHeader == null) {
            return null;
        }

        Map<String, Object> jwks = fetcher.fetch(iss, dwk, kidHeader.toString());
        if (jwks == null) {
            return null;
        }
        Map<String, Object> signingKey = findKeyByKid(jwks, kidHeader.toString());
        if (signingKey == null) {
            return null;
        }

        try {
            PublicKey issuerKey = Jwk.toPublicKey(signingKey);
            if (!Jwts.verifySignature(jwt, issuerKey)) {
                return null;
            }
        } catch (IllegalArgumentException e) {
            return null;
        }

        return confirmationKey(jwt);
    }

    private static @Nullable PublicKey confirmationKey(Jwts.Decoded jwt) {
        Object cnf = jwt.payload().get("cnf");
        if (cnf instanceof Map<?, ?> cnfMap && cnfMap.get("jwk") instanceof Map<?, ?> jwkMap) {
            try {
                return Jwk.toPublicKey(castJwk(jwkMap));
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
        return null;
    }

    // --- Signature verification ------------------------------------------------------------

    /**
     * Verifies raw signature bytes against a key. For EC keys both DER and IEEE P1363
     * ({@code r||s}, produced by the Web Crypto API) signature encodings are accepted.
     */
    private static boolean verifyWithKey(PublicKey publicKey, byte[] signatureBytes, byte[] message) {
        if ("Ed25519".equals(publicKey.getAlgorithm()) || "EdDSA".equals(publicKey.getAlgorithm())) {
            return jdkVerify("Ed25519", publicKey, signatureBytes, message);
        }
        if (publicKey instanceof ECPublicKey ecKey) {
            int fieldSize = ecKey.getParams().getCurve().getField().getFieldSize();
            String algorithm = fieldSize >= 384 ? "SHA384withECDSA" : "SHA256withECDSA";
            return jdkVerify(algorithm, publicKey, signatureBytes, message)
                    || jdkVerify(algorithm, publicKey, p1363ToDer(signatureBytes), message);
        }
        throw new HttpSignatureException("Unsupported public key type: " + publicKey.getAlgorithm());
    }

    private static boolean jdkVerify(String algorithm, PublicKey key, byte[] signatureBytes, byte[] message) {
        try {
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(key);
            verifier.update(message);
            return verifier.verify(signatureBytes);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /** Converts an IEEE P1363 ECDSA signature ({@code r||s}) to DER (ASN.1 SEQUENCE). */
    static byte[] p1363ToDer(byte[] signature) {
        int half = signature.length / 2;
        byte[] rEnc = derInteger(new BigInteger(1, java.util.Arrays.copyOfRange(signature, 0, half)));
        byte[] sEnc = derInteger(new BigInteger(1, java.util.Arrays.copyOfRange(signature, half, signature.length)));
        byte[] inner = new byte[rEnc.length + sEnc.length];
        System.arraycopy(rEnc, 0, inner, 0, rEnc.length);
        System.arraycopy(sEnc, 0, inner, rEnc.length, sEnc.length);

        List<Byte> out = new ArrayList<>();
        out.add((byte) 0x30);
        for (byte b : derLength(inner.length)) {
            out.add(b);
        }
        for (byte b : inner) {
            out.add(b);
        }
        byte[] result = new byte[out.size()];
        for (int i = 0; i < result.length; i++) {
            result[i] = out.get(i);
        }
        return result;
    }

    private static byte[] derInteger(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] encoded = new byte[2 + raw.length];
        encoded[0] = 0x02;
        encoded[1] = (byte) raw.length;
        System.arraycopy(raw, 0, encoded, 2, raw.length);
        return encoded;
    }

    private static byte[] derLength(int length) {
        if (length < 0x80) {
            return new byte[] {(byte) length};
        }
        return new byte[] {(byte) 0x81, (byte) length};
    }

    // --- Small helpers ---------------------------------------------------------------------

    private static @Nullable String labelOf(String headerValue) {
        Matcher matcher = LABEL_PREFIX.matcher(headerValue);
        return matcher.lookingAt() ? matcher.group(1) : null;
    }

    private static @Nullable Map<String, Object> findKeyByKid(Map<String, Object> jwks, String kid) {
        Object keys = jwks.get("keys");
        if (!(keys instanceof List<?> keyList)) {
            return null;
        }
        for (Object key : keyList) {
            if (key instanceof Map<?, ?> keyMap && kid.equals(keyMap.get("kid"))) {
                return castJwk(keyMap);
            }
        }
        return null;
    }

    private static Map<String, Object> castJwk(Map<?, ?> map) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            jwk.put(entry.getKey().toString(), entry.getValue());
        }
        return jwk;
    }

    private static void putIfPresent(Map<String, Object> jwk, Map<String, String> params, String name) {
        String value = params.get(name);
        if (value != null) {
            jwk.put(name, value);
        }
    }

    private static String requireParam(Map<String, String> params, String name, String scheme) {
        String value = params.get(name);
        if (value == null || value.isEmpty()) {
            throw new HttpSignatureException("scheme=" + scheme + ": missing required '" + name + "' parameter");
        }
        return value;
    }
}
