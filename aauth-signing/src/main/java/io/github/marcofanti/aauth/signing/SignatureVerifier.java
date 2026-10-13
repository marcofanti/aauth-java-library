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
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jspecify.annotations.Nullable;

/**
 * HTTP signature verification per RFC 9421 and draft-hardt-httpbis-signature-key (mirrors the
 * reference {@code verify_signature}, AAuth draft-11).
 *
 * <p>Returns {@code false} for signatures that fail verification and throws
 * {@link HttpSignatureException} — carrying the {@code Signature-Error} code — for structural or
 * policy failures: missing required components ({@code invalid_input}), a {@code created} in the
 * future ({@code clock_skew}), invalid keys or tokens ({@code invalid_key},
 * {@code unsupported_algorithm}, {@code invalid_jwt}, {@code expired_jwt}, {@code unknown_key}),
 * a missing fetcher, or an unknown scheme.
 */
public final class SignatureVerifier {

    /** {@code Signature-Error} code for a {@code created} timestamp ahead of the verifier's clock. */
    public static final String ERROR_CLOCK_SKEW = "clock_skew";

    /** {@code Signature-Error} code for missing required covered components. */
    public static final String ERROR_INVALID_INPUT = "invalid_input";

    private static final List<String> DEFAULT_REQUIRED = List.of("@method", "@authority", "@path", "signature-key");

    private static final Pattern LABEL_PREFIX = Pattern.compile("(\\w+)=");

    private SignatureVerifier() {}

    /**
     * Verifies an HTTP message signature.
     *
     * @return {@code true} if the signature is valid, {@code false} otherwise
     * @throws HttpSignatureException on invalid format, policy violation or unusable configuration
     */
    public static boolean verify(VerifyRequest request) {
        try {
            SignatureInputHeader.Parsed input = SignatureInputHeader.parse(request.signatureInput());
            requireComponents(request, input.components());
            if (!timestampsAcceptable(request, input)) {
                return false;
            }
            if (input.components().contains("content-digest") && !contentDigestMatches(request)) {
                return false;
            }

            SignatureKeyHeader.Parsed signatureKey = SignatureKeyHeader.parse(request.signatureKey());
            if (!labelsConsistent(request, signatureKey)) {
                return false;
            }

            PublicKey publicKey = resolvePublicKey(request, signatureKey);
            if (publicKey == null) {
                return false;
            }
            requireKeyIdMatches(input, signatureKey);
            return verifyBase(request, input, signatureKey, publicKey);
        } catch (HttpSignatureException e) {
            throw e;
        } catch (JoseException e) {
            throw new HttpSignatureException(String.valueOf(e.getMessage()), e.errorCode(), null, e);
        } catch (RuntimeException e) {
            throw new HttpSignatureException("Signature verification failed: " + e.getMessage(), e);
        }
    }

    // --- Policy checks ---------------------------------------------------------------------

    private static void requireComponents(VerifyRequest request, List<String> covered) {
        List<String> configured = request.requiredComponents();
        Set<String> required = new TreeSet<>(configured == null ? DEFAULT_REQUIRED : configured);
        if (SignatureBase.getHeader(request.headers(), "authorization") != null) {
            required.add("authorization");
        }
        if (!covered.containsAll(required)) {
            throw new HttpSignatureException(
                    "Missing required covered components",
                    ERROR_INVALID_INPUT,
                    Map.of("required_input", List.copyOf(required)),
                    null);
        }
    }

    /** {@code created} must be an integer within the window; a future one is {@code clock_skew}. */
    private static boolean timestampsAcceptable(VerifyRequest request, SignatureInputHeader.Parsed input) {
        Long created = input.integerParam("created");
        if (created == null) {
            return false;
        }
        long now = request.clock().instant().getEpochSecond();
        if (created > now + request.signatureWindow()) {
            throw new HttpSignatureException("Signature created is in the future", ERROR_CLOCK_SKEW, null, null);
        }
        if (created < now - request.signatureWindow()) {
            return false;
        }
        if (input.params().containsKey("expires")) {
            Long expires = input.integerParam("expires");
            return expires != null && expires > now && expires >= created;
        }
        return true;
    }

    private static boolean contentDigestMatches(VerifyRequest request) {
        String header = SignatureBase.getHeader(request.headers(), "content-digest");
        byte[] body = request.body();
        return header != null
                && body != null
                && SignatureBase.verifyContentDigest(header, body) == SignatureBase.DigestCheck.MATCH;
    }

    /** Label consistency across all three headers (SIG-KEY §3.1). */
    private static boolean labelsConsistent(VerifyRequest request, SignatureKeyHeader.Parsed signatureKey) {
        String inputLabel = labelOf(request.signatureInput());
        String signatureLabel = labelOf(request.signature());
        return inputLabel != null && inputLabel.equals(signatureLabel) && inputLabel.equals(signatureKey.label());
    }

    /** A {@code keyid} signature parameter must name the key the Signature-Key header carries. */
    private static void requireKeyIdMatches(SignatureInputHeader.Parsed input, SignatureKeyHeader.Parsed signatureKey) {
        if (!input.params().containsKey("keyid")) {
            return;
        }
        Map<String, String> params = signatureKey.params();
        Set<@Nullable String> candidates = new java.util.HashSet<>();
        switch (signatureKey.scheme()) {
            case "jwks_uri" -> candidates.add(params.get("kid"));
            case "hwk" -> candidates.add(Jwk.thumbprint(hwkJwk(params)));
            default -> {
                Map<String, Object> confirmation = confirmationJwk(Jwts.parse(params.getOrDefault("jwt", "")));
                if (confirmation != null) {
                    Object kid = confirmation.get("kid");
                    candidates.add(kid == null ? null : kid.toString());
                    candidates.add(Jwk.thumbprint(confirmation));
                }
            }
        }
        if (!candidates.contains(input.stringParam("keyid"))) {
            throw new HttpSignatureException(
                    "keyid disagrees with Signature-Key", JoseException.INVALID_KEY, null, null);
        }
    }

    private static boolean verifyBase(
            VerifyRequest request,
            SignatureInputHeader.Parsed input,
            SignatureKeyHeader.Parsed signatureKey,
            PublicKey publicKey) {
        URI uri = URI.create(request.targetUri());
        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        String prefix = signatureKey.label() + "=";
        String signatureParams = request.signatureInput().startsWith(prefix)
                ? request.signatureInput().substring(prefix.length())
                : request.signatureInput();
        if (signatureParams.isEmpty()) {
            return false;
        }
        String signatureBase = SignatureBase.build(
                request.method(),
                uri.getRawAuthority(),
                path,
                uri.getRawQuery(),
                request.headers(),
                request.body(),
                request.signatureKey(),
                input.components(),
                signatureParams);
        byte[] signatureBytes = SignatureHeader.parse(request.signature(), signatureKey.label());
        return verifyWithKey(publicKey, signatureBytes, signatureBase.getBytes(StandardCharsets.UTF_8));
    }

    // --- Scheme dispatch -------------------------------------------------------------------

    private static @Nullable PublicKey resolvePublicKey(VerifyRequest request, SignatureKeyHeader.Parsed signatureKey) {
        Map<String, String> params = signatureKey.params();
        return switch (signatureKey.scheme()) {
            case "hwk" -> hwkKey(request, params);
            case "jwks_uri" -> jwksUriKey(request, params);
            case "jkt-jwt" -> jktJwtKey(params);
            case "jwt" -> jwtKey(request, params);
            case "x509" -> throw new HttpSignatureException("scheme=x509 is not yet implemented");
            default -> throw new HttpSignatureException("Unknown signature scheme: " + signatureKey.scheme());
        };
    }

    /**
     * SIG-KEY §3.3: inline JWK parameters, validated strictly. A caller-supplied key must have the
     * same thumbprint as the inline one.
     */
    private static @Nullable PublicKey hwkKey(VerifyRequest request, Map<String, String> params) {
        Map<String, Object> jwk = hwkJwk(params);
        PublicKey discovered = Jwk.toPublicKey(jwk);
        PublicKey expected = request.publicKey();
        if (expected != null
                && !Jwk.thumbprint(Jwk.publicKeyToJwk(expected, null)).equals(Jwk.thumbprint(jwk))) {
            return null;
        }
        return discovered;
    }

    private static Map<String, Object> hwkJwk(Map<String, String> params) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        for (String name : List.of("kty", "crv", "x", "y", "n", "e", "alg")) {
            String value = params.get(name);
            if (value != null) {
                jwk.put(name, value);
            }
        }
        return jwk;
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
        if (jwks == null || jwks.isEmpty()) {
            return null;
        }
        Map<String, Object> signingKey = findKeyByKid(jwks, kid);
        return signingKey == null ? null : Jwk.toPublicKey(signingKey);
    }

    /**
     * SIG-KEY §3.4: self-issued key delegation from an enclave key carried in the JWT header. Any
     * failure yields {@code null} (an unverifiable signature), as in the reference.
     */
    private static @Nullable PublicKey jktJwtKey(Map<String, String> params) {
        String token = params.get("jwt");
        if (token == null || token.isEmpty()) {
            return null;
        }
        try {
            Jwts.Decoded jwt = Jwts.parse(token);
            Object typ = jwt.header().get("typ");
            String hashAlgorithm =
                    switch (typ == null ? "" : typ.toString()) {
                        case "jkt-s256+jwt" -> "SHA-256";
                        case "jkt-s512+jwt" -> "SHA-512";
                        default -> null;
                    };
            if (hashAlgorithm == null || !(jwt.header().get("jwk") instanceof Map<?, ?> headerJwkMap)) {
                return null;
            }
            Map<String, Object> enclaveJwk = castJwk(headerJwkMap);
            String hashName = "SHA-256".equals(hashAlgorithm) ? "sha-256" : "sha-512";
            if (!("urn:jkt:" + hashName + ":" + Jwk.thumbprint(enclaveJwk, hashAlgorithm)).equals(jwt.claim("iss"))) {
                return null;
            }
            Map<String, Object> payload = Jwts.verifyEmbedded(token, enclaveJwk);
            Map<String, Object> confirmation = confirmationJwk(payload);
            return confirmation == null ? null : Jwk.toPublicKey(confirmation);
        } catch (JoseException | IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * SIG-KEY §3.6: JWT confirmation key. The token is verified strictly against its issuer's
     * JWKS ({@code iss}, {@code dwk}, header {@code kid}); failures surface their error code.
     * AAuth token-type validation belongs to the protocol layer.
     */
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
            throw new JoseException("Cannot decode JWT", JoseException.INVALID_JWT, e);
        }
        String iss = jwt.claim("iss");
        String dwk = jwt.claim("dwk");
        if (iss == null || iss.isEmpty() || dwk == null || dwk.isEmpty()) {
            throw new JoseException("JWT missing issuer or dwk", JoseException.INVALID_JWT);
        }
        Object kid = jwt.header().get("kid");
        Map<String, Object> jwks = fetcher.fetch(iss, dwk, kid == null ? null : kid.toString());
        if (jwks == null || jwks.isEmpty()) {
            throw new JoseException("Issuer JWKS unavailable", JoseException.UNKNOWN_KEY);
        }
        Map<String, Object> confirmation = confirmationJwk(Jwts.verify(token, jwks));
        if (confirmation == null) {
            throw new JoseException("JWT missing cnf.jwk", JoseException.INVALID_JWT);
        }
        return Jwk.toPublicKey(confirmation);
    }

    private static @Nullable Map<String, Object> confirmationJwk(Jwts.Decoded jwt) {
        return confirmationJwk(jwt.payload());
    }

    private static @Nullable Map<String, Object> confirmationJwk(Map<String, Object> payload) {
        if (payload.get("cnf") instanceof Map<?, ?> cnf && cnf.get("jwk") instanceof Map<?, ?> jwk) {
            return castJwk(jwk);
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

    private static String requireParam(Map<String, String> params, String name, String scheme) {
        String value = params.get(name);
        if (value == null || value.isEmpty()) {
            throw new HttpSignatureException("scheme=" + scheme + ": missing required '" + name + "' parameter");
        }
        return value;
    }
}
