package io.github.marcofanti.aauth.signing;

import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/** HTTP request signing per RFC 9421 with the Signature-Key header extension. */
public final class RequestSigner {

    private static final String LABEL = "sig";

    private RequestSigner() {}

    /**
     * Signs an HTTP request.
     *
     * <p>Unlike the Python reference (which mutates the caller's header dict), this returns every
     * header the caller must add to the outgoing request: {@code Signature-Input},
     * {@code Signature}, {@code Signature-Key}, and — when body components are covered —
     * {@code Content-Digest} / {@code Content-Type} if they were computed here.
     *
     * @return headers to add to the request, in insertion order
     * @throws HttpSignatureException if signing fails
     */
    public static Map<String, String> sign(SignRequest request) {
        try {
            URI uri = URI.create(request.targetUri());
            String authority = uri.getRawAuthority();
            String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
            String query = uri.getRawQuery();

            String signatureKeyHeader = SignatureKeyHeader.build(
                    request.scheme(), LABEL, request.keyPair().getPublic());

            // Working header view for signature-base lookups: caller headers + headers we add.
            Map<String, String> workingHeaders = new LinkedHashMap<>(request.headers());
            Map<String, String> addedHeaders = new LinkedHashMap<>();
            workingHeaders.put("Signature-Key", signatureKeyHeader);

            List<String> bodyComponents = new ArrayList<>();
            byte[] body = request.body();
            if (body != null && body.length > 0) {
                for (String component : request.additionalComponents()) {
                    if ("content-type".equals(component) || "content-digest".equals(component)) {
                        bodyComponents.add(component);
                    }
                }
                if (bodyComponents.contains("content-digest") && lookup(workingHeaders, "content-digest") == null) {
                    String digest = SignatureBase.contentDigest(body);
                    workingHeaders.put("Content-Digest", digest);
                    addedHeaders.put("Content-Digest", digest);
                }
                if (bodyComponents.contains("content-type") && lookup(workingHeaders, "content-type") == null) {
                    workingHeaders.put("Content-Type", "application/octet-stream");
                    addedHeaders.put("Content-Type", "application/octet-stream");
                }
            }

            // Cover aauth-mission when the request carries AAuth-Mission (spec §Authorization
            // Endpoint Request).
            boolean includeAauthMission = lookup(workingHeaders, "aauth-mission") != null;

            List<String> coveredComponents =
                    SignatureBase.determineCoveredComponents(query, body, bodyComponents, includeAauthMission);

            long created = request.created() != null
                    ? request.created()
                    : Instant.now().getEpochSecond();
            String signatureParams = SignatureInputHeader.buildParams(coveredComponents, created);

            String signatureBase = SignatureBase.build(
                    request.method(),
                    authority,
                    path,
                    query,
                    workingHeaders,
                    body,
                    signatureKeyHeader,
                    coveredComponents,
                    signatureParams);

            byte[] signatureBytes = signWithKey(
                    request.keyPair().getPrivate(), signatureBase.getBytes(java.nio.charset.StandardCharsets.UTF_8));

            Map<String, String> result = new LinkedHashMap<>();
            result.put("Signature-Input", LABEL + "=" + signatureParams);
            result.put("Signature", SignatureHeader.build(signatureBytes, LABEL));
            result.put("Signature-Key", signatureKeyHeader);
            result.putAll(addedHeaders);
            return result;
        } catch (HttpSignatureException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new HttpSignatureException(
                    "Failed to sign request: " + e.getMessage(),
                    null,
                    Map.of("scheme", request.scheme().wireName()),
                    e);
        }
    }

    private static byte[] signWithKey(PrivateKey privateKey, byte[] message) {
        try {
            Signature signer = Signature.getInstance(jdkAlgorithmFor(privateKey));
            signer.initSign(privateKey);
            signer.update(message);
            return signer.sign();
        } catch (GeneralSecurityException e) {
            throw new HttpSignatureException("Signing failed: " + e.getMessage(), e);
        }
    }

    private static String jdkAlgorithmFor(PrivateKey privateKey) {
        if ("Ed25519".equals(privateKey.getAlgorithm()) || "EdDSA".equals(privateKey.getAlgorithm())) {
            return "Ed25519";
        }
        if (privateKey instanceof ECPrivateKey ecKey) {
            int fieldSize = ecKey.getParams().getCurve().getField().getFieldSize();
            return fieldSize >= 384 ? "SHA384withECDSA" : "SHA256withECDSA";
        }
        throw new HttpSignatureException("Unsupported private key type: " + privateKey.getAlgorithm());
    }

    private static @Nullable String lookup(Map<String, String> headers, String name) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return null;
    }
}
