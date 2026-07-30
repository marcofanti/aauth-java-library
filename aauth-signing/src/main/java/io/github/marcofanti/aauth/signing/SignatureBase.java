package io.github.marcofanti.aauth.signing;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/** Signature base construction for HTTP Message Signatures (RFC 9421 §2.5). */
public final class SignatureBase {

    private SignatureBase() {}

    /**
     * Builds the signature base string per RFC 9421 §2.5.
     *
     * @param method HTTP method
     * @param authority canonical authority ({@code host[:port]})
     * @param path request path
     * @param query query string without the leading {@code ?}, or {@code null}
     * @param headers request headers (looked up case-insensitively)
     * @param body request body, or {@code null} when there is none
     * @param signatureKeyHeader the {@code Signature-Key} header value
     * @param coveredComponents component identifiers to cover, in order
     * @param signatureParams the {@code Signature-Input} value after the label, used for the
     *     final {@code @signature-params} line
     * @throws IllegalArgumentException if a component cannot be resolved from the request
     */
    public static String build(
            String method,
            String authority,
            String path,
            String query,
            Map<String, String> headers,
            byte[] body,
            String signatureKeyHeader,
            List<String> coveredComponents,
            String signatureParams) {
        if (signatureParams == null || signatureParams.isEmpty()) {
            throw new IllegalArgumentException("signatureParams is required for a valid signature base");
        }

        StringBuilder base = new StringBuilder();
        for (String component : coveredComponents) {
            String value =
                    switch (component) {
                        case "@method" -> method;
                        case "@authority" -> authority;
                        case "@path" -> path;
                        case "@query" -> {
                            if (query == null || query.isEmpty()) {
                                throw new IllegalArgumentException(
                                        "@query component specified but no query string present");
                            }
                            yield "?" + query;
                        }
                        case "content-type" -> requireBodyHeader(headers, body, "content-type");
                        case "content-digest" -> requireBodyHeader(headers, body, "content-digest");
                        case "signature-key" -> signatureKeyHeader;
                        case "aauth-mission" -> {
                            String mission = getHeader(headers, "aauth-mission");
                            if (mission == null) {
                                throw new IllegalArgumentException(
                                        "aauth-mission in Signature-Input but AAuth-Mission header missing");
                            }
                            yield mission;
                        }
                        default -> throw new IllegalArgumentException("Unknown component: " + component);
                    };
            base.append('"')
                    .append(component.toLowerCase())
                    .append("\": ")
                    .append(value)
                    .append('\n');
        }

        // @signature-params is the final line (RFC 9421 §2.5), with no trailing newline.
        base.append("\"@signature-params\": ").append(signatureParams);
        return base.toString();
    }

    /**
     * Determines covered components from the request structure.
     *
     * <p>Per AAuth spec §15.3 the signature MUST cover {@code @method}, {@code @authority},
     * {@code @path} and {@code signature-key}; {@code @query} is added when a query string is
     * present, and {@code aauth-mission} is appended after {@code signature-key} on authorization
     * requests that carry the {@code AAuth-Mission} header.
     *
     * @param query query string, or {@code null}
     * @param body request body, or {@code null} (reserved: body presence does not add components
     *     by itself; body coverage is opt-in via {@code additionalComponents})
     * @param additionalComponents extra components required by the resource, or {@code null}
     * @param includeAauthMission whether to append {@code aauth-mission}
     */
    public static List<String> determineCoveredComponents(
            String query, byte[] body, List<String> additionalComponents, boolean includeAauthMission) {
        List<String> components = new ArrayList<>(List.of("@method", "@authority", "@path"));
        if (query != null && !query.isEmpty()) {
            components.add("@query");
        }
        if (additionalComponents != null) {
            components.addAll(additionalComponents);
        }
        components.add("signature-key");
        if (includeAauthMission) {
            components.add("aauth-mission");
        }
        return List.copyOf(components);
    }

    /** Calculates the {@code Content-Digest} header value per RFC 9530 (sha-256). */
    public static String contentDigest(byte[] body) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(body);
            return "sha-256=:" + Base64.getEncoder().encodeToString(digest) + ":";
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JDK is missing SHA-256", e);
        }
    }

    private static String requireBodyHeader(Map<String, String> headers, byte[] body, String name) {
        if (body == null || body.length == 0) {
            throw new IllegalArgumentException(name + " component specified but no body present");
        }
        String value = getHeader(headers, name);
        if (value == null) {
            throw new IllegalArgumentException(name + " component required but header missing");
        }
        return value;
    }

    /** Case-insensitive header lookup; returns {@code null} when absent. */
    static String getHeader(Map<String, String> headers, String name) {
        if (headers == null) {
            return null;
        }
        String value = headers.get(name);
        if (value != null) {
            return value;
        }
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return null;
    }
}
