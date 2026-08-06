package io.github.marcofanti.aauth.resource;

import io.github.marcofanti.aauth.headers.AAuthHeaders;
import io.github.marcofanti.aauth.signing.HttpSignatureException;
import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.SignatureBase;
import io.github.marcofanti.aauth.signing.SignatureInputHeader;
import io.github.marcofanti.aauth.signing.SignatureKeyHeader;
import io.github.marcofanti.aauth.signing.SignatureVerifier;
import io.github.marcofanti.aauth.signing.VerifyRequest;
import java.net.URI;
import java.util.List;
import java.util.Map;

/** Verifies incoming signed requests for the resource role. */
public final class RequestVerifier {

    private final List<String> canonicalAuthorities;
    private final JwksFetcher jwksFetcher;

    /**
     * @param canonicalAuthorities canonical authorities ({@code host[:port]}) this resource
     *     accepts, per spec §10.3.1
     * @param jwksFetcher key discovery for {@code jwks_uri}/{@code jwt} schemes; may be
     *     {@code null} when only pseudonymous schemes are expected
     */
    public RequestVerifier(List<String> canonicalAuthorities, JwksFetcher jwksFetcher) {
        this.canonicalAuthorities = List.copyOf(canonicalAuthorities);
        this.jwksFetcher = jwksFetcher;
    }

    /**
     * Outcome of request verification. When {@code valid} is false, {@code error} explains why;
     * identity fields are filled in based on the Signature-Key scheme. {@code mission} is the
     * parsed {@code AAuth-Mission} header when the request carried one (always
     * signature-covered — see {@link #verifyRequest}).
     */
    public record Result(
            boolean valid,
            String agentId,
            Map<String, Object> act,
            String userSub,
            List<String> scopes,
            AAuthHeaders.Mission mission,
            String error) {

        static Result failure(String error) {
            return new Result(false, null, null, null, null, null, error);
        }
    }

    /**
     * Verifies an incoming request's HTTP signature and extracts identity/authorization context.
     *
     * <p>When the request carries both a {@code Content-Digest} header and a body, the digest is
     * recomputed from the body per RFC 9530 and the request is rejected on mismatch — unlike the
     * Python reference, which only signs/verifies the header value.
     *
     * @param method HTTP method
     * @param targetUri target URI as received
     * @param headers request headers (must include the three signature headers)
     * @param body request body, or {@code null}
     * @param requireIdentity fail when the scheme conveys no agent identity
     * @param requireAuthToken fail when the request carries no auth-token scopes
     */
    public Result verifyRequest(
            String method,
            String targetUri,
            Map<String, String> headers,
            byte[] body,
            boolean requireIdentity,
            boolean requireAuthToken) {
        String signatureInput = header(headers, "Signature-Input");
        String signature = header(headers, "Signature");
        String signatureKey = header(headers, "Signature-Key");
        if (signatureInput == null || signature == null || signatureKey == null) {
            return Result.failure("Missing signature headers");
        }

        SignatureKeyHeader.Parsed parsedKey;
        try {
            parsedKey = SignatureKeyHeader.parse(signatureKey);
        } catch (RuntimeException e) {
            return Result.failure("Invalid Signature-Key: " + e.getMessage());
        }

        String requestAuthority = URI.create(targetUri).getRawAuthority();
        if (!canonicalAuthorities.contains(requestAuthority)) {
            return Result.failure("Request authority " + requestAuthority + " not in canonical authorities");
        }

        try {
            boolean valid = SignatureVerifier.verify(VerifyRequest.builder(method, targetUri)
                    .headers(headers)
                    .body(body)
                    .signatureHeaders(signatureInput, signature, signatureKey)
                    .jwksFetcher(jwksFetcher)
                    .build());
            if (!valid) {
                return Result.failure("Signature verification failed");
            }
        } catch (HttpSignatureException e) {
            return Result.failure(e.getMessage());
        }

        // RFC 9530 body-digest enforcement: the signature base covers the Content-Digest
        // *header*, not the body itself, so a tampered body with an intact header would pass
        // signature verification. Recompute whenever both header and body are present.
        // Intentional divergence from the Python reference, which trusts the header.
        String contentDigest = header(headers, "Content-Digest");
        if (contentDigest != null && body != null && body.length > 0) {
            switch (SignatureBase.verifyContentDigest(contentDigest, body)) {
                case MISMATCH -> {
                    return Result.failure("content-digest mismatch");
                }
                case NO_SUPPORTED_ALGORITHM -> {
                    return Result.failure("unsupported content-digest algorithm");
                }
                case MATCH -> {
                    // Body integrity confirmed.
                }
            }
        }

        // Spec §Authorization Endpoint Request: a request carrying AAuth-Mission MUST cover it
        // in the signature; an uncovered mission header could be swapped after signing.
        AAuthHeaders.Mission mission = null;
        String missionHeader = header(headers, AAuthHeaders.HEADER_AAUTH_MISSION);
        if (missionHeader != null) {
            if (!SignatureInputHeader.parse(signatureInput).components().contains("aauth-mission")) {
                return Result.failure("aauth-mission header not covered by signature");
            }
            mission = AAuthHeaders.parseMissionHeader(missionHeader);
        }

        String agentId = null;
        Map<String, Object> act = null;
        String userSub = null;
        List<String> scopes = null;

        switch (parsedKey.scheme()) {
            case "jwks_uri" -> agentId = parsedKey.params().get("id");
            case "jwt" -> {
                String token = parsedKey.params().get("jwt");
                if (token != null) {
                    try {
                        Jwts.Decoded jwt = Jwts.parse(token);
                        Object typ = jwt.header().get("typ");
                        if ("aa-agent+jwt".equals(typ)) {
                            // Agent token: sub is the agent (delegate) identifier.
                            agentId = jwt.claim("sub");
                        } else if ("aa-auth+jwt".equals(typ)) {
                            agentId = jwt.claim("agent");
                            userSub = jwt.claim("sub");
                            act = jwt.payload().get("act") instanceof Map<?, ?> actMap ? castMap(actMap) : null;
                            String scope = jwt.claim("scope");
                            // Whitespace-collapsing split, matching Python's str.split(); an
                            // empty or blank scope claim yields no scopes at all.
                            if (scope != null && !scope.isBlank()) {
                                scopes = List.of(scope.strip().split("\\s+"));
                            }
                        }
                    } catch (IllegalArgumentException e) {
                        // The HTTP signature already verified; claim extraction is best-effort.
                    }
                }
            }
            default -> {
                // hwk / jkt-jwt are pseudonymous — no identity to extract.
            }
        }

        if (requireIdentity && agentId == null) {
            return Result.failure("Agent identity required but not present");
        }
        if (requireAuthToken && (scopes == null || scopes.isEmpty())) {
            return Result.failure("Auth token required but not present");
        }

        return new Result(true, agentId, act, userSub, scopes, mission, null);
    }

    private static String header(Map<String, String> headers, String name) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return null;
    }

    private static Map<String, Object> castMap(Map<?, ?> map) {
        Map<String, Object> result = new java.util.LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            result.put(entry.getKey().toString(), entry.getValue());
        }
        return result;
    }
}
