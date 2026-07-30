package io.github.marcofanti.aauth.http;

import io.github.marcofanti.aauth.headers.AAuthHeaders;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Deferred response handling per AAuth spec §10.
 *
 * <p>Any endpoint may return 202 Accepted with a {@code Location} header to indicate the request
 * is pending; the agent polls the Location URL with GET until a terminal response.
 */
public final class DeferredResponses {

    private static final String CODE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final SecureRandom RANDOM = new SecureRandom();

    private DeferredResponses() {}

    /** Generates a unique pending-request ID for use in Location URLs (12 hex chars). */
    public static String generatePendingId() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    }

    /** Generates an interaction code per spec §19.11 (uppercase letters and digits). */
    public static String generateInteractionCode(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(CODE_ALPHABET.charAt(RANDOM.nextInt(CODE_ALPHABET.length())));
        }
        return sb.toString();
    }

    /** Generates an 8-character interaction code. */
    public static String generateInteractionCode() {
        return generateInteractionCode(8);
    }

    /**
     * Parameters shared by the pending-response body and header builders.
     *
     * @param location the pending URL (echoed in the body and the {@code Location} header)
     * @param status {@code pending} (default) or {@code interacting}
     * @param require requirement level ({@code interaction}, {@code approval},
     *     {@code clarification}, {@code claims}), or {@code null}
     * @param code interaction code (required when require=interaction)
     * @param url interaction URL (required in headers when require=interaction, spec §6.2)
     * @param clarification the question asked during clarification chat
     * @param requiredClaims claim names for require=claims
     * @param clarificationTimeout body {@code timeout} field, or {@code null}
     * @param clarificationOptions body {@code options} field, or {@code null}
     * @param retryAfter seconds before the agent should poll (headers only)
     */
    public record PendingSpec(
            String location,
            String status,
            String require,
            String code,
            String url,
            String clarification,
            List<String> requiredClaims,
            Integer clarificationTimeout,
            List<String> clarificationOptions,
            int retryAfter) {

        public PendingSpec {
            if (location == null || location.isEmpty()) {
                throw new IllegalArgumentException("location is required");
            }
            status = status == null ? "pending" : status;
        }

        public static Builder builder(String location) {
            return new Builder(location);
        }

        /** Builder for {@link PendingSpec}. */
        public static final class Builder {
            private final String location;
            private String status;
            private String require;
            private String code;
            private String url;
            private String clarification;
            private List<String> requiredClaims;
            private Integer clarificationTimeout;
            private List<String> clarificationOptions;
            private int retryAfter;

            private Builder(String location) {
                this.location = location;
            }

            public Builder status(String status) {
                this.status = status;
                return this;
            }

            public Builder require(String require) {
                this.require = require;
                return this;
            }

            public Builder code(String code) {
                this.code = code;
                return this;
            }

            public Builder url(String url) {
                this.url = url;
                return this;
            }

            public Builder clarification(String clarification) {
                this.clarification = clarification;
                return this;
            }

            public Builder requiredClaims(List<String> requiredClaims) {
                this.requiredClaims = requiredClaims;
                return this;
            }

            public Builder clarificationTimeout(Integer timeout) {
                this.clarificationTimeout = timeout;
                return this;
            }

            public Builder clarificationOptions(List<String> options) {
                this.clarificationOptions = options;
                return this;
            }

            public Builder retryAfter(int retryAfter) {
                this.retryAfter = retryAfter;
                return this;
            }

            public PendingSpec build() {
                return new PendingSpec(
                        location,
                        status,
                        require,
                        code,
                        url,
                        clarification,
                        requiredClaims,
                        clarificationTimeout,
                        clarificationOptions,
                        retryAfter);
            }
        }
    }

    /** Builds the JSON body for a 202 Accepted pending response. */
    public static Map<String, Object> buildPendingResponseBody(PendingSpec spec) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", spec.status());
        body.put("location", spec.location());
        if (spec.require() != null) {
            body.put("requirement", spec.require());
        }
        if (spec.code() != null) {
            body.put("code", spec.code());
        }
        if (spec.clarification() != null) {
            body.put("clarification", spec.clarification());
        }
        if (spec.requiredClaims() != null && !spec.requiredClaims().isEmpty()) {
            body.put("required_claims", spec.requiredClaims());
        }
        if (spec.clarificationTimeout() != null) {
            body.put("timeout", spec.clarificationTimeout());
        }
        if (spec.clarificationOptions() != null && !spec.clarificationOptions().isEmpty()) {
            body.put("options", spec.clarificationOptions());
        }
        return body;
    }

    /** Builds the response headers for a 202 Accepted pending response. */
    public static Map<String, String> buildPendingResponseHeaders(PendingSpec spec) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Location", spec.location());
        headers.put("Retry-After", String.valueOf(spec.retryAfter()));
        headers.put("Cache-Control", "no-store");
        headers.put("Content-Type", "application/json");

        String require = spec.require();
        if ("interaction".equals(require) && spec.code() != null && spec.url() != null) {
            headers.put(
                    AAuthHeaders.HEADER_AAUTH_REQUIREMENT,
                    AAuthHeaders.buildInteractionRequirement(spec.url(), spec.code()));
        } else if ("approval".equals(require)) {
            headers.put(AAuthHeaders.HEADER_AAUTH_REQUIREMENT, AAuthHeaders.buildApprovalRequirement());
        } else if ("clarification".equals(require)) {
            // Spec §Clarification Chat: the 202 carrying a question MUST signal it in the header.
            headers.put(AAuthHeaders.HEADER_AAUTH_REQUIREMENT, AAuthHeaders.buildClarificationRequirement());
        } else if ("claims".equals(require)
                && spec.requiredClaims() != null
                && !spec.requiredClaims().isEmpty()) {
            StringBuilder inner = new StringBuilder();
            for (int i = 0; i < spec.requiredClaims().size(); i++) {
                if (i > 0) {
                    inner.append(' ');
                }
                inner.append('"').append(spec.requiredClaims().get(i)).append('"');
            }
            headers.put(AAuthHeaders.HEADER_AAUTH_REQUIREMENT, "requirement=claims; required_claims=(" + inner + ")");
        }
        return headers;
    }

    /** Builds the JSON body for a successful token response (200 OK). */
    public static Map<String, Object> buildSuccessResponse(String authToken, int expiresIn) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("auth_token", authToken);
        body.put("expires_in", expiresIn);
        return body;
    }

    /** Builds the error body for terminal polling responses. */
    public static Map<String, Object> buildPollingErrorBody(String error, String description) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        if (description != null && !description.isEmpty()) {
            body.put("error_description", description);
        }
        return body;
    }

    /** A parsed 202 pending body. Unrecognized status values normalize to {@code pending}. */
    public record PendingResponse(
            String status, String location, String requirement, String code, String clarification) {}

    /** Parses a pending response body from a server. */
    public static PendingResponse parsePendingResponse(Map<String, Object> body) {
        String status = str(body.get("status"));
        if (!"pending".equals(status) && !"interacting".equals(status)) {
            status = "pending";
        }
        String requirement = str(body.get("requirement"));
        if (requirement == null) {
            requirement = str(body.get("require"));
        }
        return new PendingResponse(
                status, str(body.get("location")), requirement, str(body.get("code")), str(body.get("clarification")));
    }

    /** Returns whether an HTTP status code indicates a pending/deferred state (202). */
    public static boolean isPendingResponse(int statusCode) {
        return statusCode == 202;
    }

    /**
     * Detects the token endpoint mode from request parameters per spec §11.1:
     * {@code resource_access}, {@code self_access}, {@code call_chaining} or
     * {@code token_refresh}.
     *
     * @throws IllegalArgumentException if the parameters match no known mode
     */
    public static String detectTokenRequestMode(Map<String, Object> params) {
        boolean hasResourceToken = present(params.get("resource_token"));
        boolean hasUpstreamToken = present(params.get("upstream_token"));
        boolean hasScope = present(params.get("scope"));
        boolean hasAuthToken = present(params.get("auth_token"));

        if (hasAuthToken) {
            return "token_refresh";
        }
        if (hasResourceToken && hasUpstreamToken) {
            return "call_chaining";
        }
        if (hasResourceToken) {
            return "resource_access";
        }
        if (hasScope) {
            return "self_access";
        }
        throw new IllegalArgumentException("Request parameters don't match any known token endpoint mode");
    }

    private static boolean present(Object value) {
        return value != null && !value.toString().isEmpty();
    }

    private static String str(Object value) {
        return value == null ? null : value.toString();
    }
}
