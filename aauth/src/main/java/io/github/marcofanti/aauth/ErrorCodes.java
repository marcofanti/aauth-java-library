package io.github.marcofanti.aauth;

import java.util.LinkedHashMap;
import java.util.Map;

/** AAuth protocol error codes and error-response bodies. */
public final class ErrorCodes {

    // --- Signature-Error header codes (401 responses, per draft-hardt-httpbis-signature-key) ---
    public static final String ERROR_INVALID_REQUEST = "invalid_request";
    public static final String ERROR_INVALID_INPUT = "invalid_input";
    public static final String ERROR_INVALID_SIGNATURE = "invalid_signature";
    public static final String ERROR_UNSUPPORTED_ALGORITHM = "unsupported_algorithm";
    public static final String ERROR_INVALID_KEY = "invalid_key";
    public static final String ERROR_UNKNOWN_KEY = "unknown_key";
    public static final String ERROR_INVALID_JWT = "invalid_jwt";
    public static final String ERROR_EXPIRED_JWT = "expired_jwt";

    /** Sigkey draft-08 §5.4.2: the Signature-Key scheme is not supported by the recipient. */
    public static final String ERROR_UNSUPPORTED_SCHEME = "unsupported_scheme";

    /** Sigkey draft-08 §5.4.3: a {@code cached} scheme identifier could not be resolved. */
    public static final String ERROR_CACHE_MISS = "cache_miss";

    // --- Token endpoint error codes (JSON body, per draft-hardt-aauth-protocol) ---
    public static final String ERROR_INVALID_AGENT_TOKEN = "invalid_agent_token";
    public static final String ERROR_EXPIRED_AGENT_TOKEN = "expired_agent_token";
    public static final String ERROR_INVALID_RESOURCE_TOKEN = "invalid_resource_token";
    public static final String ERROR_EXPIRED_RESOURCE_TOKEN = "expired_resource_token";
    public static final String ERROR_INVALID_AUTH_TOKEN = "invalid_auth_token";
    public static final String ERROR_SERVER_ERROR = "server_error";

    // --- Interaction / authorization error codes ---
    /** 403: user interaction needed but no interaction channel is available. */
    public static final String ERROR_INTERACTION_REQUIRED = "interaction_required";

    // --- Mission status error codes ---
    public static final String ERROR_MISSION_TERMINATED = "mission_terminated";

    // --- Polling error codes (JSON body, per draft-hardt-aauth-protocol) ---
    public static final String ERROR_DENIED = "denied";
    public static final String ERROR_ABANDONED = "abandoned";
    public static final String ERROR_EXPIRED = "expired";
    public static final String ERROR_INVALID_CODE = "invalid_code";
    public static final String ERROR_SLOW_DOWN = "slow_down";

    private ErrorCodes() {}

    /**
     * Builds a standard AAuth token-endpoint error response body.
     *
     * <p>For authentication errors (401), build the {@code Signature-Error} header via
     * {@code AAuthHeaders} instead.
     *
     * @param error error code (one of the {@code ERROR_*} constants)
     * @param description human-readable description, or {@code null}
     * @param extras additional fields, or {@code null}
     */
    public static Map<String, Object> buildErrorResponse(String error, String description, Map<String, Object> extras) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("error", error);
        if (description != null && !description.isEmpty()) {
            response.put("error_description", description);
        }
        if (extras != null) {
            response.putAll(extras);
        }
        return response;
    }
}
