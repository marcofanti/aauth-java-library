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

    /** Draft-11 §11.12.5: the presented token (agent, person or auth) has been revoked. */
    public static final String ERROR_REVOKED_JWT = "revoked_jwt";

    /**
     * Draft-11 §11.3.4: {@code created} (or a token's {@code iat}) is ahead of the server's clock.
     * A fresh token from the same issuer has the same skew, so do not refresh — retry later.
     */
    public static final String ERROR_CLOCK_SKEW = "clock_skew";

    // --- Token endpoint error codes (JSON body, draft-11 §11.9.3) ---
    // Draft-11 removed invalid_agent_token / expired_agent_token: a bad agent token is a 401
    // with Signature-Error.
    public static final String ERROR_INVALID_RESOURCE_TOKEN = "invalid_resource_token";
    public static final String ERROR_EXPIRED_RESOURCE_TOKEN = "expired_resource_token";

    /** The resource token was revoked: do not resubmit it; call the resource again. */
    public static final String ERROR_REVOKED_RESOURCE_TOKEN = "revoked_resource_token";

    /** The {@code presented_token} expired: get a fresh person token, then a fresh resource token. */
    public static final String ERROR_EXPIRED_PRESENTED_TOKEN = "expired_presented_token";

    /** The {@code presented_token} was revoked: get a fresh person token, then a resource token. */
    public static final String ERROR_REVOKED_PRESENTED_TOKEN = "revoked_presented_token";

    /** 502: the PS could not reach the access server; retry with a fresh resource token later. */
    public static final String ERROR_AS_UNREACHABLE = "as_unreachable";

    /** The PS must reach the person but the agent declared no usable capabilities. */
    public static final String ERROR_USER_UNREACHABLE = "user_unreachable";

    /** A sub-agent token whose {@code iss} differs from its parent's (draft-11 §10.2.1). */
    public static final String ERROR_INVALID_SUBAGENT_TOKEN = "invalid_subagent_token";

    public static final String ERROR_INVALID_AUTH_TOKEN = "invalid_auth_token";
    public static final String ERROR_SERVER_ERROR = "server_error";

    // --- Interaction / authorization error codes ---
    /** 403: user interaction needed but no interaction channel is available. */
    public static final String ERROR_INTERACTION_REQUIRED = "interaction_required";

    /** 400 (draft-11 §6.6.3): the {@code account} is not held by the person token's person. */
    public static final String ERROR_INVALID_ACCOUNT = "invalid_account";

    // --- Mission status error codes ---
    public static final String ERROR_MISSION_TERMINATED = "mission_terminated";

    /** 404 (draft-11 §8.8): no mission exists at the mission URL. */
    public static final String ERROR_MISSION_NOT_FOUND = "mission_not_found";

    // --- Polling error codes (JSON body, per draft-hardt-aauth-protocol) ---
    public static final String ERROR_DENIED = "denied";
    public static final String ERROR_ABANDONED = "abandoned";
    public static final String ERROR_EXPIRED = "expired";
    public static final String ERROR_INVALID_CODE = "invalid_code";
    public static final String ERROR_SLOW_DOWN = "slow_down";

    /** 403 (draft-11 §11.9.4): a token the pending request depends on was revoked. */
    public static final String ERROR_REVOKED = "revoked";

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
