package io.github.marcofanti.aauth.http;

import java.util.Map;

/**
 * Framework-agnostic HTTP response representation.
 *
 * @param statusCode HTTP status code
 * @param headers response headers
 * @param body response body, or {@code null}
 */
public record AAuthResponse(int statusCode, Map<String, String> headers, byte[] body) {

    public AAuthResponse {
        headers = headers == null ? Map.of() : Map.copyOf(headers);
    }

    /** Case-insensitive header lookup; returns {@code null} when absent. */
    public String getHeader(String name) {
        String direct = headers.get(name);
        if (direct != null) {
            return direct;
        }
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return null;
    }
}
