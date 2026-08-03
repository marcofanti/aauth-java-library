package io.github.marcofanti.aauth.http;

import java.util.Map;

/**
 * Framework-agnostic HTTP request representation.
 *
 * <p>Adapters for specific frameworks (servlet, Spring, JDK HttpServer) construct this from
 * their native request type; the AAuth core only ever sees this shape.
 *
 * @param method HTTP method, upper-cased
 * @param authority canonical authority ({@code host[:port]}) per spec §10.3.1
 * @param path request path; defaults to {@code /}
 * @param query query string without the leading {@code ?}, or {@code null}
 * @param headers request headers
 * @param body request body, or {@code null}
 */
// byte[] body is intentional: raw HTTP bytes; record equality is never used.
@SuppressWarnings("ArrayRecordComponent")
public record AAuthRequest(
        String method, String authority, String path, String query, Map<String, String> headers, byte[] body) {

    public AAuthRequest {
        if (method == null || method.isEmpty()) {
            throw new IllegalArgumentException("method is required");
        }
        if (authority == null || authority.isEmpty()) {
            throw new IllegalArgumentException("authority is required");
        }
        method = method.toUpperCase(java.util.Locale.ROOT);
        path = path == null || path.isEmpty() ? "/" : path;
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

    /** Reconstructs the target URI (https assumed, per AAuth's TLS requirement). */
    public String targetUri() {
        String base = "https://" + authority + path;
        return query == null || query.isEmpty() ? base : base + "?" + query;
    }
}
