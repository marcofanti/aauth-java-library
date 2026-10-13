package io.github.marcofanti.aauth.http;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Sends one HTTP request and returns the raw response. Agent-side flows take a transport so that
 * callers (and tests) can supply their own, mirroring the reference's injectable HTTP client.
 */
@FunctionalInterface
public interface HttpTransport {

    /**
     * Sends a request.
     *
     * @param method HTTP method
     * @param url absolute URL
     * @param headers request headers
     * @param body request body, or {@code null}
     * @throws IOException on a transport failure
     */
    AAuthResponse send(String method, String url, Map<String, String> headers, byte @Nullable [] body)
            throws IOException;

    /**
     * A transport over a JDK {@link HttpClient}, pinned to HTTP/1.1 with 30-second timeouts (the JDK's
     * h2c upgrade breaks h11-based servers such as uvicorn). Every request URL must pass
     * {@link Egress#admitPublicUrl}; inject {@link #jdk(HttpClient)} to apply your own policy.
     */
    static HttpTransport defaultTransport() {
        return Egress.admitted(jdk(defaultHttpClient()));
    }

    /**
     * The library's default JDK client: HTTP/1.1 with a 30-second connect timeout. It does not
     * follow redirects, so a redirect cannot bypass egress admission.
     */
    static HttpClient defaultHttpClient() {
        return HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(30))
                .build();
    }

    /** A transport over the given JDK client. Redirects follow the client's own policy. */
    static HttpTransport jdk(HttpClient client) {
        return (method, url, headers, body) -> {
            HttpRequest.Builder builder =
                    HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(30));
            headers.forEach(builder::header);
            builder.method(
                    method,
                    body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body));
            HttpResponse<byte[]> response;
            try {
                response = client.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while sending " + method + " " + url, e);
            }
            Map<String, String> responseHeaders = new LinkedHashMap<>();
            response.headers().map().forEach((name, values) -> {
                if (!values.isEmpty()) {
                    responseHeaders.put(name, values.get(0));
                }
            });
            byte[] responseBody = response.body();
            return new AAuthResponse(
                    response.statusCode(), responseHeaders, responseBody == null ? new byte[0] : responseBody);
        };
    }
}
