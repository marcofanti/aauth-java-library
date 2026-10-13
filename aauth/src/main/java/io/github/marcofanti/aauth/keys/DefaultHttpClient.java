package io.github.marcofanti.aauth.keys;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.marcofanti.aauth.JwksException;
import io.github.marcofanti.aauth.http.Egress;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/**
 * JDK {@link HttpClient}-based JSON fetcher with a 10-second timeout.
 *
 * <p>The default client is pinned to HTTP/1.1: the JDK's default HTTP/2 h2c upgrade breaks
 * h11-based servers (uvicorn/FastAPI reject the request or silently drop the body), which AAuth
 * person servers commonly run on.
 *
 * <p>The no-argument client applies the library's egress policy ({@link Egress#admitPublicUrl})
 * to every URL and does not follow redirects. A client injected via
 * {@link #DefaultHttpClient(HttpClient)} is used as-is: its owner sets the egress policy.
 */
public final class DefaultHttpClient implements JsonHttpClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    private final HttpClient httpClient;
    private final boolean admitPublicUrls;

    public DefaultHttpClient() {
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        this.admitPublicUrls = true;
    }

    /** The underlying client (exposed for configuration assertions). */
    HttpClient httpClient() {
        return httpClient;
    }

    public DefaultHttpClient(HttpClient httpClient) {
        this.httpClient = httpClient;
        this.admitPublicUrls = false;
    }

    @Override
    public Map<String, Object> fetchJson(String url) {
        if (admitPublicUrls) {
            Egress.admitPublicUrl(url);
        }
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(10))
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new JwksException(
                        "Failed to fetch JSON from " + url + ": HTTP " + response.statusCode(), url, null);
            }
            return MAPPER.readValue(response.body(), MAP_TYPE);
        } catch (IOException e) {
            throw new JwksException("Failed to fetch JSON from " + url + ": " + e.getMessage(), url, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new JwksException("Interrupted while fetching " + url, url, e);
        }
    }
}
