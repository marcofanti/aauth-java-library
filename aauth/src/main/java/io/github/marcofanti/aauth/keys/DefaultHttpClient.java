package io.github.marcofanti.aauth.keys;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.marcofanti.aauth.JwksException;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/** JDK {@link HttpClient}-based JSON fetcher with a 10-second timeout. */
public final class DefaultHttpClient implements JsonHttpClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    private final HttpClient httpClient;

    public DefaultHttpClient() {
        this(HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build());
    }

    public DefaultHttpClient(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public Map<String, Object> fetchJson(String url) {
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
