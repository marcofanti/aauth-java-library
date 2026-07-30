package io.github.marcofanti.aauth.keys;

import java.util.Map;

/** HTTP client abstraction for JSON GET requests (JWKS and metadata discovery). */
@FunctionalInterface
public interface JsonHttpClient {

    /**
     * Fetches and parses a JSON object from {@code url}.
     *
     * @throws io.github.marcofanti.aauth.JwksException if the fetch or parse fails
     */
    Map<String, Object> fetchJson(String url);
}
