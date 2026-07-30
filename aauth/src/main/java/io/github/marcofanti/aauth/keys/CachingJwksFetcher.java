package io.github.marcofanti.aauth.keys;

import io.github.marcofanti.aauth.JwksException;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * JWKS fetcher with caching, re-fetch on unknown {@code kid}, and per-issuer rate limiting.
 *
 * <p>Per spec §JWKS Discovery:
 *
 * <ul>
 *   <li>two-step discovery: fetch {@code {id}/.well-known/{dwk}}, extract {@code jwks_uri},
 *       fetch the JWKS
 *   <li>re-fetch on unknown {@code kid} to support key rotation
 *   <li>MUST NOT fetch more than once per minute per issuer
 *   <li>cache entries expire after at most 24 hours
 * </ul>
 */
public final class CachingJwksFetcher {

    private final JsonHttpClient httpClient;
    private final JwksCache cache;
    private final long minFetchIntervalSeconds;
    private final Clock clock;
    private final ConcurrentHashMap<String, Long> lastFetchTimes = new ConcurrentHashMap<>();

    /** Creates a fetcher with the JDK HTTP client, 1-hour cache TTL, 60-second rate limit. */
    public CachingJwksFetcher() {
        this(new DefaultHttpClient(), new JwksCache(), 60, Clock.systemUTC());
    }

    public CachingJwksFetcher(JsonHttpClient httpClient, JwksCache cache, long minFetchIntervalSeconds, Clock clock) {
        this.httpClient = httpClient;
        this.cache = cache;
        this.minFetchIntervalSeconds = minFetchIntervalSeconds;
        this.clock = clock == null ? Clock.systemUTC() : clock;
    }

    /**
     * Fetches the JWKS for an identifier via two-step metadata discovery.
     *
     * @param identifier agent/resource/auth-server identifier (HTTPS URL)
     * @param kid optional key ID; triggers a re-fetch when absent from the cached JWKS
     * @param metadataPath well-known metadata filename (e.g. {@code aauth-agent.json})
     * @return the JWKS document
     * @throws JwksException if discovery or fetching fails
     */
    public Map<String, Object> fetch(String identifier, String kid, String metadataPath) {
        String metadataUrl = identifier + "/.well-known/" + metadataPath;
        Map<String, Object> metadata = httpClient.fetchJson(metadataUrl);
        Object jwksUriValue = metadata.get("jwks_uri");
        if (jwksUriValue == null || jwksUriValue.toString().isEmpty()) {
            throw new JwksException("No jwks_uri in metadata from " + metadataUrl, metadataUrl, null);
        }
        String jwksUri = jwksUriValue.toString();

        Map<String, Object> cached = cache.get(jwksUri);
        if (cached != null) {
            if (kid == null) {
                return cached;
            }
            if (getKeyByKid(cached, kid) != null) {
                return cached;
            }
            // Unknown kid — re-fetch if the rate limit allows, otherwise serve the stale copy.
            if (!canFetch(identifier)) {
                return cached;
            }
            cache.invalidate(jwksUri);
        }

        if (!canFetch(identifier)) {
            throw new JwksException(
                    "Rate limited: cannot fetch JWKS for " + identifier + " more than once per "
                            + minFetchIntervalSeconds + "s",
                    jwksUri,
                    null);
        }

        Map<String, Object> jwks = httpClient.fetchJson(jwksUri);
        if (!(jwks.get("keys") instanceof List)) {
            throw new JwksException("Invalid JWKS structure from " + jwksUri, jwksUri, null);
        }
        cache.set(jwksUri, jwks);
        lastFetchTimes.put(identifier, clock.instant().getEpochSecond());
        return jwks;
    }

    /** Finds a key in a JWKS by {@code kid}; returns {@code null} when absent. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> getKeyByKid(Map<String, Object> jwks, String kid) {
        if (jwks.get("keys") instanceof List<?> keys) {
            for (Object key : keys) {
                if (key instanceof Map<?, ?> keyMap && kid.equals(keyMap.get("kid"))) {
                    return (Map<String, Object>) keyMap;
                }
            }
        }
        return null;
    }

    private boolean canFetch(String identifier) {
        Long last = lastFetchTimes.get(identifier);
        if (last == null) {
            return true;
        }
        return clock.instant().getEpochSecond() - last >= minFetchIntervalSeconds;
    }
}
