package io.github.marcofanti.aauth.keys;

import io.github.marcofanti.aauth.JwksException;
import io.github.marcofanti.aauth.MetadataException;
import io.github.marcofanti.aauth.metadata.Metadata;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.jspecify.annotations.Nullable;

/**
 * JWKS fetcher with caching, re-fetch on unknown {@code kid}, and per-issuer rate limiting.
 *
 * <p>Per spec §JWKS Discovery:
 *
 * <ul>
 *   <li>two-step discovery: fetch {@code {id}/.well-known/{dwk}}, validate it with
 *       {@link Metadata#validate} ({@code issuer} must equal the identifier, HTTPS
 *       {@code jwks_uri}), fetch the JWKS
 *   <li>re-fetch on unknown {@code kid} to support key rotation
 *   <li>MUST NOT fetch more than once per minute per issuer; failed fetches count, and
 *       concurrent callers share one in-flight fetch per issuer
 *   <li>cache entries expire after at most 24 hours
 * </ul>
 */
public final class CachingJwksFetcher {

    private final JsonHttpClient httpClient;
    private final JwksCache cache;
    private final long minFetchIntervalSeconds;
    private final Clock clock;
    private final ConcurrentHashMap<String, Long> lastFetchTimes = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Object> fetchLocks = new ConcurrentHashMap<>();

    /**
     * Creates a fetcher with the JDK HTTP client (pinned to HTTP/1.1 for h11-server
     * compatibility — see {@link DefaultHttpClient}), 1-hour cache TTL, 60-second rate limit.
     */
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
        Map<String, Object> metadata;
        try {
            metadata = Metadata.validate(httpClient.fetchJson(metadataUrl), identifier, List.of("jwks_uri"));
        } catch (MetadataException e) {
            throw new JwksException(
                    "Failed to fetch metadata from " + metadataUrl + ": " + e.getMessage(), metadataUrl, e);
        }
        String jwksUri = String.valueOf(metadata.get("jwks_uri"));

        Map<String, Object> usable = usableCached(identifier, jwksUri, kid);
        if (usable != null) {
            return usable;
        }
        // Single flight per identifier: a caller arriving while a fetch is in flight waits for it
        // and then re-checks the cache, instead of tripping the rate limit on a cold cache.
        synchronized (fetchLocks.computeIfAbsent(identifier, key -> new Object())) {
            usable = usableCached(identifier, jwksUri, kid);
            if (usable != null) {
                return usable;
            }
            if (!canFetch(identifier)) {
                throw new JwksException(
                        "Rate limited: cannot fetch JWKS for " + identifier + " more than once per "
                                + minFetchIntervalSeconds + "s",
                        jwksUri,
                        null);
            }
            // Failed fetches count too, so an outage cannot bypass the rate limit.
            lastFetchTimes.put(identifier, clock.instant().getEpochSecond());
            Map<String, Object> jwks = httpClient.fetchJson(jwksUri);
            if (!(jwks.get("keys") instanceof List)) {
                throw new JwksException("Invalid JWKS structure from " + jwksUri, jwksUri, null);
            }
            cache.set(jwksUri, jwks);
            return jwks;
        }
    }

    /**
     * Returns the cached JWKS when it can be served: it holds {@code kid} (or no kid was asked
     * for), or the rate limit forbids a re-fetch for an unknown kid (stale copy). Otherwise drops
     * the entry so the caller re-fetches, and returns {@code null}.
     */
    private @Nullable Map<String, Object> usableCached(String identifier, String jwksUri, @Nullable String kid) {
        Map<String, Object> cached = cache.get(jwksUri);
        if (cached == null) {
            return null;
        }
        if (kid == null || getKeyByKid(cached, kid) != null || !canFetch(identifier)) {
            return cached;
        }
        cache.invalidate(jwksUri);
        return null;
    }

    /** Finds a key in a JWKS by {@code kid}; returns {@code null} when absent. */
    @SuppressWarnings("unchecked")
    public static @Nullable Map<String, Object> getKeyByKid(Map<String, Object> jwks, String kid) {
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
