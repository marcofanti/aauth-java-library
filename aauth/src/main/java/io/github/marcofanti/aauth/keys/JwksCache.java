package io.github.marcofanti.aauth.keys;

import java.time.Clock;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory JWKS cache with TTL and a hard maximum age.
 *
 * <p>Per spec §JWKS Discovery, cached entries SHOULD be discarded after at most 24 hours
 * regardless of cache headers.
 */
public final class JwksCache {

    private record Entry(Map<String, Object> jwks, long cachedAtEpochSeconds) {}

    private final ConcurrentHashMap<String, Entry> cache = new ConcurrentHashMap<>();
    private final long ttlSeconds;
    private final long maxAgeSeconds;
    private final Clock clock;

    /** Creates a cache with a 1-hour TTL and 24-hour maximum age. */
    public JwksCache() {
        this(3600, 86400, Clock.systemUTC());
    }

    public JwksCache(long ttlSeconds, long maxAgeSeconds, Clock clock) {
        this.ttlSeconds = ttlSeconds;
        this.maxAgeSeconds = maxAgeSeconds;
        this.clock = clock == null ? Clock.systemUTC() : clock;
    }

    /** Returns the cached JWKS for {@code url}, or {@code null} when absent or expired. */
    public Map<String, Object> get(String url) {
        Entry entry = cache.get(url);
        if (entry == null) {
            return null;
        }
        long age = clock.instant().getEpochSecond() - entry.cachedAtEpochSeconds();
        if (age > maxAgeSeconds || age > ttlSeconds) {
            cache.remove(url);
            return null;
        }
        return entry.jwks();
    }

    /** Caches a JWKS document for {@code url}. */
    public void set(String url, Map<String, Object> jwks) {
        cache.put(url, new Entry(jwks, clock.instant().getEpochSecond()));
    }

    /** Invalidates one entry (e.g. on unknown {@code kid}). */
    public void invalidate(String url) {
        cache.remove(url);
    }

    /** Clears all cached entries. */
    public void clear() {
        cache.clear();
    }
}
