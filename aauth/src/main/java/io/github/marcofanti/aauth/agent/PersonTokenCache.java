package io.github.marcofanti.aauth.agent;

import io.github.marcofanti.aauth.signing.Jwts;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.jspecify.annotations.Nullable;

/**
 * Agent-side cache of person tokens, one per resource and per mission (draft-11 §7.1, AG-11).
 *
 * <p>A cached token is returned only while it has more than {@link #REFRESH_MARGIN} left: the
 * agent SHOULD NOT present an agent, person or auth token inside that margin and SHOULD refresh it
 * instead (§7.9.1, AG-70). Rotating the agent's signing key invalidates every person token bound to
 * the old key — call {@link #clear()} and re-request on next use.
 */
public final class PersonTokenCache {

    /** Refresh tokens when fewer than five minutes remain (draft-11 §7.9.1). */
    public static final Duration REFRESH_MARGIN = Duration.ofMinutes(5);

    private record Key(String resource, @Nullable String missionS256) {}

    private record Entry(String token, Instant expiresAt) {}

    private final Clock clock;
    private final Map<Key, Entry> entries = new ConcurrentHashMap<>();

    public PersonTokenCache() {
        this(Clock.systemUTC());
    }

    /** @param clock time source (injectable for tests) */
    public PersonTokenCache(Clock clock) {
        this.clock = clock;
    }

    /**
     * Caches a person token for a resource (and mission). Its expiry is read from the token's
     * {@code exp} claim.
     *
     * @throws IllegalArgumentException if the token is malformed or has no {@code exp}
     */
    public void put(String resource, @Nullable String missionS256, String personToken) {
        entries.put(new Key(resource, missionS256), new Entry(personToken, expiry(personToken)));
    }

    /**
     * Returns the cached person token for a resource (and mission), or {@code null} when none is
     * cached or the cached one is inside the refresh margin (it is evicted).
     */
    public @Nullable String get(String resource, @Nullable String missionS256) {
        Key key = new Key(resource, missionS256);
        Entry entry = entries.get(key);
        if (entry == null) {
            return null;
        }
        if (insideMargin(entry.expiresAt(), clock.instant())) {
            entries.remove(key, entry);
            return null;
        }
        return entry.token();
    }

    /** Drops every cached token — required after the agent rotates its signing key. */
    public void clear() {
        entries.clear();
    }

    /**
     * Returns whether a token (agent, person or auth) should be refreshed rather than presented:
     * true when it has no {@code exp}, cannot be parsed, or has {@link #REFRESH_MARGIN} or less left.
     */
    public static boolean needsRefresh(String jwt, Instant now) {
        try {
            return insideMargin(expiry(jwt), now);
        } catch (IllegalArgumentException e) {
            return true;
        }
    }

    private static boolean insideMargin(Instant expiresAt, Instant now) {
        return !now.plus(REFRESH_MARGIN).isBefore(expiresAt);
    }

    private static Instant expiry(String jwt) {
        Long exp = Jwts.parse(jwt).numericClaim("exp");
        if (exp == null) {
            throw new IllegalArgumentException("token has no 'exp' claim");
        }
        return Instant.ofEpochSecond(exp);
    }
}
