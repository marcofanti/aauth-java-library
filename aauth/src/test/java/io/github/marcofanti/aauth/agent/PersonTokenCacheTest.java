package io.github.marcofanti.aauth.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PersonTokenCacheTest {

    private static final String RESOURCE = "https://gateway.uma.lab";
    private static final Instant NOW = Instant.parse("2026-10-12T12:00:00Z");

    private final KeyPair keys = KeyPairs.generateEd25519();
    private final PersonTokenCache cache = new PersonTokenCache(Clock.fixed(NOW, ZoneOffset.UTC));

    private String tokenExpiringIn(long seconds) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("sub", "person-sub-1");
        payload.put("exp", NOW.getEpochSecond() + seconds);
        return Jwts.signEdDsa(Map.of("typ", "aa-person+jwt", "alg", "Ed25519"), payload, keys.getPrivate());
    }

    @Test
    void returnsCachedTokenWhileOutsideRefreshMargin() {
        String token = tokenExpiringIn(3600);
        cache.put(RESOURCE, null, token);

        assertThat(cache.get(RESOURCE, null)).isEqualTo(token);
    }

    @Test
    void missingEntryReturnsNull() {
        assertThat(cache.get(RESOURCE, null)).isNull();
    }

    @Test
    void cachesPerResourceAndPerMission() {
        String plain = tokenExpiringIn(3600);
        String withMission = tokenExpiringIn(3600);
        cache.put(RESOURCE, null, plain);
        cache.put(RESOURCE, "abc123", withMission);

        assertThat(cache.get(RESOURCE, null)).isEqualTo(plain);
        assertThat(cache.get(RESOURCE, "abc123")).isEqualTo(withMission);
        assertThat(cache.get(RESOURCE, "other")).isNull();
        assertThat(cache.get("https://grafana.uma.lab", null)).isNull();
    }

    @Test
    void tokenInsideFiveMinuteMarginIsEvicted() {
        cache.put(RESOURCE, null, tokenExpiringIn(299));

        assertThat(cache.get(RESOURCE, null)).isNull();
        // Evicted, so a later lookup still misses.
        assertThat(cache.get(RESOURCE, null)).isNull();
    }

    @Test
    void tokenJustOutsideMarginIsReturned() {
        // Exactly five minutes left is still usable: refresh when exp - now < 300 (reference rule).
        String token = tokenExpiringIn(300);
        cache.put(RESOURCE, null, token);

        assertThat(cache.get(RESOURCE, null)).isEqualTo(token);
    }

    @Test
    void clearDropsEverything() {
        cache.put(RESOURCE, null, tokenExpiringIn(3600));
        cache.clear();

        assertThat(cache.get(RESOURCE, null)).isNull();
    }

    @Test
    void putRejectsTokenWithoutExp() {
        String noExp = Jwts.signEdDsa(Map.of("alg", "Ed25519"), Map.of("sub", "x"), keys.getPrivate());

        assertThatThrownBy(() -> cache.put(RESOURCE, null, noExp))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("exp");
    }

    @Test
    void needsRefreshAppliesTheMarginToAnyToken() {
        assertThat(PersonTokenCache.needsRefresh(tokenExpiringIn(3600), NOW)).isFalse();
        assertThat(PersonTokenCache.needsRefresh(tokenExpiringIn(60), NOW)).isTrue();
        assertThat(PersonTokenCache.needsRefresh(tokenExpiringIn(-10), NOW)).isTrue();
        assertThat(PersonTokenCache.needsRefresh("not-a-jwt", NOW)).isTrue();
    }
}
