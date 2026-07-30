package io.github.marcofanti.aauth.keys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.JwksException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class CachingJwksFetcherTest {

    /** Mutable clock so cache TTL and rate limiting can be tested deterministically. */
    private static final class FakeClock extends Clock {
        private Instant now = Instant.ofEpochSecond(1_700_000_000);

        void advanceSeconds(long seconds) {
            now = now.plusSeconds(seconds);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }

    private static final String AGENT = "https://portal.uma.lab";
    private static final String METADATA_URL = AGENT + "/.well-known/aauth-agent.json";
    private static final String JWKS_URL = AGENT + "/jwks.json";

    private static Map<String, Object> jwksWithKid(String kid) {
        return Map.of("keys", List.of(Map.of("kty", "OKP", "crv", "Ed25519", "x", "abc", "kid", kid)));
    }

    private static JsonHttpClient fakeServer(Map<String, Object> jwks, AtomicInteger jwksFetches) {
        return url -> {
            if (url.equals(METADATA_URL)) {
                return Map.of("jwks_uri", JWKS_URL);
            }
            if (url.equals(JWKS_URL)) {
                jwksFetches.incrementAndGet();
                return jwks;
            }
            throw new JwksException("Unexpected URL " + url);
        };
    }

    @Test
    void performsTwoStepDiscoveryAndCaches() {
        FakeClock clock = new FakeClock();
        AtomicInteger fetches = new AtomicInteger();
        CachingJwksFetcher fetcher = new CachingJwksFetcher(
                fakeServer(jwksWithKid("key-1"), fetches), new JwksCache(3600, 86400, clock), 60, clock);

        Map<String, Object> first = fetcher.fetch(AGENT, "key-1", "aauth-agent.json");
        Map<String, Object> second = fetcher.fetch(AGENT, "key-1", "aauth-agent.json");

        assertThat(first).isEqualTo(second);
        assertThat(fetches.get()).isEqualTo(1);
    }

    @Test
    void cacheExpiresAfterTtl() {
        FakeClock clock = new FakeClock();
        AtomicInteger fetches = new AtomicInteger();
        CachingJwksFetcher fetcher = new CachingJwksFetcher(
                fakeServer(jwksWithKid("key-1"), fetches), new JwksCache(3600, 86400, clock), 60, clock);

        fetcher.fetch(AGENT, null, "aauth-agent.json");
        clock.advanceSeconds(3601);
        fetcher.fetch(AGENT, null, "aauth-agent.json");

        assertThat(fetches.get()).isEqualTo(2);
    }

    @Test
    void refetchesOnUnknownKidWhenRateLimitAllows() {
        FakeClock clock = new FakeClock();
        AtomicInteger fetches = new AtomicInteger();
        Map<String, Object> rotatingJwks = new HashMap<>(jwksWithKid("old-key"));
        JsonHttpClient server = url -> {
            if (url.equals(METADATA_URL)) {
                return Map.of("jwks_uri", JWKS_URL);
            }
            fetches.incrementAndGet();
            return Map.copyOf(rotatingJwks);
        };
        CachingJwksFetcher fetcher = new CachingJwksFetcher(server, new JwksCache(3600, 86400, clock), 60, clock);

        fetcher.fetch(AGENT, "old-key", "aauth-agent.json");

        // Key rotation happens server-side; a lookup for the new kid must re-fetch.
        rotatingJwks.putAll(jwksWithKid("new-key"));
        clock.advanceSeconds(61);
        Map<String, Object> refreshed = fetcher.fetch(AGENT, "new-key", "aauth-agent.json");

        assertThat(fetches.get()).isEqualTo(2);
        assertThat(CachingJwksFetcher.getKeyByKid(refreshed, "new-key")).isNotNull();
    }

    @Test
    void servesStaleCacheWhenRateLimitedOnUnknownKid() {
        FakeClock clock = new FakeClock();
        AtomicInteger fetches = new AtomicInteger();
        CachingJwksFetcher fetcher = new CachingJwksFetcher(
                fakeServer(jwksWithKid("key-1"), fetches), new JwksCache(3600, 86400, clock), 60, clock);

        fetcher.fetch(AGENT, "key-1", "aauth-agent.json");
        Map<String, Object> stale = fetcher.fetch(AGENT, "unknown-kid", "aauth-agent.json");

        assertThat(fetches.get()).isEqualTo(1);
        assertThat(CachingJwksFetcher.getKeyByKid(stale, "key-1")).isNotNull();
    }

    @Test
    void rejectsMetadataWithoutJwksUri() {
        FakeClock clock = new FakeClock();
        JsonHttpClient server = url -> Map.of("issuer", AGENT);
        CachingJwksFetcher fetcher = new CachingJwksFetcher(server, new JwksCache(3600, 86400, clock), 60, clock);

        assertThatThrownBy(() -> fetcher.fetch(AGENT, null, "aauth-agent.json"))
                .isInstanceOf(JwksException.class)
                .hasMessageContaining("jwks_uri");
    }

    @Test
    void rejectsInvalidJwksStructure() {
        FakeClock clock = new FakeClock();
        JsonHttpClient server = url -> url.equals(METADATA_URL) ? Map.of("jwks_uri", JWKS_URL) : Map.of("nope", 1);
        CachingJwksFetcher fetcher = new CachingJwksFetcher(server, new JwksCache(3600, 86400, clock), 60, clock);

        assertThatThrownBy(() -> fetcher.fetch(AGENT, null, "aauth-agent.json"))
                .isInstanceOf(JwksException.class)
                .hasMessageContaining("Invalid JWKS structure");
    }

    @Test
    void getKeyByKidFindsKeysAndHandlesMisses() {
        Map<String, Object> jwks = jwksWithKid("key-1");
        assertThat(CachingJwksFetcher.getKeyByKid(jwks, "key-1")).containsEntry("kid", "key-1");
        assertThat(CachingJwksFetcher.getKeyByKid(jwks, "nope")).isNull();
        assertThat(CachingJwksFetcher.getKeyByKid(Map.of(), "key-1")).isNull();
    }
}
