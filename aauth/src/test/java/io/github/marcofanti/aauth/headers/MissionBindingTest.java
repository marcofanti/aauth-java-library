package io.github.marcofanti.aauth.headers;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class MissionBindingTest {

    private static final byte[] MISSION_DOC = "hello".getBytes(StandardCharsets.UTF_8);
    // sha256("hello"), base64url without padding — matches the PS reference s256_hash_bytes.
    private static final String MISSION_S256 = "LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ";

    @Test
    void s256MatchesReferenceEncoding() {
        assertThat(MissionBinding.s256(MISSION_DOC)).isEqualTo(MISSION_S256);
    }

    @Test
    void matchesVerifiesTheBlobAgainstTheClaim() {
        assertThat(MissionBinding.matches(MISSION_S256, MISSION_DOC)).isTrue();
        assertThat(MissionBinding.matches(MISSION_S256, "tampered".getBytes(StandardCharsets.UTF_8)))
                .isFalse();
    }
}
