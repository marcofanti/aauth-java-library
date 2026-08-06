package io.github.marcofanti.aauth.headers;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Map;
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
    void matchesDocumentChecksHash() {
        AAuthHeaders.Mission mission = new AAuthHeaders.Mission("https://ps.uma.lab", MISSION_S256);

        assertThat(MissionBinding.matchesDocument(mission, MISSION_DOC)).isTrue();
        assertThat(MissionBinding.matchesDocument(mission, "tampered".getBytes(StandardCharsets.UTF_8)))
                .isFalse();
        assertThat(MissionBinding.matchesDocument(new AAuthHeaders.Mission("https://ps.uma.lab", null), MISSION_DOC))
                .isFalse();
    }

    @Test
    void matchesClaimRequiresBothFieldsEqual() {
        AAuthHeaders.Mission mission = new AAuthHeaders.Mission("https://ps.uma.lab", MISSION_S256);

        assertThat(MissionBinding.matchesClaim(mission, Map.of("approver", "https://ps.uma.lab", "s256", MISSION_S256)))
                .isTrue();
        assertThat(MissionBinding.matchesClaim(
                        mission, Map.of("approver", "https://other.uma.lab", "s256", MISSION_S256)))
                .isFalse();
        assertThat(MissionBinding.matchesClaim(mission, Map.of("approver", "https://ps.uma.lab")))
                .isFalse();
        assertThat(MissionBinding.matchesClaim(new AAuthHeaders.Mission(null, MISSION_S256), Map.of()))
                .isFalse();
    }

    @Test
    void roundTripsWithMissionHeaderAndResourceTokenClaim() {
        String s256 = MissionBinding.s256(MISSION_DOC);
        String header = AAuthHeaders.buildMissionHeader("https://ps.uma.lab", s256);
        AAuthHeaders.Mission parsed = AAuthHeaders.parseMissionHeader(header);

        assertThat(MissionBinding.matchesDocument(parsed, MISSION_DOC)).isTrue();
        assertThat(MissionBinding.matchesClaim(parsed, Map.of("approver", "https://ps.uma.lab", "s256", s256)))
                .isTrue();
    }
}
