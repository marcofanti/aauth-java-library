package io.github.marcofanti.aauth.missions;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.TokenException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Mission approval bytes and lifecycle requests (mirrors the reference test_draft11_governance). */
class MissionsTest {

    private static final String PS = "https://ps.uma.lab";

    @Test
    void missionApprovalValidatesOriginalBytesAndHash() {
        Map<String, Object> mission = new LinkedHashMap<>();
        mission.put("description", "Trip");
        mission.put("approved_at", 123);
        Map<String, Object> approval =
                Missions.buildApproval(mission, List.of("interaction"), Map.of("https://gateway.uma.lab", "pt"));

        Missions.Approval parsed = Missions.parseApproval(approval);
        assertThat(parsed.mission()).isEqualTo(mission);
        assertThat(parsed.capabilities()).containsExactly("interaction");
        assertThat(parsed.personTokens()).containsEntry("https://gateway.uma.lab", "pt");
        assertThat(new String(parsed.blob(), java.nio.charset.StandardCharsets.UTF_8))
                .isEqualTo("{\"description\":\"Trip\",\"approved_at\":123}");

        Missions.Request request =
                Missions.missionRequest(PS + "/mission", parsed.missionS256(), "completion", Map.of("summary", "Done"));
        assertThat(request.url()).isEqualTo(PS + "/mission/" + parsed.missionS256());
        assertThat(request.body()).isEqualTo(Map.of("action", "completion", "summary", "Done"));

        Map<String, Object> tampered = new LinkedHashMap<>(approval);
        String blob = approval.get("mission").toString();
        tampered.put("mission", blob.substring(0, blob.length() - 1) + (blob.endsWith("A") ? "B" : "A"));
        assertThatThrownBy(() -> Missions.parseApproval(tampered)).isInstanceOf(TokenException.class);
    }

    @Test
    void approvalRejectsApproverCapabilitiesAndBadHashes() {
        assertThatThrownBy(() -> Missions.buildApproval(Map.of("approver", PS), null, null))
                .isInstanceOf(TokenException.class);
        assertThatThrownBy(() -> Missions.parseApproval(Map.of("s256", "short", "mission", "e30")))
                .isInstanceOf(TokenException.class);
        assertThatThrownBy(() -> Missions.parseApproval(Map.of("s256", "m".repeat(43))))
                .isInstanceOf(TokenException.class);
        Map<String, Object> withApprover = Missions.buildApproval(Map.of("description", "x"), null, null);
        assertThat(Missions.parseApproval(withApprover).capabilities()).isEmpty();
    }

    @Test
    void missionRequestValidatesInputs() {
        String hash = "m".repeat(43);
        assertThat(Missions.missionRequest(PS + "/mission/", hash, "update", Map.of("description", "d"))
                        .url())
                .isEqualTo(PS + "/mission/" + hash);
        assertThatThrownBy(() -> Missions.missionRequest(PS + "/mission", hash, "delete", Map.of()))
                .isInstanceOf(TokenException.class);
        assertThatThrownBy(() -> Missions.missionRequest(PS + "/mission", "short", "update", Map.of()))
                .isInstanceOf(TokenException.class);
        assertThatThrownBy(() -> Missions.missionRequest("http://ps.uma.lab/mission", hash, "update", Map.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refreshMargin() {
        assertThat(Missions.tokenNeedsRefresh(Map.of("exp", 1000), 701, Missions.REFRESH_MARGIN_SECONDS))
                .isTrue();
        assertThat(Missions.tokenNeedsRefresh(Map.of("exp", 1000), 700, Missions.REFRESH_MARGIN_SECONDS))
                .isFalse();
        assertThat(Missions.tokenNeedsRefresh(Map.of(), 700, Missions.REFRESH_MARGIN_SECONDS))
                .isTrue();
    }
}
