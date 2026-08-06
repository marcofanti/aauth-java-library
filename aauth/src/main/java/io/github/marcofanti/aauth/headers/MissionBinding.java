package io.github.marcofanti.aauth.headers;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;

/**
 * Mission binding checks per spec §Mission Approval.
 *
 * <p>An approved mission is immutable, bound by the SHA-256 of its canonical JSON:
 * {@code s256 = base64url(sha256(missionJson))}, unpadded. The person server builds the
 * canonical mission JSON; this class only verifies bindings between the {@code AAuth-Mission}
 * header, the mission document bytes, and a token's {@code mission} claim.
 */
public final class MissionBinding {

    private MissionBinding() {}

    /** Computes the mission hash: unpadded base64url SHA-256 of the mission document bytes. */
    public static String s256(byte[] missionDocument) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(missionDocument);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JDK is missing SHA-256", e);
        }
    }

    /**
     * Returns whether the {@code AAuth-Mission} header's {@code s256} matches the given mission
     * document bytes. False when the header carries no {@code s256}.
     */
    public static boolean matchesDocument(AAuthHeaders.Mission mission, byte[] missionDocument) {
        return mission.s256() != null && mission.s256().equals(s256(missionDocument));
    }

    /**
     * Returns whether the {@code AAuth-Mission} header matches a token's {@code mission} claim
     * ({@code {"approver": ..., "s256": ...}}): both fields must be present on both sides and
     * equal.
     */
    public static boolean matchesClaim(AAuthHeaders.Mission mission, Map<String, Object> missionClaim) {
        if (mission.approver() == null || mission.s256() == null) {
            return false;
        }
        return mission.approver().equals(str(missionClaim, "approver"))
                && mission.s256().equals(str(missionClaim, "s256"));
    }

    private static String str(Map<String, Object> claim, String key) {
        Object value = claim.get(key);
        return value == null ? "" : value.toString();
    }
}
