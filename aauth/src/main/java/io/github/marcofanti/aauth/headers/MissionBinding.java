package io.github.marcofanti.aauth.headers;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Mission binding hash per AAuth draft-11 §8.
 *
 * <p>An approved mission is immutable, bound by the SHA-256 of its blob:
 * {@code mission_s256 = base64url(sha256(missionBlob))}, unpadded. Draft-11 carries this value as
 * the {@code mission_s256} claim in the person/auth/resource token (the {@code AAuth-Mission}
 * header and the {@code {approver, s256}} object of earlier drafts are gone). An agent that
 * receives a mission blob SHOULD verify {@code mission_s256} over it before first use (§8.2).
 */
public final class MissionBinding {

    private MissionBinding() {}

    /** Computes {@code mission_s256}: unpadded base64url SHA-256 of the mission blob bytes. */
    public static String s256(byte[] missionBlob) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(missionBlob);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JDK is missing SHA-256", e);
        }
    }

    /** Returns whether {@code expectedS256} matches the hash of {@code missionBlob} (§8.2). */
    public static boolean matches(String expectedS256, byte[] missionBlob) {
        return expectedS256.equals(s256(missionBlob));
    }
}
