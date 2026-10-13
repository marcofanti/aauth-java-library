package io.github.marcofanti.aauth.missions;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.marcofanti.aauth.Identifiers;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.headers.MissionBinding;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.jspecify.annotations.Nullable;

/**
 * Draft-11 mission approval bytes and lifecycle requests (§8, mirrors the reference
 * {@code missions} module). A mission is bound by the SHA-256 of its exact blob bytes
 * ({@code mission_s256}); the approval carries the blob base64url-encoded so the agent can verify
 * the hash over the original bytes.
 */
public final class Missions {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final Pattern MISSION_HASH = Pattern.compile("[A-Za-z0-9_-]{43}");
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    /** Default refresh margin: refresh when fewer than five minutes remain. */
    public static final long REFRESH_MARGIN_SECONDS = 300;

    private Missions() {}

    /**
     * A verified mission approval.
     *
     * @param missionS256 the verified mission hash
     * @param mission the decoded mission object
     * @param blob the original mission bytes the hash covers
     * @param capabilities capabilities granted alongside the mission
     * @param personTokens person tokens issued with the approval, keyed by resource
     */
    // byte[] blob is intentional: the hashed bytes; record equality is never used.
    @SuppressWarnings("ArrayRecordComponent")
    public record Approval(
            String missionS256,
            Map<String, Object> mission,
            byte[] blob,
            List<Object> capabilities,
            Map<String, Object> personTokens) {}

    /**
     * Builds a mission approval response (the PS side): {@code {s256, mission}} plus optional
     * {@code capabilities} and {@code person_tokens}.
     *
     * @throws TokenException if the mission is not an object or carries {@code approver} or
     *     {@code capabilities}
     */
    public static Map<String, Object> buildApproval(
            Map<String, Object> mission,
            @Nullable List<String> capabilities,
            @Nullable Map<String, String> personTokens) {
        if (mission.containsKey("approver") || mission.containsKey("capabilities")) {
            throw new TokenException("Mission blob must be an object without approver or capabilities", null);
        }
        byte[] blob;
        try {
            blob = MAPPER.writeValueAsBytes(mission);
        } catch (IOException e) {
            throw new TokenException("Mission blob is not serializable", null, null, null, e);
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("s256", MissionBinding.s256(blob));
        result.put("mission", B64URL.encodeToString(blob));
        if (capabilities != null) {
            result.put("capabilities", capabilities);
        }
        if (personTokens != null) {
            result.put("person_tokens", personTokens);
        }
        return result;
    }

    /**
     * Parses and verifies a mission approval (the agent side, AG-32): decodes the blob, checks
     * {@code s256} over the original bytes in constant time, and rejects a blob carrying
     * {@code approver} or {@code capabilities}.
     *
     * @throws TokenException if the approval or hash is invalid
     */
    @SuppressWarnings("unchecked")
    public static Approval parseApproval(Map<String, Object> response) {
        try {
            if (!(response.get("s256") instanceof String s256)
                    || !MISSION_HASH.matcher(s256).matches()) {
                throw new IllegalArgumentException("Invalid s256");
            }
            if (!(response.get("mission") instanceof String encoded)) {
                throw new IllegalArgumentException("Missing mission");
            }
            byte[] blob = Base64.getUrlDecoder().decode(encoded);
            String digest = MissionBinding.s256(blob);
            if (!MessageDigest.isEqual(
                    digest.getBytes(StandardCharsets.US_ASCII), s256.getBytes(StandardCharsets.US_ASCII))) {
                throw new IllegalArgumentException("Mission hash mismatch");
            }
            Map<String, Object> mission = MAPPER.readValue(blob, MAP_TYPE);
            if (mission == null || mission.containsKey("approver") || mission.containsKey("capabilities")) {
                throw new IllegalArgumentException("Invalid mission blob");
            }
            List<Object> capabilities =
                    response.get("capabilities") instanceof List<?> list ? (List<Object>) list : List.of();
            Map<String, Object> personTokens =
                    response.get("person_tokens") instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
            return new Approval(digest, mission, blob, capabilities, personTokens);
        } catch (IOException | IllegalArgumentException e) {
            throw new TokenException("Invalid mission approval or hash", null, null, null, e);
        }
    }

    /** A mission lifecycle request: where to POST it and its JSON body. */
    public record Request(String url, Map<String, Object> body) {}

    /**
     * Builds a mission lifecycle request (§8.4, §8.5): {@code POST {mission_endpoint}/{mission_s256}}
     * with {@code action} {@code update} or {@code completion} plus its parameters (e.g.
     * {@code description}, {@code summary}).
     *
     * @throws TokenException for an unknown action or an invalid {@code mission_s256}
     * @throws IllegalArgumentException for an invalid endpoint URL
     */
    public static Request missionRequest(
            String missionEndpoint, String missionS256, String action, Map<String, Object> params) {
        Identifiers.validateEndpointUrl(missionEndpoint);
        if (!MISSION_HASH.matcher(missionS256).matches()) {
            throw new TokenException("Invalid mission_s256", null, "invalid_jwt", null, null);
        }
        if (!"update".equals(action) && !"completion".equals(action)) {
            throw new TokenException("Unknown mission action: " + action, null);
        }
        String base = missionEndpoint.endsWith("/")
                ? missionEndpoint.substring(0, missionEndpoint.length() - 1)
                : missionEndpoint;
        Map<String, Object> body = new LinkedHashMap<>(params);
        body.put("action", action);
        return new Request(base + "/" + missionS256, body);
    }

    /**
     * Returns whether a token with these claims should be refreshed: fewer than {@code margin}
     * seconds remain ({@code exp - now < margin}).
     */
    public static boolean tokenNeedsRefresh(Map<String, Object> claims, long now, long margin) {
        return !(claims.get("exp") instanceof Number exp) || exp.longValue() - now < margin;
    }
}
