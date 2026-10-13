package io.github.marcofanti.aauth.agent;

import io.github.marcofanti.aauth.ChallengeException;
import io.github.marcofanti.aauth.headers.AAuthHeaders;

/** Selects the credential for a published draft-11 requirement (mirrors the reference). */
public final class ChallengeHandler {

    /**
     * Which tokens the agent currently holds for the challenging resource.
     *
     * @param agentToken an agent token ({@code aa-agent+jwt})
     * @param personToken a person token ({@code aa-person+jwt}) for this resource
     * @param authToken an auth token ({@code aa-auth+jwt}) for this resource
     */
    public record HeldTokens(boolean agentToken, boolean personToken, boolean authToken) {}

    /**
     * Parses an AAuth challenge header value (any of the supported formats).
     *
     * @throws ChallengeException if parsing fails
     */
    public AAuthHeaders.ParsedChallenge parseChallenge(String aauthHeader) {
        return AAuthHeaders.parseAAuthHeader(aauthHeader);
    }

    /**
     * Determines the signature scheme for a challenge. Draft-11 requirements are
     * {@code agent-token}, {@code person-token} and {@code auth-token}; each is met only by
     * presenting that token, always under the {@code jwt} scheme — there is no pseudonymous
     * fallback.
     *
     * @return {@code jwt}
     * @throws ChallengeException for any other requirement, or when the required token is not held
     */
    public String determineResponseScheme(AAuthHeaders.ParsedChallenge challenge, HeldTokens held) {
        String requirement = challenge.requirement();
        boolean available;
        if (AAuthHeaders.REQUIRE_AGENT_TOKEN.equals(requirement)) {
            available = held.agentToken();
        } else if (AAuthHeaders.REQUIRE_PERSON_TOKEN.equals(requirement)) {
            available = held.personToken();
        } else if (AAuthHeaders.REQUIRE_AUTH_TOKEN.equals(requirement)) {
            available = held.authToken();
        } else {
            throw new ChallengeException("Unsupported or non-credential requirement", requirement);
        }
        if (!available) {
            throw new ChallengeException("Required token is unavailable", requirement);
        }
        return "jwt";
    }
}
