package io.github.marcofanti.aauth.agent;

import io.github.marcofanti.aauth.ChallengeException;
import io.github.marcofanti.aauth.headers.AAuthHeaders;

/** Handles AAuth challenges from resources and auth servers (agent role). */
public final class ChallengeHandler {

    /**
     * Parses an AAuth challenge header value (any of the supported formats).
     *
     * @throws ChallengeException if parsing fails
     */
    public AAuthHeaders.ParsedChallenge parseChallenge(String aauthHeader) {
        return AAuthHeaders.parseAAuthHeader(aauthHeader);
    }

    /**
     * Determines the signature scheme to use in response to a challenge.
     *
     * @param challenge the parsed challenge
     * @param hasAgentToken whether the agent holds an agent token
     * @param hasAuthToken whether the agent holds an auth token
     * @return {@code hwk}, {@code jwks_uri} or {@code jwt}
     * @throws ChallengeException if the challenge cannot be satisfied
     */
    public String determineResponseScheme(
            AAuthHeaders.ParsedChallenge challenge, boolean hasAgentToken, boolean hasAuthToken) {
        String require = challenge.requirement();

        if (AAuthHeaders.REQUIRE_AUTH_TOKEN.equals(require)) {
            if (hasAuthToken) {
                return "jwt";
            }
            throw new ChallengeException(
                    "Challenge requires auth token but agent doesn't have one", AAuthHeaders.REQUIRE_AUTH_TOKEN);
        }

        if (AAuthHeaders.REQUIRE_IDENTITY.equals(require)) {
            return hasAgentToken ? "jwt" : "jwks_uri";
        }

        // Pseudonym or anything else — sign with an inline key.
        return "hwk";
    }
}
