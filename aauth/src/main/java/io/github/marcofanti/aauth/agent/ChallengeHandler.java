package io.github.marcofanti.aauth.agent;

import io.github.marcofanti.aauth.ChallengeException;
import io.github.marcofanti.aauth.headers.AAuthHeaders;

/** Handles AAuth challenges from resources and auth servers (agent role). */
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
     * Determines the signature scheme to use in response to a challenge.
     *
     * <p>Draft-11 §6.4 / AG-12: {@code requirement=person-token} is met by presenting the person
     * token under the {@code jwt} scheme — or the auth token, once the agent holds one for the
     * resource. An agent with neither cannot meet it (an agent without a PS never can).
     *
     * @param challenge the parsed challenge
     * @param held the tokens the agent holds
     * @return {@code hwk}, {@code jwks_uri} or {@code jwt}
     * @throws ChallengeException if the challenge cannot be satisfied
     */
    public String determineResponseScheme(AAuthHeaders.ParsedChallenge challenge, HeldTokens held) {
        String require = challenge.requirement();

        if (AAuthHeaders.REQUIRE_AUTH_TOKEN.equals(require)) {
            if (held.authToken()) {
                return "jwt";
            }
            throw new ChallengeException(
                    "Challenge requires auth token but agent doesn't have one", AAuthHeaders.REQUIRE_AUTH_TOKEN);
        }

        if (AAuthHeaders.REQUIRE_PERSON_TOKEN.equals(require)) {
            if (held.authToken() || held.personToken()) {
                return "jwt";
            }
            throw new ChallengeException(
                    "Challenge requires a person token but agent doesn't have one; request one from the"
                            + " person server's person_token_endpoint",
                    AAuthHeaders.REQUIRE_PERSON_TOKEN);
        }

        if (AAuthHeaders.REQUIRE_IDENTITY.equals(require)) {
            return held.agentToken() ? "jwt" : "jwks_uri";
        }

        // Pseudonym or anything else — sign with an inline key.
        return "hwk";
    }
}
