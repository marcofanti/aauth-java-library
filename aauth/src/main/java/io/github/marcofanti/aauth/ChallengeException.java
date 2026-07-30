package io.github.marcofanti.aauth;

import io.github.marcofanti.aauth.signing.AAuthException;

/** AAuth requirement/challenge parsing or building error. */
public class ChallengeException extends AAuthException {

    private final String challengeType;

    public ChallengeException(String message) {
        this(message, null);
    }

    public ChallengeException(String message, String challengeType) {
        super(message);
        this.challengeType = challengeType;
    }

    /** The requirement level or challenge kind involved, or {@code null}. */
    public String challengeType() {
        return challengeType;
    }
}
