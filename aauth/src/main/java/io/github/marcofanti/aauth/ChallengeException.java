package io.github.marcofanti.aauth;

import io.github.marcofanti.aauth.signing.AAuthException;
import org.jspecify.annotations.Nullable;

/** AAuth requirement/challenge parsing or building error. */
public class ChallengeException extends AAuthException {

    private final @Nullable String challengeType;

    public ChallengeException(String message) {
        this(message, null);
    }

    public ChallengeException(String message, @Nullable String challengeType) {
        super(message);
        this.challengeType = challengeType;
    }

    /** The requirement level or challenge kind involved, or {@code null}. */
    public @Nullable String challengeType() {
        return challengeType;
    }
}
