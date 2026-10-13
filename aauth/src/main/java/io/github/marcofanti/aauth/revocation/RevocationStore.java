package io.github.marcofanti.aauth.revocation;

import io.github.marcofanti.aauth.Identifiers;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.tokens.RevocationChecker;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.jspecify.annotations.Nullable;

/**
 * Issuer-scoped revocation state (draft-11 §11.12, mirrors the reference {@code RevocationStore}).
 * Keys always include the issuer, never {@code jti} alone. Entries expire with the token.
 *
 * <p>This in-memory store suits tests and a single process; multi-worker deployments must keep
 * these records in shared durable storage.
 */
public final class RevocationStore implements RevocationChecker {

    /** A token identity: issuer plus {@code jti}. */
    public record TokenKey(String issuer, String jti) {}

    /** An agent token the PS saw, so revoking it can cascade by agent identity {@code (iss, sub)}. */
    public record AgentRecord(String issuer, String sub, long exp) {}

    private final Clock clock;
    private final Map<TokenKey, Long> revoked = new ConcurrentHashMap<>();
    private final Map<TokenKey, IssuedToken> issued = new ConcurrentHashMap<>();
    private final Map<TokenKey, AgentRecord> agents = new ConcurrentHashMap<>();

    public RevocationStore() {
        this(Clock.systemUTC());
    }

    /** @param clock time source (injectable for tests) */
    public RevocationStore(Clock clock) {
        this.clock = clock;
    }

    long now() {
        return clock.instant().getEpochSecond();
    }

    @Override
    public boolean isRevoked(String issuer, String jti) {
        TokenKey key = new TokenKey(issuer, jti);
        Long exp = revoked.get(key);
        if (exp == null) {
            return false;
        }
        if (now() > exp) {
            revoked.remove(key, exp);
            return false;
        }
        return true;
    }

    /**
     * Records a revocation, keeping the later expiry when one already exists.
     *
     * @throws TokenException {@code invalid_jwt} for a bad issuer, {@code invalid_request} for a
     *     bad {@code jti}
     */
    public void record(String issuer, String jti, long exp) {
        try {
            Identifiers.validateServerIdentifier(issuer);
        } catch (IllegalArgumentException e) {
            throw new TokenException("Invalid server identifier: " + issuer, null, "invalid_jwt", null, e);
        }
        Revocations.body(jti, exp);
        revoked.merge(new TokenKey(issuer, jti), exp, Math::max);
    }

    /** Records an agent token the PS accepted, from its verified claims ({@code iss}, {@code jti}, {@code sub}, {@code exp}). */
    public void recordAgent(Map<String, Object> claims) {
        TokenKey key = new TokenKey(String.valueOf(claims.get("iss")), String.valueOf(claims.get("jti")));
        agents.put(key, new AgentRecord(key.issuer(), String.valueOf(claims.get("sub")), number(claims.get("exp"))));
    }

    /**
     * Records a token this server issued, so a revocation can cascade to it.
     *
     * @param claims the issued token's claims ({@code iss}, {@code jti}, {@code exp},
     *     optionally {@code mission_s256})
     * @param recipients servers to notify when it is revoked
     * @param dependencies tokens whose revocation revokes this one
     * @param agentIdentity the agent {@code (iss, sub)} it was issued to, or {@code null}
     */
    public void recordIssued(
            Map<String, Object> claims,
            List<String> recipients,
            List<TokenKey> dependencies,
            @Nullable AgentIdentity agentIdentity) {
        TokenKey key = new TokenKey(String.valueOf(claims.get("iss")), String.valueOf(claims.get("jti")));
        Object mission = claims.get("mission_s256");
        issued.put(
                key,
                new IssuedToken(
                        key,
                        number(claims.get("exp")),
                        recipients,
                        dependencies,
                        agentIdentity,
                        mission == null ? null : mission.toString()));
    }

    /** An agent identity {@code (iss, sub)} used to cascade agent revocations. */
    public record AgentIdentity(String issuer, String sub) {}

    @Nullable
    AgentRecord agent(TokenKey key) {
        return agents.get(key);
    }

    Map<TokenKey, IssuedToken> issued() {
        return issued;
    }

    private static long number(@Nullable Object value) {
        if (value instanceof Number n) {
            return n.longValue();
        }
        throw new TokenException("Revocation records require an integer exp", null, "invalid_request", null, null);
    }
}
