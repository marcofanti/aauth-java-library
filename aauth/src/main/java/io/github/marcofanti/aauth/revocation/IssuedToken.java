package io.github.marcofanti.aauth.revocation;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.jspecify.annotations.Nullable;

/**
 * A token this server issued, with what its revocation depends on and who must be told (mirrors
 * the reference {@code IssuedToken}). {@link #outcomes()} remembers each recipient's last result so
 * a repeated revocation retries only the failures.
 *
 * @param key the token's issuer and {@code jti}
 * @param exp the token's expiry (Unix seconds); expired tokens are not cascaded
 * @param recipients servers to notify on revocation
 * @param dependencies tokens whose revocation revokes this one
 * @param agentIdentity the agent identity it was issued to, or {@code null}
 * @param missionS256 its mission binding, or {@code null}
 */
public record IssuedToken(
        RevocationStore.TokenKey key,
        long exp,
        List<String> recipients,
        List<RevocationStore.TokenKey> dependencies,
        RevocationStore.@Nullable AgentIdentity agentIdentity,
        @Nullable String missionS256,
        Map<String, Map<String, Object>> outcomes) {

    public IssuedToken {
        recipients = List.copyOf(recipients);
        dependencies = List.copyOf(dependencies);
    }

    IssuedToken(
            RevocationStore.TokenKey key,
            long exp,
            List<String> recipients,
            List<RevocationStore.TokenKey> dependencies,
            RevocationStore.@Nullable AgentIdentity agentIdentity,
            @Nullable String missionS256) {
        this(key, exp, recipients, dependencies, agentIdentity, missionS256, new ConcurrentHashMap<>());
    }
}
