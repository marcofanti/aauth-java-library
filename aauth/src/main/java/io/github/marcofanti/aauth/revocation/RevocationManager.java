package io.github.marcofanti.aauth.revocation;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.marcofanti.aauth.Identifiers;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.http.AAuthResponse;
import io.github.marcofanti.aauth.signing.AAuthException;
import io.github.marcofanti.aauth.signing.HttpSignatureException;
import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.signing.SignatureKeyHeader;
import io.github.marcofanti.aauth.signing.SignatureVerifier;
import io.github.marcofanti.aauth.signing.VerifyRequest;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * Accepts revocations and cascades them to dependent tokens (draft-11 §11.12, mirrors the
 * reference {@code RevocationManager}). A revocation is recorded before anything is sent; each
 * dependent token is revoked locally and its recipients notified. A PS ({@code role ps}) answers
 * with an empty body; an AS ({@code role as}) reports per-recipient {@code downstream} outcomes.
 */
public final class RevocationManager {

    /** Default upper bound on an accepted revocation's {@code exp}: 24 hours from now. */
    public static final long DEFAULT_MAX_LIFETIME_SECONDS = 86_400;

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final Set<String> SERVER_DOCUMENTS =
            Set.of("aauth-agent.json", "aauth-person.json", "aauth-access.json", "aauth-resource.json");
    private static final List<String> REQUIRED_COMPONENTS =
            List.of("@method", "@authority", "@path", "signature-key", "content-digest", "content-type");

    /** Delivers a revocation of {@code (jti, exp)} to {@code recipient}; see {@link Revocations#send}. */
    @FunctionalInterface
    public interface Sender {
        Map<String, Object> send(String recipient, String jti, long exp);
    }

    private final String role;
    private final RevocationStore store;
    private final Sender sender;
    private final Set<String> allowedIssuers;
    private final long maxLifetimeSeconds;

    /**
     * @param issuer this server's identifier
     * @param role {@code ps}, {@code as} or {@code resource}
     * @param store the revocation state
     * @param sender delivers cascaded revocations
     * @param allowedIssuers issuers whose revocations are accepted
     * @param maxLifetimeSeconds the furthest accepted {@code exp}, relative to now
     */
    public RevocationManager(
            String issuer,
            String role,
            RevocationStore store,
            Sender sender,
            Set<String> allowedIssuers,
            long maxLifetimeSeconds) {
        try {
            Identifiers.validateServerIdentifier(issuer);
        } catch (IllegalArgumentException e) {
            throw new TokenException("Invalid server identifier: " + issuer, null, "invalid_jwt", null, e);
        }
        this.role = role;
        this.store = store;
        this.sender = sender;
        this.allowedIssuers = Set.copyOf(allowedIssuers);
        this.maxLifetimeSeconds = maxLifetimeSeconds;
    }

    public RevocationManager(
            String issuer, String role, RevocationStore store, Sender sender, Set<String> allowedIssuers) {
        this(issuer, role, store, sender, allowedIssuers, DEFAULT_MAX_LIFETIME_SECONDS);
    }

    /**
     * Revokes {@code (issuer, jti)} and cascades to every live token that depends on it — or, at a
     * PS revoking an agent token, to every token issued to that agent identity.
     *
     * @return {@code {}}, or for an AS {@code {"downstream": [...]}}
     * @throws TokenException {@code unsupported_iss} for an unaccepted issuer, {@code invalid_request}
     *     for an invalid body or an {@code exp} beyond the accepted lifetime
     */
    public Map<String, Object> revoke(String issuer, String jti, long exp) {
        Revocations.body(jti, exp);
        if (!allowedIssuers.contains(issuer)) {
            throw new TokenException("Revocations from issuer are not accepted", null, "unsupported_iss", null, null);
        }
        if (exp > store.now() + maxLifetimeSeconds) {
            throw new TokenException(
                    "Revocation expiration exceeds accepted lifetime", null, "invalid_request", null, null);
        }
        store.record(issuer, jti, exp);
        RevocationStore.TokenKey root = new RevocationStore.TokenKey(issuer, jti);
        RevocationStore.AgentRecord agent = "ps".equals(role) ? store.agent(root) : null;
        List<Map<String, Object>> report = cascade(root, agent);
        return "as".equals(role) && !report.isEmpty() ? Map.of("downstream", report) : Map.of();
    }

    private List<Map<String, Object>> cascade(
            RevocationStore.TokenKey root, RevocationStore.@Nullable AgentRecord agent) {
        Deque<RevocationStore.TokenKey> queue = new ArrayDeque<>(List.of(root));
        Set<RevocationStore.TokenKey> visited = new HashSet<>();
        Set<RevocationStore.TokenKey> scheduled = new HashSet<>(Set.of(root));
        List<Map<String, Object>> report = new ArrayList<>();
        while (!queue.isEmpty()) {
            RevocationStore.TokenKey key = queue.poll();
            if (!visited.add(key)) {
                continue;
            }
            for (IssuedToken node : List.copyOf(store.issued().values())) {
                if (node.exp() <= store.now() || scheduled.contains(node.key()) || !dependsOn(node, key, agent)) {
                    continue;
                }
                store.record(node.key().issuer(), node.key().jti(), node.exp());
                scheduled.add(node.key());
                queue.add(node.key());
                notifyRecipients(node, report);
            }
        }
        return report;
    }

    private static boolean dependsOn(
            IssuedToken node, RevocationStore.TokenKey key, RevocationStore.@Nullable AgentRecord agent) {
        return node.dependencies().contains(key)
                || (agent != null
                        && new RevocationStore.AgentIdentity(agent.issuer(), agent.sub()).equals(node.agentIdentity()));
    }

    /** Sends to each recipient not yet confirmed; a repeat also reports prior successes. */
    private void notifyRecipients(IssuedToken node, List<Map<String, Object>> report) {
        for (String recipient : node.recipients()) {
            if (Map.of().equals(node.outcomes().get(recipient))) {
                continue;
            }
            Map<String, Object> outcome;
            try {
                outcome = sender.send(recipient, node.key().jti(), node.exp());
            } catch (RuntimeException e) {
                outcome = Map.of("error", Revocations.REVOCATION_UNAVAILABLE);
            }
            if (!Revocations.isOutcomeCode(outcome.get("error"))) {
                outcome = Map.of("error", Revocations.REVOCATION_UNAVAILABLE);
            }
            node.outcomes().put(recipient, outcome);
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("recipient", recipient);
            Object error = outcome.get("error");
            if (error != null) {
                entry.put("error", error);
            }
            report.add(entry);
        }
        for (String recipient : node.recipients()) {
            boolean reported = report.stream().anyMatch(entry -> recipient.equals(entry.get("recipient")));
            if (Map.of().equals(node.outcomes().get(recipient)) && !reported) {
                report.add(Map.of("recipient", recipient));
            }
        }
    }

    /**
     * Handles a revocation request at this server's {@code revocation_endpoint}: the request must be
     * a POST signed under the {@code jwks_uri} scheme by a server identity, covering
     * {@code content-digest} and {@code content-type}, with body exactly {@code {jti, exp}}.
     *
     * @return {@code 200} (empty, or a JSON report), {@code 401} with {@code Signature-Error},
     *     {@code 403 unsupported_iss}, or {@code 400} with a problem body
     */
    public AAuthResponse handleRequest(
            String method, String targetUri, Map<String, String> headers, byte[] body, JwksFetcher jwksFetcher) {
        String issuer;
        try {
            issuer = verifiedIssuer(method, targetUri, headers, body, jwksFetcher);
        } catch (AAuthException | IllegalArgumentException e) {
            String code = e instanceof AAuthException aauth && aauth.errorCode() != null
                    ? aauth.errorCode()
                    : HttpSignatureException.ERROR_INVALID_SIGNATURE;
            return new AAuthResponse(401, Map.of("Signature-Error", "error=" + code), new byte[0]);
        }
        try {
            Map<String, Object> params = revocationParams(headers, body);
            long exp = params.get("exp") instanceof Number number ? number.longValue() : 0;
            Map<String, Object> result = revoke(issuer, String.valueOf(params.get("jti")), exp);
            return result.isEmpty()
                    ? new AAuthResponse(200, Map.of(), new byte[0])
                    : new AAuthResponse(200, Map.of("Content-Type", "application/json"), Revocations.json(result));
        } catch (TokenException e) {
            String code = e.errorCode() != null ? e.errorCode() : "invalid_request";
            Map<String, Object> problem = new LinkedHashMap<>();
            problem.put("error", code);
            problem.put("detail", String.valueOf(e.getMessage()));
            return new AAuthResponse(
                    "unsupported_iss".equals(code) ? 403 : 400,
                    Map.of("Content-Type", "application/problem+json"),
                    Revocations.json(problem));
        }
    }

    private static String verifiedIssuer(
            String method, String targetUri, Map<String, String> headers, byte[] body, JwksFetcher fetcher) {
        SignatureKeyHeader.Parsed key = SignatureKeyHeader.parse(header(headers, "signature-key"));
        if (!"POST".equals(method) || !"jwks_uri".equals(key.scheme())) {
            throw new HttpSignatureException(
                    "Revocations require a signed server POST", "unsupported_scheme", null, null);
        }
        String issuer = java.util.Objects.requireNonNullElse(key.params().get("id"), "");
        try {
            Identifiers.validateServerIdentifier(issuer);
        } catch (IllegalArgumentException e) {
            throw new HttpSignatureException("Invalid server identifier", "invalid_jwt", null, e);
        }
        if (!SERVER_DOCUMENTS.contains(key.params().get("dwk"))) {
            throw new HttpSignatureException("Invalid server metadata document", "invalid_key", null, null);
        }
        boolean valid = SignatureVerifier.verify(VerifyRequest.builder(method, targetUri)
                .headers(headers)
                .body(body)
                .signatureHeaders(
                        header(headers, "signature-input"),
                        header(headers, "signature"),
                        header(headers, "signature-key"))
                .jwksFetcher(fetcher)
                .requiredComponents(REQUIRED_COMPONENTS)
                .build());
        if (!valid) {
            throw new HttpSignatureException("Invalid revocation signature");
        }
        return issuer;
    }

    private static Map<String, Object> revocationParams(Map<String, String> headers, byte[] body) {
        String contentType = header(headers, "content-type");
        int semicolon = contentType.indexOf(';');
        if (!"application/json".equals((semicolon >= 0 ? contentType.substring(0, semicolon) : contentType).strip())) {
            throw new TokenException("Expected application/json", null, "invalid_request", null, null);
        }
        Map<String, Object> params;
        try {
            params = MAPPER.readValue(body, MAP_TYPE);
        } catch (IOException e) {
            throw new TokenException("Malformed JSON", null, "invalid_request", null, e);
        }
        if (params == null
                || !params.keySet().equals(Set.of("jti", "exp"))
                || !(params.get("jti") instanceof String)
                || !(params.get("exp") instanceof Integer || params.get("exp") instanceof Long)) {
            throw new TokenException("Expected jti and exp", null, "invalid_request", null, null);
        }
        return params;
    }

    private static String header(Map<String, String> headers, String name) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return "";
    }
}
