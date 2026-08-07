package io.github.marcofanti.aauth;

import java.net.URI;
import java.util.regex.Pattern;

/**
 * Server and agent identifier validation per AAuth spec §5.
 *
 * <p>Server identifiers use HTTPS URLs; agent identifiers use the {@code aauth:} URI scheme of
 * the form {@code aauth:local@domain}.
 */
public final class Identifiers {

    private static final Pattern AAUTH_LOCAL = Pattern.compile("^[a-z0-9\\-_+.]+$");

    private Identifiers() {}

    /** An {@code aauth:local@domain} agent identifier split into its parts. */
    public record AgentIdentifier(String local, String domain) {}

    /**
     * Validates an agent identifier ({@code aauth:local@domain}).
     *
     * @return the identifier unchanged when valid
     * @throws IllegalArgumentException if the identifier is invalid
     */
    public static String validateAgentIdentifier(String identifier) {
        if (identifier == null || identifier.isEmpty()) {
            throw new IllegalArgumentException("Agent identifier must not be empty");
        }
        if (!identifier.startsWith("aauth:")) {
            throw new IllegalArgumentException("Agent identifier must use aauth: scheme: " + identifier);
        }
        String rest = identifier.substring("aauth:".length());
        int at = rest.indexOf('@');
        if (at == -1) {
            throw new IllegalArgumentException(
                    "Agent identifier must contain '@' separating local and domain: " + identifier);
        }
        String local = rest.substring(0, at);
        String domain = rest.substring(at + 1);

        if (local.isEmpty()) {
            throw new IllegalArgumentException("Agent identifier local part must not be empty: " + identifier);
        }
        if (local.length() > 255) {
            throw new IllegalArgumentException(
                    "Agent identifier local part must not exceed 255 characters: " + identifier);
        }
        if (!AAUTH_LOCAL.matcher(local).matches()) {
            throw new IllegalArgumentException(
                    "Agent identifier local part contains invalid characters (only a-z, 0-9, -, _, +, . allowed): "
                            + identifier);
        }
        if (domain.isEmpty()) {
            throw new IllegalArgumentException("Agent identifier domain part must not be empty: " + identifier);
        }
        if (domain.contains("://")) {
            throw new IllegalArgumentException("Agent identifier domain must not include a scheme: " + identifier);
        }
        return identifier;
    }

    /** Parses an {@code aauth:local@domain} identifier, validating it first. */
    public static AgentIdentifier parseAgentIdentifier(String identifier) {
        validateAgentIdentifier(identifier);
        String rest = identifier.substring("aauth:".length());
        int at = rest.indexOf('@');
        return new AgentIdentifier(rest.substring(0, at), rest.substring(at + 1));
    }

    /**
     * Derives an {@code aauth:} identifier from an agent server URL.
     *
     * <p>URLs with a port (localhost demos) get the port appended to the local part so multiple
     * participants on one host stay distinct: {@code http://ps.uma.lab:8001} →
     * {@code aauth:agent-8001@ps.uma.lab}.
     */
    public static String agentIdentifierFromServerUrl(String serverUrl, String local) {
        URI uri = URI.create(serverUrl);
        String host = uri.getHost() == null ? "localhost" : uri.getHost();
        int port = uri.getPort();
        String localPart = port != -1 ? local + "-" + port : local;
        return "aauth:" + localPart + "@" + host;
    }

    /**
     * Validates a server identifier per AAuth spec §5.1: https scheme, host only (no port, path,
     * query, or fragment), no trailing slash, lowercase.
     *
     * @return the URL unchanged when valid
     * @throws IllegalArgumentException if the identifier is invalid
     */
    public static String validateServerIdentifier(String url) {
        if (url == null || url.isEmpty()) {
            throw new IllegalArgumentException("Server identifier must not be empty");
        }
        URI uri = parseUri(url, "Server identifier");
        if (!"https".equals(uri.getScheme())) {
            throw new IllegalArgumentException("Server identifier must use https scheme: " + url);
        }
        if (uri.getHost() == null) {
            throw new IllegalArgumentException("Server identifier must have a hostname: " + url);
        }
        if (uri.getPort() != -1) {
            throw new IllegalArgumentException("Server identifier must not contain a port: " + url);
        }
        if (uri.getRawPath() != null && !uri.getRawPath().isEmpty()) {
            throw new IllegalArgumentException("Server identifier must not contain a path: " + url);
        }
        if (uri.getRawQuery() != null) {
            throw new IllegalArgumentException("Server identifier must not contain a query string: " + url);
        }
        if (uri.getRawFragment() != null) {
            throw new IllegalArgumentException("Server identifier must not contain a fragment: " + url);
        }
        if (url.endsWith("/")) {
            throw new IllegalArgumentException("Server identifier must not include a trailing slash: " + url);
        }
        if (!url.equals(url.toLowerCase(java.util.Locale.ROOT))) {
            throw new IllegalArgumentException("Server identifier must be lowercase: " + url);
        }
        return url;
    }

    /**
     * Validates an endpoint URL per AAuth spec §5.2: https scheme, no fragment, no query string.
     *
     * @return the URL unchanged when valid
     * @throws IllegalArgumentException if the URL is invalid
     */
    public static String validateEndpointUrl(String url) {
        if (url == null || url.isEmpty()) {
            throw new IllegalArgumentException("Endpoint URL must not be empty");
        }
        URI uri = parseUri(url, "Endpoint URL");
        if (!"https".equals(uri.getScheme())) {
            throw new IllegalArgumentException("Endpoint URL must use https scheme: " + url);
        }
        if (uri.getRawFragment() != null) {
            throw new IllegalArgumentException("Endpoint URL must not contain a fragment: " + url);
        }
        if (uri.getRawQuery() != null) {
            throw new IllegalArgumentException("Endpoint URL must not contain a query string: " + url);
        }
        return url;
    }

    /**
     * Validates other URLs (jwks_uri, tos_uri, …) per AAuth spec §5.3: https scheme.
     *
     * @return the URL unchanged when valid
     * @throws IllegalArgumentException if the URL is invalid
     */
    public static String validateOtherUrl(String url) {
        if (url == null || url.isEmpty()) {
            throw new IllegalArgumentException("URL must not be empty");
        }
        URI uri = parseUri(url, "URL");
        if (!"https".equals(uri.getScheme())) {
            throw new IllegalArgumentException("URL must use https scheme: " + url);
        }
        return url;
    }

    /**
     * Validates a server URL loosely for token-claim checks: an absolute {@code http(s)} URL
     * with a host. Unlike {@link #validateServerIdentifier}, this tolerates {@code http} and a
     * port so dev/demo deployments on non-TLS hosts (e.g. {@code http://ps.uma.lab:8765}) are
     * accepted. The draft-10 requirement that a production {@code ps} be HTTPS is a deployment
     * policy, not a reason to fail token verification.
     *
     * @return the URL unchanged when valid
     * @throws IllegalArgumentException if the URL is not an absolute http(s) URL with a host
     */
    public static String validateServerUrl(String url) {
        if (url == null || url.isEmpty()) {
            throw new IllegalArgumentException("Server URL must not be empty");
        }
        URI uri = parseUri(url, "Server URL");
        String scheme = uri.getScheme();
        if (!"https".equals(scheme) && !"http".equals(scheme)) {
            throw new IllegalArgumentException("Server URL must use http or https scheme: " + url);
        }
        if (uri.getHost() == null) {
            throw new IllegalArgumentException("Server URL must have a hostname: " + url);
        }
        return url;
    }

    private static URI parseUri(String url, String what) {
        try {
            return URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(what + " is not a valid URL: " + url, e);
        }
    }
}
