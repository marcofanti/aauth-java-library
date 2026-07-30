package io.github.marcofanti.aauth.metadata;

import io.github.marcofanti.aauth.MetadataException;
import io.github.marcofanti.aauth.keys.DefaultHttpClient;
import io.github.marcofanti.aauth.keys.JsonHttpClient;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * AAuth {@code .well-known} metadata documents: generation and fetching.
 *
 * <p>Each factory seeds the document's required fields; optional fields are added with
 * {@link Doc#with(String, Object)} using the JSON field names from the spec. Documents are plain
 * maps, matching the JSON shape on the wire.
 */
public final class Metadata {

    /** Well-known document names ({@code dwk} values). */
    public static final String DWK_AGENT = "aauth-agent.json";

    public static final String DWK_RESOURCE = "aauth-resource.json";
    public static final String DWK_ACCESS = "aauth-access.json";
    public static final String DWK_PERSON = "aauth-person.json";

    private Metadata() {}

    /** Fluent builder for a metadata document; {@code null} values are skipped. */
    public static final class Doc {
        private final Map<String, Object> fields = new LinkedHashMap<>();

        private Doc() {}

        /** Adds an optional field; ignored when {@code value} is {@code null}. */
        public Doc with(String field, Object value) {
            if (value != null) {
                fields.put(field, value);
            }
            return this;
        }

        /** Returns the document as an immutable ordered map. */
        public Map<String, Object> build() {
            return java.util.Collections.unmodifiableMap(new LinkedHashMap<>(fields));
        }
    }

    /**
     * Agent metadata per spec §Agent Server Metadata, published at
     * {@code /.well-known/aauth-agent.json}. Optional fields: {@code client_name},
     * {@code logo_uri}, {@code logo_dark_uri}, {@code callback_endpoint}, {@code login_endpoint},
     * {@code localhost_callback_allowed}, {@code clarification_supported}, {@code tos_uri},
     * {@code policy_uri}.
     */
    public static Doc agent(String agentId, String jwksUri) {
        return required(agentId, jwksUri);
    }

    /**
     * Resource metadata per spec §13.3, published at {@code /.well-known/aauth-resource.json}.
     * Optional fields: {@code client_name}, {@code logo_uri}, {@code logo_dark_uri},
     * {@code authorization_endpoint}, {@code resource_token_endpoint},
     * {@code interaction_endpoint}, {@code scope_descriptions},
     * {@code additional_signature_components}, {@code signature_window},
     * {@code login_endpoint}, {@code revocation_endpoint}.
     */
    public static Doc resource(String resourceId, String jwksUri) {
        return required(resourceId, jwksUri);
    }

    /**
     * Access (auth) server metadata, published at {@code /.well-known/aauth-access.json}.
     * Optional fields: {@code login_endpoint}, {@code revocation_endpoint}.
     */
    public static Doc authServer(String authId, String jwksUri, String tokenEndpoint, String interactionEndpoint) {
        Doc doc = new Doc();
        doc.with("issuer", requireValue(authId, "issuer"));
        doc.with("token_endpoint", requireValue(tokenEndpoint, "token_endpoint"));
        doc.with("interaction_endpoint", requireValue(interactionEndpoint, "interaction_endpoint"));
        doc.with("jwks_uri", requireValue(jwksUri, "jwks_uri"));
        return doc;
    }

    /**
     * Person server metadata per spec §PS Metadata, published at
     * {@code /.well-known/aauth-person.json}. Optional fields: {@code mission_endpoint},
     * {@code permission_endpoint}, {@code audit_endpoint}, {@code interaction_endpoint},
     * {@code mission_control_endpoint}, {@code login_endpoint}, {@code revocation_endpoint},
     * {@code scopes_supported}, {@code claims_supported}.
     */
    public static Doc personServer(String personServer, String tokenEndpoint, String jwksUri) {
        Doc doc = new Doc();
        doc.with("issuer", requireValue(personServer, "issuer"));
        doc.with("token_endpoint", requireValue(tokenEndpoint, "token_endpoint"));
        doc.with("jwks_uri", requireValue(jwksUri, "jwks_uri"));
        return doc;
    }

    /**
     * Fetches a metadata document over HTTPS (HTTP allowed only for localhost development).
     *
     * @throws IllegalArgumentException if the URL is non-HTTPS and not localhost
     * @throws MetadataException if the fetch fails
     */
    public static Map<String, Object> fetch(String url, JsonHttpClient httpClient) {
        if (!url.startsWith("https://")) {
            String host = URI.create(url).getHost();
            boolean localhost =
                    "localhost".equals(host) || "127.0.0.1".equals(host) || "::1".equals(host) || "[::1]".equals(host);
            if (!localhost) {
                throw new IllegalArgumentException("Metadata URL must use HTTPS (except localhost): " + url);
            }
        }
        try {
            return client(httpClient).fetchJson(url);
        } catch (RuntimeException e) {
            throw new MetadataException("Failed to fetch metadata from " + url + ": " + e.getMessage(), url, e);
        }
    }

    /**
     * Fetches person-server metadata, trying {@code /.well-known/aauth-person.json} then the
     * extensionless {@code /.well-known/aauth-person}.
     *
     * @throws MetadataException if neither path yields a document
     */
    public static Map<String, Object> fetchPersonServer(String psUrl, JsonHttpClient httpClient) {
        String base = psUrl.endsWith("/") ? psUrl.substring(0, psUrl.length() - 1) : psUrl;
        RuntimeException lastFailure = null;
        for (String path : new String[] {"/.well-known/" + DWK_PERSON, "/.well-known/aauth-person"}) {
            try {
                return client(httpClient).fetchJson(base + path);
            } catch (RuntimeException e) {
                lastFailure = e;
            }
        }
        throw new MetadataException("Could not fetch PS metadata from " + psUrl, psUrl, lastFailure);
    }

    private static Doc required(String issuer, String jwksUri) {
        Doc doc = new Doc();
        doc.with("issuer", requireValue(issuer, "issuer"));
        doc.with("jwks_uri", requireValue(jwksUri, "jwks_uri"));
        return doc;
    }

    private static String requireValue(String value, String field) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value;
    }

    private static JsonHttpClient client(JsonHttpClient httpClient) {
        return httpClient != null ? httpClient : new DefaultHttpClient();
    }
}
