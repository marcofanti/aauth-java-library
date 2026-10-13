package io.github.marcofanti.aauth.metadata;

import io.github.marcofanti.aauth.Identifiers;
import io.github.marcofanti.aauth.MetadataException;
import io.github.marcofanti.aauth.keys.DefaultHttpClient;
import io.github.marcofanti.aauth.keys.JsonHttpClient;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
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
     * Person server metadata per draft-11 §11.2.2, published at
     * {@code /.well-known/aauth-person.json}. Draft-11 renamed {@code token_endpoint} to
     * {@code auth_token_endpoint} and added {@code person_token_endpoint}. Optional fields:
     * {@code mission_endpoint}, {@code permission_endpoint}, {@code audit_endpoint},
     * {@code interaction_endpoint}, {@code mission_control_endpoint}, {@code revocation_endpoint},
     * {@code scopes_supported}, {@code claims_supported}.
     */
    public static Doc personServer(
            String personServer, String personTokenEndpoint, String authTokenEndpoint, String jwksUri) {
        Doc doc = new Doc();
        doc.with("issuer", requireValue(personServer, "issuer"));
        doc.with("person_token_endpoint", requireValue(personTokenEndpoint, "person_token_endpoint"));
        doc.with("auth_token_endpoint", requireValue(authTokenEndpoint, "auth_token_endpoint"));
        doc.with("jwks_uri", requireValue(jwksUri, "jwks_uri"));
        return doc;
    }

    /**
     * Fetches a metadata document over HTTPS (HTTP allowed only for localhost development).
     *
     * <p>When {@code httpClient} is {@code null}, the default client is pinned to HTTP/1.1 for
     * h11-server compatibility — see {@link DefaultHttpClient}.
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

    /** Endpoints a person server's metadata MUST publish for draft-11 agents. */
    public static final List<String> PS_REQUIRED_FIELDS =
            List.of("jwks_uri", "auth_token_endpoint", "person_token_endpoint");

    /**
     * Fetches and validates person-server metadata from {@code {ps}/.well-known/aauth-person.json}
     * (mirrors the reference {@code fetch_ps_metadata}); there is no fallback location.
     *
     * @throws MetadataException if the fetch fails or the document fails {@link #validate}
     */
    public static Map<String, Object> fetchPersonServer(String psUrl, JsonHttpClient httpClient) {
        String url = psUrl + "/.well-known/" + DWK_PERSON;
        Map<String, Object> metadata;
        try {
            metadata = client(httpClient).fetchJson(url);
        } catch (RuntimeException e) {
            throw new MetadataException("Failed to fetch PS metadata from " + url + ": " + e.getMessage(), url, e);
        }
        return validate(metadata, psUrl, PS_REQUIRED_FIELDS);
    }

    /**
     * Validates a metadata document's identity (mirrors the reference {@code validate_metadata}):
     * {@code issuer} must equal the expected server identifier, every {@code required} field must be
     * present, every {@code *_endpoint} must be a valid endpoint URL, and {@code jwks_uri} must be
     * HTTPS.
     *
     * @throws MetadataException {@code issuer_missing} / {@code issuer_mismatch}, or for a missing
     *     field or invalid URL
     */
    public static Map<String, Object> validate(Map<String, Object> metadata, String issuer, List<String> required) {
        try {
            Identifiers.validateServerIdentifier(issuer);
        } catch (IllegalArgumentException e) {
            throw new MetadataException(String.valueOf(e.getMessage()), issuer, e);
        }
        if (!metadata.containsKey("issuer")) {
            throw MetadataException.withCode("Metadata issuer is missing", issuer, "issuer_missing");
        }
        if (!issuer.equals(metadata.get("issuer"))) {
            throw MetadataException.withCode("Metadata issuer mismatch", issuer, "issuer_mismatch");
        }
        for (String name : required) {
            if (!metadata.containsKey(name)) {
                throw new MetadataException("Metadata missing " + name, issuer, null);
            }
        }
        for (Map.Entry<String, Object> entry : metadata.entrySet()) {
            String name = entry.getKey();
            try {
                if (name.endsWith("_endpoint")) {
                    Identifiers.validateEndpointUrl(String.valueOf(entry.getValue()));
                }
                if ("jwks_uri".equals(name) && !String.valueOf(entry.getValue()).startsWith("https://")) {
                    throw new IllegalArgumentException("JWKS URI must be HTTPS");
                }
            } catch (IllegalArgumentException e) {
                throw new MetadataException(String.valueOf(e.getMessage()), issuer, e);
            }
        }
        return metadata;
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
