package io.github.marcofanti.aauth.metadata;

import io.github.marcofanti.aauth.Identifiers;
import io.github.marcofanti.aauth.MetadataException;
import io.github.marcofanti.aauth.keys.DefaultHttpClient;
import io.github.marcofanti.aauth.keys.JsonHttpClient;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

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

    /**
     * Fluent builder for a metadata document; {@code null} values are skipped. {@link #build()}
     * validates the document with {@link Metadata#validate}, as the reference generators do.
     */
    public static final class Doc {
        private final Map<String, Object> fields = new LinkedHashMap<>();
        private final String issuer;
        private final List<String> required;

        private Doc(String issuer, List<String> required) {
            this.issuer = issuer;
            this.required = required;
            fields.put("issuer", issuer);
        }

        /** Adds an optional field; ignored when {@code value} is {@code null}. */
        public Doc with(String field, @Nullable Object value) {
            if (value != null) {
                fields.put(field, value);
            }
            return this;
        }

        /**
         * Returns the validated document as an immutable ordered map.
         *
         * @throws MetadataException if the issuer is not a server identifier, a required field is
         *     missing, an {@code *_endpoint} is invalid, or {@code jwks_uri} is not HTTPS
         */
        public Map<String, Object> build() {
            return validate(java.util.Collections.unmodifiableMap(new LinkedHashMap<>(fields)), issuer, required);
        }
    }

    /**
     * Agent metadata, published at {@code /.well-known/aauth-agent.json}. Optional fields:
     * {@code name}, {@code logo_uri}, {@code logo_dark_uri}, {@code callback_endpoint},
     * {@code localhost_callback_allowed}, {@code tos_uri}, {@code policy_uri},
     * {@code description}, {@code documentation_uri}, {@code accept_signature_algs}.
     */
    public static Doc agent(String agentId, String jwksUri) {
        return new Doc(agentId, List.of("jwks_uri")).with("jwks_uri", jwksUri);
    }

    /**
     * Resource metadata, published at {@code /.well-known/aauth-resource.json}; {@code jwks_uri}
     * is optional. Optional fields: {@code name}, {@code logo_uri}, {@code logo_dark_uri},
     * {@code authorization_endpoint}, {@code resource_token_endpoint},
     * {@code interaction_endpoint}, {@code scope_descriptions},
     * {@code additional_signature_components}, {@code signature_window},
     * {@code revocation_endpoint}, {@code access_mode}, {@code description},
     * {@code documentation_uri}, {@code accept_signature_algs}.
     */
    public static Doc resource(String resourceId, @Nullable String jwksUri) {
        return new Doc(resourceId, jwksUri != null ? List.of("jwks_uri") : List.of()).with("jwks_uri", jwksUri);
    }

    /**
     * Access server metadata, published at {@code /.well-known/aauth-access.json}. Optional
     * fields: {@code revocation_endpoint} and the common {@code name}, {@code description},
     * {@code documentation_uri}, {@code accept_signature_algs}.
     */
    public static Doc authServer(String authId, String jwksUri, String authTokenEndpoint) {
        return new Doc(authId, AUTH_SERVER_REQUIRED_FIELDS)
                .with("jwks_uri", jwksUri)
                .with("auth_token_endpoint", authTokenEndpoint);
    }

    /**
     * Person server metadata per draft-11, published at {@code /.well-known/aauth-person.json}.
     * Optional fields: {@code mission_endpoint}, {@code permission_endpoint},
     * {@code audit_endpoint}, {@code interaction_endpoint}, {@code mission_control_endpoint},
     * {@code revocation_endpoint}, {@code scopes_supported}, {@code claims_supported} and the
     * common {@code name}, {@code description}, {@code documentation_uri},
     * {@code accept_signature_algs}.
     */
    public static Doc personServer(
            String personServer, String personTokenEndpoint, String authTokenEndpoint, String jwksUri) {
        return new Doc(personServer, PS_REQUIRED_FIELDS)
                .with("jwks_uri", jwksUri)
                .with("auth_token_endpoint", authTokenEndpoint)
                .with("person_token_endpoint", personTokenEndpoint);
    }

    /**
     * Fetches a metadata document from a {@code {issuer}/.well-known/{name}} URL and validates it
     * against the issuer derived from that URL (mirrors the reference {@code fetch_metadata}).
     *
     * @param httpClient JSON client, or {@code null} for {@link DefaultHttpClient}, which admits
     *     only public HTTPS URLs
     * @throws MetadataException if the URL is not a well-known URL of a server identifier, the
     *     fetch fails, or the document fails {@link #validate}
     */
    public static Map<String, Object> fetch(String url, @Nullable JsonHttpClient httpClient) {
        return fetchValidated(url, issuerFromMetadataUrl(url), List.of("jwks_uri"), httpClient);
    }

    /**
     * Fetches and validates access-server metadata ({@code jwks_uri} and
     * {@code auth_token_endpoint} required).
     *
     * @see #fetch(String, JsonHttpClient)
     */
    public static Map<String, Object> fetchAuthServer(String url, @Nullable JsonHttpClient httpClient) {
        return fetchValidated(url, issuerFromMetadataUrl(url), AUTH_SERVER_REQUIRED_FIELDS, httpClient);
    }

    /**
     * Returns the issuer a {@code {issuer}/.well-known/{name}} metadata URL belongs to.
     *
     * @throws MetadataException if the URL is not a single-segment well-known URL
     */
    public static String issuerFromMetadataUrl(String url) {
        String marker = "/.well-known/";
        int index = url.indexOf(marker);
        if (index < 0) {
            throw new MetadataException("Expected a well-known metadata URL", url, null);
        }
        String suffix = url.substring(index + marker.length());
        if (suffix.isEmpty() || suffix.contains("/") || suffix.contains("?") || suffix.contains("#")) {
            throw new MetadataException("Invalid metadata URL", url, null);
        }
        return url.substring(0, index);
    }

    /** Endpoints a person server's metadata MUST publish for draft-11 agents. */
    public static final List<String> PS_REQUIRED_FIELDS =
            List.of("jwks_uri", "auth_token_endpoint", "person_token_endpoint");

    /** Fields an access server's metadata MUST publish. */
    public static final List<String> AUTH_SERVER_REQUIRED_FIELDS = List.of("auth_token_endpoint", "jwks_uri");

    /**
     * Fetches and validates person-server metadata from {@code {ps}/.well-known/aauth-person.json}
     * (mirrors the reference {@code fetch_ps_metadata}); there is no fallback location.
     *
     * @throws MetadataException if the fetch fails or the document fails {@link #validate}
     */
    public static Map<String, Object> fetchPersonServer(String psUrl, @Nullable JsonHttpClient httpClient) {
        return fetchValidated(psUrl + "/.well-known/" + DWK_PERSON, psUrl, PS_REQUIRED_FIELDS, httpClient);
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

    /** Checks the issuer before any network access, then fetches and validates. */
    private static Map<String, Object> fetchValidated(
            String url, String issuer, List<String> required, @Nullable JsonHttpClient httpClient) {
        try {
            Identifiers.validateServerIdentifier(issuer);
        } catch (IllegalArgumentException e) {
            throw new MetadataException(String.valueOf(e.getMessage()), url, e);
        }
        Map<String, Object> metadata;
        try {
            metadata = (httpClient != null ? httpClient : new DefaultHttpClient()).fetchJson(url);
        } catch (RuntimeException e) {
            throw new MetadataException("Failed to fetch metadata from " + url + ": " + e.getMessage(), url, e);
        }
        return validate(metadata, issuer, required);
    }
}
