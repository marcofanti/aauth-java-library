package io.github.marcofanti.aauth.metadata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.JwksException;
import io.github.marcofanti.aauth.MetadataException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MetadataTest {

    @Test
    void buildsAgentMetadataWithOptionalFields() {
        Map<String, Object> metadata = Metadata.agent("https://portal.uma.lab", "https://portal.uma.lab/jwks.json")
                .with("name", "My Agent")
                .with("callback_endpoint", "https://portal.uma.lab/callback")
                .with("tos_uri", null)
                .build();

        assertThat(metadata)
                .containsEntry("issuer", "https://portal.uma.lab")
                .containsEntry("jwks_uri", "https://portal.uma.lab/jwks.json")
                .containsEntry("name", "My Agent")
                .doesNotContainKey("tos_uri");
        assertThat(metadata.keySet().iterator().next()).isEqualTo("issuer");
    }

    @Test
    void buildsResourceMetadataWithSignatureComponents() {
        Map<String, Object> metadata = Metadata.resource("https://grafana.uma.lab", "https://grafana.uma.lab/jwks.json")
                .with("authorization_endpoint", "https://grafana.uma.lab/authz")
                .with("additional_signature_components", List.of("content-digest"))
                .with("signature_window", 60)
                .build();

        assertThat(metadata)
                .containsEntry("additional_signature_components", List.of("content-digest"))
                .containsEntry("signature_window", 60);
    }

    @Test
    void resourceJwksUriIsOptional() {
        assertThat(Metadata.resource("https://grafana.uma.lab", null).build()).containsOnlyKeys("issuer");
    }

    @Test
    void buildsAuthServerMetadataWithRequiredEndpoints() {
        Map<String, Object> metadata = Metadata.authServer(
                        "https://alice-as.uma.lab",
                        "https://alice-as.uma.lab/jwks.json",
                        "https://alice-as.uma.lab/token")
                .with("revocation_endpoint", "https://alice-as.uma.lab/revoke")
                .build();

        assertThat(metadata)
                .containsEntry("issuer", "https://alice-as.uma.lab")
                .containsEntry("auth_token_endpoint", "https://alice-as.uma.lab/token")
                .containsEntry("revocation_endpoint", "https://alice-as.uma.lab/revoke")
                .doesNotContainKeys("token_endpoint", "interaction_endpoint");
    }

    @Test
    void buildsPersonServerMetadata() {
        Map<String, Object> metadata = Metadata.personServer(
                        "https://ps.uma.lab",
                        "https://ps.uma.lab/person-token",
                        "https://ps.uma.lab/auth-token",
                        "https://ps.uma.lab/jwks.json")
                .with("scopes_supported", List.of("email", "payment"))
                .build();

        assertThat(metadata)
                .containsEntry("issuer", "https://ps.uma.lab")
                .containsEntry("person_token_endpoint", "https://ps.uma.lab/person-token")
                .containsEntry("auth_token_endpoint", "https://ps.uma.lab/auth-token")
                .containsEntry("scopes_supported", List.of("email", "payment"));
    }

    @Test
    void generatorsValidateTheirOutput() {
        assertThatThrownBy(() -> Metadata.agent("http://portal.uma.lab", "https://portal.uma.lab/jwks.json")
                        .build())
                .isInstanceOf(MetadataException.class);
        assertThatThrownBy(() -> Metadata.agent("https://portal.uma.lab", "http://portal.uma.lab/jwks.json")
                        .build())
                .hasMessageContaining("JWKS URI must be HTTPS");
        assertThatThrownBy(() -> Metadata.authServer(
                                "https://as.uma.lab", "https://as.uma.lab/jwks", "http://as.uma.lab/token")
                        .build())
                .isInstanceOf(MetadataException.class);
    }

    @Test
    void fetchValidatesAgainstTheIssuerInTheUrl() {
        Map<String, Object> document = Metadata.agent("https://portal.uma.lab", "https://portal.uma.lab/jwks")
                .build();
        assertThat(Metadata.fetch("https://portal.uma.lab/.well-known/aauth-agent.json", url -> document))
                .isEqualTo(document);
        assertThatThrownBy(() -> Metadata.fetch("https://other.uma.lab/.well-known/aauth-agent.json", url -> document))
                .extracting(e -> ((MetadataException) e).errorCode())
                .isEqualTo("issuer_mismatch");
    }

    @Test
    void fetchRejectsBadUrlsBeforeFetching() {
        for (String url : List.of(
                "http://gateway.uma.lab/.well-known/aauth-resource.json",
                "http://localhost:8080/.well-known/aauth-agent.json",
                "https://gateway.uma.lab/meta.json",
                "https://gateway.uma.lab/.well-known/a/b.json",
                "https://gateway.uma.lab/.well-known/")) {
            assertThatThrownBy(() -> Metadata.fetch(url, u -> {
                        throw new AssertionError("should not fetch");
                    }))
                    .as(url)
                    .isInstanceOf(MetadataException.class);
        }
    }

    @Test
    void fetchAuthServerRequiresAuthTokenEndpoint() {
        Map<String, Object> document = Map.of("issuer", "https://as.uma.lab", "jwks_uri", "https://as.uma.lab/jwks");
        assertThatThrownBy(() ->
                        Metadata.fetchAuthServer("https://as.uma.lab/.well-known/aauth-access.json", url -> document))
                .hasMessageContaining("missing auth_token_endpoint");
    }

    @Test
    void fetchWrapsClientFailures() {
        assertThatThrownBy(() -> Metadata.fetch("https://grafana.uma.lab/.well-known/aauth-resource.json", url -> {
                    throw new JwksException("boom");
                }))
                .isInstanceOf(MetadataException.class)
                .hasMessageContaining("grafana.uma.lab");
    }

    @Test
    void personServerFetchIsStrictAndValidated() {
        Map<String, Object> document = Metadata.personServer(
                        "https://ps.uma.lab",
                        "https://ps.uma.lab/identity",
                        "https://ps.uma.lab/authorize",
                        "https://ps.uma.lab/jwks")
                .build();
        java.util.List<String> fetched = new java.util.ArrayList<>();
        assertThat(Metadata.fetchPersonServer("https://ps.uma.lab", url -> {
                    fetched.add(url);
                    return document;
                }))
                .containsEntry("auth_token_endpoint", "https://ps.uma.lab/authorize");
        assertThat(fetched).containsExactly("https://ps.uma.lab/.well-known/aauth-person.json");
    }

    @Test
    void validateChecksIssuerFieldsAndUrls() {
        Map<String, Object> ok = Map.of(
                "issuer",
                "https://ps.uma.lab",
                "jwks_uri",
                "https://ps.uma.lab/jwks",
                "auth_token_endpoint",
                "https://ps.uma.lab/a");
        assertThat(Metadata.validate(ok, "https://ps.uma.lab", java.util.List.of("jwks_uri")))
                .isEqualTo(ok);

        assertThatThrownBy(() -> Metadata.validate(Map.of(), "https://ps.uma.lab", java.util.List.of()))
                .isInstanceOf(MetadataException.class)
                .extracting(e -> ((MetadataException) e).errorCode())
                .isEqualTo("issuer_missing");
        assertThatThrownBy(() -> Metadata.validate(
                        Map.of("issuer", "https://other.uma.lab"), "https://ps.uma.lab", java.util.List.of()))
                .extracting(e -> ((MetadataException) e).errorCode())
                .isEqualTo("issuer_mismatch");
        assertThatThrownBy(() -> Metadata.validate(
                        Map.of("issuer", "https://ps.uma.lab"), "https://ps.uma.lab", java.util.List.of("jwks_uri")))
                .hasMessageContaining("missing jwks_uri");
        assertThatThrownBy(() -> Metadata.validate(
                        Map.of("issuer", "https://ps.uma.lab", "auth_token_endpoint", "http://ps.uma.lab/a"),
                        "https://ps.uma.lab",
                        java.util.List.of()))
                .isInstanceOf(MetadataException.class);
        assertThatThrownBy(() -> Metadata.validate(
                        Map.of("issuer", "https://ps.uma.lab", "jwks_uri", "http://ps.uma.lab/jwks"),
                        "https://ps.uma.lab",
                        java.util.List.of()))
                .hasMessageContaining("JWKS URI must be HTTPS");
        assertThatThrownBy(() -> Metadata.validate(Map.of(), "http://ps.uma.lab:8765", java.util.List.of()))
                .isInstanceOf(MetadataException.class);
    }

    @Test
    void personServerFetchFailureIsWrapped() {
        assertThatThrownBy(() -> Metadata.fetchPersonServer("https://ps.uma.lab", url -> {
                    throw new JwksException("404");
                }))
                .isInstanceOf(MetadataException.class)
                .hasMessageContaining("ps.uma.lab");
    }
}
