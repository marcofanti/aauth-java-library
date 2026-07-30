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
                .with("client_name", "My Agent")
                .with("clarification_supported", true)
                .with("tos_uri", null)
                .build();

        assertThat(metadata)
                .containsEntry("issuer", "https://portal.uma.lab")
                .containsEntry("jwks_uri", "https://portal.uma.lab/jwks.json")
                .containsEntry("client_name", "My Agent")
                .containsEntry("clarification_supported", true)
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
    void buildsAuthServerMetadataWithRequiredEndpoints() {
        Map<String, Object> metadata = Metadata.authServer(
                        "https://alice-as.uma.lab",
                        "https://alice-as.uma.lab/jwks.json",
                        "https://alice-as.uma.lab/token",
                        "https://alice-as.uma.lab/interact")
                .with("revocation_endpoint", "https://alice-as.uma.lab/revoke")
                .build();

        assertThat(metadata)
                .containsEntry("issuer", "https://alice-as.uma.lab")
                .containsEntry("token_endpoint", "https://alice-as.uma.lab/token")
                .containsEntry("interaction_endpoint", "https://alice-as.uma.lab/interact")
                .containsEntry("revocation_endpoint", "https://alice-as.uma.lab/revoke");
    }

    @Test
    void buildsPersonServerMetadata() {
        Map<String, Object> metadata = Metadata.personServer(
                        "https://ps.uma.lab", "https://ps.uma.lab/token", "https://ps.uma.lab/jwks.json")
                .with("scopes_supported", List.of("email", "payment"))
                .build();

        assertThat(metadata)
                .containsEntry("issuer", "https://ps.uma.lab")
                .containsEntry("scopes_supported", List.of("email", "payment"));
    }

    @Test
    void requiredFieldsAreEnforced() {
        assertThatThrownBy(() -> Metadata.agent(null, "https://x/jwks.json"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("issuer");
        assertThatThrownBy(() ->
                        Metadata.authServer("https://keycloak.uma.lab", "https://a/jwks.json", null, "https://a/i"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("token_endpoint");
    }

    @Test
    void fetchRejectsNonHttpsExceptLocalhost() {
        assertThatThrownBy(() -> Metadata.fetch("http://gateway.uma.lab/.well-known/aauth-resource.json", url -> {
                    throw new AssertionError("should not fetch");
                }))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("HTTPS");

        // Localhost HTTP is allowed for development.
        Map<String, Object> fetched =
                Metadata.fetch("http://localhost:8080/.well-known/aauth-agent.json", url -> Map.of("issuer", "x"));
        assertThat(fetched).containsEntry("issuer", "x");
    }

    @Test
    void fetchWrapsClientFailures() {
        assertThatThrownBy(() -> Metadata.fetch("https://grafana.uma.lab/meta.json", url -> {
                    throw new JwksException("boom");
                }))
                .isInstanceOf(MetadataException.class)
                .hasMessageContaining("grafana.uma.lab");
    }

    @Test
    void personServerFetchFallsBackToExtensionlessPath() {
        Map<String, Object> fetched = Metadata.fetchPersonServer("https://ps.uma.lab/", url -> {
            if (url.endsWith("/.well-known/aauth-person.json")) {
                throw new JwksException("404");
            }
            assertThat(url).isEqualTo("https://ps.uma.lab/.well-known/aauth-person");
            return Map.of("issuer", "https://ps.uma.lab");
        });

        assertThat(fetched).containsEntry("issuer", "https://ps.uma.lab");
    }

    @Test
    void personServerFetchFailsWhenBothPathsFail() {
        assertThatThrownBy(() -> Metadata.fetchPersonServer("https://ps.uma.lab", url -> {
                    throw new JwksException("404");
                }))
                .isInstanceOf(MetadataException.class)
                .hasMessageContaining("ps.uma.lab");
    }
}
