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
        Map<String, Object> metadata = Metadata.agent("https://agent.example", "https://agent.example/jwks.json")
                .with("client_name", "My Agent")
                .with("clarification_supported", true)
                .with("tos_uri", null)
                .build();

        assertThat(metadata)
                .containsEntry("issuer", "https://agent.example")
                .containsEntry("jwks_uri", "https://agent.example/jwks.json")
                .containsEntry("client_name", "My Agent")
                .containsEntry("clarification_supported", true)
                .doesNotContainKey("tos_uri");
        assertThat(metadata.keySet().iterator().next()).isEqualTo("issuer");
    }

    @Test
    void buildsResourceMetadataWithSignatureComponents() {
        Map<String, Object> metadata = Metadata.resource("https://r.example", "https://r.example/jwks.json")
                .with("authorization_endpoint", "https://r.example/authz")
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
                        "https://auth.example",
                        "https://auth.example/jwks.json",
                        "https://auth.example/token",
                        "https://auth.example/interact")
                .with("revocation_endpoint", "https://auth.example/revoke")
                .build();

        assertThat(metadata)
                .containsEntry("issuer", "https://auth.example")
                .containsEntry("token_endpoint", "https://auth.example/token")
                .containsEntry("interaction_endpoint", "https://auth.example/interact")
                .containsEntry("revocation_endpoint", "https://auth.example/revoke");
    }

    @Test
    void buildsPersonServerMetadata() {
        Map<String, Object> metadata = Metadata.personServer(
                        "https://ps.example", "https://ps.example/token", "https://ps.example/jwks.json")
                .with("scopes_supported", List.of("email", "payment"))
                .build();

        assertThat(metadata)
                .containsEntry("issuer", "https://ps.example")
                .containsEntry("scopes_supported", List.of("email", "payment"));
    }

    @Test
    void requiredFieldsAreEnforced() {
        assertThatThrownBy(() -> Metadata.agent(null, "https://x/jwks.json"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("issuer");
        assertThatThrownBy(() -> Metadata.authServer("https://a.example", "https://a/jwks.json", null, "https://a/i"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("token_endpoint");
    }

    @Test
    void fetchRejectsNonHttpsExceptLocalhost() {
        assertThatThrownBy(() -> Metadata.fetch("http://resource.example/.well-known/aauth-resource.json", url -> {
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
        assertThatThrownBy(() -> Metadata.fetch("https://down.example/meta.json", url -> {
                    throw new JwksException("boom");
                }))
                .isInstanceOf(MetadataException.class)
                .hasMessageContaining("down.example");
    }

    @Test
    void personServerFetchFallsBackToExtensionlessPath() {
        Map<String, Object> fetched = Metadata.fetchPersonServer("https://ps.example/", url -> {
            if (url.endsWith("/.well-known/aauth-person.json")) {
                throw new JwksException("404");
            }
            assertThat(url).isEqualTo("https://ps.example/.well-known/aauth-person");
            return Map.of("issuer", "https://ps.example");
        });

        assertThat(fetched).containsEntry("issuer", "https://ps.example");
    }

    @Test
    void personServerFetchFailsWhenBothPathsFail() {
        assertThatThrownBy(() -> Metadata.fetchPersonServer("https://ps.example", url -> {
                    throw new JwksException("404");
                }))
                .isInstanceOf(MetadataException.class)
                .hasMessageContaining("ps.example");
    }
}
