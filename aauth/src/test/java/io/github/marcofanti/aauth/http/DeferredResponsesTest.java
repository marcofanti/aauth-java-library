package io.github.marcofanti.aauth.http;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DeferredResponsesTest {

    private static final String PENDING_URL = "https://ps.example/pending/abc123";

    @Test
    void generatesPendingIdsAndInteractionCodes() {
        assertThat(DeferredResponses.generatePendingId()).hasSize(12).matches("[0-9a-f]+");
        assertThat(DeferredResponses.generateInteractionCode()).hasSize(8).matches("[A-Z0-9]+");
        assertThat(DeferredResponses.generateInteractionCode(4)).hasSize(4);
        assertThat(DeferredResponses.generatePendingId()).isNotEqualTo(DeferredResponses.generatePendingId());
    }

    @Test
    void buildsPendingBodyWithInteractionFields() {
        Map<String, Object> body =
                DeferredResponses.buildPendingResponseBody(DeferredResponses.PendingSpec.builder(PENDING_URL)
                        .require("interaction")
                        .code("ABCD1234")
                        .build());

        assertThat(body)
                .containsEntry("status", "pending")
                .containsEntry("location", PENDING_URL)
                .containsEntry("requirement", "interaction")
                .containsEntry("code", "ABCD1234");
    }

    @Test
    void buildsPendingHeadersPerRequirementLevel() {
        Map<String, String> interaction =
                DeferredResponses.buildPendingResponseHeaders(DeferredResponses.PendingSpec.builder(PENDING_URL)
                        .require("interaction")
                        .code("ABCD1234")
                        .url("https://ps.example/interact")
                        .retryAfter(3)
                        .build());
        assertThat(interaction)
                .containsEntry("Location", PENDING_URL)
                .containsEntry("Retry-After", "3")
                .containsEntry("Cache-Control", "no-store")
                .containsEntry(
                        "AAuth-Requirement",
                        "requirement=interaction; url=\"https://ps.example/interact\"; code=\"ABCD1234\"");

        assertThat(DeferredResponses.buildPendingResponseHeaders(DeferredResponses.PendingSpec.builder(PENDING_URL)
                        .require("approval")
                        .build()))
                .containsEntry("AAuth-Requirement", "requirement=approval");

        assertThat(DeferredResponses.buildPendingResponseHeaders(DeferredResponses.PendingSpec.builder(PENDING_URL)
                        .require("clarification")
                        .build()))
                .containsEntry("AAuth-Requirement", "requirement=clarification");

        assertThat(DeferredResponses.buildPendingResponseHeaders(DeferredResponses.PendingSpec.builder(PENDING_URL)
                        .require("claims")
                        .requiredClaims(List.of("email", "name"))
                        .build()))
                .containsEntry("AAuth-Requirement", "requirement=claims; required_claims=(\"email\" \"name\")");
    }

    @Test
    void buildsSuccessAndErrorBodies() {
        assertThat(DeferredResponses.buildSuccessResponse("token123", 3600))
                .containsEntry("auth_token", "token123")
                .containsEntry("expires_in", 3600);
        assertThat(DeferredResponses.buildPollingErrorBody("denied", "user said no"))
                .containsEntry("error", "denied")
                .containsEntry("error_description", "user said no");
        assertThat(DeferredResponses.buildPollingErrorBody("expired", null)).containsOnlyKeys("error");
    }

    @Test
    void parsePendingResponseNormalizesUnknownStatus() {
        DeferredResponses.PendingResponse parsed = DeferredResponses.parsePendingResponse(
                Map.of("status", "something-new", "location", PENDING_URL, "require", "approval"));

        assertThat(parsed.status()).isEqualTo("pending");
        assertThat(parsed.requirement()).isEqualTo("approval");

        assertThat(DeferredResponses.parsePendingResponse(Map.of("status", "interacting"))
                        .status())
                .isEqualTo("interacting");
    }

    @Test
    void detectsTokenRequestModes() {
        assertThat(DeferredResponses.detectTokenRequestMode(Map.of("resource_token", "rt")))
                .isEqualTo("resource_access");
        assertThat(DeferredResponses.detectTokenRequestMode(Map.of("scope", "data.read")))
                .isEqualTo("self_access");
        assertThat(DeferredResponses.detectTokenRequestMode(Map.of("resource_token", "rt", "upstream_token", "ut")))
                .isEqualTo("call_chaining");
        assertThat(DeferredResponses.detectTokenRequestMode(Map.of("auth_token", "at")))
                .isEqualTo("token_refresh");
        assertThatThrownBy(() -> DeferredResponses.detectTokenRequestMode(Map.of("other", "x")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void pendingSpecRequiresLocation() {
        assertThatThrownBy(() -> DeferredResponses.PendingSpec.builder(null).build())
                .isInstanceOf(IllegalArgumentException.class);
    }
}
