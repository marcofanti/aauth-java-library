package io.github.marcofanti.aauth;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.marcofanti.aauth.http.AAuthRequest;
import io.github.marcofanti.aauth.http.AAuthResponse;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CoreTypesTest {

    @Test
    void buildsErrorResponseBody() {
        Map<String, Object> body = ErrorCodes.buildErrorResponse(
                ErrorCodes.ERROR_INVALID_RESOURCE_TOKEN, "resource token expired", Map.of("retry", true));

        assertThat(body)
                .containsEntry("error", "invalid_resource_token")
                .containsEntry("error_description", "resource token expired")
                .containsEntry("retry", true);
    }

    @Test
    void errorResponseOmitsNullDescription() {
        assertThat(ErrorCodes.buildErrorResponse(ErrorCodes.ERROR_DENIED, null, null))
                .containsOnlyKeys("error");
    }

    @Test
    void requestNormalizesMethodAndPath() {
        AAuthRequest request = new AAuthRequest("get", "resource.example", null, null, null, null);

        assertThat(request.method()).isEqualTo("GET");
        assertThat(request.path()).isEqualTo("/");
        assertThat(request.targetUri()).isEqualTo("https://resource.example/");
    }

    @Test
    void requestHeaderLookupIsCaseInsensitive() {
        AAuthRequest request =
                new AAuthRequest("GET", "resource.example", "/api", "a=1", Map.of("Signature-Input", "sig=..."), null);

        assertThat(request.getHeader("signature-input")).isEqualTo("sig=...");
        assertThat(request.getHeader("missing")).isNull();
        assertThat(request.targetUri()).isEqualTo("https://resource.example/api?a=1");
    }

    @Test
    void responseHeaderLookupIsCaseInsensitive() {
        AAuthResponse response = new AAuthResponse(401, Map.of("AAuth-Requirement", "auth-token"), null);

        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.getHeader("aauth-requirement")).isEqualTo("auth-token");
        assertThat(response.getHeader("location")).isNull();
    }

    @Test
    void exceptionsCarryContextFields() {
        assertThat(new TokenException("bad", "aa-agent+jwt").tokenType()).isEqualTo("aa-agent+jwt");
        assertThat(new ChallengeException("bad", "interaction").challengeType()).isEqualTo("interaction");
        assertThat(new MetadataException("bad", "https://x/.well-known/a.json", null).metadataUrl())
                .isEqualTo("https://x/.well-known/a.json");
        assertThat(new JwksException("bad", "https://x/jwks.json", null).jwksUri())
                .isEqualTo("https://x/jwks.json");
        assertThat(new ChallengeException("bad").challengeType()).isNull();
        assertThat(new MetadataException("bad").metadataUrl()).isNull();
        assertThat(new JwksException("bad").jwksUri()).isNull();
    }
}
