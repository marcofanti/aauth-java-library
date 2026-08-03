package io.github.marcofanti.aauth.signing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SignatureBaseTest {

    private static final String SIGNATURE_KEY_HEADER = "sig=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"abc\"";
    private static final String PARAMS =
            "(\"@method\" \"@authority\" \"@path\" \"@query\" \"signature-key\");created=1700000000";

    @Test
    void buildsRfc9421SignatureBase() {
        String base = SignatureBase.build(
                "GET",
                "example.com",
                "/api",
                "a=1",
                Map.of(),
                null,
                SIGNATURE_KEY_HEADER,
                List.of("@method", "@authority", "@path", "@query", "signature-key"),
                PARAMS);

        assertThat(base).isEqualTo("""
                        "@method": GET
                        "@authority": example.com
                        "@path": /api
                        "@query": ?a=1
                        "signature-key": sig=hwk;kty="OKP";crv="Ed25519";x="abc"
                        "@signature-params": ("@method" "@authority" "@path" "@query" "signature-key");created=1700000000""");
    }

    @Test
    void coversContentHeadersWhenBodyPresent() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        Map<String, String> headers = Map.of(
                "Content-Type", "application/json",
                "Content-Digest", "sha-256=:abc=:");

        String base = SignatureBase.build(
                "POST",
                "example.com",
                "/",
                null,
                headers,
                body,
                SIGNATURE_KEY_HEADER,
                List.of("@method", "content-type", "content-digest", "signature-key"),
                "(\"@method\" \"content-type\" \"content-digest\" \"signature-key\");created=1");

        assertThat(base).contains("\"content-type\": application/json");
        assertThat(base).contains("\"content-digest\": sha-256=:abc=:");
    }

    @Test
    void coversAauthMissionHeader() {
        String base = SignatureBase.build(
                "POST",
                "example.com",
                "/",
                null,
                Map.of("AAuth-Mission", "jwt=abc.def.ghi"),
                null,
                SIGNATURE_KEY_HEADER,
                List.of("@method", "signature-key", "aauth-mission"),
                "(\"@method\" \"signature-key\" \"aauth-mission\");created=1");

        assertThat(base).contains("\"aauth-mission\": jwt=abc.def.ghi");
    }

    @Test
    void rejectsQueryComponentWithoutQueryString() {
        assertThatThrownBy(() -> SignatureBase.build(
                        "GET",
                        "example.com",
                        "/",
                        null,
                        Map.of(),
                        null,
                        SIGNATURE_KEY_HEADER,
                        List.of("@query"),
                        PARAMS))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("@query");
    }

    @Test
    void rejectsContentComponentsWithoutBody() {
        assertThatThrownBy(() -> SignatureBase.build(
                        "GET",
                        "example.com",
                        "/",
                        null,
                        Map.of(),
                        null,
                        SIGNATURE_KEY_HEADER,
                        List.of("content-digest"),
                        PARAMS))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsMissingContentDigestHeader() {
        assertThatThrownBy(() -> SignatureBase.build(
                        "POST",
                        "example.com",
                        "/",
                        null,
                        Map.of(),
                        new byte[] {1},
                        SIGNATURE_KEY_HEADER,
                        List.of("content-digest"),
                        PARAMS))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("content-digest");
    }

    @Test
    void rejectsUnknownComponent() {
        assertThatThrownBy(() -> SignatureBase.build(
                        "GET",
                        "example.com",
                        "/",
                        null,
                        Map.of(),
                        null,
                        SIGNATURE_KEY_HEADER,
                        List.of("x-custom"),
                        PARAMS))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("x-custom");
    }

    @Test
    void rejectsMissingSignatureParams() {
        assertThatThrownBy(() -> SignatureBase.build(
                        "GET",
                        "example.com",
                        "/",
                        null,
                        Map.of(),
                        null,
                        SIGNATURE_KEY_HEADER,
                        List.of("@method"),
                        null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void determinesDefaultCoveredComponents() {
        assertThat(SignatureBase.determineCoveredComponents(null, null, null, false))
                .containsExactly("@method", "@authority", "@path", "signature-key");
    }

    @Test
    void includesQueryAndAdditionalComponentsAndMission() {
        assertThat(SignatureBase.determineCoveredComponents("a=1", new byte[] {1}, List.of("content-digest"), true))
                .containsExactly(
                        "@method", "@authority", "@path", "@query", "content-digest", "signature-key", "aauth-mission");
    }

    @Test
    void contentDigestMatchesRfc9530Vector() {
        byte[] body = "{\"hello\": \"world\"}".getBytes(StandardCharsets.UTF_8);
        assertThat(SignatureBase.contentDigest(body))
                .isEqualTo("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:");
    }

    @Test
    void contentDigestSupportsSha512Rfc9530Vector() {
        byte[] body = "{\"hello\": \"world\"}".getBytes(StandardCharsets.UTF_8);
        assertThat(SignatureBase.contentDigest(body, "sha-512"))
                .isEqualTo("sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm"
                        + "+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:");
        assertThatThrownBy(() -> SignatureBase.contentDigest(body, "md5"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("md5");
    }

    @Test
    void verifyContentDigestHandlesDictionaries() {
        byte[] body = "{\"hello\": \"world\"}".getBytes(StandardCharsets.UTF_8);
        String sha256 = SignatureBase.contentDigest(body);
        String sha512 = SignatureBase.contentDigest(body, "sha-512");

        assertThat(SignatureBase.verifyContentDigest(sha256, body)).isEqualTo(SignatureBase.DigestCheck.MATCH);
        assertThat(SignatureBase.verifyContentDigest(sha512, body)).isEqualTo(SignatureBase.DigestCheck.MATCH);
        assertThat(SignatureBase.verifyContentDigest(sha256 + ", " + sha512, body))
                .isEqualTo(SignatureBase.DigestCheck.MATCH);

        byte[] otherBody = "tampered".getBytes(StandardCharsets.UTF_8);
        assertThat(SignatureBase.verifyContentDigest(sha256, otherBody)).isEqualTo(SignatureBase.DigestCheck.MISMATCH);
        // One matching and one stale member: any recognized mismatch fails.
        assertThat(SignatureBase.verifyContentDigest(SignatureBase.contentDigest(otherBody) + ", " + sha512, otherBody))
                .isEqualTo(SignatureBase.DigestCheck.MISMATCH);

        assertThat(SignatureBase.verifyContentDigest("unixsum=:AAAA:", body))
                .isEqualTo(SignatureBase.DigestCheck.NO_SUPPORTED_ALGORITHM);
        assertThat(SignatureBase.verifyContentDigest("garbage", body))
                .isEqualTo(SignatureBase.DigestCheck.NO_SUPPORTED_ALGORITHM);
    }

    @Test
    void headerLookupIsCaseInsensitive() {
        String base = SignatureBase.build(
                "POST",
                "example.com",
                "/",
                null,
                Map.of("CONTENT-TYPE", "text/plain"),
                new byte[] {1},
                SIGNATURE_KEY_HEADER,
                List.of("content-type", "signature-key"),
                "(\"content-type\" \"signature-key\");created=1");

        assertThat(base).contains("\"content-type\": text/plain");
    }
}
