package io.github.marcofanti.aauth.headers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.ChallengeException;
import io.github.marcofanti.aauth.ErrorCodes;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AAuthHeadersTest {

    // --- Requirement builders and parsing -------------------------------------------------

    @Test
    void buildsPseudonymAndIdentityRequirements() {
        assertThat(AAuthHeaders.buildPseudonymRequirement(null, null)).isEqualTo("requirement=pseudonym");
        assertThat(AAuthHeaders.buildIdentityRequirement(List.of("EdDSA", "ES256"), List.of("content-digest")))
                .isEqualTo("requirement=identity, algorithms=(\"EdDSA\" \"ES256\"),"
                        + " required_input=(\"content-digest\")");
    }

    @Test
    void buildsAAuthRequirementLevels() {
        assertThat(AAuthHeaders.buildAuthTokenRequirement("rt.jwt.value"))
                .isEqualTo("requirement=auth-token; resource-token=\"rt.jwt.value\"");
        assertThat(AAuthHeaders.buildInteractionRequirement("https://ps.example/interact", "ABCD1234"))
                .isEqualTo("requirement=interaction; url=\"https://ps.example/interact\"; code=\"ABCD1234\"");
        assertThat(AAuthHeaders.buildApprovalRequirement()).isEqualTo("requirement=approval");
        assertThat(AAuthHeaders.buildClarificationRequirement()).isEqualTo("requirement=clarification");
        assertThat(AAuthHeaders.buildClaimsRequirement()).isEqualTo("requirement=claims");
    }

    @Test
    void parsesSignatureRequirementWithAllParameters() {
        AAuthHeaders.ParsedChallenge parsed = AAuthHeaders.parseSignatureRequirement(
                "requirement=identity, algorithms=(\"EdDSA\"), required_input=(\"@query\" \"content-digest\")");

        assertThat(parsed.requirement()).isEqualTo("identity");
        assertThat(parsed.algorithms()).containsExactly("EdDSA");
        assertThat(parsed.requiredInput()).containsExactly("@query", "content-digest");
    }

    @Test
    void parseSignatureRequirementRejectsMissingRequirement() {
        assertThatThrownBy(() -> AAuthHeaders.parseSignatureRequirement("foo=bar"))
                .isInstanceOf(ChallengeException.class)
                .hasMessageContaining("requirement");
    }

    @Test
    void parsesAuthTokenChallenge() {
        AAuthHeaders.ParsedChallenge parsed =
                AAuthHeaders.parseAAuthHeader("requirement=auth-token; resource-token=\"aaa.bbb.ccc\"");

        assertThat(parsed.requirement()).isEqualTo("auth-token");
        assertThat(parsed.resourceToken()).isEqualTo("aaa.bbb.ccc");
    }

    @Test
    void parsesInteractionChallenge() {
        AAuthHeaders.ParsedChallenge parsed = AAuthHeaders.parseAAuthHeader(
                "requirement=interaction; url=\"https://ps.example/i\"; code=\"XYZ12345\"");

        assertThat(parsed.requirement()).isEqualTo("interaction");
        assertThat(parsed.url()).isEqualTo("https://ps.example/i");
        assertThat(parsed.code()).isEqualTo("XYZ12345");
    }

    @Test
    void parsesLegacyRequireFormat() {
        AAuthHeaders.ParsedChallenge parsed = AAuthHeaders.parseAAuthHeader(
                "require=auth-token; resource-token=\"rt\"; auth-server=\"https://auth.example\"");

        assertThat(parsed.requirement()).isEqualTo("auth-token");
        assertThat(parsed.resourceToken()).isEqualTo("rt");
        assertThat(parsed.authServer()).isEqualTo("https://auth.example");
    }

    @Test
    void parsesAcceptSignatureShapeViaUnifiedParser() {
        AAuthHeaders.ParsedChallenge parsed =
                AAuthHeaders.parseAAuthHeader("sig=(\"@method\" \"@authority\" \"@path\");sigkey=jkt");

        assertThat(parsed.requirement()).isEqualTo(AAuthHeaders.REQUIRE_PSEUDONYM);
        assertThat(parsed.sigkey()).isEqualTo("jkt");
        assertThat(parsed.components()).containsExactly("@method", "@authority", "@path");
    }

    @Test
    void parseAAuthHeaderRejectsUnknownShape() {
        assertThatThrownBy(() -> AAuthHeaders.parseAAuthHeader("nonsense")).isInstanceOf(ChallengeException.class);
    }

    @Test
    void mapsRequirementLevelsToResponseHeaders() {
        assertThat(AAuthHeaders.requirementHeaderForLevel(AAuthHeaders.REQUIRE_PSEUDONYM))
                .isEqualTo(AAuthHeaders.HEADER_ACCEPT_SIGNATURE);
        assertThat(AAuthHeaders.requirementHeaderForLevel(AAuthHeaders.REQUIRE_IDENTITY))
                .isEqualTo(AAuthHeaders.HEADER_ACCEPT_SIGNATURE);
        for (String level : AAuthHeaders.aauthProtocolRequirementLevels()) {
            assertThat(AAuthHeaders.requirementHeaderForLevel(level)).isEqualTo(AAuthHeaders.HEADER_AAUTH_REQUIREMENT);
        }
    }

    @Test
    void challengeHeaderLookupPrefersAAuthRequirement() {
        Map<String, String> headers = Map.of(
                "Accept-Signature", "sig=(\"@method\");sigkey=jkt",
                "AAUTH-REQUIREMENT", "requirement=approval");

        assertThat(AAuthHeaders.getChallengeHeaderValue(headers)).isEqualTo("requirement=approval");
        assertThat(AAuthHeaders.getChallengeHeaderValue(Map.of())).isEmpty();
        assertThat(AAuthHeaders.getChallengeHeaderValue(null)).isEmpty();
    }

    // --- Accept-Signature ------------------------------------------------------------------

    @Test
    void buildsAcceptSignatureWithDefaults() {
        assertThat(AcceptSignatureHeader.build(AcceptSignatureHeader.SIGKEY_URI, null, null))
                .isEqualTo("sig=(\"@method\" \"@authority\" \"@path\");sigkey=uri");
    }

    @Test
    void buildsAcceptSignatureWithSingleAlg() {
        assertThat(AcceptSignatureHeader.build(
                        AcceptSignatureHeader.SIGKEY_JKT, List.of("@method"), List.of("ed25519")))
                .isEqualTo("sig=(\"@method\");alg=\"ed25519\";sigkey=jkt");
    }

    @Test
    void parsesAcceptSignatureAndMapsRequirement() {
        AcceptSignatureHeader.Parsed jkt =
                AcceptSignatureHeader.parse("sig=(\"@method\" \"@path\");alg=\"ed25519\";sigkey=jkt");
        assertThat(jkt.requirement()).isEqualTo("pseudonym");
        assertThat(jkt.alg()).isEqualTo("ed25519");
        assertThat(jkt.components()).containsExactly("@method", "@path");

        assertThat(AcceptSignatureHeader.parse("sig=(\"@method\");sigkey=uri").requirement())
                .isEqualTo("identity");
        assertThat(AcceptSignatureHeader.parse("sig=(\"@method\");sigkey=x509").requirement())
                .isEqualTo("identity");
    }

    // --- Signature-Error -------------------------------------------------------------------

    @Test
    void buildsSignatureErrorWithConditionalLists() {
        assertThat(SignatureErrorHeader.build(ErrorCodes.ERROR_INVALID_SIGNATURE, null, null))
                .isEqualTo("error=invalid_signature");
        assertThat(SignatureErrorHeader.build(ErrorCodes.ERROR_INVALID_INPUT, List.of("@query"), List.of("ignored")))
                .isEqualTo("error=invalid_input, required_input=(\"@query\")");
        assertThat(SignatureErrorHeader.build(
                        ErrorCodes.ERROR_UNSUPPORTED_ALGORITHM, List.of("ignored"), List.of("ed25519")))
                .isEqualTo("error=unsupported_algorithm, supported_algorithms=(\"ed25519\")");
    }

    @Test
    void parsesSignatureError() {
        SignatureErrorHeader.Parsed parsed = SignatureErrorHeader.parse(
                "error=unsupported_algorithm, supported_algorithms=(\"ed25519\" \"ecdsa-p256-sha256\")");

        assertThat(parsed.error()).isEqualTo("unsupported_algorithm");
        assertThat(parsed.supportedAlgorithms()).containsExactly("ed25519", "ecdsa-p256-sha256");
        assertThat(parsed.requiredInput()).isNull();
    }

    // --- Capabilities, access, mission -----------------------------------------------------

    @Test
    void capabilitiesRoundTrip() {
        String header = AAuthHeaders.buildCapabilitiesHeader(List.of("interaction", "clarification"));
        assertThat(header).isEqualTo("interaction, clarification");
        assertThat(AAuthHeaders.parseCapabilitiesHeader(header)).containsExactly("interaction", "clarification");
        assertThat(AAuthHeaders.parseCapabilitiesHeader(" , ")).isEmpty();
    }

    @Test
    void authorizationAAuthHeaderExtractsToken() {
        assertThat(AAuthHeaders.parseAuthorizationAAuthHeader("AAuth opaque-token-123"))
                .isEqualTo("opaque-token-123");
        assertThat(AAuthHeaders.parseAuthorizationAAuthHeader("aauth  token ")).isEqualTo("token");
        assertThat(AAuthHeaders.parseAuthorizationAAuthHeader("Bearer x")).isNull();
        assertThat(AAuthHeaders.parseAuthorizationAAuthHeader("AAuth ")).isNull();
        assertThat(AAuthHeaders.parseAuthorizationAAuthHeader(null)).isNull();
    }

    @Test
    void missionHeaderRoundTripsAndAcceptsLegacyManager() {
        String header = AAuthHeaders.buildMissionHeader("https://ps.example", "abc123");
        assertThat(header).isEqualTo("approver=\"https://ps.example\"; s256=\"abc123\"");

        AAuthHeaders.Mission mission = AAuthHeaders.parseMissionHeader(header);
        assertThat(mission.approver()).isEqualTo("https://ps.example");
        assertThat(mission.s256()).isEqualTo("abc123");

        assertThat(AAuthHeaders.parseMissionHeader("manager=\"https://old.example\"; s256=\"x\"")
                        .approver())
                .isEqualTo("https://old.example");
    }
}
