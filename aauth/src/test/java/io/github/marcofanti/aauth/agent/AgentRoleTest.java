package io.github.marcofanti.aauth.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.ChallengeException;
import io.github.marcofanti.aauth.headers.AAuthHeaders;
import io.github.marcofanti.aauth.signing.HttpSignatureException;
import io.github.marcofanti.aauth.signing.SignatureInputHeader;
import io.github.marcofanti.aauth.signing.SignatureKeyHeader;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Agent signing under the jwt profile and challenge handling (mirrors the reference). */
class AgentRoleTest {

    private static final String TARGET = "https://gateway.uma.lab/api";

    private final KeyPair keyPair = KeyPairs.generateEd25519();
    private final AgentRequestSigner signer =
            AgentRequestSigner.builder(keyPair).agentToken("agent.token.jwt").build();

    private static String jwtOf(Map<String, String> headers) {
        return SignatureKeyHeader.parse(headers.get("Signature-Key")).params().get("jwt");
    }

    private static List<String> covered(Map<String, String> headers) {
        return SignatureInputHeader.parse(headers.get("Signature-Input")).components();
    }

    @Test
    void signsWithTheJwtSchemeAndTheAgentToken() {
        Map<String, String> headers = signer.signRequest("GET", TARGET, Map.of(), null);

        assertThat(SignatureKeyHeader.parse(headers.get("Signature-Key")).scheme())
                .isEqualTo("jwt");
        assertThat(jwtOf(headers)).isEqualTo("agent.token.jwt");
    }

    @Test
    void presentsAnotherTokenWhenAsked() {
        Map<String, String> headers = signer.signRequest(
                "GET", TARGET, Map.of(), null, AgentRequestSigner.Options.presenting("person.token.jwt"));
        assertThat(jwtOf(headers)).isEqualTo("person.token.jwt");

        assertThat(jwtOf(signer.withToken("auth.token.jwt").signRequest("GET", TARGET, Map.of(), null)))
                .isEqualTo("auth.token.jwt");
    }

    @ParameterizedTest
    @ValueSource(strings = {"PS", "AS", "REVOCATION"})
    void bodiesToServersAreCovered(String role) {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        Map<String, String> headers = signer.signRequest(
                "POST",
                TARGET,
                Map.of("Content-Type", "application/json"),
                body,
                AgentRequestSigner.Options.to(AgentRequestSigner.RecipientRole.valueOf(role)));

        assertThat(covered(headers)).contains("content-digest", "content-type");
        assertThat(headers).containsKey("Content-Digest");
    }

    @Test
    void bodiesToResourcesAreCoveredOnlyOnRequest() {
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        assertThat(covered(signer.signRequest("POST", TARGET, Map.of(), body))).doesNotContain("content-digest");

        Map<String, String> headers = signer.signRequest(
                "POST",
                TARGET,
                Map.of(),
                body,
                new AgentRequestSigner.Options(
                        null, AgentRequestSigner.RecipientRole.RESOURCE, List.of("content-digest")));
        assertThat(covered(headers)).contains("content-digest");
    }

    @Test
    void aTokenIsRequired() {
        AgentRequestSigner bare = AgentRequestSigner.builder(keyPair).build();

        assertThatThrownBy(() -> bare.signRequest("GET", TARGET, Map.of(), null))
                .isInstanceOf(HttpSignatureException.class)
                .hasMessageContaining("token is required");
    }

    @Test
    void challengesNeverFallBackToHwk() {
        ChallengeHandler handler = new ChallengeHandler();
        ChallengeHandler.HeldTokens all = new ChallengeHandler.HeldTokens(true, true, true);

        for (String requirement : List.of("agent-token", "person-token", "auth-token")) {
            AAuthHeaders.ParsedChallenge challenge = handler.parseChallenge("requirement=" + requirement);
            assertThat(handler.determineResponseScheme(challenge, all)).isEqualTo("jwt");
        }
        for (String requirement : List.of("pseudonym", "identity", "unknown")) {
            AAuthHeaders.ParsedChallenge challenge = handler.parseChallenge("requirement=" + requirement);
            assertThatThrownBy(() -> handler.determineResponseScheme(challenge, all))
                    .isInstanceOf(ChallengeException.class)
                    .hasMessageContaining("non-credential");
        }
    }

    @Test
    void eachRequirementNeedsItsOwnToken() {
        ChallengeHandler handler = new ChallengeHandler();
        AAuthHeaders.ParsedChallenge person = handler.parseChallenge("requirement=person-token");
        AAuthHeaders.ParsedChallenge auth = handler.parseChallenge("requirement=auth-token; resource-token=\"rt\"");

        assertThat(handler.determineResponseScheme(person, new ChallengeHandler.HeldTokens(false, true, false)))
                .isEqualTo("jwt");
        // An auth token does not satisfy a person-token requirement, nor the reverse.
        assertThatThrownBy(() ->
                        handler.determineResponseScheme(person, new ChallengeHandler.HeldTokens(true, false, true)))
                .hasMessageContaining("unavailable");
        assertThatThrownBy(
                        () -> handler.determineResponseScheme(auth, new ChallengeHandler.HeldTokens(true, true, false)))
                .hasMessageContaining("unavailable");
    }
}
