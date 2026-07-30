package io.github.marcofanti.aauth.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.ChallengeException;
import io.github.marcofanti.aauth.headers.AAuthHeaders;
import io.github.marcofanti.aauth.signing.HttpSignatureException;
import io.github.marcofanti.aauth.signing.SignatureKeyHeader;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import java.security.KeyPair;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AgentRoleTest {

    private static final String TARGET = "https://gateway.uma.lab/api";

    private final KeyPair keyPair = KeyPairs.generateEd25519();

    @Test
    void signsWithEachScheme() {
        AgentRequestSigner signer = AgentRequestSigner.builder(keyPair)
                .agentId("https://portal.uma.lab")
                .agentToken("aaa.bbb.ccc")
                .build();

        Map<String, String> hwk = signer.signRequest("GET", TARGET, Map.of(), null, "hwk");
        assertThat(SignatureKeyHeader.parse(hwk.get("Signature-Key")).scheme()).isEqualTo("hwk");

        Map<String, String> jwksUri = signer.signRequest("GET", TARGET, Map.of(), null, "jwks_uri");
        SignatureKeyHeader.Parsed parsedJwksUri = SignatureKeyHeader.parse(jwksUri.get("Signature-Key"));
        assertThat(parsedJwksUri.scheme()).isEqualTo("jwks_uri");
        assertThat(parsedJwksUri.params())
                .containsEntry("id", "https://portal.uma.lab")
                .containsEntry("dwk", "aauth-agent.json")
                .containsEntry("kid", "key-1");

        Map<String, String> jwt = signer.signRequest("GET", TARGET, Map.of(), null, "jwt");
        assertThat(SignatureKeyHeader.parse(jwt.get("Signature-Key")).params()).containsEntry("jwt", "aaa.bbb.ccc");
    }

    @Test
    void schemesRequireTheirConfiguration() {
        AgentRequestSigner bare = AgentRequestSigner.builder(keyPair).build();

        assertThatThrownBy(() -> bare.signRequest("GET", TARGET, Map.of(), null, "jwks_uri"))
                .isInstanceOf(HttpSignatureException.class)
                .hasMessageContaining("agentId");
        assertThatThrownBy(() -> bare.signRequest("GET", TARGET, Map.of(), null, "jwt"))
                .isInstanceOf(HttpSignatureException.class)
                .hasMessageContaining("agentToken");
    }

    @Test
    void withTokenSwapsTheJwt() {
        AgentRequestSigner signer =
                AgentRequestSigner.builder(keyPair).agentToken("old.token.jwt").build();

        Map<String, String> signed =
                signer.withToken("new.token.jwt").signRequest("GET", TARGET, Map.of(), null, "jwt");

        assertThat(SignatureKeyHeader.parse(signed.get("Signature-Key")).params())
                .containsEntry("jwt", "new.token.jwt");
    }

    @Test
    void challengeHandlerParsesAndPicksSchemes() {
        ChallengeHandler handler = new ChallengeHandler();

        AAuthHeaders.ParsedChallenge authToken =
                handler.parseChallenge("requirement=auth-token; resource-token=\"rt\"");
        assertThat(handler.determineResponseScheme(authToken, false, true)).isEqualTo("jwt");
        assertThatThrownBy(() -> handler.determineResponseScheme(authToken, true, false))
                .isInstanceOf(ChallengeException.class)
                .hasMessageContaining("auth token");

        AAuthHeaders.ParsedChallenge identity = handler.parseChallenge("requirement=identity");
        assertThat(handler.determineResponseScheme(identity, true, false)).isEqualTo("jwt");
        assertThat(handler.determineResponseScheme(identity, false, false)).isEqualTo("jwks_uri");

        AAuthHeaders.ParsedChallenge pseudonym = handler.parseChallenge("requirement=pseudonym");
        assertThat(handler.determineResponseScheme(pseudonym, true, true)).isEqualTo("hwk");
    }
}
