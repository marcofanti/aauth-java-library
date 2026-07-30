package io.github.marcofanti.aauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class IdentifiersTest {

    @Test
    void validAgentIdentifierPasses() {
        assertThat(Identifiers.validateAgentIdentifier("aauth:my-agent_1+x.y@portal.uma.lab"))
                .isEqualTo("aauth:my-agent_1+x.y@portal.uma.lab");
    }

    @Test
    void agentIdentifierRejectsBadForms() {
        assertThatThrownBy(() -> Identifiers.validateAgentIdentifier(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Identifiers.validateAgentIdentifier("mailto:x@y"))
                .hasMessageContaining("aauth:");
        assertThatThrownBy(() -> Identifiers.validateAgentIdentifier("aauth:noatsign"))
                .hasMessageContaining("@");
        assertThatThrownBy(() -> Identifiers.validateAgentIdentifier("aauth:@domain"))
                .hasMessageContaining("local");
        assertThatThrownBy(() -> Identifiers.validateAgentIdentifier("aauth:UPPER@domain"))
                .hasMessageContaining("invalid characters");
        assertThatThrownBy(() -> Identifiers.validateAgentIdentifier("aauth:x@"))
                .hasMessageContaining("domain");
        assertThatThrownBy(() -> Identifiers.validateAgentIdentifier("aauth:x@https://d"))
                .hasMessageContaining("scheme");
        assertThatThrownBy(() -> Identifiers.validateAgentIdentifier("aauth:" + "a".repeat(256) + "@d"))
                .hasMessageContaining("255");
    }

    @Test
    void parsesAgentIdentifierIntoParts() {
        Identifiers.AgentIdentifier parsed = Identifiers.parseAgentIdentifier("aauth:agent@portal.uma.lab");
        assertThat(parsed.local()).isEqualTo("agent");
        assertThat(parsed.domain()).isEqualTo("portal.uma.lab");
    }

    @Test
    void derivesAgentIdentifierFromServerUrl() {
        assertThat(Identifiers.agentIdentifierFromServerUrl("http://ps.uma.lab:8001", "agent"))
                .isEqualTo("aauth:agent-8001@ps.uma.lab");
        assertThat(Identifiers.agentIdentifierFromServerUrl("https://portal.uma.lab", "agent"))
                .isEqualTo("aauth:agent@portal.uma.lab");
    }

    @Test
    void validServerIdentifierPasses() {
        assertThat(Identifiers.validateServerIdentifier("https://gateway.uma.lab"))
                .isEqualTo("https://gateway.uma.lab");
    }

    @Test
    void serverIdentifierRejectsBadForms() {
        assertThatThrownBy(() -> Identifiers.validateServerIdentifier("http://gateway.uma.lab"))
                .hasMessageContaining("https");
        assertThatThrownBy(() -> Identifiers.validateServerIdentifier("https://gateway.uma.lab:8443"))
                .hasMessageContaining("port");
        assertThatThrownBy(() -> Identifiers.validateServerIdentifier("https://gateway.uma.lab/api"))
                .hasMessageContaining("path");
        assertThatThrownBy(() -> Identifiers.validateServerIdentifier("https://gateway.uma.lab/"))
                .hasMessageContaining("path");
        assertThatThrownBy(() -> Identifiers.validateServerIdentifier("https://gateway.uma.lab?a=1"))
                .hasMessageContaining("query");
        assertThatThrownBy(() -> Identifiers.validateServerIdentifier("https://gateway.uma.lab#frag"))
                .hasMessageContaining("fragment");
        assertThatThrownBy(() -> Identifiers.validateServerIdentifier("https://Gateway.uma.lab"))
                .hasMessageContaining("lowercase");
        assertThatThrownBy(() -> Identifiers.validateServerIdentifier("")).hasMessageContaining("empty");
    }

    @Test
    void endpointUrlAllowsPathButNotQueryOrFragment() {
        assertThat(Identifiers.validateEndpointUrl("https://alice-as.uma.lab/token"))
                .isEqualTo("https://alice-as.uma.lab/token");
        assertThatThrownBy(() -> Identifiers.validateEndpointUrl("https://alice-as.uma.lab/token?x=1"))
                .hasMessageContaining("query");
        assertThatThrownBy(() -> Identifiers.validateEndpointUrl("https://alice-as.uma.lab/token#f"))
                .hasMessageContaining("fragment");
        assertThatThrownBy(() -> Identifiers.validateEndpointUrl("http://alice-as.uma.lab/token"))
                .hasMessageContaining("https");
    }

    @Test
    void otherUrlOnlyRequiresHttps() {
        assertThat(Identifiers.validateOtherUrl("https://keycloak.uma.lab/jwks.json?v=1"))
                .isEqualTo("https://keycloak.uma.lab/jwks.json?v=1");
        assertThatThrownBy(() -> Identifiers.validateOtherUrl("ftp://keycloak.uma.lab"))
                .hasMessageContaining("https");
    }
}
