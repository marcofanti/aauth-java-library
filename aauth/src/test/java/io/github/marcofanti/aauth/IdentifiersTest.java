package io.github.marcofanti.aauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class IdentifiersTest {

    @Test
    void validAgentIdentifierPasses() {
        assertThat(Identifiers.validateAgentIdentifier("aauth:my-agent_1+x.y@agent.example"))
                .isEqualTo("aauth:my-agent_1+x.y@agent.example");
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
        Identifiers.AgentIdentifier parsed = Identifiers.parseAgentIdentifier("aauth:agent@agent.example");
        assertThat(parsed.local()).isEqualTo("agent");
        assertThat(parsed.domain()).isEqualTo("agent.example");
    }

    @Test
    void derivesAgentIdentifierFromServerUrl() {
        assertThat(Identifiers.agentIdentifierFromServerUrl("http://127.0.0.1:8001", "agent"))
                .isEqualTo("aauth:agent-8001@127.0.0.1");
        assertThat(Identifiers.agentIdentifierFromServerUrl("https://agent.example", "agent"))
                .isEqualTo("aauth:agent@agent.example");
    }

    @Test
    void validServerIdentifierPasses() {
        assertThat(Identifiers.validateServerIdentifier("https://resource.example"))
                .isEqualTo("https://resource.example");
    }

    @Test
    void serverIdentifierRejectsBadForms() {
        assertThatThrownBy(() -> Identifiers.validateServerIdentifier("http://resource.example"))
                .hasMessageContaining("https");
        assertThatThrownBy(() -> Identifiers.validateServerIdentifier("https://resource.example:8443"))
                .hasMessageContaining("port");
        assertThatThrownBy(() -> Identifiers.validateServerIdentifier("https://resource.example/api"))
                .hasMessageContaining("path");
        assertThatThrownBy(() -> Identifiers.validateServerIdentifier("https://resource.example/"))
                .hasMessageContaining("path");
        assertThatThrownBy(() -> Identifiers.validateServerIdentifier("https://resource.example?a=1"))
                .hasMessageContaining("query");
        assertThatThrownBy(() -> Identifiers.validateServerIdentifier("https://resource.example#frag"))
                .hasMessageContaining("fragment");
        assertThatThrownBy(() -> Identifiers.validateServerIdentifier("https://Resource.example"))
                .hasMessageContaining("lowercase");
        assertThatThrownBy(() -> Identifiers.validateServerIdentifier("")).hasMessageContaining("empty");
    }

    @Test
    void endpointUrlAllowsPathButNotQueryOrFragment() {
        assertThat(Identifiers.validateEndpointUrl("https://auth.example/token"))
                .isEqualTo("https://auth.example/token");
        assertThatThrownBy(() -> Identifiers.validateEndpointUrl("https://auth.example/token?x=1"))
                .hasMessageContaining("query");
        assertThatThrownBy(() -> Identifiers.validateEndpointUrl("https://auth.example/token#f"))
                .hasMessageContaining("fragment");
        assertThatThrownBy(() -> Identifiers.validateEndpointUrl("http://auth.example/token"))
                .hasMessageContaining("https");
    }

    @Test
    void otherUrlOnlyRequiresHttps() {
        assertThat(Identifiers.validateOtherUrl("https://x.example/jwks.json?v=1"))
                .isEqualTo("https://x.example/jwks.json?v=1");
        assertThatThrownBy(() -> Identifiers.validateOtherUrl("ftp://x.example"))
                .hasMessageContaining("https");
    }
}
