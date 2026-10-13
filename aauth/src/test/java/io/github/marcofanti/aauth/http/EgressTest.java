package io.github.marcofanti.aauth.http;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.JwksException;
import java.net.InetAddress;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class EgressTest {

    @Test
    void publicAddressesAreGlobal() throws Exception {
        for (String ip : List.of("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111")) {
            assertThat(Egress.isGlobal(InetAddress.getByName(ip))).as(ip).isTrue();
        }
    }

    @Test
    void specialPurposeAddressesAreNotGlobal() throws Exception {
        for (String ip : List.of(
                "0.0.0.0",
                "10.1.2.3",
                "100.64.0.1",
                "127.0.0.1",
                "169.254.169.254",
                "172.16.0.1",
                "192.0.0.8",
                "192.0.2.1",
                "192.168.1.1",
                "198.18.0.1",
                "198.51.100.1",
                "203.0.113.1",
                "224.0.0.1",
                "255.255.255.255",
                "::",
                "::1",
                "fe80::1",
                "fd00::1",
                "2001:db8::1",
                "2001::1",
                "100::1")) {
            assertThat(Egress.isGlobal(InetAddress.getByName(ip))).as(ip).isFalse();
        }
    }

    @Test
    void rejectsNonHttpsCredentialsAndFragments() {
        for (String url : List.of(
                "http://example.com/x",
                "https://u:p@example.com/x",
                "https://example.com/x#f",
                "https:///x",
                "not a url")) {
            assertThatThrownBy(() -> Egress.admitPublicUrl(url)).as(url).isInstanceOf(JwksException.class);
        }
    }

    @Test
    void rejectsHostsResolvingToPrivateAddresses() {
        assertThatThrownBy(() -> Egress.admitPublicUrl("https://127.0.0.1/x"))
                .hasMessage("Network URL resolves to a non-public address");
        assertThatThrownBy(() -> Egress.admitPublicUrl("https://[::1]:8443/x"))
                .hasMessage("Network URL resolves to a non-public address");
        assertThatThrownBy(() -> Egress.admitPublicUrl("https://unresolvable.invalid/x"))
                .hasMessage("Network host cannot be resolved");
    }

    @Test
    void admittedTransportChecksBeforeSending() {
        AtomicInteger sent = new AtomicInteger();
        HttpTransport transport = Egress.admitted((method, url, headers, body) -> {
            sent.incrementAndGet();
            return new AAuthResponse(200, Map.of(), new byte[0]);
        });

        assertThatThrownBy(() -> transport.send("GET", "https://10.0.0.1/x", Map.of(), null))
                .isInstanceOf(JwksException.class);
        assertThat(sent).hasValue(0);
    }

    @Test
    void admittedTransportSendsToPublicLiteralAddress() throws Exception {
        AtomicInteger sent = new AtomicInteger();
        HttpTransport transport = Egress.admitted((method, url, headers, body) -> {
            sent.incrementAndGet();
            return new AAuthResponse(204, Map.of(), new byte[0]);
        });

        assertThat(transport.send("GET", "https://8.8.8.8/x", Map.of(), null).statusCode())
                .isEqualTo(204);
        assertThat(sent).hasValue(1);
    }
}
