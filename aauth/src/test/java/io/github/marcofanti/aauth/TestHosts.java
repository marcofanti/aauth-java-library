package io.github.marcofanti.aauth;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Hostname selection for live-socket tests.
 *
 * <p>Lab hostnames ({@code *.uma.lab}) resolve to 127.0.0.1 on development machines; CI runners
 * cannot resolve them. Tests use the lab name when it resolves to a loopback address (never a
 * real remote host) and fall back to {@code 127.0.0.1} otherwise.
 */
public final class TestHosts {

    private TestHosts() {}

    /** Returns {@code preferred} when it resolves to loopback; {@code 127.0.0.1} otherwise. */
    public static String loopbackHost(String preferred) {
        try {
            if (InetAddress.getByName(preferred).isLoopbackAddress()) {
                return preferred;
            }
        } catch (UnknownHostException e) {
            // Not resolvable here (e.g. CI) — use the literal loopback address.
        }
        return "127.0.0.1";
    }
}
