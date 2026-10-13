package io.github.marcofanti.aauth.http;

import io.github.marcofanti.aauth.JwksException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;

/**
 * The library's default network policy (mirrors the reference {@code admit_public_url}): a URL is
 * admitted only if it is HTTPS without credentials or fragment and every address its host
 * resolves to is publicly routable.
 *
 * <p>Applied by the library's default clients only. Callers that inject their own client own its
 * egress policy; production deployments should also enforce egress at their proxy or network
 * layer, since resolution here and at connect time can differ.
 */
public final class Egress {

    private Egress() {}

    /**
     * Admits a URL for an outbound request.
     *
     * @throws JwksException if the URL is not HTTPS, carries credentials or a fragment, cannot be
     *     resolved, or resolves to any non-public address
     */
    public static void admitPublicUrl(String url) {
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new JwksException("Network URL is invalid: " + url, url, e);
        }
        String host = uri.getHost();
        if (!"https".equals(uri.getScheme())
                || host == null
                || uri.getRawUserInfo() != null
                || uri.getRawFragment() != null) {
            throw new JwksException("Network URL must be HTTPS without credentials or fragment", url, null);
        }
        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            throw new JwksException("Network host cannot be resolved", url, e);
        }
        for (InetAddress address : addresses) {
            if (!isGlobal(address)) {
                throw new JwksException("Network URL resolves to a non-public address", url, null);
            }
        }
    }

    /** Wraps a transport so every request URL, including discovered endpoints, is admitted first. */
    public static HttpTransport admitted(HttpTransport transport) {
        return (method, url, headers, body) -> {
            admitPublicUrl(url);
            return transport.send(method, url, headers, body);
        };
    }

    /** Whether an address is publicly routable (Python's {@code ipaddress.is_global}). */
    static boolean isGlobal(InetAddress address) {
        if (address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return false;
        }
        byte[] bytes = address.getAddress();
        if (address instanceof Inet4Address) {
            return isGlobalV4(bytes);
        }
        if (address instanceof Inet6Address) {
            return isGlobalV6(bytes);
        }
        return false;
    }

    private static boolean isGlobalV4(byte[] b) {
        int first = b[0] & 0xFF;
        int second = b[1] & 0xFF;
        int third = b[2] & 0xFF;
        return first != 0 // 0.0.0.0/8 "this network"
                && !(first == 100 && (second & 0xC0) == 64) // 100.64.0.0/10 shared address space
                && !(first == 192 && second == 0 && third == 0) // 192.0.0.0/24 IETF assignments
                && !(first == 192 && second == 0 && third == 2) // 192.0.2.0/24 TEST-NET-1
                && !(first == 198 && (second & 0xFE) == 18) // 198.18.0.0/15 benchmarking
                && !(first == 198 && second == 51 && third == 100) // 198.51.100.0/24 TEST-NET-2
                && !(first == 203 && second == 0 && third == 113) // 203.0.113.0/24 TEST-NET-3
                && first < 240; // 240.0.0.0/4 reserved, incl. broadcast
    }

    private static boolean isGlobalV6(byte[] b) {
        int first = b[0] & 0xFF;
        int second = b[1] & 0xFF;
        if ((first & 0xFE) == 0xFC) {
            return false; // fc00::/7 unique local
        }
        if (first == 0x20 && second == 0x01 && (b[2] & 0xFF) == 0x0D && (b[3] & 0xFF) == 0xB8) {
            return false; // 2001:db8::/32 documentation
        }
        if (first == 0x20 && second == 0x01 && (b[2] & 0xFE) == 0x00) {
            return false; // 2001::/23 IETF protocol assignments (incl. Teredo)
        }
        if (first == 0x01 && second == 0x00 && isZero(b, 2, 8)) {
            return false; // 100::/64 discard-only
        }
        if (isZero(b, 0, 10) && (b[10] & 0xFF) == 0xFF && (b[11] & 0xFF) == 0xFF) {
            return false; // ::ffff:0:0/96 IPv4-mapped
        }
        return true;
    }

    private static boolean isZero(byte[] bytes, int from, int to) {
        for (int i = from; i < to; i++) {
            if (bytes[i] != 0) {
                return false;
            }
        }
        return true;
    }
}
