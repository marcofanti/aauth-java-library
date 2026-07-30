package io.github.marcofanti.aauth.keys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import io.github.marcofanti.aauth.JwksException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class DefaultHttpClientTest {

    private static HttpServer server;
    private static String baseUrl;

    @BeforeAll
    static void startServer() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/jwks.json", exchange -> {
            byte[] body = "{\"keys\": []}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.createContext("/missing", exchange -> exchange.sendResponseHeaders(404, -1));
        server.createContext("/garbage", exchange -> {
            byte[] body = "not json".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterAll
    static void stopServer() {
        server.stop(0);
    }

    @Test
    void fetchesAndParsesJson() {
        Map<String, Object> json = new DefaultHttpClient().fetchJson(baseUrl + "/jwks.json");
        assertThat(json).containsKey("keys");
    }

    @Test
    void non2xxStatusRaisesJwksException() {
        assertThatThrownBy(() -> new DefaultHttpClient().fetchJson(baseUrl + "/missing"))
                .isInstanceOf(JwksException.class)
                .hasMessageContaining("HTTP 404");
    }

    @Test
    void malformedJsonRaisesJwksException() {
        assertThatThrownBy(() -> new DefaultHttpClient().fetchJson(baseUrl + "/garbage"))
                .isInstanceOf(JwksException.class);
    }

    @Test
    void connectionFailureRaisesJwksException() {
        assertThatThrownBy(() -> new DefaultHttpClient().fetchJson("http://127.0.0.1:1/nope"))
                .isInstanceOf(JwksException.class);
    }
}
