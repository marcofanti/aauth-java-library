package io.github.marcofanti.aauth.keys;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.marcofanti.aauth.http.HttpTransport;
import java.net.http.HttpClient;
import org.junit.jupiter.api.Test;

/**
 * Library-constructed default HTTP clients must be pinned to HTTP/1.1: the JDK's h2c upgrade
 * breaks h11-based servers (uvicorn/FastAPI person servers reject requests or drop bodies).
 */
class Http11DefaultTest {

    @Test
    void defaultJsonHttpClientIsHttp11() {
        assertThat(new DefaultHttpClient().httpClient().version()).isEqualTo(HttpClient.Version.HTTP_1_1);
    }

    @Test
    void defaultTransportClientIsHttp11() {
        assertThat(HttpTransport.defaultHttpClient().version()).isEqualTo(HttpClient.Version.HTTP_1_1);
    }
}
