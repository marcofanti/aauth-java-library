package io.github.marcofanti.aauth.keys;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.marcofanti.aauth.agent.TokenExchange;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
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
    void tokenExchangeDefaultClientIsHttp11() {
        TokenExchange.Exchange exchange = TokenExchange.Exchange.builder(
                        "a.b.c", KeyPairs.generateEd25519(), "agent.jwt")
                .build();

        assertThat(exchange.httpClient().version()).isEqualTo(HttpClient.Version.HTTP_1_1);
    }

    @Test
    void callerInjectedClientIsUntouched() {
        HttpClient http2Client =
                HttpClient.newBuilder().version(HttpClient.Version.HTTP_2).build();

        TokenExchange.Exchange exchange = TokenExchange.Exchange.builder(
                        "a.b.c", KeyPairs.generateEd25519(), "agent.jwt")
                .httpClient(http2Client)
                .build();

        assertThat(exchange.httpClient()).isSameAs(http2Client);
        assertThat(exchange.httpClient().version()).isEqualTo(HttpClient.Version.HTTP_2);
    }
}
