package io.github.marcofanti.aauth.revocation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.http.AAuthResponse;
import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.signing.SignatureKeyHeader;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Revocation state, cascades and the signed endpoint (mirrors the reference test_draft11_governance). */
class RevocationTest {

    /** Tests talk to loopback servers, so they inject a client (the default one refuses loopback). */
    private static final HttpClient LOOPBACK =
            HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();

    private static final String RESOURCE = "https://gateway.uma.lab";
    private static final String PS = "https://ps.uma.lab";
    private static final String AP = "https://portal.uma.lab";
    private static final String AS = "https://alice-as.uma.lab";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final long now = Instant.now().getEpochSecond();
    private final KeyPair issuerKeys = KeyPairs.generateEd25519();
    private final Revocations.Signer psSigner = new Revocations.Signer(PS, issuerKeys, "issuer-1", "aauth-person.json");
    private final JwksFetcher fetch =
            (id, dwk, kid) -> Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(issuerKeys.getPublic(), "issuer-1")));

    @Test
    void statelessRevocationAndIssuerNamespace() {
        RevocationStore store = new RevocationStore();
        store.record(PS, "unknown", now + 600);

        assertThat(store.isRevoked(PS, "unknown")).isTrue();
        assertThat(store.isRevoked(AP, "unknown")).isFalse();
        store.record(PS, "expired", now - 1);
        assertThat(store.isRevoked(PS, "expired")).isFalse();
        assertThatThrownBy(() -> store.record("http://ps.uma.lab", "x", now + 600))
                .isInstanceOf(TokenException.class);
        assertThatThrownBy(() -> store.record(PS, "", now + 600))
                .isInstanceOf(TokenException.class)
                .extracting(e -> ((TokenException) e).errorCode())
                .isEqualTo("invalid_request");
    }

    @Test
    void agentRevocationCascadesByIdentityAndRetriesFailures() {
        RevocationStore store = new RevocationStore();
        store.recordAgent(Map.of("iss", AP, "jti", "agent-old", "sub", "aauth:Agent@portal.uma.lab", "exp", now + 600));
        RevocationStore.AgentIdentity agent = new RevocationStore.AgentIdentity(AP, "aauth:Agent@portal.uma.lab");
        for (String jti : List.of("grant-old", "grant-new")) {
            store.recordIssued(Map.of("iss", PS, "jti", jti, "exp", now + 600), List.of(RESOURCE), List.of(), agent);
        }
        List<String> sent = new ArrayList<>();
        RevocationManager manager = new RevocationManager(
                PS,
                "ps",
                store,
                (recipient, jti, exp) -> {
                    assertThat(store.isRevoked(AP, "agent-old")).isTrue();
                    assertThat(store.isRevoked(PS, jti)).isTrue();
                    sent.add(jti);
                    boolean firstNewAttempt = "grant-new".equals(jti)
                            && sent.stream().filter(jti::equals).count() == 1;
                    return firstNewAttempt ? Map.of("error", Revocations.REVOCATION_UNAVAILABLE) : Map.of();
                },
                Set.of(AP));

        assertThat(manager.revoke(AP, "agent-old", now + 600)).isEmpty();
        assertThat(manager.revoke(AP, "agent-old", now + 600)).isEmpty();

        // The confirmed recipient is not re-sent; the failed one is retried.
        assertThat(sent.stream().filter("grant-old"::equals).count()).isEqualTo(1);
        assertThat(sent.stream().filter("grant-new"::equals).count()).isEqualTo(2);
    }

    @Test
    void personRevocationCascadesAuthTokensAndReportsOutcomes() {
        RevocationStore store = new RevocationStore();
        store.recordIssued(
                Map.of("iss", AS, "jti", "auth", "exp", now + 600),
                List.of(RESOURCE),
                List.of(new RevocationStore.TokenKey(PS, "person")),
                null);
        RevocationManager manager = new RevocationManager(
                AS,
                "as",
                store,
                (recipient, jti, exp) -> Map.of("error", Revocations.REVOCATION_UNSUPPORTED),
                Set.of(PS));

        assertThat(manager.revoke(PS, "person", now + 600))
                .isEqualTo(Map.of(
                        "downstream",
                        List.of(Map.of("recipient", RESOURCE, "error", Revocations.REVOCATION_UNSUPPORTED))));
        assertThat(store.isRevoked(AS, "auth")).isTrue();
    }

    @Test
    void cascadeTreatsUnknownOutcomesAndFailuresAsUnavailable() {
        RevocationStore store = new RevocationStore();
        store.recordIssued(
                Map.of("iss", AS, "jti", "a1", "exp", now + 600),
                List.of(RESOURCE, "https://grafana.uma.lab"),
                List.of(new RevocationStore.TokenKey(PS, "person")),
                null);
        RevocationManager manager = new RevocationManager(
                AS,
                "as",
                store,
                (recipient, jti, exp) -> {
                    if (RESOURCE.equals(recipient)) {
                        throw new IllegalStateException("network down");
                    }
                    return Map.of("error", "something_else");
                },
                Set.of(PS));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> downstream = (List<Map<String, Object>>)
                manager.revoke(PS, "person", now + 600).get("downstream");
        assertThat(downstream).allSatisfy(entry -> assertThat(entry).containsEntry("error", "revocation_unavailable"));
    }

    @Test
    void revokeRejectsUnacceptedIssuersAndOverlongLifetimes() {
        RevocationManager manager =
                new RevocationManager(RESOURCE, "resource", new RevocationStore(), (r, j, e) -> Map.of(), Set.of(PS));
        assertThatThrownBy(() -> manager.revoke(AP, "jti", now + 600))
                .extracting(e -> ((TokenException) e).errorCode())
                .isEqualTo("unsupported_iss");
        assertThatThrownBy(() -> manager.revoke(PS, "jti", now + 2 * RevocationManager.DEFAULT_MAX_LIFETIME_SECONDS))
                .extracting(e -> ((TokenException) e).errorCode())
                .isEqualTo("invalid_request");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void revocationEndpointChecksBodyAndVerifiedIssuer(boolean tamper) {
        RevocationStore store = new RevocationStore();
        RevocationManager manager = new RevocationManager(
                RESOURCE,
                "resource",
                store,
                (r, j, e) -> {
                    throw new AssertionError("Nothing downstream");
                },
                Set.of(PS));
        Revocations.SignedRequest request =
                Revocations.signRequest(RESOURCE + "/revoke", "unknown", now + 600, psSigner);
        byte[] body = tamper
                ? new String(request.body(), StandardCharsets.UTF_8)
                        .replace("unknown", "another")
                        .getBytes(StandardCharsets.UTF_8)
                : request.body();

        AAuthResponse response = manager.handleRequest("POST", RESOURCE + "/revoke", request.headers(), body, fetch);

        assertThat(response.statusCode()).isEqualTo(tamper ? 401 : 200);
        assertThat(store.isRevoked(PS, "unknown")).isEqualTo(!tamper);
        if (!tamper) {
            assertThat(response.body()).isEmpty();
            assertThat(response.headers()).isEmpty();
        }
    }

    @Test
    void unacceptedRevocationIssuerIsForbidden() throws Exception {
        RevocationManager manager = new RevocationManager(
                RESOURCE,
                "resource",
                new RevocationStore(),
                (r, j, e) -> {
                    throw new AssertionError("Unauthorized cascade");
                },
                Set.of());
        Revocations.SignedRequest request = Revocations.signRequest(RESOURCE + "/revoke", "jti", now + 600, psSigner);

        AAuthResponse response =
                manager.handleRequest("POST", RESOURCE + "/revoke", request.headers(), request.body(), fetch);

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(MAPPER.readTree(response.body()).get("error").asText()).isEqualTo("unsupported_iss");
        assertThat(response.headers()).doesNotContainKey("Signature-Error");
    }

    @Test
    void endpointRejectsWrongSchemeAndMalformedBodies() throws Exception {
        RevocationManager manager =
                new RevocationManager(RESOURCE, "resource", new RevocationStore(), (r, j, e) -> Map.of(), Set.of(PS));
        Revocations.SignedRequest request = Revocations.signRequest(RESOURCE + "/revoke", "jti", now + 600, psSigner);

        AAuthResponse get =
                manager.handleRequest("GET", RESOURCE + "/revoke", request.headers(), request.body(), fetch);
        assertThat(get.statusCode()).isEqualTo(401);
        assertThat(get.getHeader("Signature-Error")).isEqualTo("error=unsupported_scheme");

        AAuthResponse unsigned = manager.handleRequest("POST", RESOURCE + "/revoke", Map.of(), request.body(), fetch);
        assertThat(unsigned.statusCode()).isEqualTo(401);

        // A correctly signed body with extra members is a 400 problem, not a revocation.
        Revocations.SignedRequest extra = signedRaw("{\"jti\":\"x\",\"exp\":" + (now + 600) + ",\"more\":1}");
        AAuthResponse bad = manager.handleRequest("POST", RESOURCE + "/revoke", extra.headers(), extra.body(), fetch);
        assertThat(bad.statusCode()).isEqualTo(400);
        assertThat(MAPPER.readTree(bad.body()).get("error").asText()).isEqualTo("invalid_request");
    }

    /** Signs an arbitrary JSON body the way {@link Revocations#signRequest} would. */
    private Revocations.SignedRequest signedRaw(String json) {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        Map<String, String> headers = new java.util.LinkedHashMap<>(Map.of("Content-Type", "application/json"));
        headers.putAll(io.github.marcofanti.aauth.signing.RequestSigner.sign(
                io.github.marcofanti.aauth.signing.SignRequest.builder("POST", RESOURCE + "/revoke")
                        .headers(headers)
                        .body(body)
                        .additionalComponents(List.of("content-digest", "content-type"))
                        .keyPair(issuerKeys)
                        .scheme(new io.github.marcofanti.aauth.signing.SignatureScheme.JwksUri(
                                PS, "aauth-person.json", "issuer-1"))
                        .build()));
        return new Revocations.SignedRequest(headers, body);
    }

    // --- Sending ---------------------------------------------------------------------------

    private static void respond(
            HttpExchange exchange, int status, String contentType, String body, Map<String, String> headers)
            throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        headers.forEach((k, v) -> exchange.getResponseHeaders().set(k, v));
        if (!contentType.isEmpty()) {
            exchange.getResponseHeaders().set("Content-Type", contentType);
        }
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        }
        exchange.close();
    }

    private String withServer(HttpServer server) {
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @Test
    void deferredRevocationUsesSameServerIdentityAndEmpty200() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        List<String> calls = new CopyOnWriteArrayList<>();
        server.createContext("/", exchange -> {
            SignatureKeyHeader.Parsed key =
                    SignatureKeyHeader.parse(exchange.getRequestHeaders().getFirst("Signature-Key"));
            calls.add(exchange.getRequestMethod() + " " + key.scheme() + " "
                    + key.params().get("id"));
            if ("POST".equals(exchange.getRequestMethod())) {
                respond(
                        exchange,
                        202,
                        "application/json",
                        "{\"status\":\"pending\"}",
                        Map.of("Location", "/pending/revoke", "Retry-After", "0"));
            } else {
                respond(exchange, 200, "", "", Map.of());
            }
        });
        try {
            String base = withServer(server);
            Map<String, Object> outcome =
                    Revocations.send(base + "/revoke", "jti", now + 600, psSigner, LOOPBACK, seconds -> {});

            assertThat(outcome).isEmpty();
            assertThat(calls).containsExactly("POST jwks_uri " + PS, "GET jwks_uri " + PS);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void sendMapsRecipientAnswersToOutcomes() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(
                "/unsupported", e -> respond(e, 403, "application/json", "{\"error\":\"unsupported_iss\"}", Map.of()));
        server.createContext("/broken", e -> respond(e, 500, "application/json", "{}", Map.of()));
        server.createContext("/text", e -> respond(e, 200, "text/plain", "ok", Map.of()));
        server.createContext(
                "/report",
                e -> respond(
                        e,
                        200,
                        "application/json",
                        "{\"downstream\":[{\"recipient\":\"https://gateway.uma.lab\"}]}",
                        Map.of()));
        server.createContext(
                "/bad-report",
                e -> respond(
                        e,
                        200,
                        "application/json",
                        "{\"downstream\":[{\"recipient\":\"x\",\"error\":\"weird\"}]}",
                        Map.of()));
        try {
            String base = withServer(server);
            assertThat(Revocations.send(base + "/unsupported", "j", now + 600, psSigner, LOOPBACK, null))
                    .containsEntry("error", Revocations.REVOCATION_UNSUPPORTED);
            assertThat(Revocations.send(base + "/broken", "j", now + 600, psSigner, LOOPBACK, null))
                    .containsEntry("error", Revocations.REVOCATION_UNAVAILABLE);
            assertThat(Revocations.send(base + "/text", "j", now + 600, psSigner, LOOPBACK, null))
                    .containsEntry("error", Revocations.REVOCATION_UNAVAILABLE);
            assertThat(Revocations.send(base + "/report", "j", now + 600, psSigner, LOOPBACK, null))
                    .containsKey("downstream");
            assertThat(Revocations.send(base + "/bad-report", "j", now + 600, psSigner, LOOPBACK, null))
                    .containsEntry("error", Revocations.REVOCATION_UNAVAILABLE);
            assertThat(Revocations.send(null, "j", now + 600, psSigner, null, null))
                    .containsEntry("error", Revocations.REVOCATION_UNSUPPORTED);
            assertThat(Revocations.send("http://127.0.0.1:1/closed", "j", now + 600, psSigner, LOOPBACK, null))
                    .containsEntry("error", Revocations.REVOCATION_UNAVAILABLE);
            // The library's default client admits only public HTTPS URLs, so it never reaches a loopback server.
            assertThat(Revocations.send(base + "/unsupported", "j", now + 600, psSigner, null, null))
                    .containsEntry("error", Revocations.REVOCATION_UNAVAILABLE);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void signRequestRequiresAServerIdentity() {
        Revocations.Signer badIssuer =
                new Revocations.Signer("http://ps.uma.lab:8765", issuerKeys, "k", "aauth-person.json");
        assertThatThrownBy(() -> Revocations.signRequest(RESOURCE + "/revoke", "jti", now + 600, badIssuer))
                .isInstanceOf(TokenException.class);
        assertThat(Revocations.body("jti", 5L)).isEqualTo(Map.of("jti", "jti", "exp", 5L));
    }
}
