package io.github.marcofanti.aauth.revocation;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.marcofanti.aauth.Identifiers;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.agent.Poller;
import io.github.marcofanti.aauth.http.Egress;
import io.github.marcofanti.aauth.signing.RequestSigner;
import io.github.marcofanti.aauth.signing.SignRequest;
import io.github.marcofanti.aauth.signing.SignatureScheme;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Signed revocation requests (draft-11 §11.12, mirrors the reference {@code revocation} module).
 * The request is {@code {jti, exp}}, POSTed under the issuer's own identity ({@code jwks_uri}
 * scheme) with {@code content-digest} and {@code content-type} covered.
 */
public final class Revocations {

    /** Outcome code: the recipient does not accept revocations from this issuer. */
    public static final String REVOCATION_UNSUPPORTED = "revocation_unsupported";

    /** Outcome code: the revocation could not be delivered or confirmed. */
    public static final String REVOCATION_UNAVAILABLE = "revocation_unavailable";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final List<String> BODY_COMPONENTS = List.of("content-digest", "content-type");

    private Revocations() {}

    /**
     * Builds the revocation body {@code {jti, exp}}.
     *
     * @throws TokenException {@code invalid_request} for an empty {@code jti}
     */
    public static Map<String, Object> body(String jti, long exp) {
        if (jti.isEmpty()) {
            throw new TokenException(
                    "Revocation requires nonempty jti and integer exp", null, "invalid_request", null, null);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("jti", jti);
        body.put("exp", exp);
        return body;
    }

    /** A signed revocation request: headers to send and the exact body bytes they cover. */
    // byte[] body is intentional: the signed request bytes; record equality is never used.
    @SuppressWarnings("ArrayRecordComponent")
    public record SignedRequest(Map<String, String> headers, byte[] body) {}

    /**
     * Who is revoking: the issuer's server identity and signing key.
     *
     * @param issuer the revoking server's identifier ({@code id} of the {@code jwks_uri} scheme)
     * @param keyPair its signing key pair
     * @param kid the signing key's ID in its JWKS
     * @param dwk its metadata document, e.g. {@code aauth-person.json}
     */
    public record Signer(String issuer, KeyPair keyPair, String kid, String dwk) {}

    /**
     * Signs a revocation request for {@code endpoint}.
     *
     * @throws TokenException if the issuer is not a server identifier or the body is invalid
     */
    public static SignedRequest signRequest(String endpoint, String jti, long exp, Signer signer) {
        try {
            Identifiers.validateServerIdentifier(signer.issuer());
        } catch (IllegalArgumentException e) {
            throw new TokenException("Invalid server identifier: " + signer.issuer(), null, "invalid_jwt", null, e);
        }
        byte[] body = json(body(jti, exp));
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.putAll(RequestSigner.sign(SignRequest.builder("POST", endpoint)
                .headers(headers)
                .body(body)
                .additionalComponents(BODY_COMPONENTS)
                .keyPair(signer.keyPair())
                .scheme(new SignatureScheme.JwksUri(signer.issuer(), signer.dwk(), signer.kid()))
                .build()));
        return new SignedRequest(headers, body);
    }

    /**
     * Sends a revocation and returns the recipient's outcome: {@code {}} when it is done, the
     * recipient's JSON report (e.g. an AS's {@code downstream} list), or
     * {@code {"error": "revocation_unsupported" | "revocation_unavailable"}}. A {@code 202} is
     * polled under the same server identity. Never throws.
     *
     * @param endpoint the recipient's {@code revocation_endpoint}, or {@code null} when it has none
     * @param httpClient HTTP client, or {@code null} for an HTTP/1.1 default that admits only
     *     public HTTPS URLs ({@link Egress#admitPublicUrl}), including the polling URL
     * @param sleeper poll sleep implementation, or {@code null} for real sleeping
     */
    public static Map<String, Object> send(
            @Nullable String endpoint,
            String jti,
            long exp,
            Signer signer,
            @Nullable HttpClient httpClient,
            Poller.@Nullable Sleeper sleeper) {
        if (endpoint == null || endpoint.isEmpty()) {
            return Map.of("error", REVOCATION_UNSUPPORTED);
        }
        Outbound client = httpClient != null ? new Outbound(httpClient, false) : new Outbound(defaultClient(), true);
        try {
            SignedRequest request = signRequest(endpoint, jti, exp, signer);
            HttpResponse<String> response =
                    client.send(withHeaders(HttpRequest.newBuilder(URI.create(endpoint)), request.headers())
                            .POST(HttpRequest.BodyPublishers.ofByteArray(request.body()))
                            .build());
            if (response.statusCode() == 202) {
                return pollOutcome(endpoint, response, signer, client, sleeper);
            }
            return outcome(response.statusCode(), response.body(), contentType(response));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Map.of("error", REVOCATION_UNAVAILABLE);
        } catch (IOException | RuntimeException e) {
            return Map.of("error", REVOCATION_UNAVAILABLE);
        }
    }

    private static Map<String, Object> pollOutcome(
            String endpoint,
            HttpResponse<String> accepted,
            Signer signer,
            Outbound client,
            Poller.@Nullable Sleeper sleeper) {
        String location = accepted.headers().firstValue("location").orElse(null);
        if (location == null) {
            return Map.of("error", REVOCATION_UNAVAILABLE);
        }
        String pendingUrl = URI.create(endpoint).resolve(location).toString();
        Poller.PollingResult result = Poller.poll(Poller.Request.builder(pendingUrl, url -> {
                    Map<String, String> headers = RequestSigner.sign(SignRequest.builder("GET", url)
                            .keyPair(signer.keyPair())
                            .scheme(new SignatureScheme.JwksUri(signer.issuer(), signer.dwk(), signer.kid()))
                            .build());
                    HttpResponse<String> polled =
                            client.send(withHeaders(HttpRequest.newBuilder(URI.create(url)), headers)
                                    .GET()
                                    .build());
                    return new Poller.PollResponse(
                            polled.statusCode(),
                            parse(polled.body()),
                            Map.of(
                                    "retry-after",
                                    polled.headers().firstValue("retry-after").orElse("")));
                })
                .sleeper(sleeper)
                .build());
        if (!result.success()) {
            return Map.of("error", REVOCATION_UNAVAILABLE);
        }
        return validReport(result.responseBody());
    }

    /** Interprets a terminal response the way the reference does. */
    static Map<String, Object> outcome(int status, @Nullable String body, String contentType) {
        Map<String, Object> parsed = parse(body);
        if (status == 403 && "unsupported_iss".equals(parsed.get("error"))) {
            return Map.of("error", REVOCATION_UNSUPPORTED);
        }
        if (status != 200) {
            return Map.of("error", REVOCATION_UNAVAILABLE);
        }
        if (body == null || body.isEmpty()) {
            return Map.of();
        }
        if (!"application/json".equals(contentType)) {
            return Map.of("error", REVOCATION_UNAVAILABLE);
        }
        return validReport(parsed);
    }

    /** A {@code downstream} report must list recipients with only known outcome codes. */
    private static Map<String, Object> validReport(Map<String, Object> report) {
        Object downstream = report.get("downstream");
        if (downstream == null) {
            return report;
        }
        if (!(downstream instanceof List<?> entries)) {
            return Map.of("error", REVOCATION_UNAVAILABLE);
        }
        for (Object entry : entries) {
            if (!(entry instanceof Map<?, ?> item)
                    || !(item.get("recipient") instanceof String)
                    || !isOutcomeCode(item.get("error"))) {
                return Map.of("error", REVOCATION_UNAVAILABLE);
            }
        }
        return report;
    }

    static boolean isOutcomeCode(@Nullable Object error) {
        return error == null || REVOCATION_UNSUPPORTED.equals(error) || REVOCATION_UNAVAILABLE.equals(error);
    }

    private static String contentType(HttpResponse<?> response) {
        String value = response.headers().firstValue("content-type").orElse("");
        int semicolon = value.indexOf(';');
        return (semicolon >= 0 ? value.substring(0, semicolon) : value).strip();
    }

    private static Map<String, Object> parse(@Nullable String body) {
        if (body == null || body.isBlank()) {
            return Map.of();
        }
        try {
            return MAPPER.readValue(body, MAP_TYPE);
        } catch (IOException e) {
            return Map.of();
        }
    }

    static byte[] json(Map<String, Object> value) {
        try {
            return MAPPER.writeValueAsString(value).getBytes(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to serialize revocation body", e);
        }
    }

    private static HttpRequest.Builder withHeaders(HttpRequest.Builder builder, Map<String, String> headers) {
        builder.timeout(Duration.ofSeconds(30));
        headers.forEach(builder::header);
        return builder;
    }

    /** An HTTP client plus whether the library's egress admission applies to it. */
    private record Outbound(HttpClient client, boolean admit) {
        HttpResponse<String> send(HttpRequest request) throws IOException, InterruptedException {
            if (admit) {
                Egress.admitPublicUrl(request.uri().toString());
            }
            return client.send(request, HttpResponse.BodyHandlers.ofString());
        }
    }

    private static HttpClient defaultClient() {
        return HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(30))
                .build();
    }
}
