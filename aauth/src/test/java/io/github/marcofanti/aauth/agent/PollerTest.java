package io.github.marcofanti.aauth.agent;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class PollerTest {

    private static final String PENDING_URL = "https://ps.uma.lab/pending/1";

    /** Serves a scripted sequence of responses. */
    private static Poller.SignedGet script(Deque<Poller.PollResponse> responses) {
        return url -> responses.pop();
    }

    private static Poller.Request.Builder request(Deque<Poller.PollResponse> responses, List<Long> sleeps) {
        return Poller.Request.builder(PENDING_URL, script(responses)).sleeper(sleeps::add);
    }

    @Test
    void immediateSuccessReturnsAuthToken() {
        Deque<Poller.PollResponse> responses =
                new ArrayDeque<>(List.of(new Poller.PollResponse(200, Map.of("auth_token", "tok"), Map.of())));

        Poller.PollingResult result =
                Poller.poll(request(responses, new ArrayList<>()).build());

        assertThat(result.success()).isTrue();
        assertThat(result.authToken()).isEqualTo("tok");
        assertThat(result.statusCode()).isEqualTo(200);
    }

    @Test
    void pendingThenSuccessSleepsBetweenPolls() {
        Deque<Poller.PollResponse> responses = new ArrayDeque<>(List.of(
                new Poller.PollResponse(202, Map.of("status", "pending"), Map.of("Retry-After", "1")),
                new Poller.PollResponse(200, Map.of("auth_token", "tok"), Map.of())));
        List<Long> sleeps = new ArrayList<>();

        Poller.PollingResult result = Poller.poll(request(responses, sleeps).build());

        assertThat(result.success()).isTrue();
        assertThat(sleeps).containsExactly(1L);
    }

    @Test
    void deniedIsTerminal() {
        Deque<Poller.PollResponse> responses = new ArrayDeque<>(List.of(new Poller.PollResponse(
                403, Map.of("error", "denied", "error_description", "user said no"), Map.of())));

        Poller.PollingResult result =
                Poller.poll(request(responses, new ArrayList<>()).build());

        assertThat(result.success()).isFalse();
        assertThat(result.error()).isEqualTo("denied");
        assertThat(result.errorDescription()).isEqualTo("user said no");
    }

    @Test
    void terminalStatusesUseDefaultErrorCodes() {
        for (Map.Entry<Integer, String> entry : Map.of(
                        403, "denied", 408, "expired", 410, "invalid_code", 500, "server_error")
                .entrySet()) {
            Deque<Poller.PollResponse> responses =
                    new ArrayDeque<>(List.of(new Poller.PollResponse(entry.getKey(), Map.of(), Map.of())));
            Poller.PollingResult result =
                    Poller.poll(request(responses, new ArrayList<>()).build());
            assertThat(result.error()).isEqualTo(entry.getValue());
            assertThat(result.statusCode()).isEqualTo(entry.getKey());
        }
    }

    @Test
    void slowDownIncreasesInterval() {
        Deque<Poller.PollResponse> responses = new ArrayDeque<>(List.of(
                new Poller.PollResponse(429, Map.of(), Map.of()),
                new Poller.PollResponse(200, Map.of("auth_token", "tok"), Map.of())));
        List<Long> sleeps = new ArrayList<>();

        Poller.PollingResult result = Poller.poll(request(responses, sleeps).build());

        assertThat(result.success()).isTrue();
        // default 2 + 5 per spec.
        assertThat(sleeps).containsExactly(7L);
    }

    @Test
    void interactionCallbackFiresOnceWithUrlFromHeader() {
        AtomicReference<String> seenUrl = new AtomicReference<>();
        AtomicReference<String> seenCode = new AtomicReference<>();
        Deque<Poller.PollResponse> responses = new ArrayDeque<>(List.of(
                new Poller.PollResponse(
                        202,
                        Map.of("status", "pending", "requirement", "interaction", "code", "ABCD1234"),
                        Map.of(
                                "AAuth-Requirement",
                                "requirement=interaction; url=\"https://ps.uma.lab/interact\"; code=\"ABCD1234\"",
                                "Retry-After",
                                "0")),
                new Poller.PollResponse(200, Map.of("auth_token", "tok"), Map.of())));

        Poller.PollingResult result = Poller.poll(request(responses, new ArrayList<>())
                .onInteraction((url, code) -> {
                    seenUrl.set(url);
                    seenCode.set(code);
                })
                .build());

        assertThat(result.success()).isTrue();
        assertThat(seenUrl.get()).isEqualTo("https://ps.uma.lab/interact?code=ABCD1234");
        assertThat(seenCode.get()).isEqualTo("ABCD1234");
    }

    @Test
    void clarificationAnswerIsPostedBack() {
        List<Map<String, Object>> posted = new ArrayList<>();
        Deque<Poller.PollResponse> responses = new ArrayDeque<>(List.of(
                new Poller.PollResponse(
                        202,
                        Map.of("status", "pending", "clarification", "Which account?"),
                        Map.of("AAuth-Requirement", "requirement=clarification", "Retry-After", "0")),
                new Poller.PollResponse(200, Map.of("auth_token", "tok"), Map.of())));

        Poller.PollingResult result = Poller.poll(request(responses, new ArrayList<>())
                .onClarification((url, question) -> {
                    assertThat(question).isEqualTo("Which account?");
                    return "Checking";
                })
                .signedPost((url, body) -> {
                    posted.add(body);
                    return new Poller.PollResponse(200, Map.of(), Map.of());
                })
                .build());

        assertThat(result.success()).isTrue();
        assertThat(posted).containsExactly(Map.of("clarification_response", "Checking"));
    }

    @Test
    void emptyCodeOrClarificationDoesNotFireCallbacks() {
        // Regression: falsy-but-present values must not trigger user-facing callbacks.
        Deque<Poller.PollResponse> responses = new ArrayDeque<>(List.of(
                new Poller.PollResponse(
                        202,
                        Map.of("status", "pending", "requirement", "interaction", "code", "", "clarification", ""),
                        Map.of("Retry-After", "0")),
                new Poller.PollResponse(200, Map.of("auth_token", "tok"), Map.of())));

        Poller.PollingResult result = Poller.poll(request(responses, new ArrayList<>())
                .onInteraction((url, code) -> {
                    throw new AssertionError("onInteraction must not fire for empty code");
                })
                .onClarification((url, question) -> {
                    throw new AssertionError("onClarification must not fire for empty question");
                })
                .signedPost((url, body) -> {
                    throw new AssertionError("no clarification POST expected");
                })
                .build());

        assertThat(result.success()).isTrue();
    }

    @Test
    void unexpectedStatusIsTerminal() {
        Deque<Poller.PollResponse> responses =
                new ArrayDeque<>(List.of(new Poller.PollResponse(301, Map.of(), Map.of())));

        Poller.PollingResult result =
                Poller.poll(request(responses, new ArrayList<>()).build());

        assertThat(result.success()).isFalse();
        assertThat(result.error()).isEqualTo("unexpected_status");
    }

    @Test
    void networkErrorIsTerminal() {
        Poller.PollingResult result = Poller.poll(Poller.Request.builder(PENDING_URL, url -> {
                    throw new java.io.IOException("connection refused");
                })
                .sleeper(seconds -> {})
                .build());

        assertThat(result.success()).isFalse();
        assertThat(result.error()).isEqualTo("network_error");
        assertThat(result.errorDescription()).contains("connection refused");
    }

    @Test
    void maxPollsExhaustionFails() {
        Poller.PollingResult result = Poller.poll(Poller.Request.builder(
                        PENDING_URL, url -> new Poller.PollResponse(202, Map.of("status", "pending"), Map.of()))
                .maxPolls(3)
                .sleeper(seconds -> {})
                .build());

        assertThat(result.success()).isFalse();
        assertThat(result.error()).isEqualTo("max_polls_exceeded");
    }

    @Test
    void serviceUnavailableRetriesThenSucceeds() {
        Deque<Poller.PollResponse> responses = new ArrayDeque<>(List.of(
                new Poller.PollResponse(503, Map.of(), Map.of("Retry-After", "9")),
                new Poller.PollResponse(200, Map.of("auth_token", "tok"), Map.of())));
        List<Long> sleeps = new ArrayList<>();

        Poller.PollingResult result = Poller.poll(request(responses, sleeps).build());

        assertThat(result.success()).isTrue();
        assertThat(sleeps).containsExactly(9L);
    }

    @Test
    void extractInteractionUrlFallsBackToPendingUrl() {
        assertThat(Poller.extractInteractionUrl(null, "C", PENDING_URL)).isEqualTo(PENDING_URL);
        assertThat(Poller.extractInteractionUrl("requirement=approval", "C", PENDING_URL))
                .isEqualTo(PENDING_URL);
        assertThat(Poller.extractInteractionUrl(
                        "requirement=interaction; url=\"https://keycloak.uma.lab/i?a=1\"; code=\"C\"",
                        "C",
                        PENDING_URL))
                .isEqualTo("https://keycloak.uma.lab/i?a=1&code=C");
    }
}
