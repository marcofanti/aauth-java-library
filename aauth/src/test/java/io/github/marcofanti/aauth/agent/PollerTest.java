package io.github.marcofanti.aauth.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.TokenException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** The deferred-response state machine (mirrors the reference test_poller). */
class PollerTest {

    private static final String PENDING_URL = "https://ps.uma.lab/pending/1";

    private final List<Long> sleeps = new ArrayList<>();

    private static Poller.PollResponse response(int status, Map<String, Object> body, Map<String, String> headers) {
        return new Poller.PollResponse(status, body, headers);
    }

    private static Poller.PollResponse response(int status, Map<String, Object> body) {
        return response(status, body, Map.of("Retry-After", "0"));
    }

    private Poller.Request.Builder sequence(Deque<Poller.PollResponse> responses, List<String> urls) {
        return Poller.Request.builder(PENDING_URL, url -> {
                    urls.add(url);
                    return responses.removeFirst();
                })
                .sleeper(sleeps::add);
    }

    private Poller.Request.Builder sequence(Poller.PollResponse... responses) {
        return sequence(new ArrayDeque<>(List.of(responses)), new ArrayList<>());
    }

    // --- Terminal responses ----------------------------------------------------------------

    @Test
    void okReturnsSuccessWithTheAuthToken() {
        List<String> urls = new ArrayList<>();
        Poller.PollingResult result =
                Poller.poll(sequence(new ArrayDeque<>(List.of(response(200, Map.of("auth_token", "tok123")))), urls)
                        .build());

        assertThat(result.success()).isTrue();
        assertThat(result.authToken()).isEqualTo("tok123");
        assertThat(result.statusCode()).isEqualTo(200);
        assertThat(result.response()).isNotNull();
        assertThat(urls).containsExactly(PENDING_URL);
    }

    @Test
    void anyTwoOrThreeHundredIsSuccess() {
        assertThat(Poller.poll(sequence(response(201, Map.of())).build()).success())
                .isTrue();
        assertThat(Poller.poll(sequence(response(301, Map.of())).build()).success())
                .isTrue();
    }

    @Test
    void terminalErrorsUseTheBodyOrDefaultCodes() {
        Poller.PollingResult denied =
                Poller.poll(sequence(response(403, Map.of("error", "denied", "error_description", "User rejected")))
                        .build());
        assertThat(denied.success()).isFalse();
        assertThat(denied.error()).isEqualTo("denied");
        assertThat(denied.errorDescription()).isEqualTo("User rejected");
        assertThat(denied.statusCode()).isEqualTo(403);

        Map<Integer, String> defaults = Map.of(
                403, "denied", 408, "expired", 410, "invalid_code", 500, "server_error", 418, "unexpected_status");
        defaults.forEach((status, error) -> assertThat(
                        Poller.poll(sequence(response(status, Map.of())).build())
                                .error())
                .isEqualTo(error));
        assertThat(Poller.poll(sequence(response(403, Map.of("error", "revoked", "detail", "agent token revoked")))
                                .build())
                        .errorDescription())
                .isEqualTo("agent token revoked");
    }

    // --- Pending ---------------------------------------------------------------------------

    @Test
    void pendingThenSuccess() {
        List<String> urls = new ArrayList<>();
        Poller.PollingResult result = Poller.poll(sequence(
                        new ArrayDeque<>(List.of(
                                response(202, Map.of("status", "pending"), Map.of("Retry-After", "3")),
                                response(200, Map.of("auth_token", "tok_final")))),
                        urls)
                .build());

        assertThat(result.authToken()).isEqualTo("tok_final");
        assertThat(urls).hasSize(2);
        assertThat(sleeps).containsExactly(3L);
    }

    @Test
    void initialResponseIsProcessedBeforeTheFirstGet() {
        List<String> urls = new ArrayList<>();
        Poller.PollingResult result =
                Poller.poll(sequence(new ArrayDeque<>(List.of(response(200, Map.of("auth_token", "tok")))), urls)
                        .initialResponse(response(202, Map.of("status", "pending")))
                        .build());

        assertThat(result.success()).isTrue();
        assertThat(urls).containsExactly(PENDING_URL);
    }

    @Test
    void maxPollsExceeded() {
        AtomicInteger gets = new AtomicInteger();
        Poller.PollingResult result = Poller.poll(Poller.Request.builder(PENDING_URL, url -> {
                    gets.incrementAndGet();
                    return response(202, Map.of("status", "pending"));
                })
                .maxPolls(3)
                .sleeper(sleeps::add)
                .build());

        assertThat(result.success()).isFalse();
        assertThat(result.error()).isEqualTo("max_polls_exceeded");
        assertThat(gets.get()).isEqualTo(3);
    }

    @Test
    void newLocationReplacesThePendingUrlOnTheSameOriginOnly() {
        List<String> urls = new ArrayList<>();
        Poller.PollingResult moved = Poller.poll(sequence(
                        new ArrayDeque<>(List.of(
                                response(202, Map.of(), Map.of("Location", "/pending/2", "Retry-After", "0")),
                                response(200, Map.of()))),
                        urls)
                .build());
        assertThat(moved.success()).isTrue();
        assertThat(urls).containsExactly(PENDING_URL, "https://ps.uma.lab/pending/2");

        Poller.PollingResult foreign =
                Poller.poll(sequence(response(202, Map.of(), Map.of("Location", "https://evil.uma.lab/x")))
                        .build());
        assertThat(foreign.success()).isFalse();
        assertThat(foreign.error()).isEqualTo("invalid_response");
    }

    @Test
    void pendingLocationStaysOnOrigin() {
        assertThat(Poller.pendingLocation("/pending/1", "https://ps.uma.lab/token"))
                .isEqualTo("https://ps.uma.lab/pending/1");
        assertThat(Poller.pendingLocation("https://ps.uma.lab:443/p", "https://ps.uma.lab/token"))
                .isEqualTo("https://ps.uma.lab:443/p");
        for (String bad : List.of(
                "https://evil.uma.lab/p",
                "https://ps.uma.lab:8443/p",
                "http://ps.uma.lab/p",
                "https://user@ps.uma.lab/p",
                "/p#frag")) {
            assertThatThrownBy(() -> Poller.pendingLocation(bad, "https://ps.uma.lab/token"))
                    .as(bad)
                    .isInstanceOf(TokenException.class);
        }
        assertThatThrownBy(() -> Poller.pendingLocation(null, "https://ps.uma.lab/token"))
                .hasMessageContaining("no Location");
    }

    // --- Interaction -----------------------------------------------------------------------

    @Test
    void interactionIsPromptedOnceAndNotWhileInteracting() {
        List<List<String>> prompts = new ArrayList<>();
        Poller.PollingResult result = Poller.poll(sequence(
                        response(202, Map.of("status", "pending", "requirement", "interaction", "code", "ABCD1234")),
                        response(
                                202, Map.of("status", "interacting", "requirement", "interaction", "code", "ABCD1234")),
                        response(202, Map.of("status", "pending", "requirement", "interaction", "code", "ABCD1234")),
                        response(200, Map.of("auth_token", "tok")))
                .onInteraction((url, code) -> prompts.add(List.of(url, code)))
                .build());

        assertThat(result.success()).isTrue();
        assertThat(prompts).containsExactly(List.of(PENDING_URL, "ABCD1234"));
    }

    @Test
    void lateInteractionIsPromptedOnceWithTheHeaderUrl() {
        List<List<String>> prompts = new ArrayList<>();
        Map<String, String> header = Map.of(
                "AAuth-Requirement",
                "requirement=interaction; url=\"https://ps.uma.lab/interaction\"; code=\"LATE99\"",
                "Retry-After",
                "0");
        Poller.PollingResult result = Poller.poll(sequence(
                        response(202, Map.of("status", "pending")),
                        response(202, Map.of("status", "pending"), header),
                        response(202, Map.of("status", "pending"), header),
                        response(200, Map.of("auth_token", "tok")))
                .onInteraction((url, code) -> prompts.add(List.of(url, code)))
                .build());

        assertThat(result.success()).isTrue();
        assertThat(prompts).containsExactly(List.of("https://ps.uma.lab/interaction?code=LATE99", "LATE99"));
    }

    @Test
    void invalidInteractionUrlEndsPolling() {
        Map<String, String> header =
                Map.of("AAuth-Requirement", "requirement=interaction; url=\"http://ps.uma.lab/i\"; code=\"C1\"");
        Poller.PollingResult result = Poller.poll(sequence(response(202, Map.of(), header))
                .onInteraction((url, code) -> {})
                .build());

        assertThat(result.success()).isFalse();
        assertThat(result.error()).isEqualTo("invalid_response");
    }

    // --- Clarification ---------------------------------------------------------------------

    @Test
    void clarificationAnswerIsPosted() {
        List<Map<String, Object>> posts = new ArrayList<>();
        List<String> questions = new ArrayList<>();
        Poller.PollingResult result = Poller.poll(sequence(
                        response(202, Map.of("requirement", "clarification", "clarification", "Do you approve?")),
                        response(200, Map.of("auth_token", "tok_clarified")))
                .onClarification((url, question) -> {
                    questions.add(question);
                    return "yes";
                })
                .signedPost((url, body) -> {
                    posts.add(body);
                    return response(202, Map.of("status", "pending"));
                })
                .build());

        assertThat(result.authToken()).isEqualTo("tok_clarified");
        assertThat(questions).containsExactly("Do you approve?");
        assertThat(posts).containsExactly(Map.of("action", "clarification_response", "clarification_response", "yes"));
    }

    @Test
    void nullClarificationAnswerSkipsThePost() {
        AtomicInteger posts = new AtomicInteger();
        Poller.PollingResult result = Poller.poll(sequence(
                        response(202, Map.of("requirement", "clarification", "clarification", "Approve?")),
                        response(200, Map.of("auth_token", "tok")))
                .onClarification((url, question) -> null)
                .signedPost((url, body) -> {
                    posts.incrementAndGet();
                    return response(200, Map.of());
                })
                .build());

        assertThat(result.success()).isTrue();
        assertThat(posts.get()).isZero();
    }

    @Test
    void repeatedClarificationPostsObeyTheRequestLimit() {
        Poller.PollResponse pending = response(
                202,
                Map.of("clarification", "Approve?"),
                Map.of("AAuth-Requirement", "requirement=clarification", "Retry-After", "0"));
        AtomicInteger gets = new AtomicInteger();
        AtomicInteger posts = new AtomicInteger();
        Poller.PollingResult result = Poller.poll(Poller.Request.builder(PENDING_URL, url -> {
                    gets.incrementAndGet();
                    return pending;
                })
                .maxPolls(2)
                .initialResponse(pending)
                .onClarification((url, question) -> "yes")
                .signedPost((url, body) -> {
                    posts.incrementAndGet();
                    return pending;
                })
                .sleeper(sleeps::add)
                .build());

        assertThat(result.success()).isFalse();
        assertThat(result.error()).isEqualTo("max_polls_exceeded");
        assertThat(posts.get()).isEqualTo(2);
        assertThat(gets.get()).isZero();
    }

    // --- Rate limiting and failures --------------------------------------------------------

    @Test
    void slowDownIncreasesTheWait() {
        Poller.PollingResult result = Poller.poll(sequence(
                        response(429, Map.of(), Map.of("Retry-After", "0")), response(200, Map.of("auth_token", "tok")))
                .build());

        assertThat(result.success()).isTrue();
        assertThat(sleeps).containsExactly(10L); // default 5 + 5
    }

    @Test
    void serviceUnavailableHonorsRetryAfter() {
        Poller.PollingResult result = Poller.poll(sequence(
                        response(503, Map.of(), Map.of("Retry-After", "9")), response(200, Map.of("auth_token", "tok")))
                .build());

        assertThat(result.success()).isTrue();
        assertThat(sleeps).containsExactly(9L);
    }

    @Test
    void networkErrorEndsPolling() {
        Poller.PollingResult result = Poller.poll(Poller.Request.builder(PENDING_URL, url -> {
                    throw new java.io.IOException("connection timeout");
                })
                .build());

        assertThat(result.success()).isFalse();
        assertThat(result.error()).isEqualTo("network_error");
        assertThat(result.errorDescription()).contains("timeout");
    }

    @Test
    void interruptedSleepEndsPolling() {
        Poller.PollingResult result =
                Poller.poll(Poller.Request.builder(PENDING_URL, url -> response(202, Map.of(), Map.of()))
                        .sleeper(seconds -> {
                            throw new InterruptedException();
                        })
                        .build());

        assertThat(result.error()).isEqualTo("network_error");
        assertThat(Thread.interrupted()).isTrue();
    }

    @Test
    void pollAsyncAndCancelDelegate() throws Exception {
        Poller.PollingResult result = Poller.pollAsync(
                        sequence(response(200, Map.of("auth_token", "tok"))).build(), Runnable::run)
                .get();
        assertThat(result.authToken()).isEqualTo("tok");
        assertThat(Poller.cancelPendingRequest(url -> response(204, Map.of()), PENDING_URL)
                        .statusCode())
                .isEqualTo(204);
    }
}
