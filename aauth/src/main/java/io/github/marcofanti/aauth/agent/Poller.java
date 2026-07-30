package io.github.marcofanti.aauth.agent;

import io.github.marcofanti.aauth.headers.AAuthHeaders;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Polling state machine for deferred responses per AAuth spec §10.6.
 *
 * <p>The agent polls the pending URL with signed GETs until a terminal response. Terminal:
 * 200 (success), 403 (denied/abandoned), 408 (expired), 410 (invalid code), 500. Transient:
 * 202 (pending/interacting), 429 (slow down — interval grows by 5s), 503.
 */
public final class Poller {

    private static final Logger LOGGER = Logger.getLogger(Poller.class.getName());

    private Poller() {}

    /** A minimal HTTP response view the poller understands. */
    public record PollResponse(int statusCode, Map<String, Object> body, Map<String, String> headers) {
        public PollResponse {
            body = body == null ? Map.of() : body;
            headers = headers == null ? Map.of() : headers;
        }
    }

    /** Sends a signed GET to a URL. */
    @FunctionalInterface
    public interface SignedGet {
        PollResponse get(String url) throws Exception;
    }

    /** Sends a signed POST with a JSON body to a URL. */
    @FunctionalInterface
    public interface SignedPost {
        PollResponse post(String url, Map<String, Object> body) throws Exception;
    }

    /** Outcome of polling a pending URL. */
    public record PollingResult(
            boolean success,
            String authToken,
            Map<String, Object> responseBody,
            int statusCode,
            String error,
            String errorDescription) {}

    /**
     * Parameters for {@link #poll(Request)}.
     *
     * @param pendingUrl the Location URL from the 202 response
     * @param signedGet sends a signed GET and returns the response
     * @param maxPolls maximum poll attempts (default 60)
     * @param defaultWaitSeconds base seconds between polls (default 2)
     * @param onInteraction invoked once with (interactionUrl, code) when
     *     {@code requirement=interaction} arrives on the first poll
     * @param onClarification invoked with (pendingUrl, question); returns the user's answer or
     *     {@code null} to skip
     * @param signedPost sends the clarification answer; required for clarification handling
     * @param sleeper sleep implementation in seconds (injectable for tests)
     */
    public record Request(
            String pendingUrl,
            SignedGet signedGet,
            int maxPolls,
            int defaultWaitSeconds,
            BiConsumer<String, String> onInteraction,
            BiFunction<String, String, String> onClarification,
            SignedPost signedPost,
            Sleeper sleeper) {

        public Request {
            if (pendingUrl == null || signedGet == null) {
                throw new IllegalArgumentException("pendingUrl and signedGet are required");
            }
            maxPolls = maxPolls <= 0 ? 60 : maxPolls;
            defaultWaitSeconds = defaultWaitSeconds <= 0 ? 2 : defaultWaitSeconds;
            sleeper = sleeper == null ? Poller::sleepSeconds : sleeper;
        }

        public static Builder builder(String pendingUrl, SignedGet signedGet) {
            return new Builder(pendingUrl, signedGet);
        }

        /** Builder for {@link Request}. */
        public static final class Builder {
            private final String pendingUrl;
            private final SignedGet signedGet;
            private int maxPolls = 60;
            private int defaultWaitSeconds = 2;
            private BiConsumer<String, String> onInteraction;
            private BiFunction<String, String, String> onClarification;
            private SignedPost signedPost;
            private Sleeper sleeper;

            private Builder(String pendingUrl, SignedGet signedGet) {
                this.pendingUrl = pendingUrl;
                this.signedGet = signedGet;
            }

            public Builder maxPolls(int maxPolls) {
                this.maxPolls = maxPolls;
                return this;
            }

            public Builder defaultWaitSeconds(int defaultWaitSeconds) {
                this.defaultWaitSeconds = defaultWaitSeconds;
                return this;
            }

            public Builder onInteraction(BiConsumer<String, String> onInteraction) {
                this.onInteraction = onInteraction;
                return this;
            }

            public Builder onClarification(BiFunction<String, String, String> onClarification) {
                this.onClarification = onClarification;
                return this;
            }

            public Builder signedPost(SignedPost signedPost) {
                this.signedPost = signedPost;
                return this;
            }

            public Builder sleeper(Sleeper sleeper) {
                this.sleeper = sleeper;
                return this;
            }

            public Request build() {
                return new Request(
                        pendingUrl,
                        signedGet,
                        maxPolls,
                        defaultWaitSeconds,
                        onInteraction,
                        onClarification,
                        signedPost,
                        sleeper);
            }
        }
    }

    /** Sleep abstraction (seconds); injectable so tests run instantly. */
    @FunctionalInterface
    public interface Sleeper {
        void sleep(long seconds) throws InterruptedException;
    }

    /** Polls a pending URL until a terminal response, per the spec §10.6 state machine. */
    public static PollingResult poll(Request request) {
        int wait = request.defaultWaitSeconds();

        for (int attempt = 0; attempt < request.maxPolls(); attempt++) {
            PollResponse response;
            try {
                response = request.signedGet().get(request.pendingUrl());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return failure(0, null, "network_error", "Interrupted while polling");
            } catch (Exception e) {
                LOGGER.log(Level.FINE, "Poll request failed", e);
                return failure(0, null, "network_error", String.valueOf(e.getMessage()));
            }

            int status = response.statusCode();
            Map<String, Object> body = response.body();

            switch (status) {
                case 200 -> {
                    Object authToken = body.get("auth_token");
                    return new PollingResult(
                            true, authToken == null ? null : authToken.toString(), body, 200, null, null);
                }
                case 403 -> {
                    return failure(403, body, errorOr(body, "denied"), description(body));
                }
                case 408 -> {
                    return failure(408, body, errorOr(body, "expired"), description(body));
                }
                case 410 -> {
                    return failure(410, body, errorOr(body, "invalid_code"), description(body));
                }
                case 500 -> {
                    return failure(500, body, errorOr(body, "server_error"), description(body));
                }
                case 429 -> {
                    // Per spec: increase the interval by 5 seconds on slow_down.
                    wait += 5;
                    long retryAfter = Math.max(retryAfterSeconds(response, wait), wait);
                    if (!trySleep(request, retryAfter)) {
                        return failure(429, body, "network_error", "Interrupted while polling");
                    }
                }
                case 202 -> {
                    if (!handlePending(request, response, attempt)) {
                        return failure(202, body, "network_error", "Interrupted while polling");
                    }
                }
                case 503 -> {
                    long retryAfter = Math.max(retryAfterSeconds(response, wait * 2L), 1);
                    if (!trySleep(request, retryAfter)) {
                        return failure(503, body, "network_error", "Interrupted while polling");
                    }
                }
                default -> {
                    LOGGER.warning("Unexpected status code " + status + " during polling");
                    return failure(status, body, "unexpected_status", "Unexpected HTTP status " + status);
                }
            }
        }

        return failure(0, null, "max_polls_exceeded", "Exceeded maximum " + request.maxPolls() + " poll attempts");
    }

    /** Runs {@link #poll(Request)} on the given executor. */
    public static CompletableFuture<PollingResult> pollAsync(Request request, Executor executor) {
        return CompletableFuture.supplyAsync(() -> poll(request), executor);
    }

    /** Sends a signed DELETE to a pending URL to cancel the request (spec §11.4.3). */
    public static PollResponse cancelPendingRequest(SignedGet signedDelete, String pendingUrl) throws Exception {
        return signedDelete.get(pendingUrl);
    }

    // --- Internals ---------------------------------------------------------------------------

    /** Handles a 202 body: interaction callback, clarification round-trip, retry wait. */
    private static boolean handlePending(Request request, PollResponse response, int attempt) {
        Map<String, Object> body = response.body();
        String require = firstNonNull(str(body.get("requirement")), str(body.get("require")));
        String code = str(body.get("code"));
        String aauthRequirementHeader = header(response, "aauth-requirement");
        if (require == null
                && aauthRequirementHeader != null
                && aauthRequirementHeader.contains("requirement=clarification")) {
            require = "clarification";
        }
        String clarification = str(body.get("clarification"));

        if ("interaction".equals(require) && code != null && request.onInteraction() != null && attempt == 0) {
            request.onInteraction()
                    .accept(extractInteractionUrl(aauthRequirementHeader, code, request.pendingUrl()), code);
        }

        if (clarification != null && request.onClarification() != null && request.signedPost() != null) {
            String answer = request.onClarification().apply(request.pendingUrl(), clarification);
            if (answer != null && !answer.isEmpty()) {
                try {
                    request.signedPost().post(request.pendingUrl(), Map.of("clarification_response", answer));
                } catch (Exception e) {
                    LOGGER.warning("Failed to send clarification response: " + e.getMessage());
                }
            }
        }

        long retryAfter = retryAfterSeconds(response, request.defaultWaitSeconds());
        return retryAfter <= 0 || trySleep(request, retryAfter);
    }

    /**
     * Extracts the user-facing interaction URL from the AAuth-Requirement header, appending the
     * code as a query parameter; falls back to the pending URL.
     */
    static String extractInteractionUrl(String aauthRequirementHeader, String code, String pendingUrl) {
        if (aauthRequirementHeader == null || aauthRequirementHeader.isEmpty()) {
            return pendingUrl;
        }
        try {
            AAuthHeaders.ParsedChallenge parsed = AAuthHeaders.parseAAuthHeader(aauthRequirementHeader);
            String endpoint = parsed.url();
            if (endpoint != null) {
                return endpoint + (endpoint.contains("?") ? "&" : "?") + "code=" + code;
            }
        } catch (RuntimeException e) {
            LOGGER.log(Level.FINE, "Could not parse AAuth-Requirement header", e);
        }
        return pendingUrl;
    }

    private static boolean trySleep(Request request, long seconds) {
        try {
            request.sleeper().sleep(seconds);
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static void sleepSeconds(long seconds) throws InterruptedException {
        Thread.sleep(seconds * 1000);
    }

    private static long retryAfterSeconds(PollResponse response, long fallback) {
        String value = header(response, "retry-after");
        if (value != null) {
            try {
                return Math.max(Long.parseLong(value.strip()), 0);
            } catch (NumberFormatException e) {
                return fallback;
            }
        }
        return fallback;
    }

    private static String header(PollResponse response, String name) {
        for (Map.Entry<String, String> entry : response.headers().entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return null;
    }

    private static PollingResult failure(int status, Map<String, Object> body, String error, String description) {
        return new PollingResult(false, null, body == null ? Map.of() : body, status, error, description);
    }

    private static String errorOr(Map<String, Object> body, String fallback) {
        Object error = body.get("error");
        return error == null ? fallback : error.toString();
    }

    private static String description(Map<String, Object> body) {
        Object description = body.get("error_description");
        return description == null ? null : description.toString();
    }

    private static String str(Object value) {
        return value == null ? null : value.toString();
    }

    private static String firstNonNull(String a, String b) {
        return a != null ? a : b;
    }
}
