package io.github.marcofanti.aauth.agent;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.headers.AAuthHeaders;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import org.jspecify.annotations.Nullable;

/**
 * The deferred-response state machine for draft-11 (mirrors the reference {@code agent/poller}).
 *
 * <p>The agent polls the pending URL with signed GETs until a terminal response. A 2xx/3xx is
 * success; 403/408/410/500 and anything else unexpected end the poll with an error. 202 means
 * pending: a new {@code Location} (same origin only) replaces the pending URL, an
 * {@code interaction} requirement prompts the person once per {@code (url, code)}, and a
 * {@code clarification} is answered with a POST. 429 lengthens the wait by five seconds; 503
 * backs off. GET polls and clarification replies together count toward {@code maxPolls}.
 */
public final class Poller {

    private static final int DEFAULT_WAIT_SECONDS = 5;

    private Poller() {}

    /**
     * A minimal HTTP response view the poller understands.
     *
     * @param statusCode HTTP status
     * @param body the JSON object body, or empty
     * @param headers response headers
     * @param raw the raw response body bytes
     */
    // byte[] raw is intentional: the response bytes; record equality is never used.
    @SuppressWarnings("ArrayRecordComponent")
    public record PollResponse(int statusCode, Map<String, Object> body, Map<String, String> headers, byte[] raw) {
        public PollResponse {
            body = body == null ? Map.of() : body;
            headers = headers == null ? Map.of() : headers;
            raw = raw == null ? new byte[0] : raw;
        }

        public PollResponse(int statusCode, Map<String, Object> body, Map<String, String> headers) {
            this(statusCode, body, headers, new byte[0]);
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

    /**
     * Outcome of polling.
     *
     * @param success whether the terminal response was 2xx/3xx
     * @param authToken the {@code auth_token} of the terminal body, if any
     * @param responseBody the terminal JSON body
     * @param statusCode the terminal status, or 0 when polling ended without one
     * @param error the error code on failure
     * @param errorDescription the {@code detail} / {@code error_description}, if any
     * @param response the terminal response, or {@code null} when polling ended without one
     */
    public record PollingResult(
            boolean success,
            @Nullable String authToken,
            Map<String, Object> responseBody,
            int statusCode,
            @Nullable String error,
            @Nullable String errorDescription,
            @Nullable PollResponse response) {}

    /**
     * Parameters for {@link #poll(Request)}.
     *
     * @param pendingUrl the pending URL (the 202 response's {@code Location}, already resolved)
     * @param signedGet sends a signed GET and returns the response
     * @param maxPolls maximum GET polls plus clarification replies (default 60)
     * @param defaultWaitSeconds seconds between polls without {@code Retry-After} (default 5)
     * @param onInteraction invoked with (interaction URL including {@code ?code=}, code) once per
     *     distinct prompt
     * @param onClarification invoked with (pendingUrl, question); returns the answer or {@code null}
     * @param signedPost sends a clarification answer; required for clarification handling
     * @param sleeper sleep implementation in seconds (injectable for tests)
     * @param initialResponse the 202 that started the deferral, processed before the first GET
     */
    public record Request(
            String pendingUrl,
            SignedGet signedGet,
            int maxPolls,
            int defaultWaitSeconds,
            @Nullable BiConsumer<String, String> onInteraction,
            @Nullable BiFunction<String, String, String> onClarification,
            @Nullable SignedPost signedPost,
            Sleeper sleeper,
            @Nullable PollResponse initialResponse) {

        public Request {
            maxPolls = maxPolls <= 0 ? 60 : maxPolls;
            defaultWaitSeconds = defaultWaitSeconds <= 0 ? DEFAULT_WAIT_SECONDS : defaultWaitSeconds;
        }

        public static Builder builder(String pendingUrl, SignedGet signedGet) {
            return new Builder(pendingUrl, signedGet);
        }

        /** Builder for {@link Request}. */
        public static final class Builder {
            private final String pendingUrl;
            private final SignedGet signedGet;
            private int maxPolls = 60;
            private int defaultWaitSeconds = DEFAULT_WAIT_SECONDS;
            private @Nullable BiConsumer<String, String> onInteraction;
            private @Nullable BiFunction<String, String, String> onClarification;
            private @Nullable SignedPost signedPost;
            private @Nullable Sleeper sleeper;
            private @Nullable PollResponse initialResponse;

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

            public Builder onInteraction(@Nullable BiConsumer<String, String> onInteraction) {
                this.onInteraction = onInteraction;
                return this;
            }

            public Builder onClarification(@Nullable BiFunction<String, String, String> onClarification) {
                this.onClarification = onClarification;
                return this;
            }

            public Builder signedPost(@Nullable SignedPost signedPost) {
                this.signedPost = signedPost;
                return this;
            }

            public Builder sleeper(@Nullable Sleeper sleeper) {
                this.sleeper = sleeper;
                return this;
            }

            /** Processes this 202 first instead of starting with a GET. */
            public Builder initialResponse(@Nullable PollResponse initialResponse) {
                this.initialResponse = initialResponse;
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
                        sleeper == null ? Poller::sleepSeconds : sleeper,
                        initialResponse);
            }
        }
    }

    /** Sleep abstraction (seconds); injectable so tests run instantly. */
    @FunctionalInterface
    public interface Sleeper {
        void sleep(long seconds) throws InterruptedException;
    }

    /**
     * Resolves a 202 {@code Location} against its base and requires it to stay on the same origin
     * (scheme, host, port), without credentials or a fragment.
     *
     * @throws TokenException if the location is missing or leaves the origin
     */
    public static String pendingLocation(@Nullable String location, String base) {
        if (location == null || location.isEmpty()) {
            throw new TokenException("202 response has no Location header", null);
        }
        URI baseUri = URI.create(base);
        URI target = baseUri.resolve(location);
        if (!origin(baseUri).equals(origin(target))
                || target.getRawUserInfo() != null
                || target.getRawFragment() != null) {
            throw new TokenException("Pending Location must remain on the same origin", null);
        }
        return target.toString();
    }

    private static String origin(URI uri) {
        String scheme = String.valueOf(uri.getScheme()).toLowerCase(Locale.ROOT);
        int port = uri.getPort() != -1 ? uri.getPort() : "https".equals(scheme) ? 443 : 80;
        return scheme + "://" + String.valueOf(uri.getHost()).toLowerCase(Locale.ROOT) + ":" + port;
    }

    /** Polls a pending URL until a terminal response. Never throws. */
    public static PollingResult poll(Request request) {
        try {
            return run(request);
        } catch (TokenException e) {
            return failure("invalid_response", e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return failure("network_error", "Interrupted while polling");
        } catch (Exception e) {
            return failure("network_error", e.getMessage());
        }
    }

    /** Runs {@link #poll(Request)} on the given executor. */
    public static CompletableFuture<PollingResult> pollAsync(Request request, Executor executor) {
        return CompletableFuture.supplyAsync(() -> poll(request), executor);
    }

    /** Sends a signed DELETE to a pending URL to cancel the request. */
    public static PollResponse cancelPendingRequest(SignedGet signedDelete, String pendingUrl) throws Exception {
        return signedDelete.get(pendingUrl);
    }

    private static PollingResult run(Request request) throws Exception {
        PollState state = new PollState(request);
        PollResponse response = request.initialResponse();
        while (true) {
            if (response == null) {
                if (state.count >= request.maxPolls()) {
                    return failure("max_polls_exceeded", "Exceeded " + request.maxPolls() + " polls");
                }
                response = request.signedGet().get(state.pendingUrl);
                state.count++;
            }
            Map<String, String> headers = lowercase(response.headers());
            int status = response.statusCode();
            if (status == 429) {
                state.defaultWait += 5;
                sleep(request, Math.max(state.defaultWait, waitSeconds(headers, state.defaultWait)));
            } else if (status == 503) {
                sleep(request, waitSeconds(headers, Math.max(state.defaultWait * 2, 1)));
            } else if (status != 202) {
                return terminal(response);
            } else {
                Pending outcome = pending(request, state, response, headers);
                PollResponse reply = outcome.reply();
                if (outcome.next() == Next.REPLIED && reply != null) {
                    response = reply;
                    continue;
                }
                if (outcome.next() == Next.MAX_POLLS) {
                    return failure("max_polls_exceeded", "Exceeded " + request.maxPolls() + " polls/replies");
                }
                sleep(request, waitSeconds(headers, state.defaultWait));
            }
            response = null;
        }
    }

    /** Mutable polling state. */
    private static final class PollState {
        private String pendingUrl;
        private int count;
        private int defaultWait;
        private final Set<String> prompted = new HashSet<>();

        PollState(Request request) {
            this.pendingUrl = request.pendingUrl();
            this.defaultWait = request.defaultWaitSeconds();
        }
    }

    /** What to do after a 202: wait and poll again, stop at the poll limit, or process a reply. */
    private enum Next {
        WAIT,
        MAX_POLLS,
        REPLIED
    }

    private record Pending(Next next, @Nullable PollResponse reply) {
        static final Pending WAIT = new Pending(Next.WAIT, null);
        static final Pending LIMIT = new Pending(Next.MAX_POLLS, null);
    }

    /**
     * Handles a 202: follows {@code Location}, prompts for interaction, answers clarification
     * (whose POST response is processed next).
     */
    private static Pending pending(Request request, PollState state, PollResponse response, Map<String, String> headers)
            throws Exception {
        Map<String, Object> body = response.body();
        String location = headers.get("location");
        if (location != null) {
            state.pendingUrl = pendingLocation(location, state.pendingUrl);
        }
        String raw = headers.getOrDefault("aauth-requirement", "");
        AAuthHeaders.ParsedChallenge parsed = raw.isEmpty() ? null : AAuthHeaders.parseAAuthHeader(raw);
        String requirement = firstNonNull(
                parsed == null ? null : parsed.requirement(), str(body.get("requirement")), str(body.get("require")));
        String code = firstNonNull(parsed == null ? null : parsed.code(), str(body.get("code")));
        if ("interaction".equals(requirement)
                && code != null
                && !code.isEmpty()
                && request.onInteraction() != null
                && !"interacting".equals(body.get("status"))) {
            prompt(request, state, parsed == null ? null : parsed.url(), code);
        }
        String clarification = str(body.get("clarification"));
        BiFunction<String, String, String> onClarification = request.onClarification();
        SignedPost signedPost = request.signedPost();
        if ("clarification".equals(requirement)
                && clarification != null
                && !clarification.isEmpty()
                && onClarification != null
                && signedPost != null) {
            String answer = onClarification.apply(state.pendingUrl, clarification);
            if (answer != null) {
                if (state.count >= request.maxPolls()) {
                    return Pending.LIMIT;
                }
                state.count++;
                Map<String, Object> reply = new LinkedHashMap<>();
                reply.put("action", "clarification_response");
                reply.put("clarification_response", answer);
                // The POST can itself complete or deny the pending operation.
                return new Pending(Next.REPLIED, signedPost.post(state.pendingUrl, reply));
            }
        }
        return Pending.WAIT;
    }

    /** Prompts once per distinct interaction URL and code; the URL must be a plain HTTPS URL. */
    private static void prompt(Request request, PollState state, @Nullable String url, String code) {
        String endpoint;
        if (url != null && !url.isEmpty()) {
            URI uri = URI.create(url);
            if (!"https".equals(uri.getScheme())
                    || uri.getRawQuery() != null
                    || uri.getRawFragment() != null
                    || uri.getRawUserInfo() != null) {
                throw new TokenException("Invalid interaction URL", null);
            }
            endpoint = url + "?code=" + URLEncoder.encode(code, StandardCharsets.UTF_8);
        } else {
            endpoint = state.pendingUrl; // Older responses mirror the interaction in the body.
        }
        BiConsumer<String, String> onInteraction = Objects.requireNonNull(request.onInteraction());
        if (state.prompted.add(endpoint + "\n" + code)) {
            onInteraction.accept(endpoint, code);
        }
    }

    private static PollingResult terminal(PollResponse response) {
        int status = response.statusCode();
        Map<String, Object> body = response.body();
        boolean success = status >= 200 && status < 400;
        String error = str(body.get("error"));
        if (error == null) {
            error = switch (status) {
                case 403 -> "denied";
                case 408 -> "expired";
                case 410 -> "invalid_code";
                case 500 -> "server_error";
                default -> "unexpected_status";
            };
        }
        return new PollingResult(
                success,
                str(body.get("auth_token")),
                body,
                status,
                success ? null : error,
                firstNonNull(str(body.get("detail")), str(body.get("error_description"))),
                response);
    }

    private static PollingResult failure(String error, @Nullable String description) {
        return new PollingResult(false, null, Map.of(), 0, error, description, null);
    }

    private static void sleep(Request request, long seconds) throws InterruptedException {
        if (seconds > 0) {
            request.sleeper().sleep(seconds);
        }
    }

    private static int waitSeconds(Map<String, String> headers, int defaultWait) {
        String value = headers.get("retry-after");
        if (value == null) {
            return defaultWait;
        }
        try {
            return Math.max(Integer.parseInt(value.strip()), 0);
        } catch (NumberFormatException e) {
            return defaultWait;
        }
    }

    private static Map<String, String> lowercase(Map<String, String> headers) {
        Map<String, String> result = new LinkedHashMap<>();
        headers.forEach((name, value) -> result.put(name.toLowerCase(Locale.ROOT), value));
        return result;
    }

    private static void sleepSeconds(long seconds) throws InterruptedException {
        Thread.sleep(seconds * 1000L);
    }

    private static @Nullable String str(@Nullable Object value) {
        return value == null ? null : value.toString();
    }

    @SafeVarargs
    private static <T> @Nullable T firstNonNull(@Nullable T... values) {
        for (T value : values) {
            if (value != null) {
                return value;
            }
        }
        return null;
    }
}
