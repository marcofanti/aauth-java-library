package io.github.marcofanti.aauth.headers;

import io.github.marcofanti.aauth.ErrorCodes;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** {@code Signature-Error} response header per draft-hardt-httpbis-signature-key. */
public final class SignatureErrorHeader {

    private static final Pattern ERROR_PATTERN = Pattern.compile("error=([\\w_]+)");
    private static final Pattern QUOTED_PATTERN = Pattern.compile("\"([^\"]+)\"");

    private SignatureErrorHeader() {}

    /** Parsed {@code Signature-Error} header. List fields are {@code null} when absent. */
    public record Parsed(String error, List<String> requiredInput, List<String> supportedAlgorithms) {}

    /**
     * Builds a {@code Signature-Error} header value.
     *
     * @param error error code (an {@link ErrorCodes} constant)
     * @param requiredInput for {@code invalid_input}: required covered components
     * @param supportedAlgorithms for {@code unsupported_algorithm}: supported algorithms
     */
    public static String build(String error, List<String> requiredInput, List<String> supportedAlgorithms) {
        StringBuilder sb = new StringBuilder("error=").append(error);
        if (requiredInput != null && !requiredInput.isEmpty() && ErrorCodes.ERROR_INVALID_INPUT.equals(error)) {
            sb.append(", required_input=(").append(quotedList(requiredInput)).append(')');
        }
        if (supportedAlgorithms != null
                && !supportedAlgorithms.isEmpty()
                && ErrorCodes.ERROR_UNSUPPORTED_ALGORITHM.equals(error)) {
            sb.append(", supported_algorithms=(")
                    .append(quotedList(supportedAlgorithms))
                    .append(')');
        }
        return sb.toString();
    }

    /** Parses a {@code Signature-Error} header value. */
    public static Parsed parse(String headerValue) {
        String error = null;
        Matcher errorMatcher = ERROR_PATTERN.matcher(headerValue);
        if (errorMatcher.find()) {
            error = errorMatcher.group(1);
        }
        return new Parsed(
                error, innerList(headerValue, "required_input"), innerList(headerValue, "supported_algorithms"));
    }

    private static List<String> innerList(String headerValue, String paramName) {
        Matcher matcher = Pattern.compile(paramName + "=\\(([^)]+)\\)").matcher(headerValue);
        if (!matcher.find()) {
            return null;
        }
        List<String> values = new ArrayList<>();
        Matcher quoted = QUOTED_PATTERN.matcher(matcher.group(1));
        while (quoted.find()) {
            values.add(quoted.group(1));
        }
        return values;
    }

    private static String quotedList(List<String> values) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                sb.append(' ');
            }
            sb.append('"').append(values.get(i)).append('"');
        }
        return sb.toString();
    }
}
