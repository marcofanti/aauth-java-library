package io.github.marcofanti.aauth.signing;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jspecify.annotations.Nullable;

/** {@code Signature-Input} header building and parsing (RFC 9421 §4.1). */
public final class SignatureInputHeader {

    private static final Pattern HEADER_PATTERN = Pattern.compile("(\\w+)=\\((.*)\\)(?:;(.*))?");
    private static final Pattern COMPONENT_PATTERN = Pattern.compile("\"([^\"]+)\"");
    private static final Pattern PARAM_PATTERN = Pattern.compile("(\\w+)=([^\\s;]+)");

    private SignatureInputHeader() {}

    /**
     * Parsed {@code Signature-Input} header: covered component identifiers and the
     * post-component parameters (e.g. {@code created}).
     */
    public record Parsed(List<String> components, Map<String, String> params) {
        public Parsed {
            components = List.copyOf(components);
            params = Map.copyOf(params);
        }
    }

    /**
     * Builds a {@code Signature-Input} header value.
     *
     * <p>Per AAuth spec §15.4 only the {@code created} parameter is required.
     *
     * @param coveredComponents component identifiers to cover
     * @param label signature label (conventionally {@code sig})
     * @param created creation timestamp in Unix seconds; {@code null} uses the current time
     */
    public static String build(List<String> coveredComponents, String label, @Nullable Long created) {
        long timestamp = created != null ? created : Instant.now().getEpochSecond();
        return label + "=" + buildParams(coveredComponents, timestamp);
    }

    /** Builds the value after the label: {@code ("@method" ...);created=1234567890}. */
    public static String buildParams(List<String> coveredComponents, long created) {
        StringBuilder sb = new StringBuilder("(");
        for (int i = 0; i < coveredComponents.size(); i++) {
            if (i > 0) {
                sb.append(' ');
            }
            sb.append('"').append(coveredComponents.get(i)).append('"');
        }
        return sb.append(");created=").append(created).toString();
    }

    /**
     * Parses a {@code Signature-Input} header value.
     *
     * @throws IllegalArgumentException if the header format is invalid
     */
    public static Parsed parse(String headerValue) {
        Matcher matcher = HEADER_PATTERN.matcher(headerValue);
        if (!matcher.lookingAt()) {
            throw new IllegalArgumentException("Invalid Signature-Input format: " + headerValue);
        }

        String componentsPart = matcher.group(2);
        String paramsPart = matcher.group(3) == null ? "" : matcher.group(3);

        List<String> components = new ArrayList<>();
        Matcher componentMatcher = COMPONENT_PATTERN.matcher(componentsPart);
        while (componentMatcher.find()) {
            components.add(componentMatcher.group(1));
        }

        Map<String, String> params = new LinkedHashMap<>();
        Matcher paramMatcher = PARAM_PATTERN.matcher(paramsPart);
        while (paramMatcher.find()) {
            params.put(paramMatcher.group(1), stripQuotes(paramMatcher.group(2)));
        }

        return new Parsed(components, params);
    }

    private static String stripQuotes(String value) {
        if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1);
        }
        return value;
    }
}
