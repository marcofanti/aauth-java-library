package io.github.marcofanti.aauth.signing;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * {@code Signature-Input} header building and parsing (RFC 9421 §4.1).
 *
 * <p>Parsing follows the RFC 8941 Dictionary grammar strictly, mirroring the reference's use of
 * {@code http_sfv}: exactly one signature label, an inner list of quoted component identifiers with
 * no duplicates, and typed parameters.
 */
public final class SignatureInputHeader {

    private SignatureInputHeader() {}

    /**
     * Parsed {@code Signature-Input} header: the signature label, covered component identifiers,
     * and the inner-list parameters with RFC 8941 types ({@link Long} integers, {@link BigDecimal}
     * decimals, {@link String} strings/tokens/byte sequences, {@link Boolean} booleans).
     */
    public record Parsed(String label, List<String> components, Map<String, Object> params) {
        public Parsed {
            components = List.copyOf(components);
            params = java.util.Collections.unmodifiableMap(new LinkedHashMap<>(params));
        }

        /** Returns an integer parameter (e.g. {@code created}), or {@code null} if absent or not an integer. */
        public @Nullable Long integerParam(String name) {
            return params.get(name) instanceof Long value ? value : null;
        }

        /** Returns a string-valued parameter (e.g. {@code keyid}), or {@code null} if absent or not a string. */
        public @Nullable String stringParam(String name) {
            return params.get(name) instanceof String value ? value : null;
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
     * @throws IllegalArgumentException if the value is not a single-label RFC 8941 dictionary whose
     *     member is an inner list of distinct strings
     */
    public static Parsed parse(String headerValue) {
        Map<String, StructuredFields.Item> members = StructuredFields.parseDictionary(headerValue);
        if (members.size() != 1) {
            throw new IllegalArgumentException("Exactly one signature label is supported");
        }
        Map.Entry<String, StructuredFields.Item> member =
                members.entrySet().iterator().next();
        if (!(member.getValue().value() instanceof List<?> items)) {
            throw new IllegalArgumentException("Signature-Input member must be an inner list");
        }
        List<String> components = new ArrayList<>();
        for (Object item : items) {
            if (!(item instanceof StructuredFields.Item component && component.value() instanceof String name)) {
                throw new IllegalArgumentException("Covered components must be strings");
            }
            components.add(name);
        }
        if (new LinkedHashSet<>(components).size() != components.size()) {
            throw new IllegalArgumentException("Duplicate covered components");
        }
        Map<String, Object> params = new LinkedHashMap<>();
        member.getValue().params().forEach((name, value) -> params.put(name, plainParam(value)));
        return new Parsed(member.getKey(), components, params);
    }

    private static Object plainParam(Object value) {
        return value instanceof StructuredFields.ByteSequence bytes ? bytes.base64() : StructuredFields.plain(value);
    }
}
