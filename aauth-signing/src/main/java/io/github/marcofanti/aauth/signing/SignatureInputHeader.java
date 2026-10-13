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
        Cursor cursor = new Cursor(headerValue);
        cursor.skipSpaces();
        String label = cursor.key();
        cursor.expect('=');
        List<String> components = cursor.innerListOfStrings();
        Map<String, Object> params = cursor.parameters();
        cursor.skipOws();
        if (!cursor.atEnd()) {
            throw new IllegalArgumentException(
                    cursor.peek() == ',' ? "Exactly one signature label is supported" : "Invalid Signature-Input");
        }
        if (new LinkedHashSet<>(components).size() != components.size()) {
            throw new IllegalArgumentException("Duplicate covered components");
        }
        return new Parsed(label, components, params);
    }

    /** Minimal RFC 8941 reader for the one shape {@code Signature-Input} uses. */
    private static final class Cursor {
        private final String input;
        private int pos;

        Cursor(String input) {
            this.input = input;
        }

        boolean atEnd() {
            return pos >= input.length();
        }

        char peek() {
            return input.charAt(pos);
        }

        void expect(char c) {
            if (atEnd() || peek() != c) {
                throw new IllegalArgumentException("Invalid Signature-Input: expected '" + c + "' at " + pos);
            }
            pos++;
        }

        void skipSpaces() {
            while (!atEnd() && peek() == ' ') {
                pos++;
            }
        }

        void skipOws() {
            while (!atEnd() && (peek() == ' ' || peek() == '\t')) {
                pos++;
            }
        }

        /** RFC 8941 key: {@code ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" )}. */
        String key() {
            int start = pos;
            if (atEnd() || !(isLcAlpha(peek()) || peek() == '*')) {
                throw new IllegalArgumentException("Invalid Signature-Input key at " + pos);
            }
            while (!atEnd() && (isLcAlpha(peek()) || Character.isDigit(peek()) || "_-.*".indexOf(peek()) >= 0)) {
                pos++;
            }
            return input.substring(start, pos);
        }

        List<String> innerListOfStrings() {
            expect('(');
            List<String> items = new ArrayList<>();
            while (true) {
                skipSpaces();
                if (atEnd()) {
                    throw new IllegalArgumentException("Unterminated inner list");
                }
                if (peek() == ')') {
                    pos++;
                    return items;
                }
                if (peek() != '"') {
                    throw new IllegalArgumentException("Covered components must be strings");
                }
                items.add(string());
                parameters(); // Component parameters (e.g. ;sf) are not used by AAuth.
                if (!atEnd() && peek() != ' ' && peek() != ')') {
                    throw new IllegalArgumentException("Invalid inner list item separator at " + pos);
                }
            }
        }

        Map<String, Object> parameters() {
            Map<String, Object> params = new LinkedHashMap<>();
            while (!atEnd() && peek() == ';') {
                pos++;
                skipSpaces();
                String name = key();
                Object value = Boolean.TRUE;
                if (!atEnd() && peek() == '=') {
                    pos++;
                    value = bareItem();
                }
                params.put(name, value);
            }
            return params;
        }

        Object bareItem() {
            if (atEnd()) {
                throw new IllegalArgumentException("Missing parameter value");
            }
            char c = peek();
            if (c == '"') {
                return string();
            }
            if (c == '-' || Character.isDigit(c)) {
                return number();
            }
            if (c == '?') {
                return bool();
            }
            if (c == ':') {
                return byteSequence();
            }
            return token();
        }

        String string() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (!atEnd()) {
                char c = input.charAt(pos++);
                if (c == '\\') {
                    if (atEnd() || (peek() != '"' && peek() != '\\')) {
                        throw new IllegalArgumentException("Invalid escape in string");
                    }
                    sb.append(input.charAt(pos++));
                } else if (c == '"') {
                    return sb.toString();
                } else if (c < 0x20 || c > 0x7E) {
                    throw new IllegalArgumentException("Invalid character in string");
                } else {
                    sb.append(c);
                }
            }
            throw new IllegalArgumentException("Unterminated string");
        }

        Object number() {
            int start = pos;
            if (peek() == '-') {
                pos++;
            }
            while (!atEnd() && (Character.isDigit(peek()) || peek() == '.')) {
                pos++;
            }
            String text = input.substring(start, pos);
            if (text.contains(".")) {
                return new BigDecimal(text);
            }
            if (text.replace("-", "").length() > 15) {
                throw new IllegalArgumentException("Integer out of range");
            }
            return Long.parseLong(text);
        }

        Boolean bool() {
            expect('?');
            if (atEnd() || (peek() != '0' && peek() != '1')) {
                throw new IllegalArgumentException("Invalid boolean");
            }
            return input.charAt(pos++) == '1';
        }

        String byteSequence() {
            expect(':');
            int end = input.indexOf(':', pos);
            if (end < 0) {
                throw new IllegalArgumentException("Unterminated byte sequence");
            }
            String value = input.substring(pos, end);
            pos = end + 1;
            return value;
        }

        String token() {
            int start = pos;
            char first = peek();
            if (!(Character.isLetter(first) || first == '*')) {
                throw new IllegalArgumentException("Invalid parameter value at " + pos);
            }
            while (!atEnd() && " ;,()\"".indexOf(peek()) < 0) {
                pos++;
            }
            return input.substring(start, pos);
        }

        private static boolean isLcAlpha(char c) {
            return c >= 'a' && c <= 'z';
        }
    }
}
