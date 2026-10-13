package io.github.marcofanti.aauth.signing;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A strict reader for RFC 8941 Structured Field Dictionaries, used for {@code Signature-Input} and
 * {@code AAuth-Requirement} (mirrors the reference's use of {@code http_sfv}).
 *
 * <p>Bare item values are typed: {@link String} for sf-strings, {@link Token} for tokens,
 * {@link Long} integers, {@link BigDecimal} decimals, {@link Boolean} booleans and
 * {@link ByteSequence} byte sequences. A member whose value is an inner list has a
 * {@link List} of {@link Item}s as its value.
 */
public final class StructuredFields {

    private StructuredFields() {}

    /** An sf-token (unquoted), distinct from an sf-string. */
    public record Token(String value) {
        @Override
        public String toString() {
            return value;
        }
    }

    /** An sf-binary byte sequence, kept in its base64 form. */
    public record ByteSequence(String base64) {}

    /** A dictionary member or inner-list item: its value and parameters. */
    public record Item(Object value, Map<String, Object> params) {
        public Item {
            params = java.util.Collections.unmodifiableMap(new LinkedHashMap<>(params));
        }
    }

    /**
     * Parses a Structured Field Dictionary, keeping member order.
     *
     * @throws IllegalArgumentException if the value is not a valid dictionary
     */
    public static Map<String, Item> parseDictionary(String value) {
        Cursor cursor = new Cursor(value);
        Map<String, Item> members = new LinkedHashMap<>();
        cursor.skipSpaces();
        while (!cursor.atEnd()) {
            String key = cursor.key();
            Item item;
            if (!cursor.atEnd() && cursor.peek() == '=') {
                cursor.pos++;
                item = cursor.peek() == '(' ? cursor.innerList() : new Item(cursor.bareItem(), cursor.parameters());
            } else {
                item = new Item(true, cursor.parameters());
            }
            members.put(key, item);
            cursor.skipOws();
            if (cursor.atEnd()) {
                break;
            }
            cursor.expect(',');
            cursor.skipOws();
            if (cursor.atEnd()) {
                throw new IllegalArgumentException("Trailing comma in dictionary");
            }
        }
        return members;
    }

    /** Converts a typed parameter value to its plain form ({@link Token} becomes its string). */
    public static Object plain(Object value) {
        return value instanceof Token token ? token.value() : value;
    }

    /** RFC 8941 reader for the dictionary shapes AAuth uses. */
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
            if (atEnd()) {
                throw new IllegalArgumentException("Unexpected end of structured field");
            }
            return input.charAt(pos);
        }

        void expect(char c) {
            if (atEnd() || input.charAt(pos) != c) {
                throw new IllegalArgumentException("Expected '" + c + "' at " + pos);
            }
            pos++;
        }

        void skipSpaces() {
            while (!atEnd() && input.charAt(pos) == ' ') {
                pos++;
            }
        }

        void skipOws() {
            while (!atEnd() && (input.charAt(pos) == ' ' || input.charAt(pos) == '\t')) {
                pos++;
            }
        }

        /** {@code ( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" )}. */
        String key() {
            int start = pos;
            if (atEnd() || !(isLcAlpha(input.charAt(pos)) || input.charAt(pos) == '*')) {
                throw new IllegalArgumentException("Invalid key at " + pos);
            }
            while (!atEnd() && isKeyChar(input.charAt(pos))) {
                pos++;
            }
            return input.substring(start, pos);
        }

        Item innerList() {
            expect('(');
            List<Item> items = new ArrayList<>();
            while (true) {
                skipSpaces();
                if (peek() == ')') {
                    pos++;
                    return new Item(List.copyOf(items), parameters());
                }
                items.add(new Item(bareItem(), parameters()));
                if (!atEnd() && input.charAt(pos) != ' ' && input.charAt(pos) != ')') {
                    throw new IllegalArgumentException("Invalid inner list separator at " + pos);
                }
            }
        }

        Map<String, Object> parameters() {
            Map<String, Object> params = new LinkedHashMap<>();
            while (!atEnd() && input.charAt(pos) == ';') {
                pos++;
                skipSpaces();
                String name = key();
                Object value = true;
                if (!atEnd() && input.charAt(pos) == '=') {
                    pos++;
                    value = bareItem();
                }
                params.put(name, value);
            }
            return params;
        }

        Object bareItem() {
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
                    if (atEnd() || (input.charAt(pos) != '"' && input.charAt(pos) != '\\')) {
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
            if (input.charAt(pos) == '-') {
                pos++;
            }
            while (!atEnd() && (Character.isDigit(input.charAt(pos)) || input.charAt(pos) == '.')) {
                pos++;
            }
            String text = input.substring(start, pos);
            if (text.equals("-") || text.endsWith(".")) {
                throw new IllegalArgumentException("Invalid number: " + text);
            }
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
            if (atEnd() || (input.charAt(pos) != '0' && input.charAt(pos) != '1')) {
                throw new IllegalArgumentException("Invalid boolean");
            }
            return input.charAt(pos++) == '1';
        }

        ByteSequence byteSequence() {
            expect(':');
            int end = input.indexOf(':', pos);
            if (end < 0) {
                throw new IllegalArgumentException("Unterminated byte sequence");
            }
            String value = input.substring(pos, end);
            pos = end + 1;
            return new ByteSequence(value);
        }

        /** {@code ( ALPHA / "*" ) *( tchar / ":" / "/" )}. */
        Token token() {
            int start = pos;
            char first = input.charAt(pos);
            if (!(isAlpha(first) || first == '*')) {
                throw new IllegalArgumentException("Invalid bare item at " + pos);
            }
            while (!atEnd() && isTokenChar(input.charAt(pos))) {
                pos++;
            }
            return new Token(input.substring(start, pos));
        }

        private static boolean isLcAlpha(char c) {
            return c >= 'a' && c <= 'z';
        }

        private static boolean isAlpha(char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        }

        private static boolean isKeyChar(char c) {
            return isLcAlpha(c) || Character.isDigit(c) || "_-.*".indexOf(c) >= 0;
        }

        private static boolean isTokenChar(char c) {
            return isAlpha(c) || Character.isDigit(c) || "!#$%&'*+-.^_`|~:/".indexOf(c) >= 0;
        }
    }
}
