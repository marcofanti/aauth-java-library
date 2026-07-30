package io.github.marcofanti.aauth.signing;

import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * {@code Signature} header building and parsing (RFC 9421 §4.2).
 *
 * <p>Note: for interoperability with the Python reference implementation, the signature bytes
 * are base64url-encoded without padding (RFC 9421 itself specifies standard base64 sf-binary).
 */
public final class SignatureHeader {

    private static final Pattern SIGNATURE_PATTERN = Pattern.compile("(\\w+)=:([A-Za-z0-9_-]+):");

    private SignatureHeader() {}

    /** Builds a {@code Signature} header value: {@code label=:base64url:}. */
    public static String build(byte[] signature, String label) {
        return label + "=:" + Base64.getUrlEncoder().withoutPadding().encodeToString(signature) + ":";
    }

    /**
     * Parses a {@code Signature} header value and returns the raw signature bytes.
     *
     * @param headerValue the header value
     * @param expectedLabel when non-null, the label must match
     * @throws IllegalArgumentException if the format is invalid or the label does not match
     */
    public static byte[] parse(String headerValue, String expectedLabel) {
        Matcher matcher = SIGNATURE_PATTERN.matcher(headerValue);
        if (!matcher.find()) {
            throw new IllegalArgumentException("Invalid Signature format: " + headerValue);
        }

        String label = matcher.group(1);
        if (expectedLabel != null && !expectedLabel.equals(label)) {
            throw new IllegalArgumentException("Label mismatch: expected " + expectedLabel + ", got " + label);
        }

        try {
            return Base64.getUrlDecoder().decode(matcher.group(2));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Failed to decode signature: " + e.getMessage(), e);
        }
    }
}
