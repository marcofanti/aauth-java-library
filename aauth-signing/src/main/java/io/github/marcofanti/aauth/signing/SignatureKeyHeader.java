package io.github.marcofanti.aauth.signing;

import io.github.marcofanti.aauth.signing.keys.Jwk;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jspecify.annotations.Nullable;

/**
 * {@code Signature-Key} header building and parsing per draft-hardt-httpbis-signature-key.
 *
 * <p>The header is an RFC 8941 Structured Fields Dictionary whose single member is an Item: the
 * bare item is the scheme token with semicolon-separated parameters, e.g.
 * {@code sig=hwk;kty="OKP";crv="Ed25519";x="..."}.
 */
public final class SignatureKeyHeader {

    private static final Pattern LABEL_PATTERN = Pattern.compile("^(\\w+)=(.*)$", Pattern.DOTALL);
    private static final Pattern LEGACY_PARAM_PATTERN = Pattern.compile("([\\w_-]+)=(?:\"([^\"]*)\"|([^\\s)]+))");

    private SignatureKeyHeader() {}

    /** Parsed {@code Signature-Key} header: label, scheme token, and parameters. */
    public record Parsed(String label, String scheme, Map<String, String> params) {
        public Parsed {
            params = Map.copyOf(params);
        }
    }

    /**
     * Builds a {@code Signature-Key} header value.
     *
     * @param scheme the signature scheme with its parameters
     * @param label the signature label; must match the label in Signature-Input and Signature
     * @param hwkPublicKey the signer's public key; required for the {@code hwk} scheme, ignored
     *     otherwise
     * @throws IllegalArgumentException if required parameters are missing
     */
    public static String build(SignatureScheme scheme, String label, @Nullable PublicKey hwkPublicKey) {
        if (scheme instanceof SignatureScheme.Hwk) {
            if (hwkPublicKey == null) {
                throw new IllegalArgumentException("scheme=hwk requires the signer's public key");
            }
            Map<String, Object> jwk = Jwk.publicKeyToJwk(hwkPublicKey, null);
            List<Map.Entry<String, String>> pairs = new ArrayList<>();
            pairs.add(Map.entry("kty", (String) jwk.get("kty")));
            pairs.add(Map.entry("crv", (String) jwk.get("crv")));
            pairs.add(Map.entry("x", (String) jwk.get("x")));
            if (jwk.get("y") instanceof String y) {
                pairs.add(Map.entry("y", y));
            }
            return label + "=hwk;" + formatParams(pairs);
        }
        if (scheme instanceof SignatureScheme.JktJwt jktJwt) {
            return label + "=jkt-jwt;" + formatParams(List.of(Map.entry("jwt", jktJwt.jwt())));
        }
        if (scheme instanceof SignatureScheme.JwksUri jwksUri) {
            return label + "=jwks_uri;"
                    + formatParams(List.of(
                            Map.entry("id", jwksUri.id()),
                            Map.entry("dwk", jwksUri.dwk()),
                            Map.entry("kid", jwksUri.kid())));
        }
        if (scheme instanceof SignatureScheme.Jwt jwt) {
            return label + "=jwt;" + formatParams(List.of(Map.entry("jwt", jwt.jwt())));
        }
        if (scheme instanceof SignatureScheme.X509 x509) {
            // x5t is an RFC 8941 byte sequence (:base64:) built from the provided base64 string.
            return label + "=x509;x5u=\"" + escape(x509.x5u()) + "\";x5t=:" + x509.x5t() + ":";
        }
        throw new IllegalArgumentException("Unknown signature scheme: " + scheme);
    }

    /**
     * Parses a {@code Signature-Key} header value.
     *
     * <p>Accepts the spec form {@code label=scheme;param="value";...} and the legacy inner-list
     * form {@code label=(scheme=hwk ...)} emitted by older Python library versions.
     *
     * @throws IllegalArgumentException if the header format is invalid
     */
    public static Parsed parse(String headerValue) {
        Matcher matcher = LABEL_PATTERN.matcher(headerValue.strip());
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid Signature-Key format: " + headerValue);
        }
        String label = matcher.group(1);
        String rest = matcher.group(2).strip();

        if (rest.startsWith("(") && rest.endsWith(")")) {
            return parseLegacyInnerList(label, rest.substring(1, rest.length() - 1));
        }
        return parseDictionaryItemForm(label, rest);
    }

    private static Parsed parseDictionaryItemForm(String label, String rest) {
        if (rest.isEmpty()) {
            throw new IllegalArgumentException("Missing scheme in Signature-Key");
        }
        int semicolon = rest.indexOf(';');
        String scheme =
                semicolon == -1 ? rest.strip() : rest.substring(0, semicolon).strip();
        String paramPart = semicolon == -1 ? "" : rest.substring(semicolon + 1);
        if (scheme.isEmpty()) {
            throw new IllegalArgumentException("Missing scheme in Signature-Key");
        }
        return new Parsed(label, scheme, parseItemParameters(paramPart));
    }

    /** Parses RFC 8941 Item parameters after the scheme token (leading {@code ;} optional). */
    private static Map<String, String> parseItemParameters(String paramPart) {
        Map<String, String> params = new LinkedHashMap<>();
        int i = 0;
        int n = paramPart.length();
        while (i < n) {
            while (i < n && (paramPart.charAt(i) == ' ' || paramPart.charAt(i) == '\t' || paramPart.charAt(i) == ';')) {
                i++;
            }
            if (i >= n) {
                break;
            }
            int eq = paramPart.indexOf('=', i);
            if (eq == -1) {
                break;
            }
            String key = paramPart.substring(i, eq).strip();
            i = eq + 1;
            if (i >= n) {
                params.put(key, "");
                break;
            }
            if (paramPart.charAt(i) == '"') {
                i++;
                StringBuilder buf = new StringBuilder();
                while (i < n) {
                    char c = paramPart.charAt(i);
                    if (c == '\\' && i + 1 < n) {
                        buf.append(paramPart.charAt(i + 1));
                        i += 2;
                        continue;
                    }
                    if (c == '"') {
                        i++;
                        break;
                    }
                    buf.append(c);
                    i++;
                }
                params.put(key, buf.toString());
            } else {
                int start = i;
                while (i < n && paramPart.charAt(i) != ';') {
                    i++;
                }
                params.put(key, paramPart.substring(start, i).strip());
            }
        }
        return params;
    }

    private static Parsed parseLegacyInnerList(String label, String innerContent) {
        Map<String, String> params = new LinkedHashMap<>();
        String scheme = null;
        Matcher matcher = LEGACY_PARAM_PATTERN.matcher(innerContent);
        while (matcher.find()) {
            String key = matcher.group(1);
            String value = matcher.group(2) != null ? matcher.group(2) : matcher.group(3);
            if ("scheme".equals(key)) {
                scheme = value;
            } else {
                params.put(key, value);
            }
        }
        if (scheme == null) {
            throw new IllegalArgumentException("Missing scheme in Signature-Key: (" + innerContent + ")");
        }
        return new Parsed(label, scheme, params);
    }

    private static String formatParams(List<Map.Entry<String, String>> pairs) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < pairs.size(); i++) {
            if (i > 0) {
                sb.append(';');
            }
            sb.append(pairs.get(i).getKey())
                    .append("=\"")
                    .append(escape(pairs.get(i).getValue()))
                    .append('"');
        }
        return sb.toString();
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
