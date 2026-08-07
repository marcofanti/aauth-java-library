package io.github.marcofanti.aauth.headers;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jspecify.annotations.Nullable;

/**
 * {@code Accept-Signature} response header per draft-hardt-httpbis-signature-key §4.1.
 *
 * <p>Resources return this header to declare they accept HTTP Message Signatures. It replaces
 * the older {@code Signature-Requirement: requirement=pseudonym/identity} format.
 */
public final class AcceptSignatureHeader {

    /** Pseudonym: inline public key / JWK thumbprint ({@code hwk}, {@code jkt-jwt}). */
    public static final String SIGKEY_JKT = "jkt";

    /** Identity: URI-identified key ({@code jwks_uri}, {@code jwt}). */
    public static final String SIGKEY_URI = "uri";

    /** PKI: X.509 certificate chain. */
    public static final String SIGKEY_X509 = "x509";

    private static final List<String> DEFAULT_COMPONENTS = List.of("@method", "@authority", "@path");

    private static final Pattern SIGKEY_PATTERN = Pattern.compile("sigkey=([^\\s;,]+)");
    private static final Pattern ALG_PATTERN = Pattern.compile("alg=\"([^\"]+)\"");
    private static final Pattern COMPONENTS_PATTERN = Pattern.compile("sig=\\(([^)]*)\\)");
    private static final Pattern QUOTED_PATTERN = Pattern.compile("\"([^\"]+)\"");

    private AcceptSignatureHeader() {}

    /**
     * Parsed {@code Accept-Signature} header. {@code requirement} is the mapped requirement level
     * ({@code pseudonym} for jkt, {@code identity} for uri/x509) for challenge-handler
     * compatibility.
     */
    public record Parsed(
            @Nullable String sigkey,
            List<String> components,
            @Nullable String alg,
            @Nullable String requirement) {
        public Parsed {
            components = List.copyOf(components);
        }
    }

    /**
     * Builds an {@code Accept-Signature} header value, e.g.
     * {@code sig=("@method" "@authority" "@path");sigkey=uri}.
     *
     * @param sigkey key discovery type ({@link #SIGKEY_JKT}, {@link #SIGKEY_URI}, {@link #SIGKEY_X509})
     * @param components covered components; defaults to {@code @method @authority @path}
     * @param algs acceptable algorithms; a single entry is emitted as the {@code alg} parameter
     */
    public static String build(String sigkey, @Nullable List<String> components, @Nullable List<String> algs) {
        List<String> comps = components == null || components.isEmpty() ? DEFAULT_COMPONENTS : components;
        StringBuilder inner = new StringBuilder();
        for (int i = 0; i < comps.size(); i++) {
            if (i > 0) {
                inner.append(' ');
            }
            inner.append('"').append(comps.get(i)).append('"');
        }
        String params = "sigkey=" + sigkey;
        if (algs != null && algs.size() == 1) {
            params = "alg=\"" + algs.get(0) + "\";" + params;
        }
        return "sig=(" + inner + ");" + params;
    }

    /** Parses an {@code Accept-Signature} header value. */
    public static Parsed parse(String headerValue) {
        String sigkey = null;
        @Nullable String requirement = null;
        Matcher sigkeyMatcher = SIGKEY_PATTERN.matcher(headerValue);
        if (sigkeyMatcher.find()) {
            sigkey = sigkeyMatcher.group(1);
            requirement = switch (sigkey) {
                case SIGKEY_JKT -> AAuthHeaders.REQUIRE_PSEUDONYM;
                case SIGKEY_URI, SIGKEY_X509 -> AAuthHeaders.REQUIRE_IDENTITY;
                default -> null;
            };
        }

        String alg = null;
        Matcher algMatcher = ALG_PATTERN.matcher(headerValue);
        if (algMatcher.find()) {
            alg = algMatcher.group(1);
        }

        List<String> components = new ArrayList<>();
        Matcher componentsMatcher = COMPONENTS_PATTERN.matcher(headerValue);
        if (componentsMatcher.find()) {
            Matcher quoted = QUOTED_PATTERN.matcher(componentsMatcher.group(1));
            while (quoted.find()) {
                components.add(quoted.group(1));
            }
        }

        return new Parsed(sigkey, components, alg, requirement);
    }
}
