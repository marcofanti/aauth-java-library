package io.github.marcofanti.aauth.headers;

import io.github.marcofanti.aauth.ChallengeException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AAuth protocol headers: requirement levels, challenge building/parsing, capabilities, access
 * tokens and mission binding.
 *
 * <p>Per draft-hardt-aauth-protocol, the {@code AAuth-Requirement} response header conveys
 * AAuth-specific requirements (auth-token, interaction, approval, clarification, claims);
 * pseudonym/identity levels use {@code Accept-Signature} (see {@link AcceptSignatureHeader}).
 */
public final class AAuthHeaders {

    // Requirement levels.
    public static final String REQUIRE_PSEUDONYM = "pseudonym";
    public static final String REQUIRE_IDENTITY = "identity";
    public static final String REQUIRE_AUTH_TOKEN = "auth-token";
    public static final String REQUIRE_INTERACTION = "interaction";
    public static final String REQUIRE_APPROVAL = "approval";
    public static final String REQUIRE_CLARIFICATION = "clarification";
    public static final String REQUIRE_CLAIMS = "claims";

    // Header field names.
    public static final String HEADER_ACCEPT_SIGNATURE = "Accept-Signature";

    /** Deprecated in the spec — use {@link #HEADER_ACCEPT_SIGNATURE}; still parsed for compat. */
    public static final String HEADER_SIGNATURE_REQUIREMENT = "Signature-Requirement";

    public static final String HEADER_AAUTH_REQUIREMENT = "AAuth-Requirement";
    public static final String HEADER_AAUTH_ACCESS = "AAuth-Access";
    public static final String HEADER_AAUTH_CAPABILITIES = "AAuth-Capabilities";
    public static final String HEADER_AAUTH_MISSION = "AAuth-Mission";
    public static final String HEADER_SIGNATURE_ERROR = "Signature-Error";

    // AAuth-Capabilities values.
    public static final String CAPABILITY_INTERACTION = "interaction";
    public static final String CAPABILITY_CLARIFICATION = "clarification";
    public static final String CAPABILITY_PAYMENT = "payment";

    private static final Set<String> AAUTH_PROTOCOL_LEVELS =
            Set.of(REQUIRE_AUTH_TOKEN, REQUIRE_INTERACTION, REQUIRE_APPROVAL, REQUIRE_CLARIFICATION, REQUIRE_CLAIMS);

    private static final Pattern REQUIREMENT_PATTERN = Pattern.compile("requirement=([\\w-]+)");
    private static final Pattern REQUIRE_PATTERN = Pattern.compile("require=([\\w-]+)");
    private static final Pattern QUOTED_PATTERN = Pattern.compile("\"([^\"]+)\"");
    private static final Pattern ACCEPT_SIGNATURE_SHAPE = Pattern.compile("\\s*sig\\d*=\\(");

    private AAuthHeaders() {}

    /**
     * A parsed requirement/challenge header, unified across the {@code AAuth-Requirement},
     * {@code Accept-Signature} and legacy formats. Fields not present in the header are
     * {@code null} (lists empty).
     */
    public record ParsedChallenge(
            String requirement,
            String resourceToken,
            String authServer,
            String url,
            String code,
            List<String> algorithms,
            List<String> requiredInput,
            String sigkey,
            List<String> components,
            String alg) {

        public ParsedChallenge {
            components = components == null ? List.of() : List.copyOf(components);
        }
    }

    // --- Requirement value builders ------------------------------------------------------

    /** Builds a {@code Signature-Requirement} value requiring a pseudonymous signature. */
    public static String buildPseudonymRequirement(List<String> algorithms, List<String> requiredInput) {
        return buildSignatureLevelRequirement(REQUIRE_PSEUDONYM, algorithms, requiredInput);
    }

    /** Builds a {@code Signature-Requirement} value requiring verified agent identity. */
    public static String buildIdentityRequirement(List<String> algorithms, List<String> requiredInput) {
        return buildSignatureLevelRequirement(REQUIRE_IDENTITY, algorithms, requiredInput);
    }

    /**
     * Builds an {@code AAuth-Requirement} value requiring an auth token. The auth server is
     * discovered from the resource token's {@code aud} claim.
     */
    public static String buildAuthTokenRequirement(String resourceToken) {
        return "requirement=auth-token; resource-token=\"" + resourceToken + "\"";
    }

    /** Builds an {@code AAuth-Requirement} value for user interaction. */
    public static String buildInteractionRequirement(String url, String code) {
        return "requirement=interaction; url=\"" + url + "\"; code=\"" + code + "\"";
    }

    /** Builds an {@code AAuth-Requirement} value for approval pending. */
    public static String buildApprovalRequirement() {
        return "requirement=approval";
    }

    /** Builds an {@code AAuth-Requirement} value for clarification (body carries the question). */
    public static String buildClarificationRequirement() {
        return "requirement=clarification";
    }

    /** Builds an {@code AAuth-Requirement} value for claims (body carries required_claims). */
    public static String buildClaimsRequirement() {
        return "requirement=claims";
    }

    private static String buildSignatureLevelRequirement(
            String level, List<String> algorithms, List<String> requiredInput) {
        StringBuilder sb = new StringBuilder("requirement=").append(level);
        if (algorithms != null && !algorithms.isEmpty()) {
            sb.append(", algorithms=(").append(quotedList(algorithms)).append(')');
        }
        if (requiredInput != null && !requiredInput.isEmpty()) {
            sb.append(", required_input=(").append(quotedList(requiredInput)).append(')');
        }
        return sb.toString();
    }

    // --- Parsing --------------------------------------------------------------------------

    /**
     * Parses a {@code Signature-Requirement} / {@code AAuth-Requirement} header value in
     * {@code requirement=...} form.
     *
     * @throws ChallengeException if the value lacks a {@code requirement} parameter
     */
    public static ParsedChallenge parseSignatureRequirement(String headerValue) {
        Matcher requirement = REQUIREMENT_PATTERN.matcher(headerValue);
        if (!requirement.find()) {
            throw new ChallengeException("Signature-Requirement header must include 'requirement' parameter");
        }
        return new ParsedChallenge(
                requirement.group(1),
                quotedParam(headerValue, "resource-token"),
                quotedParam(headerValue, "auth-server"),
                quotedParam(headerValue, "url"),
                quotedParam(headerValue, "code"),
                innerList(headerValue, "algorithms"),
                innerList(headerValue, "required_input"),
                null,
                null,
                null);
    }

    /**
     * Parses any AAuth challenge header value: {@code Accept-Signature} form,
     * {@code requirement=...} form, or the legacy {@code require=...} form.
     *
     * @throws ChallengeException if none of the known shapes is present
     */
    public static ParsedChallenge parseAAuthHeader(String headerValue) {
        if (headerValue.contains("sigkey=")
                || ACCEPT_SIGNATURE_SHAPE.matcher(headerValue).lookingAt()) {
            AcceptSignatureHeader.Parsed parsed = AcceptSignatureHeader.parse(headerValue);
            return new ParsedChallenge(
                    parsed.requirement(),
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    parsed.sigkey(),
                    parsed.components(),
                    parsed.alg());
        }
        if (headerValue.contains("requirement=")) {
            return parseSignatureRequirement(headerValue);
        }
        if (headerValue.contains("require=")) {
            Matcher require = REQUIRE_PATTERN.matcher(headerValue);
            String level = require.find() ? require.group(1) : null;
            return new ParsedChallenge(
                    level,
                    quotedParam(headerValue, "resource-token"),
                    quotedParam(headerValue, "auth-server"),
                    quotedParam(headerValue, "url"),
                    quotedParam(headerValue, "code"),
                    null,
                    null,
                    null,
                    null,
                    null);
        }
        throw new ChallengeException("Header must include 'requirement', 'require', or 'sigkey' parameter");
    }

    /** Requirement levels that MUST use the {@code AAuth-Requirement} response header. */
    public static Set<String> aauthProtocolRequirementLevels() {
        return AAUTH_PROTOCOL_LEVELS;
    }

    /**
     * Returns the response header name for a requirement level: {@code Accept-Signature} for
     * pseudonym/identity, {@code AAuth-Requirement} for all AAuth-specific levels.
     */
    public static String requirementHeaderForLevel(String requirementLevel) {
        if (REQUIRE_PSEUDONYM.equals(requirementLevel) || REQUIRE_IDENTITY.equals(requirementLevel)) {
            return HEADER_ACCEPT_SIGNATURE;
        }
        return HEADER_AAUTH_REQUIREMENT;
    }

    /**
     * Extracts the challenge header value from response headers (case-insensitive), checking
     * {@code AAuth-Requirement}, {@code Accept-Signature}, {@code Signature-Requirement}
     * (deprecated) and legacy {@code AAuth} / {@code Agent-Auth}. Returns {@code ""} when none
     * is present.
     */
    public static String getChallengeHeaderValue(Map<String, String> headers) {
        if (headers == null) {
            return "";
        }
        for (String name :
                List.of("aauth-requirement", "accept-signature", "signature-requirement", "aauth", "agent-auth")) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(name)
                        && entry.getValue() != null
                        && !entry.getValue().isEmpty()) {
                    return entry.getValue();
                }
            }
        }
        return "";
    }

    // --- Capabilities, access, mission ----------------------------------------------------

    /** Builds an {@code AAuth-Capabilities} request header value, e.g. {@code interaction, payment}. */
    public static String buildCapabilitiesHeader(List<String> capabilities) {
        return String.join(", ", capabilities);
    }

    /** Parses an {@code AAuth-Capabilities} header into capability tokens. */
    public static List<String> parseCapabilitiesHeader(String headerValue) {
        List<String> capabilities = new ArrayList<>();
        for (String part : headerValue.split(",")) {
            String token = part.strip();
            if (!token.isEmpty()) {
                capabilities.add(token);
            }
        }
        return capabilities;
    }

    /**
     * Extracts the opaque token from an {@code Authorization: AAuth <token>} request header.
     * Returns {@code null} when the header is not an AAuth bearer.
     */
    public static String parseAuthorizationAAuthHeader(String headerValue) {
        if (headerValue != null && headerValue.toLowerCase().startsWith("aauth ")) {
            String token = headerValue.substring(6).strip();
            return token.isEmpty() ? null : token;
        }
        return null;
    }

    /** Parsed {@code AAuth-Mission} header. */
    public record Mission(String approver, String s256) {}

    /** Builds an {@code AAuth-Mission} request header value per spec §8.2. */
    public static String buildMissionHeader(String approver, String s256) {
        return "approver=\"" + approver + "\"; s256=\"" + s256 + "\"";
    }

    /** Parses an {@code AAuth-Mission} header (accepts legacy {@code manager=} for approver). */
    public static Mission parseMissionHeader(String headerValue) {
        String approver = quotedParam(headerValue, "approver");
        if (approver == null) {
            approver = quotedParam(headerValue, "manager");
        }
        return new Mission(approver, quotedParam(headerValue, "s256"));
    }

    // --- Helpers ---------------------------------------------------------------------------

    private static String quotedParam(String headerValue, String name) {
        Matcher matcher = Pattern.compile(name + "=\"([^\"]+)\"").matcher(headerValue);
        return matcher.find() ? matcher.group(1) : null;
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
