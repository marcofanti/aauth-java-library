package io.github.marcofanti.aauth.interop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.signing.RequestSigner;
import io.github.marcofanti.aauth.signing.SignRequest;
import io.github.marcofanti.aauth.signing.SignatureScheme;
import io.github.marcofanti.aauth.signing.SignatureVerifier;
import io.github.marcofanti.aauth.signing.VerifyRequest;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import io.github.marcofanti.aauth.tokens.AgentTokens;
import io.github.marcofanti.aauth.tokens.AuthTokens;
import io.github.marcofanti.aauth.tokens.PersonTokens;
import io.github.marcofanti.aauth.tokens.ResourceTokens;
import io.github.marcofanti.aauth.tokens.TokenVerifier;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Draft-11 cross-implementation interop against the Python reference library (aauth 0.5.0).
 *
 * <p>Runs the Python side via {@code uv run} in the checkout named by the {@code AAUTH_PYTHON_LIB}
 * environment variable, defaulting to {@code ../aauth-python-library}. Skipped when {@code uv} or
 * the checkout is unavailable (as in CI).
 */
class PythonInteropTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final Path PYTHON_LIB = pythonLib();

    private static final String RESOURCE = "https://gateway.uma.lab";
    private static final String PS = "https://ps.uma.lab";
    private static final String AP = "https://portal.uma.lab";
    private static final String AGENT_ID = "aauth:Agent@portal.uma.lab";

    private record PythonResult(int exitCode, String stdout, String stderr) {}

    private static Path pythonLib() {
        String override = System.getenv("AAUTH_PYTHON_LIB");
        Path path = override != null && !override.isBlank()
                ? Paths.get(override)
                : Paths.get("..", "..", "aauth-python-library");
        return path.toAbsolutePath().normalize();
    }

    @BeforeAll
    static void requirePythonEnvironment() {
        assumeTrue(Files.isDirectory(PYTHON_LIB), "aauth-python-library checkout not found at " + PYTHON_LIB);
        try {
            PythonResult probe = runPython("import aauth; print(aauth.__version__)", "");
            assumeTrue(probe.exitCode() == 0, "uv/aauth unavailable: " + probe.stderr());
            assumeTrue(
                    probe.stdout().startsWith("0.5"),
                    "interop targets the draft-11 reference (aauth 0.5.x), found " + probe.stdout());
        } catch (IOException | InterruptedException e) {
            assumeTrue(false, "uv not runnable: " + e.getMessage());
        }
    }

    private static PythonResult runPython(String script, String stdin) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder("uv", "run", "python", "-c", script);
        pb.directory(PYTHON_LIB.toFile());
        Process process = pb.start();
        process.getOutputStream().write(stdin.getBytes(StandardCharsets.UTF_8));
        process.getOutputStream().close();
        boolean finished = process.waitFor(120, TimeUnit.SECONDS);
        String stdout = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        String stderr = new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!finished) {
            process.destroyForcibly();
            throw new IOException("python interop process timed out");
        }
        return new PythonResult(process.exitValue(), stdout.strip(), stderr);
    }

    /** Runs a script fed {@code input} as JSON on stdin and parses the JSON it prints. */
    private static Map<String, Object> python(String script, Map<String, Object> input) throws Exception {
        PythonResult result = runPython(script, MAPPER.writeValueAsString(input));
        assertThat(result.exitCode()).as(result.stderr()).isZero();
        return MAPPER.readValue(result.stdout(), MAP_TYPE);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) {
        return (Map<String, Object>) value;
    }

    private static JwksFetcher fetcherFor(Map<String, Map<String, Object>> jwksByIssuer) {
        return (id, dwk, kid) -> jwksByIssuer.get(id);
    }

    // --- HTTP message signatures ---------------------------------------------------------

    @Test
    void javaSignedRequestWithBodyVerifiesInPython() throws Exception {
        KeyPair keyPair = KeyPairs.generateEd25519();
        String target = RESOURCE + "/api/data?x=1";
        byte[] body = "{\"amount\":1}".getBytes(StandardCharsets.UTF_8);
        Map<String, String> headers = new LinkedHashMap<>(Map.of("Content-Type", "application/json"));
        headers.putAll(RequestSigner.sign(SignRequest.builder("POST", target)
                .keyPair(keyPair)
                .headers(headers)
                .body(body)
                .additionalComponents(List.of("content-type", "content-digest"))
                .scheme(new SignatureScheme.Hwk())
                .build()));

        Map<String, Object> out = python(
                """
                import sys, json, aauth
                d = json.load(sys.stdin)
                h = d["headers"]
                def check(body):
                    return aauth.verify_signature(
                        "POST", d["target"], h, body, h["Signature-Input"], h["Signature"], h["Signature-Key"],
                        required_components=["@method", "@authority", "@path", "signature-key",
                                             "content-digest", "content-type"])
                print(json.dumps({"valid": check(d["body"].encode()), "tampered": check(b'{"amount":9}')}))
                """, Map.of("target", target, "headers", headers, "body", new String(body, StandardCharsets.UTF_8)));

        assertThat(out).containsEntry("valid", true).containsEntry("tampered", false);
    }

    @Test
    void pythonSignedRequestWithBodyVerifiesInJava() throws Exception {
        Map<String, Object> out = python("""
                import sys, json, aauth
                key, _ = aauth.generate_ed25519_keypair()
                target = "https://gateway.uma.lab/api/items?q=abc"
                body = b'{"hello":"world"}'
                headers = {"Content-Type": "application/json"}
                headers.update(aauth.sign_request("POST", target, headers, body, key, sig_scheme="hwk",
                    additional_signature_components=["content-type", "content-digest"]))
                print(json.dumps({"target": target, "headers": headers, "body": body.decode()}))
                """, Map.of());
        @SuppressWarnings("unchecked")
        Map<String, String> headers = (Map<String, String>) (Map<?, ?>) out.get("headers");

        boolean valid = SignatureVerifier.verify(VerifyRequest.builder(
                        "POST", out.get("target").toString())
                .headers(headers)
                .body(out.get("body").toString().getBytes(StandardCharsets.UTF_8))
                .signatureHeaders(
                        headers.get("Signature-Input"), headers.get("Signature"), headers.get("Signature-Key"))
                .requiredComponents(List.of("@method", "@authority", "@path", "signature-key", "content-digest"))
                .build());

        assertThat(valid).isTrue();
        assertThat(headers.get("Signature-Key")).contains("alg=\"Ed25519\"");
    }

    // --- Agent tokens --------------------------------------------------------------------

    @Test
    void javaAgentTokenVerifiesInPython() throws Exception {
        KeyPair issuerKeys = KeyPairs.generateEd25519();
        String token = AgentTokens.create(AgentTokens.Spec.builder(
                        AP,
                        AGENT_ID,
                        Jwk.publicKeyToJwk(KeyPairs.generateEd25519().getPublic(), null),
                        issuerKeys.getPrivate(),
                        "key-1")
                .ps(PS)
                .build());

        Map<String, Object> out = python(
                """
                import sys, json, aauth
                d = json.load(sys.stdin)
                p = aauth.verify_agent_token(d["token"], lambda *a: d["jwks"])
                print(json.dumps({"sub": p["sub"], "ps": p["ps"],
                                  "alg": aauth.parse_token_claims(d["token"])["header"]["alg"]}))
                """,
                Map.of(
                        "token",
                        token,
                        "jwks",
                        Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(issuerKeys.getPublic(), "key-1")))));

        assertThat(out).containsEntry("sub", AGENT_ID).containsEntry("ps", PS).containsEntry("alg", "Ed25519");
    }

    @Test
    void pythonAgentTokenVerifiesInJava() throws Exception {
        Map<String, Object> out = python("""
                import sys, json, aauth
                key, pub = aauth.generate_ed25519_keypair()
                _, agent = aauth.generate_ed25519_keypair()
                token = aauth.create_agent_token("https://portal.uma.lab", "aauth:Agent@portal.uma.lab",
                    aauth.public_key_to_jwk(agent), key, "key-1", ps="https://ps.uma.lab")
                print(json.dumps({"token": token, "jwks": aauth.generate_jwks([aauth.public_key_to_jwk(pub, kid="key-1")])}))
                """, Map.of());

        Map<String, Object> claims =
                AgentTokens.verify(out.get("token").toString(), (id, dwk, kid) -> map(out.get("jwks")), null);
        assertThat(claims).containsEntry("sub", AGENT_ID).containsEntry("ps", PS);
    }

    // --- Person and auth tokens ----------------------------------------------------------

    @Test
    void pythonPersonAndAuthTokensVerifyInJava() throws Exception {
        KeyPair agentKeys = KeyPairs.generateEd25519();
        Map<String, Object> agentJwk = Jwk.publicKeyToJwk(agentKeys.getPublic(), null);
        long now = Instant.now().getEpochSecond();

        Map<String, Object> out = python("""
                import sys, json, aauth
                d = json.load(sys.stdin)
                key, pub = aauth.generate_ed25519_keypair()
                person = aauth.create_person_token("https://ps.uma.lab", "https://gateway.uma.lab", "person-1",
                    d["jwk"], key, "ps-1", agent_exp=d["now"] + 600, tenant="tenant-1")
                auth = aauth.create_auth_token("https://ps.uma.lab", "https://gateway.uma.lab", d["jwk"], key, "ps-1",
                    ps="https://ps.uma.lab", sub="person-1", agent_exp=d["now"] + 600, presented_exp=d["now"] + 500,
                    scope="data.read", dwk="aauth-person.json")
                print(json.dumps({"person": person, "auth": auth,
                                  "jwks": aauth.generate_jwks([aauth.public_key_to_jwk(pub, kid="ps-1")])}))
                """, Map.of("jwk", agentJwk, "now", now));
        JwksFetcher fetcher = (id, dwk, kid) -> map(out.get("jwks"));

        Map<String, Object> person = PersonTokens.verify(
                out.get("person").toString(),
                fetcher,
                TokenVerifier.Options.forType(null).withAudience(RESOURCE).withRequestSigningJwk(agentJwk));
        assertThat(person).containsEntry("sub", "person-1").containsEntry("tenant", "tenant-1");

        Map<String, Object> auth = TokenVerifier.verify(
                out.get("auth").toString(),
                fetcher,
                TokenVerifier.Options.forType(AuthTokens.TYPE)
                        .withAudience(RESOURCE)
                        .withRequestSigningJwk(agentJwk));
        assertThat(auth)
                .containsEntry("scope", "data.read")
                .containsEntry("ps", PS)
                .doesNotContainKeys("agent", "act");
        assertThat(((Number) auth.get("exp")).longValue()).isLessThanOrEqualTo(now + 500);
    }

    @Test
    void javaPersonAndAuthTokensVerifyInPython() throws Exception {
        KeyPair psKeys = KeyPairs.generateEd25519();
        Map<String, Object> agentJwk =
                Jwk.publicKeyToJwk(KeyPairs.generateEd25519().getPublic(), null);
        long now = Instant.now().getEpochSecond();
        String person = PersonTokens.create(
                PersonTokens.Spec.builder(PS, RESOURCE, "person-1", agentJwk, psKeys.getPrivate(), "ps-1")
                        .agentExp(now + 600)
                        .mission("m".repeat(43), now + 600)
                        .build());
        String auth = AuthTokens.create(AuthTokens.Spec.builder(PS, RESOURCE, "person-1", PS)
                .cnfJwk(agentJwk)
                .signingKey(psKeys.getPrivate(), "ps-1")
                .bounds(now + 600, now + 500)
                .dwk(AuthTokens.DWK_PERSON)
                .scope("data.read")
                .build());

        Map<String, Object> out = python(
                """
                import sys, json, aauth
                d = json.load(sys.stdin)
                fetch = lambda *a: d["jwks"]
                p = aauth.verify_person_token(d["person"], fetch, expected_aud="https://gateway.uma.lab",
                    request_signing_jwk=d["jwk"])
                a = aauth.verify_token(d["auth"], fetch, expected_typ="aa-auth+jwt",
                    expected_aud="https://gateway.uma.lab", request_signing_jwk=d["jwk"])
                print(json.dumps({"person_mission": p["mission_s256"], "auth_scope": a["scope"], "auth_ps": a["ps"]}))
                """,
                Map.of(
                        "person", person,
                        "auth", auth,
                        "jwk", agentJwk,
                        "jwks", Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(psKeys.getPublic(), "ps-1")))));

        assertThat(out)
                .containsEntry("person_mission", "m".repeat(43))
                .containsEntry("auth_scope", "data.read")
                .containsEntry("auth_ps", PS);
    }

    // --- Resource tokens bound to presented tokens --------------------------------------------

    @Test
    void javaResourceTokenFromPythonPersonTokenVerifiesInPython() throws Exception {
        KeyPair agentKeys = KeyPairs.generateEd25519();
        KeyPair resourceKeys = KeyPairs.generateEd25519();
        Map<String, Object> agentJwk = Jwk.publicKeyToJwk(agentKeys.getPublic(), null);
        long now = Instant.now().getEpochSecond();

        Map<String, Object> issued = python("""
                import sys, json, aauth
                d = json.load(sys.stdin)
                key, pub = aauth.generate_ed25519_keypair()
                person = aauth.create_person_token("https://ps.uma.lab", "https://gateway.uma.lab", "person-1",
                    d["jwk"], key, "ps-1", agent_exp=d["now"] + 600, mission_s256="m" * 43,
                    mission_exp=d["now"] + 600)
                print(json.dumps({"person": person,
                                  "jwks": aauth.generate_jwks([aauth.public_key_to_jwk(pub, kid="ps-1")])}))
                """, Map.of("jwk", agentJwk, "now", now));
        String person = issued.get("person").toString();
        Map<String, Object> resourceJwks =
                Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(resourceKeys.getPublic(), "r-1")));

        String resourceToken = ResourceTokens.create(ResourceTokens.Spec.builder(
                        RESOURCE, PS, Jwk.thumbprint(agentJwk), resourceKeys.getPrivate(), "r-1")
                .presentedToken(person, fetcherFor(Map.of(PS, map(issued.get("jwks")))))
                .scope("data.read")
                .build());

        Map<String, Object> out = python(
                """
                import sys, json, aauth
                d = json.load(sys.stdin)
                fetch = lambda iss, *a: d["jwks"][iss]
                p = aauth.verify_resource_token(d["rt"], fetch, presented_token=d["person"],
                    expected_aud="https://ps.uma.lab", expected_ps="https://ps.uma.lab",
                    expected_agent_jkt=aauth.calculate_jwk_thumbprint(d["jwk"]), mission_checker=lambda s: True)
                print(json.dumps({"sub": p["sub"], "presented_jti": p["presented_jti"], "mission": p["mission_s256"]}))
                """,
                Map.of(
                        "rt", resourceToken,
                        "person", person,
                        "jwk", agentJwk,
                        "jwks", Map.of(PS, issued.get("jwks"), RESOURCE, resourceJwks)));

        assertThat(out).containsEntry("sub", "person-1").containsEntry("mission", "m".repeat(43));
        assertThat(out.get("presented_jti"))
                .isEqualTo(
                        AuthTokens.parseTokenClaims(person).get("payload") instanceof Map<?, ?> p
                                ? p.get("jti")
                                : null);
    }

    @Test
    void pythonResourceTokenVerifiesInJava() throws Exception {
        KeyPair agentKeys = KeyPairs.generateEd25519();
        Map<String, Object> agentJwk = Jwk.publicKeyToJwk(agentKeys.getPublic(), null);
        long now = Instant.now().getEpochSecond();

        Map<String, Object> out = python("""
                import sys, json, aauth
                d = json.load(sys.stdin)
                ps_key, ps_pub = aauth.generate_ed25519_keypair()
                rs_key, rs_pub = aauth.generate_ed25519_keypair()
                jwks = {"https://ps.uma.lab": aauth.generate_jwks([aauth.public_key_to_jwk(ps_pub, kid="ps-1")]),
                        "https://gateway.uma.lab": aauth.generate_jwks([aauth.public_key_to_jwk(rs_pub, kid="r-1")])}
                person = aauth.create_person_token("https://ps.uma.lab", "https://gateway.uma.lab", "person-1",
                    d["jwk"], ps_key, "ps-1", agent_exp=d["now"] + 600, tenant="tenant-1")
                rt = aauth.create_resource_token("https://gateway.uma.lab", "https://ps.uma.lab",
                    aauth.calculate_jwk_thumbprint(d["jwk"]), rs_key, "r-1", presented_token=person,
                    jwks_fetcher=lambda iss, *a: jwks[iss], scope="data.read")
                print(json.dumps({"person": person, "rt": rt, "jwks": jwks}))
                """, Map.of("jwk", agentJwk, "now", now));
        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> jwks = (Map<String, Map<String, Object>>) (Map<?, ?>) out.get("jwks");

        Map<String, Object> claims = ResourceTokens.verify(
                out.get("rt").toString(),
                fetcherFor(jwks),
                new ResourceTokens.VerifyOptions(
                        out.get("person").toString(), PS, RESOURCE, PS, Jwk.thumbprint(agentJwk), null, null));

        assertThat(claims)
                .containsEntry("sub", "person-1")
                .containsEntry("ps", PS)
                .containsEntry("tenant", "tenant-1")
                .containsEntry("scope", "data.read");
    }

    // --- jwt scheme: an HTTP signature carrying an agent token --------------------------------

    @Test
    void javaJwtSchemeSignatureVerifiesInPython() throws Exception {
        KeyPair issuerKeys = KeyPairs.generateEd25519();
        KeyPair agentKeys = KeyPairs.generateEd25519();
        String agentToken = AgentTokens.create(AgentTokens.Spec.builder(
                        AP, AGENT_ID, Jwk.publicKeyToJwk(agentKeys.getPublic(), null), issuerKeys.getPrivate(), "key-1")
                .build());
        String target = RESOURCE + "/api/data";
        Map<String, String> headers = RequestSigner.sign(SignRequest.builder("GET", target)
                .keyPair(agentKeys)
                .scheme(new SignatureScheme.Jwt(agentToken))
                .build());

        Map<String, Object> out = python(
                """
                import sys, json, aauth
                d = json.load(sys.stdin)
                h = d["headers"]
                ok = aauth.verify_signature("GET", d["target"], h, None, h["Signature-Input"], h["Signature"],
                    h["Signature-Key"], jwks_fetcher=lambda *a: d["jwks"])
                print(json.dumps({"valid": ok}))
                """,
                Map.of(
                        "target", target,
                        "headers", headers,
                        "jwks", Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(issuerKeys.getPublic(), "key-1")))));

        assertThat(out).containsEntry("valid", true);
    }
}
