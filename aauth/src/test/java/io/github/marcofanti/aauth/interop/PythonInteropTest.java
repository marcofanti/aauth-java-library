package io.github.marcofanti.aauth.interop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.marcofanti.aauth.signing.RequestSigner;
import io.github.marcofanti.aauth.signing.SignRequest;
import io.github.marcofanti.aauth.signing.SignatureScheme;
import io.github.marcofanti.aauth.signing.SignatureVerifier;
import io.github.marcofanti.aauth.signing.VerifyRequest;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import io.github.marcofanti.aauth.tokens.AgentTokens;
import io.github.marcofanti.aauth.tokens.AuthTokens;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Cross-implementation interop tests against the Python reference library.
 *
 * <p>Runs the Python side via {@code uv run} inside {@code ../aauth-python-library}. Skipped
 * when {@code uv} or the Python library checkout is not available.
 */
class PythonInteropTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final Path PYTHON_LIB =
            Paths.get("..", "..", "aauth-python-library").toAbsolutePath().normalize();

    private record PythonResult(int exitCode, String stdout, String stderr) {}

    @BeforeAll
    static void requirePythonEnvironment() {
        assumeTrue(Files.isDirectory(PYTHON_LIB), "aauth-python-library checkout not found");
        try {
            PythonResult probe = runPython("import aauth; print('ok')", "");
            assumeTrue(
                    probe.exitCode() == 0 && probe.stdout().contains("ok"), "uv/aauth unavailable: " + probe.stderr());
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

    @Test
    void javaSignedRequestVerifiesInPython() throws Exception {
        KeyPair keyPair = KeyPairs.generateEd25519();
        String target = "https://resource.example/api/data?x=1";
        Map<String, String> signed = RequestSigner.sign(SignRequest.builder("GET", target)
                .keyPair(keyPair)
                .scheme(new SignatureScheme.Hwk())
                .build());

        String payload = MAPPER.writeValueAsString(Map.of("method", "GET", "target", target, "headers", signed));
        String script = """
                import sys, json, aauth
                data = json.load(sys.stdin)
                h = data["headers"]
                ok = aauth.verify_signature(
                    method=data["method"], target_uri=data["target"], headers=h, body=None,
                    signature_input_header=h["Signature-Input"],
                    signature_header=h["Signature"],
                    signature_key_header=h["Signature-Key"])
                print("VALID" if ok else "INVALID")
                """;

        PythonResult result = runPython(script, payload);

        assertThat(result.exitCode()).as(result.stderr()).isZero();
        assertThat(result.stdout()).isEqualTo("VALID");
    }

    @Test
    void pythonSignedRequestVerifiesInJava() throws Exception {
        String script = """
                import json, aauth
                private_key, _ = aauth.generate_ed25519_keypair()
                target = "https://resource.example/api/items?q=abc"
                headers = aauth.sign_request(
                    method="POST", target_uri=target, headers={}, body=None,
                    private_key=private_key, sig_scheme="hwk")
                print(json.dumps({"target": target, "headers": headers}))
                """;
        PythonResult result = runPython(script, "");
        assertThat(result.exitCode()).as(result.stderr()).isZero();

        Map<String, Object> data = MAPPER.readValue(result.stdout(), MAP_TYPE);
        @SuppressWarnings("unchecked")
        Map<String, String> headers = (Map<String, String>) (Map<?, ?>) data.get("headers");

        boolean valid = SignatureVerifier.verify(
                VerifyRequest.builder("POST", data.get("target").toString())
                        .headers(headers)
                        .signatureHeaders(
                                headers.get("Signature-Input"), headers.get("Signature"), headers.get("Signature-Key"))
                        .build());

        assertThat(valid).isTrue();
    }

    @Test
    void javaAgentTokenVerifiesInPython() throws Exception {
        KeyPair issuerKeys = KeyPairs.generateEd25519();
        KeyPair delegateKeys = KeyPairs.generateEd25519();
        String token = AgentTokens.create(AgentTokens.Spec.builder(
                        "https://agent.example",
                        "delegate-1",
                        Jwk.publicKeyToJwk(delegateKeys.getPublic(), null),
                        issuerKeys.getPrivate(),
                        "key-1")
                .build());
        Map<String, Object> jwks = Jwk.generateJwks(List.of(Jwk.publicKeyToJwk(issuerKeys.getPublic(), "key-1")));

        String payload = MAPPER.writeValueAsString(Map.of("token", token, "jwks", jwks));
        String script = """
                import sys, json, aauth
                data = json.load(sys.stdin)
                claims = aauth.verify_agent_token(data["token"], lambda iss: data["jwks"])
                print("SUB=" + claims["sub"])
                """;

        PythonResult result = runPython(script, payload);

        assertThat(result.exitCode()).as(result.stderr()).isZero();
        assertThat(result.stdout()).isEqualTo("SUB=delegate-1");
    }

    @Test
    void pythonAuthTokenVerifiesInJava() throws Exception {
        String script = """
                import json, aauth
                private_key, public_key = aauth.generate_ed25519_keypair()
                agent_private, agent_public = aauth.generate_ed25519_keypair()
                agent_jwk = aauth.public_key_to_jwk(agent_public)
                token = aauth.create_auth_token(
                    iss="https://auth.example", aud="https://resource.example",
                    agent="aauth:agent@agent.example", cnf_jwk=agent_jwk,
                    act={"sub": "aauth:agent@agent.example"}, scope="data.read",
                    private_key=private_key, kid="as-key-1")
                jwks = aauth.generate_jwks([aauth.public_key_to_jwk(public_key, kid="as-key-1")])
                print(json.dumps({"token": token, "jwks": jwks}))
                """;
        PythonResult result = runPython(script, "");
        assertThat(result.exitCode()).as(result.stderr()).isZero();

        Map<String, Object> data = MAPPER.readValue(result.stdout(), MAP_TYPE);
        @SuppressWarnings("unchecked")
        Map<String, Object> jwks = (Map<String, Object>) data.get("jwks");

        Map<String, Object> claims = AuthTokens.verifyToken(
                data.get("token").toString(),
                iss -> jwks,
                new AuthTokens.VerifyOptions(
                        AuthTokens.TYPE,
                        "https://auth.example",
                        "https://resource.example",
                        "aauth:agent@agent.example",
                        null));

        assertThat(claims).containsEntry("scope", "data.read");
    }
}
