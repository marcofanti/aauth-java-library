# aauth-java-library

**Source:** https://github.com/marcofanti/aauth-java-library (authored locally) — port of https://github.com/christian-posta/aauth-python-library
**Stack:** Java 26, Maven multi-module (io.github.marcofanti:aauth-signing, io.github.marcofanti:aauth)

Java implementation of the AAuth protocol (github.com/dickhardt/AAuth) — agent-to-resource
authorization built on HTTP Message Signatures (RFC 9421) with the Signature-Key header
extension (hwk, jkt-jwt, jwks_uri, jwt schemes) and JWT proof-of-possession tokens
(agent/auth/resource). Wire-compatible with the sibling `aauth-python-library`: cross-language
interop tests sign in one library and verify in the other. Only third-party runtime dependency
is Jackson; all crypto is JDK-native.

## Running it

```bash
mvn verify        # build + 187 tests + coverage/format gates (requires Java 26+, Maven 3.9+)
```

Interop tests additionally need `uv` and the `../aauth-python-library` checkout.
