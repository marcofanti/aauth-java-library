# aauth-java-library

Java port of `../aauth-python-library` (AAuth protocol: RFC 9421 HTTP Message Signatures +
Signature-Key header + JWT proof-of-possession). The Python library is the reference
implementation — mirror its behavior, module split, and README structure.

## Structure

- `aauth-signing/` — `io.github.marcofanti:aauth-signing`, package
  `io.github.marcofanti.aauth.signing`. Standalone RFC 9421 + Signature-Key. No AAuth deps.
- `aauth/` — `io.github.marcofanti:aauth`, package `io.github.marcofanti.aauth`.
  Full protocol; depends on `aauth-signing`.

## Rules

- JDK 26 target (`--release 26`); Java 26+ required (user decision 2026-07-30).
- Build: `mvn verify` (runs tests, JaCoCo 80% line-coverage gate, Spotless check).
- Format: `mvn spotless:apply` (Palantir Java Format) before committing.
- Zero warnings: compiler runs `-Xlint:all,-serial,-processing -Werror`.
- Immutable value types (records) for parsed headers, claims, results.
- No framework dependencies in the core; HTTP via JDK `java.net.http` behind interfaces.
- Tests use JUnit Jupiter + AssertJ; test HTTP servers via JDK `com.sun.net.httpserver`.

## Docs to keep current

- `docs/PLAN.md` — the approved implementation plan.
- `docs/PROGRESS.md` — phase status, decision log, deviations from the Python library.
  Update both when completing a phase or making a design decision.
