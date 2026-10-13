# Releasing to Maven Central

The build is already wired for Central publishing (the `release` Maven profile adds sources
and javadoc jars, GPG signing, and the Central Portal upload). Two one-time setup steps must
be done by a human; after that, a release is one script run: `./release.sh <version>`.

## One-time setup

### 1. Central Portal account + namespace

1. Sign in at <https://central.sonatype.com> **with your GitHub account** (`marcofanti`).
2. Signing in with GitHub automatically verifies the `io.github.marcofanti` namespace.
3. Generate a **user token** (Account → Generate User Token) and put it in
   `~/.m2/settings.xml`:

   ```xml
   <settings>
     <servers>
       <server>
         <id>central</id>
         <username><!-- token username --></username>
         <password><!-- token password --></password>
       </server>
     </servers>
   </settings>
   ```

   The `id` must be `central` (it matches `publishingServerId` in the parent POM).
   Never commit these credentials.

### 2. GPG signing key

```bash
gpg --gen-key                          # name: Marco Fanti, email: your GitHub email
gpg --list-keys --keyid-format long    # note the key ID (after ed25519/ or rsa4096/)
gpg --keyserver keyserver.ubuntu.com --send-keys <KEY_ID>
```

Central verifies signatures against public keyservers; sending the key once is enough.
The `maven-gpg-plugin` uses `gpg-agent`, so you'll be prompted for the passphrase on the
first signing of a session.

## Release procedure

Run the release script from a clean, up-to-date `main`:

```bash
./release.sh --dry-run 0.1.1   # preflight only: git state, credentials, GPG, mvn verify
./release.sh 0.1.1             # the real thing
```

The script does, in order:

1. **Preflight** — verifies you're on a clean `main` in sync with origin, the `v0.1.1` tag
   doesn't exist, Maven is 3.9.x (see Notes), `~/.m2/settings.xml` has real `central`
   credentials, GPG can actually sign (fails early on the pinentry/`GPG_TTY` problem), and
   `mvn verify` is green.
2. Sets the version in all three POMs, commits `release: 0.1.1`, tags `v0.1.1`.
3. `mvn clean deploy -Prelease` — builds, signs, and uploads to the Central Portal.
4. Bumps to the next snapshot (defaults to the next minor, e.g. `0.2.0-SNAPSHOT`; pass a
   second argument to override), commits, and pushes `main` plus the tag.
5. Prints the last manual step: press **Publish** on the validated deployment at
   <https://central.sonatype.com/publishing>. (To skip the manual press, add
   `<autoPublish>true</autoPublish>` to the central-publishing-maven-plugin config.)

If anything fails before the push, git has not left your machine; the script prints the
two-line local rollback (`git tag -d`, `git reset --hard origin/main`). If the failure came
after the upload in step 3, Central also holds a FAILED deployment; it is never published,
and you can drop it at <https://central.sonatype.com/publishing>.

Artifacts appear on Maven Central (search.maven.org) within an hour of publishing:

```xml
<dependency>
  <groupId>io.github.marcofanti</groupId>
  <artifactId>aauth</artifactId>          <!-- or aauth-signing for the signing layer only -->
  <version>0.1.1</version>
</dependency>
```

## Notes

- Release with Maven 3.9.x. Maven 3.10+ puts local-repository files
  (`maven-metadata-local.xml`, `_remote.repositories`) into the central-publishing staging
  bundle, and Central rejects it ("Bundle has content that does NOT have a .pom file"). The
  0.3.0 release hit this with Homebrew's Maven 3.10.0 and went out with 3.9.16. The script
  refuses 3.10+; put a 3.9.x `bin` first on `PATH` for the release.

- `mvn verify -Prelease -Dgpg.skip=true` exercises the sources/javadoc jar generation
  without needing the GPG key (useful as a pre-release smoke test; CI does not run the
  release profile).
- Javadoc runs with `doclint` on (missing-comment checks relaxed); a javadoc error fails
  the release build rather than shipping a broken javadoc jar.
