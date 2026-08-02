# Releasing to Maven Central

The build is already wired for Central publishing (the `release` Maven profile adds sources
and javadoc jars, GPG signing, and the Central Portal upload). Two one-time setup steps must
be done by a human; after that, releases are a short procedure.

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

```bash
# 1. Start from a green main
git checkout main && git pull && mvn verify

# 2. Set the release version (drop -SNAPSHOT) in all three POMs
mvn versions:set -DnewVersion=0.1.0 && mvn versions:commit

# 3. Commit and tag (via PR per repo convention, or directly if you prefer for releases)
git commit -am "release: 0.1.0" && git tag v0.1.0

# 4. Build, sign and upload to the Central Portal
mvn clean deploy -Prelease

# 5. Publish: the artifacts land in https://central.sonatype.com/publishing as a
#    validated deployment — press "Publish" there. (To skip the manual press, add
#    <autoPublish>true</autoPublish> to the central-publishing-maven-plugin config.)

# 6. Bump back to the next snapshot and push
mvn versions:set -DnewVersion=0.2.0-SNAPSHOT && mvn versions:commit
git commit -am "chore: bump to 0.2.0-SNAPSHOT" && git push && git push --tags
```

Artifacts appear on Maven Central (search.maven.org) within an hour of publishing:

```xml
<dependency>
  <groupId>io.github.marcofanti</groupId>
  <artifactId>aauth</artifactId>          <!-- or aauth-signing for the signing layer only -->
  <version>0.1.0</version>
</dependency>
```

## Notes

- `mvn verify -Prelease -Dgpg.skip=true` exercises the sources/javadoc jar generation
  without needing the GPG key (useful as a pre-release smoke test; CI does not run the
  release profile).
- Javadoc runs with `doclint` on (missing-comment checks relaxed); a javadoc error fails
  the release build rather than shipping a broken javadoc jar.
