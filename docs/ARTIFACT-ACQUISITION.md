# Artifact acquisition

The initial lock selects Neo4j Community 2026.10.2 from
`https://dist.neo4j.org/neo4j-community-2026.10.2-unix.tar.gz`.
Its `.sha256` sidecar matches the downloaded archive. The deployment centre
links this checksum. No detached tarball signature is published on this path
(the `.asc` and `.sig` endpoints were checked); the Linux tarball instructions
provide no signature procedure. This is a limitation of the selected artifact
path, not a claim about all Neo4j distribution channels. A checksum fetched
from the same publisher is not independent proof of publisher identity.

Temurin JRE 25.0.5+8 comes from Adoptium's official GitHub release. Its archive
and detached signature are digest locked. GPG must verify a VALIDSIG under
`3B04D753C9050D9A5D343F39843C48A565F8F04B`, documented by
[Adoptium](https://adoptium.net/installation/gpg-verification/).
The public key is vendored and hashed. No private signing key is used.
[Neo4j requirements](https://neo4j.com/docs/operations-manual/current/installation/requirements/)
list Java 25 for versions from 2025.10; this is not a platform support claim for
this image. Native CI is the integration evidence.

The newest observed UBI 9.8 indexes are resolved live from Red Hat's registry.
The resolver checks the response digest against the index bytes and requires
exactly one linux/amd64 and linux/arm64 descriptor. The lock records both.
Refresh re-resolves the tag; normal builds use only locked digests.

The runtime delta is libstdc++ and zlib. The resolver records their exact NEVRA,
architecture, URL and SHA-256 from UBI BaseOS metadata. Acquisition checks the
bytes, queries the NEVRA, and verifies the Red Hat signature in a temporary RPM
database containing only the pinned Red Hat keys. Offline assembly checks the
signature again against the UBI Micro key database and lets RPM enforce the
runtime dependency closure. No online resolver runs in the image build.
Packages already in UBI are locked by its image digest; added RPMs are locked
individually. Acquisition tooling is not copied into the runtime.

Archives are extracted only after verification. Traversal and special files are
rejected; internal symlinks are materialized as regular files. Optional Neo4j
labs/products are removed. The selected architecture's JNA library is copied
unchanged from the verified jar into `/opt/neo4j/native`, with its own locked
member name and digest. JNA loads that read-only library with runtime unpacking
disabled, so `/tmp` and `/run/neo4j` remain `noexec`. The lock pins the resulting SHA256SUMS manifest;
assembly verifies its digest, every file and the file count, rejecting extra
files or links. The build script reacquires/revalidates before every build.

Refresh writes candidates only. It retains the selected Neo4j version unless
`--version` is given, selects current Temurin 25 and UBI inputs, verifies all
artifacts for both architectures, and creates no human sign-off. The owner must
review licence changes, signing identities, dependency changes and scan/runtime
results before adopting a candidate. Do not automatically trust a new key.
