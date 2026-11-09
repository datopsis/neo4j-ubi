# Repository guidance

This repository builds a security-oriented, rootless Neo4j Community graph
container on Red Hat UBI 9. Preserve these non-negotiable properties:

- The final image is based on digest-pinned UBI 9 and has no package manager.
- The service starts and stays non-root, without entrypoint privilege transitions.
- Default HTTP (7474) and Bolt (7687) listeners use unprivileged ports.
- Read-only-root operation uses explicit writable mounts: durable `/data`,
  ephemeral `/run/neo4j` and `/tmp`. Drop all capabilities and enable
  `no-new-privileges` in documented deployments.
- Every build input is pinned and verified: base indexes by digest with both
  architectures, added RPMs by NEVRA and SHA-256 per architecture, Neo4j and
  the JVM by archive digest. Verify publisher signatures where available.
  Neo4j's tarball is digest-only; do not call it publisher-authenticated.
- No credentials, private keys or default passwords in images or examples.
  Missing operator credentials fail closed. Keep the documented explicit
  `NEO4J_UBI_ALLOW_NO_AUTH=true` opt-out available and conspicuous.
- Durable state requires an explicit volume, never an anonymous image volume.
- Ship Community only, preserve its GPL-3.0-or-later notices, and never accept
  Enterprise or other commercial terms on the owner's behalf.
- Trivy AND Grype block fixed High/Critical findings on native amd64 AND arm64.
  Report unfixed findings in full. Do not suppress them or weaken a check.
- No FIPS, STIG, platform support, or release-readiness claim without evidence.

Follow `docs/ROADMAP.md` and `docs/VERSION.md`. The container-hardening draft
criteria are an informative reference only: no dependency, pinned commit,
reusable conformance workflow, or release-eligible gate.

## Verification

Run `scripts/lint.py`, policy tests, and the documented native build/runtime
checks. Verify authenticated real Cypher, actual Community/version identity,
persistence after replacement, graceful stop, credential rejection, readonly
root, every process's UID/capabilities/no-new-privileges, and secret hygiene.
Keep hash-pinned CI Python requirements complete, including transitive packages
and their `.in` source. Lock refresh is a read-only proposal for owner review.

Do not commit databases, secrets, downloaded artifacts, SBOMs, scanner caches,
or generated evidence. Keep public publisher verification keys in `artifacts/keys`.
Never invent human review, approval, or sign-off records.

## Git and release boundaries

Use feature branches, PRs and Conventional Commit subjects. No force-push,
AI/tool-attribution or Co-Authored-By trailers. Do not change repository/org
settings, secrets, branch protection or permissions; report needs to the owner.
This increment creates no version, tag, published image, or release workflow.
A tag must not publish anything. Do not merge the implementation PR.
