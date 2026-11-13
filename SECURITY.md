# Security policy

This is unreleased development work. There are no supported release versions
and no FIPS, STIG or deployment-platform certification claims.

Report sensitive vulnerabilities through GitHub's private vulnerability reporting
UI if available. If it is unavailable, contact the repository owner privately to
arrange a reporting channel; do not post credentials or exploit details publicly.
Enabling that feature or any repository protection is an owner action, not
something this increment changes.

Trivy and Grype scan each native image and retain complete reports, including
unfixed findings. The owner-approved UBI-installable fix rule applies to
High/Critical findings on both native architectures:

- A fixable RPM finding blocks when UBI publishes a target-architecture or
  noarch version at or above any vendor fixed version. Comparison uses librpm's
  epoch/version/release ordering, not lexical or semantic-version ordering.
- Only a successful query proving no suitable version exists defers an RPM
  finding. Deferred findings remain vulnerabilities, with their vendor fixed
  versions shown in the job summary and retained admission JSON/Markdown.
- Query errors/timeouts, missing or empty repositories, malformed versions,
  unknown RPM identity/architecture and incomplete query results block. Fixed
  non-RPM findings (including jars and language modules) always block as before.
- Unfixed findings remain reported. Missing/malformed scanner reports fail.
  No CVE/package/date exceptions, ignore lists, or severity changes are used.

`artifacts/ubi.repo` is the shared repository configuration for RPM lock
resolution and admission queries. This image's added RPMs come from **UBI 9
BaseOS only**, expanded separately for x86_64/aarch64; no host, subscription or
extra repositories are used. Image assembly remains offline from verified,
pinned inputs. The gate queries fresh metadata in an isolated DNF cache and
never updates the image or installs packages. Publishing a fix makes the next
gate block until the lock/image is refreshed and rescanned.

CI repeats every six hours. On scheduled or manual **main** runs only, a tracking
job creates one issue when deferrals first exist, reuses it, closes it when the
set is empty, and reopens it for later deferrals. It comments only when the
deferred set changes (including vendor fix versions); run URLs, ordering,
unrelated blockers and unfixed changes do not trigger comments. Missing or
corrupt admission evidence fails the tracking job and preserves the issue;
it cannot be mistaken for resolution. An empty deferred set does not mean CI
passes. The tracking job alone has `issues: write`; it is skipped on PRs and
non-main dispatches, with an independent script guard. Required native and lint
job names remain unchanged. No GitHub settings or permissions outside the
workflow's narrowly scoped job token are changed.

Assess reachability and deployment impact before use. Target remediation once fixes exist: 7 days for Critical/known exploited,
14 days for High, 30 days for other findings. This is a maintenance target, not
a support SLA for an unreleased image.

The image excludes `parquet-jackson-1.18.1.jar` from the verified Neo4j bundle
at assembly time for CVE-2026-89407, CVE-2026-89425, CVE-2026-91776 and
CVE-2026-91777. No replacement jar, finding exception or scanner bypass is used.
Parquet import and its metadata/key tooling are unavailable and outside this
console-server profile; APOC/custom plugins and admin import/export workflows
are unsupported. See [dependency assessment and removal](docs/KNOWN-FINDINGS.md).
Revisit on every Neo4j upgrade and when upstream bundles Jackson 2.22.3 or newer;
restoration requires both architectures' runtime and scanner evidence.

The image enforces non-root startup, explicit data mounting and credentials.
The operator supplies read-only secrets, durable storage, read-only-root/capability
runtime restrictions, network isolation, encrypted remote transport, backups,
resource limits and host updates. Localhost-only publication is the documented
initial plaintext HTTP/Bolt profile. Do not use the no-auth opt-out on a shared
or untrusted network. Neo4j tarball digests are not publisher signatures.

Do not change gates to get green. Report failures and unverified boundaries.
