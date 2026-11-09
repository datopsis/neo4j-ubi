# Known blocking findings

The initial locked Neo4j 2026.10.2 archive contains Jackson 2.22.2 shaded into
`/opt/neo4j/lib/parquet-jackson-1.18.1.jar`. The 2026-11-09 native scans report
the following on **both amd64 and arm64**. The complete JSON reports are in
[CI evidence](https://github.com/datopsis/neo4j-ubi/actions/runs/42609156571)
(14-day artifact retention); the PR records subsequent runs.

| Trivy ID | Grype ID | Component | Severity | Reported fix |
| --- | --- | --- | --- | --- |
| CVE-2026-89407 | GHSA-p6pp-m3f8-5c89 | jackson-core 2.22.2 | High | 2.22.3 |
| CVE-2026-89425 | GHSA-7hhh-6rmp-j9qf | jackson-core 2.22.2 | High | 2.22.3 |
| CVE-2026-91776 | GHSA-wv8q-qhhj-9h54 | jackson-databind 2.22.2 | High | 2.22.3 |
| CVE-2026-91777 | GHSA-cxp5-3px4-pw24 | jackson-databind 2.22.2 | High | 2.22.3 |

Each scanner reports four High findings, zero Critical, and zero unfixed
High/Critical. Trivy additionally reports 15 Medium and 14 Low; Grype reports
12 Medium and 14 Low. Full reports retain these and their fix status.
These are scanner results, not a claim that every vulnerable code path is
reachable or that lower-severity/unfixed findings are safe.

**The vulnerability gate correctly fails on both architectures.** There are no
suppressions, exceptions, invented approvals or report-only bypasses. This
candidate must not be presented as passing the security gate or release ready.

Replacing top-level Jackson jars does not fix the shaded copy. Remediation
requires a patched upstream Neo4j/Parquet artifact, or a separately reviewed
and qualified rebuild. This increment does not silently rewrite publisher
archives, delete internal dependencies to hide findings, or accept this risk
on the owner's behalf. Re-run both native scans after any input change.
