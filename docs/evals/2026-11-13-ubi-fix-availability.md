# UBI fix availability evaluation — 2026-11-13

Reference: [sail-ubi #4](https://github.com/datopsis/sail-ubi/pull/4), merged at
`861d92fb12e1a8b25c728da93129efdc770fd540`. Implements the owner-requested
repository-availability rule without scanner suppressions or package exceptions.

## Repository and comparison evidence

The existing Neo4j RPM resolver uses UBI 9 BaseOS only. Its URL is now shared
through `artifacts/ubi.repo`; the gate uses isolated, fresh DNF metadata for the
same architecture and repository. No installed host RPMs or other repos enter
the query. System librpm compares epoch/version/release.

Ran 28 live query cases: 12 installed versions from the retained main-image RPM
inventory on each architecture, plus two deliberately unreachable epoch-999
thresholds per architecture to exercise successful negative queries. All 24
real-version thresholds were available; all four synthetic future thresholds
were unavailable. These synthetic thresholds are **not vendor CVE fixes** and
are not evidence of live deferred vulnerabilities. The matrix below records
the actual results; unit tests separately cover errors, timeouts, missing repos,
malformed EVRs, non-RPM packages and issue state transitions.

Architecture | Package | Queried EVR | Available versions | Meets threshold
--- | --- | --- | --- | ---
amd64 | basesystem | 0:11-13.el9 | 0:11-13.el9 | True
amd64 | bash | 0:5.1.8-9.el9 | 0:5.1.8-9.el9 | True
amd64 | coreutils-single | 0:8.32-41.el9_8.1 | 0:8.32-43.el9 | True
amd64 | filesystem | 0:3.16-5.el9 | 0:3.16-5.el9 | True
amd64 | glibc | 0:2.34-284.el9_8.4 | 0:2.34-290.el9_9 | True
amd64 | glibc-common | 0:2.34-284.el9_8.4 | 0:2.34-290.el9_9 | True
amd64 | glibc-minimal-langpack | 0:2.34-284.el9_8.4 | 0:2.34-290.el9_9 | True
amd64 | libacl | 0:2.4.0-1.el9_8 | 0:2.4.0-2.el9 | True
amd64 | libattr | 0:2.6.0-1.el9_8 | 0:2.6.0-2.el9 | True
amd64 | libcap | 0:2.48-10.el9_8.1 | 0:2.48-10.el9_8.1 | True
amd64 | libstdc++ | 0:11.5.0-14.el9 | 0:11.5.0-17.el9_9 | True
amd64 | zlib | 0:1.2.11-40.el9 | 0:1.2.11-40.el9 | True
amd64 | basesystem | 999:11-13.el9 | 0:11-13.el9 | False
amd64 | bash | 999:5.1.8-9.el9 | 0:5.1.8-9.el9 | False
arm64 | basesystem | 0:11-13.el9 | 0:11-13.el9 | True
arm64 | bash | 0:5.1.8-9.el9 | 0:5.1.8-9.el9 | True
arm64 | coreutils-single | 0:8.32-41.el9_8.1 | 0:8.32-43.el9 | True
arm64 | filesystem | 0:3.16-5.el9 | 0:3.16-5.el9 | True
arm64 | glibc | 0:2.34-284.el9_8.4 | 0:2.34-290.el9_9 | True
arm64 | glibc-common | 0:2.34-284.el9_8.4 | 0:2.34-290.el9_9 | True
arm64 | glibc-minimal-langpack | 0:2.34-284.el9_8.4 | 0:2.34-290.el9_9 | True
arm64 | libacl | 0:2.4.0-1.el9_8 | 0:2.4.0-2.el9 | True
arm64 | libattr | 0:2.6.0-1.el9_8 | 0:2.6.0-2.el9 | True
arm64 | libcap | 0:2.48-10.el9_8.1 | 0:2.48-10.el9_8.1 | True
arm64 | libstdc++ | 0:11.5.0-14.el9 | 0:11.5.0-17.el9_9 | True
arm64 | zlib | 0:1.2.11-40.el9 | 0:1.2.11-40.el9 | True
arm64 | basesystem | 999:11-13.el9 | 0:11-13.el9 | False
arm64 | bash | 999:5.1.8-9.el9 | 0:5.1.8-9.el9 | False

## Lock refresh and verification limits

`python3 scripts/artifacts.py refresh` regenerated both architecture bundles
and verified archive hashes, Temurin signatures and Red Hat RPM signatures.
The candidate changes only libstdc++ 11.5.0-14.el9 → 11.5.0-17.el9_9 and the
two bundle manifest digests. Zlib, Neo4j, JVM and base image pins are unchanged.
The refreshed lock is applied in this PR.

Local Podman is blocked by `cannot clone: Operation not permitted`; container
evidence must come from the PR native CI jobs. The [fresh baseline CI run](https://github.com/datopsis/neo4j-ubi/actions/runs/43423216844)
on unchanged main (`1816f4583bfb6a90acabbccad181b29c84edf875`) passed. Downloaded
and read both architectures' complete Trivy/Grype reports: each scanner reports
**0 fixable blocking / 0 deferred / 1 unfixed High**, and zero Critical. The one
unfixed High is in zlib. Replaying these reports through the new gate preserves
those counts; no actual RPM fix is currently deferred. Trivy also reports 23
Medium/14 Low and Grype 17 Medium/14 Low per architecture. Final PR counts and
exact run links will be recorded in the PR after downloading native evidence.

The issue tracker is dry-run/unit tested only before merge. The scheduled
workflow and live issue writes cannot be exercised from a PR because both the
workflow and script restrict them to scheduled/manual main runs. An incomplete
evidence set fails tracking instead of closing the issue. Comments are keyed
only to the deferred set, including vendor versions; unrelated scan findings
and run URLs do not change that key. No merge or owner sign-off is performed.
