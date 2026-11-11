# Changelog

## Unreleased

- Enforce LF line endings: `.gitattributes` normalizes text to LF, a local
  pre-commit hook and CI reject any committed CRLF.
### Added

- Neo4j Community 2026.10.2 and Temurin JRE 25.0.5+8 on digest-pinned UBI 9.8 Micro.
- Verified archive/RPM locks and read-only lock-update proposals.
- Non-root startup, explicit durable storage, read-only-root operation and
  fail-closed operator credentials with a documented unauthenticated opt-out.
- Native amd64/arm64 CI, real database/runtime tests, SPDX SBOMs and blocking
  fixed High/Critical Trivy and Grype gates with complete findings retained.
- Licensing notices, security guidance and ordered qualification/release roadmap.

### Changed

- Exclude only `parquet-jackson-1.18.1.jar` after full locked-bundle verification
  to remove CVE-2026-89407, CVE-2026-89425, CVE-2026-91776 and CVE-2026-91777
  (shaded Jackson 2.22.2; fixed in 2.22.3). No fixed parquet-jackson release is
  available. Parquet admin import and metadata/key tooling are unavailable;
  these are outside the supported console-server profile.
- Fail assembly on a changed Neo4j version or Parquet Jackson jar set; assert
  absence in the final image and clean startup/shutdown logs in native runtime
  tests. Keep both vulnerability gates and all other jars unchanged. Revisit
  with each Neo4j upgrade and upstream Jackson 2.22.3-or-newer bundling.
