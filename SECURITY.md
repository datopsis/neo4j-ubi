# Security policy

This is unreleased development work. There are no supported release versions
and no FIPS, STIG or deployment-platform certification claims.

Report sensitive vulnerabilities through GitHub's private vulnerability reporting
UI if available. If it is unavailable, contact the repository owner privately to
arrange a reporting channel; do not post credentials or exploit details publicly.
Enabling that feature or any repository protection is an owner action, not
something this increment changes.

Trivy and Grype scan each native image and retain complete reports, including
unfixed findings. Any fixed High/Critical finding from either scanner fails CI.
No ignore list is used. Missing scan reports also fail. An unfixed finding is
reported, not declared safe; assess reachability and deployment impact before
use. Target remediation once fixes exist: 7 days for Critical/known exploited,
14 days for High, 30 days for other findings. This is a maintenance target, not
a support SLA for an unreleased image.

The image enforces non-root startup, explicit data mounting and credentials.
The operator supplies read-only secrets, durable storage, read-only-root/capability
runtime restrictions, network isolation, encrypted remote transport, backups,
resource limits and host updates. Localhost-only publication is the documented
initial plaintext HTTP/Bolt profile. Do not use the no-auth opt-out on a shared
or untrusted network. Neo4j tarball digests are not publisher signatures.

Do not change gates to get green. Report failures and unverified boundaries.
