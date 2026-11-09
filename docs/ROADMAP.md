# Ordered remaining work

This first increment is development evidence only. It does not establish a
supported release, certification, or a complete hardening-standard assessment.
The draft [container-hardening criteria](https://github.com/datopsis/container-hardening/blob/main/docs/standard/criteria.md)
were read as design guidance; there is no code or workflow dependency on them.

1. Close initial native CI findings. Review both architectures' Trivy and Grype
   reports, preserve unfixed findings, and remediate fixed High/Critical findings.
   Confirm the guarded credential, real Cypher, restart and constrained-runtime
   evidence at the exact PR commit. Expand hostile credential/configuration tests.
2. Produce scoped SCAP evidence: agree rule selection, pin scanner/content,
   assess the actual image filesystem on each architecture, document exclusions
   and host/orchestrator responsibilities. Do not translate results into STIG
   certification or FIPS validation. Malware inspection is also future work.
3. Prepare source-delivery and licence compliance for distribution, including
   corresponding source and notices for Neo4j, JVM, UBI and bundled libraries.
   Then implement release signing/publishing in a separate approved increment:
   immutable images, SBOM/provenance attestations, signature verification and
   retention. No publishing workflow or tag trigger exists now. Any needed
   registry permissions, repository settings or secrets must be reported to the
   owner rather than changed automatically.
4. Deepen qualification: native TLS with operator keys/trust, rootless Podman on
   a specific Red Hat host, arbitrary UID/OpenShift, backup/restore, upgrade and
   rollback, crash/power-loss recovery, bounded disk/memory exhaustion, long-lived
   workloads, configuration tuning and controlled-network artifact transfer.
5. Decide a support boundary from that evidence. Only then consider the first
   immutable release. Human reviews/approvals remain the owner's responsibility;
   no sign-off is inferred from tests or authored by automation.
