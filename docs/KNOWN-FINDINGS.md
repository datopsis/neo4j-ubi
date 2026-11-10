# Known findings and scoped dependency removal

## Jackson findings in the upstream archive

Neo4j Community 2026.10.2 contains Jackson 2.22.2 shaded into
`/opt/neo4j/lib/parquet-jackson-1.18.1.jar`. The 2026-11-09 native scans reported
the following on **both amd64 and arm64**. The complete pre-removal reports are
in [CI evidence](https://github.com/datopsis/neo4j-ubi/actions/runs/42611680873)
(14-day artifact retention).

| Trivy ID | Grype ID | Component | Severity | Reported fix in 2.22 |
| --- | --- | --- | --- | --- |
| CVE-2026-89407 | GHSA-p6pp-m3f8-5c89 | jackson-core 2.22.2 | High | 2.22.3 |
| CVE-2026-89425 | GHSA-7hhh-6rmp-j9qf | jackson-core 2.22.2 | High | 2.22.3 |
| CVE-2026-91776 | GHSA-wv8q-qhhj-9h54 | jackson-databind 2.22.2 | High | 2.22.3 |
| CVE-2026-91777 | GHSA-cxp5-3px4-pw24 | jackson-databind 2.22.2 | High | 2.22.3 |

Each scanner reported four High findings, zero Critical, and zero unfixed
High/Critical per architecture. Trivy additionally reported 15 Medium and 14
Low; Grype reported 12 Medium and 14 Low. The gate correctly failed. These
counts describe the old image, not an exception for the new one.

As checked on 2026-11-10, the [Maven Central metadata](https://repo.maven.apache.org/maven2/org/apache/parquet/parquet-jackson/maven-metadata.xml)
still lists 1.18.1 as the latest parquet-jackson release. There is no newer fixed
Parquet artifact to pick up for this locked Neo4j distribution. See also the
[Apache release announcement](https://parquet.apache.org/blog/2026/08/04/1.18.1/).
The separate top-level Jackson core/databind jars are already 2.22.3; they cannot
satisfy the relocated `shaded.parquet.com.fasterxml.jackson` classes.

## Dependency and feature assessment

Inspected the SHA-256-verified upstream tarball pinned in
`artifacts/neo4j.lock.json`, every `lib/*.jar` class file for Parquet/relocated
Jackson references, embedded Maven POMs and manifests, and `javap -c -p` output.
The manifests identify Parquet 1.18.1 and Neo4j 2026.10.2, with no manifest
`Class-Path` dependency forcing the server to load parquet-jackson. Embedded
Jackson `pom.properties` confirm core/databind 2.22.2.

| Bundled jar | Relevant dependency / reference |
| --- | --- |
| `neo4j-import-tool-2026.10.2.jar` | CLI command provider; `FileImporter` selects `ParquetInput` for Parquet input, separately from `CsvInput` |
| `neo4j-import-util-2026.10.2.jar` | Twelve classes reference Apache Parquet directly, all under `internal/batchimport/input/parquet`; POM depends on parquet-floor, column, common and hadoop |
| `parquet-floor-2.4.jar` | Reader adapter; depends on parquet-column and parquet-hadoop 1.18.1 |
| `parquet-hadoop-1.18.1.jar` | Declares parquet-jackson as a runtime dependency; twelve classes reference shaded Jackson, in metadata and encryption key tools |
| `parquet-column`, `parquet-common`, `parquet-encoding`, `parquet-format-structures` (all 1.18.1) | Parquet internals; retained, with no direct shaded Jackson class references |
| `parquet-jackson-1.18.1.jar` | Relocated Jackson core, databind and annotations; the sole jar removed |

No other `lib` jar directly references Apache Parquet classes or the relocated
Jackson classes. `neo4j-import-tool` references Neo4j's Parquet input classes
instead. This static check is evidence of the dependency path, not proof of
all possible reflective or third-party use.

The affected Neo4j feature is offline
[`neo4j-admin database import full --input-type=parquet`](https://neo4j.com/docs/operations-manual/current/import/full-import/).
`ParquetMetadata` initializes a shaded `ObjectMapper` in its static initializer,
so removal affects reading metadata, not just optional JSON export. A local
class-initialization probe succeeded with the original jar and failed without
it with `NoClassDefFoundError` for that mapper. **Parquet import is therefore
unavailable in this image.** Parquet metadata JSON conversion and encryption
key tooling also lose their Jackson dependency. Do not invoke them by overriding
the entrypoint or adding procedures.

This image's fixed profile supports the Community console server, authenticated
Cypher reads/writes and durable storage under the documented restrictions.
Its entrypoint only permits `console`; admin import/export workflows are outside
that profile. No built-in server Parquet export/procedure dependency was found.
APOC-style import/export procedures are optional plugins: `labs` and `products`
are already excluded during acquisition, and arbitrary plugins are unsupported.
No supported feature is intentionally removed. Ordinary Cypher and the server's
unshaded Jackson remain intact. CSV admin import, backup/restore and other admin
workflows are not newly qualified by this change.

## Assembly, validation and revisit conditions

The Containerfile verifies the **complete original bundle**, including the jar,
against the locked manifest before removing exactly
`/bundle/neo4j/lib/parquet-jackson-1.18.1.jar` from the builder's verified tree.
It then copies that tree into the final image. Acquisition, archive hashes and
bundle manifest hashes remain unchanged; no unverified replacement or patched
jar is introduced. No additional jar is removed, and upstream notices remain.
The excluded bytes never enter a final-image layer.

Assembly fails unless the Neo4j version is exactly 2026.10.2 and the only
parquet-jackson jar anywhere in the Neo4j bundle is the expected 1.18.1 file.
A missing, renamed, additional or upgraded jar requires reassessment. An explicit
post-copy assertion and the native runtime test reject reintroduction. Policy
regressions exercise the actual Containerfile exclusion against changed inputs.

The existing full native runtime suite remains required on both architectures:
startup, credential guards, authenticated Cypher and version/edition, writes and
reads across container replacement, graceful shutdown, non-root processes,
read-only root, dropped capabilities, no-new-privileges and secret hygiene.
Additional checks assert jar absence and successful startup with no class-loading
errors in logs, both at readiness and after shutdown (including restart and the
explicit no-auth test). Passing a static dependency check alone is insufficient.
Local Podman cannot create namespaces in the development sandbox (`cannot clone:
Operation not permitted`); native GitHub CI supplies the container evidence.
Post-removal results must be read from PR #1's CI at the tested commit; the
unchanged Trivy/Grype gate remains blocking on both architectures.

Re-check this decision **on every Neo4j upgrade**, and when a Neo4j/Parquet release
bundles Jackson **2.22.3 or newer**. Reassess dependency paths and supported
features, then restore the upstream jar only with fresh full native runtime and
scanner evidence on both architectures. Do not merely change the version guard.
There are no finding suppressions, exceptions, scanner changes or risk sign-offs.
Lower-severity and unfixed findings remain in the complete reports. This work
does not establish release readiness or deployment certification.

Owner review:

Owner approval:
