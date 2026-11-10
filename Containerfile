ARG UBI_MINIMAL_IMAGE="registry.access.redhat.com/ubi9/ubi-minimal:9.8@sha256:f26ef64172ea61f5ac5ba4be8c5c738bf8760b22b3e5148ce7b40f7308ab32db"
ARG UBI_MICRO_IMAGE="registry.access.redhat.com/ubi9/ubi-micro:9.8@sha256:d3499a0896e2d6a1642f922615831bc5c2fd513bbb34f3446cabba530d9d54a2"
FROM ${UBI_MICRO_IMAGE} AS micro
FROM ${UBI_MINIMAL_IMAGE} AS builder
ARG TARGETARCH
ARG BUNDLE_SHA256
ARG NEO4J_VERSION
COPY .artifact-bundle/${TARGETARCH}/ /bundle/
COPY --from=micro / /final/
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# The manifest digest is locked, not generated from arbitrary build-context files.
# Verify the complete bundle BEFORE excluding exactly the reviewed Parquet jar.
# Any Neo4j upgrade or changed jar set requires revisiting docs/KNOWN-FINDINGS.md.
RUN test -n "${BUNDLE_SHA256}" \
    && echo "${BUNDLE_SHA256}  /bundle/SHA256SUMS" | sha256sum --check --strict - \
    && cd /bundle && sha256sum --check --strict SHA256SUMS \
    && test "$(find . -type f ! -path ./SHA256SUMS | wc -l)" = "$(wc -l < SHA256SUMS)" \
    && test -z "$(find . ! -type f ! -type d -print -quit)" \
    && rpmkeys --root /final --checksig /bundle/rpms/*.rpm \
    && rpm --root /final --upgrade /bundle/rpms/*.rpm \
    && mkdir -p /final/opt /final/data /final/import /final/run/neo4j
RUN { test "${NEO4J_VERSION}" = "2026.10.2" \
         && test "$(find /bundle/neo4j -iname '*parquet-jackson*.jar' -print)" = "/bundle/neo4j/lib/parquet-jackson-1.18.1.jar"; \
    } || { echo 'Revisit the parquet-jackson exclusion in docs/KNOWN-FINDINGS.md' >&2; exit 1; }; \
    rm -- /bundle/neo4j/lib/parquet-jackson-1.18.1.jar \
    && cp -a /bundle/neo4j /final/opt/neo4j \
    && test -z "$(find /final/opt/neo4j -iname '*parquet-jackson*.jar' -print -quit)" \
    && cp -a /bundle/jre /final/opt/java \
    && rm -rf /final/etc/yum.repos.d /final/etc/pki/rpm-gpg /final/etc/rhsm /final/etc/dnf \
    && rpm --root /final -qa 'gpg-pubkey*' > /tmp/keys \
    && while read -r key; do rpm --root /final -e "$key"; done < /tmp/keys \
    && find /final -xdev -type f -perm /6000 -exec chmod a-s {} + \
    && chmod -R go-w /final/opt \
    && chown 10001:0 /final/data /final/run/neo4j \
    && chmod 0750 /final/data /final/run/neo4j \
    && printf 'neo4j:x:10001:0:Neo4j:/run/neo4j:/sbin/nologin\n' >> /final/etc/passwd
FROM ${UBI_MICRO_IMAGE}
ARG NEO4J_VERSION
ARG SOURCE_REVISION
ARG CREATED
ARG LOCK_SHA256
ARG UBI_MICRO_IMAGE
LABEL org.opencontainers.image.title="Neo4j Community on UBI 9" \
      org.opencontainers.image.source="https://github.com/datopsis/neo4j-ubi" \
      org.opencontainers.image.licenses="Apache-2.0 AND GPL-3.0-or-later AND GPL-2.0-with-classpath-exception" \
      org.opencontainers.image.version="${NEO4J_VERSION}-development" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      io.datopsis.artifact-lock.sha256="${LOCK_SHA256}" \
      io.datopsis.ubi.runtime="${UBI_MICRO_IMAGE}"
COPY --from=builder /final/ /
# COPY overlays a base; it does not propagate deletions made in /final.
RUN rm -rf /etc/yum.repos.d /etc/pki/rpm-gpg /etc/rhsm /etc/dnf
COPY --chmod=0555 container/entrypoint.sh /usr/local/bin/neo4j-entrypoint
COPY --chmod=0555 container/healthcheck.sh /usr/local/bin/neo4j-healthcheck
COPY --chmod=0444 container/neo4j.conf container/logs.xml /etc/neo4j/
COPY --chmod=0444 LICENSE THIRD_PARTY_NOTICES /usr/share/licenses/neo4j-ubi/
ENV LANG=C.UTF-8 TZ=UTC PATH="/opt/java/bin:/opt/neo4j/bin:/usr/bin:/bin"
USER 10001:0
WORKDIR /opt/neo4j
EXPOSE 7474 7687
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=15s --timeout=5s --start-period=120s --retries=5 CMD ["/usr/local/bin/neo4j-healthcheck"]
ENTRYPOINT ["/usr/local/bin/neo4j-entrypoint"]
CMD ["console"]
