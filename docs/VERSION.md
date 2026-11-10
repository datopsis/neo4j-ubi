# Version rules

No container release version or tag is created by this increment. Source is
identified by its full Git commit SHA and changes remain under `Unreleased`.
Build labels use the selected upstream version with a `development` suffix.

Future image releases may use `v<neo4j-version>-ubi<ubi-version>-<packaging-revision>`.
An upstream or UBI version change starts a new pair's revision at 1; every new
image for an existing pair increments that pair's revision. Refreshing a base
digest, JVM, RPM, configuration or entrypoint changes the image and requires a
new packaging revision when a release is actually published. Repository-only
changes do not create source-only releases or tags. Never move a release tag.

Release signing, publishing, provenance and source distribution are roadmap
work. This repository currently has no tag-triggered workflow and no publishing
credentials or write permissions. Creating a tag cannot publish an image.
