# syntax=docker/dockerfile:1
# The image of the patchgate Harbor tasks. The patchgate-harbor command builds it from the project root.
# It builds harbor/environment.nix, the file that the bubblewrap backend builds too.
FROM nixos/nix:2.35.3@sha256:ff480dbb23511aa1c10710aa068ceea5b93fed9bfce5f5379f3a6b07282cbc7b AS tools-builder

# The tools come first, so a change to the project does not fetch them again.
COPY devenv.lock /build/devenv.lock

COPY harbor/environment.nix /build/harbor/environment.nix

COPY nix /build/nix

RUN <<'SH'
set -eu

nix-build /build/harbor/environment.nix -A runtimeClosure --option sandbox false --out-link /runtime-closure

mkdir /runtime-base-export
LC_ALL=C sort -u /runtime-closure/store-paths > /runtime-base-export/paths

nix-store --export $(cat /runtime-base-export/paths) > /runtime-base-export/closure.nar
SH

FROM tools-builder AS builder

COPY Cargo.toml Cargo.lock /build/

# Cache compiled dependencies before Rust source enters the image.
RUN nix-build /build/harbor/environment.nix -A cargoArtifacts --option sandbox false --out-link /cargo-artifacts

COPY src /build/src

COPY harbor/tasks /build/harbor/tasks
COPY harbor/scenarios.py /build/harbor/scenarios.py

# The installed application must pass the runtime check on Linux.
RUN nix-build /build/harbor/environment.nix -A runtimeCheck --option sandbox false --no-out-link

RUN nix-build /build/harbor/environment.nix -A default --option sandbox false --out-link /env

# Export only paths absent from the stable runtime closure.
RUN <<'SH'
set -eu
export LC_ALL=C

mkdir /runtime-export
cd /runtime-export

nix-store --query --requisites /env > paths
sort -u paths -o paths

comm -23 /runtime-base-export/paths paths > extra
cat extra
test ! -s extra

comm -23 paths /runtime-base-export/paths > delta
nix-store --export $(cat delta) > closure.nar

readlink /env > env
SH

FROM nixos/nix:2.35.3@sha256:ff480dbb23511aa1c10710aa068ceea5b93fed9bfce5f5379f3a6b07282cbc7b AS runtime-base

# The stable tool layer does not depend on application or fixture source.
RUN --mount=type=bind,from=tools-builder,source=/runtime-base-export,target=/tmp/runtime-base-export \
    nix-store --import < /tmp/runtime-base-export/closure.nar

FROM runtime-base AS runtime

# Import registers the delta. Both comparisons use the complete environment closure.
RUN --mount=type=bind,from=builder,source=/runtime-export,target=/tmp/runtime-export <<'SH'
set -eu
export LC_ALL=C

work="$(mktemp -d)"
cd "$work"

nix --extra-experimental-features nix-command path-info --all > base
cat base /tmp/runtime-export/paths > expected
sort -u expected -o expected

nix-store --import < /tmp/runtime-export/closure.nar
ln -s "$(cat /tmp/runtime-export/env)" /env

nix-store --query --requisites /env > closure
sort -u closure -o closure

comm -3 /tmp/runtime-export/paths closure > difference
cat difference
test ! -s difference

nix --extra-experimental-features nix-command path-info --all > registered
sort -u registered -o registered

comm -3 expected registered > difference
cat difference
test ! -s difference

cd /
rm -rf "$work"
SH

# The rootfs files become real files that the agent can change.
# The scripts of the tasks start with #!/bin/bash, and the base image has only /bin/sh.
RUN cp -R /env/rootfs/. / && \
    chmod -R u+w /opt/patchgate /scenarios && \
    ln -sf /env/bin/bash /bin/bash

# Runtime checks need a real Nix sandbox. Only the Nix tasks receive container privileges.
RUN printf '\nsandbox = true\n' >> /etc/nix/nix.conf

ENV PATH=/env/bin:$PATH

WORKDIR /scenarios
