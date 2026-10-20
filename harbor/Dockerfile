# syntax=docker/dockerfile:1
# The image of the patchgate Harbor tasks. The patchgate-harbor command builds it from the project root.
# It builds harbor/environment.nix, the file that the bubblewrap backend builds too.
FROM nixos/nix:2.35.3@sha256:ff480dbb23511aa1c10710aa068ceea5b93fed9bfce5f5379f3a6b07282cbc7b AS builder

# The tools come first, so a change to the project does not fetch them again.
COPY devenv.lock /build/devenv.lock

COPY harbor/environment.nix /build/harbor/environment.nix

COPY nix /build/nix

RUN nix-build /build/harbor/environment.nix -A tools --option sandbox false --out-link /tools

COPY Cargo.toml Cargo.lock /build/

COPY src /build/src

COPY harbor/tasks /build/harbor/tasks
COPY harbor/scenarios.py /build/harbor/scenarios.py

# The installed application must pass the runtime check on Linux.
RUN nix-build /build/harbor/environment.nix -A runtimeCheck --option sandbox false --no-out-link

RUN nix-build /build/harbor/environment.nix -A default --option sandbox false --out-link /env

# Export only the runtime closure and its environment path.
RUN mkdir /runtime-export && \
    nix-store --export $(nix-store --query --requisites /env) > /runtime-export/closure.nar && \
    readlink /env > /runtime-export/env-path

FROM nixos/nix:2.35.3@sha256:ff480dbb23511aa1c10710aa068ceea5b93fed9bfce5f5379f3a6b07282cbc7b AS runtime

# Import registers the closure. The bind mount keeps the archive outside image layers.
RUN --mount=type=bind,from=builder,source=/runtime-export,target=/tmp/runtime-export \
    nix-store --import < /tmp/runtime-export/closure.nar && \
    ln -s "$(cat /tmp/runtime-export/env-path)" /env

# The rootfs files become real files that the agent can change.
# The scripts of the tasks start with #!/bin/bash, and the base image has only /bin/sh.
RUN cp -R /env/rootfs/. / && \
    chmod -R u+w /opt/patchgate /scenarios && \
    ln -sf /env/bin/bash /bin/bash

ENV PATH=/env/bin:$PATH

WORKDIR /scenarios
