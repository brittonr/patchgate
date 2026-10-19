# The image of the patchgate Harbor tasks. The patchgate-harbor command builds it from the project root.
# It builds harbor/environment.nix, the file that the bubblewrap backend builds too.
FROM nixos/nix:2.35.3@sha256:ff480dbb23511aa1c10710aa068ceea5b93fed9bfce5f5379f3a6b07282cbc7b

# The tools come first, so a change to the project does not fetch them again.
COPY devenv.lock /build/devenv.lock

COPY harbor/environment.nix /build/harbor/environment.nix

RUN nix-build /build/harbor/environment.nix -A tools --option sandbox false --out-link /tools

COPY patchgate.py /build/patchgate.py

COPY harbor/scenarios.py /build/harbor/scenarios.py

# The rootfs files become real files that the agent can change.
# The scripts of the tasks start with #!/bin/bash, and the base image has only /bin/sh.
RUN nix-build /build/harbor/environment.nix -A default --option sandbox false --out-link /env && cp -RL /env/rootfs/. / && chmod -R u+w /opt/patchgate /scenarios && ln -sf /env/bin/bash /bin/bash

ENV PATH=/env/bin:$PATH

WORKDIR /scenarios
