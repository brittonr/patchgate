# syntax=docker/dockerfile:1
# This check image keeps Harbor and bubblewrap outside the task runtime.
FROM patchgate-harbor:dev

RUN --mount=type=bind,target=/build \
    nix-build /build/harbor/environment.nix -A lifecycleTools --option sandbox false --out-link /lifecycle-tools

RUN --mount=type=bind,source=harbor/requirements.txt,target=/tmp/requirements.txt \
    /lifecycle-tools/bin/uv venv --python /lifecycle-tools/bin/python3.12 /opt/harbor-venv && \
    /lifecycle-tools/bin/uv pip sync --require-hashes --python /opt/harbor-venv/bin/python /tmp/requirements.txt

# The named context contains only the package from the locked source input.
COPY --from=backend / /opt/harbor-backend/hell_env/
COPY harbor/lifecycle.py /opt/harbor-lifecycle.py

ENV PATH=/lifecycle-tools/bin:/opt/harbor-venv/bin:/env/bin:$PATH
ENV PYTHONPATH=/opt/harbor-backend

WORKDIR /project
ENTRYPOINT ["/opt/harbor-venv/bin/python", "/opt/harbor-lifecycle.py"]
