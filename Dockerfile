# Replicant CLI container image (roadmap 2026-09 item 14).
#
# CLI-first: the web UI is an optional extra and is NOT installed here, so the
# image stays small and a CLI-first evaluator does not build a React bundle to see
# one FortiGate line. `replicant web` in this image serves its build-it page; for
# the UI, install the wheel with the [web] extra instead.
#
# The build context excludes everything but the package and its metadata (see
# .dockerignore), including the in-tree backup repositories and the checked-in
# webui_dist, so the CLI image carries no UI assets and no scrubbed history.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Replicant" \
      org.opencontainers.image.description="Safe synthetic firewall CEF telemetry for detection engineering (CLI)" \
      org.opencontainers.image.source="https://github.com/404SecNotFound/Replicant" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY replicant ./replicant

RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 runner

# Runs land here: manifests default to ./manifests and --to-file paths are
# relative to the working directory, so mount a volume at /work to keep them.
WORKDIR /work
RUN chown runner:runner /work
USER runner

ENTRYPOINT ["replicant"]
CMD ["list"]
