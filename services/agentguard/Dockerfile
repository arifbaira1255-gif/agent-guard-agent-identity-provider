# AgentGuard Identity Service -- multi-stage production image.
#
#   Stage 1 (builder): install pinned dependencies into a virtualenv.
#   Stage 2 (runtime): copy ONLY the venv + source into a minimal, non-root image.
#
# Properties: non-root (UID 10001), no build toolchain in the runtime image, no credentials baked
# in, read-only-rootfs friendly (writable paths are /tmp only), and a healthcheck that uses the
# process-only liveness endpoint.
#
# Build:  docker build -t agentguard/agent-identity:0.1.0 .
# Run:    docker run --rm -p 8443:8443 --env-file .env agentguard/agent-identity:0.1.0 serve

# --------------------------------------------------------------------------- builder
FROM python:3.11.9-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# Build-only toolchain (never reaches the runtime image).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml ./
COPY src ./src

# Install the package + the production extras into an isolated venv.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip==24.0 \
    && /opt/venv/bin/pip install ".[postgres,redis,aws]"

# --------------------------------------------------------------------------- runtime
FROM python:3.11.9-slim-bookworm AS runtime

# Runtime shared libs only (libpq for psycopg; no compilers).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 agentguard \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin agentguard

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/src \
    AGENTGUARD_LISTEN_HOST=0.0.0.0 \
    AGENTGUARD_LISTEN_PORT=8443

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=10001:10001 src ./src
COPY --chown=10001:10001 console ./console
COPY --chown=10001:10001 pyproject.toml README.md ./

USER 10001:10001

EXPOSE 8443

# Process-only liveness: a dependency outage must not mark the container unhealthy.
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${AGENTGUARD_LISTEN_PORT}/livez" || exit 1

# `serve` runs the production server; `migrate` runs the schema migration step.
ENTRYPOINT ["python", "-m", "agent_identity.server"]
CMD ["serve"]
