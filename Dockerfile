# Container image for the mcpprobe GitHub Action (and for `docker run` use).
# GitHub runs Docker actions as root with the workspace mounted at /github/workspace,
# so no USER instruction is set here.
FROM python:3.13-slim

LABEL org.opencontainers.image.title="mcpprobe" \
      org.opencontainers.image.description="Security scanner for MCP servers" \
      org.opencontainers.image.source="https://github.com/mcpprobe-dev/mcpprobe" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/mcpprobe
COPY pyproject.toml README.md LICENSE CHANGELOG.md CHECKS.md SECURITY.md ./
COPY mcpprobe ./mcpprobe
RUN pip install . && rm -rf /opt/mcpprobe/build

ENTRYPOINT ["python", "-m", "mcpprobe.action"]
