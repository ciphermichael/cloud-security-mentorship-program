# =============================================================================
# Hardened Python Application Dockerfile
# Project 10 — Container Security Framework
# Implements CIS Docker Benchmark controls
# =============================================================================

# ── Stage 1: Dependency installer (builder) ───────────────────────────────────
FROM python:3.11-slim AS builder
WORKDIR /app

# Install build dependencies only in builder stage (not in final image)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: Hardened runtime image ──────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL maintainer="security-team@company.com" \
      version="1.0.0" \
      description="Hardened Python API — CIS Benchmark compliant"

# CIS 4.1: Create non-root user and group
RUN groupadd -r appgroup --gid=1001 && \
    useradd -r -g appgroup --uid=1001 --no-log-init --shell /bin/false appuser

WORKDIR /app

# Copy only installed packages from builder (not build tools)
COPY --from=builder /install /usr/local

# Copy application code with correct ownership
COPY --chown=appuser:appgroup . .

# CIS 4.9: Remove setuid/setgid bits from all binaries
RUN find / -perm /6000 -type f -exec chmod a-s {} \; 2>/dev/null || true

# CIS 4.6: Do not expose unnecessary ports — only expose what the app uses
EXPOSE 8080

# CIS 4.1: Drop to non-root user
USER appuser

# CIS 5.2: Set read-only root filesystem (combine with --read-only docker run flag)
# Application writes only to /tmp and /app/data (mounted volumes)
VOLUME ["/tmp", "/app/data"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

# CIS 4.5: Use COPY not ADD (no URL fetching or tar extraction)
# Entry point — use exec form to be PID 1 (receives signals correctly)
ENTRYPOINT ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
