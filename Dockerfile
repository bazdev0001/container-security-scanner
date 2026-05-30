FROM python:3.11-slim AS base

# Install system dependencies needed to install Trivy
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy
ARG TRIVY_VERSION=0.50.1
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}" \
    && trivy --version

# ── Python deps ────────────────────────────────────────────────────────────
FROM base AS deps
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime image ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Copy Trivy binary from base
COPY --from=base /usr/local/bin/trivy /usr/local/bin/trivy

# Copy installed Python packages
COPY --from=deps /install /usr/local

# Non-root user for safety
RUN groupadd --gid 1001 scanner \
    && useradd --uid 1001 --gid scanner --shell /bin/bash --create-home scanner

WORKDIR /app
COPY scanner/ ./scanner/

# Pre-warm Trivy DB on build (optional — can be skipped for faster builds)
# The cache is then volume-mounted at runtime to persist across runs.
# RUN trivy image --download-db-only

# Trivy DB cache dir — mount a volume here in production for DB persistence
ENV TRIVY_CACHE_DIR=/home/scanner/.cache/trivy
ENV SCANNER_TRIVY_BIN=/usr/local/bin/trivy
ENV SCANNER_OUTPUT_DIR=/reports

RUN mkdir -p /reports "${TRIVY_CACHE_DIR}" \
    && chown -R scanner:scanner /reports "${TRIVY_CACHE_DIR}"

USER scanner

# Expose reports output dir as a volume
VOLUME ["/reports", "/home/scanner/.cache/trivy"]

ENTRYPOINT ["python", "-m", "scanner.main"]
CMD ["--help"]

LABEL org.opencontainers.image.title="container-security-scanner"
LABEL org.opencontainers.image.description="Docker image CVE scanner with policy-based CI blocking"
LABEL org.opencontainers.image.source="https://github.com/barry-auyeung/container-security-scanner"
LABEL org.opencontainers.image.licenses="MIT"
