# ============================================================
# STAGE 1: Python dependencies
# ============================================================
FROM python:3.12-slim AS deps

WORKDIR /app

COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -e .

# ============================================================
# STAGE 2: Full runtime with all analysis tools
# ============================================================
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="MORDOR"
LABEL org.opencontainers.image.description="Malware Orchestration & Reverse engineering Detection Operations Runtime"
LABEL org.opencontainers.image.version="1.0.0"

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV MORDOR_HOME=/app
ENV MORDOR_CASES_DIR=/cases

WORKDIR /app

# Install system dependencies for analysis tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # YARA
    yara \
    # Network tools
    tcpdump \
    tshark \
    # General
    curl \
    ca-certificates \
    file \
    binutils \
    xxd \
    && rm -rf /var/lib/apt/lists/*

# Install radare2 from .deb package (not available in Debian trixie)
RUN arch=$(dpkg --print-architecture) && \
    curl -fsSL -o /tmp/radare2.deb \
      "https://github.com/radareorg/radare2/releases/download/6.1.4/radare2_6.1.4_${arch}.deb" && \
    apt-get update && apt-get install -y --no-install-recommends /tmp/radare2.deb && \
    rm -rf /var/lib/apt/lists/* /tmp/radare2.deb

# Copy Python deps from stage 1
COPY --from=deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin

# Copy application code and re-install mordor package (no-deps to reuse cached deps)
COPY . .
RUN pip install --no-cache-dir -e . --no-deps

# Make cases directory a volume
VOLUME ["/cases"]

# Expose API port
EXPOSE 8765

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8765/v1/health || exit 1

# Default: serve API
CMD ["mordor", "serve"]
