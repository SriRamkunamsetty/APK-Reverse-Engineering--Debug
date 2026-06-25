# ═══════════════════════════════════════════════════════════════
# RAKSHAK — Dockerfile
# DRDO APK Threat Intelligence Platform v3.0.0
# Multi-stage build for minimal production image
# ═══════════════════════════════════════════════════════════════

FROM python:3.12-slim AS base

LABEL maintainer="DRDO Cybersecurity Division"
LABEL version="3.0.0"
LABEL description="RAKSHAK APK Threat Intelligence Platform"

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    libmagic1 \
    file \
    unzip \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ─── Builder stage ────────────────────────────────────────────────────────────
FROM base AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─── Final stage ─────────────────────────────────────────────────────────────
FROM base AS final

# Create non-root user for security
RUN groupadd -r rakshak && useradd -r -g rakshak -d /app rakshak

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY --chown=rakshak:rakshak . .

# Create runtime directories
RUN mkdir -p uploads reports database static yara_rules \
    && chown -R rakshak:rakshak /app

# Switch to non-root user
USER rakshak

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/status || exit 1

# Environment defaults
ENV HOST=0.0.0.0
ENV PORT=8000
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Entry point
CMD ["python", "-m", "uvicorn", "main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "4", \
     "--log-level", "info"]
