# Argus 2.0 Docker Image
# Multi-stage build for optimized production deployment

# Build stage
FROM python:3.11-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim-bookworm AS production

LABEL maintainer="Argus Security Team"
LABEL version="0.3.0"
LABEL description="Argus - The All-Seeing Eye - Enterprise security scanner with intelligence"

# Security: Run as non-root user
RUN useradd --create-home --shell /bin/bash argus

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /root/.local /home/argus/.local

# Copy application code
COPY --chown=argus:argus . .

# Set environment variables
ENV PATH="/home/argus/.local/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV ARGUS_API_HOST=0.0.0.0
ENV ARGUS_API_PORT=8000

# Switch to non-root user
USER argus

# Create necessary directories
RUN mkdir -p /app/reports /app/data

# Health check for API mode
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose API port
EXPOSE 8000

# Default command: Run API server
CMD ["python", "-m", "argus.api.server"]
