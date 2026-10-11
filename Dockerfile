# Multi-stage Rootless Dockerfile for AI Phishing Detection System
FROM python:3.12-slim-bookworm AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --upgrade pip && \
    pip install .

# Final runtime stage
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PHISH_AI_ENVIRONMENT=production \
    PHISH_AI_DB_PATH=/var/lib/phish_ai/phish_ai.db

WORKDIR /app

# Create unprivileged service user (UID 10001)
RUN groupadd -g 10001 phishai && \
    useradd -u 10001 -g phishai -s /bin/false -M phishai && \
    mkdir -p /var/lib/phish_ai /app/data && \
    chown -R phishai:phishai /var/lib/phish_ai /app/data

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/phish-ai /usr/local/bin/phish-ai
COPY --from=builder /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY src/ ./src/

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health').read()" || exit 1

ENTRYPOINT ["uvicorn", "phish_ai.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
