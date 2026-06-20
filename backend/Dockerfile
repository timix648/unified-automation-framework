# Base builder stage — installs Python dependencies into a clean site-packages
# that the production stage copies out. Keeps the runtime image free of build
# toolchain while still carrying every dependency.
FROM python:3.11-slim as base

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage — single worker (scheduler + WebSocket bus assume one process)
FROM python:3.11-slim as production

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libssl-dev iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY --from=base /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=base /usr/local/bin /usr/local/bin

COPY app/ ./app/
RUN mkdir -p /app/logs
# NOTE: no `COPY .env` — env comes from docker-compose `env_file: .env.prod`

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/api/health')"

# Single worker — NOT --workers 4 (would 4x the scheduler and break WS alerts)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]