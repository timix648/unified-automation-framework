# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# UAF Frontend — Reflex (compiles to React). Serves the operations console UI
# and proxies its state backend on 8001. Connects to the API + the real-time
# WebSocket channel at API_BASE (Report 4.7).
# ---------------------------------------------------------------------------
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Reflex downloads bun at first run; unzip/curl let it bootstrap cleanly.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl unzip \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Compile the frontend ahead of time so container start is fast.
RUN reflex init --loglevel warning || true

EXPOSE 3000 8001

# --env prod serves the compiled frontend; backend-port is the Reflex state server.
CMD ["reflex", "run", "--env", "prod", "--backend-port", "8001"]
