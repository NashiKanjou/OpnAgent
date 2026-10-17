# OpnAgent launcher: OpenShell CLI (static musl build) + the FastAPI
# orchestrator/auth gate.
FROM python:3.14-slim

ARG OPENSHELL_VERSION=0.1.4
ARG OPENSHELL_CLI_URL=https://github.com/NVIDIA/OpenShell/releases/download/v0.1.4/openshell-x86_64-unknown-linux-musl.tar.gz

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Static musl CLI (no glibc dependency). Pin the checksum in production.
RUN curl -fsSL "$OPENSHELL_CLI_URL" -o /tmp/openshell.tgz \
    && tar -xzf /tmp/openshell.tgz -C /tmp \
    && find /tmp -name openshell -type f -exec mv {} /usr/local/bin/openshell \; \
    && chmod +x /usr/local/bin/openshell \
    && openshell --version || true

WORKDIR /opt/launcher
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

ENV OPN_CONFIG_DIR=/config \
    OPN_GATEWAY_URL=http://gateway:8080 \
    PYTHONUNBUFFERED=1

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
