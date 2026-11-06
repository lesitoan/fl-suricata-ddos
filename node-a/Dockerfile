FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    suricata python3 python3-yaml python3-venv ca-certificates tcpdump iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY node-a/configure.py /opt/node-a/configure.py
RUN python3 /opt/node-a/configure.py && mkdir -p /var/log/suricata
WORKDIR /app
