ARG BASE_IMAGE=ddos-fl-laptop-node-a-ml:step1
FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.title="DDoS laptop Flower runtime" \
      org.opencontainers.image.version="1.43.0"

COPY fl/requirements.txt /opt/fl-runtime/requirements.txt
RUN python3 -m pip install --no-cache-dir --only-binary=:all: --no-deps \
      --disable-pip-version-check -r /opt/fl-runtime/requirements.txt \
    && python3 -m pip check

COPY fl/check_runtime.py /opt/fl-runtime/check_runtime.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 \
    FLWR_TELEMETRY_ENABLED=0 FLWR_DISABLE_RUNTIME_DEPENDENCY_INSTALLATION=1
WORKDIR /app

# A plain docker run checks dependencies only; it does not start a federation.
CMD ["python3", "-B", "/opt/fl-runtime/check_runtime.py"]
