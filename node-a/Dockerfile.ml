ARG BASE_IMAGE=ddos-fl-node-a:local
FROM ${BASE_IMAGE}
RUN python3 -m venv /opt/node-a-ml \
    && /opt/node-a-ml/bin/pip install --no-cache-dir --only-binary=:all: \
       numpy==2.4.3 scikit-learn==1.8.0 scipy==1.18.1 joblib==1.6.0 \
       threadpoolctl==3.7.0 cloudpickle==3.1.2
ENV PATH="/opt/node-a-ml/bin:${PATH}" \
    OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
