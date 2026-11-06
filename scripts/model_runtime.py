"""Chuyển 9 đặc trưng thành 13 đầu vào và tính dự đoán từ trọng số MLP"""
import numpy as np
from flow_features import FEATURES

TRANSFORM = 'flow-v2-fixed-log-v1'
PROTOCOL_CODES = [6, 17, 1, 58, 0]


def transform(values):
    raw = np.asarray(values, dtype=np.float64)
    if raw.ndim != 2 or raw.shape[1] != len(FEATURES):
        raise ValueError('Expected ordered flow-v2 feature matrix')
    if not np.isfinite(raw).all() or (raw < 0).any():
        raise ValueError('Invalid feature value')
    if not np.isin(raw[:, 0], PROTOCOL_CODES).all() or not np.isin(raw[:, -1], [0, 1]).all():
        raise ValueError('Invalid protocol or duration flag')
    protocol = (raw[:, :1] == np.asarray(PROTOCOL_CODES)).astype(np.float64)
    continuous = np.log1p(raw[:, 1:-1])/10.0
    return np.concatenate([protocol, continuous, raw[:, -1:]], axis=1)


def predict_proba(values, weights):
    output = transform(values)
    layers = int(weights['layers'])
    for index in range(layers):
        output = output @ weights[f'coef_{index}'] + weights[f'intercept_{index}']
        if index+1 < layers:
            output = np.maximum(output, 0)
    return (1/(1+np.exp(-np.clip(output[:, 0], -709, 709))))
