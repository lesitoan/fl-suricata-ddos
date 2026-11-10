"""Synthetic-only checks for the MLP FL adapter. Does not load any lab data."""
import argparse
import copy
import json
from pathlib import Path
import sys

import numpy as np
from flwr.app import ArrayRecord

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
from model_runtime import transform, predict_proba
from train_mlp import build_sample_weights
from mlp_adapter import (initial_parameters, estimator_from_parameters, export_parameters,
                         portable_weights, parameter_sha256, validate_parameters,
                         train_round, evaluate)


def full_batch_adam_first_step(parameters, raw, labels, weights, config):
    """Independent one-step gradient/Adam reference; does not call sklearn fit."""
    x = transform(raw)
    w0, b0, w1, b1, w2, b2 = parameters
    h0 = np.maximum(x @ w0 + b0, 0)
    h1 = np.maximum(h0 @ w1 + b1, 0)
    logits = h1 @ w2 + b2
    probability = 1/(1+np.exp(-logits[:, 0]))
    delta2 = ((probability-labels)*weights)[:, None]
    delta1 = (delta2 @ w2.T) * (h1 > 0)
    delta0 = (delta1 @ w1.T) * (h0 > 0)
    total, alpha = weights.sum(), config['training']['alpha']
    gradients = [(x.T @ delta0 + alpha*w0)/total, delta0.sum(axis=0)/total,
                 (h0.T @ delta1 + alpha*w1)/total, delta1.sum(axis=0)/total,
                 (h1.T @ delta2 + alpha*w2)/total, delta2.sum(axis=0)/total]
    # scikit-learn 1.8 Adam's default betas/epsilon, first update after reset.
    lr = config['training']['learning_rate_init']*np.sqrt(1-.999)/(1-.9)
    return [value-lr*(.1*gradient)/(np.sqrt(.001*gradient*gradient)+1e-8)
            for value, gradient in zip(parameters, gradients)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT/'config/fl/fedavg.json')
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding='utf-8-sig'))
    n = config['training']['batch_size']
    if n != 256 or config['training']['local_epochs'] != 1:
        raise ValueError('This one-full-batch check expects batch256/local_epoch1')
    rng = np.random.RandomState(401)
    raw = np.empty((n, 9), dtype=np.float64)
    raw[:, 0] = rng.choice([6, 17], n)
    raw[:, 1] = rng.uniform(.001, 1.0, n)
    raw[:, 2] = rng.randint(1, 20, n)
    raw[:, 3] = rng.randint(1, 10, n)
    labels = np.tile([0, 1], n//2).astype(np.int64)
    raw[np.arange(n)%8 == 1, 3] = 0  # Both attack direction groups for B.
    raw[:, 4] = raw[:, 2]*rng.randint(60, 1500, n)
    raw[:, 5] = raw[:, 3]*rng.randint(60, 1500, n)
    raw[:, 6] = (raw[:, 4]+raw[:, 5])/(raw[:, 2]+raw[:, 3])
    raw[:, 7] = raw[:, 3]/raw[:, 2]
    raw[:, 8] = 0
    initial = initial_parameters(config)
    initial_hash = parameter_sha256(initial)
    assert initial_hash == parameter_sha256(initial_parameters(config))
    changed_seed = copy.deepcopy(config)
    changed_seed['training']['seed'] += 1
    assert initial_hash != parameter_sha256(initial_parameters(changed_seed))
    estimator = estimator_from_parameters(initial, config, seed=42)
    assert estimator.n_iter_ == estimator.t_ == 0 and not hasattr(estimator, '_optimizer')
    assert parameter_sha256(export_parameters(estimator)) == initial_hash
    portable = predict_proba(raw, portable_weights(initial))
    error = float(np.max(np.abs(estimator.predict_proba(transform(raw))[:, 1]-portable)))
    assert error <= 1e-12
    after_transport = ArrayRecord(numpy_ndarrays=initial).to_numpy_ndarrays()
    assert parameter_sha256(after_transport) == initial_hash
    rounds, gradient_errors = {}, []
    for node_id in ('A', 'B', 'C'):
        updated, details = train_round(after_transport, raw, labels, config, node_id, 1)
        assert details['num_examples'] == n and details['received_parameters_sha256'] == initial_hash
        assert details['updated_parameters_sha256'] != initial_hash
        assert parameter_sha256(initial) == initial_hash  # Caller/global arrays untouched.
        weights, _ = build_sample_weights(raw, labels, config['clients'][node_id]['sample_weighting'])
        reference = full_batch_adam_first_step(initial, raw, labels, weights, config)
        max_error = max(float(np.max(np.abs(a-b))) for a,b in zip(updated, reference))
        assert max_error <= 1e-12, (node_id, max_error)
        gradient_errors.append(max_error)
        # A second round must use the newly supplied global weights and reset
        # Adam moments. Its first step is checked against an independent reset.
        second, second_info = train_round(updated, raw, labels, config, node_id, 2)
        reference = full_batch_adam_first_step(updated, raw, labels, weights, config)
        max_error = max(float(np.max(np.abs(a-b))) for a,b in zip(second, reference))
        assert max_error <= 1e-12, (node_id, 'round2', max_error)
        gradient_errors.append(max_error)
        assert second_info['received_parameters_sha256'] == parameter_sha256(updated)
        repeat, _ = train_round(updated, raw, labels, config, node_id, 2)
        assert parameter_sha256(second) == parameter_sha256(repeat)
        before_eval = parameter_sha256(second)
        report = evaluate(second, raw, labels, config)
        assert report['rows'] == n and sum(map(sum,report['confusion_matrix'])) == n
        assert np.isfinite(report['loss']) and parameter_sha256(second) == before_eval
        rounds[node_id] = {'num_examples': n, 'weighting': details['sample_weighting']['mode'],
                           'round2_received_global_exactly': True, 'evaluation_does_not_fit': True}
    rejected = []
    for name, mutation in (
        ('shape', lambda p: p.__setitem__(0, p[0][:1])),
        ('dtype', lambda p: p.__setitem__(0, p[0].astype(np.float32))),
        ('nonfinite', lambda p: p[0].__setitem__((0,0),np.nan)),
        ('missing_array', lambda p: p.pop()),
    ):
        invalid = [value.copy() for value in initial]
        mutation(invalid)
        try:
            validate_parameters(invalid)
        except ValueError:
            rejected.append(name)
        else:
            raise AssertionError('Invalid weights accepted: '+name)
    print(json.dumps({'result':'PASS FL MLP adapter','scope':'Synthetic256rows only; no dataset/baseline mounts, real node training, or FL networking',
        'initial_parameters_sha256':initial_hash, 'parameters':sum(p.size for p in initial),
        'portable_inference_max_abs_error':error,
        'independent_adam_step_max_abs_error':max(gradient_errors),
        'initialization_without_fit':True,'optimizer_reset_each_round_verified':True,
        'flower_array_roundtrip':True,'nodes':rounds,'invalid_inputs_rejected':rejected}),flush=True)


if __name__ == '__main__':
    main()
