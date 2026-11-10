"""Shared, dataset-independent MLP operations for Flower server/client code.

The sole private sklearn initialization hook is pinned to 1.8.0. It allocates
an unfitted estimator; no dummy gradient step is used to load global weights.
Adam state is local to one train_round call and is never aggregated.
"""
import hashlib
import json

import numpy as np
import sklearn
from sklearn.metrics import log_loss
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import LabelBinarizer
from sklearn.utils import check_random_state

from flow_features import FEATURES, SCHEMA
from model_runtime import TRANSFORM, transform, predict_proba
from train_mlp import build_sample_weights, metrics

PARAMETER_NAMES = ('coef_0', 'intercept_0', 'coef_1', 'intercept_1', 'coef_2', 'intercept_2')
PARAMETER_SHAPES = ((13, 32), (32,), (32, 16), (16,), (16, 1), (1,))


def validate_config(config):
    if sklearn.__version__ != '1.8.0':
        raise ValueError('MLP initialization adapter requires scikit-learn 1.8.0')
    model, training = config['model'], config['training']
    expected = {'schema_version': SCHEMA, 'features': FEATURES, 'transform': TRANSFORM,
                'input_width': 13, 'hidden_layer_sizes': [32, 16], 'output_width': 1,
                'activation': 'relu', 'output_activation': 'sigmoid', 'dtype': 'float64',
                'threshold': .5, 'labels': {'benign': 0, 'attack': 1}}
    if any(model.get(key) != value for key, value in expected.items()):
        raise ValueError('Unsupported MLP feature/architecture/label contract')
    if training.get('solver') != 'adam' or training.get('optimizer_state') != 'reset_each_round':
        raise ValueError('Require local Adam with fresh state each round')
    if training.get('initialization') != 'fresh_shared_weights':
        raise ValueError('Require common fresh global initialization')
    for key in ('seed', 'local_epochs', 'batch_size'):
        value = training[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < (0 if key == 'seed' else 1):
            raise ValueError('Invalid training integer: ' + key)
    if training['seed'] > 2**32-1:
        raise ValueError('Seed exceeds RandomState range')
    for key in ('learning_rate_init', 'alpha'):
        value = training[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not np.isfinite(value) or value < 0:
            raise ValueError('Invalid optimizer setting: ' + key)
    if training['learning_rate_init'] == 0:
        raise ValueError('Learning rate must be positive')


def validate_parameters(parameters):
    if len(parameters) != len(PARAMETER_NAMES):
        raise ValueError('Expected six ordered coefficient/bias arrays')
    for name, shape, value in zip(PARAMETER_NAMES, PARAMETER_SHAPES, parameters):
        if not isinstance(value, np.ndarray) or value.dtype != np.dtype('float64') or value.shape != shape:
            raise ValueError('Wrong dtype or shape: ' + name)
        if not np.isfinite(value).all():
            raise ValueError('Nonfinite parameter: ' + name)


def parameter_sha256(parameters):
    """Canonical tensor hash, distinct from the SHA256 of an NPZ file."""
    validate_parameters(parameters)
    digest = hashlib.sha256()
    for name, value in zip(PARAMETER_NAMES, parameters):
        digest.update(json.dumps([name, list(value.shape), '<f8'], separators=(',', ':')).encode())
        digest.update(np.asarray(value, dtype='<f8', order='C').tobytes(order='C'))
    return digest.hexdigest()


def portable_weights(parameters):
    validate_parameters(parameters)
    result = {name: value.copy() for name, value in zip(PARAMETER_NAMES, parameters)}
    result['layers'] = np.asarray(3, dtype=np.int64)
    return result


def export_parameters(estimator):
    parameters = []
    for coefficient, bias in zip(estimator.coefs_, estimator.intercepts_):
        parameters.extend((coefficient.copy(), bias.copy()))
    validate_parameters(parameters)
    return parameters


def _untrained_estimator(config, seed):
    validate_config(config)
    training = config['training']
    estimator = MLPClassifier(
        hidden_layer_sizes=(32, 16), activation='relu', solver='adam',
        learning_rate_init=training['learning_rate_init'], alpha=training['alpha'],
        batch_size=training['batch_size'], random_state=seed,
        max_iter=1, shuffle=True, early_stopping=False,
    )
    # Pinned 1.8.0 hook: initialize structure/RNG/label encoding, without fitting.
    estimator._random_state = check_random_state(seed)
    estimator._label_binarizer = LabelBinarizer().fit(np.asarray([0, 1]))
    estimator.classes_ = estimator._label_binarizer.classes_.copy()
    estimator.n_features_in_ = 13
    estimator._initialize(np.empty((0, 1), dtype=np.float64), [13, 32, 16, 1], np.float64)
    return estimator


def initial_parameters(config):
    """Common random initialization from config seed; no data or fitting."""
    return export_parameters(_untrained_estimator(config, config['training']['seed']))


def estimator_from_parameters(parameters, config, seed=None):
    validate_parameters(parameters)
    estimator = _untrained_estimator(config, config['training']['seed'] if seed is None else seed)
    estimator.coefs_ = [parameters[i].copy() for i in (0, 2, 4)]
    estimator.intercepts_ = [parameters[i].copy() for i in (1, 3, 5)]
    estimator._best_coefs = [value.copy() for value in estimator.coefs_]
    estimator._best_intercepts = [value.copy() for value in estimator.intercepts_]
    return estimator


def _data(raw, labels):
    transformed = transform(raw)
    labels = np.asarray(labels)
    if len(transformed) == 0 or labels.ndim != 1 or labels.dtype.kind not in 'iu' or len(labels) != len(transformed):
        raise ValueError('Expected nonempty aligned data and integer binary labels')
    if not np.array_equal(np.unique(labels), [0, 1]):
        raise ValueError('Both classes 0 and 1 are required by this pilot protocol')
    return transformed, labels


def train_round(parameters, raw, labels, config, node_id, round_id):
    """One local update; never reads files, test data, or baseline checkpoints."""
    validate_config(config)
    validate_parameters(parameters)
    if node_id not in ('A', 'B', 'C'):
        raise ValueError('Expected node A/B/C')
    if isinstance(round_id, bool) or not isinstance(round_id, int) or round_id < 1:
        raise ValueError('Expected a positive round ID')
    transformed, labels = _data(raw, labels)
    raw = np.asarray(raw, dtype=np.float64)
    weighting_mode = config['clients'][node_id]['sample_weighting']
    sample_weights, weighting = build_sample_weights(raw, labels, weighting_mode)
    # Explicit deterministic shuffle seed for this node/round. Same global
    # parameters are installed regardless of this seed; only local order varies.
    seed = (config['training']['seed'] + 1009 * round_id + ord(node_id)-ord('A')) % (2**32)
    estimator = estimator_from_parameters(parameters, config, seed=seed)
    received_sha = parameter_sha256(export_parameters(estimator))
    if received_sha != parameter_sha256(parameters):
        raise RuntimeError('Incoming global weights were not installed exactly')
    losses = []
    for _ in range(config['training']['local_epochs']):
        estimator.partial_fit(transformed, labels, classes=np.asarray([0, 1]), sample_weight=sample_weights)
        if not np.isfinite(estimator.loss_):
            raise ValueError('Nonfinite local training loss')
        losses.append(float(estimator.loss_))
    updated = export_parameters(estimator)
    # FedAvg weight is the number of actual train rows, not sum(sample_weight).
    return updated, {'node_id': node_id, 'round_id': round_id,
                     'num_examples': int(len(labels)),
                     'local_epochs': config['training']['local_epochs'],
                     'epoch_losses': losses, 'sample_weighting': weighting,
                     'received_parameters_sha256': received_sha,
                     'updated_parameters_sha256': parameter_sha256(updated)}


def evaluate(parameters, raw, labels, config):
    """Evaluate a supplied local array without fit or parameter changes."""
    validate_config(config)
    _data(raw, labels)
    labels = np.asarray(labels)
    probability = predict_proba(raw, portable_weights(parameters))
    report = metrics(labels, (probability >= config['model']['threshold']).astype(int))
    report['loss'] = float(log_loss(labels, probability, labels=[0, 1]))
    report['num_examples'] = int(len(labels))
    return report
