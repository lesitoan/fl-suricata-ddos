"""Check the pinned Flower/ML environment without datasets, network, or fitting."""
import inspect
import json
import platform
import shutil
import subprocess
import sys
from importlib.metadata import version

import numpy as np
import scipy
import sklearn
import flwr
from sklearn.neural_network import MLPClassifier
from flwr.app import ArrayRecord, ConfigRecord, MetricRecord
from flwr.clientapp import ClientApp
from flwr.serverapp import ServerApp
from flwr.serverapp.strategy import FedAvg

EXPECTED = {
    'flwr': '1.43.0', 'numpy': '2.4.3', 'scikit-learn': '1.8.0',
    'scipy': '1.18.1', 'joblib': '1.6.0', 'threadpoolctl': '3.7.0',
    'cloudpickle': '3.1.2',
}


def main():
    versions = {name: version(name) for name in EXPECTED}
    if versions != EXPECTED:
        raise RuntimeError('Pinned ML/Flower versions differ: ' + str(versions))
    check = subprocess.run([sys.executable, '-m', 'pip', 'check'], capture_output=True, text=True, timeout=30)
    if check.returncode:
        raise RuntimeError('Dependency check failed: ' + check.stdout + check.stderr)
    names = ('flwr', 'flower-superlink', 'flower-supernode', 'flower-superexec')
    commands = {name: shutil.which(name) for name in names}
    if not all(commands.values()):
        raise RuntimeError('Missing Flower command: ' + str(commands))
    if 'sample_weight' not in inspect.signature(MLPClassifier.partial_fit).parameters:
        raise RuntimeError('MLP partial_fit sample_weight unavailable')
    arrays = [np.arange(6, dtype=np.float64).reshape(2, 3), np.zeros(3, dtype=np.float64)]
    restored = ArrayRecord(numpy_ndarrays=arrays).to_numpy_ndarrays()
    if len(restored) != len(arrays) or not all(np.array_equal(a, b) and a.dtype == b.dtype for a, b in zip(arrays, restored)):
        raise RuntimeError('Flower ndarray serialization differs')
    strategy = FedAvg(fraction_train=1.0, fraction_evaluate=1.0,
                      min_train_nodes=3, min_evaluate_nodes=3,
                      min_available_nodes=3, weighted_by_key='num-examples')
    ClientApp()
    ServerApp()
    ConfigRecord({'local-epochs': 1})
    MetricRecord({'num-examples': 3, 'loss': .5})
    print(json.dumps({
        'result': 'PASS FL runtime image', 'python': platform.python_version(),
        'versions': versions, 'pip_check': 'PASS',
        'flower_commands': list(commands), 'message_api': 'ServerApp/ClientApp',
        'strategy': type(strategy).__name__, 'numpy_arrayrecord_roundtrip': True,
        'partial_fit_sample_weight': True,
        'scope': 'Dependency/API/serialization check only; no dataset mounts, training, client connection, or convergence verified',
    }), flush=True)


if __name__ == '__main__':
    main()
