"""One Flower 1.43 ClientApp for nodes A/B/C. Importing never starts training."""
from pathlib import Path
import sys
import time

# Keep the existing shared scripts usable from both the repo and app bundle.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))

from flwr.app import ArrayRecord, ConfigRecord, Context, Message, MetricRecord, RecordDict
from flwr.clientapp import ClientApp
from flow_features import SCHEMA
from model_runtime import predict_proba
from train_mlp import attack_group_recall
from fl.local_data import LocalInputs
from fl.mlp_adapter import (PARAMETER_NAMES, evaluate as evaluate_model, parameter_sha256,
                           portable_weights, train_round, validate_parameters)

app = ClientApp()


def _local(context):
    # These values are set by the local SuperNode, never by server message data.
    return LocalInputs(context.node_config['project-root'], context.node_config['node-id'])


def _config(message, local, *, with_arrays):
    expected_records = {'config', 'arrays'} if with_arrays else {'config'}
    if set(message.content) != expected_records or not isinstance(message.content['config'], ConfigRecord):
        raise ValueError('Unexpected message records')
    config = message.content['config']
    allowed = {'fl-config-sha256', 'schema-version'}
    if with_arrays:
        allowed |= {'server-round', 'parameters-sha256', 'local-epochs'}
    if set(config) - allowed:
        raise ValueError('Server cannot override node, data path, split, or training policy')
    if config.get('schema-version') != SCHEMA or config.get('fl-config-sha256') != local.config_sha256:
        raise ValueError('Server/local FL config or schema mismatch')
    if with_arrays:
        round_id = config.get('server-round')
        if type(round_id) is not int or not 1 <= round_id <= local.config['training']['rounds']:
            raise ValueError('Invalid server-round')
        epochs = config.get('local-epochs', local.config['training']['local_epochs'])
        if type(epochs) is not int or epochs != local.config['training']['local_epochs']:
            raise ValueError('Server local-epochs differs from fixed FL config')
    return config


def _parameters(message, config):
    record = message.content['arrays']
    if not isinstance(record, ArrayRecord) or set(record) != {str(i) for i in range(len(PARAMETER_NAMES))}:
        raise ValueError('Expected six numbered model arrays')
    # Decode by explicit keys rather than relying on wire/map insertion order.
    parameters = [record[str(i)].numpy() for i in range(len(PARAMETER_NAMES))]
    validate_parameters(parameters)
    if parameter_sha256(parameters) != config.get('parameters-sha256'):
        raise ValueError('Global parameter hash differs from request')
    return parameters


def _metadata(local, request, received, updated=None):
    values = local.properties()
    values.update({'server-round': request['server-round'],
                   'received-parameters-sha256': received})
    if updated is not None:
        values['updated-parameters-sha256'] = updated
    return ConfigRecord(values)


@app.query('properties')
def properties(message: Message, context: Context) -> Message:
    local = _local(context)
    _config(message, local, with_arrays=False)
    return Message(content=RecordDict({'properties': ConfigRecord(local.properties())}), reply_to=message)


@app.train()
def train(message: Message, context: Context) -> Message:
    local = _local(context)
    request = _config(message, local, with_arrays=True)
    parameters = _parameters(message, request)
    values, labels = local.load('train')
    start = time.perf_counter()
    updated, details = train_round(parameters, values, labels, local.config,
                                   local.node_id, request['server-round'])
    metrics = MetricRecord({'num-examples': details['num_examples'],
                            'train-loss': details['epoch_losses'][-1],
                            'local-epochs': details['local_epochs'],
                            'train-seconds': time.perf_counter()-start})
    content = RecordDict({'arrays': ArrayRecord(numpy_ndarrays=updated), 'metrics': metrics,
        'metadata': _metadata(local, request, details['received_parameters_sha256'],
                              details['updated_parameters_sha256'])})
    return Message(content=content, reply_to=message)


@app.evaluate()
def evaluate(message: Message, context: Context) -> Message:
    local = _local(context)
    request = _config(message, local, with_arrays=True)
    parameters = _parameters(message, request)
    values, labels = local.load('validation')
    start = time.perf_counter()
    report = evaluate_model(parameters, values, labels, local.config)
    tn, fp = report['confusion_matrix'][0]
    fn, tp = report['confusion_matrix'][1]
    probability = predict_proba(values, portable_weights(parameters))
    groups = attack_group_recall(values, labels, (probability >= local.config['model']['threshold']).astype(int))
    metrics = {'num-examples': report['num_examples'], 'loss': report['loss'],
               'balanced-accuracy': report['balanced_accuracy'], 'f1-macro': report['f1_macro'],
               'precision-attack': report['precision_attack'], 'recall-attack': report['recall_attack'],
               'false-positive-rate': report['false_positive_rate'],
               'tn': tn, 'fp': fp, 'fn': fn, 'tp': tp,
               'evaluate-seconds': time.perf_counter()-start}
    for name, group in groups.items():
        metrics[name + '-total'] = group['rows']
        metrics[name + '-detected'] = group['detected']
    return Message(content=RecordDict({'metrics': MetricRecord(metrics),
        'metadata': _metadata(local, request, parameter_sha256(parameters))}), reply_to=message)
