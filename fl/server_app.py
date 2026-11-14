"""Flower ServerApp: strict 3-client FedAvg, validation selection, portable export.

No node CSV, EVE, PCAP, or local baseline is opened by the server. Importing
only registers the app; real execution needs the Flower deployment runtime.
"""
import copy
import hashlib
import json
import math
from pathlib import Path
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))

import numpy as np
from flwr.app import ArrayRecord, ConfigRecord, Context, Message, MetricRecord, RecordDict
from flwr.serverapp import Grid, ServerApp
from flwr.serverapp.strategy import FedAvg
from check_fl_inputs import inside, sha
from flow_features import SCHEMA
from train_mlp import model_output
from fl.mlp_adapter import (initial_parameters, parameter_sha256, portable_weights,
                           validate_config, validate_parameters)

app = ServerApp()


def parameters(record):
    if not isinstance(record, ArrayRecord) or set(record) != {str(i) for i in range(6)}:
        raise ValueError('Expected six numbered global/update arrays')
    values = [record[str(i)].numpy() for i in range(6)]
    validate_parameters(values)
    return values


def logical_message_bytes(message):
    """Serialized Flower object tree, not HTTP/TLS/network/cache traffic."""
    seen = set()
    def size(obj):
        identifier = obj.object_id
        if identifier in seen:
            return 0
        seen.add(identifier)
        return len(obj.deflate()) + sum(size(child) for child in (obj.children or {}).values())
    return size(message)


def counts_metrics(tn, fp, fn, tp):
    if min(tn, fp, fn, tp) < 0 or tn+fp == 0 or fn+tp == 0:
        raise ValueError('Confusion counts must contain both classes')
    precision = tp/(tp+fp) if tp+fp else 0.0
    recall = tp/(tp+fn)
    attack_f1 = 2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0.0
    benign_f1 = 2*tn/(2*tn+fp+fn) if 2*tn+fp+fn else 0.0
    return {'precision-attack': precision, 'recall-attack': recall,
            'false-positive-rate': fp/(tn+fp), 'balanced-accuracy': (recall+tn/(tn+fp))/2,
            'f1-macro': (attack_f1+benign_f1)/2}


def _finite_number(value):
    return type(value) in (int, float) and math.isfinite(value)


class StrictFedAvg(FedAvg):
    def __init__(self, config, config_sha256, peers, on_round=None):
        validate_config(config)
        if (config['algorithm'] != 'FedAvg' or set(config['clients']) != {'A','B','C'}
                or config['training']['require_all_clients'] is not True
                or config['training']['aggregation_weight'] != 'num_train_rows'
                or config['training']['checkpoint_selection'] != 'mean_node_validation_balanced_accuracy'
                or config['training']['checkpoint_tie_break'] != 'earliest_round'):
            raise ValueError('Unsupported federation policy')
        super().__init__(fraction_train=1.0, fraction_evaluate=1.0,
                         min_train_nodes=3, min_evaluate_nodes=3, min_available_nodes=3,
                         weighted_by_key='num-examples')
        self.config, self.config_sha256 = copy.deepcopy(config), config_sha256
        self.peers = {}
        logical_ids = set()
        if len(peers) != 3:
            raise ValueError('Exactly three peer identities required')
        for transport_id, properties in peers.items():
            self.validate_properties(properties)
            if properties['node-id'] in logical_ids:
                raise ValueError('Duplicate logical client ID')
            logical_ids.add(properties['node-id'])
            self.peers[transport_id] = dict(properties)
        if logical_ids != {'A','B','C'}:
            raise ValueError('Require clients A/B/C')
        self.history, self.best_parameters = [], None
        self.best_score, self.best_round = -math.inf, None
        self.pending, self.on_round = None, on_round

    def validate_properties(self, properties):
        node = properties.get('node-id')
        if node not in self.config['clients']:
            raise ValueError('Unknown logical client ID')
        expected = {'schema-version': SCHEMA, 'fl-config-sha256': self.config_sha256,
                    'manifest-sha256': self.config['clients'][node]['manifest_sha256'],
                    'sample-weighting': self.config['clients'][node]['sample_weighting']}
        if any(properties.get(key) != value for key, value in expected.items()):
            raise ValueError('Peer config/manifest contract differs')
        if set(properties) != {'node-id',*expected,'num-train-examples','num-validation-examples'}:
            raise ValueError('Unexpected client properties')
        for key in ('num-train-examples','num-validation-examples'):
            if type(properties.get(key)) is not int or properties[key] < 2:
                raise ValueError('Invalid peer sample count')

    def _messages(self, round_id, arrays, grid, kind):
        if set(grid.get_node_ids()) != set(self.peers):
            raise ValueError('Connected peer set changed; require registered A/B/C')
        values = parameters(arrays)
        config = ConfigRecord({'schema-version': SCHEMA, 'fl-config-sha256': self.config_sha256,
                               'server-round': round_id, 'parameters-sha256': parameter_sha256(values),
                               'local-epochs': self.config['training']['local_epochs']})
        content = RecordDict({'arrays':arrays,'config':config})
        messages = [Message(content=content,dst_node_id=peer,message_type=kind) for peer in sorted(self.peers)]
        return messages

    def configure_train(self, server_round, arrays, config, grid):
        started = time.perf_counter()
        if self.pending is not None or server_round != len(self.history)+1:
            raise ValueError('Train rounds must follow fully validated rounds')
        messages = self._messages(server_round, arrays, grid, 'train')
        self.pending = {'round':server_round,'started_monotonic':started,'input_parameters_sha256':parameter_sha256(parameters(arrays)),
                        'communication':{'train_down_model_array_bytes':3*sum(v.nbytes for v in parameters(arrays)),
                                         'train_down_flower_object_bytes':sum(logical_message_bytes(m) for m in messages)}}
        return messages

    def _replies(self, round_id, replies, *, train):
        replies = list(replies)
        if self.pending is None or self.pending['round'] != round_id or len(replies) != 3:
            raise ValueError('Missing replies or invalid round')
        expected_hash = self.pending['input_parameters_sha256'] if train else self.pending['global_parameters_sha256']
        by_node, transports = {}, set()
        for reply in replies:
            peer = reply.metadata.src_node_id
            if peer not in self.peers or peer in transports or reply.has_error():
                raise ValueError('Unknown/duplicate/failed peer reply')
            if reply.metadata.message_type != ('train' if train else 'evaluate'):
                raise ValueError('Wrong reply message type')
            transports.add(peer)
            expected_records = {'arrays','metrics','metadata'} if train else {'metrics','metadata'}
            if set(reply.content) != expected_records or not isinstance(reply.content['metadata'],ConfigRecord) or not isinstance(reply.content['metrics'],MetricRecord):
                raise ValueError('Unexpected reply record contract')
            meta, metric = reply.content['metadata'], reply.content['metrics']
            required_meta = dict(self.peers[peer], **{'server-round':round_id,'received-parameters-sha256':expected_hash})
            if any(meta.get(key) != value for key,value in required_meta.items()):
                raise ValueError('Peer/round/global hash mismatch')
            expected_meta_keys = set(required_meta) | ({'updated-parameters-sha256'} if train else set())
            if set(meta) != expected_meta_keys:
                raise ValueError('Unexpected reply metadata')
            count_key = 'num-train-examples' if train else 'num-validation-examples'
            if type(metric.get('num-examples')) is not int or metric['num-examples'] != self.peers[peer][count_key]:
                raise ValueError('Reply sample count differs from registered partition')
            if any(not _finite_number(value) for value in metric.values()):
                raise ValueError('Nonfinite or nonnumeric reply metric')
            if train:
                values = parameters(reply.content['arrays'])
                if parameter_sha256(values) != meta.get('updated-parameters-sha256'):
                    raise ValueError('Update hash mismatch')
                if set(metric) != {'num-examples','train-loss','local-epochs','train-seconds'} or metric['train-loss'] < 0 or metric['train-seconds'] < 0 or type(metric['local-epochs']) is not int or metric['local-epochs'] != self.config['training']['local_epochs']:
                    raise ValueError('Invalid local training metrics/policy')
            else:
                keys = ('tn','fp','fn','tp')
                if any(type(metric.get(key)) is not int or metric[key] < 0 for key in keys) or sum(metric[key] for key in keys) != metric['num-examples']:
                    raise ValueError('Invalid validation confusion counts')
                recomputed = counts_metrics(*(metric[key] for key in keys))
                if any(abs(metric.get(key,math.inf)-value) > 1e-12 for key,value in recomputed.items()):
                    raise ValueError('Validation ratios differ from confusion counts')
                if metric.get('loss',-1) < 0 or metric.get('evaluate-seconds',-1) < 0:
                    raise ValueError('Invalid validation loss/time')
                for group in ('attack_no_return','attack_has_return'):
                    total,detected = metric.get(group+'-total'),metric.get(group+'-detected')
                    if type(total) is not int or type(detected) is not int or not 0 <= detected <= total:
                        raise ValueError('Invalid attack subgroup counts')
                if metric['attack_no_return-total']+metric['attack_has_return-total'] != metric['fn']+metric['tp'] or metric['attack_no_return-detected']+metric['attack_has_return-detected'] != metric['tp']:
                    raise ValueError('Attack subgroups differ from confusion counts')
            by_node[meta['node-id']] = reply
        if transports != set(self.peers) or set(by_node) != {'A','B','C'}:
            raise ValueError('Incomplete A/B/C replies')
        return replies,by_node

    def aggregate_train(self, server_round, replies):
        if self.pending is None or 'global_parameters_sha256' in self.pending:
            raise ValueError('No pending train or already aggregated')
        replies,by_node = self._replies(server_round,replies,train=True)
        self.pending['train_clients'] = {node:{'metrics':dict(reply.content['metrics']),
            'updated_parameters_sha256':reply.content['metadata']['updated-parameters-sha256']} for node,reply in by_node.items()}
        self.pending['communication'].update({
            'train_up_model_array_bytes':sum(sum(v.nbytes for v in parameters(reply.content['arrays'])) for reply in replies),
            'train_up_flower_object_bytes':sum(logical_message_bytes(reply) for reply in replies)})
        # Use Flower's FedAvg implementation after strict reply checks.
        arrays,metrics = super().aggregate_train(server_round,replies)
        if arrays is None or metrics is None:
            raise ValueError('FedAvg did not produce a global model')
        self.pending['global_parameters_sha256'] = parameter_sha256(parameters(arrays))
        self.pending['global_arrays'] = arrays
        return arrays,metrics

    def configure_evaluate(self, server_round, arrays, config, grid):
        if self.pending is None or self.pending['round'] != server_round or self.pending.get('global_parameters_sha256') != parameter_sha256(parameters(arrays)) or self.pending.get('evaluate_sent'):
            raise ValueError('Evaluation must use this round aggregated global weights')
        messages = self._messages(server_round,arrays,grid,'evaluate')
        self.pending['evaluate_sent'] = True
        self.pending['communication'].update({
            'evaluate_down_model_array_bytes':3*sum(v.nbytes for v in parameters(arrays)),
            'evaluate_down_flower_object_bytes':sum(logical_message_bytes(m) for m in messages)})
        return messages

    def aggregate_evaluate(self, server_round, replies):
        if self.pending is None or not self.pending.get('evaluate_sent'):
            raise ValueError('No pending validation request')
        replies,by_node = self._replies(server_round,replies,train=False)
        per_node = {node:dict(reply.content['metrics']) for node,reply in by_node.items()}
        counts = [sum(values[key] for values in per_node.values()) for key in ('tn','fp','fn','tp')]
        pooled = counts_metrics(*counts)
        total = sum(values['num-examples'] for values in per_node.values())
        mean_ba = sum(values['balanced-accuracy'] for values in per_node.values())/3
        summary = MetricRecord({'balanced-accuracy-macro-node':mean_ba,
            'loss':sum(values['loss']*values['num-examples'] for values in per_node.values())/total,
            'num-examples':total,**dict(zip(('tn','fp','fn','tp'),counts)),
            **{'pooled-'+key:value for key,value in pooled.items()}})
        self.pending['communication']['evaluate_up_flower_object_bytes'] = sum(logical_message_bytes(reply) for reply in replies)
        global_parameters = parameters(self.pending['global_arrays'])
        if mean_ba > self.best_score:
            self.best_score,self.best_round = mean_ba,server_round
            self.best_parameters = [value.copy() for value in global_parameters]
        completed = {key:value for key,value in self.pending.items() if key not in ('global_arrays','evaluate_sent','started_monotonic')}
        completed.update({'validation_clients':per_node,'validation_summary':dict(summary),
                          'round_seconds':time.perf_counter()-self.pending['started_monotonic']})
        self.history.append(completed)
        self.pending = None
        if self.on_round:
            self.on_round(self)
        return summary


def discover_peers(grid,config,config_sha256,timeout):
    deadline = time.monotonic()+timeout
    ids = set(grid.get_node_ids())
    while len(ids) < 3 and time.monotonic() < deadline:
        time.sleep(.5)
        ids = set(grid.get_node_ids())
    if len(ids) != 3:
        raise ValueError('Discovery requires exactly three connected SuperNodes')
    content = RecordDict({'config':ConfigRecord({'schema-version':SCHEMA,'fl-config-sha256':config_sha256})})
    requests = [Message(content=content,dst_node_id=peer,message_type='query.properties') for peer in sorted(ids)]
    replies = list(grid.send_and_receive(requests,timeout=max(.01,deadline-time.monotonic())))
    peers = {}
    for reply in replies:
        peer = reply.metadata.src_node_id
        if peer not in ids or peer in peers or reply.has_error() or reply.metadata.message_type != 'query.properties' or set(reply.content) != {'properties'} or not isinstance(reply.content['properties'],ConfigRecord):
            raise ValueError('Invalid or failed discovery reply')
        peers[peer] = dict(reply.content['properties'])
    # Constructor verifies unique logical A/B/C and frozen config/manifest hashes.
    StrictFedAvg(config,config_sha256,peers)
    return peers


def _atomic_json(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=path.parent,delete=False,prefix='.'+path.name+'-') as stream:
        temporary = Path(stream.name)
        json.dump(value,stream,indent=2,allow_nan=False);stream.write('\n')
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def publish_global(root,config,config_sha256,strategy,num_rounds):
    if strategy.best_parameters is None or len(strategy.history) != num_rounds or strategy.pending is not None:
        raise ValueError('Cannot publish an incomplete federation run')
    if config['global_model_output'] != 'models/fl/current':
        raise ValueError('Global output must be models/fl/current')
    output = inside(root,config['global_model_output'],'models/fl')
    with model_output(output) as prepared:
        np.savez(prepared/'weights.npz',**portable_weights(strategy.best_parameters))
        meta = copy.deepcopy(config['model'])
        meta.update({'weights_sha256':sha(prepared/'weights.npz'),
            'selected_round':strategy.best_round,'preprocessing_fitted':False,
            'config':{'experiment_id':config['experiment_id'],'algorithm':'FedAvg',
                      'seed':config['training']['seed'],'local_epochs':config['training']['local_epochs']},
            'scope':'Federated pilot selected by distributed validation; no independent generalization, convergence or live attack claim'})
        (prepared/'model.json').write_text(json.dumps(meta,indent=2)+'\n',encoding='utf-8')
        report = {'algorithm':'FedAvg','config_sha256':config_sha256,'rounds_completed':num_rounds,
            'selected_round':strategy.best_round,'selection_metric':'mean_node_validation_balanced_accuracy',
            'best_validation_score':strategy.best_score,'history':strategy.history,
            'convergence_assessed':False,'test_evaluated':False,
            'artifacts':{name:sha(prepared/name) for name in ('weights.npz','model.json')}}
        (prepared/'metrics.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    return output


def run_federation(grid,root,num_rounds=None,timeout=300):
    root = Path(root)
    if not root.is_absolute():
        raise ValueError('Server project-root must be absolute')
    root = root.resolve()
    config_path = inside(root,'config/fl/fedavg.json','config/fl')
    blob = config_path.read_bytes()
    config,config_sha256 = json.loads(blob.decode('utf-8-sig')),hashlib.sha256(blob).hexdigest()
    validate_config(config)
    rounds = config['training']['rounds'] if num_rounds is None else num_rounds
    if type(rounds) is not int or not 1 <= rounds <= config['training']['rounds'] or type(timeout) not in (int,float) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('Invalid round count/timeout')
    report_path = inside(root,'reports/fl/training.json','reports/fl')
    report_path.parent.mkdir(parents=True,exist_ok=True)
    lock = report_path.parent/'.server-run-lock'
    lock.mkdir()  # Fixed model/report paths permit only one run at a time.
    strategy = None
    state = {'status':'discovering','algorithm':'FedAvg','config_sha256':config_sha256,
             'telemetry_run_id':uuid.uuid4().hex,
             'rounds_requested':rounds,'completed_rounds':0,'history':[],
             'test_evaluated':False,'convergence_assessed':False,
             'communication_scope':'Train/evaluate round messages: raw arrays and serialized Flower object trees. Excludes discovery, app bundles, HTTP/TLS/cache effects and actual network traffic'}
    try:
        _atomic_json(report_path,state)
        peers = discover_peers(grid,config,config_sha256,timeout)
        state['peers'] = {str(peer):properties for peer,properties in peers.items()}
        def on_round(current):
            state.update({'status':'training','completed_rounds':len(current.history),
                          'history':current.history,'selected_round':current.best_round,
                          'best_validation_score':current.best_score})
            _atomic_json(report_path,state)
        strategy = StrictFedAvg(config,config_sha256,peers,on_round=on_round)
        initial = initial_parameters(config)
        state['initial_parameters_sha256'] = parameter_sha256(initial)
        strategy.start(grid=grid,initial_arrays=ArrayRecord(numpy_ndarrays=initial),num_rounds=rounds,timeout=timeout)
        output = publish_global(root,config,config_sha256,strategy,rounds)
        state.update({'status':'complete','global_model_output':output.relative_to(root).as_posix(),
                      'weights_sha256':sha(output/'weights.npz')})
        _atomic_json(report_path,state)
        return state
    except Exception as error:
        state.update({'status':'failed','completed_rounds':len(strategy.history) if strategy else 0,
                      'error':type(error).__name__+': '+str(error)})
        try:
            _atomic_json(report_path,state)
        except OSError:
            pass
        raise
    finally:
        lock.rmdir()


@app.main()
def main(grid:Grid,context:Context)->None:
    run_federation(grid,context.run_config.get('project-root','/workspace'),
                   num_rounds=context.run_config.get('num-rounds'),
                   timeout=context.run_config.get('timeout-seconds',300))
