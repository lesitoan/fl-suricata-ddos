"""Read-only FL input preflight. Uses Python standard library; never trains a model."""
import argparse
import ast
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import struct
import zipfile

from flow_features import FEATURES, SCHEMA

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inside(root, relative, prefix):
    relative = Path(relative)
    require(not relative.is_absolute() and '..' not in relative.parts, 'Expected a project-relative path')
    path = (root / relative).resolve()
    require(path.is_relative_to((root / prefix).resolve()), 'Path outside allowed node scope: ' + str(relative))
    return path


def check_weights(path, contract):
    widths = [contract['input_width'], *contract['hidden_layer_sizes'], contract['output_width']]
    shapes = {'layers': ()}
    for index, (left, right) in enumerate(zip(widths, widths[1:])):
        shapes['coef_' + str(index)] = (left, right)
        shapes['intercept_' + str(index)] = (right,)
    parameter_count = 0
    with zipfile.ZipFile(path) as archive:
        require(sorted(archive.namelist()) == sorted(k + '.npy' for k in shapes), 'Unexpected weights archive members')
        for name, shape in shapes.items():
            info = archive.getinfo(name + '.npy')
            require(info.file_size <= 65536, 'Unexpectedly large parameter array')
            with archive.open(info) as stream:
                require(stream.read(6) == b'\x93NUMPY', 'Bad NPY magic')
                version = stream.read(2)
                require(version in (b'\x01\0', b'\x02\0', b'\x03\0'), 'Unsupported NPY version')
                size_bytes = 2 if version[0] == 1 else 4
                size = int.from_bytes(stream.read(size_bytes), 'little')
                require(size <= 8192, 'NPY header too large')
                header = ast.literal_eval(stream.read(size).decode('utf-8' if version[0] == 3 else 'latin1').strip())
                data = stream.read()
            require(header['shape'] == shape and header['fortran_order'] is False, 'Wrong parameter shape/order: ' + name)
            if name == 'layers':
                require(header['descr'] in ('<i8', '<i4'), 'Wrong layers dtype')
                require(len(data) == int(header['descr'][-1]) and int.from_bytes(data, 'little', signed=True) == len(widths)-1, 'Wrong number of layers')
            else:
                require(header['descr'] == '<f8', 'Expected float64 weights: ' + name)
                elements = math.prod(shape)
                require(len(data) == elements * 8, 'Wrong parameter byte length')
                require(all(math.isfinite(value[0]) for value in struct.iter_unpack('<d', data)), 'Nonfinite parameter')
                parameter_count += elements
    return parameter_count


def check(root, config):
    cfg_path = inside(root, config, 'config/fl')
    cfg = json.loads(cfg_path.read_text(encoding='utf-8-sig'))
    model, training = cfg['model'], cfg['training']
    require(cfg['algorithm'] == 'FedAvg' and cfg['framework'] == 'flower', 'Unexpected FL algorithm/framework')
    require(model['features'] == FEATURES and model['schema_version'] == SCHEMA, 'Unsupported FL feature contract')
    require(model['transform'] == 'flow-v2-fixed-log-v1', 'Unsupported transform')
    require((model['input_width'], model['hidden_layer_sizes'], model['output_width']) == (13, [32, 16], 1), 'Unsupported MLP architecture')
    require(model['labels'] == {'benign': 0, 'attack': 1} and model['threshold'] == .5, 'Unexpected label/threshold contract')
    require(model['dtype'] == 'float64' and model['activation'] == 'relu' and model['output_activation'] == 'sigmoid', 'Unsupported MLP numeric contract')
    require(set(cfg['clients']) == set(training['required_client_ids']) == {'A', 'B', 'C'}, 'Require clients A/B/C')
    require(training['require_all_clients'] is True and training['aggregation_weight'] == 'num_train_rows', 'Unexpected aggregation policy')
    require(training['initialization'] == 'fresh_shared_weights' and training['test_during_training'] is False, 'Unexpected initialization/test policy')
    require(training['local_epochs'] >= 1 and training['rounds'] >= 1, 'Invalid training limits')
    groups_by_partition, uids_by_partition, nodes = {}, {}, {}
    for node, spec in cfg['clients'].items():
        prefix = 'data/node-' + node.lower()
        manifest_path = inside(root, spec['manifest_path'], prefix)
        require(sha(manifest_path) == spec['manifest_sha256'], node + ': manifest hash differs')
        manifest = json.loads(manifest_path.read_text(encoding='utf-8-sig'))
        require(manifest['features'] == FEATURES and manifest['schema_version'] == SCHEMA, node + ': split feature contract differs')
        require(bool(manifest['checks']) and all(value is True for value in manifest['checks'].values()), node + ': split checks not passed')
        model_dir = inside(root, spec['baseline_model_dir'], 'models/node-' + node.lower())
        meta = json.loads((model_dir/'model.json').read_text(encoding='utf-8-sig'))
        for field in ('schema_version', 'features', 'transform', 'input_width', 'hidden_layer_sizes', 'activation', 'output_activation', 'threshold'):
            require(meta[field] == model[field], node + ': baseline model contract differs: ' + field)
        require(sha(model_dir/'weights.npz') == meta['weights_sha256'] == spec['baseline_weights_sha256'], node + ': baseline weights hash differs')
        parameters = check_weights(model_dir/'weights.npz', model)
        model_report = json.loads((model_dir/'metrics.json').read_text(encoding='utf-8-sig'))
        require(model_report['manifest_sha256'] == spec['manifest_sha256'], node + ': baseline/split provenance differs')
        for filename, digest in model_report['artifacts'].items():
            require(Path(filename).name == filename, 'Unexpected artifact filename')
            require(sha(model_dir/filename) == digest, node + ': model artifact hash differs: ' + filename)
        config_path = inside(root, 'config/node-' + node.lower() + '/node-' + node.lower() + '-baseline.json', 'config/node-' + node.lower())
        local_cfg = json.loads(config_path.read_text(encoding='utf-8-sig'))
        weighting = local_cfg.get('sample_weighting', 'class_balanced')
        require(weighting == spec['sample_weighting'] == meta['config'].get('sample_weighting', 'class_balanced'), node + ': local weighting differs')
        partitions = {}
        for split in ('train', 'validation', 'test'):
            artifact = manifest['artifacts'][split]
            path = inside(root, artifact['path'], prefix)
            require(sha(path) == artifact['sha256'], node + '/' + split + ': CSV hash differs')
            groups, uids, labels = set(), set(), Counter()
            attack_with_return = 0
            with path.open(encoding='utf-8-sig', newline='') as stream:
                reader = csv.DictReader(stream)
                require(set(FEATURES + ['schema_version', 'label', 'row_uid', 'group_id']).issubset(reader.fieldnames or []), 'Missing split columns')
                for row in reader:
                    require(row['schema_version'] == SCHEMA and row['label'] in ('benign', 'attack'), 'Invalid schema/label')
                    require(row['row_uid'] and row['row_uid'] not in uids and row['group_id'], 'Duplicate/empty row identity')
                    values = [float(row[name]) for name in FEATURES]
                    require(all(math.isfinite(v) and v >= 0 for v in values), 'Invalid split feature')
                    require(values[0] in (0, 1, 6, 17, 58) and values[-1] in (0, 1), 'Invalid protocol/duration flag')
                    uids.add(row['row_uid']); groups.add(row['group_id']); labels[row['label']] += 1
                    attack_with_return += row['label'] == 'attack' and int(row['pkts_toclient']) > 0
            require(sum(labels.values()) == artifact['rows'] and dict(labels) == artifact['label_counts'], 'Split counts differ')
            require(labels['benign'] > 0 and labels['attack'] > 0, 'Both classes required')
            key = node + '/' + split
            for old_key, old_groups in groups_by_partition.items():
                require(not groups.intersection(old_groups), 'Connection groups overlap: ' + old_key + ' and ' + key)
                require(not uids.intersection(uids_by_partition[old_key]), 'Row identities overlap: ' + old_key + ' and ' + key)
            groups_by_partition[key], uids_by_partition[key] = groups, uids
            partitions[split] = {'rows': sum(labels.values()), 'labels': dict(labels), 'groups': len(groups)}
            if split == 'train' and weighting == 'class_and_attack_response':
                require(0 < attack_with_return < labels['attack'], 'Response weighting requires both attack groups in train')
        nodes[node] = {'splits': partitions, 'sample_weighting': weighting, 'parameters': parameters,
                       'baseline_weights_sha256': spec['baseline_weights_sha256']}
    total = sum(node['splits']['train']['rows'] for node in nodes.values())
    for node in nodes.values():
        node['fedavg_weight'] = node['splits']['train']['rows'] / total
    return {'result': 'PASS FL input preflight', 'checked_at_utc': datetime.now(timezone.utc).isoformat(),
            'config_sha256': sha(cfg_path), 'nodes': nodes, 'total_train_rows': total,
            'cross_partition_row_and_group_overlap': False,
            'scope': 'Read-only host validation of frozen inputs and baseline contracts. No Flower runtime, client/server connection, fitting, or convergence verified. Test CSVs inspected for provenance/overlap only.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='config/fl/fedavg.json')
    parser.add_argument('--output', help='Optional new JSON report under reports/fl; existing files are preserved')
    args = parser.parse_args()
    try:
        output = inside(ROOT, args.output, 'reports/fl') if args.output else None
        require(output is None or not output.exists(), 'Report already exists; omit --output to check again')
        report = check(ROOT, args.config)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open('x', encoding='utf-8') as stream:
                stream.write(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
    except (ValueError, OSError, KeyError, TypeError, zipfile.BadZipFile, SyntaxError, struct.error) as error:
        parser.exit(1, 'FAIL FL input preflight: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
