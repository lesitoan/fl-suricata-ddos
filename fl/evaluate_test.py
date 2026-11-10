"""Offline evaluation of one node's frozen test, using global and local models."""
import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
from unittest.mock import patch

import numpy as np
from sklearn.metrics import log_loss
from sklearn.neural_network import MLPClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
from check_fl_inputs import sha, inside
from flow_features import FEATURES, SCHEMA
from infer_eve import load_model
from model_runtime import predict_proba
from train_mlp import load_split, metrics, attack_group_recall


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_files(folder, files):
    for name, digest in files.items():
        require(Path(name).name == name and sha(folder/name) == digest, 'Frozen model differs: '+name)


def evaluate_node(root, plan, node, output, global_dir, local_dir):
    require(node in ('A', 'B', 'C'), 'Unsupported node')
    own = 'data/node-'+node.lower()+'/work/splits/pilot-v1/'
    spec = plan['nodes'][node]
    config_path = root/'config/fl/fedavg.json'
    require(sha(config_path) == plan['config_sha256'], 'Frozen config differs')
    config = json.loads(config_path.read_text(encoding='utf-8-sig'))
    require(spec['manifest_path'] == own+'manifest.json', 'Foreign manifest path')
    manifest_path = inside(root, spec['manifest_path'], own)
    require(sha(manifest_path) == spec['manifest_sha256'] == config['clients'][node]['manifest_sha256'], 'Manifest hash differs')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8-sig'))
    require(manifest['node_id'] == node and manifest['features'] == FEATURES and manifest['schema_version'] == SCHEMA, 'Manifest contract differs')
    require(manifest['checks'] and all(value is True for value in manifest['checks'].values()), 'Split checks failed')
    artifact = manifest['artifacts']['test']
    require(artifact == spec['test'] and artifact['path'] == own+'test.csv', 'Only this node test.csv is allowed')
    test_path = inside(root, artifact['path'], own)

    def verify_sources():
        require(sha(test_path) == artifact['sha256'], 'Test hash differs')
        require(sha(manifest_path) == spec['manifest_sha256'] and sha(config_path) == plan['config_sha256'], 'Input metadata changed')
        verify_files(global_dir, plan['global']['files'])
        verify_files(local_dir, spec['local']['files'])

    verify_sources()
    values, labels = load_split(root, artifact)
    counts = Counter('attack' if y else 'benign' for y in labels)
    require(dict(counts) == artifact['label_counts'] and all(counts[name] > 0 for name in ('attack','benign')), 'Test label counts differ')
    require(values.shape == (len(labels), len(FEATURES)) and np.isfinite(values).all(), 'Invalid test features')
    with test_path.open(encoding='utf-8-sig', newline='') as stream:
        identities = [row['row_uid'] for row in csv.DictReader(stream)]
    probabilities, reports = {}, {}
    # This job uses the portable, fixed transform. Fit calls are forbidden even
    # if a later edit accidentally adds a sklearn training path.
    with patch.object(MLPClassifier, 'fit', side_effect=AssertionError('Test cannot fit')), \
         patch.object(MLPClassifier, 'partial_fit', side_effect=AssertionError('Test cannot partial_fit')):
        for name, folder, frozen in [('global',global_dir,plan['global']), ('local',local_dir,spec['local'])]:
            meta, weights, threshold, digest = load_model(folder)
            try:
                require(digest == frozen['weights_sha256'] and threshold == frozen['threshold'] == .5, 'Frozen weights/threshold differ')
                if name == 'global':
                    require(meta['selected_round'] == plan['selected_round'], 'Global checkpoint changed')
                started = time.perf_counter()
                probability = predict_proba(values, weights)
                seconds = time.perf_counter()-started
            finally:
                weights.close()
            require(probability.shape == labels.shape and np.isfinite(probability).all() and ((probability >= 0) & (probability <= 1)).all(), 'Invalid probabilities')
            predicted = (probability >= threshold).astype(int)
            report = metrics(labels, predicted)
            report.update({'accuracy': float(np.mean(predicted == labels)),
                           'loss': float(log_loss(labels, probability, labels=[0,1])),
                           'weights_sha256': digest, 'threshold': threshold,
                           'scoring_seconds': seconds,
                           'attack_group_recall': attack_group_recall(values, labels, predicted)})
            probabilities[name] = probability
            reports[name] = report
    verify_sources()
    output.mkdir(parents=True, exist_ok=True)
    prediction_path = output/'predictions.csv'
    with prediction_path.open('x', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['test_row_index','row_uid','true_label','global_probability_attack','global_predicted_label','local_probability_attack','local_predicted_label'])
        writer.writerows((i, identities[i], int(y), float(probabilities['global'][i]),
                          int(probabilities['global'][i] >= .5), float(probabilities['local'][i]),
                          int(probabilities['local'][i] >= .5)) for i,y in enumerate(labels))
    result = {'node': node, 'partition': 'test', 'rows': len(labels), 'label_counts': dict(counts),
              'evaluated_at_utc': datetime.now(timezone.utc).isoformat(),
              'run_id': plan['run_id'], 'selected_round': plan['selected_round'],
              'manifest_sha256': spec['manifest_sha256'], 'test_csv_sha256': artifact['sha256'],
              'models': reports, 'artifacts': {'predictions.csv': sha(prediction_path)},
              'checks': {'sources_unchanged': True, 'same_rows_for_global_and_local': True,
                         'no_fitting': True, 'no_threshold_tuning': True, 'no_test_checkpoint_selection': True},
              'scope': 'Held-out partition of the existing pilot recordings; not an independent recording or equal-training-budget benchmark'}
    with (output/'metrics.json').open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', required=True, choices=('a','b','c'))
    parser.add_argument('--plan', type=Path, default=Path('/evaluation-plan.json'))
    parser.add_argument('--output', type=Path, default=Path('/output'))
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text(encoding='utf-8'))
    report = evaluate_node(ROOT, plan, args.node.upper(), args.output, Path('/model/global'), Path('/model/local'))
    print(json.dumps({'result': 'COMPLETE node test evaluation', 'node': report['node'], 'rows': report['rows']}))


if __name__ == '__main__':
    main()
