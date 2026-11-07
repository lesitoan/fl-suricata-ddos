"""Score a frozen labelled B UDP selection from Suricata EVE; never train."""
import argparse
import csv
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from flow_features import FEATURES, event_signature, flow_features, timestamp
from infer_eve import load_model
from model_runtime import predict_proba
from split_helpers import hashed


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def row_signature(row):
    return (str(row['flow_id']), row['src_ip'], int(row['src_port']),
        row['dest_ip'], int(row['dest_port']), row['protocol_name'],
        timestamp(row['flow_start_utc']).isoformat(), timestamp(row['flow_end_utc']).isoformat(),
        *(int(row[k]) for k in ('pkts_toserver', 'pkts_toclient', 'bytes_toserver', 'bytes_toclient')))


def evaluate(source_dir, reference, selection_path, model_dir, out):
    if out.exists():
        raise FileExistsError('Keep previous evaluation; output already exists')
    selection = json.loads(selection_path.read_text())
    source = source_dir/'flows-v2.csv'
    eve = source_dir/'eve.json'
    if (sha(source) != selection['source_csv_sha256'] or sha(eve) != selection['eve_sha256'] or
            sha(reference) != selection['reference_csv_sha256']):
        raise ValueError('Frozen input hash differs')
    meta, weights, threshold, digest = load_model(model_dir)
    if digest != selection['weights_sha256'] or meta['config']['experiment_id'] != selection['model_id']:
        raise ValueError('Model changed after selection; inspect the frozen evaluation protocol')
    selected = set(selection['selected_row_uids'])
    if len(selected) != selection['selected_rows']:
        raise ValueError('Selection count mismatch')
    rows, lookup = [], {}
    with source.open(newline='', encoding='utf-8-sig') as stream:
        for index, row in enumerate(csv.DictReader(stream), start=2):
            uid = hashed([row['capture_id'], index, selection['source_csv_sha256']])
            if uid not in selected:
                continue
            row['row_uid'] = uid
            signature = row_signature(row)
            if signature in lookup or row['protocol'] != '17' or row['label'] not in ('attack', 'benign'):
                raise ValueError('Selected row contract failed')
            lookup[signature] = len(rows)
            rows.append(row)
    if len(rows) != len(selected):
        raise ValueError('Selected source rows missing')
    raw = np.zeros((len(rows), len(FEATURES)), dtype=np.float64)
    found = set()
    with eve.open(encoding='utf-8') as stream:
        for line in stream:
            event = json.loads(line)
            if event.get('event_type') != 'flow' or event.get('proto') != 'UDP':
                continue
            signature = event_signature(event)
            if signature not in lookup:
                continue
            index = lookup[signature]
            if index in found:
                continue
            values = flow_features(event)
            if not np.allclose([values[f] for f in FEATURES], [float(rows[index][f]) for f in FEATURES], rtol=0, atol=1e-12):
                raise ValueError('EVE features differ from labelled source')
            raw[index] = [values[f] for f in FEATURES]
            found.add(index)
    if len(found) != len(rows):
        raise ValueError('Some selected rows do not have matching EVE events')
    start = time.perf_counter()
    probability = predict_proba(raw, weights)
    weights.close()
    if not np.isfinite(probability).all() or ((probability < 0) | (probability > 1)).any():
        raise ValueError('Invalid predicted probability')
    scoring_seconds = time.perf_counter()-start
    prediction = probability >= threshold
    labels = np.asarray([row['label'] == 'attack' for row in rows])
    cm = [[int(np.sum((labels == i) & (prediction == j))) for j in (0, 1)] for i in (0, 1)]
    tn, fp = cm[0]
    fn, tp = cm[1]
    groups = {}
    for label in ('attack', 'benign'):
        for has_return in (False, True):
            mask = np.asarray([row['label'] == label and (int(row['pkts_toclient']) > 0) == has_return for row in rows])
            n = int(mask.sum())
            if n:
                groups[label+('_has_return' if has_return else '_no_return')] = {
                    'rows': n, 'predicted_attack': int(prediction[mask].sum()),
                    'predicted_benign': int((~prediction[mask]).sum()),
                    ('recall_attack' if label == 'attack' else 'false_positive_rate'): float(prediction[mask].mean())}
    if {k: v['rows'] for k, v in groups.items()} != selection['selected_counts']:
        raise ValueError('Selection strata changed')
    report = {'created_at_utc': datetime.now(timezone.utc).isoformat(),
        'scope': selection['purpose'], 'model_id': selection['model_id'], 'weights_sha256': digest,
        'selection_sha256': sha(selection_path), 'source_csv_sha256': selection['source_csv_sha256'],
        'eve_sha256': selection['eve_sha256'], 'reference_csv_sha256': selection['reference_csv_sha256'],
        'threshold': threshold, 'rows': len(rows), 'confusion_matrix_labels': ['benign', 'attack'],
        'confusion_matrix': cm, 'recall_attack': tp/(tp+fn) if tp+fn else None,
        'precision_attack': tp/(tp+fp) if tp+fp else None,
        'false_positive_rate': fp/(tn+fp) if tn+fp else None,
        'subgroups': groups, 'batch_scoring_seconds': scoring_seconds,
        'checks': {'frozen_input_model_hashes_match': True, 'selected_rows_match_source': True,
            'all_selected_EVE_features_match_labelled_CSV': True, 'no_fitting_or_threshold_tuning': True},
        'limitations': selection['limitations']}
    out.mkdir(parents=True)
    with (out/'predictions.csv').open('w', newline='', encoding='utf-8') as stream:
        fields = ['row_uid', 'flow_id', 'flow_start_utc', 'protocol', 'label', 'attack_family',
                  'pkts_toserver', 'pkts_toclient', 'probability_attack', 'prediction']
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row, value, predicted in zip(rows, probability, prediction):
            item = {f: row[f] for f in fields if f not in ('probability_attack', 'prediction')}
            item.update(probability_attack=float(value), prediction='attack' if predicted else 'benign')
            writer.writerow(item)
    (out/'metrics.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.output.resolve().is_relative_to(Path('/reports').resolve()) or args.output.resolve() == Path('/reports').resolve():
        parser.error('Output must be a child of /reports')
    result = evaluate(Path('/source'), Path('/reference.csv.gz'), Path('/selection.json'), Path('/model'), args.output)
    print(json.dumps(result, indent=2), flush=True)
