"""Prepare and verify a bounded EVE replay smoke check for a local node model."""
import argparse
import csv
import hashlib
import json
import math
from collections import Counter
from pathlib import Path

from flow_features import FEATURES, SCHEMA, event_signature, flow_features, timestamp
from split_helpers import hashed

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_csv(path):
    with path.open(newline='', encoding='utf-8-sig') as stream:
        return list(csv.DictReader(stream))


def sig_hash(signature):
    return hashed(list(signature))


def row_signature(row):
    return (str(row['flow_id']), row['src_ip'], int(row['src_port']), row['dest_ip'],
            int(row['dest_port']), row['protocol_name'],
            timestamp(row['flow_start_utc']).isoformat(), timestamp(row['flow_end_utc']).isoformat(),
            *(int(row[k]) for k in ('pkts_toserver', 'pkts_toclient', 'bytes_toserver', 'bytes_toclient')))


def prepare(root, node, split, model_dir, out, count):
    out = out.resolve()
    if not out.is_relative_to((root/f'reports/node-{node}').resolve()):
        raise ValueError('Output must stay in this node reports folder')
    if out.exists():
        raise FileExistsError('Keep prior smoke evidence; choose a new report folder')
    manifest_path = root/f'data/node-{node}/work/splits/pilot-v1/manifest.json'
    manifest = json.loads(manifest_path.read_text())
    meta = json.loads((model_dir/'model.json').read_text())
    digest = sha(model_dir/'weights.npz')
    if meta['weights_sha256'] != digest or meta['features'] != FEATURES or meta['schema_version'] != SCHEMA:
        raise ValueError('Model contract differs')
    model_report = json.loads((model_dir/'metrics.json').read_text())
    if model_report['manifest_sha256'] != sha(manifest_path):
        raise ValueError('Model was trained on a different frozen split')
    path = root/manifest['artifacts'][split]['path']
    if sha(path) != manifest['artifacts'][split]['sha256']:
        raise ValueError('Split file hash differs')
    rows = read_csv(path)
    for index, row in enumerate(rows):
        row['_index'] = index
    rows.sort(key=lambda r: r['row_uid'])
    if any(r['schema_version'] != SCHEMA or r['label'] not in ('attack', 'benign') for r in rows):
        raise ValueError('Unsupported split schema/labels')
    target = min(count, len(rows))
    if target < 1:
        raise ValueError('Empty split')
    benign = [r for r in rows if r['label'] == 'benign'][:target//2]
    reply = [r for r in rows if r['label'] == 'attack' and int(r['pkts_toclient']) > 0][:(target-len(benign))//2]
    one_way = [r for r in rows if r['label'] == 'attack' and int(r['pkts_toclient']) == 0][:target-len(benign)-len(reply)]
    selected = {r['row_uid']: r for r in benign+reply+one_way}
    for row in rows:
        if len(selected) == target:
            break
        selected.setdefault(row['row_uid'], row)
    saved_path = model_dir/(split+'-predictions.csv')
    if saved_path.is_file() and sha(saved_path) != model_report['artifacts'].get(saved_path.name):
        raise ValueError('Saved prediction export hash differs')
    saved = read_csv(saved_path) if saved_path.is_file() else None
    lookup, inputs = {}, []
    for source in manifest['sources']:
        if source['capture_id'] not in {r['capture_id'] for r in selected.values()}:
            continue
        source_path = (root/source['path']).resolve()
        if not source_path.is_relative_to((root/f'data/node-{node}').resolve()):
            raise ValueError('Source belongs to another node')
        if sha(source_path) != source['sha256']:
            raise ValueError('Source CSV changed')
        eve = source_path.with_name('eve.json')
        joined = json.loads((root/source['join_evidence']).read_text())
        if joined['output_sha256'] != source['sha256'] or sha(eve) != joined['eve_sha256']:
            raise ValueError('EVE provenance differs')
        inputs.append({'path': eve.relative_to(root).as_posix(), 'sha256': joined['eve_sha256']})
        with source_path.open(newline='', encoding='utf-8-sig') as stream:
            for index, original in enumerate(csv.DictReader(stream), start=2):
                uid = hashed([original['capture_id'], index, source['sha256']])
                if uid not in selected:
                    continue
                row = selected[uid]
                if any(row[f] != original[f] for f in FEATURES+['label', 'capture_id', 'flow_start_utc', 'flow_end_utc']):
                    raise ValueError('Frozen row differs from source')
                lookup[row_signature(original)] = row
    if len(lookup) != target:
        raise ValueError('Some selected source identities missing')
    events, expected = [], []
    found = set()
    for source in inputs:
        with (root/source['path']).open(encoding='utf-8') as stream:
            for line in stream:
                event = json.loads(line)
                if event.get('event_type') != 'flow':
                    continue
                signature = event_signature(event)
                if signature not in lookup or signature in found:
                    continue
                row = lookup[signature]
                values = flow_features(event)
                if any(abs(values[f]-float(row[f])) > 1e-12 for f in FEATURES):
                    raise ValueError('EVE feature differs from frozen CSV')
                export_probability = None
                if saved is not None:
                    item = saved[row['_index']]
                    if int(item[split+'_row_index']) != row['_index'] or int(item['true_label']) != int(row['label'] == 'attack'):
                        raise ValueError('Saved prediction row order differs')
                    export_probability = float(item['probability_attack'])
                events.append(event)
                expected.append({'row_uid': row['row_uid'], 'signature': sig_hash(signature),
                    'flow_id': str(event['flow_id']), 'label': row['label'],
                    'has_return': int(row['pkts_toclient']) > 0,
                    'export_probability': export_probability})
                found.add(signature)
    if len(events) != target:
        raise ValueError('Some selected raw EVE events missing')
    out.mkdir(parents=True)
    sample = out/'sample.eve.json'
    sample.write_text(''.join(json.dumps(e, separators=(',', ':'))+'\n' for e in events), encoding='utf-8')
    report = {'node': node, 'purpose': 'Integration smoke on samples from an already evaluated split; not a new accuracy estimate',
        'split': split, 'model_dir': model_dir.relative_to(root).as_posix(),
        'model_id': meta['config']['experiment_id'], 'weights_sha256': digest,
        'threshold': meta['threshold'], 'manifest_sha256': sha(manifest_path),
        'sample_sha256': sha(sample), 'source_EVE': inputs, 'rows': target,
        'selection_policy': 'By row UID and label/response strata only; not prediction scores',
        'labels': dict(Counter(r['label'] for r in expected)),
        'attack_has_return': sum(r['label'] == 'attack' and r['has_return'] for r in expected),
        'expected': expected}
    (out/'expected.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    return {k: v for k, v in report.items() if k != 'expected'}


def verify(root, out):
    out = out.resolve()
    if not out.is_relative_to((root/'reports').resolve()):
        raise ValueError('Run folder must stay in reports')
    if (out/'verification.json').exists():
        raise FileExistsError('Keep previous verification')
    expected = json.loads((out/'expected.json').read_text())
    node = expected['node']
    model = (root/expected['model_dir']).resolve()
    if node not in ('a', 'b', 'c') or not out.is_relative_to((root/f'reports/node-{node}').resolve()) or not model.is_relative_to((root/f'models/node-{node}').resolve()):
        raise ValueError('Model/report belongs to another node')
    if sha(root/f'data/node-{node}/work/splits/pilot-v1/manifest.json') != expected['manifest_sha256']:
        raise ValueError('Frozen manifest changed')
    if sha(out/'sample.eve.json') != expected['sample_sha256'] or sha(root/expected['model_dir']/'weights.npz') != expected['weights_sha256']:
        raise ValueError('Model or sample changed after preparation')
    with (out/'predictions.jsonl').open(encoding='utf-8-sig') as stream:
        predictions = [json.loads(line) for line in stream if line.strip()]
    by_signature = {p['event_signature_sha256']: p for p in predictions}
    if len(predictions) != len(by_signature) or set(by_signature) != {x['signature'] for x in expected['expected']}:
        raise ValueError('Missing, duplicate or unrelated predictions')
    cm = [[0, 0], [0, 0]]
    errors = []
    for item in expected['expected']:
        p = by_signature[item['signature']]
        if (p['model_id'] != expected['model_id'] or p['weights_sha256'] != expected['weights_sha256'] or
                p['flow_id'] != item['flow_id'] or p['mode'] != 'historical_replay'):
            raise ValueError('Wrong model/event/mode')
        probability = p['probability_attack']
        if not math.isfinite(probability) or not 0 <= probability <= 1 or p['threshold'] != expected['threshold']:
            raise ValueError('Invalid probability/threshold')
        label = 'attack' if probability >= expected['threshold'] else 'benign'
        if label != p['prediction']:
            raise ValueError('Threshold decision differs')
        if item['export_probability'] is not None:
            error = abs(probability-item['export_probability'])
            if error > 1e-12:
                raise ValueError('EVE inference differs from saved training export')
            errors.append(error)
        cm[int(item['label'] == 'attack')][int(label == 'attack')] += 1
    report = {'result': 'PASS integration', 'purpose': expected['purpose'],
        'model_id': expected['model_id'], 'weights_sha256': expected['weights_sha256'],
        'rows': len(predictions), 'labels': expected['labels'],
        'prediction_counts': dict(Counter(p['prediction'] for p in predictions)),
        'confusion_matrix_labels': ['benign', 'attack'], 'confusion_matrix_for_selected_sample': cm,
        'matched_event_signatures': True, 'max_abs_error_vs_saved_export': max(errors) if errors else None,
        'note': 'Stratified smoke subset; keep original full-test metrics as baseline. No training or threshold change.'}
    (out/'verification.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'verify'])
    parser.add_argument('--node', choices=['a', 'b', 'c'], default='c')
    parser.add_argument('--split', choices=['validation', 'test'], default='test')
    parser.add_argument('--model-dir', type=Path)
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--count', type=int, default=100)
    args = parser.parse_args()
    if not 1 <= args.count <= 500:
        parser.error('count must be 1..500')
    out = args.run_dir if args.run_dir.is_absolute() else ROOT/args.run_dir
    model = args.model_dir or Path(f'models/node-{args.node}/current')
    model = (model if model.is_absolute() else ROOT/model).resolve()
    if not model.is_relative_to((ROOT/f'models/node-{args.node}').resolve()):
        parser.error('Model must stay in the selected node model folder')
    result = prepare(ROOT, args.node, args.split, model, out, args.count) if args.action == 'prepare' else verify(ROOT, out)
    print(json.dumps(result, indent=2))
