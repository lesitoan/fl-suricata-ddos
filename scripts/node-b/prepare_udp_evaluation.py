"""Freeze unused, reference-labelled B UDP rows without scoring the model."""
import csv
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from flow_features import event_signature, timestamp
from split_helpers import group_id, hashed

ROOT = Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(root):
    out = root/'data/node-b/work/evaluation/labeled-udp'
    if out.exists():
        raise FileExistsError('Evaluation selection already exists; keep its frozen protocol')
    used = set()
    manifests = {}
    for node in ('a', 'b'):
        path = root/f'data/node-{node}/work/splits/pilot-v1/manifest.json'
        manifest = json.loads(path.read_text())
        manifests[node] = sha(path)
        for artifact in manifest['artifacts'].values():
            path = root/artifact['path']
            if sha(path) != artifact['sha256']:
                raise ValueError('Frozen split changed: '+str(path))
            with path.open(newline='', encoding='utf-8-sig') as stream:
                used.update(row['group_id'] for row in csv.DictReader(stream))
    source_dir = root/'data/node-b/dataset/derived/suricata/node-b-source-0592'
    source = source_dir/'flows-v2.csv'
    eve = source_dir/'eve.json'
    reference = root/'data/node-b/dataset/reference/node-b-reference.csv.gz'
    evidence = json.loads((source_dir/'flows-v2.report.json').read_text())
    digest = sha(source)
    if (digest != evidence['output_sha256'] or sha(eve) != evidence['eve_sha256'] or
            sha(reference) != evidence['reference_csv_sha256'] or evidence['reference_label_conflicts']):
        raise ValueError('Source/reference provenance check failed')
    # The previously executed first-100-flow inference smoke is excluded too.
    seen = set()
    smoke_groups = set()
    with eve.open(encoding='utf-8') as stream:
        for line in stream:
            event = json.loads(line)
            if event.get('event_type') != 'flow' or event.get('proto') not in ('TCP', 'UDP'):
                continue
            signature = event_signature(event)
            if signature in seen:
                continue
            seen.add(signature)
            smoke_groups.add(group_id({'protocol': 17 if event['proto'] == 'UDP' else 6,
                'src_ip': event['src_ip'], 'src_port': event['src_port'],
                'dest_ip': event['dest_ip'], 'dest_port': event['dest_port']}))
            if len(seen) == 100:
                break
    if len(seen) != 100:
        raise ValueError('Cannot reconstruct earlier smoke exclusion')
    used.update(smoke_groups)
    cfg_path = root/'config/node-b/node-b-expansion.json'
    cfg = json.loads(cfg_path.read_text())
    blocks = [tuple(map(timestamp, pair)) for pair in cfg['split_time_blocks_utc']['node-b-source-0592'].values()]
    counts, selected_counts = Counter(), Counter()
    selected = []
    selected_groups = set()
    with source.open(newline='', encoding='utf-8-sig') as stream:
        for index, row in enumerate(csv.DictReader(stream), start=2):
            counts['all_rows'] += 1
            if row['protocol'] != '17':
                counts['excluded_non_UDP'] += 1
                continue
            if row['label'] not in ('attack', 'benign'):
                counts['excluded_unknown'] += 1
                continue
            if (row['label_basis'] != 'CICFlowMeter timestamp+5tuple' or
                    row['reference_match'] not in ('forward', 'reverse') or
                    (row['label'] == 'attack' and row['attack_family'] != 'DrDoS_UDP')):
                raise ValueError('Unsupported reference label')
            gid = group_id(row)
            if gid in used:
                counts['excluded_seen_group'] += 1
                continue
            start, end = map(timestamp, (row['flow_start_utc'], row['flow_end_utc']))
            if any(start < right and end >= left for left, right in blocks):
                counts['excluded_overlapping_used_time'] += 1
                continue
            selected.append(hashed([row['capture_id'], index, digest]))
            selected_groups.add(gid)
            category = row['label'] + ('_has_return' if int(row['pkts_toclient']) else '_no_return')
            selected_counts[category] += 1
    if not selected or len(set(selected)) != len(selected):
        raise ValueError('Empty or duplicate selection')
    model = root/'models/node-b/current'
    meta = json.loads((model/'model.json').read_text())
    model_hash = sha(model/'weights.npz')
    if model_hash != meta['weights_sha256']:
        raise ValueError('Current model hash differs')
    result = {'created_at_utc': datetime.now(timezone.utc).isoformat(),
        'purpose': 'Supplemental reference-labelled UDP evaluation from unused groups/time ranges of the same capture',
        'capture_id': 'node-b-source-0592', 'source_csv_sha256': digest,
        'eve_sha256': evidence['eve_sha256'], 'reference_csv_sha256': evidence['reference_csv_sha256'],
        'frozen_manifest_sha256': manifests, 'split_config_sha256': sha(cfg_path),
        'weights_sha256': model_hash, 'model_id': meta['config']['experiment_id'],
        'selection_policy': 'All eligible UDP rows; exclude unknown; all A/B train/validation/test groups; earlier 100-flow smoke groups; any flow overlapping B used time blocks. No model prediction used for selection.',
        'excluded_group_count': len(used), 'excluded_smoke_groups': len(smoke_groups),
        'filter_counts': dict(counts), 'selected_counts': dict(selected_counts),
        'selected_group_count': len(selected_groups), 'selected_rows': len(selected),
        'limitations': ['Same PCAP and recording day; not an independent recording.',
            'Reference labels come from the existing timestamp+5tuple CSV join, not packet-payload adjudication.',
            'Very few unused benign flows; false-positive estimates may be unreliable.',
            'Attack direction groups can be very imbalanced; inspect subgroup recall.'],
        'selected_row_uids': sorted(selected)}
    out.mkdir(parents=True)
    (out/'selection.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    return {k: v for k, v in result.items() if k != 'selected_row_uids'}


if __name__ == '__main__':
    print(json.dumps(prepare(ROOT), indent=2))
