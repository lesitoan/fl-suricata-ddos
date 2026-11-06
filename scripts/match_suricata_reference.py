"""	Đọc EVE, khử trùng, tính đặc trưng và ghép nhãn reference"""
import argparse
import csv
import gzip
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from flow_features import SCHEMA, FEATURES, flow_features, event_signature, timestamp

ROOT = Path(__file__).resolve().parents[1]
OUT_FIELDS = ['schema_version', 'capture_id', 'flow_id', 'src_ip', 'src_port', 'dest_ip', 'dest_port',
              'protocol_name', 'flow_start_utc', 'flow_end_utc'] + FEATURES + [
              'label', 'attack_family', 'label_basis', 'reference_match']


def parse_eve_time(value):
    return timestamp(value).replace(tzinfo=None)


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def text_open(path, **kwargs):
    return gzip.open(path, 'rt', **kwargs) if path.suffix == '.gz' else path.open('r', **kwargs)


def key(src, sport, dst, dport, proto):
    return (src, int(sport), dst, int(dport), int(proto))


def eve_features(event, capture):
    flow = event.get('flow') or {}
    start, end = parse_eve_time(flow['start']), parse_eve_time(flow['end'])
    values = flow_features(event)
    proto_name = event.get('proto', 'OTHER')
    proto = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'ICMPv6': 58}.get(proto_name, 0)
    row = {
        'schema_version': SCHEMA, 'capture_id': capture, 'flow_id': event['flow_id'], 'src_ip': event.get('src_ip'),
        'src_port': event.get('src_port', ''), 'dest_ip': event.get('dest_ip'),
        'dest_port': event.get('dest_port', ''), 'protocol_name': proto_name,
        'flow_start_utc': event['flow']['start'], 'flow_end_utc': event['flow']['end'],
        **values,
        'label': 'unknown', 'attack_family': '', 'label_basis': 'unmatched',
        'reference_match': 'no',
    }
    return row, key(row['src_ip'], row['src_port'], row['dest_ip'], row['dest_port'], proto), start


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture-id', required=True)
    parser.add_argument('--eve', required=True)
    parser.add_argument('--reference-csv', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--utc-offset-hours', type=int, default=4,
                        help='Convert naive CICFlowMeter local timestamp to UTC; dataset UTC-4 is inferred, then checked against 5-tuples')
    parser.add_argument('--tolerance-seconds', type=float, default=3.0)
    parser.add_argument('--attack-label', action='append', default=None,
                        help='Exact CICFlowMeter attack family label to join; defaults to Syn')
    args = parser.parse_args()
    accepted_attack_labels = args.attack_label if args.attack_label is not None else ['Syn']
    accepted_attack_labels = {value.strip().casefold() for value in accepted_attack_labels if value.strip()}
    if not accepted_attack_labels:
        parser.error('at least one non-empty --attack-label is required')
    if not re.fullmatch('[a-z0-9][a-z0-9-]{0,99}', args.capture_id):
        parser.error('Invalid capture ID')
    eve_path, csv_path, output = [(ROOT/p).resolve() for p in (args.eve, args.reference_csv, args.output)]
    if any(not p.is_relative_to(ROOT) for p in (eve_path, csv_path, output)):
        parser.error('all paths must stay within the project')
    if not eve_path.is_file() or not csv_path.is_file():
        parser.error('EVE or reference CSV is missing')
    if output.exists():
        parser.error('Output exists; use a new evidence path')

    rows, by_key = [], defaultdict(list)
    malformed_eve = duplicate_eve_records = 0
    seen_events = set()
    with text_open(eve_path, encoding='utf-8') as f:
        for line in f:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                if event.get('event_type') != 'flow' or not event.get('flow', {}).get('start'):
                    continue
                row, flow_key, start = eve_features(event, args.capture_id)
                flow = event['flow']
                signature = event_signature(event)
                if signature in seen_events:
                    duplicate_eve_records += 1
                    continue
                seen_events.add(signature)
                idx = len(rows)
                rows.append(row)
                by_key[flow_key].append((idx, start))
            except (ValueError, KeyError, TypeError, json.JSONDecodeError):
                malformed_eve += 1

    key_rows = 0
    timestamp_deltas = Counter()
    joined_rows = set()
    reference_labels = Counter()
    ref_label_key_conflicts = 0
    conflicting_indices = set()
    with text_open(csv_path, newline='', encoding='utf-8-sig', errors='replace') as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            parser.error('reference CSV has no header')
        for raw in reader:
            item = {str(k).strip(): (v.strip() if v else '') for k, v in raw.items() if k is not None}
            try:
                src, dst = item['Source IP'], item['Destination IP']
                sport, dport, proto = int(item['Source Port']), int(item['Destination Port']), int(item['Protocol'])
                stamp = datetime.strptime(item['Timestamp'], '%Y-%m-%d %H:%M:%S.%f')
                label = item.get('Label', '').strip()
            except (KeyError, ValueError):
                continue
            if label.upper() != 'BENIGN' and label.casefold() not in accepted_attack_labels:
                continue
            refkey = key(src, sport, dst, dport, proto)
            candidates = by_key.get(refkey, [])
            direction = 'forward'
            if not candidates:
                candidates = by_key.get(key(dst, dport, src, sport, proto), [])
                direction = 'reverse'
            if not candidates:
                continue
            key_rows += 1
            converted = stamp + timedelta(hours=args.utc_offset_hours)
            idx, start = min(candidates, key=lambda candidate: abs((candidate[1]-converted).total_seconds()))
            delta = (start-converted).total_seconds()
            if abs(delta) <= args.tolerance_seconds:
                if idx in conflicting_indices:
                    continue
                is_benign = label.strip().upper() == 'BENIGN'
                new_class = 'benign' if is_benign else 'attack'
                new_family = '' if is_benign else label
                if rows[idx]['reference_match'] != 'no' and (
                        rows[idx]['label'] != new_class or rows[idx]['attack_family'].lower() != new_family.lower()):
                    ref_label_key_conflicts += 1
                    conflicting_indices.add(idx)
                    joined_rows.discard(idx)
                    rows[idx]['label'] = 'unknown'
                    rows[idx]['attack_family'] = ''
                    rows[idx]['label_basis'] = 'conflicting_reference_rows'
                    rows[idx]['reference_match'] = 'no'
                else:
                    rows[idx]['label'] = new_class
                    rows[idx]['attack_family'] = new_family
                    rows[idx]['label_basis'] = 'CICFlowMeter timestamp+5tuple'
                    rows[idx]['reference_match'] = direction
                    joined_rows.add(idx)
                    reference_labels[label] += 1
            else:
                timestamp_deltas[round(delta/60)*60] += 1

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=OUT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    counts = Counter(row['label'] for row in rows)
    direction_counts = Counter(row['reference_match'] for row in rows if row['reference_match'] != 'no')
    report = {
        'schema_version': SCHEMA, 'capture_id': args.capture_id, 'eve_sha256': sha256(eve_path),
        'reference_csv_sha256': sha256(csv_path), 'output_sha256': sha256(output),
        'output_path': output.relative_to(ROOT).as_posix(), 'output_rows': len(rows),
        'feature_columns': FEATURES, 'identity_and_label_fields_excluded_from_model_input':
            ['schema_version', 'capture_id', 'flow_id', 'src_ip', 'src_port', 'dest_ip', 'dest_port',
             'protocol_name', 'flow_start_utc', 'flow_end_utc', 'label', 'attack_family',
             'label_basis', 'reference_match'],
        'label_counts': dict(counts), 'matched_reference_flows': len(joined_rows),
        'matched_attack_flows': sum(1 for row in rows if row['label'] == 'attack' and row['label_basis'] == 'CICFlowMeter timestamp+5tuple'),
        'matched_benign_flows': sum(1 for row in rows if row['label'] == 'benign' and row['label_basis'] == 'CICFlowMeter timestamp+5tuple'),
        'match_direction_counts': dict(direction_counts),
        'matched_reference_labels': dict(reference_labels), 'same_5tuple_reference_rows': key_rows,
        'accepted_attack_labels': sorted(accepted_attack_labels),
        'timestamp_offset_hours_applied': args.utc_offset_hours,
        'unmatched_timestamp_delta_minutes_rounded': dict(timestamp_deltas.most_common(20)),
        'reference_label_conflicts': ref_label_key_conflicts,
        'duplicate_eve_records_removed': duplicate_eve_records,
        'malformed_eve_events': malformed_eve,
        'limitations': [
            'Mirror CSV hash matches its pinned LFS metadata; publisher-original hash is unavailable.',
            'Attack rows require exact protocol/IP/port and timestamp match within tolerance.',
            'Unmatched capture flows remain unknown; they are not assumed benign.',
            'Only matched BENIGN CSV records get benign labels; time outside a published attack window is insufficient.',
            'Dataset folder says 01-12 while PCAP and CSV timestamps say 2018-12-01; date discrepancy remains documented.',
            'Suricata flow-v2 differs from CICFlowMeter; a CSV row is reference ground truth, not a one-to-one feature equivalence.'
        ]
    }
    report_path = output.with_suffix('.report.json')
    report_path.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
