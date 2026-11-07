"""Match a bounded B UDP probe to its live Suricata flow and ML prediction."""
import argparse
import hashlib
import json
import math
import sys
import time
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from flow_features import event_signature, timestamp

ROOT = Path(__file__).resolve().parents[2]


def json_lines(path):
    if not path.is_file():
        return []
    with path.open(encoding='utf-8-sig') as stream:
        return [json.loads(line) for line in stream if line.endswith('\n') and line.strip()]


def signature(event):
    return hashlib.sha256(json.dumps(list(event_signature(event)),
        separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def verify(root, run_dir, wait_seconds):
    run_dir = run_dir.resolve()
    if not run_dir.is_relative_to((root/'reports/node-b').resolve()):
        raise ValueError('Report folder must stay inside reports/node-b')
    if (run_dir/'verification.json').exists():
        raise FileExistsError('Verification already exists; keep previous evidence')
    sender = json.loads((run_dir/'sender.json').read_text(encoding='utf-8-sig'))
    meta = json.loads((root/'models/node-b/current/model.json').read_text())
    digest = hashlib.sha256((root/'models/node-b/current/weights.npz').read_bytes()).hexdigest()
    if digest != meta['weights_sha256']:
        raise ValueError('Current model hash mismatch')
    deadline = time.monotonic() + wait_seconds
    while True:
        flows = []
        for event in json_lines(root/'data/node-b/live/eve/eve.json'):
            if event.get('event_type') != 'flow' or event.get('proto') != 'UDP':
                continue
            if (event.get('src_ip'), event.get('src_port'), event.get('dest_ip'), event.get('dest_port')) != (
                    sender['source_ip'], sender['source_port'], sender['destination_ip'], sender['destination_port']):
                continue
            if not (timestamp(sender['start_utc'])-timedelta(seconds=1) <= timestamp(event['flow']['start'])
                    <= timestamp(sender['end_utc'])+timedelta(seconds=1)):
                continue
            flows.append(event)
        distinct = {signature(event): event for event in flows}
        predictions = [p for p in json_lines(root/'data/node-b/live/predictions/predictions.jsonl')
                       if p.get('event_signature_sha256') in distinct]
        if distinct and predictions:
            break
        if time.monotonic() >= deadline:
            raise TimeoutError('No matching flow/prediction yet; check service readiness and flow timeout')
        time.sleep(2)
    if len(distinct) != 1 or len(predictions) != 1:
        raise ValueError('Expected one aggregated flow and one prediction; inspect raw logs')
    event = next(iter(distinct.values()))
    prediction = predictions[0]
    if prediction['weights_sha256'] != digest or prediction['model_id'] != meta['config']['experiment_id']:
        raise ValueError('Inference has a different model; recreate inference before a new probe')
    probability = prediction['probability_attack']
    if not math.isfinite(probability) or not 0 <= probability <= 1:
        raise ValueError('Invalid probability')
    expected = 'attack' if probability >= meta['threshold'] else 'benign'
    if prediction['prediction'] != expected or prediction['threshold'] != meta['threshold'] or prediction['mode'] != 'live':
        raise ValueError('Prediction contract mismatch')
    flow = event['flow']
    report = {'result': 'MATCHED', 'scenario': sender['scenario'],
              'scope': sender['scope'], 'packets_sent': sender['packets_sent'],
              'valid_echoes': sender['valid_echoes'], 'matched_flows': 1, 'matched_predictions': 1,
              'captured_packets_toserver': flow['pkts_toserver'],
              'captured_packets_toclient': flow['pkts_toclient'],
              'sent_packet_count_matches_capture': sender['packets_sent'] == flow['pkts_toserver'],
              'probability_attack': probability, 'threshold': meta['threshold'],
              'prediction': prediction['prediction'], 'model_id': prediction['model_id'],
              'weights_sha256': digest,
              'seconds_from_flow_end_to_score': prediction['seconds_from_flow_end_to_score'],
              'interpretation': 'Observed classification only; matching the pipeline does not establish DDoS detection accuracy'}
    for name, value in [('flow.json', event), ('prediction.json', prediction), ('verification.json', report)]:
        (run_dir/name).write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--wait-seconds', type=int, default=75, choices=range(1, 121), metavar='1..120')
    args = parser.parse_args()
    target = args.run_dir if args.run_dir.is_absolute() else ROOT/args.run_dir
    print(json.dumps(verify(ROOT, target, args.wait_seconds), indent=2))
