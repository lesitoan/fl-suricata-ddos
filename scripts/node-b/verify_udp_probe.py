"""Match node B bounded UDP load/burst ports to live flows and local/global predictions."""
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


def verify(root, run_dir, wait_seconds, mode='local'):
    run_dir = run_dir.resolve()
    if not run_dir.is_relative_to((root/'reports/node-b').resolve()):
        raise ValueError('Report folder must stay inside reports/node-b')
    if (run_dir/'verification.json').exists():
        raise FileExistsError('Verification already exists; keep previous evidence')
    sender = json.loads((run_dir/'sender.json').read_text(encoding='utf-8-sig'))
    if mode not in ('local', 'global'):
        raise ValueError('Mode must be local or global')
    model_dir = root/('models/fl/current' if mode == 'global' else 'models/node-b/current')
    meta = json.loads((model_dir/'model.json').read_text())
    digest = hashlib.sha256((model_dir/'weights.npz').read_bytes()).hexdigest()
    expected_ports = set(sender.get('source_ports', [sender.get('source_port')]))
    if not expected_ports or any(isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 for port in expected_ports):
        raise ValueError('Invalid sender ports')
    if sender.get('destination_port') != 9000 or sender.get('node', 'B') != 'B':
        raise ValueError('Expected node B UDP sender')
    if digest != meta['weights_sha256']:
        raise ValueError('Current model hash mismatch')
    deadline = time.monotonic() + wait_seconds
    while True:
        flows = []
        for event in json_lines(root/'data/node-b/live/eve/eve.json'):
            if event.get('event_type') != 'flow' or event.get('proto') != 'UDP':
                continue
            if (event.get('src_ip'), event.get('dest_ip'), event.get('dest_port')) != (
                    sender['source_ip'], sender['destination_ip'], sender['destination_port']):
                continue
            if event.get('src_port') not in expected_ports:
                continue
            if not (timestamp(sender['start_utc'])-timedelta(seconds=1) <= timestamp(event['flow']['start'])
                    <= timestamp(sender['end_utc'])+timedelta(seconds=1)):
                continue
            flows.append(event)
        distinct = {signature(event): event for event in flows}
        predictions = [p for p in json_lines(root/('data/node-b/live/'+('predictions-global' if mode == 'global' else 'predictions')+'/predictions.jsonl'))
                       if p.get('event_signature_sha256') in distinct and p.get('weights_sha256') == digest]
        predictions = list({p['event_signature_sha256']: p for p in predictions}.values())
        covered = {distinct[p['event_signature_sha256']]['src_port'] for p in predictions}
        if expected_ports <= covered:
            break
        if time.monotonic() >= deadline:
            raise TimeoutError('No matching flow/prediction yet; check service readiness and flow timeout')
        time.sleep(2)
    for prediction in predictions:
        if prediction['model_id'] != meta['config']['experiment_id']:
            raise ValueError('Inference model ID differs')
        probability = prediction['probability_attack']
        if not math.isfinite(probability) or not 0 <= probability <= 1:
            raise ValueError('Invalid probability')
        expected = 'attack' if probability >= meta['threshold'] else 'benign'
        if prediction['prediction'] != expected or prediction['threshold'] != meta['threshold'] or prediction['mode'] != 'live':
            raise ValueError('Prediction contract mismatch')
    captured = {port: 0 for port in expected_ports}
    for event in distinct.values():
        captured[event['src_port']] += event['flow']['pkts_toserver']
    expected_counts = {item['source_port']: item['packets_sent'] for item in sender.get('per_flow', [])}
    sent_matches = (captured == expected_counts if expected_counts
                    else sum(captured.values()) == sender['packets_sent'])
    report = {'result': 'MATCHED' if sent_matches else 'PARTIAL_CAPTURE',
              'scenario': sender['scenario'], 'scope': sender['scope'], 'mode': mode,
              'packets_sent': sender['packets_sent'], 'valid_echoes': sender.get('valid_echoes'),
              'matched_flows': len(distinct), 'matched_predictions': len(predictions),
              'predicted_attack': sum(p['prediction'] == 'attack' for p in predictions),
              'predicted_benign': sum(p['prediction'] == 'benign' for p in predictions),
              'captured_packets_toserver': sum(captured.values()),
              'captured_packets_toclient': sum(e['flow']['pkts_toclient'] for e in distinct.values()),
              'sent_packet_count_matches_capture': sent_matches,
              'per_port_captured': captured, 'observed_send_pps': sender.get('observed_send_pps'),
              'health_checks': {phase: {key: value for key, value in item.items() if key != 'records'}
                               for phase, item in sender.get('health_checks', {}).items()},
              'threshold': meta['threshold'], 'model_id': meta['config']['experiment_id'],
              'weights_sha256': digest,
              'interpretation': 'Observed integration/load measurements; no verified attack accuracy or saturation claim'}
    if len(predictions) == 1:
        report.update(probability_attack=predictions[0]['probability_attack'],
                      prediction=predictions[0]['prediction'],
                      seconds_from_flow_end_to_score=predictions[0].get('seconds_from_flow_end_to_score'))
    outputs = [('flows.json', list(distinct.values())), ('predictions.json', predictions),
               ('verification.json', report)]
    if len(distinct) == len(predictions) == 1:
        outputs.extend([('flow.json', next(iter(distinct.values()))), ('prediction.json', predictions[0])])
    for name, value in outputs:
        (run_dir/name).write_text(json.dumps(value, indent=2)+'\n', encoding='utf-8')
    return report



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--wait-seconds', type=int, default=75, choices=range(1, 121), metavar='1..120')
    parser.add_argument('--mode', choices=('local', 'global'), default='local')
    args = parser.parse_args()
    target = args.run_dir if args.run_dir.is_absolute() else ROOT/args.run_dir
    print(json.dumps(verify(ROOT, target, args.wait_seconds, args.mode), indent=2))
