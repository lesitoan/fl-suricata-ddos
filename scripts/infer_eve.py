"""Score completed Suricata flow events with a portable Node A pilot model."""
import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from flow_features import FEATURES, SCHEMA, event_signature, flow_features, text_open, timestamp
from model_runtime import TRANSFORM, predict_proba


def load_model(model_dir):
    model_dir = Path(model_dir)
    meta = json.loads((model_dir / 'model.json').read_text(encoding='utf-8'))
    weights_path = model_dir / 'weights.npz'
    digest = hashlib.sha256(weights_path.read_bytes()).hexdigest()
    if meta.get('schema_version') != SCHEMA or meta.get('features') != FEATURES:
        raise ValueError('Model schema/features do not match flow-v2')
    if meta.get('transform') != TRANSFORM:
        raise ValueError('Model transform does not match this inference runtime')
    if meta.get('weights_sha256') != digest:
        raise ValueError('Model weights hash does not match model contract')
    threshold = float(meta.get('threshold'))
    if not 0.0 <= threshold <= 1.0:
        raise ValueError('Invalid model threshold')
    return meta, np.load(weights_path, allow_pickle=False), threshold, digest


class Scorer:
    def __init__(self, meta, weights, threshold, model_hash, output, live):
        self.meta = meta
        self.weights = weights
        self.threshold = threshold
        self.model_hash = model_hash
        self.live = live
        self.output = Path(output)
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.seen = set()
        self.counts = {'flow_events': 0, 'predictions': 0, 'duplicates': 0,
                       'invalid': 0, 'non_flow_events': 0}

    def process(self, line):
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.counts['invalid'] += 1
            return None
        if event.get('event_type') != 'flow':
            self.counts['non_flow_events'] += 1
            return None
        self.counts['flow_events'] += 1
        try:
            values = flow_features(event)
            signature = event_signature(event)
        except (ValueError, KeyError, TypeError, OverflowError):
            self.counts['invalid'] += 1
            return None
        if signature in self.seen:
            self.counts['duplicates'] += 1
            return None
        self.seen.add(signature)
        vector = [[values[name] for name in FEATURES]]
        probability = float(predict_proba(vector, self.weights)[0])
        flow_end = event['flow']['end']
        scored_at = datetime.now(timezone.utc)
        try:
            delay = (scored_at - timestamp(flow_end)).total_seconds() if self.live else None
        except (ValueError, TypeError):
            delay = None
        signature_sha256 = hashlib.sha256(json.dumps(
            list(signature), separators=(',', ':'), ensure_ascii=True).encode('utf-8')).hexdigest()
        scope = (self.meta.get('scope') or self.meta.get('config', {}).get('scope')
                 or self.meta.get('config', {}).get('experiment_id', 'experimental model'))
        record = {
            'schema_version': SCHEMA,
            'model_id': self.meta.get('config', {}).get('experiment_id', 'unknown'),
            'weights_sha256': self.model_hash,
            'flow_id': str(event.get('flow_id', '')),
            'event_signature_sha256': signature_sha256,
            'flow_start': event['flow']['start'],
            'flow_end': flow_end,
            'scored_at_utc': scored_at.isoformat(),
            'seconds_from_flow_end_to_score': delay,
            'probability_attack': probability,
            'threshold': self.threshold,
            'prediction': 'attack' if probability >= self.threshold else 'benign',
            'scope': scope,
            'mode': 'live' if self.live else 'historical_replay',
        }
        with self.output.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(record, separators=(',', ':')) + '\n')
            stream.flush()
        self.counts['predictions'] += 1
        print(json.dumps({'prediction': record, 'counts': self.counts}, separators=(',', ':')), flush=True)
        return record


def follow(path, scorer, start_at_end, poll_seconds):
    path = Path(path)
    while not path.exists():
        time.sleep(poll_seconds)
    with path.open('rb') as stream:
        if start_at_end:
            stream.seek(0, os.SEEK_END)
        inode = os.fstat(stream.fileno()).st_ino
        pending = b''
        while True:
            chunk = stream.readline()
            if chunk:
                pending += chunk
                if not pending.endswith(b'\n'):
                    continue
                scorer.process(pending.decode('utf-8', errors='replace'))
                pending = b''
                continue
            try:
                current = path.stat()
                if current.st_ino != inode or current.st_size < stream.tell():
                    stream.close()
                    stream = path.open('rb')
                    inode = os.fstat(stream.fileno()).st_ino
                    pending = b''
                    continue
            except FileNotFoundError:
                pass
            time.sleep(poll_seconds)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--eve', required=True, help='Suricata eve.json path')
    parser.add_argument('--model-dir', required=True, help='Directory containing model.json and weights.npz')
    parser.add_argument('--output', required=True, help='Append-only JSONL prediction output')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--once', action='store_true', help='Score every complete line currently in EVE')
    mode.add_argument('--follow', action='store_true', help='Watch EVE for new completed flow events')
    parser.add_argument('--start-at-end', action='store_true', help='In follow mode, ignore historical lines')
    parser.add_argument('--poll-seconds', type=float, default=0.5)
    args = parser.parse_args()
    if args.poll_seconds <= 0 or args.poll_seconds > 10:
        parser.error('--poll-seconds must be within (0, 10]')
    meta, weights, threshold, digest = load_model(args.model_dir)
    scorer = Scorer(meta, weights, threshold, digest, args.output, live=args.follow)
    print(json.dumps({'status': 'ready', 'schema_version': SCHEMA,
                      'model_id': meta.get('config', {}).get('experiment_id', 'unknown'),
                      'weights_sha256': digest,
                      'threshold': threshold, 'mode': 'follow' if args.follow else 'once'},
                     separators=(',', ':')), flush=True)
    if args.once:
        with text_open(Path(args.eve), encoding='utf-8') as stream:
            for line in stream:
                if line.endswith('\n'):
                    scorer.process(line)
        print(json.dumps({'status': 'complete', 'counts': scorer.counts}, separators=(',', ':')))
    else:
        follow(args.eve, scorer, args.start_at_end, args.poll_seconds)


if __name__ == '__main__':
    main()
