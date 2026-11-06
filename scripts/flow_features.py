"""Định nghĩa và tính chín đặc trưng từ flow"""
import gzip
import math
from datetime import datetime, timezone

SCHEMA = 'flow-v2'
FEATURES = ['protocol', 'duration_s', 'pkts_toserver', 'pkts_toclient',
            'bytes_toserver', 'bytes_toclient', 'mean_packet_bytes',
            'response_packet_ratio', 'duration_le_1us']
PROTOCOLS = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'ICMPv6': 58}
COUNTERS = ['pkts_toserver', 'pkts_toclient', 'bytes_toserver', 'bytes_toclient']


def timestamp(value):
    stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if stamp.tzinfo is None:
        raise ValueError('EVE timestamps must include a timezone')
    return stamp.astimezone(timezone.utc)


def text_open(path, **kwargs):
    return gzip.open(path, 'rt', **kwargs) if path.suffix == '.gz' else path.open('r', **kwargs)


def flow_features(event):
    if event.get('event_type') != 'flow':
        raise ValueError('Expected EVE flow event')
    flow = event['flow']
    duration = (timestamp(flow['end']) - timestamp(flow['start'])).total_seconds()
    if duration < 0:
        raise ValueError('Negative flow duration')
    counts = []
    for name in COUNTERS:
        value = flow[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError('Counter must be a nonnegative integer: '+name)
        counts.append(value)
    p1, p2, b1, b2 = counts
    if p1 + p2 == 0:
        raise ValueError('Flow has no packets')
    values = [PROTOCOLS.get(event.get('proto'), 0), duration, p1, p2, b1, b2,
              (b1+b2)/(p1+p2), p2/max(p1, 1), int(duration <= 0.000001)]
    if not all(math.isfinite(value) for value in values):
        raise ValueError('Nonfinite flow feature')
    return dict(zip(FEATURES, values))


def event_signature(event):
    flow = event['flow']
    return (str(event['flow_id']), event.get('src_ip'), event.get('src_port', ''),
            event.get('dest_ip'), event.get('dest_port', ''), event.get('proto', 'OTHER'),
            timestamp(flow['start']).isoformat(), timestamp(flow['end']).isoformat(),
            *(flow[name] for name in COUNTERS))
