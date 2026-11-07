"""Shared split schema, identity hashing and conservative time-block assignment."""
import hashlib
import json
from flow_features import FEATURES, timestamp

SPLITS = ('train', 'validation', 'test')
FIELDS = ['schema_version', 'row_uid', 'group_id', 'capture_id',
          'flow_start_utc', 'flow_end_utc'] + FEATURES + ['label']


def hashed(value):
    return hashlib.sha256(json.dumps(value, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def group_id(row):
    ends = sorted([(row['src_ip'], int(row['src_port'] or 0)),
                   (row['dest_ip'], int(row['dest_port'] or 0))])
    return hashed([int(row['protocol']), ends])


def assignment(row, blocks):
    start, end = timestamp(row['flow_start_utc']), timestamp(row['flow_end_utc'])
    matches = [name for name, (left, right) in blocks.items()
               if timestamp(left) <= start and end <= timestamp(right) and start < timestamp(right)]
    if len(matches) > 1:
        raise ValueError('Overlapping split definitions')
    return matches[0] if matches else None
