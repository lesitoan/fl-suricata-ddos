"""Read only the frozen train/validation partition of one local FL node."""
import json
from collections import Counter
from pathlib import Path

import numpy as np

from check_fl_inputs import inside, sha
from flow_features import FEATURES, SCHEMA
from train_mlp import load_split
from fl.mlp_adapter import validate_config


class LocalInputs:
    def __init__(self, project_root, node_id):
        if node_id not in ('A', 'B', 'C'):
            raise ValueError('Local node-id must be A/B/C')
        project_root = Path(project_root)
        if not project_root.is_absolute():
            raise ValueError('Local project-root must be absolute')
        self.root = project_root.resolve()
        self.node_id = node_id
        self.prefix = 'data/node-' + node_id.lower()
        config_path = inside(self.root, 'config/fl/fedavg.json', 'config/fl')
        self.config_sha256 = sha(config_path)
        self.config = json.loads(config_path.read_text(encoding='utf-8-sig'))
        validate_config(self.config)
        if self.config['training'].get('test_during_training') is not False:
            raise ValueError('This client never permits test data during training')
        self.spec = self.config['clients'][node_id]
        if self.spec['sample_weighting'] not in ('class_balanced', 'class_and_attack_response'):
            raise ValueError('Unknown local sample weighting')
        expected_manifest = self.prefix + '/work/splits/pilot-v1/manifest.json'
        if self.spec['manifest_path'] != expected_manifest:
            raise ValueError('Unexpected node manifest path')
        manifest_path = inside(self.root, self.spec['manifest_path'], self.prefix)
        self.manifest_sha256 = sha(manifest_path)
        if self.manifest_sha256 != self.spec['manifest_sha256']:
            raise ValueError('Local manifest hash differs from FL config')
        self.manifest = json.loads(manifest_path.read_text(encoding='utf-8-sig'))
        if (self.manifest['node_id'] != node_id or self.manifest['schema_version'] != SCHEMA
                or self.manifest['features'] != FEATURES):
            raise ValueError('Local manifest node/schema/features differ')
        checks = self.manifest['checks']
        if not checks or not all(value is True for value in checks.values()):
            raise ValueError('Local frozen split checks not passed')
        for split in ('train', 'validation'):
            artifact = self.manifest['artifacts'][split]
            expected = self.prefix + '/work/splits/pilot-v1/' + split + '.csv'
            if artifact['path'] != expected:
                raise ValueError('Partition path must be the node-owned ' + split + '.csv')
            if type(artifact['rows']) is not int or artifact['rows'] < 2:
                raise ValueError('Invalid declared split size')
            labels = artifact['label_counts']
            if set(labels) != {'benign', 'attack'} or any(type(n) is not int or n <= 0 for n in labels.values()) or sum(labels.values()) != artifact['rows']:
                raise ValueError('Both classes and matching split counts required')

    def load(self, split):
        if split not in ('train', 'validation'):
            raise ValueError('Client only reads train/validation; test is forbidden')
        artifact = self.manifest['artifacts'][split]
        inside(self.root, artifact['path'], self.prefix)
        values, labels = load_split(self.root, artifact)
        counts = Counter('attack' if y == 1 else 'benign' for y in labels)
        if dict(counts) != artifact['label_counts']:
            raise ValueError('Local split label counts differ')
        if not np.isfinite(values).all():
            raise ValueError('Nonfinite local features')
        return values, labels

    def properties(self):
        return {'node-id': self.node_id, 'schema-version': SCHEMA,
                'fl-config-sha256': self.config_sha256,
                'manifest-sha256': self.manifest_sha256,
                'sample-weighting': self.spec['sample_weighting'],
                'num-train-examples': self.manifest['artifacts']['train']['rows'],
                'num-validation-examples': self.manifest['artifacts']['validation']['rows']}
