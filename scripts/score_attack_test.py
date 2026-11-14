"""Score attack-labelled rows of a frozen flow-v2 test split with two models."""
import argparse
import csv
import json
from pathlib import Path

from flow_features import FEATURES, SCHEMA


def attack_rows(path):
    with path.open(encoding='utf-8-sig', newline='') as stream:
        for index, row in enumerate(csv.DictReader(stream)):
            if row['schema_version'] != SCHEMA or row['label'] not in ('attack', 'benign'):
                raise ValueError('Invalid test row schema or label')
            if row['label'] == 'attack':
                yield index, row


def main():
    from infer_eve import load_model
    from model_runtime import predict_proba

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--local-hash', required=True)
    parser.add_argument('--global-hash', required=True)
    args = parser.parse_args()
    attacks = list(attack_rows(Path('/input/test.csv')))
    features = [[float(row[name]) for name in FEATURES] for _, row in attacks]
    probabilities, thresholds = {}, {}
    for mode, expected_hash in (('local', args.local_hash), ('global', args.global_hash)):
        _, weights, threshold, digest = load_model(Path('/model')/mode)
        with weights:
            if digest != expected_hash:
                raise ValueError('Model weights differ from the frozen hash: '+mode)
            probabilities[mode] = predict_proba(features, weights)
        thresholds[mode] = threshold

    with Path('/output/predictions.csv').open('x', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['test_row_index', 'row_uid', 'true_label',
                         'local_probability_attack', 'local_predicted_label',
                         'global_probability_attack', 'global_predicted_label'])
        for position, (index, row) in enumerate(attacks):
            local, global_ = (float(probabilities[mode][position]) for mode in ('local', 'global'))
            writer.writerow([index, row['row_uid'], 1, local, int(local >= thresholds['local']),
                             global_, int(global_ >= thresholds['global'])])
    print(json.dumps({'attack_rows_scored': len(attacks)}))


if __name__ == '__main__':
    main()
