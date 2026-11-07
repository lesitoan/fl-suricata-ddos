"""Create explicit, conservative time-block holdouts for the Node A pilot."""
import csv
import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

# Shared modules live one directory above this node-specific script.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from flow_features import FEATURES, SCHEMA
from split_helpers import FIELDS, SPLITS, assignment, group_id, hashed

ROOT = Path(__file__).resolve().parents[2]
def main():
    config_path = ROOT/'config/node-a/node-a-expansion.json'
    config = json.loads(config_path.read_text())
    output = ROOT/'data/node-a/work/splits/pilot-v1'
    if output.exists():
        raise FileExistsError('Refusing to overwrite a split definition: '+str(output))
    counts = Counter()
    group_splits = defaultdict(set)
    candidates = []
    sources = []
    for capture in config['captures']:
        path = ROOT/'data/node-a/dataset/derived/suricata'/capture/'flows-v2.csv'
        report = json.loads(path.with_suffix('.report.json').read_text())
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != report['output_sha256']:
            raise ValueError('Source CSV hash differs from join report')
        sources.append({'capture_id':capture,'path':path.relative_to(ROOT).as_posix(),
                        'sha256':digest,'join_evidence':path.with_suffix('.report.json').relative_to(ROOT).as_posix()})
        with path.open(newline='', encoding='utf-8') as source:
            for index, row in enumerate(csv.DictReader(source), start=2):
                counts['all_rows'] += 1
                if row['schema_version'] != SCHEMA:
                    raise ValueError('Mixed schema')
                if row['label'] == 'unknown':
                    counts['excluded_unknown'] += 1
                    continue
                if row['label_basis'] != 'CICFlowMeter timestamp+5tuple' or row['reference_match'] not in ('forward', 'reverse'):
                    raise ValueError('Unverified supervised label')
                if row['label'] == 'attack' and row['attack_family'].lower() != 'syn':
                    raise ValueError('Unexpected attack family for Node A pilot')
                split = assignment(row, config['split_time_blocks_utc'][capture])
                if split is None:
                    counts['excluded_outside_or_crossing_time_block'] += 1
                    continue
                gid = group_id(row)
                uid = hashed([capture, index, digest])
                exported = {name:row[name] for name in ['schema_version','capture_id','flow_start_utc','flow_end_utc',*FEATURES,'label']}
                exported.update(row_uid=uid, group_id=gid)
                candidates.append((split, exported))
                group_splits[gid].add(split)
    contaminated = {group for group, splits in group_splits.items() if len(splits)>1}
    rows_by_split = defaultdict(list)
    for split, row in candidates:
        if row['group_id'] in contaminated:
            counts['excluded_group_spanning_splits'] += 1
            continue
        rows_by_split[split].append(row)
    labels = {name:dict(Counter(row['label'] for row in rows_by_split[name])) for name in SPLITS}
    if any(labels[name].get('benign',0)<30 or labels[name].get('attack',0)<30 for name in SPLITS):
        raise ValueError('Insufficient pilot classes after guards/group exclusion: '+str(labels))
    ids = {name:{row['row_uid'] for row in rows_by_split[name]} for name in SPLITS}
    groups = {name:{row['group_id'] for row in rows_by_split[name]} for name in SPLITS}
    assert all(not ids[a]&ids[b] and not groups[a]&groups[b] for i,a in enumerate(SPLITS) for b in SPLITS[i+1:])
    output.mkdir(parents=True)
    artifacts = {}
    for name in SPLITS:
        rows = sorted(rows_by_split[name], key=lambda row:row['row_uid'])
        path = output/(name+'.csv')
        with path.open('w', newline='', encoding='utf-8') as dest:
            writer = csv.DictWriter(dest, fieldnames=FIELDS)
            writer.writeheader(); writer.writerows(rows)
        artifacts[name] = {'path':path.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                           'rows':len(rows),'label_counts':labels[name],'group_count':len(groups[name])}
    manifest = {'created_at_utc':datetime.now(timezone.utc).isoformat(),'node_id':'A','scope':'single-recording time-block pilot',
                'schema_version':SCHEMA,'features':FEATURES,'seed':config['seed'],
                'preprocessing_fitted':False,'resampling_applied':False,
                'config_path':config_path.relative_to(ROOT).as_posix(),
                'config_sha256':hashlib.sha256(config_path.read_bytes()).hexdigest(),
                'group_rule':config['group_rule'],'time_blocks_utc':config['split_time_blocks_utc'],
                'sources':sources,'artifacts':artifacts,'filter_counts':dict(counts),
                'quarantined_cross_split_groups':len(contaminated),
                'checks':{'no_row_id_overlap':True,'no_canonical_five_tuple_group_overlap':True,
                          'all_classes_present':True,'unknown_excluded':True,'split_before_preprocessing':True},
                'research_train_ready':False,'node_a_pilot_train_ready':True,
                'non_iid_abc_created':False,'limitations':config['limitations']+[
                    'Distinct connections can have identical feature vectors (e.g. one-packet SYN); record/group identity, not feature-vector uniqueness, defines overlap.',
                    'Benign enrichment from an earlier segment can introduce capture/time confounding; metrics are pilot-only.',
                    'No family-generalization or federated-learning claims can be made from this split.']}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    (ROOT/'reports/node-a-split-pilot.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(manifest,indent=2))


if __name__ == '__main__':
    main()
