"""Freeze B time blocks and exclude every canonical group in any frozen A split."""
import csv
import hashlib
import json
import sys
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from flow_features import FEATURES,SCHEMA
from split_helpers import group_id,hashed,assignment,FIELDS,SPLITS

ROOT=Path(__file__).resolve().parents[2]


def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    cfg_path=ROOT/'config/node-b/node-b-expansion.json'
    cfg=json.loads(cfg_path.read_text())
    out=ROOT/'data/node-b/work/splits/pilot-v1'
    if out.exists(): raise FileExistsError('Never replace a frozen split')
    a_manifest=ROOT/'data/node-a/work/splits/pilot-v1/manifest.json'
    a=json.loads(a_manifest.read_text());a_groups=set();a_artifacts=[]
    for name in SPLITS:
        item=a['artifacts'][name];p=ROOT/item['path']
        if sha(p)!=item['sha256']: raise RuntimeError('Frozen A split hash mismatch')
        with p.open(newline='',encoding='utf-8') as f:
            groups={x['group_id'] for x in csv.DictReader(f)}
        a_groups.update(groups);a_artifacts.append({'split':name,'path':item['path'],'sha256':item['sha256'],'groups':len(groups)})
    counts=Counter();sources=[];candidates=[];group_splits=defaultdict(set)
    for capture in cfg['captures']:
        p=ROOT/'data/node-b/dataset/derived/suricata'/capture/'flows-v2.csv'
        report=json.loads(p.with_suffix('.report.json').read_text());digest=sha(p)
        if digest!=report['output_sha256'] or report['reference_label_conflicts']:
            raise RuntimeError('Join hash/conflict guard failed')
        sources.append({'capture_id':capture,'path':p.relative_to(ROOT).as_posix(),'sha256':digest,
            'join_evidence':p.with_suffix('.report.json').relative_to(ROOT).as_posix()})
        with p.open(newline='',encoding='utf-8') as f:
            for index,row in enumerate(csv.DictReader(f),start=2):
                counts['all_rows']+=1
                if row['schema_version']!=SCHEMA: raise RuntimeError('Mixed schema')
                if row['label']=='unknown':counts['excluded_unknown']+=1;continue
                if row['label_basis']!='CICFlowMeter timestamp+5tuple' or row['reference_match'] not in ('forward','reverse'):
                    raise RuntimeError('Unverified label')
                if row['label']=='attack' and row['attack_family']!='DrDoS_UDP':raise RuntimeError('Unexpected attack family')
                gid=group_id(row)
                if gid in a_groups:counts['excluded_group_present_in_any_A_split']+=1;continue
                split=assignment(row,cfg['split_time_blocks_utc'][capture])
                if split is None:counts['excluded_outside_or_crossing_time_block']+=1;continue
                exported={k:row[k] for k in ['schema_version','capture_id','flow_start_utc','flow_end_utc',*FEATURES,'label']}
                exported.update(row_uid=hashed([capture,index,digest]),group_id=gid)
                candidates.append((split,exported));group_splits[gid].add(split)
    contaminated={gid for gid,s in group_splits.items() if len(s)>1}
    by_split=defaultdict(list)
    for split,row in candidates:
        if row['group_id'] in contaminated:counts['excluded_group_spanning_B_splits']+=1;continue
        by_split[split].append(row)
    labels={s:dict(Counter(x['label'] for x in by_split[s])) for s in SPLITS}
    groups={s:{x['group_id'] for x in by_split[s]} for s in SPLITS}
    uids={s:{x['row_uid'] for x in by_split[s]} for s in SPLITS}
    for s in SPLITS:
        if any(labels[s].get(k,0)<30 for k in ['benign','attack']):
            raise RuntimeError('Insufficient classes after exclusions; no split frozen: '+str(labels))
        assert not groups[s]&a_groups
    assert all(not groups[s]&groups[t] and not uids[s]&uids[t] for i,s in enumerate(SPLITS) for t in SPLITS[i+1:])
    out.mkdir(parents=True)
    artifacts={}
    for s in SPLITS:
        p=out/(s+'.csv')
        with p.open('w',newline='',encoding='utf-8') as f:
            w=csv.DictWriter(f,fieldnames=FIELDS);w.writeheader();w.writerows(sorted(by_split[s],key=lambda x:x['row_uid']))
        artifacts[s]={'path':p.relative_to(ROOT).as_posix(),'sha256':sha(p),'rows':len(by_split[s]),
            'label_counts':labels[s],'group_count':len(groups[s])}
    report={'created_at_utc':datetime.now(timezone.utc).isoformat(),'node_id':'B','scope':'single-recording time-block pilot',
        'schema_version':SCHEMA,'features':FEATURES,'seed':cfg['seed'],'config_path':cfg_path.relative_to(ROOT).as_posix(),
        'config_sha256':sha(cfg_path),'time_blocks_utc':cfg['split_time_blocks_utc'],'group_rule':cfg['group_rule'],
        'sources':sources,'artifacts':artifacts,'filter_counts':dict(counts),'quarantined_cross_split_groups':len(contaminated),
        'frozen_A_manifest_sha256':sha(a_manifest),'frozen_A_artifacts_checked':a_artifacts,'frozen_A_group_count':len(a_groups),
        'preprocessing_fitted':False,'resampling_applied':False,'node_b_pilot_train_ready':True,'research_train_ready':False,
        'non_iid_ab_family_design':{'A':'Syn','B':'DrDoS_UDP','train_shards_disjoint':True,'C':'pending'},
        'checks':{'no_row_id_overlap':True,'no_canonical_five_tuple_group_overlap':True,
            'no_B_group_in_any_A_split':True,'all_classes_present':True,'unknown_excluded':True,'split_before_preprocessing':True},
        'limitations':cfg['limitations']}
    (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    report_path = ROOT/'reports/node-b/split-pilot.json'
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report,indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
