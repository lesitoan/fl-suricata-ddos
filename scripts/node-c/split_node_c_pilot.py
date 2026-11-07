"""Freeze laptop C train/validation/test and exclude all A/B groups."""
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


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def read(path):return json.loads(path.read_text(encoding='utf-8'))


def main():
    cfg_path=ROOT/'config/node-c/node-c-expansion.json';cfg=read(cfg_path)
    out=ROOT/'data/node-c/work/splits/pilot-v1'
    if out.exists():raise FileExistsError('Never overwrite a frozen or partial C split')
    excluded=set();frozen=[]
    for node in ['a','b']:
        manifest_path=ROOT/f'data/node-{node}/work/splits/pilot-v1/manifest.json';manifest=read(manifest_path)
        checked=[]
        for split in SPLITS:
            item=manifest['artifacts'][split];path=ROOT/item['path']
            if sha(path)!=item['sha256']:raise RuntimeError('Frozen A/B artifact changed')
            with path.open(newline='',encoding='utf-8') as f:groups={r['group_id'] for r in csv.DictReader(f)}
            excluded.update(groups);checked.append({'split':split,**item})
        frozen.append({'node_id':node.upper(),'manifest_path':manifest_path.relative_to(ROOT).as_posix(),'manifest_sha256':sha(manifest_path),'artifacts':checked})
    counts=Counter();sources=[];candidates=[];group_splits=defaultdict(set);observations=Counter()
    for capture in cfg['capture_assignments']:
        path=ROOT/f'data/node-c/dataset/derived/suricata/{capture}/flows-v2.csv'
        joined=read(path.with_name('flows-v2.report.json'));digest=sha(path)
        if digest!=joined['output_sha256'] or joined['reference_label_conflicts']:raise RuntimeError('C label/source hash guard failed')
        if sha(path.with_name('eve.json'))!=joined['eve_sha256'] or sha(ROOT/'data/node-c/dataset/reference/node-c-reference.csv.gz')!=joined['reference_csv_sha256']:
            raise RuntimeError('C EVE/reference hash guard failed')
        sources.append({'capture_id':capture,'path':path.relative_to(ROOT).as_posix(),'sha256':digest,'join_evidence':path.with_name('flows-v2.report.json').relative_to(ROOT).as_posix()})
        with path.open(newline='',encoding='utf-8') as f:
            for index,row in enumerate(csv.DictReader(f),start=2):
                counts['all_rows']+=1
                if row['schema_version']!=SCHEMA:raise RuntimeError('Mixed schema')
                if row['label']=='unknown':counts['excluded_unknown']+=1;continue
                if row['label'] not in ['benign','attack'] or row['label_basis']!='CICFlowMeter timestamp+5tuple' or row['reference_match'] not in ['forward','reverse']:
                    raise RuntimeError('Unverified C label')
                if row['label']=='attack' and row['attack_family']!='DrDoS_LDAP':raise RuntimeError('Unexpected family')
                gid=group_id(row)
                if gid in excluded:counts['excluded_group_present_in_any_A_or_B_split']+=1;continue
                split=assignment(row,cfg['split_time_blocks_utc'].get(capture,{}))
                if split is None:counts['excluded_outside_or_crossing_time_block']+=1;continue
                if split!=cfg['capture_assignments'].get(capture):raise RuntimeError('Capture role mismatch')
                exported={k:row[k] for k in ['schema_version','capture_id','flow_start_utc','flow_end_utc',*FEATURES,'label']}
                exported.update(row_uid=hashed([capture,index,digest]),group_id=gid)
                identity=hashed([gid,row['flow_start_utc'],row['flow_end_utc'],*[row[k] for k in FEATURES]])
                observations[identity]+=1;group_splits[gid].add(split);candidates.append((split,exported,identity))
    cross={gid for gid,splits in group_splits.items() if len(splits)>1};by_split=defaultdict(list)
    for split,row,identity in candidates:
        if row['group_id'] in cross:counts['excluded_group_spanning_C_splits']+=1;continue
        if observations[identity]>1:counts['excluded_duplicate_observation']+=1;continue
        by_split[split].append(row)
    groups={s:{x['group_id'] for x in by_split[s]} for s in SPLITS}
    uids={s:{x['row_uid'] for x in by_split[s]} for s in SPLITS}
    labels={s:dict(Counter(x['label'] for x in by_split[s])) for s in SPLITS}
    for s in SPLITS:
        if any(labels[s].get(c,0)<cfg['minimum_class_rows_per_split'] for c in ['attack','benign']):raise RuntimeError('Insufficient class coverage before fitting: '+str(labels))
        if groups[s]&excluded or len(uids[s])!=len(by_split[s]):raise RuntimeError('Group/UID exclusion failed')
    for i,s in enumerate(SPLITS):
        for t in SPLITS[i+1:]:
            if groups[s]&groups[t] or uids[s]&uids[t]:raise RuntimeError('Cross-split overlap')
    out.mkdir(parents=True)
    artifacts={}
    for s in SPLITS:
        path=out/(s+'.csv')
        with path.open('w',newline='',encoding='utf-8') as stream:
            writer=csv.DictWriter(stream,fieldnames=FIELDS,lineterminator='\n')
            writer.writeheader();writer.writerows(sorted(by_split[s],key=lambda x:x['row_uid']))
        artifacts[s]={'path':path.relative_to(ROOT).as_posix(),'sha256':sha(path),
            'size_bytes':path.stat().st_size,'rows':len(by_split[s]),
            'label_counts':labels[s],'group_count':len(groups[s])}
    report={'created_at_utc':datetime.now(timezone.utc).isoformat(),'node_id':'C','scope':'Separated short windows of one recording; not independent sessions','schema_version':SCHEMA,'features':FEATURES,'seed':cfg['seed'],'config_path':cfg_path.relative_to(ROOT).as_posix(),'config_sha256':sha(cfg_path),'time_blocks_utc':cfg['split_time_blocks_utc'],'group_rule':cfg['group_rule'],'sources':sources,'artifacts':artifacts,'filter_counts':dict(counts),'quarantined_cross_split_groups':len(cross),'frozen_AB_checked':frozen,'excluded_AB_group_count':len(excluded),'preprocessing_fitted':False,'resampling_applied':False,'node_c_pilot_train_ready':True,'research_train_ready':False,'checks':{'no_row_id_overlap':True,'no_canonical_group_overlap_across_C_splits':True,'no_C_group_in_any_A_or_B_split':True,'all_classes_present':True,'unknown_excluded':True,'duplicate_observations_excluded':True,'split_before_preprocessing':True},'limitations':cfg['limitations']}
    (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    report_path=ROOT/'reports/node-c/split-pilot.json'
    report_path.parent.mkdir(parents=True,exist_ok=True)
    report_path.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'label_counts':labels,'filter_counts':dict(counts),'cross_split_groups':len(cross),'checks':report['checks']},indent=2))


if __name__=='__main__':main()
