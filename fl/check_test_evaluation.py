"""Synthetic checks for the isolated held-out evaluator; no real datasets."""
import copy
import csv
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'scripts'))
from check_fl_inputs import sha
from flow_features import FEATURES, SCHEMA
from model_runtime import TRANSFORM
from fl.evaluate_test import evaluate_node


def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value),encoding='utf-8')


def main():
    with tempfile.TemporaryDirectory(prefix='test-evaluation-check-') as temporary:
        base=Path(temporary);root=base/'project'
        own='data/node-a/work/splits/pilot-v1/'
        path=root/own/'test.csv';path.parent.mkdir(parents=True)
        rows=[]
        for index,(protocol,label) in enumerate([(6,'benign'),(17,'attack'),(6,'attack'),(17,'attack')]):
            raw=[protocol,.1,2,int(index%2),100,20,30,.5,0]
            rows.append(dict(zip(FEATURES,raw),schema_version=SCHEMA,label=label,row_uid='row-'+str(index),group_id='group-'+str(index)))
        with path.open('w',encoding='utf-8',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
        artifact={'path':own+'test.csv','sha256':sha(path),'rows':4,'label_counts':{'benign':1,'attack':3}}
        manifest={'node_id':'A','schema_version':SCHEMA,'features':FEATURES,'checks':{'isolated':True},'artifacts':{'test':artifact}}
        write(root/own/'manifest.json',manifest)
        config=json.loads((ROOT/'config/fl/fedavg.json').read_text())
        config['clients']['A']['manifest_sha256']=sha(root/own/'manifest.json')
        write(root/'config/fl/fedavg.json',config)
        models={}
        for name,sign in [('global',1),('local',-1)]:
            folder=base/name;folder.mkdir()
            weights={'layers':np.asarray(3),'coef_0':np.zeros((13,32)), 'intercept_0':np.zeros(32),
                     'coef_1':np.zeros((32,16)), 'intercept_1':np.zeros(16),
                     'coef_2':np.zeros((16,1)), 'intercept_2':np.array([-float(sign)])}
            weights['coef_0'][1,0]=1;weights['coef_1'][0,0]=1;weights['coef_2'][0,0]=2*sign
            np.savez(folder/'weights.npz',**weights)
            meta={'schema_version':SCHEMA,'features':FEATURES,'transform':TRANSFORM,
                  'threshold':.5,'weights_sha256':sha(folder/'weights.npz'),'selected_round':4}
            write(folder/'model.json',meta)
            models[name]={'files':{p.name:sha(p) for p in folder.iterdir()},'weights_sha256':meta['weights_sha256'],'threshold':.5}
        plan={'run_id':'synthetic','selected_round':4,'config_sha256':sha(root/'config/fl/fedavg.json'),
              'global':models['global'],'nodes':{'A':{'manifest_path':own+'manifest.json',
              'manifest_sha256':sha(root/own/'manifest.json'),'test':artifact,'local':models['local']}}}
        original_open=Path.open
        def guarded_open(path,*args,**kwargs):
            if path.name in ('train.csv','validation.csv') or 'node-b' in path.parts or 'node-c' in path.parts:
                raise AssertionError('Evaluator opened a forbidden partition: '+str(path))
            return original_open(path,*args,**kwargs)
        with patch.object(Path,'open',guarded_open):
            result=evaluate_node(root,plan,'A',base/'out',base/'global',base/'local')
        assert result['models']['global']['confusion_matrix']==[[1,0],[1,2]]
        assert result['models']['local']['confusion_matrix']==[[0,1],[2,1]]
        assert abs(result['models']['global']['f1_attack']-.8)<1e-12
        assert abs(result['models']['local']['f1_attack']-.4)<1e-12
        assert abs(result['models']['global']['balanced_accuracy']-5/6)<1e-12
        assert result['checks']['no_fitting'] and sha(base/'out/predictions.csv')==result['artifacts']['predictions.csv']
        rejected=[]
        for name in ('foreign_test','test_hash','weights_hash','threshold','selected_round'):
            broken=copy.deepcopy(plan)
            if name=='foreign_test':broken['nodes']['A']['test']['path']='data/node-b/work/splits/pilot-v1/test.csv'
            elif name=='test_hash':broken['nodes']['A']['test']['sha256']='0'*64
            elif name=='weights_hash':broken['global']['weights_sha256']='0'*64
            elif name=='threshold':broken['global']['threshold']=.4
            else:broken['selected_round']=5
            try:evaluate_node(root,broken,'A',base/name,base/'global',base/'local')
            except ValueError:rejected.append(name)
            else:raise AssertionError('Accepted invalid case: '+name)
        print(json.dumps({'result':'PASS isolated test evaluator','scope':'Four synthetic rows only; no real data/model mounts',
                          'global_confusion_matches_manual_counts':True,'local_confusion_matches_manual_counts':True,
                          'fit_and_partial_fit_forbidden':True,'train_validation_other_nodes_not_read':True,
                          'paired_predictions_written':True,'rejected_cases':rejected,'real_test_evaluated':False}))


if __name__=='__main__':main()
