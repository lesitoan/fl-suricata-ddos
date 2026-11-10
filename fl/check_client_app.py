"""Exercise Flower ClientApp handlers against isolated synthetic node files."""
import argparse
import copy
import csv
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
from unittest.mock import patch

import numpy as np
from flwr.app import ArrayRecord, ConfigRecord, Context, Message, Metadata, RecordDict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT/'scripts'))
from flow_features import FEATURES, SCHEMA
from fl import client_app
from fl.local_data import LocalInputs
from fl.mlp_adapter import initial_parameters, parameter_sha256, train_round, evaluate


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(root, node, config):
    root.mkdir()
    folder = root/('data/node-' + node.lower() + '/work/splits/pilot-v1')
    folder.mkdir(parents=True)
    manifest = {'node_id':node, 'schema_version':SCHEMA, 'features':FEATURES,
                'checks':{'synthetic_fixture':True}, 'artifacts':{}}
    data = {}
    for split, count in (('train',256),('validation',64)):
        rows, labels, raw = [], [], []
        for i in range(count):
            attack = i % 2 == 1
            p1, p2 = 2+i%5, (0 if attack and i%8 == 1 else 1+i%3)
            b1, b2 = p1*(80+i%20), p2*(100+i%10)
            values = [6 if node=='A' else 17, .01+i/10000, p1,p2,b1,b2,
                      (b1+b2)/(p1+p2),p2/p1,0]
            raw.append(values); labels.append(int(attack))
            rows.append({'schema_version':SCHEMA,'row_uid':node+'-'+split+'-'+str(i),
                         'group_id':node+'-'+split+'-group-'+str(i),
                         **dict(zip(FEATURES,values)),'label':'attack' if attack else 'benign'})
        path=folder/(split+'.csv')
        with path.open('w',encoding='utf-8',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=['schema_version','row_uid','group_id',*FEATURES,'label'])
            writer.writeheader();writer.writerows(rows)
        manifest['artifacts'][split]={'path':path.relative_to(root).as_posix(),
            'sha256':sha(path),'rows':count,'label_counts':{'benign':count//2,'attack':count//2}}
        data[split]=(np.asarray(raw,dtype=np.float64),np.asarray(labels,dtype=np.int64))
    # Exists deliberately: attempts to open it make the file-access guard fail.
    (folder/'test.csv').write_text('DO NOT READ THIS TEST FILE\n',encoding='utf-8')
    manifest['artifacts']['test']={'path':(folder/'test.csv').relative_to(root).as_posix(),
                                  'sha256':sha(folder/'test.csv'),'rows':2,
                                  'label_counts':{'benign':1,'attack':1}}
    manifest_path=folder/'manifest.json'
    manifest_path.write_text(json.dumps(manifest),encoding='utf-8')
    config=copy.deepcopy(config)
    config['clients'][node]['manifest_sha256']=sha(manifest_path)
    config_path=root/'config/fl/fedavg.json';config_path.parent.mkdir(parents=True)
    config_path.write_text(json.dumps(config),encoding='utf-8')
    return config,data,manifest_path,config_path


def context(root,node):
    return Context(run_id=0,node_id=100+ord(node),
                   node_config={'project-root':str(root),'node-id':node},
                   state=RecordDict(),run_config={})


def request(ctx,config_path,kind,parameters=None,round_id=1,overrides=None):
    config={'schema-version':SCHEMA,'fl-config-sha256':sha(config_path)}
    content={}
    if parameters is not None:
        config.update({'server-round':round_id,'parameters-sha256':parameter_sha256(parameters),'local-epochs':1})
        arrays=ArrayRecord(numpy_ndarrays=parameters)
        # Deliberately reverse mapping order; array decoding must use named keys.
        content['arrays']=ArrayRecord({key:arrays[key] for key in reversed(list(arrays))})
    if overrides:config.update(overrides)
    content['config']=ConfigRecord(config)
    # A real runtime supplies task identity. This offline fixture supplies
    # explicit metadata instead of starting SuperLink/SuperNode processes.
    metadata=Metadata(run_id=ctx.run_id,message_id='synthetic-'+kind,src_node_id=1,
                      dst_node_id=ctx.node_id,reply_to_message_id='',group_id='',
                      created_at=time.time(),ttl=300,message_type=kind)
    return Message(content=RecordDict(content),metadata=metadata)


def must_reject(action,label,rejected):
    try:action()
    except (ValueError,KeyError):rejected.append(label)
    else:raise AssertionError('Accepted invalid case: '+label)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,default=ROOT/'config/fl/fedavg.json')
    args=parser.parse_args()
    config=json.loads(args.config.read_text(encoding='utf-8-sig'))
    checks={};rejected=[];real_open=Path.open
    with tempfile.TemporaryDirectory(prefix='fl-client-fixture-') as temp:
        for node in ('A','B','C'):
            root=Path(temp)/node
            local_cfg,data,manifest_path,config_path=fixture(root,node,config)
            ctx=context(root,node)
            files=[]
            def guarded_open(path,*args,**kwargs):
                path=Path(path)
                if path.name=='test.csv':raise AssertionError('Client attempted to read test')
                parts=path.parts
                if any('node-'+other.lower() in parts for other in ('A','B','C') if other!=node):
                    raise AssertionError('Client attempted to read another node')
                if path.suffix=='.csv':files.append(path.name)
                if 'models' in parts:raise AssertionError('Client attempted to load a baseline')
                return real_open(path,*args,**kwargs)
            with patch.object(Path,'open',guarded_open):
                props=client_app.app(request(ctx,config_path,'query.properties'),ctx)
                assert set(props.content)=={'properties'} and not files
                assert props.content['properties']['node-id']==node
                assert props.content['properties']['num-train-examples']==256
                parameters=initial_parameters(local_cfg);original=parameter_sha256(parameters)
                response=client_app.app(request(ctx,config_path,'train',parameters),ctx)
                assert set(response.content)=={'arrays','metrics','metadata'}
                assert set(files)=={'train.csv'};files.clear()
                updated=[response.content['arrays'][str(i)].numpy() for i in range(6)]
                expected,details=train_round(parameters,*data['train'],local_cfg,node,1)
                assert parameter_sha256(updated)==parameter_sha256(expected)!=original
                assert parameter_sha256(parameters)==original
                meta=response.content['metadata']
                assert meta['received-parameters-sha256']==original
                assert meta['updated-parameters-sha256']==parameter_sha256(updated)
                assert meta['node-id']==node and meta['server-round']==1
                assert response.content['metrics']['num-examples']==256
                with patch.object(client_app,'train_round',side_effect=AssertionError('Evaluate attempted fitting')):
                    evaluated=client_app.app(request(ctx,config_path,'evaluate',updated),ctx)
                assert set(evaluated.content)=={'metrics','metadata'}
                assert set(files)=={'validation.csv'};files.clear()
                metrics=evaluated.content['metrics'];reference=evaluate(updated,*data['validation'],local_cfg)
                assert metrics['num-examples']==64
                assert sum(metrics[k] for k in ('tn','fp','fn','tp'))==64
                assert abs(metrics['loss']-reference['loss'])<=1e-12
                assert metrics['balanced-accuracy']==reference['balanced_accuracy']
                assert evaluated.content['metadata']['received-parameters-sha256']==parameter_sha256(updated)
                round2=client_app.app(request(ctx,config_path,'train',updated,round_id=2),ctx)
                reference,_=train_round(updated,*data['train'],local_cfg,node,2)
                assert parameter_sha256([round2.content['arrays'][str(i)].numpy() for i in range(6)])==parameter_sha256(reference)
                files.clear()
                for name,change in (
                    ('config_hash',{'fl-config-sha256':'0'*64}),
                    ('schema',{'schema-version':'wrong'}),
                    ('parameter_hash',{'parameters-sha256':'0'*64}),
                    ('server_test_override',{'split':'test'}),
                    ('server_node_override',{'node-id':'B' if node=='A' else 'A'}),
                    ('local_epochs_override',{'local-epochs':2}),
                    ('zero_round',{'server-round':0}),
                    ('bool_round',{'server-round':True}),
                ):
                    must_reject(lambda:client_app.app(request(ctx,config_path,'train',parameters,overrides=change),ctx),node+'/'+name,rejected)
                    assert not files
                local=LocalInputs(root,node)
                must_reject(lambda:local.load('test'),node+'/direct_test_load',rejected)
                assert not files
                train_path=root/local.manifest['artifacts']['train']['path']
                saved=train_path.read_bytes()
                with patch.object(Path,'open',real_open):train_path.write_bytes(saved+b'\n')
                must_reject(lambda:client_app.app(request(ctx,config_path,'train',parameters),ctx),node+'/csv_hash',rejected)
                with patch.object(Path,'open',real_open):train_path.write_bytes(saved)
                files.clear()
                saved_manifest=manifest_path.read_bytes()
                with patch.object(Path,'open',real_open):manifest_path.write_bytes(saved_manifest+b' ')
                must_reject(lambda:client_app.app(request(ctx,config_path,'train',parameters),ctx),node+'/manifest_hash',rejected)
                with patch.object(Path,'open',real_open):manifest_path.write_bytes(saved_manifest)
                assert not files
                # A re-pinned malicious path must still fail the node/partition guard.
                saved_cfg=config_path.read_bytes()
                for name,path_value in (
                    ('foreign_node_path','data/node-'+('b' if node=='A' else 'a')+'/work/splits/pilot-v1/train.csv'),
                    ('test_disguised_as_train','data/node-'+node.lower()+'/work/splits/pilot-v1/test.csv'),
                ):
                    bad=json.loads(saved_manifest);bad['artifacts']['train']['path']=path_value
                    with patch.object(Path,'open',real_open):
                        manifest_path.write_text(json.dumps(bad),encoding='utf-8')
                        altered=copy.deepcopy(local_cfg);altered['clients'][node]['manifest_sha256']=sha(manifest_path)
                        config_path.write_text(json.dumps(altered),encoding='utf-8')
                    must_reject(lambda:client_app.app(request(ctx,config_path,'train',parameters),ctx),node+'/'+name,rejected)
                    assert not files
                with patch.object(Path,'open',real_open):
                    manifest_path.write_bytes(saved_manifest);config_path.write_bytes(saved_cfg)
                checks[node]={'properties_train_evaluate_round2':'PASS',
                              'train_rows':256,'validation_rows':64,
                              'train_reads_only_train':True,'evaluate_reads_only_validation':True,
                              'test_other_nodes_and_baselines_not_read':True,
                              'incoming_global_weights_used_exactly':True,
                              'reply_contains_only_weights_metrics_metadata':True}
    print(json.dumps({'result':'PASS FL ClientApp','scope':'Synthetic local node files and direct Flower message dispatch only; no real dataset/model mounts or FL network',
        'nodes':checks,'rejected_case_count':len(rejected),'rejected_cases':rejected,
        'reversed_array_mapping_order_handled':True,'real_node_training_performed':False,
        'federation_started':False}),flush=True)


if __name__=='__main__':main()
