"""Offline synthetic tests for strict FedAvg and ServerApp checkpoint lifecycle."""
import argparse
import copy
import hashlib
import json
import logging
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

import numpy as np
from flwr.app import ArrayRecord, ConfigRecord, Context, Error, Message, MetricRecord, RecordDict
from flwr.supercore.task_identity import TaskIdentity

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'scripts'))
from fl import client_app,server_app
from fl.check_client_app import fixture,context
from fl.mlp_adapter import PARAMETER_NAMES,initial_parameters,parameter_sha256
from infer_eve import load_model


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def properties(config,config_hash,train_sizes=(2,3,5),val_sizes=(10,20,30)):
    return {100+i:{'node-id':node,'schema-version':'flow-v2','fl-config-sha256':config_hash,
        'manifest-sha256':config['clients'][node]['manifest_sha256'],
        'sample-weighting':config['clients'][node]['sample_weighting'],
        'num-train-examples':train_sizes[i],'num-validation-examples':val_sizes[i]}
        for i,node in enumerate(('A','B','C'))}


class PeerSet:
    def __init__(self,peers):self.peers=peers
    def get_node_ids(self):return list(self.peers)


def train_replies(strategy,round_id,initial,offset=0):
    requests=strategy.configure_train(round_id,ArrayRecord(numpy_ndarrays=initial),ConfigRecord(),PeerSet(strategy.peers))
    replies=[]
    for i,request in enumerate(requests):
        peer=request.metadata.dst_node_id
        updated=[np.full(value.shape,(1,3,9)[i]+offset,dtype=np.float64) for value in initial]
        meta=dict(strategy.peers[peer],**{'server-round':round_id,
            'received-parameters-sha256':parameter_sha256(initial),
            'updated-parameters-sha256':parameter_sha256(updated)})
        metrics={'num-examples':strategy.peers[peer]['num-train-examples'],'train-loss':.5,
                 'local-epochs':1,'train-seconds':.01}
        replies.append(Message(content=RecordDict({'arrays':ArrayRecord(numpy_ndarrays=updated),
            'metrics':MetricRecord(metrics),'metadata':ConfigRecord(meta)}),reply_to=request))
    return replies


def evaluate_replies(strategy,round_id,arrays):
    requests=strategy.configure_evaluate(round_id,arrays,ConfigRecord(),PeerSet(strategy.peers))
    replies=[]
    for i,request in enumerate(requests):
        counts=((4,1,1,4),(9,1,1,9),(9,6,6,9))[i]
        tn,fp,fn,tp=counts;peer=request.metadata.dst_node_id
        metrics={**server_app.counts_metrics(*counts),'num-examples':sum(counts),
            'tn':tn,'fp':fp,'fn':fn,'tp':tp,'loss':.5,'evaluate-seconds':.01,
            'attack_no_return-total':fn+tp,'attack_no_return-detected':tp,
            'attack_has_return-total':0,'attack_has_return-detected':0}
        meta=dict(strategy.peers[peer],**{'server-round':round_id,
            'received-parameters-sha256':parameter_sha256(server_app.parameters(arrays))})
        replies.append(Message(content=RecordDict({'metrics':MetricRecord(metrics),
            'metadata':ConfigRecord(meta)}),reply_to=request))
    return replies


def must_reject(action,name,rejected):
    try:action()
    except (ValueError,KeyError):rejected.append(name)
    else:raise AssertionError('Invalid case accepted: '+name)


class LocalGrid:
    """Implements Grid push/pull, dispatching to ClientApp without networking."""
    def __init__(self,roots,role,fail_round2=False):
        self.roots,self.role,self.fail_round2=roots,role,fail_round2
        self.queued={};self.serial=0
    def get_node_ids(self):return list(self.roots)
    def push_messages(self,messages):
        identifiers=[]
        for message in messages:
            self.serial+=1;identifier='fixture-'+str(self.serial)
            # Emulate the runtime-assigned immutable ID in this pinned fixture.
            message.metadata._message_id=identifier
            assert message.metadata.message_id==identifier
            identifiers.append(identifier)
            node,root=self.roots[message.metadata.dst_node_id]
            if self.fail_round2 and node=='C' and message.metadata.message_type=='train' and message.content['config']['server-round']==2:
                reply=Message(error=Error(999,'Synthetic C failure'),reply_to=message)
            else:
                old=self.role['current'];self.role['current']='client'
                try:reply=client_app.app(message,context(root,node))
                finally:self.role['current']=old
            self.queued[identifier]=reply
        return identifiers
    def pull_messages(self,message_ids):
        return [self.queued.pop(identifier) for identifier in message_ids if identifier in self.queued]
    def send_and_receive(self,messages,*,timeout=None):
        return self.pull_messages(self.push_messages(messages))


def main():
    # Keep synthetic scores out of the normal checklist output; real server logs
    # remain enabled when run outside this fixture.
    logging.getLogger('flwr').setLevel(logging.ERROR)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,default=ROOT/'config/fl/fedavg.json')
    args=parser.parse_args();config=json.loads(args.config.read_text(encoding='utf-8-sig'))
    config_hash=digest(args.config)
    # A real Flower runtime sets this identity. Only this offline checker sets a
    # synthetic identity so production Message construction can be exercised.
    TaskIdentity.run_id=0;TaskIdentity.node_id=1;TaskIdentity.task_id=1
    peers=properties(config,config_hash)
    initial=initial_parameters(config);rejected=[]
    strategy=server_app.StrictFedAvg(config,config_hash,peers)
    replies=train_replies(strategy,1,initial)
    arrays,_=strategy.aggregate_train(1,replies)
    actual=server_app.parameters(arrays)
    expected=(2*1+3*3+5*9)/10
    aggregation_error=max(float(np.max(np.abs(value-expected))) for value in actual)
    assert aggregation_error<=1e-12 and expected==5.6
    summary=strategy.aggregate_evaluate(1,evaluate_replies(strategy,1,arrays))
    assert abs(summary['balanced-accuracy-macro-node']-(.8+.9+.6)/3)<=1e-12
    assert (summary['tn'],summary['fp'],summary['fn'],summary['tp'])==(22,8,8,22)
    assert abs(summary['pooled-balanced-accuracy']-22/30)<=1e-12
    arrays2,_=strategy.aggregate_train(2,train_replies(strategy,2,actual,offset=1))
    strategy.aggregate_evaluate(2,evaluate_replies(strategy,2,arrays2))
    assert strategy.best_round==1 and parameter_sha256(strategy.best_parameters)==parameter_sha256(actual)

    def mutate_train(name,replies):
        if name=='missing_client':return replies[:2]
        if name=='duplicate_client':return [replies[0],replies[0],replies[2]]
        first=replies[0]
        if name=='failed_client':
            request=Message(content=RecordDict(),dst_node_id=102,message_type='train')
            replies[2]=Message(error=Error(999,'fixture'),reply_to=request)
        elif name=='wrong_node':first.content['metadata']['node-id']='B'
        elif name=='wrong_round':first.content['metadata']['server-round']=2
        elif name=='wrong_received_hash':first.content['metadata']['received-parameters-sha256']='0'*64
        elif name=='wrong_update_hash':first.content['metadata']['updated-parameters-sha256']='0'*64
        elif name=='wrong_sample_count':first.content['metrics']['num-examples']=99
        elif name=='nonfinite_loss':first.content['metrics']['train-loss']=float('nan')
        elif name in ('nan_weights','wrong_shape'):
            values=server_app.parameters(first.content['arrays'])
            if name=='nan_weights':values[0][0,0]=np.nan
            else:values[0]=values[0][:1]
            first.content['arrays']=ArrayRecord(numpy_ndarrays=values)
        return replies
    for name in ('missing_client','duplicate_client','failed_client','wrong_node','wrong_round',
                 'wrong_received_hash','wrong_update_hash','wrong_sample_count','nonfinite_loss','nan_weights','wrong_shape'):
        candidate=server_app.StrictFedAvg(config,config_hash,peers)
        bad=mutate_train(name,train_replies(candidate,1,initial))
        must_reject(lambda:candidate.aggregate_train(1,bad),name,rejected)
        assert not candidate.history and candidate.best_parameters is None
    for name in ('missing_validation','wrong_confusion_total','wrong_validation_ratio','stale_validation_hash','wrong_subgroup'):
        candidate=server_app.StrictFedAvg(config,config_hash,peers)
        global_arrays,_=candidate.aggregate_train(1,train_replies(candidate,1,initial))
        bad=evaluate_replies(candidate,1,global_arrays)
        if name=='missing_validation':bad=bad[:2]
        elif name=='wrong_confusion_total':bad[0].content['metrics']['tp']+=1
        elif name=='wrong_validation_ratio':bad[0].content['metrics']['balanced-accuracy']=.123
        elif name=='stale_validation_hash':bad[0].content['metadata']['received-parameters-sha256']='0'*64
        else:bad[0].content['metrics']['attack_no_return-total']+=1
        must_reject(lambda:candidate.aggregate_evaluate(1,bad),name,rejected)
        assert not candidate.history and candidate.best_parameters is None
    bad_peers=copy.deepcopy(peers);bad_peers[101]=copy.deepcopy(peers[100])
    must_reject(lambda:server_app.StrictFedAvg(config,config_hash,bad_peers),'duplicate_logical_identity',rejected)
    incomplete=server_app.StrictFedAvg(config,config_hash,peers)
    with tempfile.TemporaryDirectory(prefix='fl-server-fixture-') as temp:
        base=Path(temp);server_root=base/'server';server_root.mkdir()
        must_reject(lambda:server_app.publish_global(server_root,config,config_hash,incomplete,1),'publish_incomplete',rejected)
        roots={};combined=copy.deepcopy(config)
        for i,node in enumerate(('A','B','C')):
            root=base/node;local_cfg,_,manifest_path,_=fixture(root,node,config)
            combined['clients'][node]['manifest_sha256']=digest(manifest_path)
            roots[100+i]=(node,root)
        def write_config(value):
            for root in [server_root,*[root for _,root in roots.values()]]:
                path=root/'config/fl/fedavg.json';path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text(json.dumps(value),encoding='utf-8')
        write_config(combined)
        role={'current':'server'};real_open=Path.open
        def guard(path,*args,**kwargs):
            path=Path(path)
            if role['current']=='server' and ('node-a' in path.parts or 'node-b' in path.parts or 'node-c' in path.parts):
                raise AssertionError('Server attempted node data/baseline access')
            return real_open(path,*args,**kwargs)
        ctx=Context(run_id=0,node_id=1,node_config={},state=RecordDict(),
                    run_config={'project-root':str(server_root),'num-rounds':2,'timeout-seconds':5})
        with patch.object(Path,'open',guard):
            server_app.app(LocalGrid(roots,role),ctx)
        checkpoint=server_root/'models/fl/current'
        assert set(p.name for p in checkpoint.iterdir())=={'model.json','weights.npz','metrics.json'}
        state=json.loads((server_root/'reports/fl/training.json').read_text())
        model=json.loads((checkpoint/'model.json').read_text())
        assert state['status']=='complete' and state['completed_rounds']==2
        best=max(state['history'],key=lambda h:h['validation_summary']['balanced-accuracy-macro-node'])
        assert model['selected_round']==best['round']
        # The same runtime used by live inference must accept the exported bundle.
        _,weights,threshold,model_hash=load_model(checkpoint)
        assert threshold==.5 and model_hash==model['weights_sha256']
        assert parameter_sha256([weights[name] for name in PARAMETER_NAMES])==best['global_parameters_sha256']
        assert all(entry['round_seconds']>=0 for entry in state['history'])
        saved={p.name:digest(p) for p in checkpoint.iterdir()}
        try:
            with patch.object(Path,'open',guard):server_app.app(LocalGrid(roots,role,fail_round2=True),ctx)
        except ValueError:pass
        else:raise AssertionError('Failed client did not abort run')
        assert saved=={p.name:digest(p) for p in checkpoint.iterdir()}
        assert json.loads((server_root/'reports/fl/training.json').read_text())['status']=='failed'
        combined['training']['seed']+=1
        write_config(combined)
        with patch.object(Path,'open',guard):server_app.app(LocalGrid(roots,role),ctx)
        assert digest(checkpoint/'weights.npz')!=saved['weights.npz']
        assert sorted(p.name for p in checkpoint.parent.iterdir())==['current']
    print(json.dumps({'result':'PASS FL ServerApp','scope':'Synthetic clients, local Grid dispatch and /tmp checkpoints only; no real dataset/model mounts or FL networking',
        'weighted_fedavg_matches_reference':True,'weighted_fedavg_max_abs_error':aggregation_error,
        'strict_three_clients_verified':True,'validation_macro_node_and_pooled_counts_verified':True,
        'earliest_round_wins_ties':True,'two_round_clientapp_serverapp_integration':True,
        'server_reads_no_node_dataset':True,'portable_global_model_loads':True,
        'failed_run_preserves_previous_global_model':True,'successful_run_replaces_fixed_current':True,
        'rejected_case_count':len(rejected),'rejected_cases':rejected,
        'real_node_training_performed':False,'federation_started':False}),flush=True)


if __name__=='__main__':main()
