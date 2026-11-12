"""Four synthetic rows, stdlib NPZ writer and fake worker. Never reads real datasets."""
import csv
import hashlib
import http.client
import importlib.util
import json
import math
import struct
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dataset_eval import evaluate, freeze_node, predictions_page, sha
from controller import Controller, LabError
from app import Server, make_handler
from evaluate_fl_test import counts_metrics
from flow_features import FEATURES


def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2),encoding='utf-8')


def npy(shape,dtype,values):
    header=repr({'descr':dtype,'fortran_order':False,'shape':shape})
    header=(header+' '*((64-(10+len(header)+1)%64)%64)+'\n').encode()
    body=struct.pack('<'+('q' if dtype=='<i8' else 'd')*len(values),*values)
    return b'\x93NUMPY\x01\x00'+struct.pack('<H',len(header))+header+body


def weights(path,bias):
    path.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(path,'w') as archive:
        archive.writestr('layers.npy',npy((),'<i8',[3]))
        for i,(left,right) in enumerate(((13,32),(32,16),(16,1))):
            archive.writestr('coef_%d.npy'%i,npy((left,right),'<f8',[0.]*(left*right)))
            archive.writestr('intercept_%d.npy'%i,npy((right,),'<f8',[bias if i==2 else 0.]*right))


class Synthetic:
    def __init__(self,root,node='a'):
        self.root,self.node=Path(root),node
        own='data/node-'+node+'/work/splits/pilot-v1/'
        self.own=own
        path=self.root/own/'test.csv'
        path.parent.mkdir(parents=True)
        with path.open('w',newline='',encoding='utf-8') as stream:
            writer=csv.writer(stream)
            writer.writerow(['schema_version','row_uid',*FEATURES,'label'])
            for index,label in enumerate(('benign','benign','attack','attack')):
                writer.writerow(['flow-v2',hashlib.sha256(str(index).encode()).hexdigest(),17,.01,1,1,100,100,100,1,0,label])
        artifact={'path':own+'test.csv','sha256':sha(path),'rows':4,'label_counts':{'benign':2,'attack':2}}
        manifest={'node_id':node.upper(),'schema_version':'flow-v2','features':FEATURES,
                  'checks':{'frozen':True},'artifacts':{'test':artifact}}
        save(self.root/own/'manifest.json',manifest)
        self.manifest_sha=sha(self.root/own/'manifest.json')
        contract={'schema_version':'flow-v2','features':FEATURES,'transform':'flow-v2-fixed-log-v1',
                  'input_width':13,'hidden_layer_sizes':[32,16],'output_width':1,
                  'activation':'relu','output_activation':'sigmoid','threshold':.5,'dtype':'float64',
                  'labels':{'benign':0,'attack':1}}
        local='models/node-'+node+'/current'
        self.local=local
        for relative,bias,name in ((local,-1.,'synthetic-local'),('models/fl/current',0.,'synthetic-global')):
            folder=self.root/relative
            weights(folder/'weights.npz',bias)
            meta={**contract,'weights_sha256':sha(folder/'weights.npz'),
                  'config':{'experiment_id':name},'selected_round':1}
            save(folder/'model.json',meta)
        self.config={'framework':'flower','algorithm':'FedAvg','model':contract,
                     'global_model_output':'models/fl/current','clients':{
                         node.upper():{'manifest_path':own+'manifest.json','manifest_sha256':self.manifest_sha,
                                       'baseline_model_dir':local,'baseline_weights_sha256':sha(self.root/local/'weights.npz')},
                         'Z':{'manifest_path':'data/node-z/DO_NOT_READ'}}}
        save(self.root/'config/fl/fedavg.json',self.config)
        history=[{'round':1,'validation_summary':{'balanced-accuracy-macro-node':.5}},
                 {'round':2,'validation_summary':{'balanced-accuracy-macro-node':.5}}]
        glob={'history':history,'selected_round':1,'config_sha256':sha(self.root/'config/fl/fedavg.json'),
              'test_evaluated':False,'artifacts':{}}
        save(self.root/'models/fl/current/metrics.json',glob)
        save(self.root/local/'metrics.json',{'manifest_sha256':self.manifest_sha,'artifacts':{}})
        save(self.root/'reports/fl/training.json',{**glob,'status':'complete','rounds_requested':2,
                'completed_rounds':2,'weights_sha256':sha(self.root/'models/fl/current/weights.npz')})
        save(self.root/'reports/fl/last-submission.json',{'requested-rounds':2,'run-id':'synthetic-run'})

    def worker(self,args,mutate=None):
        assert args[:2]==['docker','run']
        assert args[args.index('--network')+1]=='none'
        mounts=[args[index+1] for index,value in enumerate(args[:-1]) if value=='--mount']
        for forbidden in ('train.csv','validation.csv','node-z','docker.sock'):
            assert not any(forbidden in mount for mount in mounts),forbidden
        outputs=[mount for mount in mounts if 'target=/output' in mount]
        assert len(outputs)==1
        assert all(mount.endswith(',readonly') or 'target=/output' in mount for mount in mounts)
        folder=Path(outputs[0].split('source=',1)[1].split(',target=',1)[0])
        plan=json.loads((folder.parent/'plan.json').read_text())
        spec=plan['nodes'][self.node.upper()]
        with (self.root/self.own/'test.csv').open(encoding='utf-8') as stream:
            rows=list(csv.DictReader(stream))
        with (folder/'predictions.csv').open('w',encoding='utf-8',newline='') as stream:
            writer=csv.writer(stream)
            writer.writerow(['test_row_index','row_uid','true_label','global_probability_attack','global_predicted_label','local_probability_attack','local_predicted_label'])
            for index,row in enumerate(rows):
                writer.writerow([index,('wrong-uid' if mutate=='identity' and index==0 else row['row_uid']),
                                 int(row['label']=='attack'),.5,1,1/(1+math.exp(1)),0])
        reports={}
        for model,counts in (('global',[0,2,0,2]),('local',[2,0,2,0])):
            frozen=plan['global'] if model=='global' else spec['local']
            reports[model]={**counts_metrics(counts),'weights_sha256':frozen['weights_sha256'],
                            'threshold':.5,'scoring_seconds':.01,'loss':.7}
        if mutate=='metric':reports['local']['recall_attack']=1.
        report={'node':self.node.upper(),'partition':'test','rows':4,'label_counts':{'benign':2,'attack':2},
                'selected_round':1,'run_id':'synthetic-run','test_csv_sha256':spec['test']['sha256'],
                'manifest_sha256':spec['manifest_sha256'],'models':reports,
                'artifacts':{'predictions.csv':sha(folder/'predictions.csv')},'checks':{'synthetic_no_fit':True}}
        save(folder/'metrics.json',report)
        if mutate=='weights':
            with (self.root/'models/fl/current/weights.npz').open('ab') as stream:stream.write(b'changed')


class DatasetTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root=Path(self.temp.name)
        self.fixture=Synthetic(self.root)
        self.folder=self.root/'reports/dashboard/sessions/synthetic/job'
        self.folder.mkdir(parents=True)

    def tearDown(self):self.temp.cleanup()

    def test_only_selected_node_test_and_two_models_mounted(self):
        opened=[]
        original=Path.open
        def guarded(path,*args,**kwargs):
            text=str(path)
            if 'train.csv' in text or 'validation.csv' in text or 'node-z' in text:
                raise AssertionError('Unexpected input read: '+text)
            opened.append(text)
            return original(path,*args,**kwargs)
        with patch.object(Path,'open',guarded):
            summary=evaluate(self.root,'a',self.folder,self.fixture.worker)
        self.assertEqual(set(summary['nodes']),{'A'})
        self.assertEqual(summary['nodes']['A']['rows'],4)
        self.assertEqual(summary['nodes']['A']['models']['global']['confusion_matrix'],[[0,2],[0,2]])
        self.assertEqual(summary['nodes']['A']['models']['local']['confusion_matrix'],[[2,0],[2,0]])
        self.assertTrue(all(summary['checks'].values()))
        self.assertFalse((self.root/'runtime/dashboard/.dataset-evaluation-lock').exists())
        self.assertTrue((self.folder/'dataset/comparison.csv').is_file())

    def test_corrupt_hash_and_active_fl_rejected_before_worker(self):
        marker=[]
        path=self.root/self.fixture.own/'test.csv'
        path.write_text(path.read_text()+'\n')
        with self.assertRaisesRegex(ValueError,'Test hash'):
            evaluate(self.root,'a',self.folder,lambda args:marker.append(args))
        self.assertFalse(marker)
        lock=self.root/'reports/fl/.server-run-lock'
        lock.mkdir()
        with self.assertRaisesRegex(ValueError,'FL'):
            freeze_node(self.root,'a')

    def test_swapped_identity_wrong_metric_or_changed_weights_not_published(self):
        for mutation in ('identity','metric','weights'):
            with self.subTest(mutation=mutation):
                folder=self.folder.parent/mutation
                folder.mkdir()
                with self.assertRaises(ValueError):
                    evaluate(self.root,'a',folder,lambda args:self.fixture.worker(args,mutation))
                self.assertFalse((folder/'dataset/summary.json').exists())
                self.assertFalse((self.root/'runtime/dashboard/.dataset-evaluation-lock').exists())

    def test_filtering_fp_fn_and_pagination(self):
        evaluate(self.root,'a',self.folder,self.fixture.worker)
        path=self.folder/'dataset/node-a/predictions.csv'
        self.assertEqual(predictions_page(path,'global','fp')['total'],2)
        self.assertEqual(predictions_page(path,'local','fn')['total'],2)
        self.assertEqual(predictions_page(path,'local','fp')['total'],0)
        page=predictions_page(path,page=2,size=1)
        self.assertEqual(page['rows'][0]['index'],1)
        self.assertEqual(page['pages'],4)
        for args in (('other','all',1,50),('local','all',0,50),('local','all',1,101)):
            with self.assertRaises(ValueError):predictions_page(path,*args)

    def test_existing_output_and_foreign_destination_are_not_overwritten(self):
        evaluate(self.root,'a',self.folder,self.fixture.worker)
        before=(self.folder/'dataset/summary.json').read_bytes()
        with self.assertRaises(FileExistsError):evaluate(self.root,'a',self.folder,self.fixture.worker)
        self.assertEqual((self.folder/'dataset/summary.json').read_bytes(),before)
        with self.assertRaises(ValueError):evaluate(self.root,'a',self.root/'models',self.fixture.worker)

    def test_controller_queues_dataset_when_live_node_is_off_and_blocks_fl(self):
        control=Controller(self.root,start_monitor=False)
        with patch('controller.threading.Thread'):
            control.submit({'action':'dataset.test','node':'a'})
            self.assertIn('dataset',control.jobs[-1]['resources'])
            with self.assertRaises(LabError):control.submit({'action':'fl.run','rounds':5})
            with self.assertRaises(LabError):control.submit({'action':'dataset.test','node':'b'})
        control.closed.set()

    def completed_controller(self):
        control=Controller(self.root,start_monitor=False)
        folder=control.session_dir()/'dataset-fixture'
        folder.mkdir(parents=True)
        job={'id':'dataset-fixture','action':'dataset.test','node':'a','status':'queued',
             'created_at':'2026-11-13T00:00:00+00:00','folder':folder.relative_to(self.root).as_posix(),
             'request':{'action':'dataset.test','node':'a'},'resources':['node:a','dataset']}
        control.jobs.append(job)
        with patch.object(control,'_require_docker'),patch.object(control,'refresh_docker'),patch.object(control,'_exec',side_effect=self.fixture.worker):
            # Worker callback normally receives timeout/job kwargs from _exec.
            with patch.object(control,'_exec',side_effect=lambda args,**kwargs:self.fixture.worker(args)):
                control._work(job)
        self.assertEqual(job['status'],'complete',job.get('error'))
        return control,job

    def test_controller_result_hash_guard_and_fp_fn_rows(self):
        control,job=self.completed_controller()
        self.assertEqual(control.dataset_rows(job['id'],'local','fn')['total'],2)
        path,summary=control.dataset_artifact(job['id'])
        self.assertEqual(summary['node'],'A')
        with path.open('ab') as stream:stream.write(b'\n')
        with self.assertRaises(LabError):control.dataset_rows(job['id'])
        control.closed.set()

    def test_foreign_lock_not_removed(self):
        lock=self.root/'runtime/dashboard/.dataset-evaluation-lock'
        lock.mkdir(parents=True)
        with self.assertRaises(ValueError):evaluate(self.root,'a',self.folder,self.fixture.worker)
        self.assertTrue(lock.is_dir())

    def test_dataset_http_filters_export_and_bad_query(self):
        control,job=self.completed_controller()
        server=Server(('127.0.0.1',0),make_handler(control,'test',0))
        port=server.server_address[1]
        server.RequestHandlerClass=make_handler(control,'test',port)
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        def request(path):
            client=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
            try:
                client.request('GET',path)
                response=client.getresponse()
                return response.status,response.read(),dict(response.getheaders())
            finally:client.close()
        try:
            code,raw,_=request('/api/dataset/rows?job=dataset-fixture&model=global&filter=fp')
            self.assertEqual(code,200)
            self.assertEqual(json.loads(raw)['total'],2)
            code,raw,headers=request('/api/dataset/export?job=dataset-fixture&format=csv')
            self.assertEqual(code,200)
            self.assertIn(b'global_probability_attack',raw)
            self.assertIn('dataset-predictions.csv',headers['Content-Disposition'])
            self.assertEqual(request('/api/dataset/export?job=dataset-fixture&format=json')[0],200)
            self.assertEqual(request('/api/dataset/rows?job=dataset-fixture&model=invalid')[0],400)
            self.assertEqual(request('/api/dataset/rows?job=dataset-fixture&page=oops')[0],400)
            self.assertEqual(request('/api/dataset/rows?job=../../models')[0],400)
            self.assertEqual(request('/api/dataset/export?job=dataset-fixture&format=exe')[0],400)
        finally:
            server.shutdown();server.server_close();thread.join(timeout=3)
            control.closed.set()


if __name__=='__main__':unittest.main()
