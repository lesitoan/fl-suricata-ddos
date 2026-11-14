import copy
import json
import math
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
from collector import Collector,CollectorLock,EventSink,atomic_json,local_points,federated_points,identifier,remove_event_tree


def epoch(index,loss=.5):
    return {'epoch':index,'train_loss':loss,'validation':{'balanced_accuracy':.75,
            'recall_attack':.9,'false_positive_rate':.4}}


def federation(run='one',rounds=2):
    history=[]
    for index in range(1,rounds+1):
        history.append({'round':index,'round_seconds':.4,
            'train_clients':{node:{'metrics':{'train-loss':i/10,'train-seconds':.1}} for i,node in enumerate('ABC',1)},
            'validation_clients':{node:{'loss':.3,'balanced-accuracy':.8,'recall-attack':.9,
                                        'false-positive-rate':.3} for node in 'ABC'},
            'validation_summary':{'balanced-accuracy-macro-node':.8,'loss':.3},
            'communication':{'train_up_model_array_bytes':23832}})
    return {'telemetry_run_id':run,'status':'complete','history':history}


class FakeSink:
    def __init__(self):self.points=[]
    def write(self,*args):self.points.append(args)
    def close(self):pass
    def reset(self,run):pass
    def start_run(self,run):pass


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.root=Path(self.temporary.name)
        self.sink=FakeSink()
        self.collector=Collector(self.root,self.sink)
    def tearDown(self):
        self.collector.close();self.temporary.cleanup()
    def local(self,report):
        atomic_json(self.root/'models/node-a/local-only-pilot-v1/laptop-01/metrics.json',report)

    def test_historical_scalars_match_and_restart_is_idempotent_without_dataset_reads(self):
        self.local({'history':[epoch(1),epoch(2,.4)],'test':{'accuracy':.1}})
        original=Path.read_text
        def guarded(path,*args,**kwargs):
            self.assertNotIn('data',path.relative_to(self.root).parts)
            return original(path,*args,**kwargs)
        with patch.object(Path,'read_text',guarded):
            status=self.collector.sync()
        self.assertFalse(status['errors'])
        self.assertEqual(len(self.sink.points),2)
        self.assertEqual(self.sink.points[0][2]['train/loss'],.5)
        self.assertNotIn('test/accuracy',self.sink.points[0][2])
        self.collector.sync()
        resumed=Collector(self.root,self.sink);resumed.sync();resumed.close()
        self.assertEqual(len(self.sink.points),2)

    def test_live_epoch_append_and_published_model_are_one_run(self):
        run='a'*32
        telemetry={'schema_version':'local-training-v1','node':'A','run_id':run,'history':[epoch(1)]}
        path=self.root/f'reports/node-a/training/{run}.json'
        atomic_json(path,telemetry);self.collector.sync()
        telemetry['history'].append(epoch(2,.3));atomic_json(path,telemetry);self.collector.sync()
        self.local({'telemetry_run_id':run,'history':telemetry['history']});self.collector.sync()
        self.assertEqual(len(self.sink.points),2)
        self.assertEqual(len(self.collector.state['runs']),1)
        telemetry['history'][0]['train_loss']=.9;atomic_json(path,telemetry)
        self.assertTrue(self.collector.sync()['errors'])
        self.assertEqual(len(self.sink.points),2)

    def test_fl_node_train_and_global_validation_separate_server_and_round_reset(self):
        atomic_json(self.root/'reports/fl/training.json',federation())
        self.assertFalse(self.collector.sync()['errors'])
        self.assertEqual(len(self.sink.points),8)
        node_a=next(item for item in self.sink.points if item[0].endswith('node-a'))
        self.assertEqual(node_a[2]['train/loss'],.1)
        self.assertEqual(node_a[2]['validation/loss'],.3)
        self.assertIn('aggregated Global',node_a[3])
        atomic_json(self.root/'reports/fl/training.json',federation('two',1));self.collector.sync()
        self.assertEqual(len(self.collector.state['runs']),4)
        self.assertTrue(all(len(run['points'])==1 for run in self.collector.state['runs'].values()))
        self.assertEqual(len(self.sink.points),12)

    def test_latest_local_run_selected_and_old_telemetry_never_reimported(self):
        self.local({'created_at_utc':'2026-01-01T00:00:00+00:00','history':[epoch(1)]})
        def live(run,started,loss):
            path=self.root/f'reports/node-a/training/{run}.json'
            atomic_json(path,{'schema_version':'local-training-v1','node':'A','run_id':run,
                             'started_at_utc':started,'history':[epoch(1,loss)]})
            return path
        old=live('a'*32,'2026-02-01T00:00:00+00:00',.7)
        live('b'*32,'2026-03-01T00:00:00+00:00',.3)
        self.assertFalse(self.collector.sync()['errors'])
        self.assertEqual(len(self.collector.state['runs']),1)
        current=self.collector.state['runs']['local/node-a']
        self.assertEqual(current['metadata']['run_id'],'b'*32)
        self.assertEqual(current['points']['1']['train/loss'],.3)
        # Touch an older file later; the original run start still controls selection.
        old.write_text(old.read_text());self.collector.sync()
        self.assertEqual(self.collector.state['runs']['local/node-a']['metadata']['run_id'],'b'*32)
        live('c'*32,'2026-04-01T00:00:00+00:00',.2);self.collector.sync()
        self.assertEqual(len(self.collector.state['runs']),1)
        self.assertEqual(self.collector.state['runs']['local/node-a']['points']['1']['train/loss'],.2)

    def test_legacy_runs_migrated_and_unknown_cleanup_files_preserved(self):
        old=self.root/'reports/tensorboard/federated'/('a'*16)/'node-a'
        old.mkdir(parents=True)
        (old/'events.out.tfevents.old').write_bytes(b'old fixture')
        index=self.root/'runtime/tensorboard/index.json'
        atomic_json(index,{'runs':{'legacy':{}}})
        migrated=Collector(self.root,FakeSink())
        self.assertFalse(old.exists());self.assertEqual(migrated.state['runs'],{});migrated.close()
        protected=self.root/'reports/tensorboard/local/node-a/important.txt'
        protected.parent.mkdir(parents=True,exist_ok=True);protected.write_text('keep')
        with self.assertRaises(ValueError):remove_event_tree(self.root,protected.parent)
        self.assertEqual(protected.read_text(),'keep')
        outside=self.root/'models/current';outside.mkdir(parents=True)
        with self.assertRaises(ValueError):remove_event_tree(self.root,outside)

    def test_real_cached_accumulator_purges_previous_run_when_slot_replaced(self):
        try:
            from tensorboard.backend.event_processing.event_accumulator import EventAccumulator
        except ImportError:self.skipTest('Requires TensorBoard venv')
        self.collector.close();self.collector=Collector(self.root)
        self.local({'telemetry_run_id':'first','history':[epoch(1),epoch(2),epoch(3)]})
        self.assertFalse(self.collector.sync()['errors'])
        folder=self.root/'reports/tensorboard/local/node-a'
        accumulator=EventAccumulator(str(folder));accumulator.Reload()
        self.assertEqual(len(accumulator.Scalars('train/loss')),3)
        self.local({'telemetry_run_id':'first','history':[epoch(1)]})
        self.assertTrue(self.collector.sync()['errors'])
        self.local({'telemetry_run_id':'second','history':[epoch(1,.2)]})
        self.assertFalse(self.collector.sync()['errors'])
        accumulator.Reload()
        values=accumulator.Scalars('train/loss')
        self.assertEqual([point.step for point in values],[1])
        self.assertAlmostEqual(values[0].value,.2,places=6)
        self.assertEqual(len([path for path in folder.glob('events.out.tfevents.*') if path.stat().st_size]),1)

    def test_bad_scalars_and_incomplete_history_never_write_partial_source(self):
        for value in (math.nan,math.inf,True):
            with self.assertRaises(ValueError):local_points({'history':[epoch(1,value)]})
        self.local({'history':[epoch(1),epoch(3)]})
        self.assertTrue(self.collector.sync()['errors']);self.assertEqual(self.sink.points,[])
        bad=federation();del bad['history'][1]['train_clients']['B']
        with self.assertRaises(ValueError):federated_points(bad)

    def test_os_lock_excludes_second_writer_and_releases(self):
        path=self.root/'runtime/tensorboard/collector.lock'
        with CollectorLock(path):
            with self.assertRaises(RuntimeError):
                with CollectorLock(path):pass
        with CollectorLock(path):pass

    def test_real_tensorboard_events_roundtrip_values_and_steps(self):
        try:
            from tensorboard.backend.event_processing.event_accumulator import EventAccumulator
        except ImportError:self.skipTest('Run with runtime/tensorboard/venv to test event serialization')
        sink=EventSink(self.root/'events')
        sink.write('local/node-a/test',1,{'train/loss':.4},'Synthetic test')
        sink.write('local/node-a/test',2,{'train/loss':.2},'Synthetic test');sink.close()
        accumulator=EventAccumulator(str(self.root/'events/local/node-a/test'));accumulator.Reload()
        points=accumulator.Scalars('train/loss')
        self.assertEqual([point.step for point in points],[1,2])
        self.assertAlmostEqual(points[1].value,.2,places=6)


if __name__=='__main__':unittest.main()
