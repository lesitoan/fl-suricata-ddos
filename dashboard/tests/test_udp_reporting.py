import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from controller import (Controller, LabError, capture_snapshot, matches_sender,
                        signature, udp_load_metrics, write_json)
from test_dashboard import Fixture


def inputs(root):
    sender = {'schema_version':'udp-load-v1','scenario':'bounded_udp_load','node':'B',
              'scope':'Controlled direct UDP load', 'source_ip':'172.19.0.3',
              'source_ports':list(range(44000,44005)), 'destination_ip':'172.19.0.2',
              'destination_port':9000, 'start_utc':'2026-11-12T01:00:00+00:00',
              'end_utc':'2026-11-12T01:00:05+00:00', 'packets_sent':500,
              'valid_echoes':498, 'echoes_missing_after_observation':2,
              'observed_send_pps':99.8, 'planned_flows':5, 'sending_wall_seconds':5.,
              'health_checks':{phase:{'planned_requests':5,'successful':5,'timeouts':0,
                                     'median_rtt_ms':1.,'p95_rtt_ms':1.2,'records':[{'example':True}]}
                               for phase in ('before','during','after')},
              'per_flow':[{'source_port':port,'packets_sent':100,'valid_echoes':100}
                          for port in range(44000,44005)]}
    flows = [{'event_type':'flow','flow_id':port,'proto':'UDP','src_ip':'172.19.0.3',
              'src_port':port,'dest_ip':'172.19.0.2','dest_port':9000,
              'flow':{'start':sender['start_utc'],'end':sender['end_utc'],
                      'pkts_toserver':100,'pkts_toclient':100,'bytes_toserver':10600,'bytes_toclient':10600}}
             for port in range(44000,44005)]
    meta = json.loads((root/'models/node-b/current/model.json').read_text())
    predictions = [{'flow_id':str(event['flow_id']), 'event_signature_sha256':signature(event),
                    'model_id':meta['config']['experiment_id'], 'weights_sha256':meta['weights_sha256'],
                    'threshold':.5,'probability_attack':.2,'prediction':'benign','mode':'live',
                    'seconds_from_flow_end_to_score':35.} for event in flows]
    return sender, flows, predictions, meta


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp.name)
        Fixture(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_new_rate_and_count_are_saved_for_comparable_workloads(self):
        sender,flows,_,_=inputs(self.root)
        sender.update(planned_packets=1000,packets_sent=1000,rate_limit_pps=500,
                      target_sending_seconds=2,missed_send_slots=0)
        for item in sender['per_flow']:
            item['packets_sent']=200
        for event in flows:
            event['flow']['pkts_toserver']=200
        result=udp_load_metrics(sender,flows,None,None)
        self.assertEqual(result['planned_packets'],1000)
        self.assertEqual(result['rate_limit_pps'],500)
        self.assertEqual(result['target_sending_seconds'],2)
        self.assertEqual(result['missed_send_slots'],0)
        self.assertTrue(result['sent_packet_count_matches_capture'])

    def test_five_load_ports_exclude_benign_monitoring_and_count_exact_packets(self):
        sender, flows, _, _ = inputs(self.root)
        health = copy.deepcopy(flows[0])
        health['src_port'] = 45000
        self.assertFalse(matches_sender(health,sender))
        self.assertTrue(all(matches_sender(event,sender) for event in flows))
        before = {'timestamp':'before','uptime':10,'kernel_drops':3,'kernel_packets':100,
                  'capture_errors':0,'decoder_invalid':0}
        after = {'timestamp':'after','uptime':30,'kernel_drops':5,'kernel_packets':1130,
                 'capture_errors':0,'decoder_invalid':1}
        result = udp_load_metrics(sender, flows, before, after)
        self.assertTrue(result['sent_packet_count_matches_capture'])
        self.assertEqual(result['capture_observation']['delta']['kernel_drops'],2)
        self.assertEqual(result['capture_observation']['delta']['kernel_packets'],1030)
        self.assertNotIn('records',result['health_checks']['during'])
        flows[0]['flow']['pkts_toserver'] = 99
        self.assertFalse(udp_load_metrics(sender,flows,before,after)['sent_packet_count_matches_capture'])
        for first,last in ((None,after),(after,before),(before,before)):
            result = udp_load_metrics(sender,flows,first,last)
            self.assertIsNone(result['capture_observation']['delta']['kernel_drops'])

    def test_capture_snapshot_ignores_partial_stats_and_nonstats(self):
        path = self.root/'capture.jsonl'
        path.write_text(json.dumps({'event_type':'stats','timestamp':'old','stats':{
            'uptime':10,'capture':{'kernel_packets':100,'kernel_drops':0,'errors':0},
            'decoder':{'invalid':0}}})+'\n'+json.dumps({'event_type':'flow'})+'\n{"event_type":', encoding='utf-8')
        result=capture_snapshot(path)
        self.assertEqual(result['kernel_packets'],100)
        self.assertEqual(result['kernel_drops'],0)
        self.assertIsNone(capture_snapshot(self.root/'missing.jsonl'))

    def test_dashboard_keeps_benign_predictions_and_rejects_partial_capture(self):
        for incomplete in (False,True):
            with self.subTest(incomplete=incomplete):
                controller=Controller(self.root,start_monitor=False,runner=lambda *args,**kwargs:None)
                sender,flows,predictions,meta=inputs(self.root)
                if incomplete:
                    flows[0]['flow']['pkts_toserver']=99
                    predictions[0]['event_signature_sha256']=signature(flows[0])
                identifier='partial' if incomplete else 'complete'
                folder=f'reports/dashboard/sessions/{controller.session}/{identifier}'
                target=self.root/folder
                target.mkdir(parents=True)
                job={'id':identifier,'action':'traffic','node':'b','status':'running','folder':folder,
                     'request':{'action':'traffic','node':'b','scenario':'attack'},'resources':['node:b']}
                def sent(*args,**kwargs):
                    write_json(target/'sender.json',sender)
                    for path,records in [(self.root/'data/node-b/live/eve/eve.json',flows),
                                         (self.root/'data/node-b/live/predictions/predictions.jsonl',predictions)]:
                        with path.open('a',encoding='utf-8') as stream:
                            for record in records:
                                stream.write(json.dumps(record)+'\n')
                    return '{}'
                state={'mode':'local','loaded_hash':meta['weights_sha256'],
                       'loaded_id':meta['config']['experiment_id'],'model':{'threshold':.5}}
                with patch.object(controller,'_ready',return_value=state), patch.object(controller,'_exec',side_effect=sent):
                    with patch('controller.time.monotonic',side_effect=iter(range(0,1000))), patch.object(controller.closed,'wait',return_value=False):
                        if incomplete:
                            with self.assertRaises(LabError): controller._traffic(job,'b','attack')
                        else:
                            controller._traffic(job,'b','attack')
                self.assertEqual(job['report']['matched_predictions'],5)
                self.assertEqual(job['report']['predicted_benign'],5)
                self.assertEqual(job['report']['predicted_attack'],0)
                self.assertEqual(job['report']['traffic_profile'],'bounded_udp_load')
                self.assertEqual(job['report']['udp_load']['sent_packet_count_matches_capture'],not incomplete)
                controller.closed.set()

    def test_standalone_verifier_supports_new_and_legacy_reports(self):
        source=Path(__file__).resolve().parents[2]/'scripts/node-b/verify_udp_probe.py'
        spec=importlib.util.spec_from_file_location('verify_udp_load',source)
        verifier=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        for legacy in (False,True):
            sender,flows,predictions,_=inputs(self.root)
            if legacy:
                sender.pop('source_ports')
                sender.pop('per_flow')
                sender.update(source_port=44000,packets_sent=100,valid_echoes=100,scenario='bounded_udp_burst')
                flows,predictions=flows[:1],predictions[:1]
            folder=self.root/('reports/node-b/legacy' if legacy else 'reports/node-b/load')
            folder.mkdir(parents=True)
            write_json(folder/'sender.json',sender)
            for path,items in [(self.root/'data/node-b/live/eve/eve.json',flows),
                               (self.root/'data/node-b/live/predictions/predictions.jsonl',predictions)]:
                path.write_text(''.join(json.dumps(item)+'\n' for item in items),encoding='utf-8')
            report=verifier.verify(self.root,folder,1)
            self.assertEqual(report['result'],'MATCHED')
            self.assertEqual(report['matched_predictions'],1 if legacy else 5)
            self.assertEqual(report['predicted_attack'],0)
            self.assertTrue(report['sent_packet_count_matches_capture'])

    def test_standalone_global_verifier_reads_global_prediction_directory(self):
        source=Path(__file__).resolve().parents[2]/'scripts/node-b/verify_udp_probe.py'
        spec=importlib.util.spec_from_file_location('verify_udp_global',source)
        verifier=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        sender,flows,predictions,_=inputs(self.root)
        meta=json.loads((self.root/'models/fl/current/model.json').read_text())
        for record in predictions:
            record.update(weights_sha256=meta['weights_sha256'],model_id=meta['config']['experiment_id'])
        folder=self.root/'reports/node-b/global'
        folder.mkdir(parents=True)
        write_json(folder/'sender.json',sender)
        for path,items in [(self.root/'data/node-b/live/eve/eve.json',flows),
                           (self.root/'data/node-b/live/predictions-global/predictions.jsonl',predictions)]:
            path.write_text(''.join(json.dumps(item)+'\n' for item in items),encoding='utf-8')
        result=verifier.verify(self.root,folder,1,'global')
        self.assertEqual(result['mode'],'global')
        self.assertEqual(result['weights_sha256'],meta['weights_sha256'])
        self.assertEqual(result['matched_predictions'],5)


if __name__ == '__main__':
    unittest.main()
