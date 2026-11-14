"""No Docker or lab traffic: command runner, senders and EVE are fixtures."""
import hashlib
import http.client
import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from controller import (BASELINES, Controller, LabError, matches_sender,
                        new_records, signature, write_json)
from app import Server, make_handler


class Fixture:
    def __init__(self, root):
        self.root, self.calls, self.mode, self.running = root, [], 'local', True
        for node in 'abc':
            for path in ('eve', 'predictions', 'predictions-global'):
                (root/f'data/node-{node}/live/{path}').mkdir(parents=True)
        for path in list(BASELINES.values())+['models/fl/current']:
            folder = root/path
            folder.mkdir(parents=True)
            weights = ('test weights '+path).encode()
            (folder/'weights.npz').write_bytes(weights)
            write_json(folder/'model.json', {'config': {'experiment_id': path},
                        'weights_sha256': hashlib.sha256(weights).hexdigest(),
                        'threshold': .5, 'selected_round': 4})

    def metadata(self):
        return json.loads((self.root/('models/fl/current' if self.mode == 'global'
                                      else BASELINES['c'])/'model.json').read_text())

    def event(self, port=45001):
        return {'event_type': 'flow', 'flow_id': 123, 'src_ip': '172.20.0.3',
                'src_port': port, 'dest_ip': '172.20.0.2', 'dest_port': 389, 'proto': 'UDP',
                'flow': {'start': '2026-11-12T01:00:00+00:00',
                         'end': '2026-11-12T01:00:05+00:00', 'pkts_toserver': 100,
                         'pkts_toclient': 100, 'bytes_toserver': 11900, 'bytes_toclient': 13300}}

    def sender(self):
        return {'source_ip': '172.20.0.3', 'source_port': 45001,
                'destination_ip': '172.20.0.2', 'destination_port': 389,
                'start_utc': '2026-11-12T01:00:00+00:00',
                'end_utc': '2026-11-12T01:00:05+00:00', 'packets_sent': 100,
                'valid_responses': 100}

    def __call__(self, args, timeout=45):
        self.calls.append(list(args))
        result = ''
        meta = self.metadata()
        if args[1:3] == ['ps', '-aq']:
            result = 'fake-container'
        elif args[1] == 'inspect':
            items = []
            for service in ('ldap-c', 'sensor-c', 'inference-c'):
                items.append({'Id': 'fake-'+service, 'Config': {'Labels': {
                    'com.docker.compose.project': 'ddos-fl-laptop',
                    'com.docker.compose.service': service}},
                    'State': {'Running': self.running, 'Status': 'running' if self.running else 'exited',
                              'Health': {'Status': 'healthy'}},
                    'Mounts': [{'Destination': '/model', 'Source': str(self.root/(
                        'models/fl/current' if self.mode == 'global' else BASELINES['c']))}]
                              if service == 'inference-c' else []})
            result = json.dumps(items)
        elif args[1] == 'logs':
            result = json.dumps({'status': 'ready', 'weights_sha256': meta['weights_sha256'],
                                 'model_id': meta['config']['experiment_id']})
        elif args[1] == 'compose':
            if 'stop' in args:
                self.running = False
            if '--force-recreate' in args or 'up' in args:
                self.running = True
                self.mode = 'global' if 'compose.node-c-global.yaml' in args else 'local'
        elif args[1] == 'run':
            # Fake sender writes actual fixture JSONL, never opens a socket.
            mounts = [args[index+1] for index, value in enumerate(args[:-1]) if value == '--mount']
            report_mount = next(mount for mount in mounts if 'target=/report' in mount)
            folder = Path(report_mount.split('source=', 1)[1].split(',target=', 1)[0])
            write_json(folder/'sender.json', self.sender())
            event = self.event()
            with (self.root/'data/node-c/live/eve/eve.json').open('a') as stream:
                stream.write(json.dumps(event)+'\n')
                wrong = self.event(45002)
                stream.write(json.dumps(wrong)+'\n')
            prediction = {'flow_id': '123', 'event_signature_sha256': signature(event),
                          'weights_sha256': meta['weights_sha256'], 'mode': 'live',
                          'model_id': meta['config']['experiment_id'], 'threshold': .5,
                          'probability_attack': .12, 'prediction': 'benign',
                          'seconds_from_flow_end_to_score': 34.5}
            kind = 'predictions-global' if self.mode == 'global' else 'predictions'
            with (self.root/f'data/node-c/live/{kind}/predictions.jsonl').open('a') as stream:
                stream.write(json.dumps(prediction)+'\n')
                wrong = dict(prediction, weights_sha256='wrong hash')
                stream.write(json.dumps(wrong)+'\n')
            result = json.dumps(self.sender())
        return subprocess.CompletedProcess(args, 0, result, '')


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.root = Path(self.temp.name)
        self.fixture = Fixture(self.root)
        self.controller = Controller(self.root, runner=self.fixture, start_monitor=False)
        self.controller.refresh_docker()

    def tearDown(self):
        self.controller.closed.set()
        self.temp.cleanup()

    def job(self, action, **values):
        folder = 'reports/dashboard/sessions/'+self.controller.session+'/fixture'
        (self.root/folder).mkdir(parents=True, exist_ok=True)
        return {'id': 'fixture', 'action': action, 'node': 'c', 'folder': folder,
                'status': 'running', 'created_at': '2026-11-12T01:00:00+00:00',
                'request': {'action': action, 'node': 'c', **values},
                'resources': ['node:c']}

    def test_status_uses_mount_and_current_process_hash(self):
        state = self.controller.node_state('c')
        self.assertTrue(state['ready'])
        self.assertEqual(state['mode'], 'local')
        meta_path = self.root/BASELINES['c']/'model.json'
        weights = meta_path.parent/'weights.npz'
        weights.write_bytes(b'new weights')
        meta = json.loads(meta_path.read_text())
        meta['weights_sha256'] = hashlib.sha256(b'new weights').hexdigest()
        write_json(meta_path, meta)
        self.assertTrue(self.controller.node_state('c')['stale'])
        self.assertFalse(self.controller.node_state('c')['ready'])

    def test_unknown_mount_never_enables_traffic(self):
        self.controller.docker['services']['inference-c']['mode'] = None
        self.assertFalse(self.controller.node_state('c')['ready'])

    def test_job_file_replace_retries_transient_permission_error(self):
        path = self.root/'job.json'
        write_json(path, {'status': 'queued'})
        replace = Path.replace
        attempts = []

        def replace_after_reader_closes(source, target):
            attempts.append(target)
            if len(attempts) == 1:
                raise PermissionError('Reader is holding job.json open')
            return replace(source, target)

        with patch.object(Path, 'replace', replace_after_reader_closes):
            write_json(path, {'status': 'running'})

        self.assertEqual(json.loads(path.read_text()), {'status': 'running'})
        self.assertEqual(len(attempts), 2)
        self.assertFalse(list(self.root.glob('job.json.*.tmp')))

    def test_initial_job_status_write_failure_releases_active_job(self):
        job = self.job('dataset.cross_attack', source_node='a')
        self.controller.jobs.append(job)
        self.fixture.calls.clear()
        with patch('controller.write_json', side_effect=PermissionError('Unable to replace job.json')):
            self.controller._work(job)

        self.assertEqual(job['status'], 'failed')
        self.assertIn('Unable to replace', job['error'])
        self.assertFalse(self.controller.dataset_busy())
        self.assertFalse(self.fixture.calls)

    def test_mode_switch_only_recreates_own_inference(self):
        job = self.job('node.mode', mode='global')
        self.controller._work(job)
        self.assertEqual(job['status'], 'complete')
        commands = [call for call in self.fixture.calls if call[1] == 'compose']
        self.assertEqual(len(commands), 1)
        self.assertIn('compose.node-c-global.yaml', commands[0])
        self.assertEqual(commands[0][-1], 'inference-c')
        self.assertIn('--no-deps', commands[0])
        self.assertIn('--force-recreate', commands[0])
        self.assertNotIn('--remove-orphans', commands[0])

    def test_incremental_reader_preserves_partial_line(self):
        path = self.root/'partial.jsonl'
        path.write_bytes(b'{"value":1}\n{"value":')
        offset, rows = new_records(path, 0)
        self.assertEqual(rows, [{'value': 1}])
        with path.open('ab') as stream:
            stream.write(b'2}\n')
        self.assertEqual(new_records(path, offset)[1], [{'value': 2}])
        path.write_text('{"reset":true}\n')
        self.assertEqual(new_records(path, 100)[1], [{'reset': True}])

    def test_matching_excludes_foreign_port_time_and_signature_order(self):
        event, sender = self.fixture.event(), self.fixture.sender()
        self.assertTrue(matches_sender(event, sender))
        self.assertFalse(matches_sender(self.fixture.event(12345), sender))
        self.assertFalse(matches_sender(dict(event, proto='TCP'), sender))
        sender['start_utc'] = '2026-11-12T02:00:00+00:00'
        sender['end_utc'] = '2026-11-12T02:00:01+00:00'
        self.assertFalse(matches_sender(event, sender))
        # Match the exact serialization contract of scripts/flow_features.py.
        expected = ['123', '172.20.0.3', 45001, '172.20.0.2', 389, 'UDP',
                    '2026-11-12T01:00:00+00:00', '2026-11-12T01:00:05+00:00',
                    100, 100, 11900, 13300]
        self.assertEqual(signature(event), hashlib.sha256(json.dumps(
            expected, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest())

    def test_live_report_joins_only_sender_and_frozen_hash(self):
        job = self.job('traffic', scenario='attack')
        with patch('controller.time.monotonic', side_effect=iter(range(0, 1000))):
            with patch.object(self.controller.closed, 'wait', return_value=False):
                self.controller._traffic(job, 'c', 'attack')
        report = job['report']
        self.assertEqual(report['matched_predictions'], 1)
        self.assertEqual(report['matched_flows'], 1)
        self.assertEqual(report['predicted_attack'], 0)
        self.assertEqual(report['predicted_benign'], 1)
        self.assertEqual(report['ground_truth'], 'unverified_synthetic')
        self.assertEqual(report['mean_delay_seconds'], 34.5)
        self.assertNotIn('recall_attack', report)
        command = next(call for call in self.fixture.calls if call[1] == 'run')
        self.assertEqual(command[command.index('--network')+1], 'ddos-fl-laptop_site-c')
        self.assertIn('/app/node-c/ldap_probe.py', command)
        self.assertNotIn('--privileged', command)

    def test_clear_requires_stopped_writers_and_keeps_models_and_reports(self):
        log = self.root/'data/node-c/live/eve/eve.json'
        log.write_text('evidence')
        job = self.job('logs.clear')
        self.controller._work(job)
        self.assertEqual(job['status'], 'failed')
        self.assertEqual(log.read_text(), 'evidence')
        self.fixture.running = False
        self.controller._work(job)
        self.assertEqual(job['status'], 'complete')
        self.assertEqual(log.read_text(), '')
        self.assertTrue((self.root/BASELINES['c']/'weights.npz').is_file())
        self.assertTrue((self.root/job['folder']/'job.json').is_file())

    def test_invalid_requests_and_busy_locks(self):
        bad = [None, [], {'action': []}, {'action': 'shell', 'command': 'anything'},
               {'action':'node.start','node':'d','mode':'local'},
               {'action':'node.start','node':[],'mode':'local'},
               {'action':'node.start','node':'a','mode':'other'},
               {'action':'fl.run','rounds':True}, {'action':'fl.run','rounds':0},
               {'action':'fl.run','rounds':51}, {'action':'fl.run','rounds':'5'},
               {'action':'traffic','node':'c','scenario':'other'},
               {'action':'logs.clear','node':'c','path':'models'}]
        for payload in bad:
            with self.subTest(payload=payload), self.assertRaises(LabError):
                self.controller.submit(payload)
        lock = self.root/'reports/fl/.server-run-lock'
        lock.mkdir(parents=True)
        with self.assertRaises(LabError):
            self.controller.submit({'action':'fl.stop'})
        lock.rmdir()
        with patch('controller.threading.Thread'):
            self.controller.submit({'action':'node.stop','node':'c'})
            with self.assertRaises(LabError):
                self.controller.submit({'action':'traffic','node':'c','scenario':'attack'})
            with self.assertRaises(LabError):
                self.controller.submit({'action':'session.new'})
            self.controller.submit({'action':'node.stop','node':'b'})

    def test_new_session_retains_previous_files(self):
        old = self.controller.session
        path = self.controller.session_dir()/'kept.json'
        write_json(path, {'keep': True})
        self.controller.submit({'action':'session.new'})
        self.assertNotEqual(self.controller.session, old)
        self.assertTrue(path.is_file())

    def test_fl_start_scopes_four_services_in_server_first_order(self):
        job = self.job('fl.start')
        job['node'] = None
        self.controller._work(job)
        self.assertEqual(job['status'], 'complete')
        commands = [call for call in self.fixture.calls if call[1] == 'compose']
        self.assertEqual([call[-1] for call in commands],
                         ['fl-server', 'fl-client-a', 'fl-client-b', 'fl-client-c'])
        self.assertTrue(all('fl' in call and 'ddos-fl-laptop' in call for call in commands))
        self.assertFalse(any('down' in call or '--remove-orphans' in call for call in commands))

    def test_fl_stop_rejects_remote_active_run_even_without_local_lock(self):
        job = self.job('fl.stop')
        job['node'] = None
        self.controller.docker['services']['fl-server'] = {'running': True}
        with patch.object(self.controller, '_require_docker'):
            with patch.object(self.controller, '_exec', return_value=json.dumps(
                    {'runs': [{'status': 'running:running'}]})) as command:
                self.controller._work(job)
        self.assertEqual(job['status'], 'failed')
        self.assertIn('chưa kết thúc', job['error'])
        self.assertEqual(command.call_count, 1)
        self.assertNotEqual(command.call_args.args[0][0], 'docker')

    def test_train_waits_for_new_report_not_old_completed_run(self):
        report = self.root/'reports/fl/training.json'
        write_json(report, {'status':'complete', 'completed_rounds':5, 'weights_sha256':'old'})
        for name in ('fl-server','fl-client-a','fl-client-b','fl-client-c'):
            self.controller.docker['services'][name] = {'running':True, 'health':'healthy'}
        job = self.job('fl.run', rounds=5)
        job['node'] = None
        count = []
        def submitted(args, **kwargs):
            self.assertEqual(args[-3:], ['scripts/run_fl.py', '--rounds', '5'])
            write_json(self.root/'reports/fl/last-submission.json', {'run-id':'new-run'})
            return '{}'
        def progress(seconds):
            count.append(seconds)
            write_json(report, {'status':'complete', 'completed_rounds':5,
                                'weights_sha256':'new', 'selected_round':4})
            return False
        with patch.object(self.controller, '_exec', side_effect=submitted):
            with patch.object(self.controller.closed, 'wait', side_effect=progress):
                self.controller._train(job, 5)
        self.assertEqual(len(count), 1)
        self.assertEqual(job['weights_sha256'], 'new')
        self.assertEqual(job['run_id'], 'new-run')

    def test_clear_prevalidates_redirected_paths_before_truncating(self):
        self.fixture.running = False
        log = self.root/'data/node-c/live/eve/eve.json'
        log.write_text('keep original log')
        weights = self.root/BASELINES['c']/'weights.npz'
        original = weights.read_bytes()
        safe = self.controller.safe
        def redirected(relative):
            return weights if relative == 'data/node-c/live/eve/suricata.log' else safe(relative)
        job = self.job('logs.clear')
        with patch.object(self.controller, 'safe', side_effect=redirected):
            self.controller._work(job)
        self.assertEqual(job['status'], 'failed')
        self.assertEqual(weights.read_bytes(), original)
        self.assertEqual(log.read_text(), 'keep original log')

    def test_http_csrf_host_static_and_readonly_state(self):
        server = Server(('127.0.0.1', 0), make_handler(self.controller, 'fixture-token', 0))
        port = server.server_address[1]
        server.RequestHandlerClass = make_handler(self.controller, 'fixture-token', port)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def request(method, path, body=None, **headers):
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
            try:
                connection.request(method, path, body=body, headers=headers)
                response = connection.getresponse()
                return response.status, response.read(), dict(response.getheaders())
            finally:
                connection.close()
        try:
            status, raw, headers = request('GET', '/')
            self.assertEqual(status, 200)
            self.assertIn(b'/app.js', raw)
            self.assertIn('Content-Security-Policy', headers)
            self.assertEqual(request('GET', '/api/state')[0], 200)
            self.assertEqual(request('GET', '/../controller.py')[0], 404)
            self.assertEqual(request('GET', '/api/logs?node=../../models&kind=eve')[0], 400)
            self.assertEqual(request('GET', '/api/state', Host='external.example')[0], 403)
            body = json.dumps({'action':'session.new'})
            self.assertEqual(request('POST', '/api/action', body,
                                    **{'Content-Type':'application/json'})[0], 403)
            self.assertEqual(request('POST', '/api/action', body, **{
                'Content-Type':'application/json', 'X-Dashboard-Token':'fixture-token',
                'Origin':'http://external.example'})[0], 403)
            self.assertEqual(request('POST', '/api/action', body, **{
                'Content-Type':'application/json', 'X-Dashboard-Token':'fixture-token'})[0], 202)
            self.assertEqual(request('GET', '/api/export')[0], 200)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == '__main__':
    unittest.main()
