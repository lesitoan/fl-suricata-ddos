"""Local lab controls. Fixed commands only; no shell or arbitrary file browser."""
import copy
import hashlib
import json
import math
import os
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

from dataset_eval import evaluate as evaluate_dataset, predictions_page, sha as dataset_sha

PROJECT = 'ddos-fl-laptop'
IMAGE = 'ddos-fl-laptop-node-a-sensor:step1'
NODES = {
    'a': ('web', 'sensor', 'inference'),
    'b': ('udp-b', 'sensor-b', 'inference-b'),
    'c': ('ldap-c', 'sensor-c', 'inference-c'),
}
BASELINES = {'a': 'models/node-a/local-only-pilot-v1/laptop-01',
             'b': 'models/node-b/current', 'c': 'models/node-c/current'}
PROBES = {'a': 'syn_probe.py', 'b': 'udp_probe.py', 'c': 'ldap_probe.py'}
ACTIVE = ('queued', 'running', 'waiting')


class LabError(Exception):
    pass


def utc():
    return datetime.now(timezone.utc).isoformat()


def stamp(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Timestamp needs a timezone')
    return result.astimezone(timezone.utc)


def json_file(path, default=None):
    try:
        return json.loads(path.read_text(encoding='utf-8-sig'))
    except (OSError, ValueError):
        return default


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2,
                                    allow_nan=False) + '\n', encoding='utf-8')
    temporary.replace(path)


def tail_text(path, lines=160, max_bytes=300_000):
    try:
        with path.open('rb') as stream:
            size = stream.seek(0, 2)
            start = max(0, size-max_bytes)
            stream.seek(start)
            if start:
                stream.readline()
            return '\n'.join(stream.read(max_bytes).decode('utf-8', errors='replace')
                             .splitlines()[-lines:])
    except OSError:
        return ''


def new_records(path, offset):
    """Incremental JSONL reader: retain incomplete lines for the next poll."""
    try:
        with path.open('rb') as stream:
            if stream.seek(0, 2) < offset:
                offset = 0
            stream.seek(offset)
            rows = []
            for _ in range(5000):
                line = stream.readline(1_000_000)
                if not line or not line.endswith(b'\n'):
                    break
                offset = stream.tell()
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
            return offset, rows
    except OSError:
        return offset, []


def signature(event):
    flow = event['flow']
    fields = [str(event['flow_id']), event.get('src_ip'), event.get('src_port', ''),
              event.get('dest_ip'), event.get('dest_port', ''), event.get('proto', 'OTHER'),
              stamp(flow['start']).isoformat(), stamp(flow['end']).isoformat()]
    fields.extend(flow[name] for name in ('pkts_toserver', 'pkts_toclient',
                                          'bytes_toserver', 'bytes_toclient'))
    return hashlib.sha256(json.dumps(fields, separators=(',', ':'),
                                     ensure_ascii=True).encode()).hexdigest()


def sender_ports(sender):
    if 'source_port' in sender:
        return {int(sender['source_port'])}
    if 'source_ports' in sender:
        return {int(port) for port in sender['source_ports']}
    items = sender.get('queries', sender.get('records', []))
    return {int(item['source_port']) for item in items if 'source_port' in item}


def matches_sender(event, sender):
    try:
        if event.get('event_type') != 'flow':
            return False
        if (event.get('src_ip'), event.get('dest_ip'), event.get('dest_port')) != (
                sender['source_ip'], sender['destination_ip'], sender['destination_port']):
            return False
        ports = sender_ports(sender)
        if ports and int(event.get('src_port', -1)) not in ports:
            return False
        expected_protocol = 'TCP' if sender['destination_port'] == 8000 else 'UDP'
        return (event.get('proto') == expected_protocol
                and stamp(sender['start_utc'])-timedelta(seconds=1)
                <= stamp(event['flow']['start'])
                <= stamp(sender['end_utc'])+timedelta(seconds=1))
    except (KeyError, TypeError, ValueError):
        return False


def capture_snapshot(path):
    """Last published counters, not an instantaneous packet-capture measurement."""
    for line in reversed(tail_text(path, lines=100, max_bytes=500_000).splitlines()):
        try:
            item = json.loads(line)
            if item.get('event_type') != 'stats':
                continue
            stats = item['stats']
            return {'timestamp': item.get('timestamp'), 'uptime': stats.get('uptime'),
                    'kernel_packets': stats.get('capture', {}).get('kernel_packets'),
                    'kernel_drops': stats.get('capture', {}).get('kernel_drops'),
                    'capture_errors': stats.get('capture', {}).get('errors'),
                    'decoder_invalid': stats.get('decoder', {}).get('invalid')}
        except (ValueError, TypeError, KeyError, AttributeError):
            pass
    return None


def udp_load_metrics(sender, flows, before, after):
    expected = {int(item['source_port']): item['packets_sent'] for item in sender.get('per_flow', [])}
    captured = {port: 0 for port in expected}
    for event in flows:
        port = int(event['src_port'])
        if port in captured:
            captured[port] += event['flow']['pkts_toserver']
    comparable = bool(before and after and before.get('timestamp') != after.get('timestamp')
                      and isinstance(before.get('uptime'), int) and isinstance(after.get('uptime'), int)
                      and after['uptime'] >= before['uptime'])
    delta = {}
    for key in ('kernel_packets', 'kernel_drops', 'capture_errors', 'decoder_invalid'):
        left, right = (before or {}).get(key), (after or {}).get(key)
        delta[key] = right-left if comparable and isinstance(left, int) and isinstance(right, int) and right >= left else None
    return {'profile': sender['scenario'], 'packets_sent': sender['packets_sent'],
            'planned_packets': sender.get('planned_packets', sender['packets_sent']),
            'rate_limit_pps': sender.get('rate_limit_pps'),
            'target_sending_seconds': sender.get('target_sending_seconds'),
            'missed_send_slots': sender.get('missed_send_slots'),
            'valid_echoes': sender.get('valid_echoes'),
            'echoes_missing_after_observation': sender.get('echoes_missing_after_observation'),
            'observed_send_pps': sender.get('observed_send_pps'),
            'sending_wall_seconds': sender.get('sending_wall_seconds'),
            'planned_flows': sender.get('planned_flows'),
            'health_checks': {phase: {key: value for key, value in record.items() if key != 'records'}
                              for phase, record in sender.get('health_checks', {}).items()},
            'per_flow_capture': [{'source_port': port, 'sent': count, 'captured': captured[port]}
                                 for port, count in expected.items()],
            'sent_packet_count_matches_capture': bool(expected and captured == expected
                                                        and sum(expected.values()) == sender['packets_sent']),
            'capture_observation': {'before': before, 'after': after, 'delta': delta,
                                    'note': 'Stats interval includes flow-wait time and benign probes; not exclusively the load phase.'},
            'note': 'Missing client echoes do not establish where loss occurred. Five benign probes per phase; no saturation inference.'}


class Controller:
    def __init__(self, root, *, runner=None, start_monitor=True):
        self.root = Path(root).resolve()
        self.runner = runner
        self.lock = threading.RLock()
        self.closed = threading.Event()
        self.jobs = []
        self.docker = {'ok': False, 'checked_at': None,
                       'error': 'Đang kiểm tra Docker…', 'services': {}}
        self.metadata_cache = {}
        state = json_file(self.safe('runtime/dashboard/state.json'), {})
        self.session = state.get('session') or uuid.uuid4().hex[:12]
        if not isinstance(self.session, str) or not self.session.isalnum():
            self.session = uuid.uuid4().hex[:12]
        self.session_started = state.get('started_at', utc())
        self._save_session()
        for path in sorted(self.session_dir().glob('*/job.json'))[-100:]:
            item = json_file(path)
            if isinstance(item, dict):
                if item.get('status') in ACTIVE:
                    item.update(status='interrupted', error='Dashboard đã khởi động lại; không tự gửi lại lệnh.')
                self.jobs.append(item)
        if start_monitor:
            threading.Thread(target=self._monitor, daemon=True).start()

    def safe(self, relative):
        path = (self.root/relative).resolve()
        if not path.is_relative_to(self.root):
            raise LabError('Đường dẫn nằm ngoài bản laptop')
        return path

    def session_dir(self):
        return self.safe('reports/dashboard/sessions/'+self.session)

    def _save_session(self):
        write_json(self.safe('runtime/dashboard/state.json'),
                   {'session': self.session, 'started_at': self.session_started})

    def model(self, node, mode):
        folder = self.safe('models/fl/current' if mode == 'global' else BASELINES[node])
        metadata = json_file(folder/'model.json', {})
        weights = folder/'weights.npz'
        try:
            stat = weights.stat()
            key = (str(weights), stat.st_mtime_ns, stat.st_size)
            if key not in self.metadata_cache:
                self.metadata_cache[key] = hashlib.sha256(weights.read_bytes()).hexdigest()
            digest = self.metadata_cache[key]
        except OSError:
            digest = None
        return {'exists': bool(digest and digest == metadata.get('weights_sha256')),
                'hash': digest, 'id': metadata.get('config', {}).get('experiment_id'),
                'threshold': metadata.get('threshold'), 'round': metadata.get('selected_round')}

    def _exec(self, args, timeout=45, job=None):
        if job:
            self._job_log(job, '> '+subprocess.list2cmdline([str(arg) for arg in args]))
        if self.runner:
            result = self.runner(args, timeout=timeout)
        else:
            environment = dict(os.environ, COMPOSE_IGNORE_ORPHANS='true',
                               PYTHONIOENCODING='utf-8')
            result = subprocess.run(args, cwd=self.root, capture_output=True,
                                    text=True, encoding='utf-8', errors='replace',
                                    timeout=timeout, env=environment,
                                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if job:
            self._job_log(job, (result.stdout+'\n'+result.stderr).strip()[-50_000:])
        if result.returncode:
            raise LabError((result.stderr or result.stdout or 'Lệnh thất bại')[-8000:])
        return result.stdout

    def compose(self, node=None, mode='local', fl=False):
        args = ['docker', 'compose', '-p', PROJECT]
        if fl:
            args += ['--profile', 'fl', '-f',
                     'compose.fl.yaml' if node is None else 'compose.node-'+node+'.yaml']
        else:
            args += ['-f', 'compose.node-'+node+'-live.yaml']
            if mode == 'global':
                args += ['-f', 'compose.node-'+node+'-global.yaml']
        return args

    def refresh_docker(self):
        try:
            text = self._exec(['docker', 'ps', '-aq', '--filter',
                               'label=com.docker.compose.project='+PROJECT], timeout=8)
            ids = text.split()
            inspected = json.loads(self._exec(['docker', 'inspect', *ids], timeout=8)) if ids else []
            services = {}
            for item in inspected:
                labels = item['Config'].get('Labels') or {}
                if labels.get('com.docker.compose.project') != PROJECT:
                    continue
                service = labels.get('com.docker.compose.service')
                if service not in {name for group in NODES.values() for name in group} | {
                        'fl-server', 'fl-client-a', 'fl-client-b', 'fl-client-c'}:
                    continue
                state = item.get('State', {})
                entry = {'id': item['Id'], 'running': state.get('Running', False),
                         'status': state.get('Status', 'unknown'),
                         'health': state.get('Health', {}).get('Status'),
                         'started_at': state.get('StartedAt'), 'mode': None,
                         'loaded_hash': None, 'loaded_id': None}
                if service in ('inference', 'inference-b', 'inference-c'):
                    source = next((mount['Source'] for mount in item.get('Mounts', [])
                                   if mount['Destination'] == '/model'), '')
                    source = source.replace('\\', '/').rstrip('/').lower()
                    node = {'inference': 'a', 'inference-b': 'b', 'inference-c': 'c'}[service]
                    if source.endswith('/models/fl/current'):
                        entry['mode'] = 'global'
                    elif source.endswith('/'+BASELINES[node].lower()):
                        entry['mode'] = 'local'
                    if entry['running']:
                        raw = self._exec(['docker', 'logs', '--tail', '40', item['Id']], timeout=6)
                        for line in raw.splitlines():
                            try:
                                record = json.loads(line)
                                loaded = record.get('prediction', record)
                                if loaded.get('weights_sha256'):
                                    entry.update(loaded_hash=loaded['weights_sha256'],
                                                 loaded_id=loaded.get('model_id'))
                            except (ValueError, AttributeError):
                                pass
                    # Keep ready metadata if subsequent log tail has no model lines.
                    old = self.docker['services'].get(service, {})
                    if not entry['loaded_hash'] and old.get('id') == entry['id']:
                        entry.update(loaded_hash=old.get('loaded_hash'), loaded_id=old.get('loaded_id'))
                services[service] = entry
            value = {'ok': True, 'error': None, 'checked_at': utc(), 'services': services}
        except (OSError, ValueError, KeyError, LabError, subprocess.SubprocessError) as error:
            value = {'ok': False, 'error': str(error)[:1500], 'checked_at': utc(), 'services': {}}
        with self.lock:
            self.docker = value
        return value

    def _monitor(self):
        while not self.closed.is_set():
            self.refresh_docker()
            self.closed.wait(4)

    def fl_busy(self):
        return (self.safe('reports/fl/.server-run-lock').exists()
                or self.safe('reports/fl/.submission-lock').exists()
                or any(job['action'] == 'fl.run' and job['status'] in ACTIVE for job in self.jobs))

    def dataset_busy(self):
        return (self.safe('runtime/dashboard/.dataset-evaluation-lock').exists()
                or any(job['action']=='dataset.test' and job['status'] in ACTIVE for job in self.jobs))

    def node_state(self, node):
        services = {name: self.docker['services'].get(name, {'running': False, 'status': 'missing'})
                    for name in NODES[node]}
        inference = services[NODES[node][2]]
        mode = inference.get('mode')
        model = self.model(node, mode or 'local')
        healthy = all(item.get('running') and item.get('health') not in ('starting', 'unhealthy')
                      for item in services.values())
        return {'services': services, 'mode': mode, 'model': model,
                'loaded_hash': inference.get('loaded_hash'),
                'loaded_id': inference.get('loaded_id'),
                'ready': bool(self.docker['ok'] and healthy and mode in ('local', 'global') and model['exists']
                              and inference.get('loaded_hash') == model['hash']),
                'stale': bool(inference.get('loaded_hash') and model['hash']
                              and inference['loaded_hash'] != model['hash']),
                'local_model': self.model(node, 'local'),
                'global_model': self.model(node, 'global'),
                'dataset_available':self.safe('data/node-'+node+'/work/splits/pilot-v1/test.csv').is_file()
                    and self.safe('data/node-'+node+'/work/splits/pilot-v1/manifest.json').is_file()}

    def snapshot(self):
        with self.lock:
            training = json_file(self.safe('reports/fl/training.json'), {})
            global_model = self.model('a', 'global')
            source = json_file(self.safe('reports/fl/test-evaluation/summary.json'), {})
            test = {'available': bool(source.get('nodes')), 'nodes': {},
                    'global_hash': source.get('global_weights_sha256'),
                    'matches_current_global': source.get('global_weights_sha256') == global_model['hash'],
                    'evaluated_at': source.get('evaluated_at_utc')}
            for node, item in source.get('nodes', {}).items():
                if node in ('A', 'B', 'C'):
                    test['nodes'][node] = {'rows': item.get('rows'), 'models': item.get('models', {})}
            jobs = copy.deepcopy(self.jobs[-80:])
            return {'session': self.session, 'session_started': self.session_started,
                    'now': utc(), 'docker': copy.deepcopy(self.docker),
                    'nodes': {node: self.node_state(node) for node in NODES},
                    'dataset_busy':self.dataset_busy(),
                    'fl': {'busy': self.fl_busy(), 'training': training,
                           'submission': json_file(self.safe('reports/fl/last-submission.json'), {}),
                           'global_model': global_model},
                    'jobs': jobs, 'test': test}

    def _job_log(self, job, text):
        with self.lock:
            folder = self.safe(job['folder'])
            with (folder/'command.log').open('a', encoding='utf-8') as stream:
                stream.write(utc()+' '+text+'\n')

    def update(self, job, **values):
        with self.lock:
            job.update(values, updated_at=utc())
            write_json(self.safe(job['folder'])/'job.json', job)

    def submit(self, payload):
        if not isinstance(payload, dict):
            raise LabError('Yêu cầu phải là JSON object')
        action = payload.get('action')
        allowed = {'node.start': {'node', 'mode'}, 'node.stop': {'node'},
                   'node.mode': {'node', 'mode'}, 'traffic': {'node', 'scenario'},
                   'logs.clear': {'node'}, 'fl.start': set(), 'fl.stop': set(),
                   'fl.run': {'rounds'}, 'session.new': set(), 'dataset.test':{'node'}}
        if not isinstance(action, str) or action not in allowed or set(payload) != allowed[action] | {'action'}:
            raise LabError('Thao tác hoặc tham số không hợp lệ')
        node = payload.get('node')
        if 'node' in allowed[action] and (not isinstance(node, str) or node not in NODES):
            raise LabError('Node phải là a, b hoặc c')
        if 'mode' in allowed[action] and payload['mode'] not in ('local', 'global'):
            raise LabError('Model phải là local hoặc global')
        if action == 'traffic' and payload['scenario'] not in ('benign', 'attack'):
            raise LabError('Scenario không hợp lệ')
        if action == 'fl.run':
            rounds = payload['rounds']
            if isinstance(rounds, bool) or not isinstance(rounds, int) or not 1 <= rounds <= 50:
                raise LabError('Số vòng phải là số nguyên từ 1 đến 50')
        with self.lock:
            active = [job for job in self.jobs if job['status'] in ACTIVE]
            resources = {'node:'+node} if node else {'fl'}
            if action in ('dataset.test','fl.run'):
                resources.add('dataset')
            if action == 'session.new':
                resources = {'fl', 'node:a', 'node:b', 'node:c'}
            if any(resources & set(job['resources']) for job in active):
                raise LabError('Thao tác trước vẫn đang chạy trên thành phần này')
            if action in ('fl.start', 'fl.stop', 'fl.run') and self.fl_busy():
                raise LabError('FL đang chạy hoặc giữ lock; không dừng/gửi thêm run')
            if action=='dataset.test' and (self.fl_busy() or self.dataset_busy()):
                raise LabError('Đợi FL hoặc lượt test dataset hiện tại hoàn tất trước')
            if action=='fl.run' and self.dataset_busy():
                raise LabError('Đợi test dataset hoàn tất trước khi chạy FL')
            if action == 'fl.run' and any(job.get('mode') == 'global' for job in active):
                raise LabError('Đợi các thao tác global hiện tại hoàn tất trước khi train FL')
            if node and self.fl_busy() and (payload.get('mode') == 'global'
                    or (action == 'traffic' and self.node_state(node)['mode'] == 'global')):
                raise LabError('Đợi FL hoàn tất trước khi nạp hoặc demo global')
            if action == 'session.new':
                self.session = uuid.uuid4().hex[:12]
                self.session_started = utc()
                self.jobs = []
                self._save_session()
                return {'session': self.session}
            identifier = datetime.now().strftime('%H%M%S')+'-'+uuid.uuid4().hex[:8]
            folder = 'reports/dashboard/sessions/'+self.session+'/'+identifier
            self.safe(folder).mkdir(parents=True)
            job = {'id': identifier, 'action': action, 'node': node,
                   'status': 'queued', 'created_at': utc(), 'folder': folder,
                   'resources': sorted(resources), 'request': payload}
            if node and 'mode' in payload:
                job['mode'] = payload['mode']
            if node and action == 'traffic':
                job['mode'] = self.node_state(node)['mode']
            self.jobs.append(job)
            self.update(job)
            threading.Thread(target=self._work, args=(job,), daemon=True).start()
            return {'job': identifier}

    def _require_docker(self):
        self.refresh_docker()
        if not self.docker['ok']:
            raise LabError('Docker chưa sẵn sàng: '+str(self.docker['error']))

    def _ready(self, node, timeout=35, mode=None):
        deadline = time.monotonic()+timeout
        while time.monotonic() < deadline:
            self.refresh_docker()
            state = self.node_state(node)
            if state['ready'] and (mode is None or state['mode'] == mode):
                return state
            if self.closed.wait(1):
                break
        raise LabError('Inference chưa ready/đúng hash. Xem log container hoặc bấm Nạp model.')

    def _work(self, job):
        self.update(job, status='running', message='Đang thực hiện…')
        try:
            self._require_docker()
            payload, node, action = job['request'], job['node'], job['action']
            if action in ('fl.start', 'fl.stop') and self.fl_busy():
                raise LabError('FL giữ lock; không thay đổi dịch vụ lúc này')
            if action in ('node.start', 'node.mode'):
                mode = payload['mode']
                if mode == 'global' and self.fl_busy():
                    raise LabError('Đợi FL hoàn tất trước khi nạp global')
                if not self.model(node, mode)['exists']:
                    raise LabError('Thiếu model hoặc hash model không hợp lệ')
                for relative in ('eve', 'predictions' if mode == 'local' else 'predictions-global'):
                    self.safe('data/node-'+node+'/live/'+relative).mkdir(parents=True, exist_ok=True)
                args = self.compose(node, mode)
                if action == 'node.mode':
                    if not all(self.docker['services'].get(name, {}).get('running')
                               for name in NODES[node][:2]):
                        raise LabError('Bật node trước khi chuyển/nạp model')
                    args += ['up', '-d', '--no-deps', '--force-recreate', NODES[node][2]]
                else:
                    args += ['up', '-d', '--wait', '--wait-timeout', '90', *NODES[node]]
                self._exec(args, timeout=150, job=job)
                self._ready(node, mode=mode)
            elif action == 'node.stop':
                self._exec(self.compose(node)+['stop', '-t', '65', *reversed(NODES[node])],
                           timeout=180, job=job)
            elif action in ('fl.start', 'fl.stop'):
                if action == 'fl.start':
                    self._exec(self.compose(fl=True)+['up', '-d', '--wait', '--wait-timeout', '90', 'fl-server'],
                               timeout=150, job=job)
                    for letter in NODES:
                        self._exec(self.compose(letter, fl=True)+[
                            'up', '-d', '--wait', '--wait-timeout', '90', 'fl-client-'+letter],
                            timeout=150, job=job)
                    self._exec([sys.executable, '-B', 'scripts/check_fl_connection.py'],
                               timeout=180, job=job)
                else:
                    server = self.docker['services'].get('fl-server', {})
                    if server.get('running'):
                        query = ('import sys,json;sys.path.insert(0,"scripts");'
                                 'from check_fl_connection import cli;'
                                 'print(json.dumps(cli("list","docker","--format","json")))')
                        response = json.loads(self._exec([sys.executable, '-B', '-c', query],
                                                         timeout=90, job=job))
                        if any(not run['status'].startswith('finished:') for run in response['runs']):
                            raise LabError('Flower còn run chưa kết thúc; không dừng FL')
                        if self.fl_busy():
                            raise LabError('FL vừa nhận run/lock mới; không dừng')
                    for letter in reversed(NODES):
                        self._exec(self.compose(letter, fl=True)+['stop', 'fl-client-'+letter], job=job)
                    self._exec(self.compose(fl=True)+['stop', 'fl-server'], job=job)
            elif action == 'fl.run':
                self._train(job, payload['rounds'])
            elif action == 'traffic':
                self._traffic(job, node, payload['scenario'])
            elif action == 'dataset.test':
                if self.fl_busy():
                    raise LabError('Đợi FL hoàn tất trước khi test dataset')
                summary=evaluate_dataset(self.root,node,self.safe(job['folder']),
                    lambda args:self._exec(args,timeout=240,job=job),
                    lambda message:self.update(job,message=message))
                self.update(job,dataset_summary=summary)
            elif action == 'logs.clear':
                writers = NODES[node][1:]
                if any(self.docker['services'].get(name, {}).get('running') for name in writers):
                    raise LabError('Dừng node trước khi xóa log live')
                cleared = []
                paths = []
                for relative in ('eve/eve.json', 'eve/suricata.log', 'eve/fast.log',
                                 'eve/stats.log', 'predictions/predictions.jsonl',
                                 'predictions-global/predictions.jsonl'):
                    lexical = self.root/('data/node-'+node+'/live/'+relative)
                    path = self.safe('data/node-'+node+'/live/'+relative)
                    if os.path.normcase(str(lexical.absolute())) != os.path.normcase(str(path)):
                        raise LabError('Không xóa log thông qua symlink/junction')
                    if path.is_file():
                        paths.append((relative, path))
                for relative, path in paths:
                    with path.open('wb'):
                        pass
                    cleared.append(relative)
                self.update(job, cleared=cleared)
            self.refresh_docker()
            self.update(job, status='complete', message='Hoàn tất', finished_at=utc())
        except Exception as error:
            self._job_log(job, type(error).__name__+': '+str(error))
            self.update(job, status='failed', error=str(error)[-8000:],
                        message='Thất bại — xem chi tiết', finished_at=utc())

    def _train(self, job, rounds):
        for name in ('fl-server', 'fl-client-a', 'fl-client-b', 'fl-client-c'):
            entry = self.docker['services'].get(name, {})
            if not entry.get('running') or entry.get('health') != 'healthy':
                raise LabError('Bật FL và đợi đủ bốn service healthy trước')
        path = self.safe('reports/fl/training.json')
        old_stamp = path.stat().st_mtime_ns if path.exists() else None
        self.update(job, message='Đang kiểm đầu vào và submit FL; không bấm gửi lại…')
        self._exec([sys.executable, '-B', 'scripts/run_fl.py', '--rounds', str(rounds)],
                   timeout=300, job=job)
        receipt = json_file(self.safe('reports/fl/last-submission.json'), {})
        self.update(job, status='waiting', run_id=receipt.get('run-id'),
                    message='Đã submit; đang chờ các vòng FL hoàn tất…')
        deadline = time.monotonic()+3600
        while time.monotonic() < deadline:
            report = json_file(path, {})
            fresh = path.exists() and path.stat().st_mtime_ns != old_stamp
            if fresh:
                self.update(job, progress=report.get('completed_rounds', 0),
                            total=rounds, message='FL: %s/%s vòng' % (report.get('completed_rounds', 0), rounds))
                if report.get('status') == 'failed':
                    raise LabError(report.get('error', 'FL thất bại'))
                if report.get('status') == 'complete':
                    self.update(job, weights_sha256=report.get('weights_sha256'),
                                selected_round=report.get('selected_round'))
                    return
            if self.closed.wait(2):
                raise LabError('Dashboard dừng; FL có thể vẫn chạy. Kiểm tra trước khi gửi lại.')
        raise LabError('Hết thời gian theo dõi; không tự submit lại. Kiểm tra Flower/log server.')

    def _traffic(self, job, node, scenario):
        state = self._ready(node, timeout=8)
        mode, expected_hash = state['mode'], state['loaded_hash']
        if mode == 'global' and self.fl_busy():
            raise LabError('Đợi FL hoàn tất trước khi demo global')
        folder = self.safe(job['folder'])
        self.update(job, mode=mode, scenario=scenario, model_id=state['loaded_id'],
                    weights_sha256=expected_hash, message='Đang gửi traffic giới hạn…')
        eve = self.safe('data/node-'+node+'/live/eve/eve.json')
        predictions = self.safe('data/node-'+node+'/live/'+(
            'predictions-global' if mode == 'global' else 'predictions')+'/predictions.jsonl')
        offsets = [path.stat().st_size if path.exists() else 0 for path in (eve, predictions)]
        capture_before = capture_snapshot(eve) if node == 'b' and scenario == 'attack' else None
        container_name = PROJECT+'-demo-'+job['id']
        args = ['docker', 'run', '--rm', '--pull', 'never', '--name', container_name,
                '--label', 'ddos-fl-laptop.dashboard-job='+job['id'],
                '--network', PROJECT+'_site-'+node, '--memory', '64m', '--cpus', '0.25',
                '--read-only', '--tmpfs', '/tmp', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges', '--mount',
                'type=bind,source='+str(self.safe('scripts'))+',target=/app,readonly']
        if scenario == 'attack':
            if node == 'a':
                args += ['--cap-add', 'NET_RAW']
            args += ['--mount', 'type=bind,source='+str(folder)+',target='+(
                '/output' if node == 'a' else '/report')]
        script = 'benign_traffic.py' if scenario == 'benign' else PROBES[node]
        args += [IMAGE, 'python3', '-B', '/app/node-'+node+'/'+script]
        command_error = None
        try:
            stdout = self._exec(args, timeout=75, job=job)
            if scenario == 'benign':
                records = []
                for line in stdout.splitlines():
                    try:
                        records.append(json.loads(line))
                    except ValueError:
                        pass
                sender = next((item for item in reversed(records)
                               if isinstance(item, dict) and 'source_ip' in item), None)
                if not sender:
                    raise LabError('Không tìm thấy báo cáo sender')
                write_json(folder/'sender.json', sender)
        except (LabError, subprocess.SubprocessError) as error:
            command_error = str(error)
            if isinstance(error, subprocess.TimeoutExpired):
                # Only remove this dashboard's own fixed-name temporary sender.
                try:
                    self._exec(['docker', 'rm', '-f', container_name], job=job)
                except LabError:
                    pass
        sender = json_file(folder/'sender.json')
        if not sender or not sender.get('source_ip'):
            raise LabError(command_error or 'Sender chưa có báo cáo hợp lệ')
        if command_error:
            self.update(job, sender_warning=command_error)
        self.update(job, status='waiting', message='Chờ Suricata xuất flow và model dự đoán (tối đa 90 giây)…',
                    sender_summary={key: sender[key] for key in (
                        'packets_sent', 'successful', 'requests', 'valid_echoes', 'valid_responses',
                        'source_ip', 'source_port', 'source_ports', 'observed_send_pps',
                        'destination_ip', 'destination_port') if key in sender})
        deadline, started, last_new = time.monotonic()+90, time.monotonic(), time.monotonic()
        flows, scored = {}, {}
        expected_ports = sender_ports(sender)
        while time.monotonic() < deadline:
            previous_matches = set(flows) & set(scored)
            offsets[0], events = new_records(eve, offsets[0])
            for event in events:
                if matches_sender(event, sender):
                    try:
                        flows[signature(event)] = event
                    except (ValueError, KeyError, TypeError):
                        pass
            offsets[1], records = new_records(predictions, offsets[1])
            for record in records:
                if (record.get('weights_sha256') == expected_hash
                        and record.get('mode') == 'live'
                        and record.get('event_signature_sha256')):
                    scored[record['event_signature_sha256']] = record
            matched = {key: scored[key] for key in flows if key in scored}
            covered = {int(flows[key].get('src_port', -1)) for key in matched}
            if set(matched) != previous_matches:
                last_new = time.monotonic()
            self.update(job, matched_flows=len(flows), matched_predictions=len(matched),
                        message='Đang ghép: %s flow / %s prediction · còn %ss' % (
                            len(flows), len(matched), max(0, int(deadline-time.monotonic()))))
            ports_complete = expected_ports and expected_ports <= covered
            observation_complete = (not expected_ports and time.monotonic()-started >= 55)
            if matched and (ports_complete or observation_complete) and time.monotonic()-last_new >= 3:
                break
            if self.closed.wait(1):
                raise LabError('Dashboard dừng khi đang chờ flow; bằng chứng sender vẫn được giữ')
        matched = {key: scored[key] for key in flows if key in scored}
        rows = list(matched.values())
        for row in rows:
            value = row.get('probability_attack')
            if not isinstance(value, (float, int)) or not math.isfinite(value) or not 0 <= value <= 1:
                raise LabError('Prediction có xác suất không hợp lệ')
            threshold = state['model']['threshold']
            if (row.get('threshold') != threshold or row.get('model_id') != state['loaded_id']
                    or row.get('prediction') != ('attack' if value >= threshold else 'benign')):
                raise LabError('Prediction không khớp contract model/threshold')
        delays = [row['seconds_from_flow_end_to_score'] for row in rows
                  if isinstance(row.get('seconds_from_flow_end_to_score'), (int, float))
                  and math.isfinite(row['seconds_from_flow_end_to_score'])]
        covered = {int(flows[key].get('src_port', -1)) for key in matched}
        report = {'kind': 'live_integration', 'node': node.upper(), 'mode': mode,
                  'scenario': scenario, 'ground_truth': 'controlled_benign' if scenario == 'benign'
                  else 'unverified_synthetic', 'model_id': state['loaded_id'],
                  'weights_sha256': expected_hash, 'matched_flows': len(flows),
                  'matched_predictions': len(rows),
                  'predicted_attack': sum(row['prediction'] == 'attack' for row in rows),
                  'predicted_benign': sum(row['prediction'] == 'benign' for row in rows),
                  'expected_source_ports': len(expected_ports) if expected_ports else None,
                  'covered_source_ports': len(covered),
                  'all_source_ports_matched': expected_ports <= covered if expected_ports else None,
                  'mean_delay_seconds': sum(delays)/len(delays) if delays else None,
                  'captured_packets_toserver': sum(event['flow']['pkts_toserver'] for event in flows.values()),
                  'captured_packets_toclient': sum(event['flow']['pkts_toclient'] for event in flows.values()),
                  'sender_error': command_error, 'created_at': utc(),
                  'note': 'Live burst/probe integration only. Not dataset attack recall or a DDoS saturation test.'}
        report['traffic_profile'] = sender.get('scenario')
        if sender.get('schema_version') == 'udp-load-v1':
            report['udp_load'] = udp_load_metrics(sender, list(flows.values()), capture_before,
                                                  capture_snapshot(eve))
        write_json(folder/'report.json', report)
        write_json(folder/'matched-flows.json', list(flows.values()))
        write_json(folder/'matched-predictions.json', rows)
        self.update(job, report=report)
        if not rows:
            raise LabError('Đã gửi nhưng chưa ghép được prediction trong 90 giây; xem EVE và log inference')
        if command_error or (expected_ports and not expected_ports <= covered):
            raise LabError('Kết quả chưa đầy đủ; xem báo cáo sender/flow đã lưu')
        if report.get('udp_load', {}).get('sent_packet_count_matches_capture') is False:
            raise LabError('Đã ghép flow nhưng số gói tải gửi/Suricata chưa khớp; xem báo cáo từng cổng')

    def dataset_artifact(self, identifier):
        with self.lock:
            job=next((item for item in self.jobs if item['id']==identifier),None)
            if not job or job['action']!='dataset.test' or job['status']!='complete' or job.get('node') not in NODES:
                raise LabError('Chưa có báo cáo dataset hoàn tất cho job này')
            folder=self.safe(job['folder'])/'dataset'
            if not folder.resolve().is_relative_to(self.session_dir().resolve()):
                raise LabError('Report nằm ngoài phiên hiện tại')
            path=folder/('node-'+job['node'])/'predictions.csv'
            if not path.resolve().is_relative_to(folder.resolve()):
                raise LabError('Không đọc prediction thông qua đường dẫn ngoài report')
            summary=json_file(folder/'summary.json',{})
            if summary!=job.get('dataset_summary'):
                raise LabError('Báo cáo dataset đã thay đổi sau khi xác minh')
            expected=summary.get('artifacts',{}).get('node-'+job['node']+'/predictions.csv')
            if not expected or dataset_sha(path)!=expected:
                raise LabError('Hash predictions.csv không còn khớp báo cáo')
            return path,summary

    def dataset_rows(self,identifier,model='local',selection='all',page=1,size=50):
        path,_=self.dataset_artifact(identifier)
        return predictions_page(path,model,selection,page,size)

    def logs(self, node, kind, event='flow'):
        if node not in NODES or kind not in ('eve', 'local', 'global', 'container', 'fl', 'job'):
            raise LabError('Nguồn log không hợp lệ')
        if event not in ('flow', 'all'):
            raise LabError('Bộ lọc EVE không hợp lệ')
        if kind == 'job':
            with self.lock:
                job = next((item for item in reversed(self.jobs) if item.get('node') == node
                            or item['action'].startswith('fl.')), None)
            return tail_text(self.safe(job['folder'])/'command.log') if job else ''
        if kind in ('container', 'fl'):
            service = 'fl-server' if kind == 'fl' else NODES[node][2]
            entry = self.docker['services'].get(service)
            return self._exec(['docker', 'logs', '--tail', '100', entry['id']], timeout=8) if entry else ''
        relative = {'eve': 'eve/eve.json', 'local': 'predictions/predictions.jsonl',
                    'global': 'predictions-global/predictions.jsonl'}[kind]
        raw = tail_text(self.safe('data/node-'+node+'/live/'+relative), lines=260)
        if kind == 'eve' and event == 'flow':
            lines = []
            for line in raw.splitlines():
                try:
                    if json.loads(line).get('event_type') == 'flow':
                        lines.append(line)
                except (ValueError, AttributeError):
                    pass
            raw = '\n'.join(lines)
        return raw
