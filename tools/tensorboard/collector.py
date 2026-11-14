"""Read only metric reports, export TensorBoard scalars. Never load node CSVs or fit."""
import hashlib
import json
import math
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from datetime import datetime

BASELINES = {'A':'models/node-a/local-only-pilot-v1/laptop-01',
             'B':'models/node-b/current', 'C':'models/node-c/current'}
LOCAL_METRICS = ('loss','balanced_accuracy','precision_attack','recall_attack','f1_attack',
                 'f1_macro','false_positive_rate')
FL_METRICS = ('loss','balanced-accuracy','precision-attack','recall-attack',
              'f1-macro','false-positive-rate','tn','fp','fn','tp')
RETENTION = 'latest-per-node-v1'
SLOTS = {'local/node-'+node for node in 'abc'} | {'federated/node-'+node for node in 'abc'} | {'federated/server'}


def validate_event_tree(root, path):
    """Validate every path before changing recognized exporter output."""
    output = root/'reports/tensorboard'
    if output.resolve()!=output.absolute() or not path.resolve().is_relative_to(output.absolute()):
        raise ValueError('TensorBoard cleanup path escapes its fixed output directory')
    if not path.exists(): return
    known = r'(?:local(?:/node-[abc](?:/[0-9a-f]{16})?)?|federated(?:/(?:node-[abc]|server|[0-9a-f]{16}(?:/(?:node-[abc]|server))?))?)'
    # Prevalidate the entire tree before removing any file; never follow reparse points.
    for directory,children,files in os.walk(path,followlinks=False):
        for entry in [Path(directory), *[Path(directory)/name for name in children+files]]:
            if entry.is_symlink() or getattr(entry.stat(follow_symlinks=False),'st_file_attributes',0)&0x400:
                raise ValueError('Refusing TensorBoard cleanup through symlink/junction')
            if not entry.resolve().is_relative_to(output.absolute()):
                raise ValueError('TensorBoard cleanup escaped output directory')
            relative = entry.relative_to(output).as_posix()
            if entry.is_dir():
                if relative!='.' and not re.fullmatch(known,relative):
                    raise ValueError('Unknown directory in TensorBoard output: '+relative)
            elif not (entry.name=='source.json' or entry.name.startswith('events.out.tfevents.')):
                raise ValueError('Unknown file in TensorBoard output: '+relative)


def remove_event_tree(root, path):
    """Delete only recognized exporter files under the fixed TensorBoard output."""
    validate_event_tree(root,path)
    if path.exists(): shutil.rmtree(path)


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def atomic_json(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=path.parent,
                                     prefix='.telemetry-',delete=False) as stream:
        temporary = Path(stream.name)
        json.dump(value,stream,ensure_ascii=False,allow_nan=False,indent=2)
    try: temporary.replace(path)
    finally: temporary.unlink(missing_ok=True)


def safe_read(root, relative):
    path = root/relative
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Report path escapes project')
    return read(path)


def number(value):
    if type(value) not in (int,float) or not math.isfinite(value):
        raise ValueError('Scalar must be finite')
    return float(value)


def step(value):
    if type(value) is not int or value < 1:
        raise ValueError('Epoch/round must be a positive integer')
    return value


def identifier(value):
    # Arbitrary experiment names never become directory paths.
    return hashlib.sha256(str(value).encode()).hexdigest()[:16]


def local_points(report):
    points = []
    for expected, epoch in enumerate(report['history'],1):
        index = step(epoch['epoch'])
        if index != expected:
            raise ValueError('Epoch history must be contiguous')
        values = {'train/loss':number(epoch['train_loss'])}
        values.update({'validation/'+name:number(epoch['validation'][name])
                       for name in LOCAL_METRICS if name in epoch['validation']})
        points.append((index,values))
    return points


def federated_points(report):
    runs = {node:[] for node in ('A','B','C','server')}
    for expected, record in enumerate(report['history'],1):
        index = step(record['round'])
        if index != expected or set(record['train_clients']) != {'A','B','C'} or set(record['validation_clients']) != {'A','B','C'}:
            raise ValueError('Incomplete or out-of-order FL history')
        for node in ('A','B','C'):
            train = record['train_clients'][node]['metrics']
            validation = record['validation_clients'][node]
            values = {'train/loss':number(train['train-loss']),
                      'timing/train_seconds':number(train['train-seconds'])}
            values.update({'validation/'+name.replace('-','_'):number(validation[name])
                           for name in FL_METRICS if name in validation})
            # Validation is the aggregated Global model, not the node's post-fit update.
            runs[node].append((index,values))
        summary = record['validation_summary']
        values = {'validation/mean_node_balanced_accuracy':number(summary['balanced-accuracy-macro-node']),
                  'validation/pooled_loss':number(summary['loss']),
                  'timing/round_seconds':number(record['round_seconds'])}
        for name,value in record.get('communication',{}).items():
            values['communication/'+name] = number(value)
        runs['server'].append((index,values))
    return runs


class EventSink:
    def __init__(self, folder):
        from tensorboard.compat.proto import event_pb2, summary_pb2
        from tensorboard.summary.writer.record_writer import RecordWriter
        self.Event,self.Summary,self.Metadata = event_pb2.Event,summary_pb2.Summary,summary_pb2.SummaryMetadata
        self.RecordWriter = RecordWriter
        self.folder,self.writers = folder,{}

    def open_writer(self, run):
        folder = self.folder/run
        folder.mkdir(parents=True,exist_ok=True)
        name = 'events.out.tfevents.'+str(time.time_ns())
        previous = max((path.name for path in folder.glob('events.out.tfevents.*')),default='')
        if name<=previous: name=previous+'.next'
        writer = self.RecordWriter((folder/name).open('xb'))
        writer.write(self.Event(wall_time=time.time(),file_version='brain.Event:2').SerializeToString())
        return writer

    def write(self, run, index, values, description):
        if run not in self.writers:
            self.writers[run] = self.open_writer(run)
        summary = self.Summary(value=[self.Summary.Value(tag=tag,simple_value=value,
                    metadata=self.Metadata(summary_description=description,
                        plugin_data=self.Metadata.PluginData(plugin_name='scalars'))) for tag,value in values.items()])
        self.writers[run].write(self.Event(wall_time=time.time(),step=index,summary=summary).SerializeToString())
        self.writers[run].flush()

    def start_run(self, run):
        self.writers[run] = self.open_writer(run)
        # Tell TensorBoard to purge cached steps from the previous run in this slot.
        from tensorboard.compat.proto.event_pb2 import SessionLog
        self.writers[run].write(self.Event(wall_time=time.time(),step=0,
                                session_log=SessionLog(status=SessionLog.START)).SerializeToString())
        self.writers[run].flush()

    def reset(self, run):
        writer = self.writers.pop(run,None)
        if writer is not None: writer.close()

    def close(self):
        for writer in self.writers.values(): writer.close()


class Collector:
    def __init__(self, root, sink=None):
        self.root = Path(root).resolve()
        self.output = self.root/'reports/tensorboard'
        self.runtime = self.root/'runtime/tensorboard'
        self.output.mkdir(parents=True,exist_ok=True)
        self.runtime.mkdir(parents=True,exist_ok=True)
        self.state_path = self.runtime/'index.json'
        self.state = read(self.state_path) if self.state_path.exists() else {'runs':{}}
        self.sink = sink if sink is not None else EventSink(self.output)
        if self.state.get('retention')!=RETENTION:
            # One-time migration from historical hashed folders to seven fixed slots.
            remove_event_tree(self.root,self.output)
            self.output.mkdir(parents=True,exist_ok=True)
            self.state = {'retention':RETENTION,'runs':{}}
            atomic_json(self.state_path,self.state)
        # Before the viewer starts reading, remove empty compatibility files from old rotations.
        for run in SLOTS:
            folder = self.output/run
            if folder.exists():
                validate_event_tree(self.root,folder)
                for path in folder.glob('events.out.tfevents.*'):
                    if path.stat().st_size==0: path.unlink()

    def emit(self, run, points, metadata):
        if run not in SLOTS:
            raise ValueError('Unknown latest-run slot')
        created = run not in self.state['runs']
        saved = self.state['runs'].get(run)
        replaced = saved is not None and saved['metadata']['run_id']!=metadata['run_id']
        if created or replaced:
            self.sink.reset(run)
            folder = self.output/run
            if replaced and folder.exists():
                validate_event_tree(self.root,folder)
                if any(path.is_dir() for path in folder.iterdir()):
                    raise ValueError('Unexpected subdirectory in current TensorBoard slot')
                for path in folder.glob('events.out.tfevents.*'):
                    # Keep empty filenames until restart: a cached reader must reach EOF
                    # before advancing to the new file and its SessionLog.START marker.
                    with path.open('wb'): pass
                (folder/'source.json').unlink(missing_ok=True)
            else:
                remove_event_tree(self.root,folder)
            self.sink.start_run(run)
            saved = {'points':{},'metadata':metadata}
        elif len(points)<len(saved['points']):
            raise ValueError('History shrank without a new run ID')
        new = []
        for index,values in points:
            key = str(index)
            if key in saved['points']:
                if saved['points'][key] != values:
                    raise ValueError('Existing scalar history changed; refusing to mix runs')
            else: new.append((index,values))
        # Validate every point before emitting any part of this source.
        for index,values in new:
            self.sink.write(run,index,values,metadata['description'])
            saved['points'][str(index)] = values
        self.state['runs'][run] = saved
        folder = self.output/run
        folder.mkdir(parents=True,exist_ok=True)
        if not (folder/'source.json').exists(): atomic_json(folder/'source.json',metadata)
        if new or created or replaced:
            atomic_json(self.state_path,self.state)

    def sync(self):
        errors = []
        sources = [('local',node,path+'/metrics.json') for node,path in BASELINES.items()]
        for node in BASELINES:
            directory = self.root/('reports/node-'+node.lower()+'/training')
            sources += [('live',node,path.relative_to(self.root).as_posix())
                        for path in directory.glob('*.json') if re.fullmatch(r'[0-9a-f]{32}\.json',path.name)]
        candidates = {node:[] for node in BASELINES}
        for kind,node,relative in sources:
            if not (self.root/relative).exists(): continue
            try:
                report = safe_read(self.root,relative)
                if kind=='live' and (report.get('schema_version')!='local-training-v1' or report.get('node')!=node
                                     or Path(relative).stem!=report.get('run_id')):
                    raise ValueError('Local telemetry identity differs')
                run_id = report['run_id'] if kind=='live' else report.get('telemetry_run_id')
                if not run_id:
                    run_id = 'historical-'+identifier(json.dumps(report,sort_keys=True))
                # Choose the most recently started run, not an older file touched later.
                time_text = report.get('started_at_utc' if kind=='live' else 'created_at_utc')
                timestamp = datetime.fromisoformat(time_text.replace('Z','+00:00')).timestamp() if time_text else (self.root/relative).stat().st_mtime
                description = ('Local baseline; x=epoch; validation of local model. '+
                               'Wall time is export observation, not original training time. '+
                               'Imported from existing metrics.json.' if kind=='local' and not report.get('telemetry_run_id') else
                               'Local training; x=epoch; validation of local model. Wall time is export observation.')
                candidates[node].append((timestamp,kind=='local',local_points(report),
                    {'source':relative,'kind':kind,'axis':'epoch','run_id':str(run_id),
                     'node':node,'description':description,'test_used':False}))
            except (OSError,ValueError,KeyError,TypeError) as error:
                errors.append(relative+': '+str(error))
        for node,choices in candidates.items():
            if not choices: continue
            # A published report and live telemetry with the same run ID share one slot.
            by_id = {}
            for choice in choices:
                identity = choice[3]['run_id']
                by_id.setdefault(identity,[]).append(choice)
            grouped = []
            for group in by_id.values():
                common = min(len(item[2]) for item in group)
                if any(item[2][:common]!=group[0][2][:common] for item in group):
                    errors.append('Local model/live telemetry disagree for node '+node)
                    continue
                preferred = max(group,key=lambda item:(item[1],item[0]))
                started = min(item[0] for item in group if item[3]['kind']=='live') if any(item[3]['kind']=='live' for item in group) else preferred[0]
                grouped.append((started,*preferred[1:]))
            if not grouped: continue
            latest = max(grouped,key=lambda item:item[:2])
            try:self.emit('local/node-'+node.lower(),latest[2],latest[3])
            except (OSError,ValueError,KeyError,TypeError) as error:
                errors.append(latest[3]['source']+': '+str(error))
        relative = 'reports/fl/training.json'
        if (self.root/relative).exists():
            try:
                report = safe_read(self.root,relative)
                run_id = report.get('telemetry_run_id')
                if not run_id:
                    receipt = safe_read(self.root,'reports/fl/last-submission.json')
                    if report.get('rounds_requested') != receipt.get('requested-rounds'):
                        raise ValueError('Historical FL report/receipt rounds differ')
                    run_id = 'historical-'+str(receipt['run-id'])
                for node,points in federated_points(report).items():
                    run = 'federated/'+('server' if node=='server' else 'node-'+node.lower())
                    self.emit(run,points,{'source':relative,'kind':'federated','axis':'round','node':node,
                        'run_id':str(run_id),
                        'description':'FL; x=server round; train=local update loss; validation=aggregated Global model. '+
                                      'Wall time is export observation. Not test evaluation or a convergence claim.',
                        'test_used':False})
            except (OSError,ValueError,KeyError,TypeError) as error:
                errors.append(relative+': '+str(error))
        status = {'pid':os.getpid(),'updated_at':time.time(),'status':'running',
                  'retention':RETENTION,
                  'run_count':len(self.state['runs']),'errors':errors,
                  'scalar_steps':sum(len(item['points']) for item in self.state['runs'].values()),
                  'training_started':False,'datasets_read':False}
        atomic_json(self.runtime/'status.json',status)
        return status

    def close(self):
        self.sink.close()


class CollectorLock:
    """OS-released file lock; a crashed exporter leaves no stale directory lock."""
    def __init__(self, path): self.path = path
    def __enter__(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        self.stream = self.path.open('a+b')
        try:
            if self.path.stat().st_size==0:
                self.stream.write(b'0'); self.stream.flush()
            self.stream.seek(0)
            if os.name=='nt':
                import msvcrt
                msvcrt.locking(self.stream.fileno(),msvcrt.LK_NBLCK,1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:
            self.stream.close()
            raise RuntimeError('TensorBoard exporter is already running')
        return self
    def __exit__(self,*unused):
        try:
            if os.name=='nt':
                import msvcrt
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(),msvcrt.LK_UNLCK,1)
        finally:self.stream.close()
