"""Node-isolated test orchestration; host uses stdlib, worker reuses fl/evaluate_test.py."""
import csv
import hashlib
import json
import math
import os
import stat
import subprocess
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from itertools import zip_longest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from check_fl_inputs import check_weights
from evaluate_fl_test import verify_output
from flow_features import FEATURES, SCHEMA
from score_attack_test import attack_rows

IMAGE = 'ddos-fl-laptop-fl:step1'
MODEL_FILES = ('model.json', 'weights.npz', 'metrics.json')


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for part in iter(lambda: stream.read(1024*1024), b''):
            digest.update(part)
    return digest.hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def write_new(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write('\n')


def inside(root, relative, prefix):
    relative = Path(relative)
    require(not relative.is_absolute() and '..' not in relative.parts, 'Expected a project-relative path')
    result = (root/relative).resolve()
    require(result.is_relative_to(root.resolve()) and result.is_relative_to((root/prefix).absolute()),
            'Path outside selected node scope')
    return result


def assert_fl_idle(root):
    for name in ('.server-run-lock', '.submission-lock'):
        require(not (root/'reports/fl'/name).exists(), 'FL đang chạy/submit; đợi trước khi test dataset')


def freeze_test(root, node, config):
    require(node in ('a', 'b', 'c'), 'Unsupported node')
    upper, own = node.upper(), 'data/node-'+node+'/work/splits/pilot-v1/'
    spec = config['clients'][upper]
    require(spec['manifest_path'] == own+'manifest.json', 'Foreign manifest path')
    manifest_path = inside(root, spec['manifest_path'], own)
    require(sha(manifest_path) == spec['manifest_sha256'], 'Manifest hash differs')
    manifest = read(manifest_path)
    require(manifest['node_id'] == upper and manifest['features'] == FEATURES
            and manifest['schema_version'] == SCHEMA, 'Test feature contract differs')
    require(manifest['checks'] and all(value is True for value in manifest['checks'].values()), 'Split checks failed')
    artifact = manifest['artifacts']['test']
    require(artifact['path'] == own+'test.csv', 'Only own test.csv is allowed')
    test = inside(root, artifact['path'], own)
    require(sha(test) == artifact['sha256'], 'Test hash differs')
    return {'manifest_path': spec['manifest_path'], 'manifest_sha256': spec['manifest_sha256'],
            'test': artifact}


def freeze_node(root, node):
    require(node in ('a', 'b', 'c'), 'Unsupported node')
    assert_fl_idle(root)
    upper = node.upper()
    config_path = root/'config/fl/fedavg.json'
    config = read(config_path)
    spec, contract = config['clients'][upper], config['model']
    frozen_test = freeze_test(root, node, config)
    require(config['global_model_output'] == 'models/fl/current', 'Unexpected global model path')
    global_dir = inside(root, config['global_model_output'], 'models/fl')
    local_dir = inside(root, spec['baseline_model_dir'], 'models/node-'+node)
    global_meta, global_metrics = read(global_dir/'model.json'), read(global_dir/'metrics.json')
    local_meta, local_metrics = read(local_dir/'model.json'), read(local_dir/'metrics.json')
    state, receipt = read(root/'reports/fl/training.json'), read(root/'reports/fl/last-submission.json')
    config_sha = sha(config_path)
    require(state['status'] == 'complete' and state['completed_rounds'] == state['rounds_requested']
            == receipt['requested-rounds'] == len(state['history']), 'Latest FL run is incomplete')
    require(state['history'] == global_metrics['history'] and state['config_sha256']
            == global_metrics['config_sha256'] == config_sha, 'Global training provenance differs')
    best = max(state['history'], key=lambda item:item['validation_summary']['balanced-accuracy-macro-node'])
    require(global_meta['selected_round'] == global_metrics['selected_round'] == state['selected_round']
            == best['round'], 'Checkpoint must be selected by validation before testing')
    require(global_metrics['test_evaluated'] is False, 'Training/test contract differs')
    require(local_metrics['manifest_sha256'] == spec['manifest_sha256'], 'Local model/split provenance differs')
    for folder, meta in ((global_dir, global_meta), (local_dir, local_meta)):
        require(sha(folder/'weights.npz') == meta['weights_sha256'], 'Model weights hash differs')
        for field in ('schema_version','features','transform','input_width','hidden_layer_sizes',
                      'activation','output_activation','threshold'):
            require(meta[field] == contract[field], 'Model contract differs: '+field)
        require(meta['threshold'] == .5, 'Threshold must remain frozen at 0.5')
        check_weights(folder/'weights.npz', contract)
    require(local_meta['weights_sha256'] == spec['baseline_weights_sha256'], 'Pinned local baseline differs')
    require(global_meta['weights_sha256'] == state['weights_sha256'], 'Global state/weights differ')
    for folder, report in ((global_dir,global_metrics),(local_dir,local_metrics)):
        for name, digest in report.get('artifacts', {}).items():
            require(Path(name).name == name, 'Invalid model artifact filename')
            # Verify model metadata/weights, not historical prediction CSVs.
            if name in MODEL_FILES:
                require(sha(folder/name) == digest, 'Model artifact hash differs')
    # Record only selected-node input and model files. Never open other nodes or train/validation.
    model_spec = lambda path,meta: {'path': path.relative_to(root).as_posix(),
                                  'files': {name:sha(path/name) for name in MODEL_FILES},
                                  'weights_sha256':meta['weights_sha256'], 'threshold':meta['threshold']}
    return {'frozen_at_utc':datetime.now(timezone.utc).isoformat(), 'run_id':str(receipt['run-id']),
            'selected_round':global_meta['selected_round'], 'config_sha256':config_sha,
            'global':model_spec(global_dir,global_meta),
            'nodes':{upper:{**frozen_test, 'local':model_spec(local_dir,local_meta)}},
            'fitting':False,'threshold_tuning':False,
            'scope':'One existing held-out pilot partition; same rows for local/global; not independent recording'}


def verify_sources(root, plan):
    assert_fl_idle(root)
    require(sha(root/'config/fl/fedavg.json') == plan['config_sha256'], 'Config changed during test')
    for model in [plan['global'], *[spec['local'] for spec in plan['nodes'].values()]]:
        for name, digest in model['files'].items():
            require(sha(root/model['path']/name) == digest, 'Frozen model changed during test')
    for spec in plan['nodes'].values():
        require(sha(root/spec['manifest_path']) == spec['manifest_sha256'], 'Manifest changed during test')
        require(sha(root/spec['test']['path']) == spec['test']['sha256'], 'Test changed during scoring')


def worker_command(root, node, destination, plan, name):
    own = 'data/node-'+node+'/work/splits/pilot-v1/'
    output = destination/('node-'+node)
    output.mkdir()
    command = ['docker','run','--rm','--pull','never','--name',name,'--network','none',
               '--memory','768m','--cpus','0.75','--read-only','--tmpfs','/tmp','--cap-drop','ALL',
               '--security-opt','no-new-privileges']
    mounts = [('fl','/app/fl'),('scripts','/app/scripts'),('config/fl','/app/config/fl'),
              (own+'test.csv','/app/'+own+'test.csv'),(own+'manifest.json','/app/'+own+'manifest.json')]
    for model, target in ((plan['global'],'/model/global'),(plan['nodes'][node.upper()]['local'],'/model/local')):
        mounts.extend((model['path']+'/'+filename,target+'/'+filename) for filename in MODEL_FILES)
    for source,target in mounts:
        command += ['--mount','type=bind,source='+str(root/source)+',target='+target+',readonly']
    command += ['--mount','type=bind,source='+str(destination/'plan.json')+',target=/evaluation-plan.json,readonly',
                '--mount','type=bind,source='+str(output)+',target=/output', IMAGE,
                'python3','-B','/app/fl/evaluate_test.py','--node',node]
    return command


def verify_row_identity(root, plan, node, destination):
    spec = plan['nodes'][node.upper()]
    predictions = destination/('node-'+node)/'predictions.csv'
    with (root/spec['test']['path']).open(encoding='utf-8-sig', newline='') as source, \
         predictions.open(encoding='utf-8-sig', newline='') as output:
        for original, scored in zip_longest(csv.DictReader(source), csv.DictReader(output)):
            require(original is not None and scored is not None, 'Prediction/source row count differs')
            require(original['label'] in ('benign','attack'), 'Invalid source label')
            require(original['row_uid'] == scored['row_uid']
                    and int(scored['true_label']) == int(original['label']=='attack'),
                    'Prediction/source identities or labels differ')


@contextmanager
def evaluation_lock(root, job_folder, node):
    require(job_folder.is_relative_to((root/'reports/dashboard/sessions').resolve()),
            'Unexpected report destination')
    lock = root/'runtime/dashboard/.dataset-evaluation-lock'
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        lock.mkdir()
    except FileExistsError:
        raise ValueError('Một job dataset đang giữ lock; kiểm tra job trước khi chạy lại')
    try:
        write_new(lock/'owner.json', {'job': job_folder.name, 'node': node})
        yield
    finally:
        # Windows can briefly hold a handle after the lock metadata is closed.
        for attempt in range(5):
            try:
                (lock/'owner.json').unlink(missing_ok=True)
                lock.rmdir()
                break
            except PermissionError:
                if attempt == 4:
                    raise
                if os.name == 'nt' and lock.exists() and not lock.is_symlink():
                    # Windows may leave the now-empty lock directory marked read-only.
                    lock.chmod(stat.S_IWRITE)
                time.sleep(.1)


def execute_worker(execute, command, name):
    try:
        execute(command)
    except subprocess.TimeoutExpired:
        # Only this job's fixed-name ephemeral worker, never lab services.
        try:
            execute(['docker', 'rm', '-f', name])
        except Exception:
            pass
        raise


def evaluate(root, node, job_folder, execute, progress=lambda message:None):
    root = Path(root).resolve()
    job_folder = Path(job_folder).resolve()
    with evaluation_lock(root, job_folder, node):
        progress('Đang kiểm và đóng băng hash test/model…')
        plan = freeze_node(root,node)
        destination = job_folder/'dataset'
        destination.mkdir()
        write_new(destination/'plan.json',plan)
        name='ddos-fl-laptop-dataset-'+uuid.uuid4().hex[:12]
        progress('Đang chấm toàn bộ test bằng Local và Global trong container network none…')
        execute_worker(execute, worker_command(root,node,destination,plan,name), name)
        progress('Đang đếm lại confusion matrix và đối chiếu từng nhãn/row_uid…')
        verify_sources(root,plan)
        reports = verify_output(destination,plan)  # existing independent metric recount
        verify_row_identity(root,plan,node,destination)
        summary={'result':'COMPLETE node dataset evaluation','kind':'dataset_evaluation',
                 'node':node.upper(),'evaluated_at_utc':datetime.now(timezone.utc).isoformat(),
                 'run_id':plan['run_id'],'selected_round':plan['selected_round'],
                 'global_weights_sha256':plan['global']['weights_sha256'],'nodes':reports,
                 'checks':{'same_rows_for_local_global':True,'row_labels_and_identities_verified':True,
                           'metrics_recounted_from_predictions':True,'sources_unchanged':True,
                           'no_fitting_or_threshold_tuning':True},
                 'limitations':['Same pilot recordings, not an independent capture day.',
                                'Local/global training budgets differ.',
                                'Previously inspected test partition; no new generalization claim.']}
        report=reports[node.upper()]
        with (destination/'comparison.csv').open('x',encoding='utf-8',newline='') as stream:
            fields=['node','model','rows','recall_attack','precision_attack','f1_attack','balanced_accuracy','false_positive_rate','weights_sha256']
            writer=csv.DictWriter(stream,fieldnames=fields)
            writer.writeheader()
            for model in ('local','global'):
                writer.writerow({'node':node.upper(),'model':model,'rows':report['rows'],
                                 **{key:report['models'][model][key] for key in fields[3:]}})
        summary['artifacts']={path.relative_to(destination).as_posix():sha(path)
                              for path in destination.rglob('*') if path.is_file()}
        verify_sources(root,plan)
        write_new(destination/'summary.json',summary)
        progress('Hoàn tất đánh giá dataset; model và dữ liệu giữ nguyên')
        return summary


def cross_predictions(path, test_path, models):
    detected = dict.fromkeys(models, 0)
    rows = 0
    with path.open(encoding='utf-8', newline='') as stream:
        for original, scored in zip_longest(attack_rows(test_path), csv.DictReader(stream)):
            require(original is not None and scored is not None, 'Attack prediction count differs')
            index, row = original
            require(int(scored['test_row_index']) == index and scored['row_uid'] == row['row_uid']
                    and scored['true_label'] == '1', 'Attack prediction identity or label differs')
            for mode, model in models.items():
                probability = float(scored[mode+'_probability_attack'])
                label = int(scored[mode+'_predicted_label'])
                require(0 <= probability <= 1 and label == int(probability >= model['threshold']),
                        'Prediction differs from frozen threshold')
                detected[mode] += label
            rows += 1
    require(rows > 0, 'Tập test nguồn không có mẫu attack')
    return rows, {mode: {**model, 'tp': detected[mode], 'fn': rows-detected[mode],
                        'recall_attack': detected[mode]/rows}
                  for mode, model in models.items()}


def evaluate_cross(root, target, source, job_folder, execute, progress=lambda message: None):
    root, job_folder = Path(root).resolve(), Path(job_folder).resolve()
    require(target in ('a', 'b', 'c') and source in ('a', 'b', 'c') and target != source,
            'Node nguồn và đích phải khác nhau')
    with evaluation_lock(root, job_folder, target):
        assert_fl_idle(root)
        progress('Đang kiểm tập test nguồn và hai model đích…')
        config_path = root/'config/fl/fedavg.json'
        config_digest = sha(config_path)
        config = read(config_path)
        source_spec = freeze_test(root, source, config)
        artifact = source_spec['test']
        require(artifact['label_counts'].get('attack', 0) > 0, 'Tập test nguồn không có mẫu attack')
        target_spec = config['clients'][target.upper()]
        require(config['global_model_output'] == 'models/fl/current', 'Unexpected global model path')
        folders = {'local': inside(root, target_spec['baseline_model_dir'], 'models/node-'+target),
                   'global': inside(root, 'models/fl/current', 'models/fl')}
        test_path = root/artifact['path']
        frozen = {config_path: config_digest,
                  root/source_spec['manifest_path']: source_spec['manifest_sha256'],
                  test_path: artifact['sha256']}
        mounts = [(root/'scripts', '/app'), (test_path, '/input/test.csv')]
        models = {}
        contract = config['model']
        for mode, folder in folders.items():
            meta_path = inside(root, (folder/'model.json').relative_to(root), folder.relative_to(root))
            weights = inside(root, (folder/'weights.npz').relative_to(root), folder.relative_to(root))
            frozen[meta_path], frozen[weights] = sha(meta_path), sha(weights)
            meta = read(meta_path)
            for field in ('schema_version', 'features', 'transform', 'input_width', 'hidden_layer_sizes',
                          'activation', 'output_activation', 'threshold'):
                require(meta[field] == contract[field], 'Model contract differs: '+field)
            require(meta['weights_sha256'] == frozen[weights], 'Model weights hash differs')
            if mode == 'local':
                require(frozen[weights] == target_spec['baseline_weights_sha256'],
                        'Pinned target local baseline differs')
            check_weights(weights, contract)
            models[mode] = {'id': meta.get('config', {}).get('experiment_id'),
                            'weights_sha256': frozen[weights], 'threshold': meta['threshold']}
            mounts.extend([(meta_path, '/model/'+mode+'/model.json'),
                           (weights, '/model/'+mode+'/weights.npz')])

        destination = job_folder/'dataset'
        destination.mkdir()
        name = 'ddos-fl-laptop-dataset-'+uuid.uuid4().hex[:12]
        command = ['docker', 'run', '--rm', '--pull', 'never', '--name', name, '--network', 'none',
                   '--memory', '768m', '--cpus', '0.75', '--read-only', '--tmpfs', '/tmp',
                   '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges']
        for source_file, container_file in mounts:
            command += ['--mount', f'type=bind,source={source_file},target={container_file},readonly']
        command += ['--mount', f'type=bind,source={destination},target=/output', IMAGE,
                    'python3', '-B', '/app/score_attack_test.py',
                    '--local-hash', models['local']['weights_sha256'],
                    '--global-hash', models['global']['weights_sha256']]
        progress(f'Đang chấm {source.upper()} → {target.upper()} bằng Local và Global…')
        execute_worker(execute, command, name)
        progress('Đang đối chiếu mẫu attack và đếm lại số phát hiện, bỏ sót…')
        predictions = destination/'predictions.csv'
        rows, results = cross_predictions(predictions, test_path, models)
        require(rows == artifact['label_counts']['attack'], 'Attack count differs from test manifest')
        assert_fl_idle(root)
        require(all(sha(path) == digest for path, digest in frozen.items()),
                'Dữ liệu hoặc model thay đổi trong lúc chấm')
        summary = {'kind': 'cross_attack_test', 'node': target.upper(), 'source_node': source.upper(),
                   'partition': 'test', 'true_label': 'attack', 'rows': rows, 'models': results,
                   'evaluated_at_utc': datetime.now(timezone.utc).isoformat(),
                   'test_csv_sha256': artifact['sha256'],
                   'manifest_sha256': source_spec['manifest_sha256'],
                   'config_sha256': config_digest,
                   'artifacts': {'predictions.csv': sha(predictions)}}
        write_new(destination/'summary.json', summary)
        return summary


def predictions_page(path, model='local', selection='all', page=1, size=50):
    require(model in ('local','global') and selection in ('all','benign','attack','fp','fn'), 'Invalid dataset filter')
    require(isinstance(page,int) and not isinstance(page,bool) and 1 <= page <= 1_000_000
            and isinstance(size,int) and 1 <= size <= 100, 'Invalid pagination')
    rows,total=[],0
    with path.open(encoding='utf-8-sig',newline='') as stream:
        for row in csv.DictReader(stream):
            truth,predicted=int(row['true_label']),int(row[model+'_predicted_label'])
            matches=(selection=='all' or (selection=='benign' and truth==0)
                     or (selection=='attack' and truth==1) or (selection=='fp' and truth==0 and predicted==1)
                     or (selection=='fn' and truth==1 and predicted==0))
            if not matches: continue
            if (page-1)*size <= total < page*size:
                rows.append({'index':int(row['test_row_index']),'row_uid':row['row_uid'],
                             'true_label':'attack' if truth else 'benign',
                             **{name: {'probability_attack':float(row[name+'_probability_attack']),
                                       'prediction':'attack' if int(row[name+'_predicted_label']) else 'benign'}
                                for name in ('local','global')}})
            total+=1
    return {'rows':rows,'total':total,'page':page,'size':size,'pages':max(1,math.ceil(total/size))}
