"""Freeze global/local models and evaluate the held-out test of each node offline."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import subprocess
import tempfile

from check_fl_inputs import check as preflight, check_weights, inside, sha

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'ddos-fl-laptop-fl:step1'


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)


def file_hashes(folder):
    return {path.name: sha(path) for path in folder.iterdir() if path.is_file()}


def freeze():
    for name in ('.server-run-lock', '.submission-lock'):
        require(not (ROOT/'reports/fl'/name).exists(), 'FL run/submission is active')
    checked = preflight(ROOT, 'config/fl/fedavg.json')
    config = read(ROOT/'config/fl/fedavg.json')
    state = read(ROOT/'reports/fl/training.json')
    receipt = read(ROOT/'reports/fl/last-submission.json')
    folder = inside(ROOT, config['global_model_output'], 'models/fl')
    meta, report = read(folder/'model.json'), read(folder/'metrics.json')
    require(state['status'] == 'complete' and state['completed_rounds'] == state['rounds_requested'] == receipt['requested-rounds'], 'Latest run is incomplete')
    require(state['history'] == report['history'] and state['config_sha256'] == report['config_sha256'] == checked['config_sha256'], 'Training provenance differs')
    best = max(state['history'], key=lambda item: item['validation_summary']['balanced-accuracy-macro-node'])
    require(meta['selected_round'] == report['selected_round'] == state['selected_round'] == best['round'], 'Checkpoint was not selected by validation')
    require(sha(folder/'weights.npz') == meta['weights_sha256'] == state['weights_sha256'], 'Global weights differ')
    check_weights(folder/'weights.npz', config['model'])
    require(meta['threshold'] == config['model']['threshold'] == .5 and report['test_evaluated'] is False, 'Frozen training/test contract differs')
    for name, digest in report['artifacts'].items():
        require(Path(name).name == name and sha(folder/name) == digest, 'Global artifact hash differs')
    nodes = {}
    for node, spec in config['clients'].items():
        manifest = read(ROOT/spec['manifest_path'])
        local_folder = ROOT/spec['baseline_model_dir']
        local_meta = read(local_folder/'model.json')
        test = manifest['artifacts']['test']
        require(test['path'] == 'data/node-'+node.lower()+'/work/splits/pilot-v1/test.csv', 'Foreign test path')
        require(local_meta['threshold'] == .5, 'Baseline threshold differs')
        nodes[node] = {'manifest_path': spec['manifest_path'], 'manifest_sha256': spec['manifest_sha256'],
                       'test': test, 'local': {'path': spec['baseline_model_dir'],
                       'files': file_hashes(local_folder), 'weights_sha256': spec['baseline_weights_sha256'],
                       'threshold': local_meta['threshold']}}
    return {'frozen_at_utc': datetime.now(timezone.utc).isoformat(), 'run_id': str(receipt['run-id']),
            'selected_round': meta['selected_round'], 'config_sha256': checked['config_sha256'],
            'global': {'path': config['global_model_output'], 'files': file_hashes(folder),
                       'weights_sha256': meta['weights_sha256'], 'threshold': meta['threshold']},
            'nodes': nodes, 'selection': 'Mean node validation balanced accuracy; earliest tie',
            'threshold_tuning': False, 'fitting': False,
            'scope': 'Plan sealed before test scoring; existing local/global training budgets differ'}


def verify_sources(plan):
    require(sha(ROOT/'config/fl/fedavg.json') == plan['config_sha256'], 'Config changed')
    for model in [plan['global'], *[item['local'] for item in plan['nodes'].values()]]:
        require(file_hashes(ROOT/model['path']) == model['files'], 'Frozen model files changed')
    for node in plan['nodes'].values():
        require(sha(ROOT/node['manifest_path']) == node['manifest_sha256'], 'Manifest changed')
        require(sha(ROOT/node['test']['path']) == node['test']['sha256'], 'Test changed')


def evaluate_node(node, plan, destination):
    spec = plan['nodes'][node]
    own = 'data/node-'+node.lower()+'/work/splits/pilot-v1/'
    output = destination/('node-'+node.lower())
    output.mkdir()
    mounts = [('fl','/app/fl'), ('scripts','/app/scripts'), ('config/fl','/app/config/fl'),
              (own+'manifest.json','/app/'+own+'manifest.json'),
              (own+'test.csv','/app/'+own+'test.csv'),
              (plan['global']['path'],'/model/global'), (spec['local']['path'],'/model/local')]
    command = ['docker','run','--rm','--network','none','--memory','768m','--cpus','0.75',
               '--read-only','--tmpfs','/tmp','--cap-drop','ALL','--security-opt','no-new-privileges']
    for source, target in mounts:
        command += ['--mount','type=bind,source='+str(ROOT/source)+',target='+target+',readonly']
    command += ['--mount','type=bind,source='+str(destination/'plan.json')+',target=/evaluation-plan.json,readonly',
                '--mount','type=bind,source='+str(output)+',target=/output', IMAGE,
                'python3','-B','/app/fl/evaluate_test.py','--node',node.lower()]
    response = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                              encoding='utf-8', errors='replace', timeout=180)
    if response.returncode:
        raise RuntimeError(node+': '+response.stdout+response.stderr)
    return read(output/'metrics.json')


def counts_metrics(counts):
    tn, fp, fn, tp = counts
    divide = lambda a,b: a/b if b else 0.0
    f1_attack = divide(2*tp, 2*tp+fp+fn)
    return {'accuracy': divide(tn+tp, sum(counts)), 'precision_attack': divide(tp,tp+fp),
            'recall_attack': divide(tp,tp+fn), 'f1_attack': f1_attack,
            'f1_macro': (f1_attack+divide(2*tn,2*tn+fp+fn))/2,
            'false_positive_rate': divide(fp,tn+fp),
            'balanced_accuracy': (divide(tp,tp+fn)+divide(tn,tn+fp))/2,
            'rows': sum(counts), 'confusion_matrix_labels': ['benign','attack'],
            'confusion_matrix': [[tn,fp],[fn,tp]]}


def verify_output(destination, plan):
    reports = {}
    for node, spec in plan['nodes'].items():
        folder = destination/('node-'+node.lower())
        report = read(folder/'metrics.json')
        require(report['node'] == node and report['partition'] == 'test' and report['selected_round'] == plan['selected_round']
                and report['run_id'] == plan['run_id'] and all(report['checks'].values()), 'Evaluation contract differs')
        require(report['test_csv_sha256'] == spec['test']['sha256'] and report['manifest_sha256'] == spec['manifest_sha256'], 'Evaluated input differs')
        require(sha(folder/'predictions.csv') == report['artifacts']['predictions.csv'], 'Predictions hash differs')
        counts = {name:[0,0,0,0] for name in ('global','local')}
        identities, labels = set(), {'benign':0,'attack':0}
        with (folder/'predictions.csv').open(encoding='utf-8', newline='') as stream:
            for index, row in enumerate(csv.DictReader(stream)):
                require(int(row['test_row_index']) == index and row['row_uid'] not in identities, 'Duplicate/out-of-order prediction')
                identities.add(row['row_uid'])
                y = int(row['true_label'])
                require(y in (0,1), 'Invalid test label')
                labels['attack' if y else 'benign'] += 1
                for name in ('global','local'):
                    probability = float(row[name+'_probability_attack'])
                    predicted = int(row[name+'_predicted_label'])
                    require(math.isfinite(probability) and 0<=probability<=1 and predicted == int(probability>=.5), 'Prediction/threshold mismatch')
                    counts[name][2*y+predicted] += 1
        require(labels == spec['test']['label_counts'] == report['label_counts'] and len(identities) == spec['test']['rows'] == report['rows'], 'Test counts differ')
        for name in ('global','local'):
            expected = plan['global'] if name == 'global' else spec['local']
            actual = report['models'][name]
            require(actual['weights_sha256'] == expected['weights_sha256'] and actual['threshold'] == expected['threshold'], 'Evaluated model differs')
            for key, value in counts_metrics(counts[name]).items():
                require(abs(actual[key]-value) <= 1e-12 if isinstance(value,float) else actual[key] == value, 'Metrics disagree with predictions: '+key)
        reports[node] = report
    return reports


def aggregate(reports, model):
    counts = [0,0,0,0]
    for report in reports.values():
        matrix = report['models'][model]['confusion_matrix']
        counts = [left+right for left,right in zip(counts, [*matrix[0],*matrix[1]])]
    return {'pooled': counts_metrics(counts), 'macro_node': {
        key: sum(report['models'][model][key] for report in reports.values())/len(reports)
        for key in ('balanced_accuracy','recall_attack','f1_macro','false_positive_rate')}}


def write_comparison(destination, summary):
    columns = ['node','model','rows','precision_attack','recall_attack','f1_attack','f1_macro',
               'balanced_accuracy','false_positive_rate','accuracy','tn','fp','fn','tp','weights_sha256','threshold']
    lines = ['# Đánh giá test global và local', '',
             'Checkpoint global: vòng '+str(summary['selected_round'])+'; Flower run '+summary['run_id']+'.',
             'Global weights SHA256: `'+summary['global_weights_sha256']+'`.', '',
             'Đã hoàn tất chấm test bằng weights và threshold 0,5 cố định. Kết quả này không xác nhận chất lượng triển khai.',
             'Ba baseline local được chấm trên đúng các dòng test tương ứng; lượng huấn luyện local/global khác nhau.', '',
             '| Node | Model | Dòng test | Precision attack | Recall attack | F1 attack | F1 macro | Balanced accuracy | FPR |',
             '|---|---|---:|---:|---:|---:|---:|---:|---:|']
    with (destination/'comparison.csv').open('x', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for node, report in summary['nodes'].items():
            for model, metrics in report['models'].items():
                matrix = metrics['confusion_matrix']
                row = {'node':node,'model':model, **{key:metrics[key] for key in columns if key in metrics},
                       'tn':matrix[0][0],'fp':matrix[0][1],'fn':matrix[1][0],'tp':matrix[1][1]}
                writer.writerow(row)
                values = [node,model,str(report['rows']), *[f"{100*metrics[key]:.2f}%" for key in
                          ('precision_attack','recall_attack','f1_attack','f1_macro','balanced_accuracy','false_positive_rate')]]
                lines.append('| '+' | '.join(values)+' |')
    lines += ['', '## Confusion matrix', '',
              'Hàng là nhãn thật, cột là dự đoán; thứ tự cả hai là `[benign, attack]`: `[[TN, FP], [FN, TP]]`.', '',
              '| Node | Model | TN | FP | FN | TP |', '|---|---|---:|---:|---:|---:|']
    for node, report in summary['nodes'].items():
        for model, metrics in report['models'].items():
            matrix = metrics['confusion_matrix']
            lines.append('| '+' | '.join([node,model,*map(str,[*matrix[0],*matrix[1]])])+' |')
    lines += ['', '## Phạm vi kết quả', '',
              '- Các file predictions.csv chứa nhãn thật cùng probability/prediction global và local trên từng dòng.',
              '- Pooled trong summary.json cộng confusion counts; macro_node lấy trung bình từng node. Hai số có ý nghĩa khác nhau.',
              '- Aggregate local là kết quả gộp của ba model local, mỗi model chấm node của mình; không phải một model local duy nhất.',
              '- Test thuộc các recording pilot đã có; A/C từng được xem trong phát triển local. Đây không phải đánh giá trên recording/ngày độc lập.',
              '- A/C có ít benign; cần đọc FP và tổng benign cùng FPR. Không chọn lại checkpoint, threshold hoặc sửa model theo kết quả test này.',
              '- Metadata test_evaluated trong bộ model mô tả giai đoạn train, được giữ nguyên. summary.json của job này ghi test_evaluated: true.', '']
    with (destination/'REPORT.md').open('x', encoding='utf-8') as stream:
        stream.write('\n'.join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='reports/fl/test-evaluation')
    parser.add_argument('--verify', action='store_true', help='Verify existing reports and frozen source hashes without rescoring')
    args = parser.parse_args()
    try:
        output = inside(ROOT, args.output, 'reports/fl')
        require(output != (ROOT/'reports/fl').resolve(), 'Choose a report subdirectory')
        if args.verify:
            summary = read(output/'summary.json')
            plan = read(output/'plan.json')
            verify_sources(plan)
            reports = verify_output(output, plan)
            require(summary['nodes'] == reports and summary['selected_round'] == plan['selected_round']
                    and summary['run_id'] == plan['run_id'] and summary['global_weights_sha256'] == plan['global']['weights_sha256'],
                    'Summary provenance/nodes differ')
            for model in ('global','local'):
                require(summary['aggregate'][model] == aggregate(reports,model), 'Summary aggregate differs')
            for path, digest in summary['artifacts'].items():
                require(sha(inside(output,path,'.')) == digest, 'Report artifact differs')
            print(json.dumps({'result':'PASS frozen test evaluation artifacts','selected_round':plan['selected_round'],
                              'global_weights_sha256':plan['global']['weights_sha256'],'rescoring':False},indent=2))
            return
        require(not output.exists(), 'Output already exists; use --verify to inspect the saved evaluation')
        plan = freeze()
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.test-evaluation-', dir=output.parent) as temporary:
            prepared = Path(temporary)
            write(prepared/'plan.json', plan)
            with ThreadPoolExecutor(max_workers=3) as executor:
                list(executor.map(lambda node:evaluate_node(node,plan,prepared), ('A','B','C')))
            verify_sources(plan)
            reports = verify_output(prepared,plan)
            summary = {'result':'COMPLETE frozen global/local test evaluation',
                       'evaluated_at_utc':datetime.now(timezone.utc).isoformat(),
                       'run_id':plan['run_id'],'selected_round':plan['selected_round'],
                       'global_weights_sha256':plan['global']['weights_sha256'],
                       'nodes':reports,'aggregate':{model:aggregate(reports,model) for model in ('global','local')},
                       'checks':{'source_hashes_unchanged':True,'metrics_independently_recomputed_from_predictions':True,
                                 'no_fitting_or_threshold_tuning':True,'checkpoint_selected_before_test':True},
                       'test_evaluated':True,
                       'limitations':['Same pilot recordings; test partitions are not independent capture days.',
                                      'A/C test sets have been inspected previously during local development.',
                                      'Local/global training budgets differ; this comparison does not isolate the benefit of FL.',
                                      'No convergence, live attack or deployment quality claim.']}
            write_comparison(prepared, summary)
            summary['artifacts'] = {str(path.relative_to(prepared)).replace('\\','/'):sha(path)
                                    for path in prepared.rglob('*') if path.is_file()}
            write(prepared/'summary.json',summary)
            prepared.rename(output)
        print(json.dumps(summary,indent=2))
    except (ValueError,OSError,KeyError,RuntimeError,subprocess.SubprocessError) as error:
        parser.exit(1,'FAIL frozen test evaluation: '+str(error)+'\n')


if __name__ == '__main__':
    main()
