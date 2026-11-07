"""Train a local MLP, select by validation, then evaluate held-out test."""
import argparse
import copy
from contextlib import contextmanager
import csv
import hashlib
import json
import platform
import subprocess
import shutil
import tempfile
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import sklearn
from sklearn.metrics import (balanced_accuracy_score, confusion_matrix,
                             f1_score, precision_score, recall_score)
from sklearn.neural_network import MLPClassifier

# Use the same feature transform and portable predictor as live inference.
from flow_features import FEATURES, SCHEMA
from model_runtime import TRANSFORM, transform, predict_proba


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_split(root, artifact):
    path = root/artifact['path']
    if sha(path) != artifact['sha256']:
        raise ValueError('Split file hash mismatch: '+str(path))
    values, labels, identities = [], [], set()
    with path.open(encoding='utf-8', newline='') as stream:
        for row in csv.DictReader(stream):
            if row['schema_version'] != SCHEMA or row['label'] not in ('attack','benign'):
                raise ValueError('Unsupported schema/label')
            if row['row_uid'] in identities:
                raise ValueError('Duplicate row identity')
            identities.add(row['row_uid'])
            values.append([float(row[name]) for name in FEATURES])
            labels.append(int(row['label']=='attack'))
    if len(labels) != artifact['rows']:
        raise ValueError('Split row count differs')
    return np.asarray(values), np.asarray(labels)


def metrics(y, predicted):
    tn, fp, fn, tp = confusion_matrix(y, predicted, labels=[0,1]).ravel().tolist()
    return {'precision_attack':float(precision_score(y,predicted,zero_division=0)),
            'recall_attack':float(recall_score(y,predicted,zero_division=0)),
            'f1_attack':float(f1_score(y,predicted,zero_division=0)),
            'f1_macro':float(f1_score(y,predicted,average='macro',zero_division=0)),
            'balanced_accuracy':float(balanced_accuracy_score(y,predicted)),
            'false_positive_rate':fp/(fp+tn),
            'confusion_matrix_labels':['benign','attack'],
            'confusion_matrix':[[tn,fp],[fn,tp]],'rows':len(y)}


def build_sample_weights(raw, labels, mode):
    counts = np.bincount(labels, minlength=2)
    if len(counts) != 2 or (counts == 0).any():
        raise ValueError('Training requires both classes')
    n = len(labels)
    class_weights = n / (2 * counts)
    sample_weights = class_weights[labels].copy()
    details = {'mode': mode, 'fit_partition': 'train',
               'class_counts': counts.tolist(), 'base_class_weights': class_weights.tolist()}
    if mode == 'class_balanced':
        details['effective_class_weights'] = class_weights.tolist()
    elif mode == 'class_and_attack_response':
        response = raw[:, FEATURES.index('pkts_toclient')] > 0
        groups = {'attack_no_return': (labels == 1) & ~response,
                  'attack_has_return': (labels == 1) & response}
        details['attack_groups'] = {}
        for name, mask in groups.items():
            count = int(mask.sum())
            if not count:
                raise ValueError('Both attack response groups must be present in train')
            weight = n / (4 * count)
            sample_weights[mask] = weight
            details['attack_groups'][name] = {'rows': count, 'sample_weight': weight,
                                             'total_weight': float(sample_weights[mask].sum())}
        details['effective_benign_weight'] = float(class_weights[0])
    else:
        raise ValueError('Unknown sample weighting mode: ' + mode)
    details['total_weight_by_class'] = [float(sample_weights[labels == k].sum()) for k in (0, 1)]
    if not np.allclose(details['total_weight_by_class'], [n / 2, n / 2]):
        raise ValueError('Weight mass must remain balanced by class')
    return sample_weights, details


def attack_group_recall(raw, labels, prediction):
    response = raw[:, FEATURES.index('pkts_toclient')] > 0
    result = {}
    for name, mask in [('attack_no_return', (labels == 1) & ~response),
                       ('attack_has_return', (labels == 1) & response)]:
        total = int(mask.sum())
        detected = int(np.sum(prediction[mask] == 1))
        result[name] = {'rows': total, 'detected': detected, 'missed': total - detected,
                        'recall': detected / total if total else None}
    return result


@contextmanager
def model_output(destination):
    """Write a complete bundle first, then replace the fixed model directory."""
    destination = Path(destination).absolute()
    if destination.is_symlink():
        raise ValueError('Model output must not be a symlink')
    parent = destination.parent.resolve()
    destination = parent / destination.name
    if destination == parent or destination.name in ('', '.', '..'):
        raise ValueError('Unsafe model output directory')
    allowed = {'model.json', 'weights.npz', 'metrics.json',
               'test-predictions.csv', 'validation-predictions.csv'}
    if destination.exists():
        if not destination.is_dir():
            raise ValueError('Model output is not a directory')
        entries = list(destination.iterdir())
        if any(p.is_symlink() or not p.is_file() or p.name not in allowed for p in entries):
            raise ValueError('Refusing to replace a directory containing non-model files')
        if entries and not {'model.json', 'weights.npz'}.issubset({p.name for p in entries}):
            raise ValueError('Existing output is not a model bundle')
    parent.mkdir(parents=True, exist_ok=True)
    lock = parent / ('.' + destination.name + '.training-lock')
    backup = parent / ('.' + destination.name + '.previous')
    for path in (lock, backup):
        if path.parent != parent or path == destination:
            raise ValueError('Unsafe temporary model path')
    lock.mkdir()  # Refuse concurrent publication to the same destination.
    try:
        if backup.exists() or backup.is_symlink():
            raise FileExistsError('Previous replacement needs inspection: ' + str(backup))
        with tempfile.TemporaryDirectory(prefix='.' + destination.name + '.training-', dir=parent) as temporary:
            prepared = Path(temporary)
            yield prepared
            meta = json.loads((prepared/'model.json').read_text(encoding='utf-8'))
            report = json.loads((prepared/'metrics.json').read_text(encoding='utf-8'))
            if sha(prepared/'weights.npz') != meta['weights_sha256']:
                raise ValueError('Prepared model hash differs')
            for name, expected in report['artifacts'].items():
                if name not in allowed or sha(prepared/name) != expected:
                    raise ValueError('Prepared artifact contract failed')
            moved_old = destination.exists()
            if moved_old:
                destination.rename(backup)
            try:
                prepared.rename(destination)
            except BaseException:
                if moved_old:
                    backup.rename(destination)
                raise
            if moved_old:
                # backup is a checked child containing only the old model files.
                shutil.rmtree(backup)
    finally:
        lock.rmdir()


def main(node_id, limitation, *, validation_only_default=False):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--config', type=Path, help='Config path inside --root; default is node baseline')
    parser.add_argument('--validation-only', action='store_true', default=validation_only_default,
                        help='Do not load or evaluate test CSV (default for node B)')
    args = parser.parse_args()
    root, out = args.root, args.output
    if node_id not in ('A', 'B'):
        raise ValueError('Unsupported node')
    node = 'node-' + node_id.lower()
    cfg_path = root / (args.config if args.config is not None else Path(f'config/{node}/{node}-baseline.json'))
    if not cfg_path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Config must stay inside root')
    cfg = json.loads(cfg_path.read_text())
    manifest_path = root/f'data/{node}/work/splits/pilot-v1/manifest.json'
    manifest = json.loads(manifest_path.read_text())
    if manifest['features'] != FEATURES or not all(manifest['checks'].values()):
        raise ValueError('Split contract failed')
    train, ytrain = load_split(root,manifest['artifacts']['train'])
    val, yval = load_split(root,manifest['artifacts']['validation'])
    xtrain, xval = transform(train), transform(val)
    class_counts = np.bincount(ytrain,minlength=2)
    weights = len(ytrain)/(2*class_counts)
    sample_weights, weighting = build_sample_weights(train, ytrain, cfg.get('sample_weighting', 'class_balanced'))
    model = MLPClassifier(hidden_layer_sizes=tuple(cfg['hidden_layer_sizes']),
        activation=cfg['activation'],solver=cfg['solver'],random_state=cfg['seed'],
        learning_rate_init=cfg['learning_rate_init'],alpha=cfg['alpha'],
        batch_size=cfg['batch_size'],max_iter=1,shuffle=True,early_stopping=False)
    start = time.perf_counter()
    best = None
    best_score = -1
    best_epoch = None
    history = []
    for epoch in range(1,cfg['epochs']+1):
        model.partial_fit(xtrain,ytrain,classes=np.asarray([0,1]),sample_weight=sample_weights)
        scores = metrics(yval,(model.predict_proba(xval)[:,1]>=cfg['threshold']).astype(int))
        history.append({'epoch':epoch,'train_loss':float(model.loss_),'validation':scores})
        if scores['balanced_accuracy'] > best_score:
            best = copy.deepcopy(model); best_score=scores['balanced_accuracy']; best_epoch=epoch
        print(json.dumps({'epoch':epoch,'validation_balanced_accuracy':scores['balanced_accuracy']}),flush=True)
    training_seconds = time.perf_counter()-start
    # The validation-only path never opens test CSV, even after selection.
    evaluation_name = 'validation' if args.validation_only else 'test'
    test, ytest = (val, yval) if args.validation_only else load_split(root,manifest['artifacts']['test'])
    xtest = transform(test)
    probability = best.predict_proba(xtest)[:,1]
    exported = {'layers':np.asarray(len(best.coefs_))}
    for index,(coef,intercept) in enumerate(zip(best.coefs_,best.intercepts_)):
        exported[f'coef_{index}']=coef;exported[f'intercept_{index}']=intercept
    portable = predict_proba(test,exported)
    if not np.allclose(probability,portable,rtol=1e-12,atol=1e-12):
        raise ValueError('Portable inference differs from sklearn')
    with model_output(out) as out:
        np.savez(out/'weights.npz',**exported)
        metadata={'schema_version':SCHEMA,'features':FEATURES,'transform':TRANSFORM,
                  'transform_rule':'one-hot protocol [6,17,1,58,0]; log1p of seven continuous features /10; duration flag unchanged; no fitted scaler',
                  'hidden_layer_sizes':cfg['hidden_layer_sizes'],'input_width':xtrain.shape[1],
                  'activation':'relu','output_activation':'sigmoid','threshold':cfg['threshold'],
                  'weights_sha256':sha(out/'weights.npz'),'selected_epoch':best_epoch,
                  'config':cfg,'preprocessing_fit_on_test':False,
                  'research_deploy_ready':False,'scope':cfg['scope'],
                  'evaluation_partition':evaluation_name}
        (out/'model.json').write_text(json.dumps(metadata,indent=2)+'\n',encoding='utf-8')
        predictions_name = evaluation_name + '-predictions.csv'
        with (out/predictions_name).open('w',newline='',encoding='utf-8') as dest:
            writer=csv.writer(dest);writer.writerow([evaluation_name+'_row_index','true_label','probability_attack','predicted_label'])
            writer.writerows((i,int(y),float(p),int(p>=cfg['threshold'])) for i,(y,p) in enumerate(zip(ytest,probability)))
        report={'created_at_utc':datetime.now(timezone.utc).isoformat(),'experiment_id':cfg['experiment_id'],
                'schema_version':SCHEMA,'manifest_sha256':sha(manifest_path),
                'config_sha256':sha(cfg_path),
                'model':metadata,'runtime':{'python':platform.python_version(),'numpy':np.__version__,
                  'sklearn':sklearn.__version__,'pip_freeze':subprocess.check_output(['python3','-m','pip','freeze'],text=True)},
                'class_weights_from_train':weights.tolist() if weighting['mode']=='class_balanced' else None,
                'sample_weighting':weighting,'best_epoch':best_epoch,'training_seconds':training_seconds,
                'history':history,'validation_of_selected_checkpoint':history[best_epoch-1]['validation'],
                'test':metrics(ytest,(probability>=cfg['threshold']).astype(int)),
                'all_attack_dummy_test':metrics(ytest,np.ones_like(ytest)),
                'portable_inference_max_abs_error':float(np.max(np.abs(probability-portable))),
                'checks':{'split_hashes_verified':True,'test_evaluated_after_model_selection':True,
                           'portable_forward_pass_matches':True,'fixed_transform_no_fitted_scaler':True},
                'artifacts':{name:sha(out/name) for name in ['weights.npz','model.json',predictions_name]},
                'limitations':manifest['limitations']+[limitation]}
        report['test_evaluated'] = not args.validation_only
        report['attack_group_recall'] = {
            'train':attack_group_recall(train,ytrain,(best.predict_proba(xtrain)[:,1]>=cfg['threshold']).astype(int)),
            evaluation_name:attack_group_recall(test,ytest,(probability>=cfg['threshold']).astype(int))}
        if args.validation_only:
            report['validation_only_metrics'] = report.pop('test')
            report['all_attack_dummy_validation'] = report.pop('all_attack_dummy_test')
            report['checks'].pop('test_evaluated_after_model_selection')
            report['checks']['test_not_accessed'] = True
        (out/'metrics.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'best_epoch':best_epoch,evaluation_name:report['validation_only_metrics'] if args.validation_only else report['test'],'training_seconds':training_seconds}),flush=True)

