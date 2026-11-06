"""	Đọc split, train MLP, chọn checkpoint bằng validation và đánh giá test"""
import argparse
import copy
import csv
import hashlib
import json
import platform
import subprocess
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
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    root, out = args.root, args.output
    if out.exists():
        raise FileExistsError('Refusing to overwrite model evidence')
    cfg = json.loads((root/'config/node-a/node-a-baseline.json').read_text())
    manifest_path = root/'data/node-a/work/splits/pilot-v1/manifest.json'
    manifest = json.loads(manifest_path.read_text())
    if manifest['features'] != FEATURES or not all(manifest['checks'].values()):
        raise ValueError('Split contract failed')
    train, ytrain = load_split(root,manifest['artifacts']['train'])
    val, yval = load_split(root,manifest['artifacts']['validation'])
    xtrain, xval = transform(train), transform(val)
    class_counts = np.bincount(ytrain,minlength=2)
    weights = len(ytrain)/(2*class_counts)
    sample_weights = weights[ytrain]
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
    # Test features are loaded only after checkpoint selection has finished.
    test, ytest = load_split(root,manifest['artifacts']['test'])
    xtest = transform(test)
    probability = best.predict_proba(xtest)[:,1]
    exported = {'layers':np.asarray(len(best.coefs_))}
    for index,(coef,intercept) in enumerate(zip(best.coefs_,best.intercepts_)):
        exported[f'coef_{index}']=coef;exported[f'intercept_{index}']=intercept
    portable = predict_proba(test,exported)
    if not np.allclose(probability,portable,rtol=1e-12,atol=1e-12):
        raise ValueError('Portable inference differs from sklearn')
    out.mkdir(parents=True)
    np.savez(out/'weights.npz',**exported)
    metadata={'schema_version':SCHEMA,'features':FEATURES,'transform':TRANSFORM,
              'transform_rule':'one-hot protocol [6,17,1,58,0]; log1p of seven continuous features /10; duration flag unchanged; no fitted scaler',
              'hidden_layer_sizes':cfg['hidden_layer_sizes'],'input_width':xtrain.shape[1],
              'activation':'relu','output_activation':'sigmoid','threshold':cfg['threshold'],
              'weights_sha256':sha(out/'weights.npz'),'selected_epoch':best_epoch,
              'config':cfg,'preprocessing_fit_on_test':False,
              'research_deploy_ready':False,'scope':cfg['scope']}
    (out/'model.json').write_text(json.dumps(metadata,indent=2)+'\n',encoding='utf-8')
    with (out/'test-predictions.csv').open('w',newline='',encoding='utf-8') as dest:
        writer=csv.writer(dest);writer.writerow(['test_row_index','true_label','probability_attack','predicted_label'])
        writer.writerows((i,int(y),float(p),int(p>=cfg['threshold'])) for i,(y,p) in enumerate(zip(ytest,probability)))
    report={'created_at_utc':datetime.now(timezone.utc).isoformat(),'experiment_id':cfg['experiment_id'],
            'schema_version':SCHEMA,'manifest_sha256':sha(manifest_path),
            'config_sha256':sha(root/'config/node-a/node-a-baseline.json'),
            'model':metadata,'runtime':{'python':platform.python_version(),'numpy':np.__version__,
              'sklearn':sklearn.__version__,'pip_freeze':subprocess.check_output(['python3','-m','pip','freeze'],text=True)},
            'class_weights_from_train':weights.tolist(),'best_epoch':best_epoch,'training_seconds':training_seconds,
            'history':history,'validation_of_selected_checkpoint':history[best_epoch-1]['validation'],
            'test':metrics(ytest,(probability>=cfg['threshold']).astype(int)),
            'all_attack_dummy_test':metrics(ytest,np.ones_like(ytest)),
            'portable_inference_max_abs_error':float(np.max(np.abs(probability-portable))),
            'checks':{'split_hashes_verified':True,'test_evaluated_after_model_selection':True,
                       'portable_forward_pass_matches':True,'fixed_transform_no_fitted_scaler':True},
            'artifacts':{name:sha(out/name) for name in ['weights.npz','model.json','test-predictions.csv']},
            'limitations':manifest['limitations']+['One seed, one recording day, and a short SYN attack window per partition; no real-time/FL generalization claim.']}
    (out/'metrics.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'best_epoch':best_epoch,'test':report['test'],'training_seconds':training_seconds}),flush=True)


if __name__=='__main__':
    main()
