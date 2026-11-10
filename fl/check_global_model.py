"""Validate an exported global checkpoint on one node's validation only; no fit."""
import argparse
import json
from pathlib import Path
import sys
from unittest.mock import patch

import numpy as np
from sklearn.neural_network import MLPClassifier

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'scripts'))
from infer_eve import load_model
from model_runtime import transform,predict_proba
from fl.local_data import LocalInputs
from fl.mlp_adapter import PARAMETER_NAMES,parameter_sha256,estimator_from_parameters,evaluate


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node',required=True,choices=('a','b','c'))
    parser.add_argument('--model-dir',type=Path,default=Path('/model'))
    args=parser.parse_args()
    local=LocalInputs(ROOT,args.node.upper())
    values,labels=local.load('validation')
    meta,weights,threshold,digest=load_model(args.model_dir)
    metrics=json.loads((args.model_dir/'metrics.json').read_text(encoding='utf-8'))
    assert metrics['config_sha256']==local.config_sha256 and not metrics['test_evaluated']
    selected=next(item for item in metrics['history'] if item['round']==meta['selected_round'])
    parameters=[weights[name] for name in PARAMETER_NAMES]
    assert parameter_sha256(parameters)==selected['global_parameters_sha256']
    with patch.object(MLPClassifier,'partial_fit',side_effect=AssertionError('Verification must not fit')):
        report=evaluate(parameters,values,labels,local.config)
        estimator=estimator_from_parameters(parameters,local.config)
        portable=predict_proba(values,weights)
        error=float(np.max(np.abs(portable-estimator.predict_proba(transform(values))[:,1])))
    assert error<=1e-12 and threshold==.5
    expected=selected['validation_clients'][args.node.upper()]
    tn,fp=report['confusion_matrix'][0];fn,tp=report['confusion_matrix'][1]
    assert [tn,fp,fn,tp]==[expected[key] for key in ('tn','fp','fn','tp')]
    assert report['num_examples']==expected['num-examples']
    for own,key in (('loss','loss'),('balanced_accuracy','balanced-accuracy'),('recall_attack','recall-attack'),('false_positive_rate','false-positive-rate')):
        assert abs(report[own]-expected[key])<=1e-12
    print(json.dumps({'result':'PASS exported global model','node':args.node.upper(),
        'weights_sha256':digest,'selected_round':meta['selected_round'],
        'validation_rows':len(labels),'confusion_matrix':report['confusion_matrix'],
        'balanced_accuracy':report['balanced_accuracy'],'recall_attack':report['recall_attack'],
        'false_positive_rate':report['false_positive_rate'],'portable_max_abs_error':error,
        'matches_federated_validation':True,'no_fitting':True,'test_evaluated':False}),flush=True)


if __name__=='__main__':main()
