"""Verify the latest FL checkpoint, run status, and node-isolated validation."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import json
from pathlib import Path
import subprocess

from check_fl_inputs import check as preflight,check_weights,sha
from check_fl_connection import cli

ROOT=Path(__file__).resolve().parents[1]
IMAGE='ddos-fl-laptop-fl:step1'


def verify_node(node):
    own='data/node-'+node+'/work/splits/pilot-v1/'
    mounts=[('fl','/app/fl'),('scripts','/app/scripts'),('config/fl','/app/config/fl'),
            ('models/fl/current','/model'),(own+'validation.csv','/app/'+own+'validation.csv'),
            (own+'manifest.json','/app/'+own+'manifest.json')]
    command=['docker','run','--rm','--network','none','--memory','768m','--cpus','0.75',
             '--read-only','--tmpfs','/tmp','--cap-drop','ALL','--security-opt','no-new-privileges']
    for source,target in mounts:
        command+=['--mount','type=bind,source='+str(ROOT/source)+',target='+target+',readonly']
    command += [IMAGE,'python3','-B','/app/fl/check_global_model.py','--node',node]
    result=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=120)
    if result.returncode:raise RuntimeError('Export validation '+node+': '+result.stdout+result.stderr)
    return json.loads(result.stdout)


def check():
    source=preflight(ROOT,'config/fl/fedavg.json')
    state=json.loads((ROOT/'reports/fl/training.json').read_text(encoding='utf-8'))
    submission=json.loads((ROOT/'reports/fl/last-submission.json').read_text(encoding='utf-8'))
    if state['status']!='complete':raise ValueError('FL run is not complete: '+state['status'])
    count=submission['requested-rounds']
    if state['rounds_requested']!=count or state['completed_rounds']!=count or len(state['history'])!=count:
        raise ValueError('Completed round count differs from submitted run')
    if state['config_sha256']!=source['config_sha256'] or state['test_evaluated'] is not False:
        raise ValueError('Config/test contract differs')
    cfg=json.loads((ROOT/'config/fl/fedavg.json').read_text(encoding='utf-8'))
    folder=ROOT/'models/fl/current'
    meta=json.loads((folder/'model.json').read_text(encoding='utf-8'))
    metrics=json.loads((folder/'metrics.json').read_text(encoding='utf-8'))
    if metrics['history']!=state['history']:raise ValueError('Checkpoint history differs from training report')
    if metrics['config_sha256']!=state['config_sha256']:raise ValueError('Checkpoint provenance differs')
    for filename,digest in metrics['artifacts'].items():
        if Path(filename).name!=filename or sha(folder/filename)!=digest:raise ValueError('Bad global artifact hash')
    if sha(folder/'weights.npz')!=meta['weights_sha256'] or meta['weights_sha256']!=state['weights_sha256']:
        raise ValueError('Global weight hashes differ')
    check_weights(folder/'weights.npz',cfg['model'])
    if [item['round'] for item in state['history']]!=list(range(1,count+1)):
        raise ValueError('Round history is not complete and ordered')
    best=max(state['history'],key=lambda item:item['validation_summary']['balanced-accuracy-macro-node'])
    if any(value!=best['round'] for value in (meta['selected_round'],metrics['selected_round'],state['selected_round'])):
        raise ValueError('Checkpoint was not selected by frozen validation rule')
    for item in state['history']:
        if set(item['train_clients'])!={'A','B','C'} or set(item['validation_clients'])!={'A','B','C'}:
            raise ValueError('Incomplete round participation')
        for node in ('A','B','C'):
            if item['train_clients'][node]['metrics']['num-examples']!=source['nodes'][node]['splits']['train']['rows']:
                raise ValueError('FedAvg training sample weight differs')
            if item['train_clients'][node]['metrics']['local-epochs']!=cfg['training']['local_epochs']:
                raise ValueError('Local epoch count differs')
            if item['validation_clients'][node]['num-examples']!=source['nodes'][node]['splits']['validation']['rows']:
                raise ValueError('Validation sample count differs')
    runs=cli('list','docker','--format','json')['runs']
    matches=[run for run in runs if str(run['run-id'])==str(submission['run-id'])]
    if len(matches)!=1 or matches[0]['status']!='finished:completed':
        raise ValueError('Flower run is not finished:completed')
    if matches[0]['fab-hash']!=submission['fab-sha256']:raise ValueError('Run FAB differs')
    with ThreadPoolExecutor(max_workers=3) as executor:
        nodes=list(executor.map(verify_node,('a','b','c')))
    if any(node['weights_sha256']!=meta['weights_sha256'] for node in nodes):
        raise ValueError('Node export verification used different weights')
    return {'result':'PASS FL trained checkpoint','verified_at_utc':datetime.now(timezone.utc).isoformat(),
        'run_id':str(submission['run-id']),'run_status':matches[0]['status'],
        'rounds_completed':count,'selected_round':meta['selected_round'],'weights_sha256':meta['weights_sha256'],
        'input_and_baseline_preflight':source['result'],'validation_recomputed_from_export':nodes,
        'macro_node_validation_balanced_accuracy':best['validation_summary']['balanced-accuracy-macro-node'],
        'round_seconds':[item['round_seconds'] for item in state['history']],
        'flower_reported_network_traffic':matches[0].get('network-traffic'),
        'test_evaluated':False,'convergence_assessed':False,'training_performed_by_check':False,
        'scope':'Actual run and export/validation verification. SDK traffic counters are not a packet-level wire measurement; no independent test/generalization or convergence claim.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',help='Optional new report under reports/fl')
    args=parser.parse_args()
    try:
        output=(ROOT/args.output).resolve() if args.output else None
        if output and (not output.is_relative_to((ROOT/'reports/fl').resolve()) or output.exists()):
            raise ValueError('Choose a new output in reports/fl or omit --output')
        result=check()
        if output:
            output.parent.mkdir(parents=True,exist_ok=True)
            with output.open('x',encoding='utf-8') as stream:stream.write(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result,indent=2))
    except (ValueError,OSError,KeyError,RuntimeError,subprocess.SubprocessError) as error:
        parser.exit(1,'FAIL FL result: '+str(error)+'\n')


if __name__=='__main__':main()
