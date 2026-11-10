"""Prepare node A global inference overlay; never starts services or sends traffic."""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
IMAGE = 'ddos-fl-laptop-node-a-ml:step1'

PROBE = r'''
import json,sys
from pathlib import Path
sys.path.insert(0,'/app')
from infer_eve import load_model,Scorer
meta,weights,threshold,digest=load_model('/model')
try:
    event={'event_type':'flow','flow_id':1,'proto':'TCP','src_ip':'192.0.2.1',
           'src_port':40000,'dest_ip':'192.0.2.2','dest_port':8000,
           'flow':{'start':'2020-01-01T00:00:00.000000+0000',
                   'end':'2020-01-01T00:00:00.005000+0000',
                   'pkts_toserver':4,'pkts_toclient':3,'bytes_toserver':320,'bytes_toclient':240}}
    scorer=Scorer(meta,weights,threshold,digest,'/tmp/synthetic-predictions.jsonl',live=False)
    record=scorer.process(json.dumps(event))
    saved=json.loads(Path('/tmp/synthetic-predictions.jsonl').read_text())
    if saved!=record or record['weights_sha256']!=digest or threshold!=.5:
        raise ValueError('Inference output does not match the loaded global model')
    if not 0<=record['probability_attack']<=1 or record['mode']!='historical_replay':
        raise ValueError('Invalid synthetic inference result')
    print(json.dumps({'result':'PASS global model inference compatibility',
          'weights_sha256':digest,'model_id':record['model_id'],'selected_round':meta['selected_round'],
          'threshold':threshold,'schema_version':record['schema_version'],
          'synthetic_flow_scored':True,'network':'none','traffic_sent':False,
          'scope':'Constructed EVE record through the existing scorer; no live capture or labelled accuracy claim'}))
finally:
    weights.close()
'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(command, *, payload=None):
    result = subprocess.run(command, cwd=ROOT, input=payload, capture_output=True,
                            text=True, encoding='utf-8', errors='replace', timeout=90)
    if result.returncode:
        raise RuntimeError(result.stdout+result.stderr)
    return result.stdout


def sha(path):
    import hashlib
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):
            digest.update(block)
    return digest.hexdigest()


def compose(global_overlay):
    command = ['docker','compose','-p','ddos-fl-laptop','-f','compose.node-a-live.yaml']
    if global_overlay:
        command += ['-f','compose.node-a-global.yaml']
    return json.loads(run(command+['config','--format','json']))


def containers():
    ids = run(['docker','ps','-aq','--filter','label=com.docker.compose.project=ddos-fl-laptop']).split()
    if not ids:
        return {}
    return {item['Id']:{'image':item['Image'],'status':item['State']['Status'],
                        'started_at':item['State']['StartedAt'],'finished_at':item['State']['FinishedAt'],
                        'restart_count':item['RestartCount']}
            for item in json.loads(run(['docker','inspect',*ids]))}


def source_hashes():
    paths = [ROOT/'compose.node-a-live.yaml']
    for name in ('models/fl/current','models/node-a/local-only-pilot-v1/laptop-01'):
        folder = ROOT/name
        if folder.is_dir():
            paths += [path for path in folder.iterdir() if path.is_file()]
    return {str(path.relative_to(ROOT)).replace('\\','/'):sha(path) for path in paths}


def main():
    before = containers()
    frozen = source_hashes()
    folder = ROOT/'models/fl/current'
    meta = json.loads((folder/'model.json').read_text(encoding='utf-8'))
    require(sha(folder/'weights.npz') == meta['weights_sha256'], 'Global weight hash differs')
    baseline, effective = compose(False), compose(True)
    require(effective['name'] == 'ddos-fl-laptop', 'Wrong Compose project')
    require(set(effective['services']) == {'web','sensor','inference'}, 'Unexpected service set')
    require(effective['networks'] == baseline['networks'] and effective['networks']['site-a']['internal'] is True, 'Network changed')
    for service in ('web','sensor'):
        require(effective['services'][service] == baseline['services'][service], service+' configuration changed')
    original = copy.deepcopy(baseline['services']['inference'])
    selected = copy.deepcopy(effective['services']['inference'])
    original.pop('volumes'); selected.pop('volumes')
    require(original == selected and selected['image'] == IMAGE, 'Non-mount inference configuration changed')
    require(selected['network_mode'] == 'none' and selected['read_only'] is True and not selected.get('ports'), 'Inference isolation differs')
    require('--follow' in selected['command'] and '--start-at-end' in selected['command'], 'Expected new-flow follow mode')
    expected = {'/app':('scripts',True), '/model':('models/fl/current',True),
                '/eve':('data/node-a/live/eve',True), '/predictions':('data/node-a/live/predictions-global',False)}
    mounts = effective['services']['inference']['volumes']
    require(len(mounts) == len(expected), 'Unexpected inference mounts')
    require({mount['target'] for mount in mounts} == set(expected), 'Mount targets differ')
    for mount in mounts:
        relative, read_only = expected[mount['target']]
        require(mount['type'] == 'bind' and Path(mount['source']).resolve() == (ROOT/relative).resolve(), 'Mount source differs')
        require(bool(mount.get('read_only',False)) == read_only, 'Mount access differs')
        if mount['target'] in ('/model','/predictions'):
            require(mount.get('bind',{}).get('create_host_path') is False, 'New binds must not silently create sources')
    require((ROOT/'data/node-a/live/eve').is_dir(), 'Prepare node A EVE directory first')
    (ROOT/'data/node-a/live/predictions-global').mkdir(exist_ok=True)
    command = ['docker','run','--rm','-i','--network','none','--memory','512m','--cpus','0.5',
               '--read-only','--tmpfs','/tmp','--cap-drop','ALL','--security-opt','no-new-privileges',
               '--mount','type=bind,source='+str(ROOT/'scripts')+',target=/app,readonly',
               '--mount','type=bind,source='+str(folder)+',target=/model,readonly',
               IMAGE,'python3','-B','-']
    probe = json.loads(run(command,payload=PROBE).strip().splitlines()[-1])
    require(probe['weights_sha256'] == meta['weights_sha256'] and probe['selected_round'] == meta['selected_round'], 'Probe loaded a different checkpoint')
    require(source_hashes() == frozen, 'Base Compose or model files changed')
    require(containers() == before, 'Existing project containers changed')
    report = {'result':'PASS node A global demo preparation','checked_at_utc':datetime.now(timezone.utc).isoformat(),
              'compose_files':['compose.node-a-live.yaml','compose.node-a-global.yaml'],
              'global_weights_sha256':meta['weights_sha256'],'selected_round':meta['selected_round'],
              'global_model_read_only':True,'predictions_path':'data/node-a/live/predictions-global/predictions.jsonl',
              'web_sensor_network_and_other_inference_settings_unchanged':True,
              'existing_containers_preserved':len(before),'base_and_model_hashes_unchanged':frozen,
              'inference_compatibility':probe,'services_started':False,'traffic_sent':False,
              'scope':'Static Compose validation and one synthetic EVE record; live capture pipeline not exercised'}
    output = ROOT/'reports/node-a/global-demo-preparation.json'
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=output.parent,prefix='.global-demo-',delete=False) as stream:
        temporary = Path(stream.name)
        json.dump(report,stream,indent=2)
    try:
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    print(json.dumps(report,indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError,OSError,KeyError,RuntimeError,subprocess.SubprocessError) as error:
        raise SystemExit('FAIL global demo preparation: '+str(error))
