"""Prepare source-only FAB and validate Compose mount isolation; starts no services."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from check_fl_inputs import check as check_inputs

ROOT=Path(__file__).resolve().parents[1]
IMAGE='ddos-fl-laptop-fl:step1'


def require(condition,message):
    if not condition:raise ValueError(message)


def run(arguments):
    completed=subprocess.run(arguments,cwd=ROOT,capture_output=True,text=True,encoding='utf-8',errors='replace')
    if completed.returncode:
        raise RuntimeError('Command failed: '+arguments[0]+' '+arguments[1]+'\n'+completed.stdout+completed.stderr)
    return completed.stdout


def compose(path):
    return json.loads(run(['docker','compose','-p','ddos-fl-laptop','--profile','fl','-f',path,'config','--format','json']))


def check_service(service,expected_mounts):
    require(service['image']==IMAGE and 'fl' in service.get('profiles',[]),'Wrong FL image/profile')
    require(service.get('read_only') is True and 'ALL' in service.get('cap_drop',[]),'FL root/capability policy differs')
    require(not service.get('ports') and not service.get('privileged'),'FL service publishes ports or is privileged')
    require(set(service.get('networks',{}))=={'federation'},'FL service must use federation network only')
    require(service.get('environment',{}).get('FLWR_HOME')=='/var/lib/flwr','Wrong runtime state directory')
    mounts=service.get('volumes',[])
    require(len(mounts)==len(expected_mounts),'Unexpected FL mounts')
    for mount in mounts:
        target=mount['target']
        require(target in expected_mounts and mount['type']=='bind','Unexpected mount target/type')
        relative,read_only=expected_mounts[target]
        require(Path(mount['source']).resolve()==(ROOT/relative).resolve(),'Wrong mount source: '+target)
        require(bool(mount.get('read_only',False))==read_only,'Wrong mount access: '+target)
        require(mount.get('bind',{}).get('create_host_path') is False,'Mount must not silently create missing data')
    return {'image':service['image'],'profile':'fl','mount_targets':sorted(expected_mounts),
            'published_ports':False,'network':'federation'}


def atomic_json(path,value):
    with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=path.parent,prefix='.deployment-',delete=False) as stream:
        temporary=Path(stream.name);json.dump(value,stream,indent=2);stream.write('\n')
    try:temporary.replace(path)
    finally:temporary.unlink(missing_ok=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        preflight=check_inputs(ROOT,'config/fl/fedavg.json')
        for relative in ('runtime/fl/server','runtime/fl/client-a','runtime/fl/client-b','runtime/fl/client-c',
                         'models/fl','reports/fl/bundles'):
            path=(ROOT/relative).resolve()
            require(path.is_relative_to(ROOT),'Runtime/output path escapes project')
            path.mkdir(parents=True,exist_ok=True)
        mounts=[('fl','/app/fl',True),('scripts','/app/scripts',True),
                ('config/fl','/app/config/fl',True),('pyproject.toml','/app/pyproject.toml',True),
                ('reports/fl/bundles','/app/reports/fl/bundles',False)]
        command=['docker','run','--rm','--network','none','--memory','512m','--cpus','0.75',
                 '--read-only','--tmpfs','/tmp','--cap-drop','ALL','--security-opt','no-new-privileges']
        for source,target,read_only in mounts:
            command+=['--mount','type=bind,source='+str(ROOT/source)+',target='+target+(',readonly' if read_only else '')]
        command += [IMAGE,'python3','-B','/app/fl/build_bundle.py','--output','/app/reports/fl/bundles/ddos-fl-laptop.fab']
        bundle=json.loads(run(command))
        require(bundle['result']=='PASS source-only Flower bundle' and not bundle['contains_dataset_or_model'],'Bundle verification failed')
        server_config=compose('compose.fl.yaml')
        server=server_config['services']['fl-server']
        require(set(server_config['services'])=={'fl-server'},'Server Compose contains unexpected services')
        network=server_config['networks']['federation']
        require(network.get('name')=='ddos-fl-laptop_federation' and network.get('internal') is True and not network.get('external'),'Server must own an internal federation network')
        services={'fl-server':check_service(server,{
            '/workspace/config/fl':('config/fl',True),'/var/lib/flwr':('runtime/fl/server',False),
            '/workspace/models/fl':('models/fl',False),'/workspace/reports/fl':('reports/fl',False)})}
        require(server['command'][0]=='flower-superlink' and '--disable-runtime-dependency-installation' in server['command'],'Wrong server runtime command')
        for node in ('a','b','c'):
            cfg=compose('compose.node-'+node+'.yaml');service=cfg['services']['fl-client-'+node]
            network=cfg['networks']['federation']
            require(network.get('name')=='ddos-fl-laptop_federation' and network.get('external') is True,'Client must reference server-created federation network')
            own='data/node-'+node+'/work/splits/pilot-v1/'
            expected={'/workspace/config/fl':('config/fl',True),'/var/lib/flwr':('runtime/fl/client-'+node,False)}
            expected.update({'/workspace/'+own+name:(own+name,True) for name in ('train.csv','validation.csv','manifest.json')})
            services['fl-client-'+node]=check_service(service,expected)
            command=service['command']
            require(command[0]=='flower-supernode' and command[command.index('--superlink')+1]=='fl-server:8000','Wrong client server address')
            require(command[command.index('--node-config')+1]=='node-id="'+node.upper()+'" project-root="/workspace"','Wrong local client identity/root')
        fab=ROOT/'reports/fl/bundles/ddos-fl-laptop.fab'
        require(hashlib.sha256(fab.read_bytes()).hexdigest()==bundle['fab_sha256'],'Written FAB hash differs')
        report={'result':'PASS FL bundle and Compose','checked_at_utc':datetime.now(timezone.utc).isoformat(),
            'input_preflight':preflight['result'],'config_sha256':preflight['config_sha256'],
            'bundle':bundle,'services':services,'server_has_no_node_data_mounts':True,
            'clients_mount_only_own_train_validation_manifest':True,'default_num_rounds':1,
            'services_started':False,'federation_started':False,'training_started':False,
            'scope':'Source-only FAB/import and static Compose validation. No deployment network, container startup, connectivity or actual FL run verified.'}
        atomic_json(ROOT/'reports/fl/deployment-check.json',report)
        print(json.dumps(report,indent=2))
    except (ValueError,OSError,KeyError,RuntimeError,subprocess.SubprocessError) as error:
        parser.exit(1,'FAIL FL deployment preparation: '+str(error)+'\n')


if __name__=='__main__':main()
