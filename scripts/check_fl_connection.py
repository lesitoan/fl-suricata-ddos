"""Inspect the four FL services and online SuperNodes; never submits a run."""
import argparse
from datetime import datetime,timezone
import json
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parents[1]
IMAGE='ddos-fl-laptop-fl:step1'
NETWORK='ddos-fl-laptop_federation'
SERVICES=('fl-server','fl-client-a','fl-client-b','fl-client-c')


def run(arguments,*,logs=False):
    result=subprocess.run(arguments,cwd=ROOT,capture_output=True,text=True,
                          encoding='utf-8',errors='replace',timeout=45)
    if result.returncode:
        raise RuntimeError('Docker/Flower read failed: '+result.stdout+result.stderr)
    return result.stdout+result.stderr if logs else result.stdout


def require(condition,message):
    if not condition:raise ValueError(message)


def cli(*arguments):
    command=['docker','run','--rm','--network',NETWORK,'--memory','512m','--cpus','0.5',
             '--read-only','--tmpfs','/tmp','--cap-drop','ALL','--security-opt','no-new-privileges',
             '--env','FLWR_HOME=/tmp/flwr','--env','NO_COLOR=1','--mount',
             'type=bind,source='+str(ROOT/'fl/connection.toml')+',target=/tmp/flwr/config.toml,readonly',
             IMAGE,'flwr',*arguments]
    result=json.loads(run(command))
    require(result.get('success') is True,'Flower CLI response unsuccessful')
    return result


def check_mounts(container,expected):
    require(len(container['Mounts'])==len(expected),'Unexpected runtime mounts')
    for mount in container['Mounts']:
        target=mount['Destination']
        require(target in expected and mount['Type']=='bind','Unexpected FL mount target/type')
        source,writable=expected[target]
        require(Path(mount['Source']).resolve()==(ROOT/source).resolve(),'Wrong runtime source: '+target)
        require(mount['RW'] is writable,'Wrong runtime access: '+target)


def check():
    names=['ddos-fl-laptop-'+name+'-1' for name in SERVICES]
    containers=json.loads(run(['docker','inspect',*names]))
    image=json.loads(run(['docker','image','inspect',IMAGE]))[0]
    network=json.loads(run(['docker','network','inspect',NETWORK]))[0]
    require(network['Internal'] is True and network['Labels'].get('com.docker.compose.project')=='ddos-fl-laptop','Network must be internal and owned by laptop project')
    by_service={c['Config']['Labels'].get('com.docker.compose.service'):c for c in containers}
    require(set(by_service)==set(SERVICES),'Expected four FL services')
    state={}
    for service,container in by_service.items():
        require(container['Config']['Labels'].get('com.docker.compose.project')=='ddos-fl-laptop','Unexpected project label')
        require(container['Image']==image['Id'],'FL containers use a different image; inspect before recreating')
        require(container['State']['Status']=='running' and container['State'].get('Health',{}).get('Status')=='healthy',service+' is not running/healthy')
        require(set(container['NetworkSettings']['Networks'])=={NETWORK},service+' attached to unexpected networks')
        require(not container['HostConfig'].get('PortBindings') and not container['HostConfig'].get('Privileged'),service+' exposes host ports or is privileged')
        require(container['HostConfig']['ReadonlyRootfs'] is True,'FL root must be read-only')
        require(any(value.upper() in ('ALL','CAP_ALL') for value in container['HostConfig'].get('CapDrop',[])),'FL capability policy differs')
        if service=='fl-server':
            expected={'/workspace/config/fl':('config/fl',False),'/var/lib/flwr':('runtime/fl/server',True),
                      '/workspace/models/fl':('models/fl',True),'/workspace/reports/fl':('reports/fl',True)}
        else:
            node=service[-1];own='data/node-'+node+'/work/splits/pilot-v1/'
            expected={'/workspace/config/fl':('config/fl',False),'/var/lib/flwr':('runtime/fl/client-'+node,True)}
            expected.update({'/workspace/'+own+filename:(own+filename,False) for filename in ('train.csv','validation.csv','manifest.json')})
            command=container['Config']['Cmd']
            require(command[command.index('--node-config')+1]=='node-id="'+node.upper()+'" project-root="/workspace"','Client identity/root differs')
        check_mounts(container,expected)
        state[service]={'status':'running','health':'healthy','container_id':container['Id'],
                        'ip':container['NetworkSettings']['Networks'][NETWORK]['IPAddress']}
    nodes=cli('supernode','list','docker','--format','json')
    online=[node for node in nodes['nodes'] if node['status']=='online']
    require(len(online)==3,'Server must have exactly three online SuperNodes')
    online_ids={str(node['node-id']) for node in online}
    mapped={}
    for node in ('a','b','c'):
        container=by_service['fl-client-'+node]
        logs=run(['docker','logs','--tail','200',container['Id']],logs=True)
        ids=re.findall(r'SuperNode ID:\s*(\d+)',logs)
        require(bool(ids),'Cannot find registered SuperNode ID in client '+node.upper()+' log')
        mapped[node.upper()]=ids[-1]
        state['fl-client-'+node]['supernode_id']=ids[-1]
    require(len(set(mapped.values()))==3 and set(mapped.values())==online_ids,'A/B/C log IDs differ from server online list')
    runs=cli('list','docker','--format','json')
    return {'result':'PASS FL connectivity','checked_at_utc':datetime.now(timezone.utc).isoformat(),
            'services':state,'online_clients':3,'node_ids':mapped,'network_internal':True,
            'published_ports':False,'runtime_mount_isolation_verified':True,
            'registered_runs':len(runs['runs']),'no_runs_registered':not runs['runs'],
            'run_submitted_by_check':False,
            'scope':'Docker startup/health, runtime mount/network isolation and actual SuperNode registration only. No run submitted, training, model quality or convergence verified.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',help='Optional new report under reports/fl; omit to check again without writing')
    args=parser.parse_args()
    try:
        output=(ROOT/args.output).resolve() if args.output else None
        require(output is None or output.is_relative_to((ROOT/'reports/fl').resolve()),'Report must stay in reports/fl')
        require(output is None or not output.exists(),'Report exists; omit --output to check again')
        report=check()
        if output:
            output.parent.mkdir(parents=True,exist_ok=True)
            with output.open('x',encoding='utf-8') as stream:stream.write(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2))
    except (ValueError,OSError,KeyError,RuntimeError,subprocess.SubprocessError) as error:
        parser.exit(1,'FAIL FL connectivity: '+str(error)+'\n')


if __name__=='__main__':main()
