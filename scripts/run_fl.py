"""Submit an explicitly sized FL run; --check-only validates without submitting."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile

from check_fl_connection import check as connection, cli, IMAGE, NETWORK
from check_fl_inputs import check as preflight, sha

ROOT = Path(__file__).resolve().parents[1]

# Flower 1.43 CLI accepts a source directory, not a .fab argument. Extract only
# the verified source-only bundle inside the ephemeral CLI container.
SUBMIT = r'''
import hashlib,json,subprocess,sys,tempfile,tomllib,zipfile
from pathlib import Path,PurePosixPath
bundle=Path('/bundle/ddos-fl-laptop.fab')
expected=json.loads(Path('/deployment-check.json').read_text())
digest=hashlib.sha256(bundle.read_bytes()).hexdigest()
if digest!=expected['bundle']['fab_sha256']:raise ValueError('Bundle hash differs')
rounds=int(sys.argv[1]);check_only=sys.argv[2]=='check'
with tempfile.TemporaryDirectory(prefix='fl-submit-') as temp:
    app=Path(temp)/'ddos-fl-laptop';app.mkdir()
    with zipfile.ZipFile(bundle) as archive:
        names=archive.namelist()
        if len(names)!=len(set(names)) or set(names)!=set(expected['bundle']['members']):
            raise ValueError('Bundle members differ')
        for name in names:
            path=PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts or '\\' in name:
                raise ValueError('Unsafe bundle path')
        archive.extractall(app)
    config_path=app/'config/fl/fedavg.json'
    if hashlib.sha256(config_path.read_bytes()).hexdigest()!=expected['config_sha256']:
        raise ValueError('Packaged config differs')
    config=json.loads(config_path.read_text())
    if not 1<=rounds<=config['training']['rounds']:raise ValueError('Invalid round count')
    tomllib.loads((app/'pyproject.toml').read_text())
    if check_only:
        print(json.dumps({'result':'PASS FL submission inputs','requested_rounds':rounds,
                          'fab_sha256':digest,'training_started':False}))
    else:
        completed=subprocess.run(['flwr','run',str(app),'docker','--run-config',
                                  'num-rounds='+str(rounds),'--format','json'],capture_output=True,text=True)
        sys.stdout.write(completed.stdout);sys.stderr.write(completed.stderr)
        raise SystemExit(completed.returncode)
'''


def submit(rounds, check_only):
    command = ['docker', 'run', '--rm', '-i', '--network', 'none' if check_only else NETWORK,
               '--memory', '512m', '--cpus', '0.5', '--read-only', '--tmpfs', '/tmp',
               '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
               '--env', 'FLWR_HOME=/tmp/flwr', '--env', 'NO_COLOR=1']
    for source, target in [('reports/fl/bundles', '/bundle'),
                           ('reports/fl/deployment-check.json', '/deployment-check.json'),
                           ('fl/connection.toml', '/tmp/flwr/config.toml')]:
        command += ['--mount', 'type=bind,source='+str(ROOT/source)+',target='+target+',readonly']
    command += [IMAGE, 'python3', '-B', '-', str(rounds), 'check' if check_only else 'submit']
    result = subprocess.run(command, input=SUBMIT, cwd=ROOT, capture_output=True,
                            text=True, encoding='utf-8', errors='replace', timeout=180)
    if result.returncode:
        raise RuntimeError(result.stdout+result.stderr)
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rounds', type=int, required=True, help='Explicit number of rounds; no implicit 50-round run')
    parser.add_argument('--check-only', action='store_true', help='Check inputs and extract FAB offline; never submit')
    args = parser.parse_args()
    lock = ROOT/'reports/fl/.submission-lock'
    acquired = False
    try:
        config = json.loads((ROOT/'config/fl/fedavg.json').read_text(encoding='utf-8'))
        if not 1 <= args.rounds <= config['training']['rounds']:
            raise ValueError('Round count must be within 1..'+str(config['training']['rounds']))
        prepared = json.loads((ROOT/'reports/fl/deployment-check.json').read_text(encoding='utf-8'))
        if prepared['config_sha256'] != sha(ROOT/'config/fl/fedavg.json'):
            raise ValueError('Config changed; prepare the deployment again')
        preflight(ROOT, 'config/fl/fedavg.json')
        if args.check_only:
            print(json.dumps(submit(args.rounds, True), indent=2))
            return
        lock.mkdir()
        acquired = True
        connection()
        if (ROOT/'reports/fl/.server-run-lock').exists():
            raise ValueError('A ServerApp run holds the output lock')
        if any(not run['status'].startswith('finished:') for run in cli('list', 'docker', '--format', 'json')['runs']):
            raise ValueError('A Flower run is still active; no second submission')
        response = submit(args.rounds, False)
        if response.get('success') is not True or not response.get('run-id'):
            raise ValueError('No successful run receipt: '+json.dumps(response))
        response.update({'run-id': str(response['run-id']), 'requested-rounds': args.rounds,
                         'fab-sha256': prepared['bundle']['fab_sha256'],
                         'submitted-at-utc': datetime.now(timezone.utc).isoformat()})
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=lock,
                                         suffix='.json', delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(response, stream, indent=2)
        temporary.replace(ROOT/'reports/fl/last-submission.json')
        print(json.dumps(response, indent=2))
    except (ValueError, OSError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, 'FL submission stopped: '+str(error)+
                    '\nNo automatic retry. If the response was lost after submission, inspect Flower runs before trying again.\n')
    finally:
        if acquired:
            # Only our temporary receipt can be inside this private lock directory.
            for path in lock.iterdir():
                if path.is_file():path.unlink()
            lock.rmdir()


if __name__ == '__main__':main()
