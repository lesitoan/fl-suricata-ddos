"""Build and inspect a source-only FAB, without traversing any dataset directory."""
import argparse
import hashlib
from io import BytesIO
from importlib.metadata import version
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import zipfile

from flwr.cli.build import build_fab_from_files

ROOT = Path(__file__).resolve().parents[1]
FILES = ('pyproject.toml','fl/__init__.py','fl/server_app.py','fl/client_app.py',
         'fl/local_data.py','fl/mlp_adapter.py','scripts/flow_features.py',
         'scripts/model_runtime.py','scripts/train_mlp.py','scripts/check_fl_inputs.py',
         'config/fl/fedavg.json')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,help='Optional fixed FAB path under reports/fl/bundles')
    args=parser.parse_args()
    if version('flwr')!='1.43.0':
        raise ValueError('Bundle builder requires pinned Flower1.43.0')
    project=tomllib.loads((ROOT/'pyproject.toml').read_text(encoding='utf-8'))
    if set(project['tool']['flwr']['app']['fab-include']) != set(FILES)-{'pyproject.toml'}:
        raise ValueError('FAB allowlist differs from audited source-only list')
    if project['tool']['flwr']['app']['config']['num-rounds']!=1:
        raise ValueError('App default must remain a one-round smoke run')
    files={}
    for name in FILES:
        source=ROOT/name
        path=source.resolve()
        if not path.is_relative_to(ROOT) or source.is_symlink() or not path.is_file():
            raise ValueError('Missing or out-of-root app source: '+name)
        files[name]=path.read_bytes()
    blob,metadata=build_fab_from_files(files)
    with zipfile.ZipFile(BytesIO(blob)) as archive:
        members=archive.namelist()
        if len(members)!=len(set(members)) or set(members)!=set(FILES)|{'.info/CONTENT'}:
            raise ValueError('Unexpected or missing FAB contents')
        for name in FILES:
            if name!='pyproject.toml' and archive.read(name)!=files[name]:
                raise ValueError('Bundled source differs: '+name)
        # Import the extracted components in an isolated Python process so host
        # source paths cannot silently satisfy a missing file in the archive.
        with tempfile.TemporaryDirectory(prefix='fl-bundle-import-') as temporary:
            archive.extractall(temporary)
            env=dict(os.environ);env.pop('PYTHONPATH',None)
            code=('from fl.server_app import app as s; from fl.client_app import app as c; '
                  'from flwr.serverapp import ServerApp; from flwr.clientapp import ClientApp; '
                  'assert isinstance(s,ServerApp) and isinstance(c,ClientApp)')
            imported=subprocess.run([sys.executable,'-B','-c',code],cwd=temporary,
                                    env=env,text=True,capture_output=True,timeout=30)
            if imported.returncode:
                raise RuntimeError('Extracted FAB import failed: '+imported.stdout+imported.stderr)
    output=None
    if args.output:
        output=args.output.resolve()
        if not output.is_relative_to((ROOT/'reports/fl/bundles').resolve()) or output.suffix!='.fab':
            raise ValueError('FAB output must remain under reports/fl/bundles')
        output.parent.mkdir(parents=True,exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=output.parent,prefix='.bundle-',delete=False) as stream:
            temporary=Path(stream.name);stream.write(blob)
        try:temporary.replace(output)
        finally:temporary.unlink(missing_ok=True)
    print(json.dumps({'result':'PASS source-only Flower bundle',
        'fab_sha256':hashlib.sha256(blob).hexdigest(),'fab_bytes':len(blob),
        'members':sorted(members),'extracted_server_client_imports':True,
        'contains_dataset_or_model':False,'default_num_rounds':1,
        'output':str(output) if output else None,'services_started':False,'training_started':False}),flush=True)


if __name__=='__main__':main()
