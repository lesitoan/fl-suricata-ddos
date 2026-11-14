"""Start only the known host metric viewer; never touch Docker or training."""
import json
import os
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

URL = 'http://127.0.0.1:6006/'


def port_open():
    try:
        with socket.create_connection(('127.0.0.1',6006),timeout=.5): return True
    except OSError: return False


def ready(root):
    try:
        status = json.loads((root/'runtime/tensorboard/status.json').read_text(encoding='utf-8'))
        if status.get('status')!='running' or not 0 <= time.time()-status['updated_at'] < 15:
            return False
        # Ignore proxy environment for a local-only viewer.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(URL+'data/environment',timeout=2) as response:
            environment = json.load(response)
        with opener.open(URL+'data/logdir',timeout=2) as response:
            logdir = json.load(response)['logdir']
        return bool(environment.get('version')) and Path(logdir).resolve()==(root/'reports/tensorboard').resolve()
    except (OSError,ValueError,KeyError,TypeError): return False


def start(root):
    root = Path(root).resolve()
    if ready(root): return URL
    if port_open():
        raise RuntimeError('Cổng 6006 đang được dùng; không dừng hoặc thay tiến trình đó')
    python = root/'runtime/tensorboard/venv/Scripts/python.exe'
    if os.name!='nt': python = root/'runtime/tensorboard/venv/bin/python'
    if not python.is_file():
        raise RuntimeError('Chạy .\\tools\\tensorboard\\setup.ps1 trước để cài TensorBoard')
    folder = root/'runtime/tensorboard'
    with (folder/'server.stdout.log').open('ab') as stdout, (folder/'server.stderr.log').open('ab') as stderr:
        process = subprocess.Popen([str(python),'-B',str(root/'tools/tensorboard/serve.py')],
            cwd=root,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    (folder/'server.pid').write_text(str(process.pid),encoding='utf-8')
    for _ in range(240):
        if process.poll() is not None:
            raise RuntimeError('TensorBoard đã thoát; xem runtime/tensorboard/server.stderr.log')
        if ready(root):
            # Windows venv python.exe may be a launcher with a different child PID.
            status = json.loads((folder/'status.json').read_text(encoding='utf-8'))
            (folder/'server.pid').write_text(str(status['pid']),encoding='utf-8')
            return URL
        time.sleep(.25)
    raise RuntimeError('TensorBoard chưa sẵn sàng; xem log trước khi thử lại, không tự retry')
