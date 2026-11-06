"""Small fixed benign smoke test; no user-supplied targets or flood behavior."""
import json
import socket
import time
from datetime import datetime, timezone
from urllib.request import urlopen

start = datetime.now(timezone.utc).isoformat()
paths = ['/', '/about', '/download', '/lab-check']
success = 0
errors = []
for i in range(24):
    try:
        with urlopen('http://web:8000' + paths[i % len(paths)], timeout=5) as response:
            response.read()
            success += response.status == 200
    except Exception as exc:
        errors.append(str(exc))
    time.sleep(0.25)
print(json.dumps({'scenario': 'benign_smoke', 'label': 'benign',
                  'source_ip': socket.gethostbyname(socket.gethostname()),
                  'destination_ip': socket.gethostbyname('web'), 'destination_port': 8000,
                  'start_utc': start, 'end_utc': datetime.now(timezone.utc).isoformat(),
                  'requests': 24, 'successful': success, 'errors': errors}))
raise SystemExit(0 if success == 24 else 1)
