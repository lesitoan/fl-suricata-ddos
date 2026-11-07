"""Send ten bounded UDP echo requests to the fixed internal node B service."""
import ipaddress
import json
import socket
import time
from datetime import datetime, timezone


def main():
    destination = socket.gethostbyname('udp-b')
    address = ipaddress.ip_address(destination)
    if not address.is_private or address.is_loopback or address.is_link_local:
        raise ValueError('Expected udp-b on the private Docker network')
    start = datetime.now(timezone.utc)
    deadline = time.monotonic() + 15
    successful, source_ip = 0, None
    errors, source_ports = [], []
    attempted = 0
    for index in range(10):
        if time.monotonic() >= deadline:
            errors.append('15-second smoke-test deadline reached')
            break
        attempted += 1
        payload = ('node-b-benign-smoke:%02d' % index).encode('ascii')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(min(1.0, max(.01, deadline-time.monotonic())))
            client.connect((destination, 9000))
            local_ip, local_port = client.getsockname()
            source_ip = source_ip or local_ip
            source_ports.append(local_port)
            try:
                client.send(payload)
                response = client.recv(4096)
                if response != payload:
                    raise ValueError('Echo payload differs')
                successful += 1
            except (OSError, ValueError) as error:
                errors.append({'request': index, 'error': str(error)})
        if index != 9:
            time.sleep(.2)
    report = {'scenario': 'node_b_udp_benign_smoke', 'label': 'benign',
              'source_ip': source_ip, 'source_ports': source_ports,
              'destination_ip': destination, 'destination_port': 9000,
              'start_utc': start.isoformat(),
              'end_utc': datetime.now(timezone.utc).isoformat(),
              'planned_requests': 10, 'requests': attempted,
              'successful': successful, 'errors': errors,
              'scope': 'Application request/reply smoke check only; not model accuracy or attack-load evaluation'}
    print(json.dumps(report), flush=True)
    if successful != 10 or errors:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
