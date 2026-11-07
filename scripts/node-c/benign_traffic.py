"""Send ten bounded LDAP rootDSE queries to the fixed internal node C fixture."""
import ipaddress
import json
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ldap_protocol import MAX_DATAGRAM, parse_search_response, search_request


def main():
    destination = socket.gethostbyname('ldap-c')
    address = ipaddress.ip_address(destination)
    if not address.is_private or address.is_loopback or address.is_link_local:
        raise ValueError('Expected ldap-c on the private Docker network')
    start = datetime.now(timezone.utc)
    deadline = time.monotonic() + 15
    successful, source_ip = 0, None
    errors, queries = [], []
    for message_id in range(1, 11):
        if time.monotonic() >= deadline:
            errors.append('15-second smoke-test deadline reached')
            break
        payload = search_request(message_id)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(min(1.0, max(.01, deadline - time.monotonic())))
            client.connect((destination, 389))
            source_ip, port = client.getsockname()
            query = {'message_id': message_id, 'source_port': port,
                     'sent_bytes': len(payload)}
            queries.append(query)
            try:
                client.send(payload)
                response = client.recv(MAX_DATAGRAM + 1)
                attributes = parse_search_response(response, message_id)
                query.update({'received_bytes': len(response), 'attributes': attributes,
                              'operation_tags': ['0x64', '0x65'], 'result_code': 0})
                successful += 1
            except (OSError, ValueError) as error:
                errors.append({'message_id': message_id, 'error': str(error)})
        if message_id != 10:
            time.sleep(.2)
    report = {'scenario': 'node_c_ldap_benign_smoke', 'label': 'benign',
              'source_ip': source_ip, 'destination_ip': destination,
              'destination_port': 389, 'transport': 'UDP',
              'start_utc': start.isoformat(), 'end_utc': datetime.now(timezone.utc).isoformat(),
              'planned_requests': 10, 'requests': len(queries), 'successful': successful,
              'queries': queries, 'errors': errors,
              'scope': 'LDAP rootDSE query/reply fixture only; no model or attack-load evaluation'}
    print(json.dumps(report), flush=True)
    if successful != 10 or errors:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
