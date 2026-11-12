"""Send a fixed, bounded LDAP/UDP burst to the internal node C lab fixture.

This generates real traffic, not dataset replay. It is a synthetic integration
scenario, not a verified DrDoS_LDAP sample, reflection or saturation test.
"""
import ipaddress
import json
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ldap_protocol import MAX_DATAGRAM, parse_search_response, search_request

COUNT, INTERVAL, SEND_BUDGET_SECONDS = 100, .05, 10
HOST, PORT = 'ldap-c', 389


def utc():
    return datetime.now(timezone.utc).isoformat()


def lab_addresses():
    interfaces = json.loads(subprocess.check_output(
        ['ip', '-j', '-4', 'address', 'show', 'dev', 'eth0'],
        text=True, timeout=3))
    addresses = [address for interface in interfaces
                 for address in interface.get('addr_info', [])
                 if address.get('family') == 'inet'
                 and address.get('scope') == 'global']
    if len(addresses) != 1:
        raise ValueError('Expected one IPv4 address on Docker eth0')
    interface = addresses[0]
    source = ipaddress.ip_address(interface['local'])
    destination = ipaddress.ip_address(socket.gethostbyname(HOST))
    network = ipaddress.ip_network(
        '%s/%s' % (source, interface['prefixlen']), strict=False)
    if (not source.is_private or not destination.is_private
            or source.is_loopback or destination.is_loopback
            or source.is_link_local or destination.is_link_local
            or destination not in network or destination == source
            or destination in (network.network_address, network.broadcast_address)):
        raise ValueError('ldap-c must be another private host in the eth0 subnet')
    return str(source), str(destination)


def main():
    folder = Path('/report')
    if not folder.is_dir():
        raise FileNotFoundError('Mount a fresh report folder at /report')
    output = folder/'sender.json'
    report = {
        'scenario': 'bounded_ldap_burst', 'node': 'C',
        'scenario_role': 'attack_demo', 'ground_truth': 'unverified_synthetic',
        'scope': 'Synthetic bounded LDAP query/reply burst; not verified dataset '
                 'attack, spoofing, reflection or DDoS saturation',
        'destination_host': HOST, 'destination_port': PORT, 'transport': 'UDP',
        'source_spoofed': False, 'start_utc': utc(),
        'planned_packets': COUNT, 'rate_limit_pps': 1/INTERVAL,
        'sending_budget_seconds': SEND_BUDGET_SECONDS,
        'packets_sent': 0, 'valid_responses': 0, 'completed': False,
        'errors': [], 'packets': [],
    }
    # Exclusive creation refuses to overwrite evidence before any networking.
    with output.open('x', encoding='utf-8') as stream:
        try:
            source, destination = lab_addresses()
            report['destination_ip'] = destination
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.bind((source, 0))
                client.connect((destination, PORT))
                report['source_ip'], report['source_port'] = client.getsockname()
                started = time.monotonic()
                deadline, next_send = started + SEND_BUDGET_SECONDS, started
                for message_id in range(1, COUNT + 1):
                    if time.monotonic() >= deadline:
                        report['errors'].append('10-second sending deadline reached')
                        break
                    time.sleep(max(0, next_send - time.monotonic()))
                    if time.monotonic() >= deadline:
                        report['errors'].append('10-second sending deadline reached')
                        break
                    payload = search_request(message_id)
                    record = {'index': message_id-1, 'message_id': message_id,
                              'sent_at_utc': utc(), 'bytes_sent': 0,
                              'received_bytes': 0, 'valid_response': False}
                    report['packets'].append(record)
                    next_send = time.monotonic() + INTERVAL
                    client.settimeout(min(.1, max(.001, deadline-time.monotonic())))
                    try:
                        record['bytes_sent'] = client.send(payload)
                        if record['bytes_sent'] != len(payload):
                            raise ValueError('Partial LDAP datagram send')
                        report['packets_sent'] += 1
                        response = client.recv(MAX_DATAGRAM + 1)
                        record['received_bytes'] = len(response)
                        parse_search_response(response, message_id)
                        record['valid_response'] = True
                        report['valid_responses'] += 1
                    except (OSError, ValueError) as error:
                        report['errors'].append(
                            {'message_id': message_id, 'error': str(error)})
                report['sending_wall_seconds'] = time.monotonic() - started
            report['completed'] = report['packets_sent'] == COUNT
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            report['errors'].append({'fatal': str(error)})
        finally:
            report['end_utc'] = utc()
            json.dump(report, stream, indent=2)
            stream.write('\n')
            stream.flush()
            print(json.dumps({key: value for key, value in report.items()
                              if key != 'packets'}), flush=True)
    if (not report['completed'] or report['valid_responses'] != COUNT
            or report['errors']):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
