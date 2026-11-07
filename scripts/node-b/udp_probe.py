"""Bounded synthetic UDP burst to the fixed internal node B echo service."""
import ipaddress
import json
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

COUNT, INTERVAL, PAYLOAD_BYTES = 100, .05, 64


def main():
    output = Path('/report/sender.json')
    if output.exists():
        raise FileExistsError('Keep existing evidence; choose a new report folder')
    destination = socket.gethostbyname('udp-b')
    address = ipaddress.ip_address(destination)
    if not address.is_private or address.is_loopback or address.is_link_local:
        raise ValueError('Expected udp-b on the private Docker network')
    start = datetime.now(timezone.utc)
    clock_start = time.monotonic()
    deadline = clock_start + 10
    next_send = clock_start
    packets, errors = [], []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.connect((destination, 9000))
        source_ip, source_port = client.getsockname()
        for index in range(COUNT):
            if time.monotonic() >= deadline:
                errors.append('10-second deadline reached')
                break
            time.sleep(max(0, next_send - time.monotonic()))
            if time.monotonic() >= deadline:
                errors.append('10-second deadline reached')
                break
            next_send = time.monotonic() + INTERVAL
            client.settimeout(min(.1, max(.001, deadline-time.monotonic())))
            payload = ('node-b-udp-probe:%03d' % index).encode('ascii').ljust(PAYLOAD_BYTES, b'.')
            record = {'index': index, 'sent_at_utc': datetime.now(timezone.utc).isoformat(),
                      'bytes_sent': 0, 'valid_echo': False}
            try:
                record['bytes_sent'] = client.send(payload)
                record['valid_echo'] = client.recv(4096) == payload
                if not record['valid_echo']:
                    errors.append({'index': index, 'error': 'Echo payload differs'})
            except OSError as error:
                errors.append({'index': index, 'error': str(error)})
            packets.append(record)
    sent = sum(x['bytes_sent'] == PAYLOAD_BYTES for x in packets)
    report = {'scenario': 'bounded_udp_burst', 'scope': 'Synthetic small burst; not a verified dataset attack or DDoS saturation test',
              'source_ip': source_ip, 'source_port': source_port,
              'destination_ip': destination, 'destination_port': 9000,
              'start_utc': start.isoformat(), 'end_utc': datetime.now(timezone.utc).isoformat(),
              'planned_packets': COUNT, 'rate_limit_pps': 1/INTERVAL,
              'payload_bytes': PAYLOAD_BYTES, 'packets_sent': sent,
              'valid_echoes': sum(x['valid_echo'] for x in packets),
              'completed': sent == COUNT, 'errors': errors, 'packets': packets}
    output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in report.items() if k != 'packets'}), flush=True)
    if not report['completed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
