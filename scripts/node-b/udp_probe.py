"""Controlled node B UDP load; fixed Docker target, no spoofing/reflection.

Five sockets target 1000 datagrams at 500pps within a strict two-second window.
At most one datagram per 2ms schedule slot; missed slots are not sent in a burst.
Independent echo reception and
benign before/during/after checks measure behavior; no saturation claim.
"""
import ipaddress
import json
import math
import select
import socket
import statistics
import subprocess
import time
import uuid
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path

HOST, PORT = 'udp-b', 9000
COUNT, FLOW_COUNT, PAYLOAD_BYTES = 1000, 5, 64
INTERVAL, LOAD_BUDGET, EXPERIMENT_BUDGET = .002, 2.0, 15.0
HEALTH_COUNT, HEALTH_TIMEOUT, ECHO_GRACE = 5, .5, 1.0


def utc():
    return datetime.now(timezone.utc).isoformat()


def lab_addresses():
    interfaces = json.loads(subprocess.check_output(
        ['ip', '-j', '-4', 'address', 'show', 'dev', 'eth0'], text=True, timeout=3))
    addresses = [entry for interface in interfaces for entry in interface.get('addr_info', [])
                 if entry.get('family') == 'inet' and entry.get('scope') == 'global']
    if len(addresses) != 1:
        raise ValueError('Expected one IPv4 address on Docker eth0')
    source = ipaddress.ip_address(addresses[0]['local'])
    destination = ipaddress.ip_address(socket.gethostbyname(HOST))
    subnet = ipaddress.ip_network('%s/%s' % (source, addresses[0]['prefixlen']), strict=False)
    if (not source.is_private or not destination.is_private
            or source.is_loopback or destination.is_loopback
            or source.is_link_local or destination.is_link_local
            or destination not in subnet or destination == source
            or destination in (subnet.network_address, subnet.broadcast_address)):
        raise ValueError('udp-b must be another private host in the eth0 subnet')
    return str(source), str(destination)


def health_summary(records):
    values = sorted(item['rtt_ms'] for item in records if item['result'] == 'ok')
    return {'planned_requests': HEALTH_COUNT, 'requests': len(records), 'successful': len(values),
            'timeouts': sum(item['result'] == 'timeout' for item in records),
            'errors': sum(item['result'] == 'error' for item in records),
            'unfinished': sum(item['result'] in ('pending', 'interrupted') for item in records),
            'median_rtt_ms': statistics.median(values) if values else None,
            'p95_rtt_ms': values[max(0, math.ceil(.95*len(values))-1)] if values else None,
            'records': records}


def run_experiment(source, destination, *, clock=time.monotonic, wall=utc,
                   socket_factory=socket.socket, wait=select.select):
    report = {'schema_version': 'udp-load-v1', 'scenario': 'bounded_udp_load', 'node': 'B',
              'scenario_role': 'attack_demo', 'ground_truth': 'unverified_synthetic',
              'scope': 'Controlled direct UDP load; not verified DrDoS_UDP, reflection or saturation',
              'source_spoofed': False, 'source_ip': source, 'destination_ip': destination,
              'destination_port': PORT, 'transport': 'UDP', 'planned_packets': COUNT,
              'planned_flows': FLOW_COUNT, 'payload_bytes': PAYLOAD_BYTES,
              'rate_limit_pps': 1/INTERVAL, 'target_sending_seconds': 2,
              'sending_budget_seconds': LOAD_BUDGET, 'experiment_budget_seconds': EXPERIMENT_BUDGET,
              'experiment_start_utc': wall(), 'packets_sent': 0, 'valid_echoes': 0,
              'completed': False, 'errors': [], 'packets': []}
    health = {phase: [] for phase in ('before', 'during', 'after')}
    pending, sent_clock, load_records = {}, {}, {}
    duplicate_echoes = unexpected_echoes = 0
    nonce = uuid.uuid4().hex[:8]
    started, load_started, load_ended = clock(), None, None
    phase, next_load, next_health = 'before', None, clock()
    last_load_slot = -1
    with ExitStack() as stack:
        def make_client():
            client = stack.enter_context(socket_factory(socket.AF_INET, socket.SOCK_DGRAM))
            client.bind((source, 0))
            client.connect((destination, PORT))
            client.setblocking(False)
            return client
        try:
            loads = [make_client() for _ in range(FLOW_COUNT)]
            health_clients = {name: make_client() for name in health}
            report['source_ports'] = [client.getsockname()[1] for client in loads]
            report['health_source_ports'] = {name: client.getsockname()[1]
                                             for name, client in health_clients.items()}
            owner = {client: 'load' for client in loads}
            owner.update({client: name for name, client in health_clients.items()})
            sockets = list(owner)

            def send_health(name):
                client = health_clients[name]
                payload = ('node-b-benign:%s:%s:%d' % (nonce, name, len(health[name]))).encode()
                record = {'index': len(health[name]), 'sent_at_utc': wall(), 'bytes_sent': 0,
                          'result': 'pending', 'rtt_ms': None,
                          'source_port': client.getsockname()[1]}
                health[name].append(record)
                sent = clock()
                try:
                    record['bytes_sent'] = client.send(payload)
                    if record['bytes_sent'] != len(payload):
                        raise OSError('Partial benign datagram send')
                    pending[payload] = (client, record, sent, sent+HEALTH_TIMEOUT)
                except OSError as error:
                    record.update(result='error', error=str(error))

            while True:
                current = clock()
                if current-started >= EXPERIMENT_BUDGET:
                    report['errors'].append('15-second experiment deadline reached')
                    break
                for payload, (_, record, _, deadline) in list(pending.items()):
                    if current >= deadline:
                        record['result'] = 'timeout'
                        del pending[payload]
                health_phase = 'during' if phase == 'load' else phase
                if health_phase in health and len(health[health_phase]) < HEALTH_COUNT and current >= next_health:
                    send_health(health_phase)
                    next_health = clock()+(LOAD_BUDGET/HEALTH_COUNT if phase == 'load' else .2)
                if phase == 'before' and len(health['before']) == HEALTH_COUNT and not pending:
                    phase, load_started = 'load', clock()
                    report['start_utc'] = wall()
                    next_load = next_health = load_started
                if phase == 'load':
                    current = clock()
                    if len(report['packets']) < COUNT and current >= next_load and current-load_started < LOAD_BUDGET:
                        slot = min(COUNT-1, max(0, int((current-load_started)/INTERVAL)))
                        # Avoid a duplicate slot at floating point boundaries.
                        slot = max(last_load_slot+1, slot)
                        if slot >= COUNT:
                            next_load = load_started+LOAD_BUDGET
                            continue
                        index = len(report['packets'])
                        client = loads[index % FLOW_COUNT]
                        payload = ('node-b-load:%s:%06d' % (nonce, index)).encode().ljust(PAYLOAD_BYTES, b'.')
                        record = {'index': index, 'schedule_slot': slot, 'source_port': client.getsockname()[1],
                                  'sent_at_utc': wall(), 'bytes_sent': 0, 'valid_echo': False,
                                  'echo_rtt_ms': None}
                        report['packets'].append(record)
                        sent = clock()
                        try:
                            record['bytes_sent'] = client.send(payload)
                            if record['bytes_sent'] != PAYLOAD_BYTES:
                                raise OSError('Partial load datagram send')
                            sent_clock[payload] = sent
                            load_records[payload] = (client, record)
                            report['packets_sent'] += 1
                        except OSError as error:
                            report['errors'].append({'index': index, 'error': str(error)})
                        # Anchor to the experiment clock; skip missed slots.
                        last_load_slot = slot
                        next_load = load_started+(slot+1)*INTERVAL
                    if len(report['packets']) >= COUNT or clock()-load_started >= LOAD_BUDGET:
                        load_ended = clock()
                        report['end_utc'] = wall()
                        phase, next_health = 'after', clock()
                        if len(report['packets']) < COUNT:
                            report['errors'].append('2-second sending window ended before 1000 attempts; missed slots were not replayed')
                if (phase == 'after' and len(health['after']) == HEALTH_COUNT and not pending
                        and (report['valid_echoes'] == report['packets_sent']
                             or clock()-load_ended >= ECHO_GRACE)):
                    break
                due = [started+EXPERIMENT_BUDGET, clock()+.05]
                if phase == 'load':
                    due.extend([next_load, load_started+LOAD_BUDGET])
                if health_phase in health and len(health[health_phase]) < HEALTH_COUNT:
                    due.append(next_health)
                due.extend(item[3] for item in pending.values())
                readable, _, _ = wait(sockets, [], [], max(0, min(due)-clock()))
                for client in readable:
                    for _ in range(64):
                        try:
                            payload = client.recv(4096)
                        except BlockingIOError:
                            break
                        except OSError as error:
                            report['errors'].append({'receiver': owner[client], 'error': str(error)})
                            break
                        received = clock()
                        if payload in pending:
                            expected, record, sent, _ = pending[payload]
                            if client is expected:
                                record.update(result='ok', rtt_ms=(received-sent)*1000,
                                              received_at_utc=wall())
                                del pending[payload]
                            else:
                                unexpected_echoes += 1
                        elif payload in load_records:
                            expected, record = load_records[payload]
                            if client is not expected:
                                unexpected_echoes += 1
                            elif record['valid_echo']:
                                duplicate_echoes += 1
                            else:
                                record.update(valid_echo=True, echo_rtt_ms=(received-sent_clock[payload])*1000,
                                              received_at_utc=wall())
                                report['valid_echoes'] += 1
                        else:
                            unexpected_echoes += 1
        except (OSError, ValueError) as error:
            report['errors'].append({'fatal': str(error)})
        finally:
            ended = clock()
            if load_started is not None and load_ended is None:
                load_ended = ended
                report['end_utc'] = wall()
            times = sorted(sent_clock.values())
            report['observed_send_pps'] = ((len(times)-1)/(times[-1]-times[0])
                                           if len(times) > 1 and times[-1] > times[0] else None)
            report['sending_wall_seconds'] = load_ended-load_started if load_started is not None else 0
            report['experiment_wall_seconds'] = ended-started
            report['experiment_end_utc'] = wall()
            report['echoes_missing_after_observation'] = report['packets_sent']-report['valid_echoes']
            report['missed_send_slots'] = COUNT-len(report['packets'])
            report['duplicate_echoes'] = duplicate_echoes
            report['unexpected_echoes'] = unexpected_echoes
            for _, record, _, deadline in pending.values():
                record['result'] = 'timeout' if ended >= deadline else 'interrupted'
            report['health_checks'] = {name: health_summary(items) for name, items in health.items()}
            report['per_flow'] = []
            for port in report.get('source_ports', []):
                records = [item for item in report['packets'] if item['source_port'] == port]
                report['per_flow'].append({'source_port': port,
                    'packets_sent': sum(item['bytes_sent'] == PAYLOAD_BYTES for item in records),
                    'valid_echoes': sum(item['valid_echo'] for item in records)})
            report['completed'] = report['packets_sent'] == COUNT and not report['errors']
            report['measurement_note'] = ('15 benign probes are additional to the 1000 planned load datagrams. '
                'The send window is strictly two seconds; scheduler delays may leave missed slots. '
                'Missing echoes do not localize packet loss. Health timeout/latency and ML prediction '
                'are separate observations. No saturation or verified attack ground truth is inferred.')
    return report


def main():
    folder = Path('/report')
    if not folder.is_dir():
        raise FileNotFoundError('Mount a fresh report folder at /report')
    with (folder/'sender.json').open('x', encoding='utf-8') as stream:
        report = None
        try:
            source, destination = lab_addresses()
            report = run_experiment(source, destination)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            report = {'scenario': 'bounded_udp_load', 'node': 'B', 'completed': False,
                      'packets_sent': 0, 'errors': [{'fatal': str(error)}]}
        finally:
            if report is not None:
                json.dump(report, stream, indent=2, allow_nan=False)
                stream.write('\n')
                summary = {key: value for key, value in report.items() if key not in ('packets', 'health_checks')}
                summary['health_checks'] = {name: {key: value for key, value in item.items() if key != 'records'}
                                            for name, item in report.get('health_checks', {}).items()}
                print(json.dumps(summary, allow_nan=False), flush=True)
    if not report or not report.get('completed'):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
