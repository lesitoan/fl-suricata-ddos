"""Deterministic socket/select fixtures; never send real UDP or use Docker."""
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('udp_load_probe', ROOT/'scripts/node-b/udp_probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class Network:
    def __init__(self, delay=.001, lose=False, overhead=0):
        self.time, self.sockets, self.sent = 0., [], []
        self.delay, self.lose, self.overhead = delay, lose, overhead
        self.iterations = 0

    def clock(self):
        return self.time

    def wall(self):
        return (datetime(2026, 11, 12, tzinfo=timezone.utc)+timedelta(seconds=self.time)).isoformat()

    def factory(self, family, kind):
        client = Client(self, 44000+len(self.sockets))
        self.sockets.append(client)
        return client

    def wait(self, readers, writers, errors, timeout):
        self.iterations += 1
        assert self.iterations < 20000, 'Non-progressing event loop'
        assert 0 <= timeout <= .051
        due = [when for client in readers for when, _ in client.queue]
        target = min(self.time+timeout, min(due) if due else self.time+timeout)
        self.time = max(self.time, target)+self.overhead
        return [client for client in readers if any(when <= self.time for when, _ in client.queue)], [], []


class Client:
    def __init__(self, net, port):
        self.net, self.port, self.queue, self.closed = net, port, [], False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def bind(self, address):
        assert address == ('172.19.0.3', 0)

    def connect(self, address):
        assert address == ('172.19.0.2', 9000)

    def setblocking(self, blocking):
        assert not blocking

    def getsockname(self):
        return '172.19.0.3', self.port

    def send(self, payload):
        self.net.sent.append((self.net.time, self.port, payload))
        if not self.net.lose:
            self.queue.append((self.net.time+self.net.delay, payload))
        return len(payload)

    def recv(self, size):
        for index, (when, payload) in enumerate(self.queue):
            if when <= self.net.time:
                del self.queue[index]
                return payload
        raise BlockingIOError()


class UDPLoadTests(unittest.TestCase):
    def run_load(self, **options):
        net = Network(**options)
        report = probe.run_experiment('172.19.0.3', '172.19.0.2', clock=net.clock,
                    wall=net.wall, socket_factory=net.factory, wait=net.wait)
        self.assertTrue(all(client.closed for client in net.sockets))
        return net, report

    def test_total_rate_port_counts_and_health_phases(self):
        net, report = self.run_load()
        self.assertTrue(report['completed'], report['errors'])
        self.assertEqual(report['packets_sent'], 1000)
        self.assertEqual(report['valid_echoes'], 1000)
        self.assertEqual(len(net.sent), 1015)
        self.assertEqual(len(report['source_ports']), 5)
        self.assertEqual([flow['packets_sent'] for flow in report['per_flow']], [200]*5)
        load_times = [when for when, _, payload in net.sent if payload.startswith(b'node-b-load:')]
        self.assertTrue(all(b-a >= .002-1e-10 for a,b in zip(load_times,load_times[1:])))
        self.assertLessEqual(report['observed_send_pps'], 500+1e-8)
        self.assertLess(report['sending_wall_seconds'], 2)
        self.assertGreater(report['sending_wall_seconds'], 1.99)
        self.assertEqual(report['missed_send_slots'], 0)
        self.assertEqual([item['schedule_slot'] for item in report['packets']], list(range(1000)))
        for phase in ('before','during','after'):
            self.assertEqual(report['health_checks'][phase]['successful'], 5)
            self.assertAlmostEqual(report['health_checks'][phase]['median_rtt_ms'], 1.)
        during = [when for when, _, payload in net.sent if b':during:' in payload]
        self.assertTrue(all(load_times[0] <= when <= load_times[-1] for when in during))
        self.assertEqual(report['ground_truth'], 'unverified_synthetic')

    def test_slow_echo_does_not_gate_send_schedule(self):
        _, report = self.run_load(delay=.2)
        self.assertTrue(report['completed'])
        self.assertEqual(report['valid_echoes'], 1000)
        self.assertGreater(report['observed_send_pps'], 499)
        self.assertGreater(report['health_checks']['during']['median_rtt_ms'], 190)

    def test_echo_loss_is_measured_without_artificial_attack_or_generator_failure(self):
        _, report = self.run_load(lose=True)
        self.assertTrue(report['completed'])
        self.assertEqual(report['echoes_missing_after_observation'], 1000)
        self.assertEqual(report['valid_echoes'], 0)
        for phase in ('before','during','after'):
            self.assertEqual(report['health_checks'][phase]['timeouts'], 5)
        self.assertNotIn('prediction', report)
        self.assertLess(report['experiment_wall_seconds'], 15.1)

    def test_slow_scheduler_stops_without_catchup_bursts(self):
        net, report = self.run_load(overhead=.035)
        self.assertFalse(report['completed'])
        self.assertLess(report['packets_sent'], 1000)
        self.assertTrue(report['errors'])
        times = [when for when, _, payload in net.sent if payload.startswith(b'node-b-load:')]
        self.assertTrue(all(b-a >= .002-1e-10 for a,b in zip(times,times[1:])))
        self.assertLessEqual(times[-1]-times[0], 2)

    def test_target_guards(self):
        interface = json.dumps([{'addr_info':[{'family':'inet','scope':'global',
                            'local':'172.19.0.3','prefixlen':24}]}])
        with patch.object(probe.subprocess, 'check_output', return_value=interface):
            for target in ('8.8.8.8','127.0.0.1','172.20.0.2','172.19.0.3','172.19.0.255'):
                with self.subTest(target=target):
                    with patch.object(probe.socket, 'gethostbyname', return_value=target):
                        with self.assertRaises(ValueError):
                            probe.lab_addresses()

    def test_existing_evidence_refused_before_network(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as folder:
            path = Path(folder)
            (path/'sender.json').write_text('keep')
            with patch.object(probe, 'Path', return_value=path):
                with patch.object(probe, 'lab_addresses') as networking:
                    with self.assertRaises(FileExistsError):
                        probe.main()
                    self.assertFalse(networking.called)
            self.assertEqual((path/'sender.json').read_text(), 'keep')


if __name__ == '__main__':
    unittest.main()
