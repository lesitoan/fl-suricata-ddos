"""Fixed node A integration probe: 50 SYN at <=10 pps to Docker service web:8000.

Packet construction follows the old lab sender; this version uses eth0 on the
new isolated Docker site. No target/count/rate arguments or firewall changes.
"""
import base64
import hashlib
import ipaddress
import json
import socket
import struct
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

COUNT = 50
PPS = 10
PORT = 8000


def utc():
    return datetime.now(timezone.utc).isoformat()


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def syn_packet(src, dst, port, index):
    if not (0 <= index < COUNT and 45000 <= port < 46000):
        raise ValueError('Outside the fixed probe bounds')
    options = b'\x02\x04\x05\xb4\x04\x02\x01\x03\x03\x07\x01\x01'
    tcp = struct.pack('!HHIIBBHHH', port, PORT, 0x5a000000 + index,
                      0, 8 << 4, 2, 64240, 0, 0) + options
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 30000 + index,
                     0x4000, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return ip + tcp


def main():
    folder = Path('/output')
    report_path, pcap_path = folder/'sender.json', folder/'sent.pcap'
    if not folder.is_dir() or report_path.exists() or pcap_path.exists():
        raise RuntimeError('Mount a fresh output folder; existing results are preserved')
    interfaces = json.loads(subprocess.check_output(
        ['ip', '-j', '-4', 'address', 'show', 'dev', 'eth0'], text=True, timeout=5))
    addresses = [a for interface in interfaces for a in interface.get('addr_info', [])
                 if a.get('family') == 'inet' and a.get('scope') == 'global']
    if len(addresses) != 1:
        raise RuntimeError('Expected exactly one IPv4 address on Docker eth0')
    address = addresses[0]
    src, dst = address['local'], socket.gethostbyname('web')
    network = ipaddress.ip_network(f"{src}/{address['prefixlen']}", strict=False)
    target = ipaddress.ip_address(dst)
    if (not ipaddress.ip_address(src).is_private or not target.is_private
            or target not in network or dst == src
            or target in (network.network_address, network.broadcast_address)):
        raise RuntimeError('web must be another private address in the same Docker subnet')
    report = {'scenario': 'bounded_syn_probe', 'label': 'attack', 'node': 'A',
              'start_utc': utc(), 'source_ip': src, 'destination_ip': dst,
              'destination_port': PORT, 'count_limit': COUNT, 'pps_limit': PPS,
              'packets_sent': 0, 'source_spoofed': False,
              'automatic_kernel_rst_suppressed': False,
              'generator_completed_tcp_handshake': False,
              'scope': 'Fixed low-volume SYN integration probe, not a DDoS saturation test',
              'sent_pcap_scope': 'Generator-side record of send calls, not an independent wire capture',
              'completed': False, 'records': []}
    sockets = []
    try:
        for port in range(45000, 46000):
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                connection.bind((src, port))
            except OSError:
                connection.close()
                continue
            sockets.append(connection)
            if len(sockets) == COUNT:
                break
        if len(sockets) != COUNT:
            raise RuntimeError('Could not reserve 50 distinct source ports')
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as raw, pcap_path.open('xb') as pcap:
            raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            raw.settimeout(1)
            raw.bind((src, 0))
            # PCAP linktype 101: raw IP packets, without Ethernet headers.
            pcap.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))
            started = time.monotonic()
            for index, connection in enumerate(sockets):
                if time.monotonic() - started > 15:
                    raise RuntimeError('Probe exceeded its 15-second sending budget')
                port = connection.getsockname()[1]
                packet = syn_packet(src, dst, port, index)
                pseudo = packet[12:20] + struct.pack('!BBH', 0, 6, len(packet) - 20)
                if checksum(packet[:20]) or checksum(pseudo + packet[20:]):
                    raise RuntimeError('Packet checksum validation failed')
                sent = raw.sendto(packet, (dst, PORT))
                if sent != len(packet):
                    raise RuntimeError('Partial packet send')
                stamp = time.time()
                sec = int(stamp)
                pcap.write(struct.pack('<IIII', sec, int((stamp-sec)*1e6), sent, sent) + packet)
                report['records'].append({'index': index, 'source_port': port,
                    'sent_at_utc': datetime.fromtimestamp(stamp, timezone.utc).isoformat(),
                    'bytes_sent': sent, 'packet_sha256': hashlib.sha256(packet).hexdigest(),
                    'ip_packet_base64': base64.b64encode(packet).decode()})
                report['packets_sent'] += 1
                time.sleep(1/PPS)
            report['sending_wall_seconds'] = time.monotonic() - started
        report['completed'] = report['packets_sent'] == COUNT
        # Allow the normal kernel RST/reply traffic to finish before removal.
        time.sleep(1)
    except Exception as exc:
        report['error'] = str(exc)
        raise
    finally:
        for connection in sockets:
            connection.close()
        report['end_utc'] = utc()
        report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({k: v for k, v in report.items() if k != 'records'}), flush=True)


if __name__ == '__main__':
    main()
