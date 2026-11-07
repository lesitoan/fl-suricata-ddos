"""Small UDP echo service for the isolated node B Docker lab."""
import argparse
import json
import socket

PORT = 9000
HEALTH_PAYLOAD = b'node-b-health'


def healthcheck():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.connect(('127.0.0.1', PORT))
        client.send(HEALTH_PAYLOAD)
        if client.recv(4096) != HEALTH_PAYLOAD:
            raise RuntimeError('Unexpected UDP health response')


def serve():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(('0.0.0.0', PORT))
        print(json.dumps({'node': 'B', 'service': 'udp-echo', 'port': PORT,
                          'status': 'ready'}), flush=True)
        while True:
            payload, peer = server.recvfrom(4096)
            try:
                server.sendto(payload, peer)
            except OSError as error:
                print(json.dumps({'event': 'reply_error', 'error': str(error)}), flush=True)
                continue
            if payload != HEALTH_PAYLOAD:
                print(json.dumps({'node': 'B', 'event': 'echo', 'peer_ip': peer[0],
                                  'peer_port': peer[1], 'received_bytes': len(payload),
                                  'sent_bytes': len(payload)}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--healthcheck', action='store_true')
    args = parser.parse_args()
    healthcheck() if args.healthcheck else serve()
