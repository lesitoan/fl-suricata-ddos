"""Minimal anonymous LDAP rootDSE-over-UDP fixture for the node C Docker lab."""
import argparse
import json
import socket

from ldap_protocol import (MAX_DATAGRAM, parse_search_request,
                           parse_search_response, search_request, search_response)

PORT = 389


def healthcheck():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.connect(('127.0.0.1', PORT))
        client.send(search_request(1))
        parse_search_response(client.recv(MAX_DATAGRAM + 1), 1)


def serve():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(('0.0.0.0', PORT))
        print(json.dumps({'node': 'C', 'service': 'ldap-rootdse-udp-fixture',
                          'port': PORT, 'status': 'ready',
                          'scope': 'Anonymous rootDSE search subset; not AD or a full LDAP server'}), flush=True)
        while True:
            data, peer = server.recvfrom(MAX_DATAGRAM + 1)
            try:
                message_id, attributes = parse_search_request(data)
                response = search_response(message_id, attributes)
                server.sendto(response, peer)
            except (ValueError, OSError) as error:
                print(json.dumps({'event': 'request_rejected', 'peer_ip': peer[0],
                                  'reason': str(error)}), flush=True)
                continue
            if peer[0] != '127.0.0.1':
                print(json.dumps({'node': 'C', 'event': 'rootdse_search',
                                  'peer_ip': peer[0], 'peer_port': peer[1],
                                  'message_id': message_id, 'received_bytes': len(data),
                                  'sent_bytes': len(response), 'attributes': attributes}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--healthcheck', action='store_true')
    args = parser.parse_args()
    healthcheck() if args.healthcheck else serve()
