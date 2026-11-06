"""Tiny deterministic lab service; intentionally no host port is published."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == '/download':
            body = b'node-a-lab-data\n' * 512
            content_type = 'application/octet-stream'
        else:
            body = json.dumps({'node': 'A', 'path': path, 'status': 'ok'}).encode()
            content_type = 'application/json'
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, fmt, *args):
        if urlsplit(self.path).path != '/health':
            super().log_message(fmt, *args)


if __name__ == '__main__':
    ThreadingHTTPServer(('0.0.0.0', 8000), Handler).serve_forever()
