"""Run with: python -B dashboard/app.py [--port 8765]. No pip packages required."""
import argparse
import json
import secrets
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from controller import Controller, LabError

ROOT = Path(__file__).resolve().parents[1]
STATIC = Path(__file__).resolve().parent/'static'


def make_handler(controller, token, port):
    allowed_hosts = {'127.0.0.1:'+str(port), 'localhost:'+str(port)}
    origins = {'http://'+host for host in allowed_hosts}
    assets = {'/': ('index.html', 'text/html; charset=utf-8'),
              '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
              '/style.css': ('style.css', 'text/css; charset=utf-8')}

    class Handler(BaseHTTPRequestHandler):
        server_version = 'DDoSLabDashboard/1.0'

        def log_message(self, *args):
            pass

        def reply(self, status, value, content_type='application/json; charset=utf-8', download=False):
            if not isinstance(value, bytes):
                value = json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(value)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy',
                             "default-src 'self'; script-src 'self'; style-src 'self'; "
                             "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            if download:
                filename=download if isinstance(download,str) else 'demo-session.json'
                self.send_header('Content-Disposition', 'attachment; filename="'+filename+'"')
            try:
                self.end_headers()
                self.wfile.write(value)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

        def guard(self, mutation=False):
            if self.headers.get('Host') not in allowed_hosts:
                self.reply(403, {'error': 'Host không hợp lệ; chỉ mở localhost'})
                return False
            if self.headers.get('Origin') and self.headers['Origin'] not in origins:
                self.reply(403, {'error': 'Origin không hợp lệ'})
                return False
            if self.headers.get('Sec-Fetch-Site') == 'cross-site':
                self.reply(403, {'error': 'Không nhận yêu cầu cross-site'})
                return False
            if mutation and not secrets.compare_digest(self.headers.get('X-Dashboard-Token', ''), token):
                self.reply(403, {'error': 'Token không hợp lệ; tải lại dashboard'})
                return False
            return True

        def do_GET(self):
            if not self.guard():
                return
            request = urlsplit(self.path)
            try:
                if request.path in assets:
                    filename, mime = assets[request.path]
                    self.reply(200, (STATIC/filename).read_bytes(), mime)
                elif request.path == '/api/bootstrap':
                    self.reply(200, {'token': token, 'version': '1.0'})
                elif request.path == '/api/state':
                    self.reply(200, controller.snapshot())
                elif request.path == '/api/logs':
                    query = parse_qs(request.query)
                    if set(query)-{'node', 'kind', 'event'}:
                        raise LabError('Tham số log không hợp lệ')
                    value = controller.logs(query.get('node', ['a'])[0],
                                            query.get('kind', ['eve'])[0],
                                            query.get('event', ['flow'])[0])
                    self.reply(200, {'text': value})
                elif request.path == '/api/export':
                    state = controller.snapshot()
                    self.reply(200, {'session': state['session'], 'created_at': state['now'],
                                     'jobs': state['jobs'], 'note': 'Live integration evidence; no synthetic attack accuracy claim.'},
                               download=True)
                elif request.path == '/api/dataset/rows':
                    query=parse_qs(request.query)
                    if set(query)-{'job','model','filter','page','size'}:
                        raise LabError('Tham số dataset không hợp lệ')
                    self.reply(200,controller.dataset_rows(query.get('job',[''])[0],
                        query.get('model',['local'])[0],query.get('filter',['all'])[0],
                        int(query.get('page',['1'])[0]),int(query.get('size',['50'])[0])))
                elif request.path == '/api/dataset/export':
                    query=parse_qs(request.query)
                    if set(query)-{'job','format'}:
                        raise LabError('Tham số export không hợp lệ')
                    format_name=query.get('format',['csv'])[0]
                    if format_name not in ('csv','json'):
                        raise LabError('Chỉ export csv/json')
                    path,summary=controller.dataset_artifact(query.get('job',[''])[0])
                    if format_name=='csv':
                        self.reply(200,path.read_bytes(),'text/csv; charset=utf-8',download='dataset-predictions.csv')
                    else:
                        self.reply(200,summary,download='dataset-report.json')
                else:
                    self.reply(404, {'error': 'Không tìm thấy'})
            except (LabError, ValueError) as error:
                self.reply(400, {'error': str(error)})
            except (OSError, TypeError, KeyError) as error:
                self.reply(500, {'error': type(error).__name__+': '+str(error)[:500]})

        def do_POST(self):
            if not self.guard(mutation=True):
                return
            if self.path != '/api/action':
                self.reply(404, {'error': 'Không tìm thấy'})
                return
            try:
                size = int(self.headers.get('Content-Length', '-1'))
                if not 0 < size <= 8192:
                    raise LabError('Body phải từ 1 đến 8192 byte')
                if self.headers.get_content_type() != 'application/json':
                    raise LabError('Cần Content-Type application/json')
                payload = json.loads(self.rfile.read(size))
                self.reply(202, controller.submit(payload))
            except (LabError, ValueError, TypeError, KeyError) as error:
                self.reply(400, {'error': str(error)})
            except OSError as error:
                self.reply(500, {'error': str(error)[:500]})

    return Handler


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        # Normal browser reload/tab-close can abort an in-flight polling request.
        if not isinstance(sys.exc_info()[1],
                          (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)):
            super().handle_error(request, client_address)


def main():
    # Windows consoles and redirected output may default to cp1258/cp1252.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--open', action='store_true', help='Open the local dashboard in a browser')
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error('Port phải nằm trong 1024..65535')
    if not (ROOT/'compose.node-a-live.yaml').is_file():
        parser.error('Đặt dashboard bên trong root dự án ddos-fl-laptop')
    token = secrets.token_urlsafe(32)
    controller = Controller(ROOT)
    try:
        server = Server(('127.0.0.1', args.port), make_handler(controller, token, args.port))
    except OSError as error:
        controller.closed.set()
        parser.exit(1, 'Không mở được dashboard: '+str(error)+'\n')
    print('Dashboard: http://127.0.0.1:%s' % args.port, flush=True)
    print('Chạy trực tiếp trên Windows. Chưa bật/tắt lab, gửi traffic hoặc train FL.', flush=True)
    print('Ctrl+C dừng dashboard; các container lab giữ trạng thái hiện tại.', flush=True)
    if args.open:
        webbrowser.open('http://127.0.0.1:'+str(args.port))
    try:
        server.serve_forever(poll_interval=.5)
    except KeyboardInterrupt:
        pass
    finally:
        controller.closed.set()
        server.server_close()


if __name__ == '__main__':
    main()
