"""Loopback-only offline reference app. Does not execute assessment commands."""
import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

def main():
    pages = json.loads((HERE / 'data' / 'pages.json').read_text(encoding='utf-8'))
    sources = {s['id']: s for s in json.loads((HERE / 'data' / 'sources.json').read_text(encoding='utf-8'))}

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(HERE / 'web'), **kwargs)

        def do_GET(self):
            url = urlsplit(self.path)
            if url.path == '/api/search-docs':
                q = parse_qs(url.query).get('q', [''])[0].strip().casefold()
                hits = []
                if len(q) >= 3:
                    for page in pages:
                        index = page['text'].casefold().find(q)
                        if index >= 0:
                            hits.append({'source': page['source'], 'name': sources[page['source']]['name'],
                                         'page': page['page'], 'snippet': page['text'][max(0, index-120):index+380]})
                data = json.dumps({'total': len(hits), 'hits': hits[:60]}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            if url.path == '/guides/detection':
                path = ROOT / 'Assessment Vault' / 'Detection Validation.md'
            elif url.path.startswith('/sources/'):
                sid = url.path.rsplit('/', 1)[-1]
                if sid not in sources:
                    self.send_error(404)
                    return
                path = ROOT / sources[sid]['path']
            elif url.path.startswith('/data/'):
                name = url.path.rsplit('/', 1)[-1]
                if name not in ('catalog.json', 'sources.json', 'coverage.json', 'commands.json'):
                    self.send_error(404)
                    return
                path = HERE / 'data' / name
            else:
                if url.path not in ('/', '/index.html', '/app.js', '/style.css'):
                    self.send_error(404)
                    return
                return super().do_GET()
            self.send_response(200)
            types = {'.pdf': 'application/pdf', '.json': 'application/json; charset=utf-8', '.md': 'text/plain; charset=utf-8'}
            self.send_header('Content-Type', types[path.suffix])
            self.send_header('Content-Length', str(path.stat().st_size))
            self.end_headers()
            with path.open('rb') as f:
                while chunk := f.read(65536):
                    self.wfile.write(chunk)

    print('Assessment Desk: http://127.0.0.1:8765 — Ctrl+C to stop', flush=True)
    ThreadingHTTPServer(('127.0.0.1', 8765), Handler).serve_forever()

if __name__ == '__main__':
    main()
