#!/usr/bin/env python3
"""Serve a locally built Flutter web demo. Accepts proxied preview hosts."""
import argparse
import functools
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class Handler(SimpleHTTPRequestHandler):
    extensions_map = {**SimpleHTTPRequestHandler.extensions_map, '.wasm': 'application/wasm'}

    def end_headers(self):
        self.send_header('Cache-Control', 'no-cache')
        super().end_headers()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', default='build/web')
    parser.add_argument('--port', type=int, default=8080)
    args = parser.parse_args()
    server = ThreadingHTTPServer(('0.0.0.0', args.port), functools.partial(Handler, directory=args.directory))
    print(f'Mohalla Charcha preview listening on 0.0.0.0:{args.port}', flush=True)
    server.serve_forever()
