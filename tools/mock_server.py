#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/mock_server.py — 在线验证 mock 服务端 (PHASE3 M3.1)

实现 docs/PHASE3.md §3 的 /v1/check 语义, 供客户端 online provider
开发/测试 (无需真服务器)。纯 stdlib (http.server)。

数据: 内存吊销集合 (--revoke 参数预置)。生产换成 VPS + nginx + TLS +
持久化存储 (PHASE3 M3.2)。

CLI:
    python tools/mock_server.py [--port 8000] [--revoke SERIAL[,TIER]]...

API:
    GET /v1/check?serial=<s>&mid=<hex>&tier=<n>&build=<ver>
      -> 200 {"status":"ok","tier":1}
      -> 200 {"status":"revoked","reason":"mock"}
      -> 404 {"status":"invalid"}
"""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class MockHandler(BaseHTTPRequestHandler):
    revoked = {}  # serial -> tier or None (全 tier)

    def log_message(self, fmt, *args):
        sys.stderr.write('[mock] %s\n' % (fmt % args))

    def do_GET(self):
        u = urlparse(self.path)
        if u.path != '/v1/check':
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"status":"not_found"}')
            return
        q = parse_qs(u.query)
        serial = (q.get('serial') or [''])[0]
        tier = int((q.get('tier') or ['0'])[0])
        if not serial:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"status":"invalid"}')
            return

        r = MockHandler.revoked.get(serial)
        if r is not None and (r is None or r == tier):
            body = json.dumps({'status': 'revoked', 'reason': 'mock'})
            self.send_response(200)
        else:
            body = json.dumps({'status': 'ok', 'tier': tier})
            self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(body.encode('ascii'))


def main():
    parser = argparse.ArgumentParser(description='online check mock server (M3.1)')
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--revoke', action='append', default=[],
                        help='SERIAL or SERIAL,TIER to revoke (repeatable)')
    args = parser.parse_args()

    for item in args.revoke:
        parts = item.split(',')
        serial = parts[0]
        tier = int(parts[1]) if len(parts) > 1 else None
        MockHandler.revoked[serial] = tier
        print('[mock] revoke: %s tier=%s' % (serial, tier))

    srv = HTTPServer(('127.0.0.1', args.port), MockHandler)
    print('[mock] listening on http://127.0.0.1:%d/v1/check' % args.port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
