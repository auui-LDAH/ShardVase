#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
tools/mock_server.py — 在线验证 mock 服务端 (PHASE3 M3.1 + N5 会话级期望值)

实现 docs/PHASE3.md §3 的 /v1/check 语义, 供客户端 online provider
开发/测试 (无需真服务器)。纯 stdlib (http.server)。

N5 (ADVANCED2 §6): 响应携带**会话级期望值** expect1/expect2 —— 服务端用
与 vmenc.py 完全相同的算法 (compute_expect) 对请求的 serial+mid 复算,
每次请求下发相同的正确期望值; 客户端 VM#3 用会话期望值校验, 破解者
patch "期望值比较" 只对当次会话有效。生产服务端可在此之上每会话加盐
(expect ^ session_delta) 使值每次不同, 客户端同步解盐。

数据: 内存吊销集合 (--revoke 参数预置)。生产换成 VPS + nginx + TLS +
持久化存储 (PHASE3 M3.2)。

CLI:
    python tools/mock_server.py [--port 8000] [--revoke SERIAL[,TIER]]...

API:
    GET /v1/check?serial=<s>&mid=<hex>&tier=<n>&build=<ver>
      -> 200 {"status":"ok","tier":1,"expect1":"0x..","expect2":"0x.."}
      -> 200 {"status":"revoked","reason":"mock"}
      -> 404 {"status":"invalid"}
"""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

# N5: 复用 vmenc 的期望值算法 (与构建期 genserial 逐位一致)
sys.path.insert(0, __import__('os').path.dirname(__file__))
try:
    from vmenc import compute_expect
except ImportError:
    def compute_expect(serial, machine_id):
        raise RuntimeError('cannot import vmenc.compute_expect (N5)')


class MockHandler(BaseHTTPRequestHandler):
    revoked = {}   # serial -> tier or None (全 tier)
    blob_path = None  # BLOB_SIGN_PLAN: /v1/blob 下发的 vm.blob 文件

    def log_message(self, fmt, *args):
        sys.stderr.write('[mock] %s\n' % (fmt % args))

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == '/v1/blob':
            # BLOB_SIGN_PLAN: 下发签名版 vm.blob (客户端验签兜底, 防中间人)
            if not MockHandler.blob_path or \
                    not __import__('os').path.isfile(MockHandler.blob_path):
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'{"status":"not_found"}')
                return
            with open(MockHandler.blob_path, 'rb') as f:
                data = f.read()
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if u.path != '/v1/check':
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"status":"not_found"}')
            return
        q = parse_qs(u.query)
        serial = (q.get('serial') or [''])[0]
        tier = int((q.get('tier') or ['0'])[0])
        mid = int((q.get('mid') or ['0'])[0], 16)
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
            # N5: 服务端复算该 serial+mid 的正确期望值 (与 vmenc genserial
            # 一致), 下发会话级期望值 —— 客户端 VM#3 用它校验, 离线无法
            # 预知 (构建期默认是另一组值, 只在离线降级时用)。
            try:
                h, total = compute_expect(serial, mid)
                body = json.dumps({
                    'status': 'ok',
                    'tier': tier,
                    'expect1': '0x%x' % h,
                    'expect2': '0x%x' % total,
                })
            except Exception as e:  # 复算失败 -> 不含期望值 (客户端回退默认)
                sys.stderr.write('[mock] compute_expect failed: %s\n' % e)
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
    parser.add_argument('--blob', default=None,
                        help='vm.blob file to serve at /v1/blob (BLOB_SIGN_PLAN)')
    args = parser.parse_args()
    MockHandler.blob_path = args.blob

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
