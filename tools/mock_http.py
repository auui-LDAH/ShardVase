#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
r"""`tools/mock_http.py` — 在线会话 mock 服务器（**W4, 2026-09-25**）。

## 为什么需要（**实测驱动**）
  `tests/e2e.py` 的在线用例（T22-T28）原用 **in-process** `http.server`：
```
Windows 侧起服务 -> demo 在 **WSL 内**执行
-> **WSL 的 127.0.0.1 != Windows 的**（实测 curl rc=7 Connection refused）
```
  **W3 之前**: Linux 无 HTTP 能力 -> 这些用例只能标 `PLATFORM_NA`（**7 项**）。
  **W3 之后**: Linux 有了 POSIX socket HTTP -> **服务进 WSL 即可真验证**。

  ## 与 e2e 的**协议**（端口协商）
```
1. 调用方: wsl -- python3 tools/mock_http.py --mode check --revoke-serial X
2. 本工具: bind 127.0.0.1:0 -> **stdout 打印 `PORT=<n>`**（flush）
3. 调用方: 读该行 -> URL = http://127.0.0.1:<n>/v1/check
4. 调用方: 用完 kill
```

  ## ⚠️ 参数**必须用命令行**（不是环境变量）
    **实测教训（§32.2）**: Windows 的环境变量**不自动进入 WSL**
    （需 `WSLENV` 配置）—— 用环境变量传 `revoke_serial` 会**静默丢失**
    -> 服务器永不吊销 -> 测试假通过/假失败。
    => **命令行参数**才可靠（直接进 WSL 内进程的 argv）。

  ## 语义来源（**逐字复刻** e2e 的 `_*Handler`）
| mode | 对应 e2e 类 | 语义 |
|------|-----------|------|
| `check` | `_CheckHandler` | 路径含 `serial=<revoke_serial>` -> `revoked`，否则 `ok` |
| `expect` | `_ExpectHandler` | `--wrong` -> 固定错值；否则用 `vmenc.compute_expect` 复算 |
| `blob` | `_BlobHandler` | 把 `--blob-file` 的字节原样下发 |

  ## 诚实边界
  · **仅测试用**: 无鉴权、仅绑 `127.0.0.1`、不对外
  · 与 e2e 的 handler 是**两处实现**（一个在 Windows Python、一个在 WSL）
    —— 语义靠本注释的表格对齐；若将来漂移，**以 e2e 为准**（判据来源）
"""
import argparse
import http.server
import os
import socketserver
import sys
import threading
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

#: 仓库根（本文件在 tools/ 下）
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CheckHandler(http.server.BaseHTTPRequestHandler):
    """`/v1/check` —— 逐字复刻 e2e 的 `_CheckHandler`。"""

    revoke_serial = None

    def log_message(self, *a):
        pass

    def do_GET(self):
        if '/v1/check' not in self.path:
            self.send_response(404)
            self.end_headers()
            return
        revoked = (self.revoke_serial is not None and
                   ('serial=%s' % self.revoke_serial) in self.path)
        body = b'{"status":"revoked","reason":"e2e"}' if revoked \
            else b'{"status":"ok","tier":1}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(body)


class ExpectHandler(http.server.BaseHTTPRequestHandler):
    """`/v1/check`（期望值）—— 逐字复刻 e2e 的 `_ExpectHandler`。"""

    wrong = False

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.wrong:
            body = (b'{"status":"ok","tier":1,'
                    b'"expect1":"0x1111111111111111",'
                    b'"expect2":"0x2222222222222222"}')
        else:
            body = compute_expect_body(self.path)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(body)


class BlobHandler(http.server.BaseHTTPRequestHandler):
    """`/v1/blob` —— 逐字复刻 e2e 的 `_BlobHandler`。"""

    serve_blob = b''

    def log_message(self, *a):
        pass

    def do_GET(self):
        if '/v1/blob' not in self.path:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(self.serve_blob)))
        self.end_headers()
        self.wfile.write(self.serve_blob)


def compute_expect_body(path):
    """按 e2e 的语义从 `path` 复算正确期望值（与 `vmenc` 同源）。"""
    sys.path.insert(0, os.path.join(REPO, 'tools'))
    try:
        from urllib.parse import parse_qs, urlparse
        from vmenc import compute_expect
        qs = parse_qs(urlparse(path).query)
        serial_q = qs.get('serial', [''])[0]
        mid_q = int(qs.get('mid', ['0'])[0], 16)
        h, total = compute_expect(serial_q, mid_q)
        return ('{"status":"ok","tier":1,"expect1":"0x%x",'
                '"expect2":"0x%x"}' % (h, total)).encode()
    except Exception:                     # noqa: BLE001
        return b'{"status":"ok","tier":1}'


def build_server(mode, args):
    """按 mode 构造 server（**语义与 e2e 的 `start_*` 对齐**）。"""
    if mode == 'check':
        CheckHandler.revoke_serial = args.revoke_serial
        return socketserver.TCPServer(('127.0.0.1', 0), CheckHandler)
    if mode == 'expect':
        ExpectHandler.wrong = bool(args.wrong)
        return socketserver.TCPServer(('127.0.0.1', 0), ExpectHandler)
    if mode == 'blob':
        if not args.blob_file:
            raise SystemExit('mock_http: --mode blob 需要 --blob-file')
        # 与 e2e 同法: 读**平台 blob**（Linux: build/linux/vm.blob）
        with open(args.blob_file, 'rb') as f:
            BlobHandler.serve_blob = f.read()
        return socketserver.TCPServer(('127.0.0.1', 0), BlobHandler)
    raise SystemExit('mock_http: unknown mode %r' % mode)


def main():
    ap = argparse.ArgumentParser(prog='mock_http.py')
    ap.add_argument('--mode', required=True,
                    choices=['check', 'expect', 'blob'])
    ap.add_argument('--revoke-serial', default=None,
                    help='check: 吊销该 serial（缺省 = 不吊销）')
    ap.add_argument('--wrong', action='store_true',
                    help='expect: 下发**错误**期望值')
    ap.add_argument('--blob-file', default=None,
                    help='blob: 下发的 blob 文件路径')
    args = ap.parse_args()

    srv = build_server(args.mode, args)
    print('PORT=%d' % srv.server_address[1], flush=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        for _ in range(600):              # 最多 10 分钟（调用方 kill 即止）
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        srv.shutdown()
    return 0


if __name__ == '__main__':
    sys.exit(main())
