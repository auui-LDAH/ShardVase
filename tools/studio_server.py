#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Studio 外壳的服务端（ST5）—— 本地浏览器 UI 与 `studio_core` 之间的桥。

## 它在架构里的位置

    studio/static/*  (浏览器)  --HTTP/NDJSON-->  本模块  --函数调用-->  studio_core
                                                                          |
                                                          build.ps1 / prot_dbg.py / ...

**本模块不含任何业务判据。** 它只做三件事：静态文件、令牌校验、把
`studio_core.envelope()` / `stream_events()` 的结果按 NDJSON 写到 HTTP 响应里。
「什么算通过」「哪些模块可选」这类问题一律由 `studio_core` 回答 ——
在这里再做一次判断就是制造第二套口径（见 `docs/STUDIO_PLAN.md` D2）。

## 安全纪律（每条都有实测理由，不是默认值堆砌）

1. **只绑 `127.0.0.1`。** 不提供 `--host` 参数 —— 一个能被写成 `0.0.0.0`
   的开关，迟早会被写成 `0.0.0.0`。调试面板的默认值必须是拒绝。
2. **端口缺省为 0**（由内核分配空闲端口）。固定端口会在并发开发 / CI 上
   撞车，而撞车的表现是「服务起不来」而不是「起在别的端口」，容易被误读。
3. **一次性令牌**，每次启动重新生成（`secrets.token_urlsafe`）。
   所有 `/api/**` 都要求 `X-Studio-Token` 头。**页面本身与静态资源不要求令牌**
   —— 它们不含任何仓库状态，且浏览器无法为首屏 HTML 请求附加自定义头。
   令牌经 URL 的 **fragment**（`#t=...`）传给页面：fragment 不会进
   `Referer`，也不会进服务端访问日志。
4. **不自动打开浏览器。** 项目的硬约束是「所有命令静默执行，不要弹出窗口」
   （m14637/m14638）。本模块**打印 URL**，由人来点 —— 一个调试服务器
   没有资格替用户弹出一个窗口。
5. **零外部请求。** 不引 CDN、不引字体、不引任何前端库。UI 完全离线可用，
   且不会把「谁在用这个工具」泄露给第三方（本项目的用户正是最在意这件事的人）。
6. **路径穿越必须被拒。** 静态服务用 `realpath` + 前缀比对，且**在客户端
   与规范化之后各判一次**（`%2e%2e%2f` 这类编码要先解码再判）。
   `--selftest` 里有对应的负向用例。

## 退出码

`0` 正常结束（Ctrl+C） / `1` 启动失败 / `2` 用法错误 / `--selftest` 通过为 0
"""
import argparse
import json
import mimetypes
import os
import secrets
import sys
import time
import traceback
import urllib.parse

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
if os.path.join(REPO, 'tools') not in sys.path:
    sys.path.insert(0, os.path.join(REPO, 'tools'))

import studio_core as sc  # noqa: E402

HOST = '127.0.0.1'
UI_DIR = os.path.join(REPO, 'studio')
STATIC_NAME = 'static'
STATIC_DIR = os.path.join(UI_DIR, STATIC_NAME)
TOKEN_HEADER = 'X-Studio-Token'
TOKEN_QUERY = 't'
MAX_BODY = 1 << 20          # 1 MiB：请求体是参数，不是数据
PROTOCOL_VERSION = sc.PROTOCOL_VERSION

RC_OK = 0
RC_FAIL = 1
RC_USAGE = 2

MIME = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.png': 'image/png',
    '.txt': 'text/plain; charset=utf-8',
}


def new_token():
    """每次启动一个新的令牌。不是常量、不是配置项 —— 它没有「记住」的语义。"""
    return secrets.token_urlsafe(24)


# ---------------------------------------------------------------- 静态文件安全

def safe_join(root, rel):
    """把 URL 路径解析成 `root` 下的真实文件，越界返回 None。

    ⚠️ 为什么不能只判 `'..' in rel`：URL 里 `%2e%2e%2f` 解码后才是 `../`，
    而 Windows 上 `\\` 与 `/` 都算分隔符。这里统一解码 → 统一分隔符 →
    `normpath` → `realpath` 前缀比对，四步都做，最后一步才是有决定性的那步。
    """
    if not rel:
        return None
    rel = rel.replace('\\', '/')
    if '\x00' in rel:
        return None
    rel = rel.lstrip('/')
    cand = os.path.realpath(os.path.join(root, rel))
    root_real = os.path.realpath(root)
    if cand == root_real:
        return None
    if not cand.startswith(root_real + os.sep):
        return None
    return cand


# ---------------------------------------------------------------- HTTP handler

class Handler(BaseHTTPRequestHandler):
    server_version = 'ShardVaseStudio/' + sc.STUDIO_VERSION
    protocol_version = 'HTTP/1.1'

    # 请求日志默认关闭：调试服务器会为一次页面加载产生几十条请求行，
    # 把它们倒进终端会把真正重要的东西（构建输出 / 错误）冲掉。
    def log_message(self, fmt, *a):
        if getattr(self.server, 'verbose', False):
            sys.stderr.write('[studio_server] %s - %s\n' % (self.address_string(), fmt % a))

    # ---- 小工具 ----

    def _token_ok(self):
        got = self.headers.get(TOKEN_HEADER) or ''
        want = self.server.token
        # 常数时间比较：令牌是秘密，不给出时间侧信道（哪怕是本地）。
        return bool(want) and secrets.compare_digest(got, want)

    def _send_bytes(self, body, ctype, code=200, extra=None):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        # 本地 UI 会反复重启、改端口；缓存只会让人对着旧页面排查新问题。
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False, sort_keys=True).encode('utf-8')
        self._send_bytes(body, 'application/json; charset=utf-8', code)

    def _send_error_json(self, code, err_code, message, detail=None):
        self._send_json({'id': None, 'ok': False,
                         'error': {'code': err_code, 'message': message,
                                   'detail': detail or {}}}, code)

    def _read_body(self):
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            return None, 'Content-Length 不是整数'
        if n < 0 or n > MAX_BODY:
            return None, '请求体过大（上限 %d 字节）' % MAX_BODY
        if n == 0:
            return b'', None
        return self.rfile.read(n), None

    # ---- 路由 ----

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = urllib.parse.unquote(parsed.path)
        if path in ('/', '/index.html'):
            self._serve_static('index.html', root=self.server.ui_dir)
            return
        if path == '/favicon.ico':
            # 204 而不是 404：浏览器对 favicon 的失败会打控制台噪声，
            # 而噪声会掩盖真正的错误。
            self._send_bytes(b'', 'image/x-icon', 204)
            return
        if path.startswith('/api'):
            # GET 不该执行命令。一条能被 GET 触发的副作用命令会被
            # 浏览器的预取 / 历史恢复悄悄执行。
            self._send_error_json(405, 'E_BAD_ARGS',
                                  'API 只接受 POST（命令不是幂等的，GET 会被预取触发）',
                                  {'method': 'GET', 'use': 'POST /api'})
            return
        self._serve_static(path.lstrip('/'),
                           root=os.path.join(self.server.ui_dir, STATIC_NAME))

    def do_HEAD(self):
        self.do_GET()

    def _serve_static(self, rel, root):
        full = safe_join(root, rel)
        if not full or not os.path.isfile(full):
            self._send_bytes(('未找到: %s' % rel).encode('utf-8'),
                             'text/plain; charset=utf-8', 404)
            return
        try:
            with open(full, 'rb') as fh:
                body = fh.read()
        except OSError as e:
            self._send_bytes(('读取失败: %s' % e).encode('utf-8'),
                             'text/plain; charset=utf-8', 500)
            return
        ext = os.path.splitext(full)[1].lower()
        ctype = MIME.get(ext) or mimetypes.guess_type(full)[0] or 'application/octet-stream'
        self._send_bytes(body, ctype)

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = urllib.parse.unquote(parsed.path)
        if path not in ('/api', '/api/stream'):
            self._send_error_json(404, 'E_NOT_FOUND', '没有这个端点',
                                  {'path': path, 'endpoints': ['/api', '/api/stream']})
            return
        if not self._token_ok():
            # 令牌只认请求头。放在 query 里会被 Referer / 日志 / 截图带出去，
            # 而这条路径的唯一目的就是不让别人拿到它。
            self._send_error_json(401, 'E_FORBIDDEN', '缺少或错误的令牌',
                                  {'header': TOKEN_HEADER,
                                   'how': '页面从 URL fragment（#t=...）取令牌后放进请求头',
                                   'query_token_accepted': False})
            return

        raw, err = self._read_body()
        if err:
            self._send_error_json(400, 'E_BAD_ARGS', err, {})
            return
        try:
            req = json.loads(raw.decode('utf-8')) if raw else {}
        except (ValueError, UnicodeDecodeError) as e:
            self._send_error_json(400, 'E_BAD_LINE', '请求体不是合法 JSON: %s' % e, {})
            return
        if not isinstance(req, dict):
            self._send_error_json(400, 'E_BAD_ARGS', '请求体必须是 JSON 对象',
                                  {'given': type(req).__name__})
            return

        cmd = req.get('cmd')
        args = req.get('args') or {}
        rid = req.get('id')

        if path == '/api/stream':
            self._stream(cmd, args, rid)
        else:
            self._send_json(sc.envelope(cmd, args, rid))

    def _stream(self, cmd, args, rid):
        """一个请求 → 多行 NDJSON 响应。

        没有 `Content-Length`：响应的结束由连接关闭界定。浏览器端用
        `fetch()` + `response.body.getReader()` 逐行读 —— 这样构建输出是
        **边跑边到**的，而不是跑完一次性到达（后者会让面板在几分钟里
        看起来像卡死）。
        """
        self.send_response(200)
        self.send_header('Content-Type', 'application/x-ndjson; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True

        def w(obj):
            self.wfile.write((json.dumps(obj, ensure_ascii=False, sort_keys=True) + '\n')
                             .encode('utf-8'))
            self.wfile.flush()

        try:
            for ev in sc.stream_events(cmd, args):
                w({'id': rid, 'ok': True, 'event': ev})
        except sc.StudioError as e:
            w({'id': rid, 'ok': False, 'error': e.to_dict()})
        except Exception as e:                       # noqa: BLE001 - 边界层兜底
            w({'id': rid, 'ok': False,
               'error': {'code': 'E_INTERNAL',
                         'message': '%s: %s' % (type(e).__name__, e),
                         'detail': {'traceback': traceback.format_exc().splitlines()[-3:]}}})
        # 收尾空行：让客户端的「最后一行没有换行符」处理少一个特例。
        w({'id': rid, 'ok': True, 'end': True})


# ---------------------------------------------------------------- 启动

def make_server(port=0, token=None, ui_dir=None, verbose=False, host=HOST):
    """起一个服务器并返回 `(httpd, token, url)`。

    `ui_dir` 可覆盖（`--selftest` 用一个临时目录造合成的 UI，从而
    **不依赖真实的 studio/ 存在** —— 判据要测的是服务端，不是资产）。

    ⚠️ `ui_dir` 存在**实例**上（`httpd.ui_dir`），不写模块全局。
    第一版写的是全局，结果自检里"合成 UI"那一步把真实路径**覆盖**了，
    于是最后一条「真实资产自洽」判据拿到的是临时目录 ——
    它报的失败（找不到令牌字样）看起来像前端脱节，其实是我自己的探针改坏了环境。
    **服务端状态属于服务器实例；放模块全局的代价是"同时只能有一个用户"。**
    """
    tok = token or new_token()
    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.ui_dir = ui_dir or UI_DIR
    httpd.token = tok
    httpd.verbose = verbose
    httpd.daemon_threads = True
    actual = httpd.server_address[1]
    url = 'http://%s:%d/#t=%s' % (host, actual, tok)
    return httpd, tok, url


def serve_forever(port=0, token=None, verbose=False):
    httpd, tok, url = make_server(port=port, token=token, verbose=verbose)
    sys.stdout.write('[studio_server] ShardVase Studio %s (protocol v%d)\n'
                     % (sc.STUDIO_VERSION, PROTOCOL_VERSION))
    sys.stdout.write('[studio_server] 打开这个地址（令牌在 # 后面，不会进 Referer）：\n')
    sys.stdout.write('               %s\n' % url)
    sys.stdout.write('[studio_server] 只监听 %s；Ctrl+C 结束。'
                     '（刻意不自动打开浏览器 —— 本项目要求命令静默执行）\n' % HOST)
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stdout.write('\n[studio_server] 结束。\n')
    finally:
        httpd.server_close()
    return RC_OK


# ---------------------------------------------------------------- 自检

def _http(port, method, path, body=None, token=None, timeout=20.0):
    """极简 HTTP 客户端（urllib），返回 `(code, headers, bytes)`。"""
    import urllib.error
    import urllib.request
    url = 'http://%s:%d%s' % (HOST, port, path)
    data = json.dumps(body).encode('utf-8') if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header('Content-Type', 'application/json')
    if token:
        req.add_header(TOKEN_HEADER, token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _stream_lines(port, path, body, token, timeout=60.0):
    import urllib.request
    req = urllib.request.Request('http://%s:%d%s' % (HOST, port, path),
                                 data=json.dumps(body).encode('utf-8'),
                                 method='POST')
    req.add_header('Content-Type', 'application/json')
    req.add_header(TOKEN_HEADER, token)
    out = []
    with urllib.request.urlopen(req, timeout=timeout) as r:
        for line in r:
            line = line.decode('utf-8').strip()
            if line:
                out.append(json.loads(line))
    return out


def selftest(quiet=False):
    """负向优先：每条判据都要能**失败**，并且失败方式可指认。"""
    import shutil
    import tempfile
    import threading

    results = []

    def case(name, ok, detail=''):
        results.append((name, bool(ok), detail))

    def near(a, b, tol=400):
        return abs(a - b) <= tol

    tmp = tempfile.mkdtemp(prefix='studio_srv_')
    try:
        # 合成 UI：判据测服务端，不测真实资产是否存在。
        os.makedirs(os.path.join(tmp, 'static'))
        with open(os.path.join(tmp, 'index.html'), 'w', encoding='utf-8') as fh:
            fh.write('<!doctype html><title>t</title><p id=probe>INDEX</p>')
        with open(os.path.join(tmp, 'static', 'app.js'), 'w', encoding='utf-8') as fh:
            fh.write('/*app*/')
        with open(os.path.join(tmp, 'static', 'style.css'), 'w', encoding='utf-8') as fh:
            fh.write('/*css*/')
        outside = os.path.join(tmp, 'secret.txt')
        with open(outside, 'w', encoding='utf-8') as fh:
            fh.write('TOP-SECRET')

        httpd, tok, url = make_server(port=0, ui_dir=tmp)
        port = httpd.server_address[1]
        th = threading.Thread(target=httpd.serve_forever, daemon=True)
        th.start()
        time.sleep(0.2)
        try:
            # 1 静态资源无需令牌（浏览器无法为首屏 HTML 加自定义头）
            c, _h, b = _http(port, 'GET', '/')
            case('静态 index.html 无需令牌即可取', c == 200 and b'INDEX' in b,
                 'code=%s' % c)

            # 2 子目录静态资源 + 正确 MIME
            c, h, b = _http(port, 'GET', '/app.js')
            case('静态 app.js 取自 static/ 且 MIME 正确',
                 c == 200 and b'/*app*/' in b and 'javascript' in h.get('Content-Type', ''),
                 'code=%s ct=%s' % (c, h.get('Content-Type')))

            c, h, _b = _http(port, 'GET', '/style.css')
            case('静态 style.css MIME = text/css',
                 c == 200 and 'text/css' in h.get('Content-Type', ''),
                 'code=%s ct=%s' % (c, h.get('Content-Type')))

            # 3 无令牌 -> 401
            c, _h, b = _http(port, 'POST', '/api', {'cmd': 'ping'})
            case('**负向** 无令牌 -> 401 且不是 200', c == 401, 'code=%s' % c)

            # 4 错令牌 -> 401
            c, _h, _b = _http(port, 'POST', '/api', {'cmd': 'ping'}, token='x' * 30)
            case('**负向** 错令牌 -> 401', c == 401, 'code=%s' % c)

            # 5 令牌放 query 不算数（它会被 Referer/日志带出去）
            c, _h, _b = _http(port, 'POST', '/api?t=%s' % tok, {'cmd': 'ping'})
            case('**负向** 令牌只在 query 里 -> 仍 401', c == 401, 'code=%s' % c)

            # 6 正确令牌 -> 正常应答
            c, _h, b = _http(port, 'POST', '/api', {'cmd': 'ping', 'id': 7}, token=tok)
            d = json.loads(b.decode('utf-8'))
            case('正确令牌 -> ok 且 id 原样回传',
                 c == 200 and d.get('ok') is True and d.get('id') == 7
                 and d['data'].get('protocol_version') == PROTOCOL_VERSION,
                 'code=%s ok=%s id=%s' % (c, d.get('ok'), d.get('id')))

            # 7 未知命令 -> 结构化错误（不是 500，不是空响应）
            c, _h, b = _http(port, 'POST', '/api', {'cmd': 'nope.nope'}, token=tok)
            d = json.loads(b.decode('utf-8'))
            case('未知命令 -> E_UNKNOWN_CMD 且 200（错误是数据，不是 HTTP 失败）',
                 c == 200 and d.get('ok') is False
                 and d['error']['code'] == 'E_UNKNOWN_CMD'
                 and 'nope.nope' in json.dumps(d['error'].get('detail'), ensure_ascii=False),
                 'code=%s err=%s' % (c, d.get('error', {}).get('code')))

            # 8 **负向** 路径穿越（三种形态都要被拒）
            trav = ['/../secret.txt',
                    '/%2e%2e%2fsecret.txt',
                    '/..%2fsecret.txt',
                    '/static/../../secret.txt']
            od = []
            for p in trav:
                c, _h, b = _http(port, 'GET', p)
                od.append((p, c, b'TOP-SECRET' in b))
            case('**负向** 路径穿越（含 URL 编码）一律拿不到界外文件',
                 all((not leak) and c in (400, 404, 403) for _p, c, leak in od),
                 '; '.join('%s->%s leak=%s' % t for t in od))

            # 9 **负向** GET /api 不被当成命令执行
            c, _h, b = _http(port, 'GET', '/api?t=%s' % tok)
            case('**负向** GET /api -> 405（GET 会被预取，不能触发命令）', c == 405,
                 'code=%s' % c)

            # 10 **负向** 请求体不是 JSON 对象
            c, _h, b = _http(port, 'POST', '/api', ['not', 'an', 'object'], token=tok)
            d = json.loads(b.decode('utf-8'))
            case('**负向** 请求体是数组 -> E_BAD_ARGS 且说明实际类型',
                 c == 400 and d['error']['code'] == 'E_BAD_ARGS'
                 and d['error']['detail'].get('given') == 'list',
                 'code=%s detail=%s' % (c, d.get('error', {}).get('detail')))

            # 11 流式：不带 confirm 只出计划（与 build.run 同一纪律）
            evs = _stream_lines(port, '/api/stream',
                                {'cmd': 'build.run', 'id': 11, 'args': {}}, tok)
            kinds = [e.get('event', {}).get('event') for e in evs if 'event' in e]
            case('**负向** build.run 不带 confirm -> 只有 plan/done，没有 start',
                 'plan' in kinds and 'start' not in kinds and kinds[-1:], 
                 'events=%s' % kinds)

            # 12 流式：每条事件共用同一个 id（调用方据此归并）
            ids = set(e.get('id') for e in evs if e.get('event'))
            case('同一条流的所有事件共用同一个 id', ids == {11}, 'ids=%s' % sorted(ids))

            # 13 **负向** 流式命令不在真实命令表里（否则面板会走错路径）
            c, _h, b = _http(port, 'POST', '/api', {'cmd': 'build.run'}, token=tok)
            d = json.loads(b.decode('utf-8'))
            case('**负向** dispatch(build.run) -> E_STREAM_CMD（不是 E_UNKNOWN_CMD）',
                 d.get('ok') is False and d['error']['code'] == 'E_STREAM_CMD',
                 'err=%s' % d.get('error', {}).get('code'))

            # 14 未知端点
            c, _h, b = _http(port, 'POST', '/nope', {'cmd': 'ping'}, token=tok)
            d = json.loads(b.decode('utf-8'))
            case('**负向** 未知端点 -> 404 + E_NOT_FOUND',
                 c == 404 and d['error']['code'] == 'E_NOT_FOUND', 'code=%s' % c)

            # 15 令牌每次启动都不同
            h2, tok2, _u2 = make_server(port=0, ui_dir=tmp)
            case('令牌每次启动不同（不是常量、不落盘）', tok != tok2,
                 'len=%d/%d' % (len(tok), len(tok2)))
            h2.server_close()

            # 16 只绑回环：常量与实测都要对
            bound = httpd.server_address[0]
            case('只绑 127.0.0.1（HOST 常量与内核实测一致）',
                 HOST == '127.0.0.1' and bound == '127.0.0.1', 'bound=%s' % bound)

            # 17 响应不得带 Expires/长缓存（改完端口看到旧页面会误导排查）
            _c, h, _b = _http(port, 'GET', '/')
            case('静态响应 Cache-Control: no-store 且 nosniff',
                 h.get('Cache-Control') == 'no-store'
                 and h.get('X-Content-Type-Options') == 'nosniff',
                 'cc=%s nosniff=%s' % (h.get('Cache-Control'),
                                       h.get('X-Content-Type-Options')))

            # 18 favicon 用 204 而不是 404（404 会污染控制台噪声）
            c, _h, b = _http(port, 'GET', '/favicon.ico')
            case('favicon -> 204 且无响应体', c == 204 and not b, 'code=%s' % c)

            # 19 URL 里的令牌在 fragment 中（不在 query，避免 Referer 泄漏）
            case('启动 URL 把令牌放在 fragment（#t=），不落进请求行',
                 ('#t=' in url) and ('?' not in url.split('#')[0].split('://', 1)[1]),
                 'url=%s' % url.replace(tok, '<tok>'))
        finally:
            httpd.shutdown()
            httpd.server_close()
            time.sleep(0.1)

        # 20 真实 UI 资产存在且自洽（这一条才检查仓库里的 studio/）
        #    ⚠️ 它与上面 19 条**不同源**：上面用合成 UI 测服务端，这里测资产。
        real_ok, det = _check_real_ui()
        case('真实 studio/ 资产存在、可解析、无外部引用', real_ok, det)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    bad = [r for r in results if not r[1]]
    if not quiet:
        sys.stdout.write('=== studio_server 自检 ===\n')
        for name, ok, detail in results:
            sys.stdout.write('  %s %s%s\n' % ('ok  ' if ok else '[XX]', name,
                                              ('  (%s)' % detail) if detail else ''))
    sys.stdout.write('[studio_server-selftest] %s: %d 项（含 %d 项负向）\n'
                     % ('PASS' if not bad else 'FAIL', len(results),
                        sum(1 for n, _o, _d in results if '负向' in n)))
    return RC_OK if not bad else RC_FAIL


def _check_real_ui():
    """检查仓库里的 `studio/`。**判据只查"能自洽运行"，不查美观。**"""
    idx = os.path.join(UI_DIR, 'index.html')
    if not os.path.isfile(idx):
        return False, 'studio/index.html 不存在'
    assets = []
    for sub in ('static/app.js', 'static/style.css'):
        p = os.path.join(UI_DIR, sub)
        if not os.path.isfile(p):
            return False, '缺少 studio/%s' % sub
        assets.append(p)
    blob = ''
    for p in [idx] + assets:
        blob += open(p, 'r', encoding='utf-8').read()
    # 零外部请求：不得出现 http(s):// 指向本机以外的资源
    import re as _re
    ext = [u for u in _re.findall(r'https?://[^\s"\'<>)]+', blob)
           if '127.0.0.1' not in u and 'localhost' not in u]
    if ext:
        return False, '存在外部引用（离线纪律）: %s' % ext[:3]
    for needle in ('X-Studio-Token', '/api'):
        if needle not in blob:
            return False, '资产里找不到 %s —— 前端与协议可能已经脱节' % needle
    # 构建配置的下拉框必须覆盖 BUILD_CONFIGS。**这一条与上面的 needle 同类,
    # 但方向相反**: needle 查「前端是否用了协议」, 它查「协议里的能力前端能否
    # 触达」。ST3.2 新增 Debug 时正是这里漏掉的 —— 后端支持、协议文档写了三个
    # 取值, 而面板只发 Dev/Release ⇒ Debug 构建从 Studio 里调不到, 且不会报错。
    wants = list(getattr(sc, 'BUILD_CONFIGS', ()))
    if wants:
        m = _re.search(r'<select[^>]*id="cfg"[^>]*>(.*?)</select>', blob,
                       _re.S)
        if not m:
            return False, '生成面板缺少配置下拉框 (#cfg) —— 构建配置无处可选'
        have = _re.findall(r'<option[^>]*value="([^"]+)"', m.group(1))
        missing = [c for c in wants if c not in have]
        if missing:
            return False, ('配置下拉框缺 %s（后端支持: %s；面板只有: %s）'
                           % (missing, wants, have))
    # ST5.3/ST5.4 同型的第二例：**协议里的能力前端能否触达**。
    # 反汇编视图原本只有一个 prompt() 弹窗（连行号都无法显示），断点/单步
    # 这些命令即使后端全通，面板上没有入口就等于不存在 —— 而且不会报错。
    # ⚠️ 判据只问「面板是否**提到**了这些命令」，不查它接得对不对（那是
    #    build/_st5_e2e.py 的活体检查）。这里防的是"后端加完了,前端忘接线"。
    vm_cmds = ('vm.source', 'vm.open', 'vm.breakpoints', 'vm.continue',
               'vm.stepOver', 'vm.restart', 'vm.close')
    absent = [c for c in vm_cmds if c not in blob]
    if absent:
        return False, ('前端没有引用 VM 调试命令 %s —— 后端支持而面板无入口'
                       '（与 #cfg 漏掉 Debug 同型: 不报错, 只是够不着）' % absent)
    for need in ('id="vmlisting"', 'id="vmtools"', 'id="vmstack"'):
        if need not in blob:
            return False, ('VM 视图缺少 %s —— 源码列表/调试工具条/调用栈'
                           '三者缺一, ST5.3/ST5.4 就没有落点' % need)
    if 'prompt(' in blob:
        return False, ('前端仍在用 prompt() 取输入 —— ST5.3 的验收就是把它'
                       '换成真的视图（prompt 里连行号都显示不了）')
    return True, '%d 个资产, 无外部引用' % (len(assets) + 1)


def main(argv=None):
    ap = argparse.ArgumentParser(prog='studio_server.py')
    ap.add_argument('--port', type=int, default=0,
                    help='监听端口（缺省 0 = 由内核分配空闲端口）')
    ap.add_argument('--token', help='固定令牌（仅供自检/复现；日常不要用）')
    ap.add_argument('--verbose', action='store_true', help='打印每条请求（默认关闭）')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--version', action='store_true')
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest(args.quiet)
    if args.version:
        sys.stdout.write('studio_server %s (protocol v%d)\n'
                         % (sc.STUDIO_VERSION, PROTOCOL_VERSION))
        return RC_OK
    if args.port < 0 or args.port > 65535:
        sys.stderr.write('端口超出范围: %d\n' % args.port)
        return RC_USAGE
    return serve_forever(port=args.port, token=args.token, verbose=args.verbose)


if __name__ == '__main__':
    sys.exit(main())
