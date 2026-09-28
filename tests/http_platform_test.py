#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
r"""`tests/http_platform_test.py` — Linux HTTP 平台层的**单测**（W3）。

## 测什么
  `src/platform/prot_platform_linux.c` 的
  `prot_plat_http_get` / `prot_plat_http_get_mem`（**POSIX socket 实现**）。

  ## 为什么**在 WSL 内**跑
    被测对象是 **Linux 产物**（ELF 平台层）—— 只能在 Linux 上编译/运行。
    这与本项目既有的"Linux 侧经 WSL 验证"一致（A/B/C 阶段的形态）。

  ## 覆盖（2 正向 + **8 负向**）
    正向: 下载到内存 / 下载到文件
    负向: **https 如实 UNSUPPORTED**（不假装成功）/ 端口不可达 / 非法
          scheme / 空 host / NULL 参数 x3 / 超 max_size（**文件须被删**）/
          cap 过小

  ## 为什么负向占多数
    HTTP 是**平台层新能力**（W3）—— 新能力的**错误路径**最容易出错
    （尤其"失败却报成功"）。计划 §29.6 明确要求"必须含负向单测，
    **不得**为了'让测试通过'而放宽 HTTP 语义"。

  ## 退出码
    0 = 全部通过；1 = 有失败；2 = 环境问题（未构建 / WSL 不可用）
"""
import os
import re
import subprocess
import sys
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DISTRO = 'Ubuntu-24.04'
BUILD = os.path.join(REPO, 'build')

#: 被测驱动（C 源码）—— **内嵌**，避免"驱动与测试分离导致漂移"
DRIVER_C = '/* `tests/http_platform_test.py` 的被测驱动（W3）。\n *\n * ## 为什么用 C 驱动而不是 Python ctypes\n *   被测对象是 **C 平台层**（`src/platform/prot_platform_linux.c`）——\n *   直接 `#include` 它并链接，**测的就是真实实现**（不是复制品）。\n *   ctypes 需要把 .so 的 ABI 拼对，反而更脆。\n *\n * ## 覆盖（2 正向 + 8 负向）\n *   正向: get_mem 下载 / get 下载到文件\n *   负向: https（如实 UNSUPPORTED）/ 不可达 / 非法 scheme / 空 host /\n *         NULL 参数 x3 / 超 max_size（**文件须被删**）/ cap 过小\n */\n#include <stdio.h>\n#include <string.h>\n#include <stdlib.h>\n#include "protect/prot_platform.h"\n\nstatic const char* st_name(prot_status st)\n{\n    switch (st) {\n    case PROT_OK:              return "OK";\n    case PROT_ERR_INVALID_ARG: return "INVALID_ARG";\n    case PROT_ERR_UNSUPPORTED: return "UNSUPPORTED";\n    case PROT_ERR_INTERNAL:    return "INTERNAL";\n    default:                   return "OTHER";\n    }\n}\n\nstatic int fails = 0;\n\nstatic void chk(const char* name, prot_status got, prot_status want)\n{\n    int ok = (got == want);\n    printf("  %s %-44s got=%-12s want=%s\\n",\n           ok ? "ok " : "FAIL", name, st_name(got), st_name(want));\n    if (!ok) fails++;\n}\n\nint main(int argc, char** argv)\n{\n    char buf[8192];\n    size_t n = 0u;\n    prot_status st;\n    const char* base;\n    char url[512];\n\n    if (argc < 2) { printf("usage: %s http://host:port\\n", argv[0]); return 2; }\n    base = argv[1];\n\n    snprintf(url, sizeof(url), "%s/v1/check?serial=X", base);\n\n    /* ---- 正向 ---- */\n    st = prot_plat_http_get_mem(url, buf, sizeof(buf), &n);\n    chk("P1 get_mem 正常下载", st, PROT_OK);\n    if (st == PROT_OK) {\n        int has = (strstr(buf, "status") != NULL);\n        printf("  %s P1b 内容含 JSON 字段 (len=%u)\\n",\n               has ? "ok " : "FAIL", (unsigned)n);\n        if (!has) fails++;\n    }\n\n    st = prot_plat_http_get(url, "/tmp/w3p_dl.txt", 0u);\n    chk("P2 get 下载到文件", st, PROT_OK);\n    if (st == PROT_OK) {\n        FILE* f = fopen("/tmp/w3p_dl.txt", "rb");\n        long sz = 0;\n        if (f != NULL) { fseek(f, 0, SEEK_END); sz = ftell(f); fclose(f); }\n        printf("  %s P2b 文件非空 (%ld 字节)\\n", (sz > 0) ? "ok " : "FAIL", sz);\n        if (sz <= 0) fails++;\n    }\n\n    /* ---- 负向 ---- */\n    st = prot_plat_http_get_mem("https://127.0.0.1/x", buf, sizeof(buf), &n);\n    chk("N1 https -> 如实 UNSUPPORTED", st, PROT_ERR_UNSUPPORTED);\n    st = prot_plat_http_get("https://127.0.0.1/x", "/tmp/w3p_n1.txt", 0u);\n    chk("N1b https(get) -> UNSUPPORTED", st, PROT_ERR_UNSUPPORTED);\n\n    st = prot_plat_http_get_mem("http://127.0.0.1:59999/x", buf,\n                                sizeof(buf), &n);\n    chk("N2 端口不可达 -> INTERNAL", st, PROT_ERR_INTERNAL);\n\n    st = prot_plat_http_get_mem("ftp://x/y", buf, sizeof(buf), &n);\n    chk("N3 非法 scheme -> INVALID_ARG", st, PROT_ERR_INVALID_ARG);\n    st = prot_plat_http_get_mem("http:///nohost", buf, sizeof(buf), &n);\n    chk("N3b 空 host -> INVALID_ARG", st, PROT_ERR_INVALID_ARG);\n\n    st = prot_plat_http_get_mem(NULL, buf, sizeof(buf), &n);\n    chk("N4 NULL url -> INVALID_ARG", st, PROT_ERR_INVALID_ARG);\n    st = prot_plat_http_get_mem(base, NULL, sizeof(buf), &n);\n    chk("N4b NULL buf -> INVALID_ARG", st, PROT_ERR_INVALID_ARG);\n    st = prot_plat_http_get_mem(base, buf, 0u, &n);\n    chk("N4c cap=0 -> INVALID_ARG", st, PROT_ERR_INVALID_ARG);\n    st = prot_plat_http_get(NULL, "/tmp/x", 0u);\n    chk("N4d get(NULL) -> INVALID_ARG", st, PROT_ERR_INVALID_ARG);\n\n    st = prot_plat_http_get(url, "/tmp/w3p_n5.txt", 4u);\n    chk("N5 超 max_size -> INTERNAL", st, PROT_ERR_INTERNAL);\n    {\n        FILE* f = fopen("/tmp/w3p_n5.txt", "rb");\n        printf("  %s N5b 超限后**文件已删**\\n", (f == NULL) ? "ok " : "FAIL");\n        if (f != NULL) { fclose(f); fails++; }\n    }\n\n    st = prot_plat_http_get_mem(url, buf, 4u, &n);\n    chk("N6 cap 过小 -> INTERNAL", st, PROT_ERR_INTERNAL);\n\n    printf("\\n");\n    if (fails != 0) { printf("FAIL: %d 项不符\\n", fails); return 1; }\n    printf("PASS: 2 正向 + 8 负向\\n");\n    return 0;\n}\n'

#: WSL 内的最小 HTTP 服务（**纯标准库**）
SERVER_PY = r"""
import http.server
import socketserver
import threading
import time

BODY = b'{"status":"ok","tier":1,"pad":"' + b'x' * 200 + b'"}'


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(BODY)


s = socketserver.TCPServer(('127.0.0.1', 0), H)
print('PORT=%d' % s.server_address[1], flush=True)
threading.Thread(target=s.serve_forever, daemon=True).start()
time.sleep(180)
"""


def to_wsl(p):
    p = os.path.abspath(p)
    return '/mnt/%s%s' % (p[0].lower(), p[2:].replace('\\', '/'))


def wsl(cmd, timeout=900):
    env = dict(os.environ)
    env['WSL_UTF8'] = '1'
    r = subprocess.run(['wsl.exe', '-d', DISTRO, '--', 'bash', '-c', cmd],
                       capture_output=True, timeout=timeout, env=env)
    return r.returncode, (r.stdout + r.stderr).decode('utf-8', 'replace')


def main():
    os.makedirs(BUILD, exist_ok=True)
    drv = os.path.join(BUILD, '_http_platform_test.c')
    with open(drv, 'w', encoding='utf-8', newline='\n') as f:
        f.write(DRIVER_C)
    srv = os.path.join(BUILD, '_http_platform_srv.py')
    with open(srv, 'w', encoding='utf-8', newline='\n') as f:
        f.write(SERVER_PY)

    rp = to_wsl(REPO)

    # ① 编译（**用 build.sh 的编译约定**: -std=c11 -D_GNU_SOURCE -Werror）
    rc, o = wsl('cd "%s" && gcc -O1 -Wall -Wextra -Werror -std=c11 '
                '-D_GNU_SOURCE -I include -I demo/gen/linux '
                '-o build/_http_platform_test build/_http_platform_test.c '
                'src/platform/prot_platform_linux.c 2>&1 | head -20' % rp)
    if rc != 0 or 'error' in o:
        print('[http_platform_test] 编译失败:')
        for l in o.split('\n')[:20]:
            if l.strip():
                print('  %s' % l.strip()[:100])
        return 2

    # ② 起服务（读 stdout 的 PORT —— 与 tools/mock_http.py 同法）
    env = dict(os.environ)
    env['WSL_UTF8'] = '1'
    p = subprocess.Popen(['wsl.exe', '-d', DISTRO, '--', 'python3',
                          os.path.relpath(srv, REPO).replace('\\', '/')],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         cwd=REPO, env=env)
    port = None
    t0 = time.time()
    while time.time() - t0 < 30:
        line = p.stdout.readline()
        if not line:
            break
        m = re.match(r'PORT=(\d+)', line.decode('utf-8', 'replace').strip())
        if m:
            port = int(m.group(1))
            break

    try:
        if port is None:
            print('[http_platform_test] 无法取得服务端口（环境问题）')
            return 2
        rc2, o2 = wsl('cd "%s" && ./build/_http_platform_test '
                      '"http://127.0.0.1:%d"' % (rp, port))
        for l in o2.split('\n'):
            if l.strip() and '代理' not in l:
                print('  %s' % l.strip()[:100])
        print()
        print('[http_platform_test] %s'
              % ('PASS' if rc2 == 0 else 'FAIL'))
        return 0 if rc2 == 0 else 1
    finally:
        p.terminate()
        try:
            p.wait(timeout=5)
        except Exception:                 # noqa: BLE001
            p.kill()


if __name__ == '__main__':
    sys.exit(main())
