# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
examples/tool_demo/test_example.py — 接入示例自动化测试

覆盖 tool_demo 的完整授权场景 (保护 SDK 验收件):
  E1  无 license -> 拒绝 (防未授权使用)
  E2  正确序列号+license -> 加密成功
  E3  错误序列号 -> 拒绝
  E4  过期 license -> 拒绝 (试用期)
  E5  本地黑名单吊销 -> 0xB1E4
  E6  在线吊销 (mock) -> 0xB1E4
  E7  篡改 exe -> 0xBAD
依赖: build_example.ps1 已构建 (build\\tool_demo.exe + build\\tool_vm.blob)。
"""

import http.server
import json
import os
import shutil
import struct
import subprocess
import sys
import threading

# ---------------------------------------------------------------------------
# 隐藏窗口（2026-09-25）
#
# Windows 上从 Python 启动控制台程序（powershell/cmd/wsl/cl）会**弹出黑窗**。
# 统一用 tools/winproc.py 封装（CREATE_NO_WINDOW + STARTUPINFO/SW_HIDE）。
#
# **为什么统一封装**: 实测本项目约 60 处调用都无隐藏措施；
#   一处修好 = 全部修好，且可自检（见 winproc.py 的 --selftest）。
#
# 路径推导: 从本文件位置向上找含 tools/winproc.py 的目录。
# ---------------------------------------------------------------------------
import os as _os_hw
import sys as _sys_hw


def _hw_tools_dir():
    d = _os_hw.path.dirname(_os_hw.path.abspath(__file__))
    for _ in range(4):
        cand = _os_hw.path.join(d, 'tools')
        if _os_hw.path.isfile(_os_hw.path.join(cand, 'winproc.py')):
            return cand
        d = _os_hw.path.dirname(d)
    return None


_hw_tools = _hw_tools_dir()
if _hw_tools and _hw_tools not in _sys_hw.path:
    _sys_hw.path.insert(0, _hw_tools)
import winproc  # noqa: E402


REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     '..', '..'))
BUILD = os.path.join(REPO, 'build')
EXE = os.path.join(BUILD, 'tool_demo.exe')
VMENC = os.path.join(REPO, 'tools', 'vmenc.py')
KEY = os.path.join(BUILD, 'keys', 'license_priv.json')
JSON = os.path.join(REPO, 'demo', 'vm_build.json')
BLOB = os.path.join(BUILD, 'tool_vm.blob')
TMP = os.path.join(BUILD, 'tool_test.txt')


def run(args, stdin=None):
    p = winproc.Popen([EXE] + args, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         cwd=BUILD)
    out, _ = p.communicate(stdin, timeout=40)
    return p.returncode, out.decode('utf-8', 'replace')


def make_license(expires=0, out='tool_lic.txt'):
    winproc.run(['python', VMENC, 'sign', '--key', KEY, '--json', JSON,
                    '--out', os.path.join(BUILD, out), '--expires', str(expires)],
                   check=True, capture_output=True)
    return os.path.join(BUILD, out)


class _Handler(http.server.BaseHTTPRequestHandler):
    revoked = None

    def log_message(self, *a):
        pass

    def do_GET(self):
        revoked = self.revoked is not None and ('serial=%s' % self.revoked) in self.path
        body = b'{"status":"revoked"}' if revoked else b'{"status":"ok"}'
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)


def main():
    cfg = json.load(open(JSON, encoding='utf-8'))
    serial = cfg['serial']
    results = []

    def check(name, ok, detail):
        results.append((name, 'PASS' if ok else 'FAIL', detail))

    if not os.path.isfile(EXE):
        print('E0 build-missing FAIL (run build_example.ps1 first)')
        return 1

    with open(TMP, 'w') as f:
        f.write('test data')

    # E1: 无 license -> 拒绝
    code, out = run(['--serial', serial, '--vm-blob', BLOB, '--encrypt', TMP])
    check('E1 no-license', code == 1 and 'no license' in out, 'exit=%d' % code)

    # E2: 正确序列号 + license -> 加密成功
    lic = make_license()
    code, out = run(['--serial', serial, '--license-file', lic,
                     '--vm-blob', BLOB, '--encrypt', TMP])
    check('E2 valid', code == 0 and 'encrypted' in out, 'exit=%d' % code)

    # E3: 错误序列号 -> 拒绝
    code, out = run(['--serial', 'WRONG-0000', '--license-file', lic,
                     '--vm-blob', BLOB, '--encrypt', TMP])
    check('E3 wrong-serial', code == 1 and 'access denied' in out, 'exit=%d' % code)

    # E4: 过期 license -> 拒绝
    lic_past = make_license(1, 'tool_lic_past.txt')
    code, out = run(['--serial', serial, '--license-file', lic_past,
                     '--vm-blob', BLOB, '--encrypt', TMP])
    check('E4 expired', code == 1 and 'expired' in out, 'exit=%d' % code)

    # E5: 本地黑名单吊销 -> 0xB1E4 (BLOB_SIGN: v1 签名黑名单)
    revoke = os.path.join(BUILD, 'tool_revoke.blob')
    winproc.run(['python', VMENC, 'revoke', '--sign',
                    os.path.join(REPO, 'build', 'keys', 'license_priv.json'),
                    '--out', revoke,
                    '--add', serial, '--tier', '1'],
                   check=True, capture_output=True)
    code, out = run(['--serial', serial, '--license-file', lic,
                     '--vm-blob', BLOB, '--revoke-file', revoke, '--encrypt', TMP])
    check('E5 revoke-local', code == 0xB1E4 and 'revoked' in out, 'exit=%d' % code)

    # E6: 在线吊销 (mock) -> 0xB1E4
    h = _Handler
    h.revoked = serial
    srv = http.server.HTTPServer(('127.0.0.1', 0), h)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = 'http://127.0.0.1:%d/v1/check' % srv.server_address[1]
    code, out = run(['--serial', serial, '--license-file', lic,
                     '--vm-blob', BLOB, '--check-url', url, '--encrypt', TMP])
    check('E6 revoke-online', code == 0xB1E4 and 'revoked' in out, 'exit=%d' % code)
    srv.shutdown()

    # E7: 篡改 exe -> 0xBAD
    tampered = os.path.join(BUILD, 'tool_demo_tampered.exe')
    shutil.copyfile(EXE, tampered)
    with open(tampered, 'r+b') as f:
        f.seek(0x400)  # .text 首字节
        b = f.read(1)
        f.seek(0x400)
        f.write(bytes([b[0] ^ 0xFF]))
    p = winproc.Popen([tampered, '--serial', serial, '--license-file', lic,
                          '--vm-blob', BLOB, '--encrypt', TMP],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, _ = p.communicate(timeout=40)
    code = p.returncode
    check('E7 tamper', code == 0xBAD and 'integrity' in
          out.decode('utf-8', 'replace'), 'exit=%d' % code)

    failed = False
    for name, status, detail in results:
        print('%-16s  %-4s   (%s)' % (name, status, detail))
        if status == 'FAIL':
            failed = True
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
