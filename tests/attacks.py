# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
tests/attacks.py - 攻击模拟测试 (基础设施, 不需真机, Lane D)

在随构建生成的产物上做无调试器的"攻击者视角"回归, 验证保护在多种旁路下仍就地:

  A1 machine-bind         本机正确序列号+有效授权必须通过 (machine_id 绑定成立)
  A2 vm-ciphertext        VM 镜像 blob 的字节呈高熵均匀分布 (非明文: 静态不可还原)
  A3 build-fingerprint    记录本轮 VM 镜像内容指纹 (供跨轮对比随机性)
  A4 selftest-clean       --selftest 干净环境各项为 0 (新检测项无误报, 与 T7 互补)
  A5 license-forge        改 1 位签名 -> 必须被判无效 (RSA 防伪造)
  A6 license-other-machine 用同一私钥给异机 machine_id 签 license -> 本机必须拒绝
  A7 license-tier-forge   改 TIER 行 -> 必须被判无效 (Phase 4 分级授权防篡改)
  A8 blob-forge           构造 v0 blob (无签名) -> 拒绝 (D1a 强制 v1, BLOB_SIGN)
  A9 revoke-forge         构造 v0 黑名单 -> 不阻断 (签名强制, revoke 签名)
  A10 static-trace        静态扫描 N4 受保护函数无直接 call (间接化成本)
  A11 selfcrypt-dump      静态 dump 引擎函数无序言特征 (N1 密文)
  A12 offline-fix-expect  在线会话值覆盖本地固定期望值 (N5 边界)

依赖: 已构建产物 (build\\demo.exe / demo\\gen\\*.c / build\\license.txt)。
纯黑盒: 不解析 VM 结构, 不修改受保护文件。
任一 FAIL -> sys.exit(1)。
"""

import hashlib
import json
import os
import struct
import subprocess
import sys
import zlib

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


REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
EXE = os.path.join(REPO, 'build', 'demo.exe')
JSON_PATH = os.path.join(REPO, 'demo', 'vm_build.json')
STRINGS = os.path.join(REPO, 'demo', 'strings.txt')
LICENSE = os.path.join(REPO, 'build', 'license.txt')   # A1: build.ps1 sign 产物
VMENC = os.path.join(REPO, 'tools', 'vmenc.py')

CLEAN_FIELDS = ('peb_being_debugged', 'peb_nt_global_flag', 'debug_port',
                'debug_flags', 'debug_object', 'hardware_breakpoints',
                'timing_suspicious', 'kernel_debugger', 'debug_heap_flags',
                'int3_honey')


def _msg(name):
    with open(STRINGS, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\r\n')
            if '|' in line:
                key, _, text = line.partition('|')
                if key.strip() == name:
                    return text
    return name


def run_demo(args=None, stdin=None):
    cmd = [EXE] + (args or [])
    p = winproc.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, cwd=os.path.dirname(EXE))
    out, err = p.communicate(stdin, timeout=40)
    return p.returncode, out.decode('utf-8', 'replace')


def blob_bytes():
    """从 demo/gen/vm_*_blob.c 提取 s_code 字节数组. 返回 {name: bytes}.
    只处理 vm_*_blob.c (排除 expect_default.c 等其他生成物)。"""
    out = {}
    for fn in sorted(os.listdir(os.path.join(REPO, 'demo', 'gen'))):
        if not fn.startswith('vm_') or not fn.endswith('_blob.c'):
            continue
        with open(os.path.join(REPO, 'demo', 'gen', fn), 'r', encoding='utf-8') as f:
            text = f.read()
        # s_code[] = { 0x12, ... }; 找第一个 '{' 与对应 '}'
        start = text.find('{')
        end = text.find('}', start)
        if start < 0 or end < 0:
            continue
        body = text[start + 1:end]
        vals = []
        for tok in body.replace('\n', ' ').split(','):
            tok = tok.strip()
            if tok.lower().startswith('0x'):
                vals.append(int(tok, 16) & 0xFF)
        if vals:
            out[os.path.basename(fn)] = bytes(vals)
    return out


def shannon_entropy(data):
    if not data:
        return 0.0
    hist = [0] * 256
    for b in data:
        hist[b] += 1
    import math
    ent = 0.0
    n = float(len(data))
    for c in hist:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def main():
    with open(JSON_PATH, 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    serial = cfg['serial']
    msg_ok = _msg('MSG_OK')
    msg_fail = _msg('MSG_FAIL')

    results = []

    # ---- A1: 本机 machine_id 绑定成立 (带有效授权文件) ------------------
    try:
        if not os.path.isfile(LICENSE):
            raise RuntimeError('license.txt not found (run build.ps1)')
        code, out = run_demo(args=['--license-file', LICENSE],
                             stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 0) and (msg_ok in out) and ('license: 1' in out)
        results.append(('A1 machine-bind', 'PASS' if ok else 'FAIL',
                        'code=%d' % code))
    except Exception as e:
        results.append(('A1 machine-bind', 'FAIL', repr(e)))

    # ---- A2: VM 镜像密文高熵 (非明文可静态还原) -----------------------
    # 只统计 VM blob (vm_*_blob.c); 用相对熵 (ent/log2(len), 上限 1.0),
    # 小 blob (如 21 字节的 gate) 绝对熵低但比例应接近 1 —— 这才证明是密文。
    try:
        blobs = blob_bytes()
        bad = []
        for name, data in sorted(blobs.items()):
            if not name.startswith('vm_') or not name.endswith('_blob.c'):
                continue
            if len(data) < 4:
                continue
            ent = shannon_entropy(data)
            import math
            rel = ent / math.log2(len(data))
            if rel < 0.85:
                bad.append('%s rel=%.2f' % (name, rel))
        vm_count = sum(1 for n in blobs if n.startswith('vm_') and n.endswith('_blob.c'))
        ok = (vm_count >= 4) and (not bad)
        results.append(('A2 vm-ciphertext', 'PASS' if ok else 'FAIL',
                        'blobs=%d %s' % (vm_count, '; '.join(bad) or 'high-entropy')))
    except Exception as e:
        results.append(('A2 vm-ciphertext', 'FAIL', repr(e)))

    # ---- A3: 本轮镜像内容指纹 (供跨轮对比) ----------------------------
    try:
        h = hashlib.sha256()
        for name, data in sorted(blob_bytes().items()):
            h.update(name.encode('ascii'))
            h.update(data)
        results.append(('A3 build-fingerprint', 'PASS',
                        'sha256=%s' % h.hexdigest()[:16]))
    except Exception as e:
        results.append(('A3 build-fingerprint', 'FAIL', repr(e)))

    # ---- A4: --selftest 干净环境全 0 (vm_* 为咨询项, VM 环境预期非 0, 仅记录) ----
    try:
        code, out = run_demo(args=['--selftest', '--license-file', LICENSE],
                             stdin=(serial + '\n').encode('utf-8'))
        nonzero = []
        vm_notes = []
        for line in out.splitlines():
            line = line.strip()
            if ':' not in line:
                continue
            fname, _, fval = line.partition(':')
            fname = fname.strip()
            fval = fval.strip()
            if fname.startswith('vm_') or fname.startswith('dbi_'):
                if fval != '0':
                    vm_notes.append('%s=%s' % (fname, fval))
            elif fname in CLEAN_FIELDS and fval != '0':
                nonzero.append('%s=%s' % (fname, fval))
        ok = (code == 0) and (not nonzero)
        results.append(('A4 selftest-clean', 'PASS' if ok else 'FAIL',
                        'code=%d nonzero=%s vm=%s' %
                        (code, nonzero or 'none', vm_notes or 'none')))
    except Exception as e:
        results.append(('A4 selftest-clean', 'FAIL', repr(e)))

    # ---- A5: 伪造授权 (改签名 1 位) 必须被拒 --------------------------
    # 演示 RSA 防伪造: 攻击者就算完全复刻 VM/expect 算法, 也造不出合法签名。
    try:
        forged = os.path.join(REPO, 'build', 'license_forged.txt')
        with open(LICENSE, 'r', encoding='utf-8') as f:
            lines = f.read().splitlines()
        out_lines = []
        for ln in lines:
            if ln.startswith('SIGNATURE='):
                s = ln[len('SIGNATURE='):]
                b = bytearray(s.encode('ascii'))
                b[len(b) // 2] = b'B'[0]
                out_lines.append('SIGNATURE=' + b.decode('ascii'))
            else:
                out_lines.append(ln)
        with open(forged, 'w', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(out_lines) + '\n')
        code, out = run_demo(args=['--license-file', forged],
                             stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 1) and ('license: 0' in out)
        results.append(('A5 license-forge', 'PASS' if ok else 'FAIL',
                        'code=%d license_ok=0' % code))
    except Exception as e:
        results.append(('A5 license-forge', 'FAIL', repr(e)))

    # ---- A6: 异机授权 (机器标识不匹配) 必须被拒 ------------------------
    # 用同一私钥给「另一台机器 id」签一份 license, 当前机器运行应拒绝
    # (载荷含 machine_id, 与本地 hostid 不同 -> 验签失败)。
    try:
        other = os.path.join(REPO, 'build', 'license_othermachine.txt')
        winproc.run(
            ['python', VMENC, 'sign', '--key',
             os.path.join(REPO, 'build', 'keys', 'license_priv.json'),
             '--json', JSON_PATH, '--out', other,
             '--machine-id', '0x123456789ABCDEF0'],
            check=True, capture_output=True)
        code, out = run_demo(args=['--license-file', other],
                             stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 1) and ('license: 0' in out)
        results.append(('A6 license-other-machine', 'PASS' if ok else 'FAIL',
                        'code=%d license_ok=0' % code))
    except Exception as e:
        results.append(('A6 license-other-machine', 'FAIL', repr(e)))

    # ---- A7: 分级授权 tier 篡改 (Phase 4, 与 e2e T12 互补) --------------
    try:
        forged = os.path.join(REPO, 'build', 'license_tier_forged.txt')
        with open(LICENSE, 'r', encoding='utf-8') as f:
            lines = f.read().splitlines()
        out_lines = []
        for ln in lines:
            if ln.startswith('TIER='):
                cur = ln[len('TIER='):]
                out_lines.append('TIER=' + ('2' if cur != '2' else '0'))
            else:
                out_lines.append(ln)
        with open(forged, 'w', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(out_lines) + '\n')
        code, out = run_demo(args=['--license-file', forged],
                             stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 1) and ('license: 0' in out)
        results.append(('A7 license-tier-forge', 'PASS' if ok else 'FAIL',
                        'code=%d license_ok=0' % code))
    except Exception as e:
        results.append(('A7 license-tier-forge', 'FAIL', repr(e)))

    # ---- A8: 伪造签名 blob (ATTACK_PLAN) ---------------------------------
    # 攻击者手段: 理解格式后构造 v0 blob (无签名, 自算 CRC) —— D1a 强制 v1
    # 应拒绝。从现有 v1 blob 剥离签名区构造 v0 (不改动保护文件)。
    try:
        blob_path = os.path.join(REPO, 'build', 'vm.blob')
        if not os.path.isfile(blob_path):
            raise RuntimeError('vm.blob not found (run build.ps1)')
        v1 = open(blob_path, 'rb').read()
        # v1: MAGIC8|COUNT4|entries|SIG_LEN4|SIG384|CRC4 -> v0: MAGIC8|COUNT4|entries|CRC4
        sig_off = len(v1) - 4 - 384 - 4
        body = b'PROTVMBL' + v1[8:sig_off]
        v0 = body + struct.pack('<I', zlib.crc32(body) & 0xFFFFFFFF)
        forged_path = os.path.join(REPO, 'build', 'vm_forged_v0.blob')
        with open(forged_path, 'wb') as f:
            f.write(v0)
        code, out = run_demo(args=['--license-file', LICENSE,
                                   '--vm-blob', forged_path],
                             stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 0xB10B)  # PROT_EXIT_BLOB_MISSING
        results.append(('A8 blob-forge', 'PASS' if ok else 'FAIL',
                        'code=%d (v0 forged blob rejected)' % code))
    except Exception as e:
        results.append(('A8 blob-forge', 'FAIL', repr(e)))

    # ---- A9: 伪造黑名单 (ATTACK_PLAN) ------------------------------------
    # 攻击者手段: 构造 v0 黑名单 (PROTREVK, 自算 CRC) 想吊销他人/绕过 ——
    # 签名强制下应 CORRUPT 不阻断; 且真实 v1 黑名单命中语义不变。
    try:
        revoke_path = os.path.join(REPO, 'build', 'revoke_forged_v0.blob')
        body = (b'PROTREVK' + struct.pack('<I', 1) + struct.pack('<I', 1) +
                b'VICTIM-SERIAL-0001'.ljust(48, b'\x00') +
                struct.pack('<I', 0xFF) + struct.pack('<Q', 0))
        v0 = body + struct.pack('<I', zlib.crc32(body) & 0xFFFFFFFF)
        with open(revoke_path, 'wb') as f:
            f.write(v0)
        code, out = run_demo(args=['--license-file', LICENSE,
                                   '--vm-blob', os.path.join(REPO, 'build', 'vm.blob'),
                                   '--revoke-file', revoke_path],
                             stdin=(serial + '\n').encode('utf-8'))
        # 伪造 v0 黑名单: 损坏 -> 不阻断 (CORRUPT 语义), 正常通过
        ok = (code == 0) and (msg_ok in out)
        results.append(('A9 revoke-forge', 'PASS' if ok else 'FAIL',
                        'code=%d (forged v0 blacklist non-blocking)' % code))
    except Exception as e:
        results.append(('A9 revoke-forge', 'FAIL', repr(e)))

    # ---- A10: 静态追踪 N4 间接链 (ATTACK_PLAN) ---------------------------
    # 攻击者手段: dumpbin/反汇编静态追踪, 找 prot_vm_run 等目标函数的直接
    # call 或从间接表定位 —— N4 间接化应使"直接 call"不存在。
    #
    # ## ⚠️ M4 实测修正（2026-09-25）
    #   本项原先**自己重算**一份与 P5 相同的判据，因而**继承了 P5 的四个缺陷**
    #   （坐标系错配 / 密文噪声 / 函数集合错误 / 未区分设计允许的调用）。
    #   证据: 修正前 A10 报 `direct-call=['0x6430']` —— 那是**数值巧合**，
    #   与间接化无关（详见 `protchain_check.p5_indirect_no_direct_call`
    #   的注释）。
    #
    #   => **改为直接复用 P5 的修正实现** ——
    #      避免"同一判据在两处各写一遍"（复制即漂移；本项已因此错过修正）。
    try:
        import sys as _sys
        _sys.path.insert(0, os.path.join(REPO, 'tests'))
        from protchain_check import (pe_sections,
                                     p5_indirect_no_direct_call)
        exe_data = open(EXE, 'rb').read()
        secs = pe_sections(exe_data)
        ok, why = p5_indirect_no_direct_call(exe_data, secs)
        results.append(('A10 static-trace', 'PASS' if ok else 'FAIL',
                        'N4 indirect: %s' % why))
    except Exception as e:
        results.append(('A10 static-trace', 'FAIL', repr(e)))

    # ---- A11: dump 视角验证 N1 自变形 (ATTACK_PLAN) ----------------------
    # 攻击者手段: 静态 dump 引擎函数做特征扫描 (找 x64 序言) —— 加密态
    # 应无序言特征; 运行期 dump 为 D2a 明文, 属设计语义 (诚实记录)。
    try:
        import sys as _sys2
        _sys2.path.insert(0, os.path.join(REPO, 'tests'))
        from protchain_check import pe_sections as _ps
        from protchain_check import selfcrypt_meta as _sc_meta2
        exe_data = open(EXE, 'rb').read()
        secs = _ps(exe_data)
        text = next(s for s in secs if s['name'] == '.text')
        plain = []
        for rva, ln, _grp in _sc_meta2(exe_data, secs):
            toff = text['ptr_raw'] + (rva - text['virtual_addr'])
            head = exe_data[toff:toff + 8]
            if head.startswith((b'\x40\x55', b'\x40\x56', b'\x40\x57',
                                b'\x48\x89', b'\x48\x83')):
                plain.append(hex(rva))
        ok = (not plain)
        results.append(('A11 selfcrypt-dump', 'PASS' if ok else 'FAIL',
                        'plaintext-fns=%s (static ciphertext)' %
                        (plain or 'none')))
    except Exception as e:
        results.append(('A11 selfcrypt-dump', 'FAIL', repr(e)))

    # ---- A12: 离线固定期望值对抗 N5 会话值 (ATTACK_PLAN) ------------------
    # 攻击者手段: 认为"固定本地期望值可一劳永逸"——在线会话下服务端下发
    # 不同值, 固定值失效。此处用错误期望值模拟"攻击者固定值"。
    try:
        import http.server as _hs
        import threading as _th

        class _H(_hs.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                # 错误期望值: 攻击者固定的值 (与服务端真实值不同)
                body = (b'{"status":"ok","tier":1,'
                        b'"expect1":"0x1111111111111111",'
                        b'"expect2":"0x2222222222222222"}')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(body)

        srv = _hs.HTTPServer(('127.0.0.1', 0), _H)
        th = _th.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        url = 'http://127.0.0.1:%d/v1/check' % srv.server_address[1]
        code, out = run_demo(args=['--license-file', LICENSE,
                                   '--vm-blob', os.path.join(REPO, 'build', 'vm.blob'),
                                   '--check-url', url],
                             stdin=(serial + '\n').encode('utf-8'))
        srv.shutdown()
        ok = (code == 1) and (msg_fail in out)
        results.append(('A12 offline-fix-expect', 'PASS' if ok else 'FAIL',
                        'code=%d (online session value overrides local fix)' % code))
    except Exception as e:
        results.append(('A12 offline-fix-expect', 'FAIL', repr(e)))

    failed = False
    for name, status, detail in results:
        print('%-20s  %-4s   (%s)' % (name, status, detail), flush=True)
        if status == 'FAIL':
            failed = True
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()