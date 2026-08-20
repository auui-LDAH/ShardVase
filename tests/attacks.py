# -*- coding: utf-8 -*-
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

依赖: 已构建产物 (build\\demo.exe / demo\\gen\\*.c / build\\license.txt)。
纯黑盒: 不解析 VM 结构, 不修改受保护文件。
任一 FAIL -> sys.exit(1)。
"""

import hashlib
import json
import os
import subprocess
import sys

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
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, cwd=os.path.dirname(EXE))
    out, err = p.communicate(stdin, timeout=40)
    return p.returncode, out.decode('utf-8', 'replace')


def blob_bytes():
    """从 demo/gen/vm_*_blob.c 提取 s_code 字节数组. 返回 {name: bytes}."""
    out = {}
    for fn in sorted(os.listdir(os.path.join(REPO, 'demo', 'gen'))):
        if not fn.endswith('.c'):
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
            if fname.startswith('vm_'):
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
        subprocess.run(
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

    failed = False
    for name, status, detail in results:
        print('%-20s  %-4s   (%s)' % (name, status, detail), flush=True)
        if status == 'FAIL':
            failed = True
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()