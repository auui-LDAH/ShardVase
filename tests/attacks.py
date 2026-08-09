# -*- coding: utf-8 -*-
"""
tests/attacks.py - 攻击模拟测试 (基础设施, 不需真机, Lane D)

在随构建生成的产物上做无调试器的"攻击者视角"回归, 验证保护在多种旁路下仍就地:

  A1 machine-bind       本机正确序列号必须通过 (machine_id 绑定成立)
  A2 vm-ciphertext      VM 镜像 blob 的字节呈高熵均匀分布 (非明文: 静态不可还原)
  A3 build-fingerprint  记录本轮 VM 镜像内容指纹 (供跨轮对比随机性)
  A4 selftest-clean     --selftest 干净环境各项为 0 (新检测项无误报, 与 T7 互补)

依赖: 已构建产物 (build\\demo.exe / demo\\gen\\*.c)。
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

    # ---- A1: 本机 machine_id 绑定成立 ---------------------------------
    try:
        code, out = run_demo(stdin=(serial + '\n').encode('utf-8'))
        ok = (code == 0) and (msg_ok in out)
        results.append(('A1 machine-bind', 'PASS' if ok else 'FAIL',
                        'code=%d' % code))
    except Exception as e:
        results.append(('A1 machine-bind', 'FAIL', repr(e)))

    # ---- A2: VM blob 密文高熵 (非明文可静态还原) ----------------------
    try:
        blobs = blob_bytes()
        bad = []
        for name, data in blobs.items():
            # 熵接近 8 (均匀) => 非可读明文; 明文 opcode 序列熵显著更低
            ent = shannon_entropy(data)
            if ent < 4.5:
                bad.append('%s ent=%.2f' % (name, ent))
        ok = (len(blobs) >= 4) and (not bad)
        results.append(('A2 vm-ciphertext', 'PASS' if ok else 'FAIL',
                        'blobs=%d %s' % (len(blobs), '; '.join(bad) or 'high-entropy')))
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

    # ---- A4: --selftest 干净环境全 0 ----------------------------------
    try:
        code, out = run_demo(args=['--selftest'],
                             stdin=(serial + '\n').encode('utf-8'))
        nonzero = []
        for line in out.splitlines():
            line = line.strip()
            if ':' not in line:
                continue
            fname, _, fval = line.partition(':')
            fname = fname.strip()
            fval = fval.strip()
            if fname in CLEAN_FIELDS and fval != '0':
                nonzero.append('%s=%s' % (fname, fval))
        ok = (code == 0) and (not nonzero)
        results.append(('A4 selftest-clean', 'PASS' if ok else 'FAIL',
                        'code=%d nonzero=%s' % (code, nonzero or 'none')))
    except Exception as e:
        results.append(('A4 selftest-clean', 'FAIL', repr(e)))

    failed = False
    for name, status, detail in results:
        print('%-20s  %-4s   (%s)' % (name, status, detail), flush=True)
        if status == 'FAIL':
            failed = True
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()