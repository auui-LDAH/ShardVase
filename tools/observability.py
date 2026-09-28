#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""observability.py — 可观测性度量（W5 验证框架核心）

## 为什么需要这个工具
第二支柱的目标是"**配置不可观测**"。但在此之前，项目**没有任何手段证明
自己做到了**——所有结论都靠一次性临时脚本，不可重复、不可审计、不进 CI。

本工具把"可观测性"变成**可量化、可重复、可进 CI 的指标**。

## 四个维度
  D1 **跨构建差异**（diff）
     两次构建（同组合、不同种子）的差异率与分布。
     目标: 差异率高且**均匀** -> 攻击者无法用 diff 定位每构建秘密。

  D2 **稳定核分析**（stable core）—— *diff 的逆向利用*
     ⚠️ 关键洞察: 差异率高**不等于**不可观测。
     若 67.85% 字节每次变化，则剩余 32% **不变**的区域反而**标记出了真实代码**
     -> 攻击者可"滤掉噪声、只看稳定区"。
     故本维度度量"**稳定核占比与位置可预测性**"。

  D3 **熵分布**（entropy）
     填充用均匀随机字节（熵≈8.0），真实代码熵较低（约 5~6.5）。
     若二者熵分布**可分**，攻击者可用熵扫描直接圈出填充区。
     本维度度量"**可分性边际**"（padding 与 code 的熵差）。

  D4 **静态可识别性**（static）
     用攻击者的手段（strings/节表/符号/导入表）能否定位保护模块。

## 用法
  python tools/observability.py diff <a.exe> <b.exe>
  python tools/observability.py entropy <exe>
  python tools/observability.py static <exe>
  python tools/observability.py selftest          # 负向测试（自检）
"""
import argparse
import collections
import math
import os
import re
import struct
import sys

# Windows 控制台默认 GBK -> 输出含 ✓/✗ 会 UnicodeEncodeError
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

BLOCK = 4096          # 分析块大小
WIN = 1024            # 熵窗口

# 高熵阈值（判"均匀随机"=疑似填充）。
#
# ⚠️ **不能用理论值 8.0 或 7.9**（实测教训 2026-09-23）:
#   Shannon 熵的**经验估计**在有限样本下有负偏差 —— 1024 字节窗口下
#   均匀随机的经验熵实测均值仅 **7.805**（60 次采样最小 7.758），
#   而非理论值 8.0。初版写 `> 7.9` 导致自检失败（抓不到已知的随机窗口）。
#
# 标定依据（tools/observability.py selftest + 外部标定脚本）:
#   窗口   实测均值   实测最小   Miller-Madow 修正
#   1024   7.8050    7.7577    7.8204
#   4096   7.9542    7.9467    7.9551
#
# 取 7.75: 低于实测最小（7.758）留余量，同时高于 .text 均值（5.04）。
#
# ⚠️ **重要边界**: 实测 .text 的**最大**窗口熵达 7.759，与本阈值几乎重合
#   -> 单窗口熵判据的**可分边际很窄**（高熵压缩数据会误判为填充）。
#   故本工具输出**剖面**而非单一判决，且报告重叠区间。
ENT_HI = 7.75         # 判"均匀随机"
ENT_LO = 5.0          # 判"典型代码/数据"

# ## `.fptable` 为何在**标准节**表里（S3 核查, 2026-09-25）
#   它的生产者是 **CRT**（`?function_pointers` @
#   `libucrt:winapi_thunks.obj`，见 build/demo.map）——
#   **不是本项目代码**。故它**不是**「我们随机化的自定义节」，
#   归入标准节是正确的（本项目的随机化节只有 protxec/protcrc/
#   protcry/protpad 四个）。
STD_SECTIONS = {'.text', '.rdata', '.data', '.pdata', '.rsrc', '.reloc',
                '.fptable'}


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
def shannon(buf):
    """字节级 Shannon 熵（bits/byte，0~8）。"""
    if not buf:
        return 0.0
    cnt = collections.Counter(buf)
    n = len(buf)
    return -sum((c / n) * math.log2(c / n) for c in cnt.values())


def read_sections(path):
    """读 PE 节表 -> [(名字, VSize, RawSize, RawOff, VA), ...]"""
    with open(path, 'rb') as f:
        d = f.read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    n = struct.unpack_from('<H', d, e + 6)[0]
    osz = struct.unpack_from('<H', d, e + 20)[0]
    tb = e + 24 + osz
    out = []
    for i in range(n):
        o = tb + i * 40
        nm = d[o:o + 8].rstrip(b'\x00').decode('ascii', 'replace')
        vsz, va, rsz, raw = struct.unpack_from('<IIII', d, o + 8)
        out.append((nm, vsz, rsz, raw, va))
    return d, out


def is_custom(name):
    """是否为保护组的自定义节（名字非标准）。"""
    return name not in STD_SECTIONS


# --------------------------------------------------------------------------
# D1 + D2: 跨构建差异 与 稳定核
# --------------------------------------------------------------------------
def analyse_diff(pa, pb, quiet=False):
    da = open(pa, 'rb').read()
    db = open(pb, 'rb').read()
    n = min(len(da), len(db))
    if len(da) != len(db):
        print('  [!] 大小不同: %d vs %d —— 只比较公共前缀' % (len(da), len(db)))

    diff = bytearray(n)
    ndiff = 0
    for i in range(n):
        if da[i] != db[i]:
            diff[i] = 1
            ndiff += 1
    rate = 100.0 * ndiff / n if n else 0.0

    # 按块统计
    nblk = (n + BLOCK - 1) // BLOCK
    blk_diff = [0] * nblk
    for i in range(n):
        if diff[i]:
            blk_diff[i // BLOCK] += 1
    touched = sum(1 for x in blk_diff if x > 0)
    full = sum(1 for x in blk_diff if x >= BLOCK * 0.95)
    empty = sum(1 for x in blk_diff if x == 0)
    vals = [x for x in blk_diff if x > 0]

    # 最长连续稳定区（攻击者最想找的"真实代码"）
    runs = []
    start = None
    for i in range(n):
        if not diff[i]:
            if start is None:
                start = i
        else:
            if start is not None and i - start >= 256:
                runs.append((start, i - start))
            start = None
    if start is not None and n - start >= 256:
        runs.append((start, n - start))
    runs.sort(key=lambda t: -t[1])

    stable = n - ndiff
    if not quiet:
        print('=== D1 跨构建差异 ===')
        print('  文件: %s' % os.path.basename(pa))
        print('  大小: %d' % n)
        print('  差异: %d 字节 (%.2f%%)' % (ndiff, rate))
        print('  判定 >30%%: %s' % ('✓' if rate > 30 else '✗ 差 %.1f 个百分点'
                                    % (30 - rate)))
        print()
        print('  分布:')
        print('    块大小 %d，共 %d 块' % (BLOCK, nblk))
        print('    有差异的块: %d (%.1f%%)' % (touched, 100.0 * touched / nblk))
        print('    几乎全变的块: %d (%.1f%%)' % (full, 100.0 * full / nblk))
        print('    完全不变的块: %d (%.1f%%)' % (empty, 100.0 * empty / nblk))
        if vals:
            mean = sum(vals) / len(vals)
            var = sum((v - mean) ** 2 for v in vals) / len(vals)
            print('    差异块内均值 %.0f 标准差 %.0f' % (mean, math.sqrt(var)))
            print('    最密 %d / 最疏 %d（比值 %.1f）'
                  % (max(vals), min(vals), max(vals) / min(vals)))
        print()
        print('=== D2 稳定核（diff 的逆向利用）===')
        print('  ⚠️ 差异率高**不等于**不可观测:')
        print('     若 67.85%% 变化，则剩余 32%% **不变**的区域反而标记出真实代码')
        print('     -> 攻击者可"滤掉噪声、只看稳定区"')
        print()
        print('  稳定字节: %d (%.2f%%)' % (stable, 100.0 * stable / n))
        print('  最长稳定连续区段:')
        for off, ln in runs[:5]:
            print('    0x%06X  %d 字节 (%.1f%% of file)'
                  % (off, ln, 100.0 * ln / n))
        if runs:
            print('  **稳定核可被隔离: %s**'
                  % ('是（存在 >=256 字节的连续稳定区）' if runs else '否'))
            print('    最大稳定区占文件 %.2f%%' % (100.0 * runs[0][1] / n))
    return {'rate': rate, 'ndiff': ndiff, 'size': n, 'stable': stable,
            'runs': runs, 'touched': touched, 'nblk': nblk, 'blk': blk_diff}


# --------------------------------------------------------------------------
# D3: 熵分布（能否区分填充与代码）
# --------------------------------------------------------------------------
def analyse_entropy(path, quiet=False):
    d, secs = read_sections(path)
    n = len(d)

    # 逐窗口熵
    prof = []
    for off in range(0, n - WIN + 1, WIN):
        prof.append((off, shannon(d[off:off + WIN])))
    if not prof:
        print('  文件过小')
        return {}

    # 按节归类：自定义节（保护组，含填充）vs .text（代码）
    def owner(off):
        for nm, vsz, rsz, raw, va in secs:
            if raw <= off < raw + rsz:
                return nm
        return '?'

    ent_by_kind = {'custom': [], 'text': [], 'rdata': [], 'other': []}
    for off, h in prof:
        nm = owner(off)
        if nm == '.text':
            ent_by_kind['text'].append(h)
        elif nm == '.rdata':
            ent_by_kind['rdata'].append(h)
        elif is_custom(nm):
            ent_by_kind['custom'].append(h)
        else:
            ent_by_kind['other'].append(h)

    # 整体熵
    whole = shannon(d)

    # 填充识别：均匀随机字节经验熵≈7.75+（非理论 8.0，见 ENT_HI 注释）；
    # 代码通常 5~6.5
    hi = [off for off, h in prof if h > ENT_HI]
    lo = [off for off, h in prof if h < ENT_LO]

    if not quiet:
        print('=== D3 熵分布（填充是否可被识别）===')
        print('  文件: %s  大小: %d' % (os.path.basename(path), n))
        print('  整文件熵: %.3f bits/byte' % whole)
        print()
        print('  %-10s %6s %8s %8s %8s' % ('类别', '窗口数', '均值', '最小', '最大'))
        for k in ('text', 'rdata', 'custom', 'other'):
            v = ent_by_kind[k]
            if v:
                print('  %-10s %6d %8.3f %8.3f %8.3f'
                      % (k, len(v), sum(v) / len(v), min(v), max(v)))
        print()
        print('  高熵窗口 (>%.2f，疑似均匀随机=填充): %d / %d (%.1f%%)'
              % (ENT_HI, len(hi), len(prof), 100.0 * len(hi) / len(prof)))
        print('  低熵窗口 (<%.1f，典型代码/数据): %d / %d (%.1f%%)'
              % (ENT_LO, len(lo), len(prof), 100.0 * len(lo) / len(prof)))

        txt = ent_by_kind['text']
        cus = ent_by_kind['custom']
        if txt and cus:
            mt, mc = sum(txt) / len(txt), sum(cus) / len(cus)
            print()
            print('  **可分性**: .text 均值 %.3f vs 自定义节均值 %.3f -> 差 %.3f'
                  % (mt, mc, mc - mt))
            # 若自定义节熵显著高于 .text，则填充可被识别
            if mc - mt > 0.5:
                print('  **判定: 填充可被熵分析识别** ✗')
                print('     自定义节（含填充）熵显著高于代码节')
                print('     -> 攻击者可扫熵剖面直接圈出填充区')
            else:
                print('  **判定: 熵不可分** ✓')
    return {'whole': whole, 'by_kind': ent_by_kind, 'hi': len(hi),
            'lo': len(lo), 'nwin': len(prof)}


# --------------------------------------------------------------------------
# D4: 静态可识别性
# --------------------------------------------------------------------------
def analyse_static(path, quiet=False):
    d, secs = read_sections(path)
    reg_path = 'modules.json'
    exports = []
    if os.path.exists(reg_path):
        import json
        reg = json.load(open(reg_path, encoding='utf-8'))
        for v in reg['modules'].values():
            exports += v.get('exports', [])

    found_sym = [x for x in exports if x.encode() in d]
    old_names = [x for x in ('.protxec', '.protcrc', '.protcry', '.protp',
                             '.protect', '.protcrypt')
                 if x.encode() in d]
    strings = re.findall(rb'[\x20-\x7e]{6,}', d)
    custom = [s for s in secs if is_custom(s[0])]

    if not quiet:
        print('=== D4 静态可识别性 ===')
        print('  模块函数名可见: %d / %d %s'
              % (len(found_sym), len(exports),
                 '✓' if not found_sym else '✗ %s' % found_sym[:3]))
        print('  自解释节名残留: %s %s'
              % (old_names if old_names else '无', '✓' if not old_names else '✗'))
        print('  自定义节数: %d' % len(custom))
        print('  可读 ASCII 串: %d 条' % len(strings))
        # 高价值线索：像路径/命令的串
        susp = [s for s in strings
                if re.search(rb'selftest|revoke|blob|license|debug|hook|frida|vm_',
                             s, re.I)]
        print('  含敏感词的串: %d 条' % len(susp))
        for s in susp[:6]:
            print('    %s' % s.decode('ascii', 'replace')[:76])
    return {'sym': len(found_sym), 'old_names': old_names,
            'strings': len(strings)}


# --------------------------------------------------------------------------
# 自检（负向测试）—— 防止"只会通过的检查器"
# --------------------------------------------------------------------------
def selftest():
    """负向测试: 用**已知答案**的构造输入验证各度量是否真的能分辨。

    教训（2026-09-23）: release_check.ps1 曾因 PowerShell 数组恒真而
    7/13 项失效（必然失败的工具被报 [ok]）。**检查器必须自证能抓错**。
    """
    import tempfile
    T = tempfile.mkdtemp(prefix='obs_selftest_')
    fails = []

    def case(name, got, want, tol=0.01):
        ok = abs(got - want) <= tol if isinstance(want, float) else got == want
        print('  %s %-42s got=%s want=%s'
              % ('ok ' if ok else '**FAIL**', name, got, want))
        if not ok:
            fails.append(name)

    print('=== 熵函数 ===')
    case('全零 4096 字节 -> 熵 0', shannon(b'\x00' * 4096), 0.0)
    case('全 256 值均匀 -> 熵 8.0', shannon(bytes(range(256)) * 16), 8.0)
    case('ABAB... -> 熵 1.0', shannon(b'AB' * 2048), 1.0)

    print()
    print('=== 差异度量（构造已知差异）===')
    a = bytes(4096)
    b = bytes(4096)
    pa = os.path.join(T, 'a.bin')
    pb = os.path.join(T, 'b.bin')
    open(pa, 'wb').write(a)
    open(pb, 'wb').write(b)
    r = analyse_diff(pa, pb, quiet=True)
    case('完全相同 -> 差异率 0', r['rate'], 0.0)

    # 25% 差异
    b2 = bytearray(bytes(4096))
    for i in range(1024):
        b2[i] = 0xFF
    pb2 = os.path.join(T, 'b2.bin')
    open(pb2, 'wb').write(bytes(b2))
    r2 = analyse_diff(pa, pb2, quiet=True)
    case('25% 差异 -> 差异率 25', r2['rate'], 25.0)

    # 稳定核必须被抓到
    print()
    print('=== 稳定核检测（必须能抓到"不变的真实代码区"）===')
    # 构造: 前 3072 稳定 + 后 1024 全变
    b3 = bytearray(a)
    for i in range(3072, 4096):
        b3[i] = 0xAA
    pb3 = os.path.join(T, 'b3.bin')
    open(pb3, 'wb').write(bytes(b3))
    r3 = analyse_diff(pa, pb3, quiet=True)
    case('稳定字节数 3072', r3['stable'], 3072)
    case('最长稳定区 >= 3072', r3['runs'][0][1] if r3['runs'] else 0, 3072)

    print()
    print('=== 熵剖面（必须能区分均匀随机与代码）===')
    # ⚠️ 用**实测标定**的阈值，而非理论值 8.0（初版用 7.9 导致此处 FAIL）
    import random as _rnd
    rng = _rnd.Random(1234)
    pad = bytes(rng.randrange(1, 256) for _ in range(WIN))
    h_pad = shannon(pad)
    case('均匀随机窗口熵 > ENT_HI', h_pad > ENT_HI, True)
    code = bytes([0x48, 0x89, 0x5C, 0x24] * (WIN // 4))   # 重复指令 -> 低熵
    h_code = shannon(code)
    case('重复代码窗口熵 < ENT_LO', h_code < ENT_LO, True)
    # 记录实际分离边际（这是**关键安全指标**）
    print('    -> 填充熵 %.3f vs 重复代码熵 %.3f（分离 %.3f）'
          % (h_pad, h_code, h_pad - h_code))

    print()
    print('=== 静态度量 ===')
    tiny = os.path.join(T, 'tiny.bin')
    open(tiny, 'wb').write(b'\x00' * 1024)
    try:
        analyse_static(tiny, quiet=True)
        print('  ok  畸形输入不崩溃')
    except Exception as e:
        print('  **FAIL** 畸形输入崩溃: %s' % str(e)[:60])
        fails.append('畸形输入')

    import shutil
    shutil.rmtree(T, ignore_errors=True)

    print()
    print('=' * 62)
    if fails:
        print('[observability-selftest] FAIL: %d 项未通过 -> %s'
              % (len(fails), '; '.join(fails)))
        return 1
    print('[observability-selftest] PASS: 度量可自证能抓错')
    return 0


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(prog='observability.py')
    sub = ap.add_subparsers(dest='cmd')

    p1 = sub.add_parser('diff', help='两次构建的差异与稳定核')
    p1.add_argument('a')
    p1.add_argument('b')

    p2 = sub.add_parser('entropy', help='熵分布（填充可识别性）')
    p2.add_argument('exe')

    p3 = sub.add_parser('static', help='静态可识别性')
    p3.add_argument('exe')

    p4 = sub.add_parser('all', help='对单个产物跑全部度量')
    p4.add_argument('exe')

    sub.add_parser('selftest', help='负向测试（自检）')

    args = ap.parse_args()

    if args.cmd == 'selftest':
        return selftest()
    if args.cmd == 'diff':
        analyse_diff(args.a, args.b)
        return 0
    if args.cmd == 'entropy':
        analyse_entropy(args.exe)
        return 0
    if args.cmd == 'static':
        analyse_static(args.exe)
        return 0
    if args.cmd == 'all':
        analyse_entropy(args.exe)
        print()
        analyse_static(args.exe)
        return 0

    ap.print_help()
    return 2


if __name__ == '__main__':
    sys.exit(main())
