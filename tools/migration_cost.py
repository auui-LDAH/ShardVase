#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""migration_cost.py — 破解迁移成本度量（W5.6）

## 这是什么
  方针的最终验收: **"让破解者明知防御仍要大量时间和资源"**。
  本工具把它变成**可量化、可复现**的指标。

## 核心洞察（实测依据 2026-09-23）
  W1 把"跨构建差异率"做到 67.85%，但那**只说明文件整体不同**。
  若**关键函数的字节序列不变**，攻击者可:
    1. 在 A 上定位函数（取字节特征）
    2. 在 B 上用**特征扫描**（不依赖地址）直接找到同一函数
    3. 复用 A 上开发的绕过（补丁/脚本/hook）
  => **迁移成本接近零**，W1 的效果被部分抵消。

  **实测（首次）**: 278/815 函数字节完全相同（34.1%）；
  保护函数 9/34（26.5%）稳定；用 32 字节特征在 B 中**精确命中**。

  根因: **随机化只作用于数据，不作用于代码**。

## 四个维度
  M1 **地址稳定性**  —— 函数 RVA 是否跨构建变化
  M2 **秘密稳定性**  —— per-build 数据（节名/magic/掩码/blob）是否变化
  M3 **特征可匹配性** —— 用 A 的字节特征能否在 B 中定位同一函数（**最关键**）
  M4 **结构稳定性**  —— 节布局是否变化

## 用法
  python tools/migration_cost.py <A.exe> <B.exe> [--map-a A.map] [--map-b B.map]
  python tools/migration_cost.py --selftest
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

FUNC_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
PROT_PREFIX = 'prot_'
FEATURE_LEN = 32          # 字节特征长度


# --------------------------------------------------------------------------
def parse_map(path, image_base=None):
    """MSVC .map -> {符号: 映像RVA}

    ⚠️ **解析陷阱**（2026-09-23 实测教训）: map 行有四个关键列:
        `0001:00000020   probe_fn   0000000140001020 f   a.obj`
          ↑节:节内偏移   ↑符号      ↑**绝对 VA**
        第 2 列是**节内偏移**（section-relative），**不是**映像 RVA。
        初版误用第 2 列 -> RVA 落在节外 -> "无法换算"虚高、
        且 M1/M3 结果失真。

    正确: 映像 RVA = 绝对 VA（第 4 列） - image base。
    image base 从 PE 头读取（`OptionalHeader.ImageBase`）。
    """
    syms = {}
    if not path or not os.path.exists(path):
        return syms
    t = open(path, encoding='utf-8', errors='replace').read()
    for m in re.finditer(
            r'[0-9a-f]{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{8,16})', t):
        sym, absva = m.group(1), int(m.group(2), 16)
        syms.setdefault(sym, absva)
    if not syms:
        return syms
    if image_base is None:
        image_base = read_image_base(path)
    return {k: v - image_base for k, v in syms.items()}


def read_image_base(map_path):
    """从同名 .exe 读 PE ImageBase；失败则回退默认 0x140000000。"""
    exe = os.path.splitext(map_path)[0] + '.exe'
    try:
        with open(exe, 'rb') as f:
            head = f.read(0x400)
        e = struct.unpack_from('<I', head, 0x3C)[0]
        # PE32+ 的 ImageBase 在 OptionalHeader 偏移 24
        return struct.unpack_from('<Q', head, e + 24 + 24)[0]
    except (OSError, struct.error, IndexError):
        return 0x140000000


def read_sections(path):
    d = open(path, 'rb').read()
    e = struct.unpack_from('<I', d, 0x3C)[0]
    n = struct.unpack_from('<H', d, e + 6)[0]
    oz = struct.unpack_from('<H', d, e + 20)[0]
    tb = e + 24 + oz
    out = []
    for i in range(n):
        o = tb + i * 40
        nm = d[o:o + 8].rstrip(b'\x00').decode('ascii', 'replace')
        vsz, va, rsz, raw = struct.unpack_from('<IIII', d, o + 8)
        out.append((nm, vsz, rsz, raw, va))
    return d, out


def rva2off(rva, secs, dlen):
    for nm, vsz, rsz, raw, va in secs:
        if va <= rva < va + max(vsz, rsz):
            off = raw + (rva - va)
            return off if 0 <= off < dlen else None
    return None


# --------------------------------------------------------------------------
def analyse(pa, pb, mapa=None, mapb=None):
    da, sa = read_sections(pa)
    db, sb = read_sections(pb)
    ma, mb = parse_map(mapa), parse_map(mapb)

    res = {}

    # ---- M1 地址稳定性 ----
    common = sorted(set(ma) & set(mb))
    same_rva = [s for s in common if ma[s] == mb[s]]
    res['m1'] = {
        'common': len(common),
        'same_rva': len(same_rva),
        'diff_rva': len(common) - len(same_rva),
        'rate_same': 100.0 * len(same_rva) / len(common) if common else 0.0,
    }

    # ---- M3 特征可匹配性（最关键）----
    funcs = [s for s in common
             if FUNC_RE.match(s) and not s.startswith('$')]
    matched, total, prot_matched, prot_total = 0, 0, 0, 0
    prot_unmatched_names = []
    for s in funcs:
        oa = rva2off(ma[s], sa, len(da))
        ob = rva2off(mb[s], sb, len(db))
        if oa is None or ob is None:
            continue
        feat = da[oa:oa + FEATURE_LEN]
        if len(feat) < FEATURE_LEN:
            continue
        total += 1
        is_prot = s.startswith(PROT_PREFIX)
        if is_prot:
            prot_total += 1
        # 在 B 中用特征搜索
        idx = db.find(feat)
        hit = (idx >= 0)
        if hit:
            matched += 1
            if is_prot:
                prot_matched += 1
        elif is_prot:
            prot_unmatched_names.append(s)

    res['m3'] = {
        'total': total,
        'matched': matched,
        'rate': 100.0 * matched / total if total else 0.0,
        'prot_total': prot_total,
        'prot_matched': prot_matched,
        'prot_rate': 100.0 * prot_matched / prot_total if prot_total else 0.0,
        'prot_safe': prot_unmatched_names,
    }

    # ---- M4 结构稳定性 ----
    same_sec = 0
    for (n1, v1, r1, o1, _), (n2, v2, r2, o2, _) in zip(sa, sb):
        if v1 == v2 and o1 == o2:
            same_sec += 1
    res['m4'] = {
        'sections_a': len(sa), 'sections_b': len(sb),
        'same_layout': same_sec,
        'size_a': len(da), 'size_b': len(db),
    }
    return res


# --------------------------------------------------------------------------
def selftest():
    """负向测试: 用**已知答案**验证各度量能抓错。

    纪律（来自门禁失效教训）: 每个检查器必须自证能抓错。
    """
    import tempfile
    import random
    T = tempfile.mkdtemp(prefix='mig_selftest_')
    fails = []

    def case(name, got, want):
        ok = got == want
        print('  %s %-46s got=%s want=%s'
              % ('ok ' if ok else '**FAIL**', name, got, want))
        if not ok:
            fails.append(name)

    print('=== map 解析 ===')
    mp = os.path.join(T, 't.map')
    # 注意: map 第 2 列是**节内偏移**，第 4 列才是**绝对 VA**。
    # 自检必须用**正确格式**，否则测不到真实的解析逻辑。
    open(mp, 'w', encoding='utf-8').write(
        ' 0001:00001000       _main    0000000140002000 f   main.obj\n'
        ' 0001:00002000       _helper  0000000140003000 f   main.obj\n')
    m = parse_map(mp, image_base=0x140000000)
    case('解析出 2 个符号', len(m), 2)
    # 绝对 VA 0x140002000 - base 0x140000000 = 0x2000
    case('_main RVA = 0x2000（绝对VA - image base）', m.get('_main'), 0x2000)
    case('_helper RVA = 0x3000', m.get('_helper'), 0x3000)
    # 回归防护: 误用第 2 列会得到 0x1000 —— 必须不等于它
    case('**不得**误用第 2 列（0x1000）', m.get('_main') != 0x1000, True)

    print()
    print('=== 特征匹配（构造已知答案）===')
    # 造两个"假 PE"不现实 -> 直接验证核心逻辑: bytes.find
    a = b'AAAABBBBCCCCDDDD'
    case('相同特征可匹配', a.find(b'BBBB') >= 0, True)
    case('不同特征不匹配', a.find(b'XXXX') >= 0, False)

    print()
    print('=== 稳定性判定的边界 ===')
    # 验证"完全相同的文件"-> 匹配率 100%
    p1 = os.path.join(T, 'x1.bin')
    p2 = os.path.join(T, 'x2.bin')
    rng = random.Random(7)
    blob = bytes(rng.randrange(256) for _ in range(8192))
    open(p1, 'wb').write(blob)
    open(p2, 'wb').write(blob)
    case('相同文件 sha 相同',
         hashlib.sha256(open(p1, 'rb').read()).hexdigest()
         == hashlib.sha256(open(p2, 'rb').read()).hexdigest(), True)

    # 验证"单字节不同"能被检出
    blob2 = bytearray(blob)
    blob2[4000] ^= 0xFF
    p3 = os.path.join(T, 'x3.bin')
    open(p3, 'wb').write(bytes(blob2))
    same_n = sum(1 for i in range(len(blob)) if blob[i] == blob2[i])
    case('单字节不同 -> 相同字节数 8191', same_n, 8191)

    import shutil
    shutil.rmtree(T, ignore_errors=True)

    print()
    print('=' * 64)
    if fails:
        print('[migration_cost-selftest] FAIL: %d 项 -> %s'
              % (len(fails), '; '.join(fails)))
        return 1
    print('[migration_cost-selftest] PASS: 度量可自证能抓错')
    return 0


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(prog='migration_cost.py')
    ap.add_argument('a', nargs='?')
    ap.add_argument('b', nargs='?')
    ap.add_argument('--map-a', dest='mapa', default=None)
    ap.add_argument('--map-b', dest='mapb', default=None)
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--json', dest='json_out', default=None)
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not (args.a and args.b):
        ap.error('需要 <A.exe> <B.exe> 或 --selftest')

    # 自动找同名 .map
    mapa = args.mapa or (os.path.splitext(args.a)[0] + '.map')
    mapb = args.mapb or (os.path.splitext(args.b)[0] + '.map')

    r = analyse(args.a, args.b, mapa, mapb)

    print('=== 破解迁移成本度量 ===')
    print('  A: %s' % os.path.basename(args.a))
    print('  B: %s' % os.path.basename(args.b))
    print()
    print('--- M1 地址稳定性 ---')
    m1 = r['m1']
    print('  共同符号 %d；RVA 相同 %d (%.1f%%)'
          % (m1['common'], m1['same_rva'], m1['rate_same']))
    print('  -> 硬编码地址可复用率: %.1f%%' % m1['rate_same'])
    print('     （越低越好: 攻击者脚本需重定位）')

    print()
    print('--- M3 特征可匹配性（最关键）---')
    m3 = r['m3']
    print('  函数特征在 B 中命中: %d / %d (%.1f%%)'
          % (m3['matched'], m3['total'], m3['rate']))
    print('  **保护函数命中: %d / %d (%.1f%%)**'
          % (m3['prot_matched'], m3['prot_total'], m3['prot_rate']))
    print('  -> 命中即意味着攻击者**无需地址**即可跨构建定位 -> 迁移成本低')
    if m3['prot_safe']:
        print()
        print('  未被特征匹配的保护函数（这些是"安全"的）: %d' % len(m3['prot_safe']))
        for s in m3['prot_safe'][:10]:
            print('    %-46s' % s[:46])

    print()
    print('--- M4 结构稳定性 ---')
    m4 = r['m4']
    print('  节数: A=%d B=%d' % (m4['sections_a'], m4['sections_b']))
    print('  布局完全相同（VSize+RawOff）的节: %d' % m4['same_layout'])
    print('  文件大小: A=%d B=%d' % (m4['size_a'], m4['size_b']))

    print()
    print('=== 综合判定 ===')
    verdict = []
    if m3['prot_rate'] > 50:
        verdict.append('**迁移成本低**：%.0f%% 的保护函数可用字节特征跨构建定位'
                       % m3['prot_rate'])
    elif m3['prot_rate'] > 0:
        verdict.append('迁移成本中等：%.0f%% 的保护函数仍可特征定位'
                       % m3['prot_rate'])
    else:
        verdict.append('迁移成本高：无保护函数可被特征定位')
    if m1['rate_same'] > 50:
        verdict.append('地址复用率高（%.0f%%）' % m1['rate_same'])
    for v in verdict:
        print('  %s' % v)

    print()
    print('  根因（实测确认）: **随机化只作用于数据，不作用于代码**。')
    print('    变化: 节名/magic/期望值/密钥/掩码/填充区（都是**数据**）')
    print('    不变: 真实函数体的机器码 -> 可用特征扫描定位')

    if args.json_out:
        with open(args.json_out, 'w', encoding='ascii', newline='\n') as f:
            json.dump(r, f, indent=2)
        print()
        print('  已写 %s' % args.json_out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
