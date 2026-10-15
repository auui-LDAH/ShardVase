#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""selfcrypt_meta_check.py — selfcrypt meta **条目布局**四方一致性门禁（2026-10-08）

## 被检查的不变量

    「selfcrypt meta 的**条目步长**与**字段偏移**，在以下**四方**必须一致。」

    ① tools/selfcrypt_proto.py   写侧 —— `hdr` / `e_off` 的步长与 `struct.pack` 的格式串
    ② src/selfcrypt.c            读侧 —— `SC_ENTRY_SIZE` / `SC_ENTRY_GROUP_OFF`
    ③ tests/protchain_check.py   读侧 —— `SC_ENTRY_SIZE` / `SC_ENTRY_GROUP_OFF`
    ④ src/integrity.c            掩码侧 —— `build_selfcrypt_mask()` 里的裸步长与 rva/len 偏移

## 为什么需要（**这不是假想的风险, 是刚实测出来的洞**）

`docs/N1_PHASE2_PLAN.md:36` 逐字写着：

    **注意**：meta 布局改动必须同步 `selfcrypt_proto.py`（写）与 `selfcrypt.c`（读）、
    `integrity.c build_selfcrypt_mask`（读 rva/len 偏移），三侧一致。

这句话是**人工承诺**，四方**没有任何代码在读两侧并比较**。三侧当前字面量一致
（`24` / `24u` / `24`），但一致性**从未被验证过**，所以：

  * 改错 `SC_ENTRY_SIZE` 的**py 读侧** -> `tests/protchain_check.py` 会红（P1/P2 报错），
    **端到端有兜底**；
  * 改错 `SC_ENTRY_GROUP_OFF`（20 -> 16）-> `protchain_check` **rc=0 全绿**，
    `tests/e2e.py` **30/30 全绿**（实测）——
    因为 `tests/protchain_check.py:336`/`:368` 把 group 解出来又**丢掉**
    （写成 `_grp`），**没有任何判据在用这个字段**；
  * 改错 **C 读侧** `src/selfcrypt.c:80`（24u -> 20u）-> `protchain_check` 同样 **rc=0**，
    因为它读的是**自己文件里的** `SC_ENTRY_SIZE`。

  => 组字段偏移这一类漂移，**今天没有任何东西会红**。这正是本门禁要堵的。

## 判据（全部由**格式串推导**，不抄字面量）

① 写侧 `struct.pack('<FMT', ...)` 的 FMT 推导出**步长**与**逐字段偏移**；
② 写侧 `hdr = 4 + len(entries) * N` 与 `e_off = ... + i * N` 的 N == 推导步长；
③ `src/selfcrypt.c` 的 `SC_ENTRY_SIZE` / `SC_ENTRY_GROUP_OFF` == 推导值；
④ `tests/protchain_check.py` 的 `SC_ENTRY_SIZE` / `SC_ENTRY_GROUP_OFF` == 推导值；
⑤ `src/integrity.c` 的 `build_selfcrypt_mask()` 里裸步长 == 推导值，
   且它读 rva 用 `+0`、读 len 用 `+4`（== 推导出的 rva/len 偏移）；
⑥ **每一侧都必须被找到**（锚点消失即 FAIL —— 失锚**不得**读成"没有漂移"）。

判据 ⑥ 是刻意加的：本仓库已记名多次「判据失去锚点后静默变绿」
（§2.40 扫描面自声明 / §2.45 阈值锚点 / §2.46 ci.yml 失锚），故此处把
"读不到" 显式判红，而不是跳过。

## 含负向自检
    `--selftest` 对**文本**做 6 条变异（不碰仓库文件），每条都必须被抓。
    基线（真实源文件）必须全绿。

## 用法
    python tools/selfcrypt_meta_check.py [--quiet] [--selftest]
退出码: 0 = 一致; 1 = 漂移; 2 = SKIP（源文件缺失等前置不满足）

## 为什么能安全地跑
    纯文本只读；不执行被测代码；不写任何文件（`--selftest` 只变异内存中的字符串）。

## 诚实边界
    * 判据比对的是**源码文本**，不是编译产物：若 `SC_ENTRY_SIZE` 被重新定义在
      别的头文件里（本工具只读这 4 个文件），它会报"找不到锚点"而不是误绿。
    * 只覆盖**步长**与 **group/rva/len 三个偏移**；`key0`（+8）与 `crc32`（+16）
      的偏移没有独立消费者（C 侧靠 `sc_do_range` 整体结构访问），故未单列判据。
    * 不覆盖 Linux 侧（`src/selfcrypt.c` 是平台无关的，两侧共用）。
"""
import argparse
import os
import re
import struct
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

P_PROTO = os.path.join(REPO, 'tools', 'selfcrypt_proto.py')
P_SELFCRYPT = os.path.join(REPO, 'src', 'selfcrypt.c')
P_PROTCHAIN = os.path.join(REPO, 'tests', 'protchain_check.py')
P_INTEGRITY = os.path.join(REPO, 'src', 'integrity.c')


def _read(path):
    with open(path, encoding='utf-8', errors='replace') as f:
        return f.read()


# ---------------------------------------------------------------------------
# 解析（全部纯文本正则, 不 import —— 自检需要对文本做变异）
# ---------------------------------------------------------------------------

# 写侧的 entry 打包调用。
# ⚠️ 必须**锚定到 meta 条目那一行**：文件里还有 `struct.pack('<I', len(entries))`
#    （count 字段）与 ELF 侧的其它 pack；只写 `struct.pack('<...')` 会抓到第一个，
#    推导出步长 4 —— 那样基线与全部变异都会红，判据等于失效（本工具首版实测踩到）。
RE_PACK = re.compile(
    r"data\[e_off:e_off\s*\+\s*(\d+)\]\s*=\s*struct\.pack\(\s*'<([^']+)'\s*,\s*([^)]*)\)")
# 写侧步长: hdr = 4 + len(entries) * 24   /   e_off = blob_off + 4 + i * 24
RE_HDR = re.compile(r'hdr\s*=\s*4\s*\+\s*len\(entries\)\s*\*\s*(\d+)')
RE_E_OFF = re.compile(r'e_off\s*=\s*blob_off\s*\+\s*4\s*\+\s*i\s*\*\s*(\d+)')
# C 侧: #define SC_ENTRY_SIZE 24u
RE_C_SIZE = re.compile(r'#define\s+SC_ENTRY_SIZE\s+(\d+)u')
RE_C_GOFF = re.compile(r'#define\s+SC_ENTRY_GROUP_OFF\s+(\d+)u')
# py 侧: SC_ENTRY_SIZE = 24
RE_PY_SIZE = re.compile(r'(?m)^SC_ENTRY_SIZE\s*=\s*(\d+)\s*$')
RE_PY_GOFF = re.compile(r'(?m)^SC_ENTRY_GROUP_OFF\s*=\s*(\d+)\s*$')
# 掩码侧 build_selfcrypt_mask 体内的裸步长与 rva/len 偏移。
# ⚠️ rva 的字段偏移是**隐式 0**（写作 `blob + 4u + i * 24u`，后面没有 `+ 0u`），
#    故第二个 `+ Nu` 必须可选、缺省算 0 —— 首版写死了它，导致基线恒红（实测踩到）。
RE_MASK_RVA = re.compile(
    r'memcpy\(&s_rva,\s*blob\s*\+\s*4u\s*\+\s*i\s*\*\s*(\d+)u(?:\s*\+\s*(\d+)u)?')
RE_MASK_LEN = re.compile(
    r'memcpy\(&s_len,\s*blob\s*\+\s*4u\s*\+\s*i\s*\*\s*(\d+)u(?:\s*\+\s*(\d+)u)?')


# 逻辑字段顺序（写侧 `<IIQII` 的位置语义；`docs/N1_PHASE2_PLAN.md:36` 与
# `src/selfcrypt.c:78-79` 的注释同序）。判据按**位置**比对，不按实参变量名。
LOGICAL_FIELDS = ('rva', 'len', 'key0', 'crc', 'group')


def derive_layout(fmt, names):
    """从 struct 格式串推导 (步长, {逻辑字段名: 偏移}, 字母表)。

    '<' 前缀表示**无对齐**，故偏移 = 前缀的 calcsize。
    `names` = 调用处实参表；但实参是**变量名**（`rva, size, sd, crc, group`），
    与逻辑字段名（`rva, len, key0, crc, group`）不同 —— 故同时按
    **位置**把逻辑名映射上去，两者都进 dict（逻辑名优先，供判据 ③④⑤ 使用）。
    ⚠️ 只按实参名建 dict 会让 `len`/`key0` 的偏移查不到（`None`）而**静默跳过**
    那两条判据 —— 本工具首版实测就是如此（基线绿、变异也绿）。
    """
    letters = [c for c in fmt if c not in '@=<>!']
    offs = []
    for i in range(len(letters)):
        offs.append(struct.calcsize('<' + ''.join(letters[:i])))
    total = struct.calcsize('<' + ''.join(letters))
    named = {}
    for i, nm in enumerate(names):
        if i < len(letters):
            named[nm.strip()] = offs[i]
    for i, lname in enumerate(LOGICAL_FIELDS):
        if i < len(letters):
            named[lname] = offs[i]
    return total, named, letters


def parse_proto(t):
    """① 写侧：返回 (步长, 字段偏移 dict, 问题列表)。"""
    errs = []
    m = RE_PACK.search(t)
    if not m:
        return None, {}, ['tools/selfcrypt_proto.py: 找不到 entry 的 struct.pack（锚点消失）']
    slice_len, fmt, args = int(m.group(1)), m.group(2), m.group(3)
    names = [a.strip() for a in args.split(',')]
    size, offs, letters = derive_layout(fmt, names)
    if size <= 0:
        errs.append('tools/selfcrypt_proto.py: 格式串 %r 推导出非法步长 %d' % (fmt, size))
    if slice_len != size:
        errs.append('tools/selfcrypt_proto.py: 写入切片长度写作 %d，但格式串 %r 推导出 %d'
                    % (slice_len, fmt, size))

    mh = RE_HDR.search(t)
    if not mh:
        errs.append('tools/selfcrypt_proto.py: 找不到 hdr 步长（锚点消失）')
    elif int(mh.group(1)) != size:
        errs.append('tools/selfcrypt_proto.py: hdr 步长写作 %s，但格式串 %r 推导出 %d'
                    % (mh.group(1), fmt, size))
    me = RE_E_OFF.search(t)
    if not me:
        errs.append('tools/selfcrypt_proto.py: 找不到 e_off 步长（锚点消失）')
    elif int(me.group(1)) != size:
        errs.append('tools/selfcrypt_proto.py: e_off 步长写作 %s，但格式串 %r 推导出 %d'
                    % (me.group(1), fmt, size))
    return size, offs, errs


# C 侧逐字段读取 (src/selfcrypt.c:141-144 的 sc_do_range 前部)
RE_C_FIELD = re.compile(r'memcpy\(&(\w+),\s*e\s*(?:\+\s*(\d+)u)?\s*,\s*(\d+)u\)')


def parse_selfcrypt_c(t, size, offs):
    m1, m2 = RE_C_SIZE.search(t), RE_C_GOFF.search(t)
    errs = []
    if not m1:
        errs.append('src/selfcrypt.c: 找不到 SC_ENTRY_SIZE（锚点消失）')
    elif int(m1.group(1)) != size:
        errs.append('src/selfcrypt.c: SC_ENTRY_SIZE 写作 %s，真值 %d'
                    % (m1.group(1), size))
    gexp = offs.get('group')
    if not m2:
        errs.append('src/selfcrypt.c: 找不到 SC_ENTRY_GROUP_OFF（锚点消失）')
    elif gexp is not None and int(m2.group(1)) != gexp:
        errs.append('src/selfcrypt.c: SC_ENTRY_GROUP_OFF 写作 %s，字段 group 真偏移 %d'
                    % (m2.group(1), gexp))
    # 逐字段：`memcpy(&rva, e, 4u)` / `memcpy(&len, e + 4u, 4u)` /
    #         `memcpy(&k, e + 8u, 8u)` / `memcpy(&crc, e + 16u, 4u)`
    # ⚠️ C 侧把 key0 命名为 `k`（同名在 sc_do_range 里被广泛使用），故映射一次。
    C_NAMES = (('rva', 'rva'), ('len', 'len'), ('key0', 'k'), ('crc', 'crc'))
    seen = {}
    for m in RE_C_FIELD.finditer(t):
        seen[m.group(1)] = int(m.group(2) or 0)
    for fname, cname in C_NAMES:
        if cname not in seen:
            errs.append('src/selfcrypt.c: 找不到字段 %s 的 memcpy（锚点消失）' % cname)
            continue
        exp = offs.get(fname)
        if exp is not None and seen[cname] != exp:
            errs.append('src/selfcrypt.c: 字段 %s 解在 +%du，真偏移 +%d'
                        % (fname, seen[cname], exp))
    return errs


def parse_protchain(t, size, offs):
    m1, m2 = RE_PY_SIZE.search(t), RE_PY_GOFF.search(t)
    errs = []
    if not m1:
        errs.append('tests/protchain_check.py: 找不到 SC_ENTRY_SIZE（锚点消失）')
    elif int(m1.group(1)) != size:
        errs.append('tests/protchain_check.py: SC_ENTRY_SIZE 写作 %s，真值 %d'
                    % (m1.group(1), size))
    gexp = offs.get('group')
    if not m2:
        errs.append('tests/protchain_check.py: 找不到 SC_ENTRY_GROUP_OFF（锚点消失）')
    elif gexp is not None and int(m2.group(1)) != gexp:
        errs.append('tests/protchain_check.py: SC_ENTRY_GROUP_OFF 写作 %s，字段 group 真偏移 %d'
                    % (m2.group(1), gexp))
    return errs


def parse_integrity(t, size, offs):
    """④ 掩码侧：`build_selfcrypt_mask()` 内的裸步长与 rva/len 偏移。"""
    errs = []
    i = t.find('static void build_selfcrypt_mask')
    if i < 0:
        return ['src/integrity.c: 找不到 build_selfcrypt_mask（锚点消失）']
    body = t[i:i + 1400]
    mr, ml = RE_MASK_RVA.search(body), RE_MASK_LEN.search(body)
    rexp, lexp = offs.get('rva'), offs.get('len')
    if not mr:
        errs.append('src/integrity.c: build_selfcrypt_mask 里找不到 s_rva 的 memcpy（锚点消失）')
    else:
        if int(mr.group(1)) != size:
            errs.append('src/integrity.c: 掩码侧步长写作 %su，真值 %d' % (mr.group(1), size))
        if rexp is not None and int(mr.group(2) or 0) != rexp:
            errs.append('src/integrity.c: 掩码侧读 rva 用 +%su，真偏移 +%d'
                        % (mr.group(2) or 0, rexp))
    if not ml:
        errs.append('src/integrity.c: build_selfcrypt_mask 里找不到 s_len 的 memcpy（锚点消失）')
    else:
        if int(ml.group(1)) != size:
            errs.append('src/integrity.c: 掩码侧步长写作 %su，真值 %d' % (ml.group(1), size))
        if lexp is not None and int(ml.group(2) or 0) != lexp:
            errs.append('src/integrity.c: 掩码侧读 len 用 +%su，真偏移 +%d'
                        % (ml.group(2) or 0, lexp))
    return errs


def verify(srcs):
    """返回 [(判据名, ok, 详情), ...]。"""
    checks = []
    size, offs, errs = parse_proto(srcs[P_PROTO])
    if size is None:
        checks.append(('① 写侧 meta 布局可解析', False, errs[0]))
        return checks
    checks.append(('① 写侧 meta 布局可解析', True,
                   '格式串推导步长=%d, rva@%s len@%s key0@%s crc@%s group@%s'
                   % (size, offs.get('rva'), offs.get('len'), offs.get('key0'),
                      offs.get('crc'), offs.get('group'))))
    checks.append(('② 写侧 hdr/e_off 步长 == 格式串推导步长', not errs,
                   '; '.join(errs) if errs else 'hdr 与 e_off 均 = %d' % size))

    for label, fn, path in (('③ src/selfcrypt.c 读侧常量', parse_selfcrypt_c, P_SELFCRYPT),
                            ('④ tests/protchain_check.py 读侧常量', parse_protchain, P_PROTCHAIN),
                            ('⑤ src/integrity.c 掩码侧步长与偏移', parse_integrity, P_INTEGRITY)):
        e = fn(srcs[path], size, offs)
        checks.append((label, not e, '; '.join(e) if e else '一致 (步长 %d)' % size))
    return checks


# 变异表下限 —— `total = len(mutations)` 是**长度比较**，清空整表后
# `caught == total` 变成 `0 == 0`，自检会**静默变绿**且报文与基线逐字相同
# （2026-10-12 实测，§2.76）。紧贴当前值 9，不留余量：
# 留余量会让这条守卫对它要防的那件事失明（§2.49 的教训）。
_MUT_FLOOR = 9


def selftest():
    """负向自检: 对文本做变异，逐条必须被抓。"""
    paths = (P_PROTO, P_SELFCRYPT, P_PROTCHAIN, P_INTEGRITY)
    srcs = {p: _read(p) for p in paths}
    base = verify(srcs)
    bad = [c for c in base if not c[1]]
    print('[selfcrypt-meta-selftest] 基线: %d 条判据, %d 条失败' % (len(base), len(bad)))
    for name, ok, detail in bad:
        print('  [XX] %s  (%s)' % (name, detail))

    mutations = [
        ('M1 写侧 hdr 步长 24 -> 20', P_PROTO,
         'hdr = 4 + len(entries) * 24', 'hdr = 4 + len(entries) * 20'),
        ('M2 写侧 e_off 步长 24 -> 20', P_PROTO,
         'e_off = blob_off + 4 + i * 24', 'e_off = blob_off + 4 + i * 20'),
        ('M3 写侧格式串 group 挪位 (<IIQII> -> <IQIII>)', P_PROTO,
         "struct.pack('<IIQII'", "struct.pack('<IQIII'"),
        ('M4 C 读侧 SC_ENTRY_SIZE 24u -> 20u', P_SELFCRYPT,
         '#define SC_ENTRY_SIZE 24u', '#define SC_ENTRY_SIZE 20u'),
        ('M5 C 读侧 SC_ENTRY_GROUP_OFF 20u -> 16u', P_SELFCRYPT,
         '#define SC_ENTRY_GROUP_OFF 20u', '#define SC_ENTRY_GROUP_OFF 16u'),
        ('M6 py 读侧 SC_ENTRY_SIZE 24 -> 20', P_PROTCHAIN,
         'SC_ENTRY_SIZE = 24\n', 'SC_ENTRY_SIZE = 20\n'),
        ('M7 py 读侧 SC_ENTRY_GROUP_OFF 20 -> 16（今天无人抓的那一类）', P_PROTCHAIN,
         'SC_ENTRY_GROUP_OFF = 20\n', 'SC_ENTRY_GROUP_OFF = 16\n'),
        ('M8 掩码侧步长 24u -> 20u', P_INTEGRITY,
         'memcpy(&s_rva, blob + 4u + i * 24u', 'memcpy(&s_rva, blob + 4u + i * 20u'),
        ('M9 掩码侧读 len 用 +4u -> +8u', P_INTEGRITY,
         'memcpy(&s_len, blob + 4u + i * 24u + 4u',
         'memcpy(&s_len, blob + 4u + i * 24u + 8u'),
    ]

    caught = 0
    for label, path, old, new in mutations:
        if old not in srcs[path]:
            # ⚠️ 两种成因必须分开说（实测出处 §2.52）：真实仓库**已经被**改成
            #    了新值（例如门禁的注入轮把 `SC_ENTRY_GROUP_OFF` 改成了 16）
            #    时，这里照样命中，而旧文案一律说「自检本身失效」—— 把
            #    「被测文件处于变异态」误报成「自检坏了」。
            if new in srcs[path]:
                print('  [XX] %s -> **变异点已是新值**：%s 里已经写着变异后的文本，'
                      '说明该文件当前处于变异/未还原状态（不是自检失效）'
                      % (label, path))
            else:
                print('  [XX] %s -> 变异点未找到（自检本身失效：%s 里既无旧值也无新值，'
                      '说明源码被改名/挪走了）' % (label, path))
            continue
        m = dict(srcs)
        m[path] = srcs[path].replace(old, new, 1)
        try:
            res = verify(m)
        except Exception as e:                      # noqa: BLE001
            res = [('crash', False, repr(e))]
        hit = [c for c in res if not c[1]]
        if hit:
            caught += 1
            print('  [ok] %s -> 被抓: %s' % (label, hit[0][0]))
        else:
            print('  [XX] %s -> **未被抓**（判据无判别力）' % label)

    total = len(mutations)
    print('[selfcrypt-meta-selftest] %d/%d 变异被抓' % (caught, total))
    if total < _MUT_FLOOR:
        print('[selfcrypt-meta-selftest] FAIL: 变异表只有 %d 条，低于下限 %d —— '
              '有变异被删或被整表掏空（下限紧贴当前值：删变异须显式下调此数字）'
              % (total, _MUT_FLOOR))
        return 1
    return 0 if (caught == total and not bad) else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description='selfcrypt meta 条目布局四方一致性检查')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    paths = (P_PROTO, P_SELFCRYPT, P_PROTCHAIN, P_INTEGRITY)
    missing = [p for p in paths if not os.path.isfile(p)]
    if missing:
        print('[selfcrypt-meta] SKIP: 缺少源文件 %s' % missing)
        return 2

    checks = verify({p: _read(p) for p in paths})
    failed = [c for c in checks if not c[1]]
    if not args.quiet:
        for name, ok, detail in checks:
            print('  [%s] %s  (%s)' % ('ok' if ok else 'XX', name, detail))
    if failed:
        print('[selfcrypt-meta] FAIL: %d/%d 条判据未通过' % (len(failed), len(checks)))
        return 1
    if not args.quiet:
        print('[selfcrypt-meta] PASS: %d 条判据全通过' % len(checks))
    return 0


if __name__ == '__main__':
    sys.exit(main())
