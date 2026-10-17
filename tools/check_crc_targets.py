#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""check_crc_targets.py — 段 CRC **目标表下标一致性**门禁（DRILL9, 2026-10-04）

## 被检查的不变量

    「CRC 目标表的**下标 -> 节名 -> magic** 映射，在以下**四处**必须一致。」

    ① tools/hashpatch.py          MAGICS / TARGET_NAMES / TARGET_LOGICAL
    ② src/integrity.c             g_prot_baked_crc[] 初始化顺序 + 两处 `j < Nu` 循环
    ③ src/platform/prot_platform_win.c    prot_plat_crc_target_name() 的 names[]
    ④ include/protect/prot_sections.h     PROT_MAGIC_* / PROT_MAGIC_*_BYTES 默认值
    （+ tools/gen_sections.py 的随机 magic 生成顺序与写入顺序）

## 为什么需要（**这不是假想的风险, 是刚踩过的坑**）

DRILL9 修复把 CRC 目标从 3 个加到 4 个时，遇到一个**静默失效**：

    `.protxec` 的节名**每构建随机**（gen_sections.py 写 PROT_SEC_XEC）。
    而 hashpatch.py 用它自己的 TARGET_NAMES 常量 `.protxec` 去找节 ——
    生成路径下 **永远找不到** -> 走

        tools/hashpatch.py  print('hashpatch: %s section absent — skip')

    -> **CRC 字段保持 0，不报错、不警告、门禁全绿、构建成功**。
    即"加了第 4 个目标"这件事**看起来做完了，实际完全没生效**。

这类缺陷的共同形态是: **表的条数对得上，语义对不上**。只数条数的检查
（`doccheck` 数 `Check`、`docclaim` 数门禁项）**看不见**它 —— 与
`docs/HANDOVER.md` 记名的"门禁项数（32）看起来完全正确"是同型事故。

## 判据

① 四个下标维度的**条数**一致（PE 侧；Linux 侧见 ③ 的不对称）；
② **逐位**的节名与 magic 一致（不是只比条数）；
③ 每个 magic 的**字符串形式**与**字节数组形式**逐字节一致；
④ `TARGET_NAMES[i]` 等于 `prot_sections.h` 里对应 `PROT_SEC_*` 默认名
   （即 hashpatch 的**回退名**与头文件默认名同源，防两处各自漂移）；
⑤ **随机节名映射在场**：凡是 `TARGET_LOGICAL[i]` 非 None 的下标，
   hashpatch.py 必须真的调用 `resolve_target_names()` —— 这条直指上面那个
   "静默 skip" 坑：映射函数被删掉/未被调用，判据 ⑤ 红。
⑥ **平台不对称是显式的**：Linux 侧 names[] 要么是 3 项且不含 PROT_SEC_XEC，
   要么是 4 项且第 4 项为 PROT_SEC_XEC。**不允许"4 项却不是 PROT_SEC_XEC"**
   —— 若声称有第 4 个目标而 ELF 侧名字对不上，ELF 上同样会静默 skip。

## 用法
    python tools/check_crc_targets.py [--quiet] [--selftest]
退出码: 0 = 一致; 1 = 漂移; 2 = SKIP（读不到文件等前置不满足）
"""
import argparse
import os
import re
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

P_SECTIONS = os.path.join(REPO, 'include', 'protect', 'prot_sections.h')
P_GENSEC = os.path.join(REPO, 'tools', 'gen_sections.py')
P_HASHPATCH = os.path.join(REPO, 'tools', 'hashpatch.py')
P_INTEGRITY = os.path.join(REPO, 'src', 'integrity.c')
P_WIN = os.path.join(REPO, 'src', 'platform', 'prot_platform_win.c')
P_LINUX = os.path.join(REPO, 'src', 'platform', 'prot_platform_linux.c')


def _read(path):
    with open(path, encoding='utf-8', errors='replace') as f:
        return f.read()


# ---------------------------------------------------------------------------
# 各方解析（全部**纯文本正则**, 不 import —— 自检需要对文本做变异）
# ---------------------------------------------------------------------------

def parse_sections_header(t):
    """④ 默认 magic: [(NAME, 'PROTCRCP'), ...] 按出现顺序。

    只取单行字符串形式；`_BYTES` 是多行大括号宏，不会被这条正则命中。
    """
    out = []
    for m in re.finditer(r'(?m)^#\s*define\s+PROT_MAGIC_([A-Z0-9]+)\s+"([^"]*)"',
                         t):
        if m.group(1).endswith('_BYTES'):
            continue
        out.append((m.group(1), m.group(2)))
    return out


def parse_magic_bytes(t):
    """④ magic 的字节数组形式: {NAME: [b'P', ...]}。"""
    out = {}
    for m in re.finditer(
            r'(?m)^#\s*define\s+PROT_MAGIC_([A-Z0-9]+)_BYTES\s*\\\s*\n\s*\{([^}]*)\}',
            t):
        raw = [c for c in re.findall(r"'([^']*)'", m.group(2))]
        out[m.group(1)] = ''.join(raw)
    return out


def parse_default_sec_names(t):
    """④ 默认节名: {逻辑名: '.protxec'}。

    逻辑名 = `prot` + 后缀小写（`PROT_SEC_XEC` -> `protxec`），
    必须与 `gen_sections.SECTION_SPECS` 的键一致。
    """
    out = {}
    for m in re.finditer(r'(?m)^#\s*define\s+PROT_SEC_([A-Z0-9]+)\s+"([^"]*)"', t):
        out['prot' + m.group(1).lower()] = m.group(2)
    return out


def parse_gen_sections(t):
    """gen_sections.py: magic 的**生成顺序**与**写入头文件的顺序**。"""
    gen_keys = []
    m = re.search(r'for k in \(([^)]*)\)', t)
    if m:
        gen_keys = re.findall(r"'([a-z0-9]+)'", m.group(1))

    hdr_pairs = []      # [(C 宏后缀, 生成字典键)]
    for m in re.finditer(
            r"#define PROT_MAGIC_([A-Z0-9]+)\s+\"%s\"\\n' % magics\['([a-z0-9]+)'\]",
            t):
        hdr_pairs.append((m.group(1), m.group(2)))

    bytes_pairs = []    # [(生成字典键, C 字节宏名)]
    m = re.search(r'for key, macro in \((.*?)\):', t, re.S)
    if m:
        bytes_pairs = re.findall(r"\('([a-z0-9]+)',\s*'(PROT_MAGIC_[A-Z0-9_]+)'\)",
                                 m.group(1))

    specs = []
    m = re.search(r'SECTION_SPECS\s*=\s*\{(.*?)\n\}', t, re.S)
    if m:
        specs = re.findall(r"'([a-z0-9]+)':\s*\(", m.group(1))
    return gen_keys, hdr_pairs, bytes_pairs, specs


def parse_hashpatch(t):
    """① MAGICS / TARGET_NAMES / TARGET_LOGICAL / ELF_TARGET_NAMES。

    TARGET_LOGICAL 里的 `None` 也是有效值（下标不参与随机化），故不能用
    `re.findall` 一把抓 —— 必须**逐位**切分。
    """
    magics, target_names, logical, elf_names = [], [], [], []

    m = re.search(r'(?m)^MAGICS\s*=\s*\(([^)]*)\)', t)
    if m:
        magics = re.findall(r"b'([^']*)'", m.group(1))

    m = re.search(r'(?m)^TARGET_NAMES\s*=\s*\(([^)]*)\)', t)
    if m:
        target_names = re.findall(r"'([^']*)'", m.group(1))

    m = re.search(r'(?m)^TARGET_LOGICAL\s*=\s*\(([^)]*)\)', t)
    if m:
        for item in m.group(1).split(','):
            item = item.strip()
            if not item:
                continue
            logical.append(None if item == 'None'
                           else item.strip().strip("'").strip('"'))

    m = re.search(r'(?m)^ELF_TARGET_NAMES\s*=\s*\(([^)]*)\)', t)
    if m:
        elf_names = re.findall(r"'([^']*)'", m.group(1))

    has_resolve = bool(re.search(r'^def resolve_target_names\s*\(', t, re.M))
    calls_resolve = bool(re.search(
        r'target_names\s*=\s*resolve_target_names\s*\(\s*target_names\s*,',
        t))
    return {'magics': magics, 'target_names': target_names,
            'logical': logical, 'elf_names': elf_names,
            'has_resolve': has_resolve, 'calls_resolve': calls_resolve}


def parse_integrity(t):
    """② 烧录表: 声明长度 + 逐项 magic 宏名 + 两处循环的上界。

    阶段4（2026-10-15）: 声明与循环上界改用宏 `PROT_CRC_COUNT`
    （基座 4 + 每构建随机额外目标），宏默认值在 prot_sections.h。
    此处返回 decl 原文（宏名或数字字符串），由 verify 解析默认值。
    """
    decl = None
    entries = []
    has_extra = False
    m = re.search(r'g_prot_baked_crc\s*\[\s*([A-Za-z0-9_]+)\s*\]\s*=\s*\{(.*?)\n\};',
                  t, re.S)
    if m:
        decl = m.group(1)
        for e in re.finditer(r'\{\s*(PROT_MAGIC_[A-Z0-9_]+)\s*,', m.group(2)):
            entries.append(e.group(1))
        # 必须是**真正的初始化器条目行**（行首即宏名）—— 仅在注释里
        # 提及该宏不算数（实测: 表上方注释含同名字样, 字符串包含判据被蒙混）。
        has_extra = bool(re.search(
            r'(?m)^\s*PROT_CRC_EXTRA_ENTRIES\s*$', m.group(2)))
    loops = re.findall(r'for \(j = 0u; j < ([A-Za-z0-9_]+); j\+\+\)', t)
    # 只保留 prot_integrity_check_self 函数体内的循环上界 ——
    # 其他函数（如 guard 快照）也有 j<... 循环, 与 CRC 表长无关。
    mfn = re.search(
        r'prot_integrity_check_self\s*\(void\)\s*\{(.*?)\n\}', t, re.S)
    loops_in_fn = (re.findall(
        r'for \(j = 0u; j < ([A-Za-z0-9_]+); j\+\+\)', mfn.group(1))
        if mfn else [])
    return {'decl': decl, 'entries': entries, 'loops': loops_in_fn,
            'has_extra': has_extra}


def parse_count_macro(t):
    """prot_sections.h 的 PROT_CRC_COUNT 默认值（数字）。"""
    m = re.search(r'(?m)^#\s*define\s+PROT_CRC_COUNT\s+(\d+)u?\b', t)
    return int(m.group(1)) if m else None


def parse_plat_targets(t):
    """③ 平台层 names[]: 返回 (decl 原文, [元素文本])。

    decl 可能是数字（linux: 3）或宏名（win: PROT_CRC_COUNT）。
    """
    m = re.search(r'prot_plat_crc_target_name\s*\(unsigned idx\)\s*\{(.*?)\n\}',
                  t, re.S)
    if not m:
        return None, []
    m2 = re.search(r'names\s*\[\s*([A-Za-z0-9_]+)\s*\]\s*=\s*\{(.*?)\};', m.group(1), re.S)
    if not m2:
        return None, []
    items = [x.strip() for x in m2.group(2).replace('\n', ' ').split(',')]
    # 去掉 C 字符串字面量的引号，只留标识符/字面内容，便于与 TARGET_NAMES 比
    items = [x.strip('"') for x in items if x]
    return m2.group(1), items


# ---------------------------------------------------------------------------
# 判据
# ---------------------------------------------------------------------------

def verify(srcs):
    """srcs: {path: text}。返回 [(判据名, ok, detail), ...]。"""
    sh = parse_sections_header(srcs[P_SECTIONS])
    sb = parse_magic_bytes(srcs[P_SECTIONS])
    sec_names = parse_default_sec_names(srcs[P_SECTIONS])
    gen_keys, gen_hdr, gen_bytes, gen_specs = parse_gen_sections(srcs[P_GENSEC])
    hp = parse_hashpatch(srcs[P_HASHPATCH])
    ig = parse_integrity(srcs[P_INTEGRITY])
    win_n, win_items = parse_plat_targets(srcs[P_WIN])
    lin_n, lin_items = parse_plat_targets(srcs[P_LINUX])

    checks = []

    def chk(name, ok, detail):
        checks.append((name, bool(ok), detail))

    # ① 条数一致（**基座**维度; 额外目标由宏通道追加, 不进静态基座）
    n_pe = len(hp['magics'])
    count_macro_default = parse_count_macro(srcs[P_SECTIONS])
    # integrity decl 是宏名（PROT_CRC_COUNT）或数字, 统一解析为数字基座
    ig_decl_n = (count_macro_default if ig['decl'] == 'PROT_CRC_COUNT'
                 else int(ig['decl']) if ig['decl'] and ig['decl'].isdigit()
                 else None)
    win_n_resolved = (count_macro_default if win_n == 'PROT_CRC_COUNT'
                      else int(win_n) if win_n and str(win_n).isdigit()
                      else None)
    counts = {
        'hashpatch.MAGICS': n_pe,
        'hashpatch.TARGET_NAMES': len(hp['target_names']),
        'hashpatch.TARGET_LOGICAL': len(hp['logical']),
        'integrity.g_prot_baked_crc[]': ig_decl_n,
        'integrity.表项数': len(ig['entries']),
        'win.names[]': win_n_resolved,
        'gen_sections.magics': len(gen_keys),
        'PROT_CRC_COUNT默认': count_macro_default,
    }
    same = len(set(counts.values())) == 1 and n_pe > 0
    chk('① 七个维度的 CRC 目标基座条数一致', same, str(counts))
    n = n_pe

    # ② 逐位: integrity 表项 -> magic 宏名 -> hashpatch MAGICS
    sec_by_name = dict(sh)                       # {'TEXT': 'PROTCRCP', ...}
    want_entries = ['PROT_MAGIC_%s_BYTES' % nm for nm, _ in sh]
    chk('② integrity 表项逐位 = 头文件默认 magic 声明顺序',
        ig['entries'] == want_entries,
        'integrity=%s want=%s' % (ig['entries'], want_entries))

    hp_magic_str = [bytes(s, 'ascii', 'replace') if False else s for s in
                    hp['magics']]
    chk('② hashpatch.MAGICS 逐位 = 头文件默认 magic 字符串',
        hp_magic_str == [v for _, v in sh],
        'hashpatch=%s header=%s' % (hp_magic_str, [v for _, v in sh]))

    # ② 循环上界跟随表长（阶段4: 循环上界必须引用 PROT_CRC_COUNT 宏,
    #   不得再写字面数字 —— 否则每构建随机 K 时循环越界/漏检）
    chk('② integrity 两处 `j < N` 循环上界 = PROT_CRC_COUNT 宏',
        ig['loops'] and all(x == 'PROT_CRC_COUNT' for x in ig['loops']),
        'loops=%s decl=%s' % (ig['loops'], ig['decl']))

    # ② 表内必须含额外目标通道（PROT_CRC_EXTRA_ENTRIES 拼接位）
    chk('② integrity 表尾含 PROT_CRC_EXTRA_ENTRIES 通道',
        ig['has_extra'], 'decl=%s entries=%s' % (ig['decl'], ig['entries']))

    # ③ magic 的字符串形式与字节数组形式逐字节一致
    bad = [nm for nm, s in sh
           if sb.get(nm) != s]
    chk('③ PROT_MAGIC_*_BYTES 与 PROT_MAGIC_* 逐字节一致',
        not bad and len(sb) == len(sh),
        'mismatch=%s bytes_n=%d header_n=%d' % (bad, len(sb), len(sh)))

    # ③' gen_sections 生成顺序 / 写入顺序 = 头文件顺序
    chk('③ gen_sections 生成顺序与写入顺序 = 头文件声明顺序',
        gen_keys == [nm.lower() for nm, _ in sh] and
        [g[0] for g in gen_hdr] == [nm for nm, _ in sh] and
        [g[0].lower() for g in gen_bytes] == [nm.lower() for nm, _ in sh],
        'gen_keys=%s hdr=%s bytes=%s' % (gen_keys, gen_hdr, gen_bytes))

    # ④ TARGET_NAMES[i] == prot_sections.h 里对应逻辑名的默认节名
    bad4 = []
    for i, logical in enumerate(hp['logical']):
        if logical is None:
            default = hp['target_names'][i] if i < len(hp['target_names']) else None
            std = ('.text', '.rdata', '.pdata')[i] if i < 3 else None
            if std is not None and default != std:
                bad4.append((i, default, std))
            continue
        want = sec_names.get(logical)
        if want is None or hp['target_names'][i] != want:
            bad4.append((i, hp['target_names'][i], want))
    chk('④ TARGET_NAMES[i] = 对应 PROT_SEC_* 默认名',
        not bad4,
        'bad=%s sec_names=%s' % (bad4, sec_names))

    # ④' 每个被映射的逻辑名都真的可被随机化（在 SECTION_SPECS 里）
    missing = [x for x in hp['logical'] if x and x not in gen_specs]
    chk('④ 被映射的逻辑名都在 gen_sections.SECTION_SPECS 中',
        not missing, 'missing=%s specs=%s' % (missing, gen_specs))

    # ⑤ 随机节名映射在场且被调用（**直指静默 skip 坑**）
    need_map = any(x for x in hp['logical'])
    chk('⑤ hashpatch 定义并在位调用 resolve_target_names()',
        (not need_map) or (hp['has_resolve'] and hp['calls_resolve']),
        'need_map=%s has_def=%s calls=%s' % (need_map, hp['has_resolve'],
                                             hp['calls_resolve']))

    # ⑥ 平台不对称必须是**显式**的
    #
    #   注意判据用的是 `len(win_items)/len(lin_items)`（**实际元素个数**），
    #   不是 `names[N]` 的**声明长度** —— 两者可以不一致（自检 M8 正是如此:
    #   声明 `names[3]` 却塞 4 个元素）。用声明长度会让"多塞一个节名"逃过判据。
    #   阶段4: win 表尾允许挂 PROT_CRC_EXTRA_TARGET_NAMES 通道
    #   （名字由生成头提供, 每构建随机 K 个）。
    win_base = hp['target_names'][:3] + ['PROT_SEC_XEC']
    win_ok = (win_n_resolved == n and
              (win_items == win_base or
               (win_items[:-1] == win_base and
                win_items[-1] == 'PROT_CRC_EXTRA_TARGET_NAMES')))
    chk('⑥ win names[] = 默认三项 + PROT_SEC_XEC [+ 额外通道]（与 TARGET_NAMES 对齐）',
        win_ok, 'decl=%s items=%s want=%s' % (win_n, win_items, win_base))
    lin_n_resolved = (int(lin_n) if lin_n and str(lin_n).isdigit() else None)
    lin_ok = (lin_n_resolved == len(lin_items) and
              ((len(lin_items) == 3 and 'PROT_SEC_XEC' not in lin_items) or
               (len(lin_items) == 4 and lin_items[-1] == 'PROT_SEC_XEC')))
    chk('⑥ linux names[] 显式不对称（3 项不含 PROT_SEC_XEC，或 4 项末位为它）',
        lin_ok, 'decl=%s items=%s' % (lin_n, lin_items))

    # ⑥' ELF 目标名元组必须与 linux names[] **逐位**一致（否则 ELF 上静默 skip）
    chk('⑥ hashpatch.ELF_TARGET_NAMES = linux names[]（逐位）',
        len(hp['elf_names']) == len(lin_items) and
        all(a == b or (b == 'PROT_SEC_XEC' and a == '.protxec')
            for a, b in zip(hp['elf_names'], lin_items)),
        'elf=%s linux=%s' % (hp['elf_names'], lin_items))

    # ⑥' ELF 目标名元组条数必须与 linux names[] 一致（否则 ELF 上静默 skip）
    chk('⑥ hashpatch.ELF_TARGET_NAMES 条数 = linux names[] 条数',
        len(hp['elf_names']) == len(lin_items),
        'elf=%s linux_items=%s' % (hp['elf_names'], lin_items))

    # ## 阶段 4（2026-10-15）: 额外目标通道判据
    #   候选池 + 三宏通道 + hashpatch 消费, 三处必须同时在场 —— 少任何
    #   一处都会退化为"静默不覆盖"（正是本判据要防的失效模式）。
    gts = srcs[P_GENSEC]
    hpt = srcs[P_HASHPATCH]
    chk('⑦ gen_sections 定义 EXTRA_POOL 候选池',
        bool(re.search(r'(?m)^EXTRA_POOL\s*=\s*\(', gts)), 'EXTRA_POOL 缺失')
    chk('⑦ gen_sections 写出 crc_extra 清单（JSON 键）',
        "'crc_extra'" in gts, "JSON 键 'crc_extra' 缺失")
    chk('⑦ 生成头写入三宏通道（COUNT/EXTRA_ENTRIES/EXTRA_TARGET_NAMES）',
        all(m in gts for m in ('PROT_CRC_EXTRA_ENTRIES',
                               'PROT_CRC_EXTRA_TARGET_NAMES',
                               'PROT_CRC_COUNT')),
        'gen_sections 缺宏写入代码')
    chk('⑦ hashpatch 消费 crc_extra（load_crc_extra 在场且被调用）',
        bool(re.search(r'^def load_crc_extra\s*\(', hpt, re.M)) and
        'load_crc_extra(sections_json)' in hpt,
        'load_crc_extra 缺失或未调用 -> 额外目标静默不烧')

    # ## 阶段 4.3（2026-10-16）: CRC 链式判据
    #   烧录端与校验端必须**同时**实现折叠 —— 只有一侧实现则每次自检
    #   必然 0xBAD（build 即红）, 两侧都"实现但退化"则链式形同虚设、
    #   §7.4「改一处须重算整链」静默失效。判据盯**实际折叠动作**
    #   （<II> 双字打包 / prot_crc32 fold 调用 / 前一槽位读取）, 不盯
    #   函数名（改名/空壳函数蒙混不过）。
    igt = srcs[P_INTEGRITY]
    chk('⑧ hashpatch 链式折叠（chain_crc 用 <II> 双字打包）',
        bool(re.search(r'^def chain_crc\s*\(', hpt, re.M)) and
        "struct.pack('<II'" in hpt and 'chain_crc(crc, prev)' in hpt,
        'chain_crc 缺失/未调用/退化为单字 -> 无链式')
    chk('⑧ integrity 链式折叠（fold(raw, 前一槽位 baked)）',
        'prot_crc32(fold, 8u)' in igt and 'read_baked_crc(j - 1u)' in igt,
        'fold 缺失或不读前一槽位 -> 逐段独立 CRC, 链式静默失效')

    return checks


# 变异表下限 —— `total = len(mutations)` 是**长度比较**，清空整表后
# `caught == total` 变成 `0 == 0`，自检会**静默变绿**且报文与基线逐字相同
# （2026-10-12 实测，§2.76）。紧贴当前值 13，不留余量：
# 留余量会让这条守卫对它要防的那件事失明（§2.49 的教训）。
# 阶段4（2026-10-15）: 8 -> 11（M4/M5/M7 锚点换宏形式 + 新增 M9-M11 额外通道）。
# 阶段4.3（2026-10-16）: 11 -> 13（M12/M13 链式折叠退化）。
_MUT_FLOOR = 13


def selftest():
    """负向自检: 逐条注入漂移，必须被判据抓到。"""
    srcs = {p: _read(p) for p in (P_SECTIONS, P_GENSEC, P_HASHPATCH,
                                  P_INTEGRITY, P_WIN, P_LINUX)}
    base = verify(srcs)
    bad = [c for c in base if not c[1]]
    print('[crc-targets-selftest] 基线: %d 条判据, %d 条失败'
          % (len(base), len(bad)))
    for name, ok, detail in bad:
        print('  [XX] %s  (%s)' % (name, detail))

    mutations = [
        ('M1 改 TARGET_NAMES 第 4 项节名',
         P_HASHPATCH, "'.protxec')", "'.protxecx')"),
        ('M2 删 MAGICS 第 4 项（条数漂移）',
         P_HASHPATCH, ", b'PROTCRCX')", ")"),
        ('M3 删 resolve_target_names 的在位调用（静默 skip 坑）',
         P_HASHPATCH,
         'target_names = resolve_target_names(target_names, section_names)',
         'pass'),
        ('M4 PROT_CRC_COUNT 默认值改 3（基座条数漂移）',
         P_SECTIONS, '#define PROT_CRC_COUNT 4u', '#define PROT_CRC_COUNT 3u'),
        ('M5 循环上界退回字面数字（宏不同步）',
         P_INTEGRITY, 'j < PROT_CRC_COUNT; j++', 'j < 4u; j++'),
        ('M6 字节数组与字符串形式不一致',
         P_SECTIONS,
         "#define PROT_MAGIC_XEC_BYTES \\\n    { 'P', 'R', 'O', 'T', 'C', 'R', 'C', 'X' }",
         "#define PROT_MAGIC_XEC_BYTES \\\n    { 'P', 'R', 'O', 'T', 'C', 'R', 'C', 'Y' }"),
        ('M7 win names[] 声明退回 3 项',
         P_WIN, 'names[PROT_CRC_COUNT] = {', 'names[3] = {'),
        ('M8 linux names[] 声称 4 项却不是 PROT_SEC_XEC',
         P_LINUX, '".text", ".rodata", ".eh_frame"',
         '".text", ".rodata", ".eh_frame", ".protxec"'),
        ('M9 删 integrity 表尾额外通道（额外目标静默丢失）',
         P_INTEGRITY, 'PROT_CRC_EXTRA_ENTRIES\n};', '    /* deleted */\n};'),
        ('M10 gen_sections JSON 键改名（hashpatch 读不到清单）',
         P_GENSEC, "'crc_extra': [{", "'crc_extra_x': [{"),
        ('M11 hashpatch 消费点改成空表（额外目标不烧）',
         P_HASHPATCH, 'crc_extra = load_crc_extra(sections_json)',
         'crc_extra = []'),
        ('M12 烧录端折叠退化为单字打包（链式名存实亡）',
         P_HASHPATCH, "struct.pack('<II', raw & 0xFFFFFFFF",
         "struct.pack('<I', raw & 0xFFFFFFFF"),
        ('M13 校验端不折叠（退回逐段独立 CRC）',
         P_INTEGRITY, 'expect = prot_crc32(fold, 8u);', 'expect = crc;'),
    ]

    caught = 0
    for label, path, old, new in mutations:
        if old not in srcs[path]:
            print('  [XX] %s -> 变异点未找到（自检本身失效）' % label)
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
    print('[crc-targets-selftest] %d/%d 变异被抓' % (caught, total))
    for name, ok, detail in base:
        print('  [%s] %s  (%s)' % ('ok' if ok else 'XX', name, detail))
    if total < _MUT_FLOOR:
        print('[crc-targets-selftest] FAIL: 变异表只有 %d 条，低于下限 %d —— '
              '有变异被删或被整表掏空（下限紧贴当前值：删变异须显式下调此数字）'
              % (total, _MUT_FLOOR))
        return 1
    return 0 if (caught == total and not bad) else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description='CRC 目标表下标一致性检查')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    missing = [p for p in (P_SECTIONS, P_GENSEC, P_HASHPATCH, P_INTEGRITY,
                           P_WIN, P_LINUX) if not os.path.isfile(p)]
    if missing:
        print('[crc-targets] SKIP: 缺少源文件 %s' % missing)
        return 2

    checks = verify({p: _read(p) for p in
                     (P_SECTIONS, P_GENSEC, P_HASHPATCH, P_INTEGRITY,
                      P_WIN, P_LINUX)})
    failed = [c for c in checks if not c[1]]
    if not args.quiet:
        for name, ok, detail in checks:
            print('  [%s] %s  (%s)' % ('ok' if ok else 'XX', name, detail))
    if failed:
        print('[crc-targets] FAIL: %d/%d 条判据未通过' % (len(failed), len(checks)))
        return 1
    if not args.quiet:
        print('[crc-targets] PASS: %d 条判据全通过' % len(checks))
    return 0


if __name__ == '__main__':
    sys.exit(main())
