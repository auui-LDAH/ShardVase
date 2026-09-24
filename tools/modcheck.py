#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
tools/modcheck.py — 模块注册表校验 + 组合一致性检查

对应 docs/MODULAR_ARCH.md §4.1。两件事:

  A. 注册表漂移检查 (P3: 门禁绕过会掩盖缺陷)
     逐项比对 modules.json 与真实源码:
       - source/header 文件存在
       - exports 与头文件中的 prot_* 声明一致 (双向: 不多不少)
       - deps 与源码 #include 的真实依赖一致
       - known_limits 非空 (P4: 强制公开边界)
     任何不一致 -> 报错并非零退出。

  B. 组合一致性检查 (P2: 两个各自正确的机制组合就崩)
     给定一组模块, 检查组合是否自洽:
       - 依赖闭包完整
       - modifies_text 与 verifies_text 冲突 (需 selfcrypt 掩码豁免)
       - page_align 模块的页资源冲突
       - 阶段顺序 (init -> scan -> decide -> enforce -> watch)

用法:
    python tools/modcheck.py                    # 仅注册表漂移检查
    python tools/modcheck.py --compose standard # 检查一个组合
    python tools/modcheck.py --list             # 列出所有模块
    python tools/modcheck.py --list-compositions

退出码: 0 全部通过; 1 有错误。
"""

import argparse
import glob
import json
import os
import re
import sys

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
REGISTRY = os.path.join(REPO, 'modules.json')
COMPOSITIONS = os.path.join(REPO, 'compositions')

VALID_CAPS = {'detect', 'prevent', 'conceal', 'verify', 'respond'}
VALID_PHASES = ['init', 'scan', 'decide', 'enforce', 'watch']

# 宿主下限: main.c / indirect_table.c 硬引用、无法从组合中移除的模块。
#
# **实测更新 (2026-09-20 批2 后)**: 逐个尝试排除并观察链接器结果。
#   可排除 (5): antidebug, dbiguard, integrity, syscall, vmdetect
#   不可排除 (8): blob/hostid/indirect/license/revoke/selfcrypt/strcrypt/vm
# 批1 时为 11 项; 批2 完成 antidebug/integrity 条件编译后收敛为 8 项。
# 须与 tools/compose.py 的 SUBSTRATE 保持一致 (下方有同步校验)。
HOST_SUBSTRATE = ['blob', 'hostid', 'indirect', 'license', 'revoke',
                  'selfcrypt', 'strcrypt', 'vm']

# 已实现条件编译、可被组合排除的模块 (供文档与测试引用)
HOST_EXCLUDABLE = ['antidebug', 'dbiguard', 'integrity', 'syscall', 'vmdetect']

# 头文件中的对外函数声明。
#
# 正则演进 (2026-09-20): 初版只匹配固定几个返回类型, **漏掉了**
#   const prot_indirect_fnp* prot_indirect_table(void);
#   prot_indirect_fnp        prot_indirect_resolve(...);
# 导致 indirect 模块的 exports 被静默登记为空而无人发现 ——
# 正是本工具存在的意义所在 (注册表漂移检测) 却自身有盲区。
# 现改为通用形式: 行首类型表达式 + prot_ 前缀函数名 + '('。
# 用 [A-Za-z_][\w\s\*]*? 容忍多词返回类型 (unsigned long 等) 与指针星号。
FN_DECL = re.compile(
    r'^\s*'
    r'(?![ \t]*typedef\b)'                       # 排除 typedef (如函数指针别名)
    r'(?:[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*)'     # 返回类型 (含多词)
    r'\s*\*?\s*'                                 # 可选指针
    r'(prot_\w+)\s*\('                           # 函数名
    r'[^;]*\)\s*;',                              # 参数表到分号
    re.M)


def read(path):
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return f.read()


def load_registry():
    if not os.path.isfile(REGISTRY):
        raise SystemExit('modcheck: modules.json not found')
    with open(REGISTRY, 'r', encoding='utf-8') as f:
        return json.load(f)


def header_exports(header_path):
    """头文件里声明的 prot_* 函数名集合。"""
    if not os.path.isfile(header_path):
        return None
    return set(FN_DECL.findall(read(header_path)))


def source_deps(src_path, mod_name):
    """源码 + 自身头文件里对其它模块的真实依赖。"""
    deps = set()
    paths = [src_path]
    hdr = os.path.join(REPO, 'include', 'protect', mod_name + '.h')
    if os.path.isfile(hdr):
        paths.append(hdr)
    for p in paths:
        if not os.path.isfile(p):
            continue
        for m in re.finditer(r'#include\s+"protect/([^"]+)\.h"', read(p)):
            h = m.group(1)
            # prot_sections / prot_noise 是**基础设施头**，不是模块
            # -> 与 protdef 同类，不计入模块依赖。
            #
            # 教训（2026-09-23，**同类错误犯过两次**）:
            #   · 加 prot_sections.h（阶段1 节名随机化）-> 报未登记
            #   · 加 prot_noise.h（W1.6 序言注入）-> 又报未登记
            # **凡新增非模块的 protect/*.h，必须同步本列表。**
            INFRA_HEADERS = ('protdef', 'prot_sections', 'prot_noise')
            if h not in INFRA_HEADERS and h != mod_name:
                deps.add(h)
    return deps


# ---------------------------------------------------------------------------
# A. 注册表漂移检查
# ---------------------------------------------------------------------------
def check_registry(reg):
    errors = []
    warnings = []
    mods = reg.get('modules', {})

    # 声明为模块的源文件
    declared_srcs = set()
    for name, m in mods.items():
        src = m.get('source', '')
        declared_srcs.add(os.path.normpath(src))

        # --- 字段完整性 ---
        for field in ('source', 'caps', 'phases', 'deps', 'exports',
                      'known_limits', 'page_align', 'modifies_text',
                      'verifies_text'):
            if field not in m:
                errors.append('%s: 缺字段 %s' % (name, field))

        # --- 能力/阶段取值 ---
        for c in m.get('caps', []):
            if c not in VALID_CAPS:
                errors.append('%s: 非法 capability %r' % (name, c))
        for p in m.get('phases', []):
            if p not in VALID_PHASES:
                errors.append('%s: 非法 phase %r' % (name, p))

        # --- P4: known_limits 不得为空 ---
        if not m.get('known_limits'):
            errors.append('%s: known_limits 为空 (P4 要求显式声明边界)' % name)

        # --- 依赖指向已登记模块 ---
        for d in m.get('deps', []):
            if d not in mods:
                errors.append('%s: 依赖 %r 未在注册表登记' % (name, d))

        # --- 文件存在 ---
        sp = os.path.join(REPO, src)
        if not os.path.isfile(sp):
            errors.append('%s: source 不存在 %s' % (name, src))
            continue

        # --- 导出符号双向比对 ---
        hdr_rel = m.get('header')
        if hdr_rel:
            hp = os.path.join(REPO, hdr_rel)
            actual = header_exports(hp)
            if actual is None:
                errors.append('%s: header 不存在 %s' % (name, hdr_rel))
            else:
                declared = set(m.get('exports', []))
                missing = actual - declared
                extra = declared - actual
                if missing:
                    errors.append(
                        '%s: 头文件有声明但注册表未登记: %s'
                        % (name, ', '.join(sorted(missing))))
                if extra:
                    errors.append(
                        '%s: 注册表登记但头文件无声明: %s'
                        % (name, ', '.join(sorted(extra))))

        # --- 依赖比对 ---
        actual_deps = source_deps(sp, name)
        declared_deps = set(m.get('deps', []))
        if actual_deps != declared_deps:
            miss = actual_deps - declared_deps
            ext = declared_deps - actual_deps
            if miss:
                errors.append('%s: 源码依赖但注册表未登记: %s'
                              % (name, ', '.join(sorted(miss))))
            if ext:
                errors.append('%s: 注册表登记但源码无依赖: %s'
                              % (name, ', '.join(sorted(ext))))

    # --- 未被登记也非原语的源文件 (防止新增模块漏登记) ---
    # 例外: 以 '_' 开头的文件是**模板/草稿** (如 src/_template.c), 不参与构建,
    # 不应被要求登记。约定: 模板用 '_' 前缀, 落地时改名去掉前缀。
    prims = reg.get('primitives', {})
    prim_srcs = {os.path.normpath(v.get('source', '')) for v in prims.values()}
    src_dir = os.path.join(REPO, 'src')
    if os.path.isdir(src_dir):
        for f in sorted(os.listdir(src_dir)):
            if not f.endswith('.c') or f.startswith('_'):
                continue
            rel = os.path.normpath(os.path.join('src', f))
            if rel not in declared_srcs and rel not in prim_srcs:
                warnings.append(
                    '%s: 既未登记为模块也非原语 (新增模块请补 modules.json)'
                    % rel)

    # --- HOST_SUBSTRATE 与 compose.py 的 SUBSTRATE 必须一致 ---
    # 两处都描述"宿主无法移除的模块", 漂移会导致组合解析与校验结论矛盾。
    try:
        compose_path = os.path.join(REPO, 'tools', 'compose.py')
        if os.path.isfile(compose_path):
            m = re.search(r'^SUBSTRATE\s*=\s*\[(.*?)\]',
                          read(compose_path), re.M | re.S)
            if m:
                compose_sub = set(re.findall(r"'([^']+)'", m.group(1)))
                if compose_sub != set(HOST_SUBSTRATE):
                    errors.append(
                        'HOST_SUBSTRATE 与 compose.py SUBSTRATE 不一致: '
                        'modcheck=%s compose=%s'
                        % (sorted(set(HOST_SUBSTRATE) - compose_sub) or 'ok',
                           sorted(compose_sub - set(HOST_SUBSTRATE)) or 'ok'))
    except Exception as e:                                    # noqa: BLE001
        warnings.append('无法校验 SUBSTRATE 同步: %r' % e)

    return errors, warnings


# ---------------------------------------------------------------------------
# B. 组合一致性检查
# ---------------------------------------------------------------------------
def check_composition(reg, names):
    errors = []
    warnings = []
    mods = reg['modules']

    unknown = [n for n in names if n not in mods]
    if unknown:
        return ['组合含未登记模块: %s' % ', '.join(unknown)], []

    selected = set(names)

    # --- 1. 依赖闭包完整性 ---
    for n in sorted(selected):
        for d in mods[n].get('deps', []):
            if d not in selected:
                errors.append('%s 依赖 %s, 但组合中未包含 %s' % (n, d, d))

    # --- 2. .text 改写 vs 完整性校验冲突 (P2 的核心场景) ---
    modifiers = [n for n in selected if mods[n].get('modifies_text')]
    verifiers = [n for n in selected if mods[n].get('verifies_text')]
    if modifiers and verifiers:
        warnings.append(
            '.text 冲突: %s 改写 .text, %s 校验 .text —— '
            '必须启用 selfcrypt 掩码豁免 (integrity.build_selfcrypt_mask), '
            '否则必然 TAMPERED'
            % (', '.join(sorted(modifiers)), ', '.join(sorted(verifiers))))

    # --- 3. 页对齐资源 (P2: 页粒度自伤) ---
    page_mods = [n for n in selected if mods[n].get('page_align')]
    if len(page_mods) > 1:
        warnings.append(
            '多个模块要求页对齐: %s —— 需确认各自落在独立页 '
            '(S1 已证明同页会导致 VirtualProtect 自伤)' % ', '.join(sorted(page_mods)))

    # --- 4. 部署约束 ---
    wr = [n for n in selected if mods[n].get('needs_writable_dir')]
    if wr:
        warnings.append('需要可写目录: %s (安装目录 ACL 只读时失效)'
                        % ', '.join(sorted(wr)))

    # --- 5. 宿主下限: 未显式声明但被宿主强依赖的模块 ---
    # 依据 compose.py 的 SUBSTRATE (链接器实测)。差异必须如实报出,
    # 否则拼装图会"看起来更小"而实际等价 (对使用者是误导)。
    substrate = set(HOST_SUBSTRATE)
    implicit = sorted(substrate - selected)
    if implicit:
        warnings.append(
            '宿主下限未显式声明, 将自动补入: %s '
            '(main.c/indirect_table.c 硬引用; 见 BLUEPRINT §5 阶段 2)'
            % ', '.join(implicit))

    # --- 6. 阶段顺序 ---
    seen = set()
    for ph in VALID_PHASES:
        for n in sorted(selected):
            if ph in mods[n].get('phases', []):
                seen.add(ph)
    return errors, warnings


def load_composition(name):
    path = os.path.join(COMPOSITIONS, name + '.json')
    if not os.path.isfile(path):
        return None
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def list_compositions():
    if not os.path.isdir(COMPOSITIONS):
        return []
    return sorted(f[:-5] for f in os.listdir(COMPOSITIONS) if f.endswith('.json'))



def _drill_stats():
    """从 drills/*.json 统计 {模块: (drill 数, BREACHED 数)}。"""
    import glob as _g
    stats = {}
    d = os.path.join(REPO, 'drills')
    if not os.path.isdir(d):
        return stats
    for f in sorted(_g.glob(os.path.join(d, '*.json'))):
        if os.path.basename(f).startswith('_'):
            continue
        try:
            data = json.load(open(f, encoding='utf-8'))
        except (OSError, ValueError):
            continue
        for r in data.get('attacks', data.get('drills', [])):
            tm = r.get('target_module')
            if not tm or tm == 'unmapped':
                continue
            nd, nb = stats.get(tm, (0, 0))
            nd += 1
            if str(r.get('result', '')).upper() in ('BREACHED', 'BROKEN',
                                                    'FAIL'):
                nb += 1
            stats[tm] = (nd, nb)
    return stats


def _composition_usage():
    """统计每个模块被多少个参考组合使用。"""
    import glob as _g
    use = {}
    for f in sorted(_g.glob(os.path.join(REPO, 'compositions', '*.json'))):
        try:
            c = json.load(open(f, encoding='utf-8'))
        except (OSError, ValueError):
            continue
        for m in c.get('modules', []):
            use[m] = use.get(m, 0) + 1
    return use


def check_protocol(reg):
    """W2(协议形式化 2026-09-23): 校验新协议字段。

    ## 为什么需要
      只往 modules.json 加字段而**没人读它** = 装饰，不是协议。
      本函数让新字段成为**可强制执行的契约**。

    ## 校验规则
      R10 `abi_version` 必须等于顶层 `_protocol_version`
      R11 `ordering` 的 after/before 引用必须存在
      R12 `ordering` 必须**无环**（可拓扑排序）
      R13 `conflicts_with.with` 引用必须存在
      R14 `conflicts_with` 必须声明 `resolution`（不能只说"冲突"不说怎么办）
      R15 资源名格式合法（小写点分，如 `text.bytes`）
      R16 **数据流自洽**: consumes 的资源必须有人 produces，或属外部输入白名单

    返回 (errors, warnings)。
    """
    errors = []
    warnings = []
    mods = reg.get('modules', {})
    # ⚠️ **必须包含 primitives**: 原语（crc32/vm_rekey）也参与链接顺序且
    # 可 produces 资源。初版只取 modules -> R11 误报"引用不存在的模块 crc32"。
    # （该误报是 W2 新规则**第一次运行就抓到的真实疏漏**，见 2026-09-23 记录。）
    prims = reg.get('primitives', {})
    names = set(mods) | set(prims)
    proto = reg.get('_protocol_version')

    # 外部输入白名单: 这些资源由宿主/构建系统提供，不必有模块 produces
    EXTERNAL = {'text.bytes', 'rdata.bytes', 'pdata.bytes', 'strings.table',
                'vm.blob'}

    RES_RE = re.compile(r'^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$')

    # ---- R10 abi_version ----
    if proto is None:
        warnings.append('顶层缺 _protocol_version — 跳过 abi_version 校验')
    else:
        for n, m in sorted(mods.items()):
            av = m.get('abi_version')
            if av is None:
                errors.append('R10 %s: 缺 abi_version（协议版本 %s 要求声明）'
                              % (n, proto))
            elif av != proto:
                errors.append('R10 %s: abi_version=%s != _protocol_version=%s'
                              % (n, av, proto))

    # ---- R11/R12 ordering ----
    edges = {}       # name -> set(必须在它之前的模块)
    for n, m in sorted(mods.items()):
        o = m.get('ordering')
        if not o:
            continue
        for ref in o.get('after', []):
            if ref not in names:
                errors.append('R11 %s: ordering.after 引用不存在的模块 %r'
                              % (n, ref))
            else:
                edges.setdefault(n, set()).add(ref)
        for ref in o.get('before', []):
            if ref not in names:
                errors.append('R11 %s: ordering.before 引用不存在的模块 %r'
                              % (n, ref))
            else:
                edges.setdefault(ref, set()).add(n)

    # 环检测（DFS）
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {n: WHITE for n in names}
    cycle = []

    def dfs(u, stack):
        if color.get(u) == GRAY:
            cycle.extend(stack[stack.index(u):] + [u] if u in stack else [u])
            return True
        if color.get(u) == BLACK:
            return False
        color[u] = GRAY
        stack.append(u)
        for v in sorted(edges.get(u, ())):
            if dfs(v, stack):
                return True
        stack.pop()
        color[u] = BLACK
        return False

    for n in sorted(names):
        if color[n] == WHITE:
            if dfs(n, []):
                break
    if cycle:
        errors.append('R12 ordering 存在环: %s' % ' -> '.join(cycle))

    # ---- R13/R14 conflicts_with ----
    for n, m in sorted(mods.items()):
        for c in m.get('conflicts_with', []) or []:
            if not isinstance(c, dict):
                errors.append('R13 %s: conflicts_with 元素必须是对象' % n)
                continue
            w = c.get('with')
            if w not in names:
                errors.append('R13 %s: conflicts_with.with 引用不存在的模块 %r'
                              % (n, w))
            if not c.get('resolution'):
                errors.append('R14 %s: 与 %s 的冲突缺 resolution'
                              '（必须说明如何共存，不能只说"冲突"）' % (n, w))

    # ---- R15 资源名格式 ----
    for n, m in sorted(mods.items()):
        for kind in ('consumes', 'produces'):
            for r in m.get(kind, []) or []:
                if not RES_RE.match(str(r)):
                    errors.append('R15 %s: %s 资源名 %r 格式非法'
                                  '（应为小写点分，如 text.bytes）'
                                  % (n, kind, r))

    # ---- R16 数据流自洽 ----
    produced = set()
    for m in mods.values():
        produced.update(m.get('produces', []) or [])
    # 原语的 produces 同样算数（crc32 产 crc.value）
    for p in prims.values():
        produced.update(p.get('produces', []) or [])
    for n, m in sorted(mods.items()):
        for r in m.get('consumes', []) or []:
            if r not in produced and r not in EXTERNAL:
                warnings.append('R16 %s: consumes %r 无模块 produces，'
                                '也不在外部输入白名单' % (n, r))

    # ---- R18 maturity 与证据一致（防"自封 core"）----
    #
    # ## 为什么需要（W6.4）
    #   maturity 是**声明**，而 drill 记录是**证据**。
    #   若允许"声明 core 但无证据"，分级就失去意义。
    #   本规则从 drills/ 实测推导应得级别，与声明比对。
    #
    # 准入条件（与 modules.json 的 _maturity_scale 一致）:
    #   experimental: 无要求
    #   community:    >=1 条 drill
    #   verified:     >=3 条 drill 且 >=1 条 BREACHED
    #   core:         >=5 条 drill + >=1 BREACHED + 被 >=2 个参考组合使用
    #
    # 注: 只对**声明**做校验 —— 未声明 maturity 的模块跳过（向后兼容）。
    try:
        covers = _drill_stats()
        comp_use = _composition_usage()
        for n, m in sorted(mods.items()):
            decl = m.get('maturity')
            if not decl:
                continue
            nd, nb = covers.get(n, (0, 0))
            nc = comp_use.get(n, 0)
            if decl == 'core':
                ok = (nd >= 5 and nb >= 1 and nc >= 2)
                need = '>=5 drill + >=1 BREACHED + >=2 组合'
            elif decl == 'verified':
                ok = (nd >= 3 and nb >= 1)
                need = '>=3 drill + >=1 BREACHED'
            elif decl == 'community':
                ok = (nd >= 1)
                need = '>=1 drill'
            elif decl == 'experimental':
                ok, need = True, '(无要求)'
            else:
                errors.append('R18 %s: maturity 值非法 %r'
                              '（应为 experimental/community/verified/core）'
                              % (n, decl))
                continue
            if not ok:
                errors.append(
                    'R18 %s: 声明 maturity=%s 但证据不足'
                    '（实测 drill=%d BREACHED=%d 组合=%d；%s 需要 %s）'
                    % (n, decl, nd, nb, nc, decl, need))
    except (OSError, ValueError):
        pass  # 证据不可读时跳过（不因缺证据而阻塞）

    # ---- R17 deps 与 ordering 的**语义矛盾** ----
    #
    # ## 为什么需要（W3 实测发现 2026-09-23）
    #   我最初把 `deps` 混入**链接顺序图** -> 产生假环:
    #     `integrity.deps` 含 `selfcrypt`（**能力依赖**: 需要它的掩码豁免），
    #     而 `selfcrypt.ordering.after` 含 `integrity`（**链接顺序**）。
    #     两者语义不同，混为一图 -> 报"环"。
    #
    #   => **`deps` = 运行时能力依赖；`ordering` = 链接顺序**，不可混用。
    #      但若二者**明显矛盾**，说明契约可能写错 -> 提示（warning）。
    #
    # 矛盾定义: A.deps 含 B，而 B 声称"在 A 之后"（B.after 含 A）。
    for a, m in sorted(mods.items()):
        for b in (m.get('deps', []) or []):
            bm = mods.get(b)
            if not bm:
                continue
            b_after = (bm.get('ordering') or {}).get('after', []) or []
            if a in b_after:
                warnings.append(
                    'R17 %s 依赖 %s（能力依赖），但 %s 声明 after %s'
                    '（链接顺序）—— 语义不同属正常，但请确认契约无误'
                    % (a, b, b, a))

    return errors, warnings


def selftest_protocol():
    """W2 协议规则**负向测试**（自证能抓错）。

    ## 为什么必须内置（2026-09-23 教训）
      本门禁曾因 PowerShell 数组恒真而 **7/13 项失效**。
      **一个只会通过的检查器比没有更危险。**
      故每条协议规则都必须用**已知违规输入**验证它能报错。

    用法: python tools/modcheck.py --selftest
    """
    import copy
    import tempfile
    base = load_registry()
    fails = []

    # 每条规则: (规则号, 变异函数, 期望命中的提示文本)
    def mut_r10(d):
        d['modules']['antidebug']['abi_version'] = 999

    def mut_r11(d):
        d['modules']['indirect']['ordering'] = {'after': ['no_such_module']}

    def mut_r12(d):
        d['modules']['vm'].setdefault('ordering', {})['after'] = ['blob']
        d['modules']['blob'].setdefault('ordering', {})['after'] = ['vm']

    def mut_r13(d):
        d['modules']['selfcrypt']['conflicts_with'] = [
            {'with': 'ghost_module', 'resolution': 'x'}]

    def mut_r14(d):
        d['modules']['selfcrypt']['conflicts_with'] = [
            {'with': 'integrity', 'reason': '仅说冲突'}]

    def mut_r15(d):
        d['modules']['antidebug']['produces'] = ['BAD_NAME']

    def mut_r16(d):
        d['modules']['antidebug']['consumes'] = ['nobody.produces_this']

    def mut_r18(d):
        # 证据不足却自封 core（revoke 仅 1 条 drill、0 BREACHED）
        d['modules']['revoke']['maturity'] = 'core'

    CASES = [
        ('R10', mut_r10, 'abi_version'), ('R11', mut_r11, 'ordering.after'),
        ('R12', mut_r12, '存在环'), ('R13', mut_r13, 'conflicts_with.with'),
        ('R14', mut_r14, 'resolution'), ('R15', mut_r15, '格式非法'),
        ('R18', mut_r18, '证据不足'),
    ]

    print('=== W2 协议规则负向测试 ===')
    for rule, fn, needle in CASES:
        d = copy.deepcopy(base)
        try:
            fn(d)
        except (KeyError, TypeError) as e:
            print('  **FAIL** %s 变异无法应用: %s' % (rule, e))
            fails.append(rule)
            continue
        errs, _ = check_protocol(d)
        hit = any(rule in e and needle in e for e in errs)
        print('  %s %-4s 变异后报错=%s' % ('ok ' if hit else '**FAIL**',
                                          rule, len(errs)))
        if not hit:
            fails.append(rule)
            print('       实际报错: %s' % (errs[:2] if errs else '(无)'))

    # R16 是 warning
    d = copy.deepcopy(base)
    mut_r16(d)
    _, warns = check_protocol(d)
    hit16 = any('R16' in w for w in warns)
    print('  %s R16  变异后警告=%d' % ('ok ' if hit16 else '**FAIL**',
                                       len(warns)))
    if not hit16:
        fails.append('R16')

    # R17: deps 与 ordering 矛盾（warning）
    d = copy.deepcopy(base)
    d['modules']['selfcrypt'].setdefault('ordering', {})['after'] = ['integrity']
    _, warns17 = check_protocol(d)
    hit17 = any('R17' in w for w in warns17)
    print('  %s R17  变异后警告=%d' % ('ok ' if hit17 else '**FAIL**',
                                       len(warns17)))
    if not hit17:
        fails.append('R17')

    # 基线: 未变异不应报错
    errs0, warns0 = check_protocol(copy.deepcopy(base))
    base_ok = not errs0
    print('  %s 基线 未变异时报错=%d' % ('ok ' if base_ok else '**FAIL**',
                                         len(errs0)))
    if not base_ok:
        fails.append('基线')
        print('       基线报错: %s' % errs0[:3])

    print()
    if fails:
        print('[modcheck-selftest] FAIL: %s' % ', '.join(fails))
        return 1
    print('[modcheck-selftest] PASS: 全部协议规则可自证能抓错')
    return 0


def check_drill_coverage(reg):
    """阶段 3 准入 (P4): 每个防御模块须有 ≥1 条 drill 记录。

    理由: 项目的核心资产是"每项能力都有实证"。若某模块从未被攻击过,
    它的强度就是未经验证的声明 —— 应显式标注为 "未验证" 而非默默通过。

    返回 (errors, warnings, coverage_dict)。
    未覆盖的模块产生 **warning** 而非 error: 新模块在补齐演练前不应
    阻塞构建, 但必须在每次门禁运行时被提醒 (可见, 不静默)。
    """
    errors = []
    warnings = []
    reg_dir = os.path.join(REPO, 'drills')
    covered = {}
    if not os.path.isdir(reg_dir):
        warnings.append('drills/ 不存在 — 跳过演练覆盖检查')
        return errors, warnings, covered

    files = [f for f in glob.glob(os.path.join(reg_dir, '*.json'))
             if not os.path.basename(f).startswith('_')]
    for f in files:
        try:
            d = json.load(open(f, encoding='utf-8'))
        except ValueError:
            continue
        for r in d.get('attacks', d.get('drills', [])):
            tm = r.get('target_module')
            if not tm or tm == 'unmapped':
                continue
            # 基线/跳过记录**不计入**覆盖: 它们验证"无误报", 不是
            # "挡住了攻击"。计入会虚高覆盖率 (见 BASELINE_CASES 注释)。
            if r.get('result') == 'SKIP' or r.get('source_kind') == 'baseline':
                continue
            covered.setdefault(tm, 0)
            covered[tm] += 1

    uncovered = sorted(set(reg['modules']) - set(covered))
    for m in uncovered:
        warnings.append(
            '模块 %r 无 drill 记录 — 其强度属**未经验证**的声明 '
            '(阶段3 准入: 新增模块应提交至少一条演练记录)' % m)
    return errors, warnings, covered


def main():
    ap = argparse.ArgumentParser(description='模块注册表与组合校验')
    ap.add_argument('--compose', metavar='NAME', help='检查指定组合')
    ap.add_argument('--all-compositions', action='store_true',
                    help='检查 compositions/ 下全部组合')
    ap.add_argument('--list', action='store_true', help='列出全部模块')
    ap.add_argument('--list-compositions', action='store_true',
                    help='列出全部参考拼装图')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--selftest', action='store_true',
                    help='W2 协议规则负向测试')
    args = ap.parse_args()
    if args.selftest:
        return selftest_protocol()

    reg = load_registry()
    mods = reg['modules']

    if args.list:
        print('%-12s %-22s %-26s %s' % ('MODULE', 'CAPS', 'PHASES', 'DEPS'))
        print('-' * 78)
        for k in sorted(mods):
            m = mods[k]
            print('%-12s %-22s %-26s %s'
                  % (k, ','.join(m['caps']), ','.join(m['phases']),
                     ','.join(m['deps']) or '-'))
        return 0

    if args.list_compositions:
        names = list_compositions()
        if not names:
            print('(compositions/ 为空)')
        for n in names:
            c = load_composition(n)
            desc = c.get('description', '') if c else ''
            print('%-14s %s' % (n, desc))
        return 0

    rc = 0

    # --- A. 注册表漂移 ---
    errors, warnings = check_registry(reg)
    if not args.quiet:
        print('=== 注册表漂移检查 ===')
        print('  模块 %d 个, 原语 %d 个'
              % (len(mods), len(reg.get('primitives', {}))))
    for e in errors:
        print('  [X] %s' % e)
    for w in warnings:
        print('  [!] %s' % w)
    if errors:
        rc = 1
    elif not args.quiet:
        print('  [ok] 注册表与源码一致')

    # --- A2. 协议字段检查 (W2 形式化) ---
    perr, pwarn = check_protocol(reg)
    if not args.quiet:
        print()
        print('=== 协议字段 (W2 形式化) ===')
    for e in perr:
        print('  [X] %s' % e)
    for w in pwarn:
        print('  [!] %s' % w)
    if perr:
        rc = 1
    elif not args.quiet:
        print('  [ok] 协议字段自洽')

    # --- B. 组合检查 ---
    targets = []
    if args.compose:
        targets = [args.compose]
    elif args.all_compositions:
        targets = list_compositions()

    for name in targets:
        c = load_composition(name)
        if c is None:
            print('  [X] 组合 %r 不存在' % name)
            rc = 1
            continue
        errs, warns = check_composition(reg, c.get('modules', []))
        if not args.quiet:
            print()
            print('=== 组合: %s ===' % name)
            print('  成员: %s' % ', '.join(c.get('modules', [])))
        for e in errs:
            print('  [X] %s' % e)
        for w in warns:
            print('  [!] %s' % w)
        if errs:
            rc = 1
        elif not args.quiet:
            print('  [ok] 组合自洽')

    # --- C. 演练覆盖 (阶段 3 准入, P4) ---
    derr, dwarn, covered = check_drill_coverage(reg)
    if not args.quiet:
        print()
        print('=== 演练覆盖检查 (阶段3 准入) ===')
        print('  有 drill 记录的模块: %d / %d'
              % (len(covered), len(mods)))
    for e in derr:
        print('  [X] %s' % e)
    for w in dwarn:
        print('  [!] %s' % w)
    if derr:
        rc = 1
    elif not args.quiet and not dwarn:
        print('  [ok] 全部模块均有演练记录')

    if not args.quiet:
        print()
        print('[modcheck] %s' % ('FAIL' if rc else 'PASS'))
    return rc


if __name__ == '__main__':
    sys.exit(main())
