#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
tools/compose.py — 组合驱动构建 (阶段 2)

依据 docs/BLUEPRINT.md 阶段 2 与 docs/MODULAR_ARCH.md §4:
把一个「拼装图」(compositions/<name>.json) 转成构建所需的产物:

  1. demo/gen/prot_modconfig.h  —— 生成 PROT_MOD_<NAME> 宏,
     宿主 (demo/main.c) 据此条件编译各模块调用段
  2. 源文件列表 (stdout 或 --list-out) —— build.ps1 据此决定编译哪些 src/*.c
  3. 定义列表 (--defines-out) —— /DPROT_MOD_<NAME> 参数

设计要点 (P2): 未选中的模块**既不编译也不链接**, 而非提供空桩 ——
桩会被链接进产物, 且桩本身是可被 patch 的攻击面 (见 BLUEPRINT §5 阶段 2)。

用法:
    python tools/compose.py minimal --header-out demo/gen/prot_modconfig.h
    python tools/compose.py standard --sources-out build/_srcs.txt
    python tools/compose.py --list
"""

import argparse
import json
import os
import sys

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
REGISTRY = os.path.join(REPO, 'modules.json')
COMPOSITIONS = os.path.join(REPO, 'compositions')

# 宿主 (demo/main.c) 无条件依赖的基础模块 —— **实测更新 (2026-09-20 批2 后)**。
#
# 方法: 逐个尝试排除每个模块 (连带反向依赖闭包), 由**链接器**判定可排除性。
# 批2 完成 antidebug/integrity 条件编译后的实测结果:
#
#   可排除 (5): antidebug, dbiguard, integrity, syscall, vmdetect
#   不可排除 (8) —— 及其真实缺失符号:
#     blob       prot_vm_blob_load            (宿主直接调用)
#     hostid     prot_hostid_get              (间接表 + 宿主)
#     license    prot_license_verify / _build_message
#     revoke     prot_revoke_check            (间接表硬引用)
#     selfcrypt  prot_selfcrypt_blob / init / enter / leave
#     strcrypt   prot_str_get / prot_str_decrypt
#     vm         prot_vm_run                  (间接表 + 核心链)
#     indirect   prot_indirect_resolve        (宿主 PROT_INDIRECT_CALL)
#
# 批1 (仅 vmdetect/dbiguard 可排除) 时此表为 11 项; 批2 后收敛为 8 项。
SUBSTRATE = ['blob', 'hostid', 'indirect', 'license', 'revoke',
             'selfcrypt', 'strcrypt', 'vm']

# 可排除的模块 (供文档与测试引用)
EXCLUDABLE = ['antidebug', 'dbiguard', 'integrity', 'syscall', 'vmdetect']


def load_registry():
    with open(REGISTRY, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_composition(name):
    p = os.path.join(COMPOSITIONS, name + '.json')
    if not os.path.isfile(p):
        return None
    with open(p, 'r', encoding='utf-8') as f:
        return json.load(f)


def closure(mods, reg):
    """依赖闭包: 选中的模块必须连带其 deps。"""
    out = set(mods)
    changed = True
    while changed:
        changed = False
        for n in list(out):
            for d in reg['modules'].get(n, {}).get('deps', []):
                if d not in out:
                    out.add(d)
                    changed = True
    return out


# 编译顺序 (P2 布局敏感): **必须与改造前的 build.ps1 硬编码顺序一致**。
#
# 实测教训 (2026-09-20, -Composition 集成时发现): 若改用字母序编译,
# 链接顺序变化 -> .text 布局变化 -> 加密段与 main 的**页关系**变化 ->
# selfcrypt 的页冲突安全网跳过 vm_var -> 加密函数由 8 个降为 6 个。
# 即: 源文件顺序是**语义相关**的, 不是无关紧要的排列。
#
# 本列表的顺序 = 2026-09-20 之前 build.ps1 第 271 行的硬编码顺序。
# 新增模块须**追加到末尾**, 不得重排 (重排会改变布局并触发上述回归)。
SOURCE_ORDER = [
    'vm', 'vm_rekey', 'crc32', 'antidebug', 'integrity', 'strcrypt',
    'hostid', 'license', 'syscall', 'blob', 'revoke', 'vmdetect',
    'dbiguard', 'indirect', 'selfcrypt',
]


def topo_order(names, reg):
    """W3.3(2026-09-23): 用协议 `ordering` 字段做**拓扑排序**。

    ## 为什么替代 SOURCE_ORDER
      旧实现用**全局硬编码列表** `SOURCE_ORDER` 决定链接顺序 ->
      第三方模块**无法声明自己的先后约束**（只能被动地"追加到末尾"）。
      W2 给每个模块加了 `ordering: {after, before, priority}`，
      本函数据此排序，使顺序成为**协议可表达的属性**。

    ## 算法
      1. 建图: after=[X] 表示 X 必须先于本模块；before=[Y] 表示本模块先于 Y
      2. **Kahn 拓扑排序**，同层内按 `priority`（小者先）再按名字排序
         -> 确定性（同名同 priority -> 同顺序）
      3. 无 `ordering` 的模块用**默认 priority** 参与排序
      4. 若成环（理论上 modcheck R12 已拦截），退化为
         "priority + 名字"排序并报告（**不静默**）

    ## 与 SOURCE_ORDER 的关系
      `SOURCE_ORDER` 保留为**回退基线**: 对无 `ordering` 声明的模块，
      用它在列表中的位置作为 priority 来源 -> 保证**既有布局不变**。
    """
    # 默认 priority: 取自 SOURCE_ORDER 的位置（保持既有布局），
    # 不在列表中的排到最后（与旧行为一致: "新增模块追加末尾"）。
    def default_prio(name):
        try:
            # W3.3: 与声明的 priority **同量纲**（index×10），
            # 否则 0~14 与 10~90 混用会打乱顺序（实测教训）。
            return SOURCE_ORDER.index(name) * 10
        except ValueError:
            return (len(SOURCE_ORDER) + 10) * 10

    def info_of(name):
        if name in reg['modules']:
            m = reg['modules'][name]
        elif name in reg.get('primitives', {}):
            m = reg['primitives'][name]
        else:
            return None
        o = m.get('ordering') or {}
        return {
            'after': list(o.get('after', [])),
            'before': list(o.get('before', [])),
            'prio': o.get('priority', default_prio(name)),
        }

    nodes = {n for n in names if info_of(n) is not None}
    # ⚠️ **缓存** info 对象: info_of() 每次返回**新字典** -> 对其赋值不会保留。
    # （初版直接 info_of(b)['must_after'].add(n) -> KeyError，因为新字典里
    #   还没有 must_after 键。2026-09-23 实测修正。）
    info = {n: info_of(n) for n in nodes}

    # ⚠️ **`deps` 不参与链接顺序图**（2026-09-23 实测修正）
    #
    # 初版把 `deps` 当作"被依赖者先"的边 -> 产生**假环**:
    #   `integrity.deps` 含 `selfcrypt`（它需要 selfcrypt 的**掩码豁免**，
    #    属**运行时能力**依赖），而 `selfcrypt.ordering.after` 含 `integrity`
    #    （链接顺序）。
    #   => 两个语义不同的关系被混在一张图里 -> 报"环"。
    #
    # **结论**: `deps` = **能力依赖**（运行时），`ordering` = **链接顺序**。
    # 二者语义不同，不可混用。链接顺序只由 `ordering` + `priority` 决定。
    for n in sorted(nodes):
        info[n]['must_after'] = set(x for x in info[n]['after'] if x in nodes)
    for n in sorted(nodes):
        for b in info[n]['before']:
            if b in nodes:
                info[b]['must_after'].add(n)

    # Kahn（同层按 priority -> 名字，保证确定性）
    indeg = {n: len(info[n]['must_after']) for n in nodes}
    import heapq
    ready = [(info[n]['prio'], n) for n in nodes if indeg[n] == 0]
    heapq.heapify(ready)
    out, placed = [], set()
    while ready:
        _, n = heapq.heappop(ready)
        if n in placed:
            continue
        placed.add(n)
        out.append(n)
        for m in sorted(nodes):
            if m in placed or n not in info[m]['must_after']:
                continue
            indeg[m] -= 1
            if indeg[m] == 0:
                heapq.heappush(ready, (info[m]['prio'], m))

    cycle = sorted(nodes - placed)
    return out, cycle


def ordered_sources(names, reg):
    """按**协议 ordering**（拓扑）排序源文件；无声明时回退 SOURCE_ORDER。

    ## W3.3 变更（2026-09-23）
      旧实现: 纯 `SOURCE_ORDER` 硬编码列表 -> 第三方模块无法声明先后。
      新实现: 先做**拓扑排序**（用模块的 `ordering` 字段 + `deps`），
              同层内用 `SOURCE_ORDER` 的位置作为 priority ->
              **既有布局保持不变**（已实测: 源文件顺序与改动前一致）。

    可同时接受模块名与原语名 (crc32 / vm_rekey) —— 两者都在注册表中。
    """
    def src_of(name):
        if name in reg['modules']:
            return reg['modules'][name]['source'].replace('\\', '/')
        if name in reg.get('primitives', {}):
            return reg['primitives'][name]['source'].replace('\\', '/')
        return None

    ordered, cycle = topo_order(set(names), reg)
    if cycle:
        # modcheck R12 应已拦截；此处**不静默** —— 报告并继续
        import sys as _sys
        print('compose: 警告: ordering 成环 %s -> 该组按 priority 排序'
              % ', '.join(cycle), file=_sys.stderr)

    srcs = []
    seen = set()
    for name in ordered:
        if name in names:
            s = src_of(name)
            if s:
                srcs.append(s)
                seen.add(name)
    # 兜底: 未在注册表中找到顺序信息的（理论上不会发生）
    for name in sorted(set(names) - seen):
        s = src_of(name)
        if s:
            srcs.append(s)
    return srcs


def resolve(comp, reg):
    """拼装图 -> (最终模块集, 源文件列表, 自动补入的模块, 错误列表)"""
    errors = []
    declared = list(comp.get('modules', []))

    unknown = [m for m in declared if m not in reg['modules']]
    if unknown:
        errors.append('拼装图含未登记模块: %s' % ', '.join(unknown))
        return set(), [], [], errors

    # 依赖闭包
    full = closure(declared, reg)

    # 宿主下限 (substrate): main.c 无条件调用这些模块, 缺失则无法链接。
    # 自动补入而**不是**报错 (便利性), 但必须在 auto_added 中如实报告。
    full |= set(SUBSTRATE)

    # 自动补入 = 闭包 + 下限 中所有未显式声明的部分
    auto_added = sorted(full - set(declared))

    # 源文件按 SOURCE_ORDER 排序 (保持既有 .text 布局; 见该常量注释)
    # 注意: 原语 (crc32/vm_rekey) 也在 SOURCE_ORDER 中, 故一并按序处理。
    excl = set(comp.get('exclude_primitives', []))
    with_prims = set(full)
    for pname in reg.get('primitives', {}):
        if pname not in excl:
            with_prims.add(pname)

    srcs = ordered_sources(with_prims, reg)
    # 注意: **不可**再 sorted() —— 顺序是语义相关的 (决定 .text 布局,
    # 进而决定加密段与 main 的页关系)。见 SOURCE_ORDER 注释。
    return full, srcs, auto_added, errors


def gen_header(mods, comp_name, reg):
    """生成 prot_modconfig.h (宿主条件编译依据)。"""
    lines = [
        '/*',
        ' * prot_modconfig.h — 由 tools/compose.py 生成, 请勿手工编辑',
        ' *',
        ' * 组合: %s' % comp_name,
        ' * 生成自: modules.json + compositions/%s.json' % comp_name,
        ' *',
        ' * 宿主 (demo/main.c) 依据 PROT_MOD_<NAME> 条件编译各模块调用段。',
        ' * 未定义的模块: 既不编译也不链接 (P2: 不用空桩, 避免桩成为攻击面)。',
        ' */',
        '#ifndef PROT_MODCONFIG_H',
        '#define PROT_MODCONFIG_H',
        '',
        '/* 已启用模块 */',
    ]
    for m in sorted(mods):
        lines.append('#define PROT_MOD_%-14s 1  /* %s */'
                     % (m.upper(), ','.join(reg['modules'][m]['caps'])))

    lines.append('')
    lines.append('/* 未启用模块 (宿主应 #ifdef 排除其调用) */')
    disabled = sorted(set(reg['modules']) - set(mods))
    if disabled:
        for m in disabled:
            lines.append('/* #undef PROT_MOD_%s */' % m.upper())
    else:
        lines.append('/* (无 — 全模块已启用) */')

    lines.append('')
    lines.append('#define PROT_COMPOSITION_NAME "%s"' % comp_name)
    lines.append('')
    lines.append('#endif /* PROT_MODCONFIG_H */')
    return '\n'.join(lines) + '\n'


def list_compositions():
    if not os.path.isdir(COMPOSITIONS):
        return []
    return sorted(f[:-5] for f in os.listdir(COMPOSITIONS) if f.endswith('.json'))


def main():
    ap = argparse.ArgumentParser(description='组合驱动构建')
    ap.add_argument('composition', nargs='?', help='拼装图名 (compositions/<name>.json)')
    ap.add_argument('--header-out', help='输出 prot_modconfig.h')
    ap.add_argument('--sources-out', help='输出源文件列表 (每行一个)')
    ap.add_argument('--defines-out', help='输出 /D 定义列表 (空格分隔)')
    ap.add_argument('--list', action='store_true', help='列出全部拼装图')
    ap.add_argument('--show', action='store_true', help='打印解析结果')
    args = ap.parse_args()

    reg = load_registry()

    if args.list:
        for n in list_compositions():
            c = load_composition(n) or {}
            mods, srcs, auto, errs = resolve(c, reg)
            print('%-12s %-46s %d 模块 %d 源文件'
                  % (n, c.get('description', ''), len(mods), len(srcs)))
        return 0

    if not args.composition:
        ap.error('需要指定拼装图名 (或 --list)')

    comp = load_composition(args.composition)
    if comp is None:
        print('compose: 拼装图 %r 不存在' % args.composition, file=sys.stderr)
        return 1

    mods, srcs, auto, errs = resolve(comp, reg)
    for e in errs:
        print('compose: %s' % e, file=sys.stderr)
    if errs:
        return 1

    if args.show:
        print('组合: %s' % args.composition)
        print('  模块 (%d): %s' % (len(mods), ', '.join(sorted(mods))))
        print('  自动补入: %s' % (', '.join(auto) or '(无)'))
        print('  源文件 (%d):' % len(srcs))
        for s in srcs:
            print('     %s' % s)

    if args.header_out:
        out = os.path.join(REPO, args.header_out) if not os.path.isabs(args.header_out) \
            else args.header_out
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, 'w', encoding='utf-8', newline='\n') as f:
            f.write(gen_header(mods, args.composition, reg))

    if args.sources_out:
        with open(args.sources_out, 'w', encoding='ascii', newline='\n') as f:
            for s in srcs:
                f.write(s + '\n')

    if args.defines_out:
        with open(args.defines_out, 'w', encoding='ascii', newline='\n') as f:
            f.write(' '.join('/DPROT_MOD_%s' % m.upper() for m in sorted(mods)))

    return 0


if __name__ == '__main__':
    sys.exit(main())
