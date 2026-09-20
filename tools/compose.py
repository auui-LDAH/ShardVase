#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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

# 宿主 (demo/main.c) 无条件依赖的基础模块。
#
# **实测确定** (2026-09-20, 非推测): 用链接器作为权威 —— 只编译授权链后
# MSVC 报 12 个无法解析的外部符号, 全部来自以下 5 个"可选"模块:
#     antidebug  4 个 (scan/detected/apply_policy/fake_active)
#     integrity  3 个 (check_self/start_watchdog/set_watchdog_callback)
#     dbiguard   2 个 (scan/suspicious)
#     vmdetect   2 个 (scan/suspicious)
#     indirect   1 个 (prot_indirect_resolve)
# 加上授权链自身的 blob/hostid/license/strcrypt/vm/revoke,
# 宿主下限 = 10 个模块。
#
# 结论: 当前 main.c 是"全模块硬编码"宿主。要让 minimal 组合真正更小,
# **必须先做宿主条件编译** (BLUEPRINT §5 阶段 2 路线 A)。
# 在宿主改造完成前, 任何组合都会被解析为这 10 个模块。
SUBSTRATE = ['antidebug', 'blob', 'dbiguard', 'hostid', 'indirect',
             'integrity', 'license', 'revoke', 'strcrypt', 'vm',
             'vmdetect']

# 宿主改造完成后应缩减为 (授权链 + VM, 由 indirect 表强制):
SUBSTRATE_AFTER_HOST_REFACTOR = ['blob', 'hostid', 'license', 'revoke',
                                 'strcrypt', 'vm']


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

    srcs = []
    for m in sorted(full):
        srcs.append(reg['modules'][m]['source'].replace('\\', '/'))

    # 原语 (公共设施) 始终编译; 按需排除
    excl = set(comp.get('exclude_primitives', []))
    for pname, p in reg.get('primitives', {}).items():
        if pname in excl:
            continue
        srcs.append(p['source'].replace('\\', '/'))

    return full, sorted(srcs), auto_added, errors


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
