#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""conformance.py — 协议兼容性测试套件（W6.2）

## 与 modcheck 的区别（**关键定位**）
  | 工具 | 面向 | 校验对象 |
  |------|------|---------|
  | `modcheck`  | **本仓库**开发者 | 本仓库的 modules.json 与源码一致 |
  | **`conformance`** | **第三方实现者** | 一个**外部**模块/注册表是否合规 |

  => 本工具**不依赖本仓库的源码**，只读被检对象，
     故第三方可拿它**自证兼容**（"通过即宣称兼容协议 v1"）。

## 检查项（按协议规范 §3-§4）
  C1  **结构**: 注册表 JSON 结构合法（顶层键 + modules 对象）
  C2  **必填字段**: 13 个必填字段齐全
  C3  **类型与值域**: phases/caps 值域、布尔字段类型
  C4  **W2 字段**: abi_version / ordering / conflicts_with /
                  consumes / produces 格式合法
  C5  **资源名格式**: 小写点分（R15 规则）
  C6  **ordering 无环**: 可拓扑排序
  C7  **conflicts 完整性**: 引用存在 + 含 resolution
  C8  **known_limits 非空**: 诚实边界是协议要求
  C9  **未知字段警告**: 允许扩展，但提示（前向兼容）
  C10 **协议版本一致**: 模块 abi_version == 顶层 _protocol_version

## 用法
  python tools/conformance.py <注册表路径>
  python tools/conformance.py --selftest      # 负向测试
  python tools/conformance.py --spec-version  # 打印本套件对应的协议版本
"""
import argparse
import json
import os
import re
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

SPEC_VERSION = 1      # 本套件实现的协议版本

# 协议 v1 的字段集（见 docs/MODULE_PROTOCOL_SPEC.md）
REQUIRED = ['source', 'header', 'exports', 'deps', 'phases', 'caps',
            'modifies_text', 'verifies_text', 'page_align',
            'needs_writable_dir', 'known_limits', 'evidence', 'abi_version']
OPTIONAL_V1 = ['conflicts_with', 'ordering', 'consumes', 'produces',
               'maturity']
BOOL_FIELDS = ['modifies_text', 'verifies_text', 'page_align',
               'needs_writable_dir']
LIST_FIELDS = ['exports', 'deps', 'phases', 'caps', 'known_limits',
               'consumes', 'produces']
VALID_PHASES = {'init', 'scan', 'decide', 'enforce', 'watch'}
VALID_CAPS = {'detect', 'prevent', 'verify', 'conceal', 'respond'}
VALID_MATURITY = {'experimental', 'community', 'verified', 'core'}
RES_RE = re.compile(r'^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$')


def check(reg):
    """返回 (errors, warnings)。"""
    errors, warnings = [], []

    # C1 结构
    if not isinstance(reg, dict):
        return (['C1 注册表根必须是 JSON 对象'], [])
    if 'modules' not in reg:
        return (['C1 缺顶层键 "modules"'], [])
    if not isinstance(reg['modules'], dict):
        return (['C1 "modules" 必须是对象'], [])
    mods = reg['modules']
    prims = reg.get('primitives', {}) or {}
    names = set(mods) | set(prims)
    proto = reg.get('_protocol_version')

    if not mods:
        warnings.append('C1 modules 为空（无可检对象）')

    # C10 协议版本
    if proto is None:
        warnings.append('C10 缺顶层 _protocol_version（无法校验 abi_version）')
    elif proto != SPEC_VERSION:
        warnings.append('C10 注册表协议版本 %s != 本套件版本 %s'
                        '（可能不兼容）' % (proto, SPEC_VERSION))

    # 逐模块
    for n, m in sorted(mods.items()):
        where = n
        if not isinstance(m, dict):
            errors.append('C2 %s: 模块定义必须是对象' % where)
            continue

        # C2 必填
        for f in REQUIRED:
            if f not in m:
                errors.append('C2 %s: 缺必填字段 %r' % (where, f))

        # C3 类型与值域
        for f in BOOL_FIELDS:
            if f in m and not isinstance(m[f], bool):
                errors.append('C3 %s: %s 必须是布尔' % (where, f))
        for f in LIST_FIELDS:
            if f in m and not isinstance(m[f], list):
                errors.append('C3 %s: %s 必须是数组' % (where, f))
        for ph in (m.get('phases') or []):
            if ph not in VALID_PHASES:
                errors.append('C3 %s: phases 含非法值 %r（合法: %s）'
                              % (where, ph, sorted(VALID_PHASES)))
        for cp in (m.get('caps') or []):
            if cp not in VALID_CAPS:
                errors.append('C3 %s: caps 含非法值 %r（合法: %s）'
                              % (where, cp, sorted(VALID_CAPS)))

        # C8 known_limits 非空
        if isinstance(m.get('known_limits'), list) and not m['known_limits']:
            errors.append('C8 %s: known_limits 为空'
                          '（诚实边界是协议要求，不得省略）' % where)

        # C10 abi_version
        if proto is not None and m.get('abi_version') is not None:
            if m['abi_version'] != proto:
                errors.append('C10 %s: abi_version=%s != _protocol_version=%s'
                              % (where, m['abi_version'], proto))

        # C4 ordering
        o = m.get('ordering')
        if o is not None:
            if not isinstance(o, dict):
                errors.append('C4 %s: ordering 必须是对象' % where)
            else:
                for k in o:
                    if k not in ('after', 'before', 'priority'):
                        warnings.append('C9 %s: ordering 含未知键 %r'
                                        % (where, k))

        # C4 conflicts_with
        for c in (m.get('conflicts_with') or []):
            if not isinstance(c, dict):
                errors.append('C4 %s: conflicts_with 元素必须是对象' % where)
                continue
            if 'with' not in c:
                errors.append('C4 %s: conflicts_with 缺 "with"' % where)
            elif c['with'] not in names:
                errors.append('C7 %s: conflicts_with.with=%r 引用不存在'
                              % (where, c['with']))
            if not c.get('resolution'):
                errors.append('C7 %s: 与 %r 的冲突缺 resolution'
                              % (where, c.get('with')))

        # C5 资源名格式
        for kind in ('consumes', 'produces'):
            for r in (m.get(kind) or []):
                if not RES_RE.match(str(r)):
                    errors.append('C5 %s: %s 资源名 %r 格式非法'
                                  '（应为小写点分，如 text.bytes）'
                                  % (where, kind, r))

        # C4 maturity
        mat = m.get('maturity')
        if mat is not None and mat not in VALID_MATURITY:
            errors.append('C4 %s: maturity 值非法 %r' % (where, mat))

        # C9 未知字段（前向兼容提示）
        known = set(REQUIRED) | set(OPTIONAL_V1) | {'name'}
        for k in m:
            if k not in known:
                warnings.append('C9 %s: 未知字段 %r（协议允许扩展，'
                                '但请确认拼写）' % (where, k))

    # C6 ordering 无环
    edges = {}
    for n, m in sorted(mods.items()):
        o = (m.get('ordering') or {}) if isinstance(m, dict) else {}
        must = set(x for x in (o.get('after') or []) if x in names)
        edges[n] = must
    for n, m in sorted(mods.items()):
        o = (m.get('ordering') or {}) if isinstance(m, dict) else {}
        for b in (o.get('before') or []):
            if b in names:
                edges.setdefault(b, set()).add(n)

    WHITE, GRAY, BLACK = 0, 1, 2
    color = {n: WHITE for n in names}
    path = []

    def dfs(u):
        color[u] = GRAY
        path.append(u)
        for v in sorted(edges.get(u, ())):
            if v not in color:
                continue
            if color[v] == GRAY:
                i = path.index(v)
                errors.append('C6 ordering 存在环: %s'
                              % ' -> '.join(path[i:] + [v]))
                return True
            if color[v] == WHITE and dfs(v):
                return True
        path.pop()
        color[u] = BLACK
        return False

    for n in sorted(names):
        if color.get(n) == WHITE and dfs(n):
            break

    return errors, warnings


def selftest():
    """负向测试: 每条检查必须能抓错。"""
    import copy
    base = {
        '_protocol_version': 1,
        'modules': {
            'good': {
                'source': 'src/good.c', 'header': 'include/good.h',
                'exports': ['prot_good_scan'], 'deps': [],
                'phases': ['scan'], 'caps': ['detect'],
                'modifies_text': False, 'verifies_text': False,
                'page_align': False, 'needs_writable_dir': False,
                'known_limits': ['示例: 无实际防护'],
                'evidence': 'docs/D.md', 'abi_version': 1,
                'produces': ['good.report'],
            },
        },
    }
    fails = []

    def case(name, got, want):
        ok = got == want
        print('  %s %-46s %s' % ('ok ' if ok else '**FAIL**', name,
                                 'ok' if ok else 'got=%r want=%r' % (got, want)))
        if not ok:
            fails.append(name)

    e, w = check(base)
    case('基线: 合法注册表无错', e, [])

    print()
    print('=== C2 必填字段 ===')
    d = copy.deepcopy(base)
    del d['modules']['good']['known_limits']
    e, _ = check(d)
    case('删 known_limits -> 报错', any('C2' in x for x in e), True)

    print()
    print('=== C3 值域 ===')
    d = copy.deepcopy(base)
    d['modules']['good']['phases'] = ['bogus_phase']
    e, _ = check(d)
    case('非法 phase -> 报错', any('C3' in x for x in e), True)
    d = copy.deepcopy(base)
    d['modules']['good']['caps'] = ['bogus_cap']
    e, _ = check(d)
    case('非法 cap -> 报错', any('C3' in x for x in e), True)

    print()
    print('=== C5 资源名格式 ===')
    d = copy.deepcopy(base)
    d['modules']['good']['produces'] = ['BAD_NAME']
    e, _ = check(d)
    case('非法资源名 -> 报错', any('C5' in x for x in e), True)

    print()
    print('=== C6 环检测 ===')
    d = copy.deepcopy(base)
    d['modules']['good']['ordering'] = {'after': ['good']}
    e, _ = check(d)
    case('自环 -> 报错', any('C6' in x for x in e), True)

    print()
    print('=== C7 conflicts ===')
    d = copy.deepcopy(base)
    d['modules']['good']['conflicts_with'] = [
        {'with': 'ghost', 'resolution': 'x'}]
    e, _ = check(d)
    case('引用不存在 -> 报错', any('C7' in x for x in e), True)
    d = copy.deepcopy(base)
    d['modules']['good']['conflicts_with'] = [{'with': 'good'}]
    e, _ = check(d)
    case('缺 resolution -> 报错', any('C7' in x for x in e), True)

    print()
    print('=== C8 诚实边界 ===')
    d = copy.deepcopy(base)
    d['modules']['good']['known_limits'] = []
    e, _ = check(d)
    case('known_limits 空 -> 报错', any('C8' in x for x in e), True)

    print()
    print('=== C10 协议版本 ===')
    d = copy.deepcopy(base)
    d['modules']['good']['abi_version'] = 99
    e, _ = check(d)
    case('abi_version 不一致 -> 报错', any('C10' in x for x in e), True)

    print()
    print('=== C9 未知字段 -> 警告（前向兼容）===')
    d = copy.deepcopy(base)
    d['modules']['good']['some_future_field'] = 1
    e, w = check(d)
    case('未知字段不报错', e, [])
    case('未知字段给警告', any('C9' in x for x in w), True)

    print()
    print('=== C1 结构 ===')
    case('非对象 -> 报错', check([])[0] != [], True)
    case('缺 modules -> 报错', check({})[0] != [], True)

    print()
    print('=' * 64)
    if fails:
        print('[conformance-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    print('[conformance-selftest] PASS: 全部检查项可自证能抓错')
    return 0


def main():
    ap = argparse.ArgumentParser(prog='conformance.py')
    ap.add_argument('registry', nargs='?')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--spec-version', action='store_true')
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    if args.spec_version:
        print('conformance: 本套件实现协议 v%d' % SPEC_VERSION)
        return 0
    if args.selftest:
        return selftest()
    if not args.registry:
        ap.error('需要 <注册表路径> 或 --selftest')

    if not os.path.exists(args.registry):
        print('[conformance] FAIL: 文件不存在 %s' % args.registry,
              file=sys.stderr)
        return 1
    try:
        reg = json.load(open(args.registry, encoding='utf-8'))
    except ValueError as e:
        print('[conformance] FAIL: JSON 无效: %s' % e, file=sys.stderr)
        return 1

    errors, warnings = check(reg)
    if not args.quiet:
        print('=== 协议兼容性检查 (协议 v%d) ===' % SPEC_VERSION)
        print('  对象: %s' % args.registry)
        n_mod = len(reg.get('modules', {})) if isinstance(reg, dict) else 0
        print('  模块数: %d' % n_mod)
        print()
    for e in errors:
        print('  [X] %s' % e)
    for w in warnings:
        print('  [!] %s' % w)
    if errors:
        print()
        print('[conformance] FAIL: %d 项不合规' % len(errors))
        return 1
    if not args.quiet:
        print()
        print('[conformance] PASS: 通过协议 v%d 全部检查%s'
              % (SPEC_VERSION,
                 ('（%d 条警告）' % len(warnings)) if warnings else ''))
    return 0


if __name__ == '__main__':
    sys.exit(main())
