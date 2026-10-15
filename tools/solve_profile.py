#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""solve_profile.py — 策略驱动的模块集求解（W3.2）+ 结构化构建计划（W3.4）

## 用户视角的转变
  之前: 用户必须**手写模块列表**（`compositions/*.json` 的 `modules` 数组）
  现在: 用户描述**策略**（威胁 / 强度 / 性能预算 / 约束），本工具求解模块集

  > 这是"工作台"与"模块拼装器"的分界:
  > 拼装器要求用户懂所有模块；工作台只要求用户懂**自己的威胁**。

## 求解流程
  1. **威胁 -> 能力**映射（`THREAT_CAPS`）
  2. 按能力匹配模块（`caps` 字段）
  3. 过滤: 性能预算 / 部署约束 / 页面约束
  4. 依赖闭包（`deps`）+ 宿主下限（`SUBSTRATE`）
  5. 冲突检查（`conflicts_with` + `resolution` 是否可满足）
  6. 拓扑排序（`ordering`，见 compose.topo_order）
  7. 输出 **结构化构建计划**（含每个模块"为何被选/被排除"）

## 用法
  python tools/solve_profile.py --profile profiles/balanced.json
  python tools/solve_profile.py --profile profiles/balanced.json --out build/plan.json
  python tools/solve_profile.py --list
  python tools/solve_profile.py --selftest
"""
import argparse
import json
import os
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, 'tools'))
import compose  # noqa: E402

# 威胁 -> 所需能力（依据 caps 的值域: detect/prevent/verify/conceal/respond）
THREAT_CAPS = {
    'debugger': ['detect', 'prevent'],   # 调试器: 检测 + 阻止
    'tamper':   ['verify'],              # 篡改: 完整性校验
    'vm':       ['detect'],              # 虚拟机/沙箱: 检测
    'dbi':      ['detect'],              # Frida/DBI: 检测
    'piracy':   ['respond'],             # 盗版: 授权链响应
    'analysis': ['conceal'],             # 逆向分析: 混淆/隐藏
}

# 模块开销**估计**（非精确测量；依据 known_limits 的实际描述）
# 如实测: antidebug 的计时检测有固定 250ms 消耗
COST = {
    'antidebug': 'medium', 'dbiguard': 'medium', 'vmdetect': 'low',
    'integrity': 'low', 'selfcrypt': 'low', 'vm': 'medium',
    'license': 'low', 'hostid': 'low', 'strcrypt': 'low',
    'revoke': 'low', 'syscall': 'low', 'indirect': 'low',
}
COST_RANK = {'low': 0, 'medium': 1, 'high': 2}

STRENGTH_RANK = {'low': 0, 'medium': 1, 'high': 2, 'paranoid': 3}


def solve(profile, reg):
    """策略 -> 结构化求解结果（dict）。"""
    mods = reg['modules']
    prims = reg.get('primitives', {})
    reasons = {}     # name -> [理由]
    excluded = {}    # name -> 原因

    threats = profile.get('threats', []) or []
    want_caps = set()
    for t in threats:
        want_caps.update(THREAT_CAPS.get(t, []))

    perf = profile.get('performance_budget', 'medium')
    perf_rank = COST_RANK.get(perf, 1)
    cons = profile.get('constraints', {}) or {}
    allow_page = cons.get('allow_page_align', True)
    allow_wdir = cons.get('allow_writable_dir', False)
    max_mods = cons.get('max_modules', 99)

    # --- 1/2/3: 能力匹配 + 预算 + 约束 ---
    for n, m in sorted(mods.items()):
        caps = set(m.get('caps', []))
        hit = caps & want_caps
        if not hit:
            excluded[n] = '能力 %s 与所需 %s 无交集' % (
                sorted(caps) or '无', sorted(want_caps))
            continue
        c = COST.get(n, 'low')
        if COST_RANK[c] > perf_rank:
            excluded[n] = '开销 %s 超出性能预算 %s' % (c, perf)
            continue
        if m.get('needs_writable_dir') and not allow_wdir:
            excluded[n] = '需要可写目录（策略约束禁止）'
            continue
        if m.get('page_align') and not allow_page:
            excluded[n] = '需要独占页（策略约束禁止）'
            continue
        src_threats = [t for t in threats
                       if set(THREAT_CAPS.get(t, [])) & hit]
        reasons[n] = ['能力匹配 %s（对应威胁: %s）'
                      % (sorted(hit), ', '.join(src_threats))]

    selected = set(reasons)

    # --- 4: 依赖闭包 + 宿主下限 ---
    full = compose.closure(sorted(selected), reg)
    auto = sorted(full - selected)
    for n in auto:
        # ⚠️ **必须从 excluded 移除**（2026-09-23 实测修正）
        #
        # 缺陷: 初版只往 reasons 里加，没清 excluded ->
        #       同一模块**既在"选中"又在"排除"**，计划自相矛盾、误导用户。
        #       （balanced 策略下 selfcrypt/syscall 同时出现在两处。）
        #
        # 修法: 清掉 excluded，并在理由中**保留**"原被排除"的信息
        #       （不丢信息，只是改述为"因依赖被补入"）。
        why_was = excluded.pop(n, None)
        msg = '依赖闭包自动补入'
        if why_was:
            msg += '（原判: %s）' % why_was
        reasons.setdefault(n, []).append(msg)

    # --- 5: 冲突检查（W3.5: 共用 tools/compat.py，消除规则分叉）---
    #
    # 为什么改用 compat: 此前此处**只读 conflicts_with 字段**，
    # 而 modcheck 另有一套硬编码推导 -> 同一组合在**不同入口得到不同结论**。
    # compat.check_conflicts 同时覆盖**声明式**与**推导式**两类冲突。
    import compat as _compat
    _errs, _warns, _infos, conflicts = _compat.check_conflicts(
        reg, sorted(full), auto_added=auto)

    # --- 6: 数量上限 ---
    notes = []
    if len(full) > max_mods:
        ranked = sorted(full, key=lambda n: (
            -len(set(mods.get(n, {}).get('caps', [])) & want_caps), n))
        keep = set(ranked[:max_mods])
        for n in sorted(full - keep):
            excluded[n] = '超出 max_modules=%d' % max_mods
            reasons.pop(n, None)
        full = keep
        notes.append('因 max_modules=%d 截断' % max_mods)

    # --- 7: 拓扑排序 ---
    with_prims = set(full)
    for pn in prims:
        with_prims.add(pn)
    order, cycle = compose.topo_order(with_prims, reg)

    return {
        'profile': profile.get('name'),
        'strategy': {
            'threats': threats,
            'strength': profile.get('strength', 'medium'),
            'performance_budget': perf,
            'constraints': cons,
        },
        'derived_capabilities': sorted(want_caps),
        'selected': sorted(full),
        'auto_added': auto,
        'excluded': excluded,
        'reasons': {k: v for k, v in sorted(reasons.items())},
        'conflicts': conflicts,
        'order': order,
        'order_cycle': cycle,
        'notes': notes,
    }


def fmt_plan(r, verbose=True):
    """把求解结果格式化为**人类可读**的构建计划。"""
    L = []
    L.append('=== 构建计划 ===')
    L.append('  策略: %s' % r['profile'])
    s = r['strategy']
    L.append('    威胁: %s' % ', '.join(s['threats']))
    L.append('    强度: %s   性能预算: %s' % (s['strength'],
                                              s['performance_budget']))
    L.append('    约束: %s' % json.dumps(s['constraints'], ensure_ascii=False))
    L.append('  => 推导所需能力: %s' % ', '.join(r['derived_capabilities']))
    L.append('')
    L.append('  选中模块 (%d):' % len(r['selected']))
    for n in r['selected']:
        why = '; '.join(r['reasons'].get(n, ['(未记录)']))
        tag = ' [自动]' if n in r['auto_added'] else ''
        L.append('    %-12s%s %s' % (n, tag, why[:78]))
    if verbose:
        L.append('')
        L.append('  排除模块 (%d):' % len(r['excluded']))
        for n, why in sorted(r['excluded'].items()):
            L.append('    %-12s %s' % (n, why[:78]))
    L.append('')
    L.append('  链接顺序: %s' % ' -> '.join(r['order']))
    if r['order_cycle']:
        L.append('  **警告: ordering 成环 %s**' % r['order_cycle'])
    if r['conflicts']:
        L.append('')
        L.append('  冲突与共存条件 (%d):' % len(r['conflicts']))
        for c in r['conflicts']:
            L.append('    %s <-> %s' % (c['a'], c['b']))
            L.append('      原因: %s' % c['reason'][:74])
            L.append('      **满足条件**: %s' % c['resolution'][:74])
    for nt in r['notes']:
        L.append('  [注] %s' % nt)
    return '\n'.join(L)


def selftest():
    """负向测试: 求解器必须能抓错（纪律: 检查器须自证能抓错）。"""
    reg = json.load(open(os.path.join(REPO, 'modules.json'), encoding='utf-8'))
    fails = []

    def case(name, got, want):
        ok = got == want
        print('  %s %-46s got=%s want=%s'
              % ('ok ' if ok else '**FAIL**', name, got, want))
        if not ok:
            fails.append(name)

    print('=== 威胁 -> 能力映射 ===')
    r = solve({'name': 't', 'threats': ['tamper']}, reg)
    case('tamper -> 需要 verify', r['derived_capabilities'], ['verify'])
    case('tamper -> 选中 integrity', 'integrity' in r['selected'], True)
    r2 = solve({'name': 't', 'threats': ['analysis']}, reg)
    case('analysis -> 需要 conceal', r2['derived_capabilities'], ['conceal'])

    print()
    print('=== 性能预算过滤 ===')
    r3 = solve({'name': 't', 'threats': ['debugger'],
                'performance_budget': 'low'}, reg)
    case('low 预算 -> 排除 medium 开销的 antidebug',
         'antidebug' in r3['selected'], False)
    r4 = solve({'name': 't', 'threats': ['debugger'],
                'performance_budget': 'medium'}, reg)
    case('medium 预算 -> 允许 antidebug',
         'antidebug' in r4['selected'], True)

    print()
    print('=== 部署约束 ===')
    r5 = solve({'name': 't', 'threats': ['tamper'],
                'constraints': {'allow_page_align': False}}, reg)
    case('禁止页对齐 -> integrity 被排除（它 page_align=true）',
         'integrity' in r5['selected'], False)

    print()
    print('=== 依赖闭包 ===')
    r6 = solve({'name': 't', 'threats': ['tamper'],
                'constraints': {'allow_page_align': True,
                                'allow_writable_dir': True}}, reg)
    case('选中 integrity 时自动补入其 deps',
         all(d in r6['selected']
             for d in reg['modules']['integrity'].get('deps', [])), True)

    print()
    print('=== 冲突与共存条件被记录 ===')
    case('integrity+selfcrypt 的冲突被记录',
         any({c['a'], c['b']} == {'integrity', 'selfcrypt'}
             for c in r6['conflicts']), True)
    case('冲突带 resolution',
         all(c['resolution'] for c in r6['conflicts']), True)

    print()
    print('=== 选中与排除**不得重叠**（2026-09-23 缺陷回归）===')
    overlap = set(r6['selected']) & set(r6['excluded'])
    case('selected ∩ excluded 为空', sorted(overlap), [])
    # 对全部策略都要成立
    bad = []
    for f in sorted(os.listdir(os.path.join(REPO, 'profiles'))):
        if not f.endswith('.json') or f.startswith('_'):
            continue
        p = json.load(open(os.path.join(REPO, 'profiles', f),
                           encoding='utf-8'))
        rr = solve(p, reg)
        ov = set(rr['selected']) & set(rr['excluded'])
        if ov:
            bad.append('%s: %s' % (f, sorted(ov)))
    case('全部策略均无重叠', bad, [])

    print()
    print('=== 空威胁 -> 不选任何模块 ===')
    r7 = solve({'name': 't', 'threats': []}, reg)
    case('无威胁 -> selected 为空', len(r7['selected']), 0)

    print()
    print('=== 拓扑顺序无环 ===')
    case('顺序无环', r6['order_cycle'], [])

    print()
    print('=' * 64)
    if fails:
        print('[solve_profile-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    print('[solve_profile-selftest] PASS: 求解器可自证能抓错')
    return 0


def main():
    ap = argparse.ArgumentParser(prog='solve_profile.py')
    ap.add_argument('--profile')
    ap.add_argument('--out', help='写出结构化计划 JSON')
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    pdir = os.path.join(REPO, 'profiles')
    if args.list or not args.profile:
        names = sorted(f for f in os.listdir(pdir) if f.endswith('.json')) \
            if os.path.isdir(pdir) else []
        print('可用策略 (%d):' % len(names))
        for f in names:
            p = json.load(open(os.path.join(pdir, f), encoding='utf-8'))
            print('  %-24s %s' % (f, p.get('description', '')[:66]))
        return 0

    path = args.profile
    if not os.path.isabs(path):
        cand = os.path.join(REPO, path)
        path = cand if os.path.exists(cand) else path
    if not os.path.exists(path):
        print('[solve_profile] FAIL: 策略文件不存在 %s' % path,
              file=sys.stderr)
        return 1

    profile = json.load(open(path, encoding='utf-8'))
    reg = json.load(open(os.path.join(REPO, 'modules.json'), encoding='utf-8'))
    r = solve(profile, reg)

    if not args.quiet:
        print(fmt_plan(r))

    if args.out:
        out = args.out
        if not os.path.isabs(out):
            out = os.path.join(REPO, out)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, 'w', encoding='utf-8', newline='\n') as f:
            json.dump(r, f, indent=2, ensure_ascii=False)
            f.write('\n')
        if not args.quiet:
            print()
            print('  结构化计划 -> %s' % out)

    # 有环 = 失败（不应发生，modcheck R12 会先拦）
    if r['order_cycle']:
        print('[solve_profile] FAIL: ordering 成环 %s' % r['order_cycle'],
              file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
