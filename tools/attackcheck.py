#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""attackcheck.py — 攻击技注册表契约校验（缺口 #2）

## 与 modcheck 的**对称关系**
  | 工具 | 校验对象 | 对应防御侧 |
  |------|---------|-----------|
  | `modcheck.py`  | `modules.json`（防御模块契约）| —— |
  | **`attackcheck.py`** | **`attacks.json`（攻击技契约）** | `modcheck` |

## 规则（对照 modcheck 的 R1-R19，务实设计）
  A1 结构: 顶层键 + attacks 对象
  A2 `script` 文件存在
  A3 `func` 在 script 中**真实定义**（防"登记了不存在的攻击技"）
  A4 `taxonomy` 在既有 11 类内（不新增分类）
  A5 `round` 合理（1-99）
  A6 `targets` 必须是**真实模块**（在 modules.json 中）
  A7 有 `targets` 的条目**必须**有 `evidence`（可追溯）
  A8 未知字段 -> 警告（前向兼容）

## 用法
  python tools/attackcheck.py
  python tools/attackcheck.py --selftest
"""
import argparse
import ast
import json
import shutil
import os
import re
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

KNOWN_FIELDS = {'script', 'func', 'taxonomy', 'round', 'targets',
                'evidence', 'code', 'prerequisite', 'expected', 'notes'}


def _load(path):
    if not os.path.exists(path):
        return None
    try:
        return json.load(open(path, encoding='utf-8-sig'))
    except ValueError as e:
        raise ValueError('%s: JSON 无效: %s' % (path, e))


def _funcs_in(script_path):
    """用 ast 提取脚本里定义的函数名（含类内）。"""
    try:
        tree = ast.parse(open(script_path, encoding='utf-8',
                              errors='replace').read())
    except (OSError, SyntaxError):
        return set()
    return {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}


def check():
    """返回 (errors, warnings, stats)。"""
    errors, warnings = [], []
    stats = {}

    reg = _load(os.path.join(REPO, 'attacks.json'))
    if reg is None:
        return ['A1 找不到 attacks.json'], [], stats
    if not isinstance(reg, dict):
        return ['A1 attacks.json 根必须是对象'], [], stats
    if 'attacks' not in reg or not isinstance(reg['attacks'], dict):
        return ['A1 缺顶层键 "attacks"（对象）'], [], stats

    tax = list(reg.get('attack_taxonomy') or [])
    if not tax:
        warnings.append('A4 顶层缺 attack_taxonomy（无法校验分类）')
    stats['attacks'] = len(reg['attacks'])
    stats['taxonomy'] = len(tax)

    # 防御侧模块名（用于 A6）
    mods = set()
    mr = _load(os.path.join(REPO, 'modules.json'))
    if mr:
        mods = set(mr.get('modules', {}))

    # 缓存脚本函数集（同脚本多条目只解析一次）
    cache = {}
    n_targets, n_evidence = 0, 0

    for name, a in sorted(reg['attacks'].items()):
        where = 'A? %s' % name
        if not isinstance(a, dict):
            errors.append('%s: 条目必须是对象' % where)
            continue

        # A2 script 存在
        sp = a.get('script')
        if not sp:
            errors.append('A2 %s: 缺 script' % name)
            continue
        full = os.path.join(REPO, sp)
        if not os.path.isfile(full):
            errors.append('A2 %s: script 不存在 %s' % (name, sp))
            continue

        # A3 func 真实定义
        fn = a.get('func')
        if not fn:
            errors.append('A3 %s: 缺 func' % name)
        else:
            if sp not in cache:
                cache[sp] = _funcs_in(full)
            if fn not in cache[sp]:
                errors.append('A3 %s: func=%r 在 %s 中**未定义**'
                              '（登记了不存在的攻击技）' % (name, fn, sp))

        # A4 taxonomy
        t = a.get('taxonomy')
        if not t:
            errors.append('A4 %s: 缺 taxonomy' % name)
        elif tax and t not in tax:
            errors.append('A4 %s: taxonomy=%r 不在既有分类法中'
                          '（新增分类须先更新 drills/_schema.json）'
                          % (name, t))

        # A5 round
        rd = a.get('round')
        if rd is not None:
            if not isinstance(rd, int) or not (0 <= rd <= 99):
                errors.append('A5 %s: round=%r 非法（应为 0-99 整数）'
                              % (name, rd))

        # A6 targets 必须是真实模块
        tg = a.get('targets') or []
        if not isinstance(tg, list):
            errors.append('A6 %s: targets 必须是数组' % name)
        else:
            for x in tg:
                if mods and x not in mods:
                    errors.append('A6 %s: targets 含未登记模块 %r' % (name, x))
            if tg:
                n_targets += 1

        # A7 有 targets 必须有 evidence
        ev = a.get('evidence')
        if tg:
            if not ev:
                errors.append('A7 %s: 有 targets 但缺 evidence（不可追溯）'
                              % name)
            elif not os.path.exists(os.path.join(REPO, ev)):
                warnings.append('A7 %s: evidence 文件不存在 %s' % (name, ev))
            else:
                n_evidence += 1

        # A8 未知字段
        for k in a:
            if k not in KNOWN_FIELDS:
                warnings.append('A8 %s: 未知字段 %r（允许扩展，请确认拼写）'
                                % (name, k))

    stats['with_targets'] = n_targets
    stats['with_evidence'] = n_evidence
    return errors, warnings, stats


def selftest():
    """负向测试: 每条规则必须能抓错。"""
    import copy
    import tempfile
    fails = []

    def case(name, ok):
        print('  %s %-52s' % ('ok ' if ok else '**FAIL**', name))
        if not ok:
            fails.append(name)

    base = _load(os.path.join(REPO, 'attacks.json'))
    if not base:
        print('  **FAIL** 找不到 attacks.json')
        return 1

    def trial(mut):
        """临时改写 attacks.json -> 跑 check -> **逐字节恢复**。

        ## ⚠️ 备份/恢复必须用**原始字节**（2026-09-25 实测修正）
          原实现用 `json.dump(base, ...)` 备份 —— 那是"**加载后重新序列化**"
          的结果，**不是原文件**。实测后果: 自检跑完后
          `attacks.json` 的 `evidence` 计数从 **37 变 57**
          （`drill_C1` 的 evidence 丢失）-> **自检把被测数据改坏** ->
          门禁 attackcheck/e2e/mutate 连带失败。

          **教训**: 自检/变异测试**必须先保证"可完全恢复"**。

          修法: `shutil.copy2`（原始字节）备份与恢复；
                `finally` 中**确保清理** `.atbak`（不留残留）。
        """
        p = os.path.join(REPO, 'attacks.json')
        bak = p + '.atbak'
        shutil.copy2(p, bak)          # 原始字节备份
        try:
            d = copy.deepcopy(base)
            mut(d)
            with open(p, 'w', encoding='utf-8', newline='\n') as f:
                json.dump(d, f, indent=2, ensure_ascii=False)
            e, w, _ = check()
            return e
        finally:
            shutil.copy2(bak, p)      # **逐字节还原**
            if os.path.exists(bak):
                os.remove(bak)        # 不留残留

    print('=== 基线 ===')
    e0, w0, st = check()
    case('基线无错误（%d 攻击技 / %d 有 targets）'
         % (st.get('attacks', 0), st.get('with_targets', 0)), e0 == [])

    print()
    print('=== A2 script 不存在 ===')
    e = trial(lambda d: d['attacks'][list(d['attacks'])[0]].update(
        script='tests/no_such_script.py'))
    case('抓错', any('A2' in x for x in e))

    print()
    print('=== A3 func 未定义（登记不存在的攻击技）===')
    e = trial(lambda d: d['attacks'][list(d['attacks'])[0]].update(
        func='drill_totally_fake'))
    case('抓错', any('A3' in x for x in e))

    print()
    print('=== A4 非法 taxonomy ===')
    e = trial(lambda d: d['attacks'][list(d['attacks'])[0]].update(
        taxonomy='bogus_category'))
    case('抓错', any('A4' in x for x in e))

    print()
    print('=== A5 非法 round ===')
    e = trial(lambda d: d['attacks'][list(d['attacks'])[0]].update(round=999))
    case('抓错', any('A5' in x for x in e))

    print()
    print('=== A6 targets 含未登记模块 ===')
    e = trial(lambda d: d['attacks'][list(d['attacks'])[0]].update(
        targets=['ghost_module']))
    case('抓错', any('A6' in x for x in e))

    print()
    print('=== A7 有 targets 但缺 evidence ===')
    def m7(d):
        k = list(d['attacks'])[0]
        d['attacks'][k]['targets'] = ['integrity']
        d['attacks'][k].pop('evidence', None)
    e = trial(m7)
    case('抓错', any('A7' in x for x in e))

    print()
    print('=== A8 未知字段 -> 警告 ===')
    e = trial(lambda d: d['attacks'][list(d['attacks'])[0]].update(
        some_future_field=1))
    case('未知字段不报错', not any('A8' in x for x in e))

    print()
    print('=' * 64)
    if fails:
        print('[attackcheck-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    print('[attackcheck-selftest] PASS: 全部规则可自证能抓错')
    return 0


def main():
    ap = argparse.ArgumentParser(prog='attackcheck.py')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    errors, warnings, stats = check()
    if not args.quiet:
        print('=== 攻击技契约检查 ===')
        print('  攻击技: %d   分类法: %d   有 targets: %d   有 evidence: %d'
              % (stats.get('attacks', 0), stats.get('taxonomy', 0),
                 stats.get('with_targets', 0), stats.get('with_evidence', 0)))
        print()
    for e in errors:
        print('  [X] %s' % e)
    for w in warnings:
        print('  [!] %s' % w)
    if errors:
        print()
        print('[attackcheck] FAIL: %d 项不合规' % len(errors))
        return 1
    if not args.quiet:
        print()
        print('[attackcheck] PASS: 攻击技契约自洽'
              '（%d 项警告）' % len(warnings))
    return 0


if __name__ == '__main__':
    sys.exit(main())
