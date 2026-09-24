#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""compat.py — 组合冲突检测（**单一实现，多处复用**）W3.5

## 为什么需要抽出（W3.5 的目标）
  在此之前，冲突检测逻辑**分散且重复**:
    · `modcheck.py::check_composition` —— 硬编码推导
      （`modifies_text × verifies_text`、`page_align` 计数、可写目录）
    · `solve_profile.py::solve` —— 只读 `conflicts_with` 字段
    · `compose.py` —— **完全不检查**
  => 三处规则**不一致**：同一组合在不同入口得到不同结论。

  **W3.5 的做法**: 抽出本模块，三方共用。

## 两类冲突（**语义不同，必须区分**）
  **A. 声明式冲突**（`conflicts_with` 字段）
      模块**主动声明**的冲突 + **共存条件**（`resolution` 必填）。
      例: selfcrypt 改写 .text <-> integrity 校验 .text ->
          "启用 selfcrypt 掩码豁免"。

  **B. 推导式冲突**（从字段组合推导）
      无需模块声明，从 `modifies_text` / `verifies_text` / `page_align` /
      `needs_writable_dir` **推导**出的资源冲突。
      这是**通用规则**（任何模块组合都适用），故不要求逐一声明。

  > **为什么两者都要**: 声明式表达**特定**冲突（含解法）；
  > 推导式覆盖**通用**资源冲突（不然每个模块都要重复声明一遍）。

## 严重级别
  `error`   —— 组合**不可用**（如依赖缺失）
  `warning` —— 组合**可用但需满足条件**（如 .text 冲突需掩码豁免）
  `info`    —— 提示（如自动补入宿主下限）
"""
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def check_conflicts(reg, selected, auto_added=None):
    """检查组合的冲突。

    ## 参数
      reg        注册表（modules.json 解析结果）
      selected   选中的模块名集合（**应为闭包后的最终集合**）
      auto_added 自动补入的模块（用于 info 提示）

    ## 返回
      (errors, warnings, infos, conflicts) 四个列表
      `conflicts` 是结构化的冲突记录（供构建计划使用）：
        [{'kind': 'declared'|'derived', 'a':..., 'b':...,
          'reason':..., 'resolution':..., 'severity':...}]
    """
    errors, warnings, infos, conflicts = [], [], [], []
    mods = reg.get('modules', {})
    # ⚠️ **必须包含 primitives**（2026-09-23 实测，与 W2 的 R11 同一类错误）
    #
    # 初版只取 `modules` -> compose 传入含原语（crc32/vm_rekey）的集合时
    # 报"组合含未登记模块" -> **函数提前 return** -> 冲突检测从未执行
    # （实测: compose 无任何冲突输出，而 modcheck 正常）。
    #
    # 原语是公共设施，与模块同处一个链接集合，**必须视为合法成员**。
    prims = reg.get('primitives', {}) or {}
    all_defs = dict(mods)
    all_defs.update(prims)          # 原语用同一套字段访问（缺省由 .get 兜底）
    sel = set(selected)
    auto = set(auto_added or ())

    # --- 0. 未知模块 + 依赖闭包 ---
    unknown = sorted(n for n in sel if n not in all_defs)
    if unknown:
        errors.append('组合含未登记模块: %s' % ', '.join(unknown))
        return errors, warnings, infos, conflicts

    for n in sorted(sel):
        for d in (all_defs[n].get('deps') or []):
            if d not in sel:
                errors.append('%s 依赖 %s, 但组合中未包含 %s' % (n, d, d))

    # --- A. 声明式冲突（conflicts_with）---
    seen_pairs = set()
    for n in sorted(sel):
        for c in (all_defs[n].get('conflicts_with') or []):
            w = c.get('with')
            if w not in sel:
                continue
            pair = tuple(sorted((n, w)))
            if pair in seen_pairs:
                # 双向声明时只报一次（但保留二者的 resolution 差异提示）
                continue
            seen_pairs.add(pair)
            res = (c.get('resolution') or '').strip()
            reason = (c.get('reason') or '').strip()
            conflicts.append({
                'kind': 'declared', 'a': n, 'b': w,
                'reason': reason,
                'resolution': res or '**未声明共存条件**',
                'severity': 'warning' if res else 'error',
            })
            if res:
                warnings.append('声明式冲突 %s <-> %s: %s（共存条件: %s）'
                                % (n, w, reason or '（未述原因）', res))
            else:
                errors.append('声明式冲突 %s <-> %s 缺 resolution'
                              '（协议 R14 要求说明如何共存）' % (n, w))

    # --- B. 推导式冲突 ---
    # B1. .text 改写 × 校验（P2 的核心场景）
    modifiers = sorted(n for n in sel if all_defs[n].get('modifies_text'))
    verifiers = sorted(n for n in sel if all_defs[n].get('verifies_text'))
    if modifiers and verifiers:
        # 若已有声明式冲突覆盖了同一对，则不重复报
        covered = any({c['a'], c['b']} == {m, v}
                      for c in conflicts
                      for m in modifiers for v in verifiers)
        if not covered:
            conflicts.append({
                'kind': 'derived', 'a': modifiers[0], 'b': verifiers[0],
                'reason': '%s 改写 .text，%s 校验 .text'
                          % (', '.join(modifiers), ', '.join(verifiers)),
                'resolution': '必须启用 selfcrypt 掩码豁免'
                              '（integrity.build_selfcrypt_mask）',
                'severity': 'warning',
            })
            warnings.append(
                '推导式冲突: %s 改写 .text，%s 校验 .text —— '
                '必须启用 selfcrypt 掩码豁免，否则必然 TAMPERED'
                % (', '.join(modifiers), ', '.join(verifiers)))

    # B2. 页对齐资源（P2: 页粒度自伤）
    page_mods = sorted(n for n in sel if all_defs[n].get('page_align'))
    if len(page_mods) > 1:
        conflicts.append({
            'kind': 'derived', 'a': page_mods[0], 'b': page_mods[1],
            'reason': '多个模块要求页对齐: %s' % ', '.join(page_mods),
            'resolution': '需确认各自落在**独立页**'
                          '（S1 已证明同页会导致 VirtualProtect 自伤）',
            'severity': 'warning',
        })
        warnings.append('推导式冲突: 多个模块要求页对齐 %s —— '
                        '需确认各自落在独立页' % ', '.join(page_mods))

    # B3. 部署约束（不是"冲突"，但影响可用性）
    wr = sorted(n for n in sel if all_defs[n].get('needs_writable_dir'))
    if wr:
        infos.append('需要可写目录: %s（安装目录 ACL 只读时失效）'
                     % ', '.join(wr))

    # --- C. 自动补入提示 ---
    if auto:
        infos.append('宿主下限自动补入: %s'
                     '（main.c/indirect_table.c 硬引用）'
                     % ', '.join(sorted(auto)))

    return errors, warnings, infos, conflicts


def apply_resolutions(reg, conflicts):
    """从冲突记录推导**需要满足的条件**（供编排器/构建计划使用）。

    ## 返回
      {'ok': bool, 'conditions': [str], 'blockers': [str]}

    这是把"冲突"变成"**可执行的条件**" —— 与 W2 的设计一致
    （冲突有解而非禁止）。
    """
    conditions, blockers = [], []
    for c in conflicts:
        if c['severity'] == 'error':
            blockers.append('%s <-> %s: %s'
                            % (c['a'], c['b'], c['resolution']))
        else:
            conditions.append('%s <-> %s: %s'
                              % (c['a'], c['b'], c['resolution']))
    return {'ok': not blockers, 'conditions': conditions,
            'blockers': blockers}


def selftest():
    """负向测试: 冲突检测必须能抓错。"""
    import copy
    import json as _json
    fails = []

    def case(name, got, want):
        ok = got == want
        print('  %s %-50s %s' % ('ok ' if ok else '**FAIL**', name,
                                 'ok' if ok else 'got=%r want=%r' % (got, want)))
        if not ok:
            fails.append(name)

    reg = _json.load(open(os.path.join(REPO, 'modules.json'),
                          encoding='utf-8'))

    print('=== 声明式冲突 ===')
    e, w, i, c = check_conflicts(reg, ['selfcrypt', 'integrity'],
                                 auto_added=[])
    case('selfcrypt+integrity -> 有冲突记录',
         any({x['a'], x['b']} == {'selfcrypt', 'integrity'} for x in c), True)
    case('冲突带 kind=declared',
         any(x['kind'] == 'declared' for x in c), True)

    print()
    print('=== 缺 resolution -> error（R14）===')
    reg2 = copy.deepcopy(reg)
    reg2['modules']['selfcrypt']['conflicts_with'] = [
        {'with': 'integrity', 'reason': '仅说冲突，不说怎么办'}]
    reg2['modules']['integrity']['conflicts_with'] = []
    e2, w2, i2, c2 = check_conflicts(reg2, ['selfcrypt', 'integrity'])
    case('缺 resolution -> errors 非空', len(e2) > 0, True)

    print()
    print('=== 推导式冲突（无声明时也应发现）===')
    reg3 = copy.deepcopy(reg)
    # 清掉声明，只留字段 -> 应靠推导发现
    for m in ('selfcrypt', 'integrity'):
        reg3['modules'][m]['conflicts_with'] = []
    e3, w3, i3, c3 = check_conflicts(reg3, ['selfcrypt', 'integrity'])
    case('无声明时靠字段推导出 .text 冲突',
         any(x['kind'] == 'derived' for x in c3), True)
    case('推导式冲突也带 resolution',
         all(x['resolution'] for x in c3 if x['kind'] == 'derived'), True)

    print()
    print('=== 依赖缺失 -> error ===')
    e4, _, _, _ = check_conflicts(reg, ['integrity'], auto_added=[])
    case('integrity 缺依赖 -> errors 非空', len(e4) > 0, True)

    print()
    print('=== 未知模块 -> error ===')
    e5, _, _, _ = check_conflicts(reg, ['no_such_module'])
    case('未知模块 -> errors 非空', len(e5) > 0, True)

    print()
    print('=== 空组合 -> 无错 ===')
    e6, w6, i6, c6 = check_conflicts(reg, [])
    case('空组合无错', e6, [])
    case('空组合无冲突', c6, [])

    print()
    print('=== apply_resolutions ===')
    r = apply_resolutions(reg, c)
    case('有共存条件 -> ok=True', r['ok'], True)
    case('conditions 非空', len(r['conditions']) > 0, True)

    print()
    print('=' * 66)
    if fails:
        print('[compat-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    print('[compat-selftest] PASS: 冲突检测可自证能抓错')
    return 0


if __name__ == '__main__':
    import sys
    if '--selftest' in sys.argv:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.exit(selftest())
    print('用法: python tools/compat.py --selftest')
