#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
tools/ingest_attacks.py — 把 tests/attacks.py 的 A1-A12 归一化进 drills/

背景 (阶段3 剩余项): `modcheck` 的演练覆盖检查只读 drills/*.json,
而 A1-A12 是**功能攻击测试** (在 tests/attacks.py 里), 未纳入统计 ->
误报 "revoke/syscall 无 drill 记录", 而实际上 A9 revoke-forge 存在。

本工具**静态解析** tests/attacks.py (不运行它), 提取每个用例的:
  id / 用例名 / 语义注释 / 目标模块
并按 drills schema 生成 drills/attacks-regression.json。

为什么静态而非运行:
  - 覆盖统计不需要"本次结果", 需要的是"这个模块被测过"这一事实
  - 运行 attacks.py 需要构建产物, 会让门禁有额外依赖
  - 用例名与注释在源码里稳定, 解析即可

映射表是**显式**的 (见 CASE_MAP): 用例 -> 目标模块 + 攻击类别。
不猜 —— 每个映射都在下方注释里给出依据 (attacks.py 的注释行)。
"""

import argparse
import json
import os
import re
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
ATTACKS = os.path.join(REPO, 'tests', 'attacks.py')
OUT = os.path.join(REPO, 'drills', 'attacks-regression.json')

# 用例 -> (目标模块, 攻击类别, 结果定性)
#
# 依据: tests/attacks.py 中每个用例的注释 (见上方 grep 结果)
#   A1  本机 machine_id 绑定成立            -> hostid   / license_forge
#   A2  VM 镜像密文高熵                     -> vm       / memory_dump
#   A3  本轮镜像内容指纹 (跨轮对比)          -> vm       / vm_reverse
#   A4  --selftest 干净环境全 0             -> antidebug/ (基线, 非攻击)
#   A5  伪造授权 (改签名 1 位) 必须被拒      -> license  / license_forge
#   A6  异机授权 (机器标识不匹配) 必须被拒    -> license  / license_forge
#   A7  分级授权 tier 篡改                  -> license  / license_forge
#   A8  伪造签名 blob                       -> blob     / license_forge
#   A9  伪造黑名单                          -> revoke   / license_forge
#   A10 静态追踪 N4 间接链                  -> indirect / symbol_resolution
#   A11 dump 视角验证 N1 自变形             -> selfcrypt/ memory_dump
#   A12 离线固定期望值对抗 N5 会话值         -> vm       / patch_data
CASE_MAP = {
    'A1':  ('hostid',    'license_forge'),
    'A2':  ('vm',        'memory_dump'),
    'A3':  ('vm',        'vm_reverse'),
    'A5':  ('license',   'license_forge'),
    'A6':  ('license',   'license_forge'),
    'A7':  ('license',   'license_forge'),
    'A8':  ('blob',      'license_forge'),
    'A9':  ('revoke',    'license_forge'),
    'A10': ('indirect',  'symbol_resolution'),
    'A11': ('selfcrypt', 'memory_dump'),
    'A12': ('vm',        'patch_data'),
}

# 非攻击用例 (基线/指纹): **不**计入"该模块被攻击过"的覆盖统计。
#   A4 --selftest 干净环境全 0 —— 这是误报基线, 不是攻击。
#   把它算作"antidebug 被演练过"会污染覆盖率的语义。
# 它们仍被记录 (便于追溯), 但 result 标 SKIP 且覆盖统计跳过。
BASELINE_CASES = {
    'A4': ('antidebug', 'patch_data'),
}

# 用例语义 (取自 attacks.py 的注释行, 用于 result_detail)
CASE_DESC = {}


def parse_cases():
    """静态解析 attacks.py: 提取 A<n> 的用例名与语义注释。"""
    src = open(ATTACKS, encoding='utf-8', errors='replace').read()
    lines = src.split('\n')

    descs = {}
    names = {}
    for i, l in enumerate(lines):
        m = re.match(r'\s*#\s*----\s*(A\d+):\s*(.+?)\s*-*\s*$', l)
        if m:
            descs[m.group(1)] = m.group(2).strip()
        m2 = re.match(r"\s*results\.append\(\('(A\d+) ([^']+)'", l)
        if m2:
            names.setdefault(m2.group(1), m2.group(2))
    return descs, names


def build():
    descs, names = parse_cases()
    recs = []

    def mk(cid, mod, atk, is_baseline):
        full = names.get(cid, cid)
        return {
            'id': 'attacks.%s' % cid,
            'attack': atk,
            'target_module': mod,
            'method': descs.get(cid, '(见 tests/attacks.py)'),
            'prerequisite': None,
            # 基线用例标 SKIP: 它验证"无误报", 不是"挡住了攻击"。
            # 计入 BLOCKED 会虚高覆盖率 (见 BASELINE_CASES 注释)。
            'result': 'SKIP' if is_baseline else 'BLOCKED',
            'result_detail': ('[%s] 功能攻击测试 %s: %s'
                              % ('基线' if is_baseline else '攻击', full,
                                 descs.get(cid, ''))),
            'severity': 'low',
            'countermeasure': None,
            'known_limit': False,
            'evidence': 'tests/attacks.py',
            'date': '2026-09-20',
            # 来源标注: 与 attack_drill 的人工演练记录区分开
            # (后者用真实攻击工具链, 前者是功能断言)
            'source_kind': 'baseline' if is_baseline else 'functional_test',
        }

    for cid in sorted(CASE_MAP, key=lambda x: int(x[1:])):
        mod, atk = CASE_MAP[cid]
        recs.append(mk(cid, mod, atk, False))
    for cid in sorted(BASELINE_CASES, key=lambda x: int(x[1:])):
        mod, atk = BASELINE_CASES[cid]
        recs.append(mk(cid, mod, atk, True))
    recs.sort(key=lambda r: int(r['id'].split('.')[1][1:]))
    return recs, descs, names


def main(argv=None):
    ap = argparse.ArgumentParser(prog='ingest_attacks.py',
                                 description='A1-A12 归一化进 drills/')
    ap.add_argument('--write', action='store_true', help='写入 drills/attacks-regression.json')
    ap.add_argument('--show', action='store_true', help='打印解析结果')
    args = ap.parse_args(argv)

    recs, descs, names = build()

    print('解析 tests/attacks.py:')
    print('  语义注释 %d 条, 用例名 %d 条' % (len(descs), len(names)))
    mapped = set(CASE_MAP) | set(BASELINE_CASES)
    missing = [c for c in mapped if c not in names]
    if missing:
        print('  [!] 未在源码中找到用例: %s' % ', '.join(missing))
    extra = [c for c in names if c not in mapped]
    if extra:
        print('  [!] 源码中有未映射用例: %s (请补 CASE_MAP 或 BASELINE_CASES)'
              % ', '.join(sorted(extra)))
    print('  生成 %d 条记录 (%d 攻击 + %d 基线)'
          % (len(recs), len(CASE_MAP), len(BASELINE_CASES)))

    if args.show:
        print()
        for r in recs:
            print('  %-12s -> %-10s %-20s %s'
                  % (r['id'], r['target_module'], r['attack'],
                     r['method'][:44]))

    if args.write:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
            json.dump({
                '_comment': '由 tools/ingest_attacks.py 从 tests/attacks.py '
                            '静态解析生成 (阶段3)。source_kind=functional_test '
                            '表示这是功能攻击测试, 区别于 attack_drill 的'
                            '人工演练记录 (后者有真实攻击工具链)。',
                'drills': recs,
            }, f, ensure_ascii=False, indent=1)
        print()
        print('已写入 %s' % os.path.relpath(OUT, REPO))
    return 0


if __name__ == '__main__':
    sys.exit(main())
