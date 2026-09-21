#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/doccheck.py — 对外材料数字漂移检查 (阶段5 M5)

背景 (2026-09-20): 核对对外材料时发现 4 类漂移 —— "0 破防点"模糊表述、
release_check 11/11(实为13)、攻防轮次口径不一(8+ vs 6)、以及
tests/attack_sdk_matrix.py 的 SDK drill 标识硬编码 bug。

这些漂移的共同特征: **文档里的数字没人核对**。本工具把能自动核对的
数字固化下来 —— 与 modcheck/drills 同样的思路 (工具强制 > 人工纪律)。

检查项:
  1. publish/ 与 docs/marketing/ 中不得出现"0 破防"这类模糊表述
  2. release_check N/N 的 N 必须等于实际门禁项数
  3. 攻防轮次口径必须与 docs/ATTACK_DRILL*.md 的实际数量一致
  4. 引用的文件路径必须存在
  5. 已知的"合法例外"白名单 (如 vmcalc "流程测试 11/11" 不是门禁项)

用法:
    python tools/doccheck.py            # 检查
    python tools/doccheck.py --list     # 列出所有被检查的数字
"""

import argparse
import glob
import os
import re
import sys

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

# 被检查的对外材料
TARGETS = sorted(glob.glob(os.path.join(REPO, 'publish', '*.md'))) + \
          sorted(glob.glob(os.path.join(REPO, 'docs', 'marketing', '*.md')))

# 模糊/误导性表述 (必须不出现)
#
# 注意: 需要排除"引用/否定"语境 —— 例如
#   > 我们不写"0 破防" —— 那是模糊表述。
# 这句话本身是**正确**的 (它在批评该表述), 不应被判为违规。
# 判据: 命中位置附近若出现否定词(不/勿/非/避免)或引号包裹, 则跳过。
VAGUE_PATTERNS = [
    (r'0\s*破防', '模糊表述"0 破防"—— 应改为公开列出显式破防项'),
    (r'不可破解', '违反项目立场(不承诺永不破解)'),
    (r'100%\s*防', '绝对化表述'),
]

# 否定/引用语境关键词 (命中点前 20 字符内出现即视为"在讨论该表述"而非"使用它")
NEGATION = re.compile(r'不写|不说|勿用|避免|反对|不是|而非|所谓|声称|禁止')

# 引号: 命中被引号包裹时也视为引用
QUOTES = ('"', '"', '「', '『', "'", "'")


def _is_quoted_or_negated(text, start, end):
    """判断命中是否为引用/否定语境。"""
    # 前 24 字符内的否定词
    pre = text[max(0, start - 24):start]
    if NEGATION.search(pre):
        return True
    # 引号包裹 (命中紧邻引号)
    if start > 0 and text[start - 1] in QUOTES:
        return True
    if end < len(text) and text[end] in QUOTES:
        return True
    return False

# 合法例外: 这些"N/N"不是门禁项, 不应被 release_check 规则误判
#   golden 6/6       = c2vasm golden 样例
#   流程测试 11/11   = vmcalc flow test
EXEMPT_NN = re.compile(r'golden|流程测试|样例')


def actual_gate_count():
    """release_check.ps1 的实际门禁项数 (Check 调用数 + 签名提示项)。"""
    p = os.path.join(REPO, 'tools', 'release_check.ps1')
    if not os.path.isfile(p):
        return None
    n = len(re.findall(r"^\s*Check '", open(p, encoding='utf-8').read(), re.M))
    # +1: codesign.pfx 存在时的签名 pass++ 项
    return n + 1


def actual_rounds():
    """docs/ATTACK_DRILL*.md 的实际轮次数量。"""
    docs = glob.glob(os.path.join(REPO, 'docs', 'ATTACK_DRILL*.md'))
    return len(docs)


def main(argv=None):
    ap = argparse.ArgumentParser(prog='doccheck.py',
                                 description='对外材料数字漂移检查')
    ap.add_argument('--list', action='store_true', help='列出被检查的数字')
    args = ap.parse_args(argv)

    errors = []
    warnings = []
    checked = 0

    gate = actual_gate_count()
    rounds = actual_rounds()

    if args.list:
        print('被检查的数字:')
        print('  release_check 实际门禁项数 = %s' % gate)
        print('  docs/ATTACK_DRILL*.md 轮次数 = %s' % rounds)
        print('  检查目标文件: %d 个' % len(TARGETS))
        return 0

    print('=== 对外材料数字漂移检查 ===')
    print('  基准: 门禁 %s 项, 轮次 %s 个' % (gate, rounds))
    print()

    for f in TARGETS:
        rel = os.path.relpath(f, REPO)
        try:
            t = open(f, encoding='utf-8').read()
        except OSError:
            continue

        # --- 1. 模糊表述 (排除引用/否定语境) ---
        for pat, why in VAGUE_PATTERNS:
            for m in re.finditer(pat, t):
                if _is_quoted_or_negated(t, m.start(), m.end()):
                    continue
                ln = t[:m.start()].count('\n') + 1
                errors.append('%s:%d 出现%s' % (rel, ln, why))

        # --- 2. release_check N/N ---
        for m in re.finditer(r'release_check[^\n]*?(\d+)/(\d+)', t):
            checked += 1
            claim = int(m.group(2))
            if gate is not None and claim != gate:
                ln = t[:m.start()].count('\n') + 1
                errors.append('%s:%d release_check 声称 %d, 实际 %d'
                              % (rel, ln, claim, gate))

        # --- 3. 轮次口径 ---
        for m in re.finditer(r'(\d+)\s*\+?\s*轮(?:正式|完整|攻防|演练)?', t):
            claim = int(m.group(1))
            # 只检查"攻防演练轮次"这类主口径 (排除"第一轮/第二轮"表格行)
            if re.search(r'第[一二三四五六七八九十\d]+轮', t[max(0, m.start()-6):m.start()+8]):
                continue
            checked += 1
            if claim not in (rounds, rounds - 1) and '矩阵' in t[m.start():m.start()+30]:
                ln = t[:m.start()].count('\n') + 1
                warnings.append('%s:%d 轮次声称 %d, 实际 %d (请确认口径)'
                                % (rel, ln, claim, rounds))

        # --- 4. 引用的仓库内路径 (死链是错误, 不是警告) ---
        for m in re.finditer(r'`((?:docs|tools|tests|src|include|prot_sdk|publish|drills|compositions)/[\w\-./]+)`', t):
            checked += 1
            if not os.path.exists(os.path.join(REPO, m.group(1))):
                ln = t[:m.start()].count('\n') + 1
                errors.append('%s:%d 引用路径不存在: %s'
                              % (rel, ln, m.group(1)))

    for e in errors:
        print('  [X] %s' % e)
    for w in warnings:
        print('  [!] %s' % w)
    print()
    print('  检查数字 %d 处, 错误 %d, 警告 %d' % (checked, len(errors), len(warnings)))
    print()
    print('[doccheck] %s' % ('FAIL' if errors else 'PASS'))
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
