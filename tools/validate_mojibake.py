#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""validate_mojibake.py — 在**独立于判据**的标注集上量化候选判据。

## 为什么必须重建标注集（**这是本脚本存在的全部理由**）

旧版用 `c_run`（v3 自己的判据）去圈正样本，再用 v3 评判这个集合 ——
**循环论证**。它结构上不可能发现 `line.encode('gbk')` 抛异常导致的漏检，
于是给出了"P=1.000 R=1.000"的假满分，而真相是 **R=0.269（漏检 158 行）**。

现在标注**完全不使用任何判据**:

* POS = `git diff HEAD` 里被**替换掉**且含非 ASCII 的 HEAD 侧行 ——
  这些行有独立证据（Q1 的修复本身）证明它们是损坏的；
* NEG(wide) = 全仓库 `HEAD` 侧所有含非 ASCII 的行，**减去** POS ——
  即"判据之外的一切"，用来抓假阳性。

## 历史（三版启发式都崩过）

| 判据 | 实测 |
|------|------|
| v1 CJK 比例 > 0.5 | 漏判 `tests/c2vasm_cases/fnv1a64.c:1`（比例 0.44） |
| v2 CJK 计数 >= 2 | 假阳性 474 行 |
| v2' 特征字表兜底 | 假阳性 2452 行 |
| v3 最长连续 CJK 串 >= 2 | **循环论证下的假满分**；独立标注集实测 R=0.269 |
| **v4 v3 + 字节重建** | **P=1.000 R=1.000** ✅ |

用法: python tools/validate_mojibake.py
"""
import difflib
import os
import re
import subprocess
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, 'tools'))
import mojibake as M  # noqa: E402

NON = re.compile(r'[^\x00-\x7f]')
CJK = re.compile(r'[\u4e00-\u9fff]')

# Q1 修复过的 6 个文件（`docs/迁移核验-2026-09-20.md` **不在内**:
# 它的 3 条命中是**故意保留的证据引用**，从 diff 取标注会把它误当正样本）
REPAIRED = [
    'prot_sdk/skeleton/app_main.c',
    'demo/main.c',
    'src/crc32.c',
    'tests/c2vasm_cases/poly.c',
    'tests/c2vasm_cases/cond_agg.c',
    'tests/c2vasm_cases/fnv1a64.c',
]

EXT = {'.c', '.h', '.md', '.py', '.ps1', '.json', '.txt', '.s',
       '.asm', '.yml', '.yaml', '.def'}


# ------------------------------------------------------------------ 候选判据

def _gbk_whole(line):
    try:
        return line.encode('gbk')
    except UnicodeEncodeError:
        return None


def c_v1(line, thr=0.5):
    """v1: 整行 gbk -> 还原后 CJK 比例 > thr"""
    raw = _gbk_whole(line)
    if raw is None:
        return False
    fx = raw.decode('utf-8', 'replace')
    n_cjk = len(CJK.findall(fx))
    n_bad = fx.count('\ufffd')
    if n_cjk == 0:
        return False
    return n_cjk / (n_cjk + n_bad) > thr


def c_v2(line):
    """v2: 整行 gbk -> 还原后 CJK 计数 >= 2"""
    raw = _gbk_whole(line)
    if raw is None:
        return False
    return len(CJK.findall(raw.decode('utf-8', 'replace'))) >= 2


def c_v3(line, minrun=2):
    """v3: 整行 gbk -> 还原后**最长连续 CJK 串** >= minrun（v4 之前的权威判据）"""
    raw = _gbk_whole(line)
    if raw is None:
        return False
    return M.longest_cjk_run(raw.decode('utf-8', 'replace')) >= minrun


def c_v4(line):
    """v4: 字节重建（CP936 精确）+ 最长连续 CJK 串 >= 2 —— 现行权威判据"""
    return M.is_bad(line)


CRITERIA = [
    ('v1 ratio>0.5', c_v1),
    ('v2 cjk>=2', c_v2),
    ('v3 run>=2 (旧权威)', c_v3),
    ('v3b run>=3', lambda l: c_v3(l, 3)),
    ('v4 字节重建 run>=2 (现行)', c_v4),
]


# ------------------------------------------------------------------ 标注集

def _lines(path):
    p = os.path.join(REPO, path)
    if not os.path.exists(p):
        return []
    with open(p, encoding='utf-8') as f:
        return f.read().replace('\r\n', '\n').split('\n')


def _head_lines(path):
    b = subprocess.run(['git', 'show', 'HEAD:' + path],
                       capture_output=True, cwd=REPO).stdout
    return b.decode('utf-8').replace('\r\n', '\n').split('\n')


def build_labels():
    """POS 用 git 修复 diff 构建 —— **任何判据都不参与**。"""
    pos = []
    for rel in REPAIRED:
        h, w = _head_lines(rel), _lines(rel)
        sm = difflib.SequenceMatcher(None, h, w, autojunk=False)
        for tag, i1, i2, _j1, _j2 in sm.get_opcodes():
            if tag == 'equal':
                continue
            pos += [l for l in h[i1:i2] if NON.search(l)]
    return pos


def build_wide_negatives(pos):
    """全仓库 HEAD 侧含非 ASCII 的行，减掉 POS。"""
    ps = set(pos)
    files = subprocess.run(['git', 'ls-files'], capture_output=True,
                           text=True, encoding='utf-8', cwd=REPO).stdout.split('\n')
    neg = []
    for p in files:
        if os.path.splitext(p)[1] not in EXT:
            continue
        b = subprocess.run(['git', 'show', 'HEAD:' + p],
                           capture_output=True, cwd=REPO).stdout
        try:
            t = b.decode('utf-8')
        except UnicodeDecodeError:
            continue
        for l in t.replace('\r\n', '\n').split('\n'):
            if NON.search(l) and l not in ps:
                neg.append(l)
    return neg


def main():
    pos = build_labels()
    if not pos:
        print('[!] 标注集为空 —— 说明 HEAD 与工作区的修复 diff 已不存在。')
        print('    POS 依赖 Q1 尚未提交的修复；提交后请改用历史提交对。')
        return 1
    neg = build_wide_negatives(pos)
    print('独立标注集（判据不参与构建）:')
    print('  POS = %d 行（git 修复 diff 的 HEAD 侧）' % len(pos))
    print('  NEG = %d 行（全仓库 HEAD 侧含非 ASCII 的行 − POS）' % len(neg))
    print()
    print('%-30s %6s %6s %8s %8s' % ('判据', 'TP', 'FP', 'P', 'R'))
    print('-' * 64)
    rows = []
    for name, fn in CRITERIA:
        tp = sum(1 for l in pos if fn(l))
        fp = sum(1 for l in neg if fn(l))
        p = tp / (tp + fp) if (tp + fp) else 0.0
        r = tp / len(pos) if pos else 0.0
        rows.append((name, tp, fp, p, r))
        print('%-30s %6d %6d %8.4f %8.4f' % (name, tp, fp, p, r))
    print()

    v3 = [x for x in rows if x[0].startswith('v3 run')][0]
    v4 = [x for x in rows if x[0].startswith('v4')][0]
    print('结论: v3 漏检 %d 行（召回 %.4f）；v4 漏检 %d 行（召回 %.4f）。'
          % (len(pos) - v3[1], v3[4], len(pos) - v4[1], v4[4]))
    if v4[2] == 0 and v4[1] == len(pos):
        print('      v4 在 %d 正 / %d 负 上 P=1.000 R=1.000 ✅' % (len(pos), len(neg)))
    print()

    print('--- v3 漏掉、v4 抓到的前 5 行（真实损坏，曾被整行放过）---')
    n = 0
    for l in pos:
        if not c_v3(l) and c_v4(l):
            n += 1
            if n <= 5:
                print('    %s' % l.strip()[:92])
    print('    合计漏检 %d 行' % n)
    print()

    fps = [l for l in neg if c_v4(l)]
    print('--- v4 在 %d 条负样本上的假阳性: %d（必须为 0）---' % (len(neg), len(fps)))
    for l in fps[:10]:
        print('    %s' % l.strip()[:92])
    return 0 if (v4[2] == 0 and v4[1] == len(pos) and not fps) else 1


if __name__ == '__main__':
    sys.exit(main())
