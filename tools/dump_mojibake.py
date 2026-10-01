#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""dump_mojibake.py — Q1 判读辅助：把每个受污染文件的坏行逐条 dump 出来。

**判据只有一处**: `tools/mojibake.py`（v4 字节重建，P=1.000 R=1.000）。
本脚本**只读**，不修改任何文件。

> 历史: 本脚本曾自带一份**与 mojibake.py 不同**的 v1 判据
> （`CJK/(CJK+UFFFD) > 0.5`），实测召回只有 0.26 —— 这正是"判据分叉"的坑，
> 现已统一到唯一权威实现。

用法:
    python tools/dump_mojibake.py                  # 扫全部 Q1 目标文件
    python tools/dump_mojibake.py --file PATH      # 只扫一个
    python tools/dump_mojibake.py --plan           # 只出汇总
    python tools/dump_mojibake.py --all            # 扫整个仓库（含豁免清单）
"""
import argparse
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, 'tools'))
import mojibake as M  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# Q1 实修目标（`docs/迁移核验-2026-09-20.md` 的 3 行是**证据引用**，故意保留）
TARGETS = [
    'prot_sdk/skeleton/app_main.c',
    'demo/main.c',
    'src/crc32.c',
    'tests/c2vasm_cases/poly.c',
    'tests/c2vasm_cases/cond_agg.c',
    'tests/c2vasm_cases/fnv1a64.c',
]

# 全库扫描时**必须永远判为干净**的路径（豁免）:
#   docs/迁移核验-2026-09-20.md — 修复前后对照的证据引用
#   docs/CONTINUATION_PLAN.md   — 计划文档 §2.3 的示意还原文本
EXEMPT = {
    'docs/迁移核验-2026-09-20.md',
    'docs/CONTINUATION_PLAN.md',
}

EXT = {'.c', '.h', '.md', '.py', '.ps1', '.json', '.txt', '.s',
       '.asm', '.yml', '.yaml', '.def'}
EXD = {'.git', 'dist', 'archive', 'build', 'node_modules', '.vs', '.vscode'}


def scan_file(path, verbose=True):
    """返回 [(行号, 原文, 还原文本, 有损?)]。"""
    with open(path, encoding='utf-8') as f:
        text = f.read()
    out = []
    for i, l in enumerate(text.replace('\r\n', '\n').split('\n'), 1):
        if not M.is_bad(l):
            continue
        fx = M.restored_text(l)
        out.append((i, l, fx, '\ufffd' in fx))
    if verbose:
        for i, raw, fx, lossy in out:
            print('  [%s] L%-5d 原: %s' % ('有损' if lossy else '无损', i, raw))
            print('        还: %s' % fx)
            print()
    return out


def walk_repo():
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in EXD]
        for f in files:
            if os.path.splitext(f)[1].lower() not in EXT:
                continue
            yield os.path.relpath(os.path.join(root, f), REPO).replace('\\', '/')


def main():
    ap = argparse.ArgumentParser(prog='dump_mojibake.py')
    ap.add_argument('--file', help='只扫这一个文件（相对 REPO）')
    ap.add_argument('--plan', action='store_true', help='只输出汇总表')
    ap.add_argument('--all', action='store_true', help='扫整个仓库')
    a = ap.parse_args()

    grand = [0, 0, 0]
    rows = []

    if a.file:
        targets = [a.file]
    elif a.all:
        targets = sorted(walk_repo())
    else:
        targets = TARGETS

    for rel in targets:
        p = os.path.join(REPO, rel)
        if not os.path.exists(p):
            if not a.all:
                print('[skip] %s 不存在' % rel)
            continue
        exempt = rel in EXEMPT
        if not a.plan:
            print('=' * 78)
            print('## %s%s' % (rel, '   [豁免: 证据引用/示意文本]' if exempt else ''))
            print('=' * 78)
        items = scan_file(p, verbose=not a.plan)
        n = len(items)
        los = sum(1 for it in items if not it[3])
        loy = n - los
        if n or not a.all:
            rows.append((rel, n, los, loy, exempt))
        if not exempt:
            grand[0] += n
            grand[1] += los
            grand[2] += loy
        if n and (a.plan or a.all):
            print('  %-52s 坏行 %3d（无损 %d / 有损 %d）%s'
                  % (rel, n, los, loy, '  [豁免]' if exempt else ''))

    if a.all:
        print('=' * 78)
        for rel, n, los, loy, exempt in rows:
            print('  %-52s %3d %s' % (rel, n, '[豁免]' if exempt else ''))
    print('=' * 78)
    print('合计（不含豁免）: 坏行 %d（无损 %d / 有损 %d）' % tuple(grand))
    return 0


if __name__ == '__main__':
    sys.exit(main())
