#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
tools/update_sha_refs.py — 历史重写后更新文档中的 commit SHA 引用

背景 (docs/HISTORY_REWRITE_PLAN.md): `git filter-repo` 会重写受影响提交的
SHA。文档里用 `f0aa393` 这类形式引用提交, 重写后会失效 (GitHub 上 404)。

实测: 本仓库 docs 中 26 处引用, 重写后 23 处会失效、3 处天然保留。

本工具读 filter-repo 生成的 `.git/filter-repo/commit-map` (old -> new),
批量替换文档中的短 SHA 引用。

用法:
    python tools/update_sha_refs.py --map .git/filter-repo/commit-map
    python tools/update_sha_refs.py --map <path> --apply
"""

import argparse
import glob
import os
import re
import sys

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

# 扫描范围: 会随开源公开的文档
GLOBS = ['docs/*.md', '*.md', 'prot_sdk/*.md', 'prot_sdk/**/*.md',
         'publish/*.md', 'docs/**/*.md']


def load_map(path):
    """读 commit-map -> {old_full: new_full}"""
    m = {}
    with open(path, encoding='utf-8') as f:
        for line in f:
            parts = line.split()
            if len(parts) == 2 and parts[0] != 'old':
                m[parts[0]] = parts[1]
    return m


def git_current_shas():
    """用短 SHA -> 完整 SHA 的映射 (当前仓库)。"""
    import subprocess
    out = subprocess.run(['git', '-C', REPO, 'log', '--all',
                          '--format=%H'], capture_output=True)
    full = [l.strip() for l in out.stdout.decode().split('\n') if l.strip()]
    short = {}
    for h in full:
        for n in range(7, min(len(h), 40) + 1):
            short.setdefault(h[:n], h)
    return short, set(full)


def main(argv=None):
    ap = argparse.ArgumentParser(prog='update_sha_refs.py',
                                 description='历史重写后更新文档 SHA 引用')
    ap.add_argument('--map', required=True, help='filter-repo 的 commit-map 路径')
    ap.add_argument('--apply', action='store_true', help='实际写入 (默认 dry-run)')
    args = ap.parse_args(argv)

    if not os.path.isfile(args.map):
        print('找不到 commit-map: %s' % args.map)
        return 2
    mapping = load_map(args.map)
    print('commit-map 条目: %d' % len(mapping))
    changed = sum(1 for o, n in mapping.items() if o != n)
    print('  其中 SHA 变化: %d' % changed)

    # 收集文档、找 SHA 引用
    files = set()
    for pat in GLOBS:
        for f in glob.glob(os.path.join(REPO, pat), recursive=True):
            files.add(f)
    files = sorted(files)

    pat = re.compile(r'`([0-9a-f]{7,40})`')
    plan = {}          # file -> [(old_short, new_short, count)]
    # 需要知道 old_short 是否**确实是**一个提交: 用 mapping 的 key 前缀匹配
    old_prefix = {}
    for o in mapping:
        for n in range(7, 13):
            old_prefix.setdefault(o[:n], o)

    total = 0
    for f in files:
        try:
            text = open(f, encoding='utf-8').read()
        except OSError:
            continue
        hits = []
        for m in pat.finditer(text):
            s = m.group(1)
            if len(s) < 7 or len(s) > 40:
                continue
            full_old = old_prefix.get(s)
            if not full_old:
                continue                      # 不是提交 SHA (可能是 hash/常量)
            full_new = mapping.get(full_old, full_old)
            if full_new == full_old:
                continue                      # SHA 未变
            new_short = full_new[:len(s)]
            hits.append((s, new_short))
        if hits:
            plan[os.path.relpath(f, REPO)] = hits
            total += len(hits)

    print()
    print('=== 待更新引用 ===')
    for f, hits in sorted(plan.items()):
        print('  %s (%d 处)' % (f, len(hits)))
        for old, new in hits:
            print('      %s -> %s' % (old, new))
    print()
    print('合计: %d 处, 涉及 %d 个文件' % (total, len(plan)))

    if not args.apply:
        print()
        print('(dry-run —— 加 --apply 执行)')
        return 0

    n_files = 0
    for rel, hits in plan.items():
        p = os.path.join(REPO, rel)
        text = open(p, encoding='utf-8', newline='').read()
        for old, new in hits:
            text = text.replace('`%s`' % old, '`%s`' % new)
        with open(p, 'w', encoding='utf-8', newline='') as fh:
            fh.write(text)
        n_files += 1
    print()
    print('已更新 %d 个文件' % n_files)
    return 0


if __name__ == '__main__':
    sys.exit(main())
