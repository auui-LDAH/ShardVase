#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/add_license_headers.py — 为源文件补 SPDX 许可证头

背景: AGPL-3.0 第 5 条要求分发时保留许可证声明。完全开源前，
源文件应带机器可读的许可证标识。

采用 **SPDX 标识符**（业界标准，一行即可，工具可解析）:
    SPDX-License-Identifier: AGPL-3.0-or-later

插入位置（保持既有文件头不被破坏）:
  · C 文件: 在首个 /* ... */ 注释块**之前**插入独立注释块
  · Python: 在 shebang 与 coding 行**之后**插入注释行

用法:
    python tools/add_license_headers.py           # dry-run
    python tools/add_license_headers.py --apply
"""

import argparse
import glob
import os
import re
import sys

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
os.chdir(REPO)

SPDX = 'AGPL-3.0-or-later'
COPYRIGHT = 'Copyright (C) 2026 ShardVase contributors'

C_HEADER = (
    '/* SPDX-License-Identifier: %s\n'
    ' * %s\n'
    ' *\n'
    ' * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；\n'
    ' * 商业授权见 LICENSE.md。\n'
    ' */\n'
) % (SPDX, COPYRIGHT)

PY_HEADER = (
    '# SPDX-License-Identifier: %s\n'
    '# %s\n'
    '# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。\n'
) % (SPDX, COPYRIGHT)

# 纳入范围: 会随开源公开的源码
C_FILES = sorted(glob.glob('src/*.c')) + sorted(glob.glob('include/protect/*.h'))
PY_FILES = sorted(glob.glob('tools/*.py')) + sorted(glob.glob('tests/*.py')) \
    + sorted(glob.glob('examples/**/*.py', recursive=True)) \
    + sorted(glob.glob('prot_sdk/**/*.py', recursive=True))


def has_spdx(text):
    return 'SPDX-License-Identifier' in text[:600]


def add_c(path, apply_):
    text = open(path, encoding='utf-8', newline='').read()
    if has_spdx(text):
        return 'skip'
    # 若以 /* 开头（文件头注释），插到其之前；否则插到最前
    if text.lstrip().startswith('/*'):
        # 找第一个 /* 的位置（含前导空白）
        i = text.index('/*')
        new = text[:i] + C_HEADER + text[i:]
    else:
        new = C_HEADER + text
    if apply_:
        with open(path, 'w', encoding='utf-8', newline='') as f:
            f.write(new)
    return 'added'


def add_py(path, apply_):
    text = open(path, encoding='utf-8', newline='').read()
    if has_spdx(text):
        return 'skip'
    lines = text.split('\n')
    i = 0
    # 跳过 shebang 与 coding 声明
    while i < len(lines) and (lines[i].startswith('#!') or
                              re.match(r'^#.*coding[:=]', lines[i])):
        i += 1
    new = '\n'.join(lines[:i] + PY_HEADER.rstrip('\n').split('\n') + lines[i:])
    if apply_:
        with open(path, 'w', encoding='utf-8', newline='') as f:
            f.write(new)
    return 'added'


def main():
    ap = argparse.ArgumentParser(prog='add_license_headers.py',
                                 description='补 SPDX 许可证头')
    ap.add_argument('--apply', action='store_true', help='实际写入')
    args = ap.parse_args()

    print('=== SPDX 许可证头%s ===' % ('（APPLY）' if args.apply else '（dry-run）'))
    print()
    stats = {'added': [], 'skip': []}
    for f in C_FILES:
        r = add_c(f, args.apply)
        stats[r].append(f)
    for f in PY_FILES:
        r = add_py(f, args.apply)
        stats[r].append(f)

    print('--- 需添加 (%d) ---' % len(stats['added']))
    for f in stats['added']:
        print('  %s' % f)
    print()
    print('--- 已有 SPDX (%d) ---' % len(stats['skip']))
    for f in stats['skip']:
        print('  %s' % f)
    print()
    print('合计: %d 个文件, 需添加 %d'
          % (len(C_FILES) + len(PY_FILES), len(stats['added'])))
    if not args.apply:
        print()
        print('(dry-run —— 加 --apply 执行)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
