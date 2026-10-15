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

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


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

# 纳入范围: 会随开源公开的源码。
#
# ## 2026-10-15 扩展为递归 glob（原为两级定层 glob）
#
# 原 glob（`src/*.c` + `include/protect/*.h`，py 侧单层 tools/ tests/）
# **盖不住子目录**: 实测 36 个 .c/.h 缺 SPDX，全部在 glob 之外
# （tools/attacker/winpe_sympatcher 6 个、tests/c2vasm_cases 6 个、
#   prot_sdk/skeleton 4 个、examples/cross_platform/android 3 个 …）
# —— 与 OSS_TAIL_PLAN ④ 记的「glob 缺口」是同一件事。
#
# 排除项（与 spdx_check.py 门禁共用同一套 glob，见其文件头）:
#   · demo/gen/  —— 生成物（生成头注明「请勿手工编辑」），由生成器自管
#   · archive/ dist/ build/ —— 不随开源分发
_EXCLUDE_PARTS = ('demo/gen', 'archive', 'dist', 'build', 'build_artifacts')


def _in_scope(path):
    p = path.replace('\\', '/')
    return not any(p.startswith('%s/' % x) or ('/%s/' % x) in p
                   for x in _EXCLUDE_PARTS)


def _glob(*patterns):
    out = []
    for pat in patterns:
        out += glob.glob(pat, recursive=True)
    return sorted({f for f in out if _in_scope(f)})


C_FILES = _glob('src/**/*.c', 'include/**/*.h', 'tests/**/*.c',
                'tools/**/*.c', 'tools/**/*.h',
                'examples/**/*.c', 'examples/**/*.h',
                'prot_sdk/**/*.c', 'prot_sdk/**/*.h',
                'sdk_service/**/*.c', 'demo/*.c', 'demo/*.h')
PY_FILES = _glob('tools/**/*.py', 'tests/**/*.py', 'examples/**/*.py',
                 'prot_sdk/**/*.py', 'sdk_service/**/*.py')


def has_spdx(text):
    return 'SPDX-License-Identifier' in text[:600]


def read_src(path):
    """读源文件, 返回 (文本, 是否有 BOM)。

    **必须保留 BOM**: 实测 38 个 Python 文件中有 1 个带 BOM。
    用 encoding='utf-8' 读取会自动吞掉 BOM, 写回时也丢失 ——
    对 .ps1 会破坏 PowerShell 5.1 解析（本项目踩过多次），
    对 .py 虽不影响执行, 但属无谓改动, 应保留原状。
    """
    raw = open(path, 'rb').read()
    bom = raw[:3] == b'\xef\xbb\xbf'
    return raw.decode('utf-8-sig'), bom


def write_src(path, text, bom):
    """写源文件, 按原状保留/不保留 BOM。"""
    data = text.encode('utf-8')
    if bom:
        data = b'\xef\xbb\xbf' + data
    with open(path, 'wb') as f:
        f.write(data)


def add_c(path, apply_):
    text, bom = read_src(path)
    if has_spdx(text):
        return 'skip'
    # 若首行是 #pragma（如 src/crc32.c 的 code_seg），插到它**之后** ——
    # 保守做法: 编译指示保持在文件最前, 不依赖"注释不影响 pragma"的假设。
    lines = text.split('\n')
    ins = 0
    for i, l in enumerate(lines[:5]):
        if l.lstrip().startswith('#'):
            ins = i + 1
        else:
            break
    if ins:
        new = '\n'.join(lines[:ins] + C_HEADER.rstrip('\n').split('\n') + lines[ins:])
    elif text.lstrip().startswith('/*'):
        i = text.index('/*')
        new = text[:i] + C_HEADER + text[i:]
    else:
        new = C_HEADER + text
    if apply_:
        write_src(path, new, bom)
    return 'added'


def add_py(path, apply_):
    text, bom = read_src(path)
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
        write_src(path, new, bom)
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
