# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""BOM 修复/校验工具（Q1 期间固化）。

本项目对 BOM 极敏感（HANDOVER.md 教训 ⑦⑧）:
  · `edit` 工具**会剥掉** BOM        -> 目标文件变成 UTF-8 无 BOM
  · PowerShell `Set-Content -Encoding UTF8` **会加上** BOM
两个方向都出过事。`tools/release_check.ps1` 必须**带 BOM**（否则
PowerShell 5.1 按 ANSI 读 -> 中文全被当字节 -> AST 一堆假错误）。

用法:
  python tools/bom.py check <path>...      # 报告 BOM 状态（只读）
  python tools/bom.py add   <path>...      # 补 BOM（幂等）
  python tools/bom.py strip <path>...      # 去 BOM（幂等）
"""
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


BOM = b'\xef\xbb\xbf'


def read(path):
    with open(path, 'rb') as f:
        return f.read()


def state(path):
    b = read(path)
    return b.startswith(BOM)


def write(path, data):
    with open(path, 'wb') as f:
        f.write(data)


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 2
    cmd = argv[1]
    rc = 0
    for p in argv[2:]:
        b = read(p)
        has = b.startswith(BOM)
        if cmd == 'check':
            print('%-46s BOM=%s  bytes=%d' % (p, has, len(b)))
        elif cmd == 'add':
            if has:
                print('%-46s 已有 BOM（未改）' % p)
            else:
                write(p, BOM + b)
                print('%-46s +BOM' % p)
        elif cmd == 'strip':
            if not has:
                print('%-46s 无 BOM（未改）' % p)
            else:
                write(p, b[len(BOM):])
                print('%-46s -BOM' % p)
        else:
            print('未知命令: %s' % cmd)
            return 2
    return rc


if __name__ == '__main__':
    sys.exit(main(sys.argv))
