#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""校验 .NET 接入门 DLL 的导出表（不依赖 dumpbin，纯标准库解析 PE）。

## 为什么需要这个检查（实测教训 2026-09-21）
`.def` 文件被 MSVC 按 **ANSI/GBK** 读取。若在 `.def` 里写 UTF-8 中文注释，
链接器会**静默丢掉紧随其后的导出符号** —— 产物是个"看起来正常但少了导出"
的坏 DLL，直到运行期 C# 报 `EntryPointNotFound` 才暴露。

实测现象: .def 含中文注释后，DLL 只导出 2/3（`prot_gate_version` 消失）。
故必须主动校验，缺失即**失败**（而不是产出一个坏 DLL）。

用法: python tools/dotnet_gate_exports.py <dll 路径>
退出码: 0 = 全部导出就位; 1 = 缺失或解析失败
"""
import os
import struct
import sys

# 输出编码: 被 PowerShell 调用时 stdout 默认是 GBK, 打印 '✓' 等字符会
# UnicodeEncodeError -> 校验器自身崩溃并返回非 0 -> 被误判为"导出缺失"
# （实测 2026-09-21）。故显式重配为 UTF-8, 不依赖调用方传 -X utf8。
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

REQUIRED = ['prot_gate_version', 'prot_gate_init', 'prot_gate_check']


def pe_exports(path):
    """解析 PE 导出表，返回导出名列表。纯标准库实现。"""
    d = open(path, 'rb').read()
    if len(d) < 0x40:
        raise ValueError('文件过小，不是有效 PE')
    e = struct.unpack_from('<I', d, 0x3C)[0]
    if d[e:e + 4] != b'PE\0\0':
        raise ValueError('缺少 PE 签名')
    nsec = struct.unpack_from('<H', d, e + 6)[0]
    optsz = struct.unpack_from('<H', d, e + 20)[0]
    magic = struct.unpack_from('<H', d, e + 24)[0]
    # PE32+ 的数据目录偏移 112，PE32 为 96
    dd = e + 24 + (112 if magic == 0x20B else 96)
    exp_rva, _ = struct.unpack_from('<II', d, dd)
    if exp_rva == 0:
        return []

    tbl = e + 24 + optsz
    secs = []
    for i in range(nsec):
        o = tbl + i * 40
        vsz, va, rsz, raw = struct.unpack_from('<IIII', d, o + 8)
        secs.append((va, vsz, raw, rsz))

    def r2o(rva):
        for va, vsz, raw, rsz in secs:
            if va <= rva < va + max(vsz, rsz):
                return raw + (rva - va)
        return None

    o = r2o(exp_rva)
    if o is None:
        return []
    nnames = struct.unpack_from('<I', d, o + 24)[0]
    names_rva = struct.unpack_from('<I', d, o + 32)[0]
    no = r2o(names_rva)
    if no is None:
        return []

    out = []
    for i in range(nnames):
        nr = struct.unpack_from('<I', d, no + i * 4)[0]
        so = r2o(nr)
        if so is None:
            continue
        end = d.index(b'\x00', so)
        out.append(d[so:end].decode('ascii', 'replace'))
    return out


def main():
    if len(sys.argv) < 2:
        print('用法: python tools/dotnet_gate_exports.py <dll>')
        return 1
    path = sys.argv[1]
    if not os.path.exists(path):
        print('[X] DLL 不存在: %s' % path)
        return 1

    try:
        names = pe_exports(path)
    except Exception as ex:
        print('[X] 解析 PE 失败: %s' % ex)
        return 1

    print('  导出符号: %d 个' % len(names))
    for n in names:
        print('    %s' % n)

    missing = [r for r in REQUIRED if r not in names]
    if missing:
        print()
        print('[X] 缺失导出: %s' % ', '.join(missing))
        print('    最常见原因: .def 含非 ASCII 字符（MSVC 按 ANSI/GBK 读取,')
        print('    UTF-8 注释会破坏后续行解析, 导致导出被静默丢弃）。')
        print('    修法: 让 .def 保持纯 ASCII。')
        return 1

    print()
    print('  ✓ 全部 %d 个必需导出就位' % len(REQUIRED))
    return 0


if __name__ == '__main__':
    sys.exit(main())
