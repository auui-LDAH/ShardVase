#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
tools/osinfo.py — Windows 版本信息工具 (COMPAT §6, I4 兼容骨架)

输出 osver/build/arch/edition, 供兼容矩阵 (compat-matrix.csv) 记录与
回归脚本使用。只依赖 stdlib (platform/ctypes), 不需要第三方包。

CLI:
    python tools/osinfo.py            # 全部字段 (一行 key=value)
    python tools/osinfo.py --json     # JSON 输出
"""

import ctypes
import json
import platform
import struct
import sys

M64 = (1 << 64) - 1


def rtl_get_version():
    """调用 ntdll RtlGetVersion (runs on Win10+, 返回真实 OS 版本而非
    兼容层报告的版本)。失败返回 None (回退 platform 值)。"""
    try:
        ntdll = ctypes.WinDLL('ntdll', use_last_error=False)

        class OSVERSIONINFOEXW(ctypes.Structure):
            _fields_ = [
                ('dwOSVersionInfoSize', ctypes.c_ulong),
                ('dwMajorVersion', ctypes.c_ulong),
                ('dwMinorVersion', ctypes.c_ulong),
                ('dwBuildNumber', ctypes.c_ulong),
                ('dwPlatformId', ctypes.c_ulong),
                ('szCSDVersion', ctypes.c_wchar * 128),
                ('wServicePackMajor', ctypes.c_ushort),
                ('wServicePackMinor', ctypes.c_ushort),
                ('wSuiteMask', ctypes.c_ushort),
                ('wProductType', ctypes.c_byte),
                ('wReserved', ctypes.c_byte),
            ]

        v = OSVERSIONINFOEXW()
        v.dwOSVersionInfoSize = ctypes.sizeof(OSVERSIONINFOEXW)
        rtl = ntdll.RtlGetVersion
        rtl.argtypes = [ctypes.POINTER(OSVERSIONINFOEXW)]
        rtl.restype = ctypes.c_long
        if rtl(ctypes.byref(v)) == 0:
            return v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber
    except Exception:
        pass
    return None


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Windows version info (I4)')
    parser.add_argument('--json', action='store_true', help='JSON output')
    args = parser.parse_args()

    rv = rtl_get_version()
    if rv is not None:
        major, minor, build = rv
    else:
        major = sys.getwindowsversion().major
        minor = sys.getwindowsversion().minor
        build = sys.getwindowsversion().build

    arch = platform.machine()
    # 识别 WOW64 (32 位进程跑在 64 位系统)
    is_wow64 = False
    try:
        import ctypes
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=False)
        p = ctypes.c_void_p()
        if kernel32.IsWow64Process(kernel32.GetCurrentProcess(), ctypes.byref(p)):
            is_wow64 = bool(p.value)
    except Exception:
        pass

    osname = 'Windows 11' if (major == 10 and build >= 22000) else \
             ('Windows 10' if major == 10 else 'Windows %d.%d' % (major, minor))

    info = {
        'osver': '%d.%d.%d' % (major, minor, build),
        'build': build,
        'arch': 'x64' if (arch == 'AMD64' and not is_wow64) else 'x86',
        'edition': osname,
        'python': sys.version.split()[0],
    }

    if args.json:
        print(json.dumps(info, ensure_ascii=False))
    else:
        for k, v in info.items():
            print('%s=%s' % (k, v))
    return 0


if __name__ == '__main__':
    sys.exit(main())
