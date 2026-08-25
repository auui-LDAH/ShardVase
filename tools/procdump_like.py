#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/procdump_like.py — 内存全转储 (ATTACK_DRILL4 F1-4)

Procdump 风格: 枚举进程虚拟地址空间, ReadProcessMemory 全映射导出到文件。
离线分析可提取: 引擎明文 (D2a)、demo_mem 现场、IAT 快照等。

用法:
    python tools/procdump_like.py --pid <pid> --out build\\dump.bin
"""

import argparse
import ctypes
import os
import sys


def dump_process(pid, out_path):
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.ReadProcessMemory.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
    k32.ReadProcessMemory.restype = ctypes.c_int
    k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_void_p, ctypes.c_size_t]
    k32.VirtualQueryEx.restype = ctypes.c_size_t

    class MBI(ctypes.Structure):
        _fields_ = [('BaseAddress', ctypes.c_void_p),
                    ('AllocationBase', ctypes.c_void_p),
                    ('AllocationProtect', ctypes.c_uint32),
                    ('PartitionId', ctypes.c_uint16),
                    ('RegionSize', ctypes.c_size_t),
                    ('State', ctypes.c_uint32),
                    ('Protect', ctypes.c_uint32),
                    ('Type', ctypes.c_uint32)]

    h = k32.OpenProcess(0x1F0FFF, 0, pid)
    if not ctypes.c_void_p(h).value:
        print('OpenProcess failed (err=%d)' % ctypes.get_last_error())
        return 1

    addr = 0
    regions = []
    total = 0
    while True:
        mbi = MBI()
        n = k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                               ctypes.sizeof(MBI))
        if n == 0:
            break
        baddr = mbi.BaseAddress or 0
        if mbi.State == 0x1000:  # MEM_COMMIT
            size = mbi.RegionSize
            buf = ctypes.create_string_buffer(size or 1)
            read = ctypes.c_size_t(0)
            ok = k32.ReadProcessMemory(h, ctypes.c_void_p(baddr), buf, size,
                                       ctypes.byref(read))
            if ok and read.value > 0:
                regions.append((baddr, buf.raw[:read.value]))
                total += read.value
        nxt = (baddr + mbi.RegionSize) if mbi.RegionSize else addr + 0x1000
        if nxt <= addr:
            break
        addr = nxt
        if addr > 0x7FFFFFFFFFFF:
            break

    k32.CloseHandle(h)
    # 写 dump: 简单格式 [regions: addr,size,data...]
    with open(out_path, 'wb') as f:
        for base, data in regions:
            f.write(('%x:%d:' % (base or 0, len(data))).encode('ascii'))
            f.write(data)
    print('dumped %d regions, %d bytes -> %s' % (len(regions), total, out_path))
    return 0


def main():
    parser = argparse.ArgumentParser(description='memory dump like procdump (F1)')
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    return dump_process(args.pid, args.out)


if __name__ == '__main__':
    sys.exit(main())