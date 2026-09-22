#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
tools/hashpatch.py — PE 段 CRC32 烧录工具  (Lane C, A3 扩展)

Locates the dedicated `.protcrc` section (3 baked-crc markers) inside a PE
file and writes the CRC32 of the .text/.rdata/.pdata sections (raw data,
min(VirtualSize, SizeOfRawData) convention) into the corresponding 4-byte
fields. If a non-zero CRC is already present, it is verified instead of
overwritten.

Marker layout (CONTRACT §3 / §7.1): each entry is 16 bytes:
    magic[8] | crc u32 LE | reserved u32 LE
    index 0: .text  "PROTCRCP"   index 1: .rdata "PROTCRCD"
    index 2: .pdata "PROTCRDP"
(marker order/index must match src/integrity.c g_prot_baked_crc exactly.)

ASLR 重定位掩码 (A3): 基址重定位 (type 10 = DIR64 / type 3 = HIGHLOW) 字段在
加载时会被改写, 使 .rdata 运行期内存与文件字节不一致。因此文件侧与运行侧
(src/integrity.c build_reloc_mask) 用**同一规则**把这类字段归零后再算 CRC:
两遍计算的都是"未被重定位改写的字节", 保证一致。

CLI:
    python tools/hashpatch.py build\\demo.exe
"""

import struct
import sys
import zlib

# 与 src/integrity.c g_prot_baked_crc 顺序一致
MAGICS = (b'PROTCRCP', b'PROTCRCD', b'PROTCRDP')
TARGET_NAMES = ('.text', '.rdata', '.pdata')
ENTRY_SIZE = 16


class HashpatchError(Exception):
    pass


# N1 (D1b): selfcrypt 加密段掩码列表 [(rva, len), ...] —— 由
# tools/selfcrypt_proto.py 的 MASK 输出生成 (--mask "rva,len" 可重复)。
EXCLUDE_MASKS = []


def add_exclude_mask(rva, length):
    EXCLUDE_MASKS.append((rva, length))


def pe_sections(data):
    """Parse the PE section table; return list of dicts (raw file side)."""
    if len(data) < 0x40:
        raise HashpatchError('not a PE file (too small)')

    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if e_lfanew + 24 > len(data):
        raise HashpatchError('bad PE header: e_lfanew=%d out of range' % e_lfanew)
    if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        raise HashpatchError('not a PE file (bad NT signature)')

    num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    size_opt = struct.unpack_from('<H', data, e_lfanew + 20)[0]
    sec_table = e_lfanew + 24 + size_opt

    secs = []
    for i in range(num_sections):
        off = sec_table + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].rstrip(b'\x00').decode('ascii', 'replace')
        secs.append({
            'name': name,
            'virtual_size': struct.unpack_from('<I', data, off + 8)[0],
            'virtual_addr': struct.unpack_from('<I', data, off + 12)[0],
            'size_raw': struct.unpack_from('<I', data, off + 16)[0],
            'ptr_raw': struct.unpack_from('<I', data, off + 20)[0],
        })
    return secs


def pe_data_dirs(data, e_lfanew, size_opt):
    """PE32+/PE32 data directory entries: list of (rva, size)."""
    opt = e_lfanew + 24
    return [struct.unpack_from('<II', data, opt + 112 + i * 8) if
            opt + 112 + i * 8 + 8 <= len(data) else (0, 0) for i in range(16)]


def reloc_mask_bytes(data, secs, sec):
    """
    Return bytearray mask: 目标段 [virtual_addr, +crc_len) 内会被加载器/重定位
    改写的字节置 0xFF, 其余 0。规则与 src/integrity.c build_reloc_mask 一致:
      1. 基址重定位字段: type 10 = DIR64 8B / type 3 = HIGHLOW 4B
      2. IAT 目录项 (dir[12]): loader 启动时写入已解析的导入函数地址
    """
    crc_len = min(sec['virtual_size'], sec['size_raw'])
    mask = bytearray(crc_len)

    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    dirs = pe_data_dirs(data, e_lfanew, 0)
    iat_rva, iat_size = dirs[12]
    if iat_rva and iat_size and sec['virtual_addr'] <= iat_rva and \
            iat_rva + iat_size <= sec['virtual_addr'] + crc_len:
        o = iat_rva - sec['virtual_addr']
        mask[o:o + iat_size] = b'\xff' * iat_size

    rel = next((s for s in secs if s['name'] == '.reloc'), None)
    if rel is None:
        return mask

    pos = rel['ptr_raw']
    end = rel['ptr_raw'] + rel['size_raw']
    while pos + 8 <= end:
        page_rva = struct.unpack_from('<I', data, pos)[0]
        block_size = struct.unpack_from('<I', data, pos + 4)[0]
        if block_size < 8 or pos + block_size > end:
            break
        cnt = (block_size - 8) // 2
        for k in range(cnt):
            ent = struct.unpack_from('<H', data, pos + 8 + k * 2)[0]
            rtype = ent >> 12
            w = 8 if rtype == 10 else (4 if rtype == 3 else 0)
            if w:
                tgt = page_rva + (ent & 0xFFF)
                if sec['virtual_addr'] <= tgt and \
                        tgt + w <= sec['virtual_addr'] + crc_len:
                    o = tgt - sec['virtual_addr']
                    mask[o:o + w] = b'\xff' * w
        pos += block_size
    return mask


def compute_section_crc(data, secs, sec):
    """
    CRC32 of the target section's raw bytes with reloc-masked fields zeroed
    (raw range [ptr_raw, ptr_raw + min(VirtualSize, SizeOfRawData))).
    """
    crc_len = min(sec['virtual_size'], sec['size_raw'])
    ptr = sec['ptr_raw']
    end = ptr + crc_len
    if ptr + 40 > len(data) or end > len(data):
        raise HashpatchError(
            'section %s raw range [%d, %d) exceeds file size %d'
            % (sec['name'], ptr, end, len(data)))

    mask = reloc_mask_bytes(data, secs, sec)
    raw = bytearray(data[ptr:end])
    if mask is not None:
        for i, m in enumerate(mask):
            if m:
                raw[i] = 0
    # N1 (D1b): selfcrypt 加密段同样掩码 (与运行侧 build_selfcrypt_mask 一致)
    for (mrva, mlen) in EXCLUDE_MASKS:
        if sec['virtual_addr'] <= mrva and mrva + mlen <= sec['virtual_addr'] + crc_len:
            o = mrva - sec['virtual_addr']
            raw[o:o + mlen] = b'\x00' * mlen
    crc = zlib.crc32(bytes(raw)) & 0xFFFFFFFF
    return crc, crc_len


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 1:
        print('usage: python tools/hashpatch.py <exe> [--mask rva,len]...',
              file=sys.stderr)
        return 2
    exe_path = argv[0]
    i = 1
    while i < len(argv):
        if argv[i] == '--mask':
            rva, mlen = argv[i + 1].split(',')
            add_exclude_mask(int(rva, 0), int(mlen, 0))
            i += 2
        else:
            print('hashpatch: unknown arg: %s' % argv[i], file=sys.stderr)
            return 2

    try:
        with open(exe_path, 'rb') as f:
            data = f.read()

        secs = pe_sections(data)
        prot = next((s for s in secs if s['name'] == '.protcrc'), None)
        if prot is None:
            raise HashpatchError(
                'no .protcrc section found in %s (integrity baked table missing)'
                % exe_path)
        if prot['size_raw'] < ENTRY_SIZE * len(MAGICS):
            raise HashpatchError('.protcrc section too small (%d bytes)' %
                                 prot['size_raw'])

        for i, magic in enumerate(MAGICS):
            off = prot['ptr_raw'] + i * ENTRY_SIZE
            if off + ENTRY_SIZE > len(data):
                raise HashpatchError('marker %d out of file range' % i)
            if data[off:off + 8] != magic:
                raise HashpatchError(
                    'marker %d magic mismatch at offset %d (want %r)'
                    % (i, off, magic))

            target = next((s for s in secs if s['name'] == TARGET_NAMES[i]), None)
            if target is None:
                print('hashpatch: %s section absent — skip' % TARGET_NAMES[i])
                continue

            crc, size_crc = compute_section_crc(data, secs, target)
            field_off = off + 8
            current = struct.unpack_from('<I', data, field_off)[0]

            if current == 0:
                patched = (data[:field_off] + struct.pack('<I', crc) +
                           data[field_off + 4:])
                with open(exe_path, 'wb') as f:
                    f.write(patched)
                data = patched
                print('hashpatch: patched %s crc=0x%08x at offset %d (magic at %d)'
                      % (TARGET_NAMES[i], crc, field_off, off))
            else:
                if current != crc:
                    raise HashpatchError(
                        '%s crc mismatch: baked=0x%08x, computed=0x%08x (%s)'
                        % (TARGET_NAMES[i], current, crc, exe_path))
                print('hashpatch: verified %s crc=0x%08x at offset %d (already baked)'
                      % (TARGET_NAMES[i], current, field_off))
            print('hashpatch: %s raw [%d, +%d) -> crc32 0x%08x'
                  % (TARGET_NAMES[i], target['ptr_raw'], size_crc, crc))
    except (HashpatchError, OSError, struct.error) as e:
        print('hashpatch: error: %s' % e, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
