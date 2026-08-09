#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/hashpatch.py — PE .text CRC32 烧录工具  (Lane C)

Locates the `PROTCRCP` baked-crc marker inside a PE file and writes the
CRC32 of the .text section (raw data) into the 4-byte field right after
the 8-byte magic. If a non-zero CRC is already present, it is verified
instead of overwritten.

Marker layout (CONTRACT §3 / §7.1):
    magic[8] = 'PROTCRCP' | crc u32 LE | reserved u32 LE

CLI:
    python tools/hashpatch.py build\\demo.exe
"""

import struct
import sys
import zlib

MAGIC = b'PROTCRCP'


class HashpatchError(Exception):
    pass


def find_markers(data):
    """All byte offsets of the PROTCRCP magic in data."""
    offsets = []
    start = 0
    while True:
        i = data.find(MAGIC, start)
        if i < 0:
            break
        offsets.append(i)
        start = i + 1
    return offsets


def compute_text_crc(data):
    """
    Parse the PE headers and return zlib.crc32 of the .text raw section
    (file bytes [PointerToRawData, PointerToRawData + SizeOfRawData)).
    """
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

    for i in range(num_sections):
        off = sec_table + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].rstrip(b'\x00')
        if name == b'.text':
            virtual_size = struct.unpack_from('<I', data, off + 8)[0]
            size_raw = struct.unpack_from('<I', data, off + 16)[0]
            ptr_raw = struct.unpack_from('<I', data, off + 20)[0]
            # 与 integrity.c 的 check_self 完全一致: min(VirtualSize, SizeOfRawData)
            size_crc = min(virtual_size, size_raw)
            end = ptr_raw + size_crc
            if ptr_raw + 40 > len(data) or end > len(data):
                raise HashpatchError(
                    '.text raw range [%d, %d) exceeds file size %d'
                    % (ptr_raw, end, len(data)))
            crc = zlib.crc32(data[ptr_raw:end]) & 0xFFFFFFFF
            return crc, ptr_raw, size_crc

    raise HashpatchError('.text section not found in PE')


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        print('usage: python tools/hashpatch.py <exe>', file=sys.stderr)
        return 2
    exe_path = argv[0]

    try:
        with open(exe_path, 'rb') as f:
            data = f.read()

        markers = find_markers(data)
        if not markers:
            raise HashpatchError('no PROTCRCP marker found in %s' % exe_path)
        if len(markers) > 1:
            raise HashpatchError(
                'multiple PROTCRCP markers found (%d): %s'
                % (len(markers), markers))

        marker = markers[0]
        if marker + 12 > len(data):
            raise HashpatchError('PROTCRCP marker too close to end of file')

        crc, ptr_raw, size_raw = compute_text_crc(data)

        field_off = marker + 8
        current = struct.unpack_from('<I', data, field_off)[0]

        if current == 0:
            patched = data[:field_off] + struct.pack('<I', crc) + data[field_off + 4:]
            with open(exe_path, 'wb') as f:
                f.write(patched)
            print('hashpatch: patched .text crc=0x%08x at offset %d (magic at %d)'
                  % (crc, field_off, marker))
        else:
            if current != crc:
                raise HashpatchError(
                    'crc mismatch: baked=0x%08x, computed=0x%08x (%s)'
                    % (current, crc, exe_path))
            print('hashpatch: verified .text crc=0x%08x at offset %d (already baked)'
                  % (current, field_off))
        print('hashpatch: .text raw [%d, +%d) -> crc32 0x%08x'
              % (ptr_raw, size_raw, crc))
    except (HashpatchError, OSError, struct.error) as e:
        print('hashpatch: error: %s' % e, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
