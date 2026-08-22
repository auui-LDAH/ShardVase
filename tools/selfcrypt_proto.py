#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/selfcrypt_proto.py — N1 阶段 0 原型 (方案 B: 原位加密)

对构建产物 demo.exe 做:
  1. 从 .map 解析目标函数 RVA (prot_vm_run 等引擎核心);
  2. 从 .pdata 解析函数大小 (Begin/End RVA);
  3. 函数体在 .text **原位** XOR 加密 (CONTRACT §3 滚动密钥流) ——
     不搬移, 无跳板, 函数内相对 call/jmp 不受影响 (阶段 0 关键结论:
     方案 C 搬移+跳板在 x64 下函数内 E8 rel32 错位, 证伪);
  4. meta (rva/len/key) 写入 .protcrypt 专用节 (g_prot_selfcrypt_blob),
     供运行期 prot_selfcrypt_init 原位解密;
  5. 打印目标段的掩码信息 (hashpatch/integrity 需跳过该段 CRC, D1b)。

用法:
    python tools/selfcrypt_proto.py build\\demo.exe build\\demo.map [--seed 0x..]

约束 (D1b): .text CRC 需对目标段掩码 (hashpatch.py + integrity.c),
否则加密态(文件)与解密态(运行) CRC 不一致 -> 误报。
"""

import argparse
import struct
import sys
import zlib

M64 = (1 << 64) - 1
KS_MUL = 0x5851F42D4C957F2D
KS_ADD = 0x14057B7EF767814F

DEFAULT_TARGETS = ('prot_vm_run',)
BLOB_SIZE = 4096


class SelfcryptError(Exception):
    pass


def xorshift_ks(key):
    return (key * KS_MUL + KS_ADD) & M64


def encrypt_bytes(data, seed):
    k = seed & M64
    out = bytearray(len(data))
    for i, b in enumerate(data):
        k = xorshift_ks(k)
        out[i] = b ^ ((k >> 56) & 0xFF)
    return bytes(out)


def pe_sections(data):
    if len(data) < 0x40:
        raise SelfcryptError('not a PE file')
    e = struct.unpack_from('<I', data, 0x3C)[0]
    if data[e:e + 4] != b'PE\x00\x00':
        raise SelfcryptError('bad PE signature')
    nsec = struct.unpack_from('<H', data, e + 6)[0]
    optsz = struct.unpack_from('<H', data, e + 20)[0]
    table = e + 24 + optsz
    secs = []
    for i in range(nsec):
        off = table + i * 40
        name = data[off:off + 8].rstrip(b'\x00').decode('ascii', 'replace')
        secs.append({
            'name': name,
            'virtual_size': struct.unpack_from('<I', data, off + 8)[0],
            'virtual_addr': struct.unpack_from('<I', data, off + 12)[0],
            'size_raw': struct.unpack_from('<I', data, off + 16)[0],
            'ptr_raw': struct.unpack_from('<I', data, off + 20)[0],
        })
    return secs


def parse_map_functions(map_path):
    out = {}
    image_base = 0x140000000
    with open(map_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            m = line.split()
            if len(m) >= 3 and ':' in m[0] and m[2].startswith('0000000140'):
                try:
                    va = int(m[2], 16)
                except ValueError:
                    continue
                out[m[1]] = va - image_base
    return out


def parse_pdata(data, secs):
    sec = next((s for s in secs if s['name'] == '.pdata'), None)
    if sec is None:
        raise SelfcryptError('no .pdata section')
    crc_len = min(sec['virtual_size'], sec['size_raw'])
    raw = data[sec['ptr_raw']:sec['ptr_raw'] + crc_len]
    out = {}
    for i in range(0, len(raw) - 11, 12):
        begin, end, unwind = struct.unpack_from('<III', raw, i)
        out[begin] = (end, unwind)
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(prog='selfcrypt_proto.py',
                                     description='N1 prototype: in-place encrypt engine fns')
    parser.add_argument('exe', help='build\\demo.exe')
    parser.add_argument('map', help='build\\demo.map (link /MAP output)')
    parser.add_argument('--seed', dest='seed', type=lambda s: int(s, 0),
                        default=None, help='keystream seed (hex/dec; default random)')
    parser.add_argument('--dry-run', action='store_true',
                        help='report plan without writing')
    parser.add_argument('--disable', action='store_true',
                        help='no-op (降级构建, 函数保持明文)')
    args = parser.parse_args(argv)

    if args.disable:
        print('selfcrypt_proto: disabled (no changes)')
        return 0

    try:
        with open(args.exe, 'rb') as f:
            data = bytearray(f.read())
        secs = pe_sections(data)
        text = next((s for s in secs if s['name'] == '.text'), None)
        prot = next((s for s in secs if s['name'] in ('.protcrypt', '.protcry')), None)
        if text is None or prot is None:
            raise SelfcryptError('.text or .protcrypt section missing')

        funcs = parse_map_functions(args.map)
        pdata = parse_pdata(data, secs)
        seed = args.seed if args.seed is not None else 0x4E31504245474D21

        entries = []
        for name in DEFAULT_TARGETS:
            if name not in funcs:
                raise SelfcryptError('function %s not found in map' % name)
            rva = funcs[name]
            if rva not in pdata:
                raise SelfcryptError('%s: no .pdata entry (rva=0x%x)' % (name, rva))
            end, _ = pdata[rva]
            size = end - rva
            if size <= 5 or size > 4096:
                raise SelfcryptError('%s: bad size %d' % (name, size))

            toff = text['ptr_raw'] + (rva - text['virtual_addr'])
            body = bytes(data[toff:toff + size])
            cipher = encrypt_bytes(body, seed)

            if args.dry_run:
                print('selfcrypt_proto: [dry] %s rva=0x%x size=%d seed=0x%x'
                      % (name, rva, size, seed))
                continue

            # 原位写密文 (方案 B: 函数不搬移)
            data[toff:toff + size] = cipher
            entries.append((rva, size, seed, zlib.crc32(body) & 0xFFFFFFFF))
            print('selfcrypt_proto: %s rva=0x%x size=%d seed=0x%x crc=0x%08x (in-place)'
                  % (name, rva, size, seed, entries[-1][3]))

        if args.dry_run:
            print('selfcrypt_proto: dry-run, no write')
            return 0

        # meta 写入 .protcrypt blob: [count u32][entry*16]
        # entry = { rva u32 | len u32 | key0 u64 }
        hdr = 4 + len(entries) * 16
        if hdr > BLOB_SIZE:
            raise SelfcryptError('meta overflow (%d > %d)' % (hdr, BLOB_SIZE))
        blob_off = prot['ptr_raw']
        data[blob_off:blob_off + 4] = struct.pack('<I', len(entries))
        for i, (rva, size, sd, crc) in enumerate(entries):
            e_off = blob_off + 4 + i * 16
            data[e_off:e_off + 16] = struct.pack('<IIQ', rva, size, sd)

        with open(args.exe, 'wb') as f:
            f.write(bytes(data))
        print('selfcrypt_proto: patched %s (%d fns in-place, meta@0x%x hdr=%d)'
              % (args.exe, len(entries), blob_off, hdr))
        # 掩码提示 (D1b): 写 build/selfcrypt_mask.txt 供 hashpatch 读取
        mask_path = 'build/selfcrypt_mask.txt'
        with open(mask_path, 'w', encoding='ascii') as f:
            for rva, size, sd, crc in entries:
                f.write('0x%x,%d\n' % (rva, size))
        print('selfcrypt_proto: MASK written -> %s' % mask_path)
        return 0
    except (SelfcryptError, OSError, struct.error) as e:
        print('selfcrypt_proto: error: %s' % e, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
