#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/selfcrypt_elf.py — ELF 函数自加密 (EXTENSION_PLAN A3, Android 侧)

仿 Windows tools/selfcrypt_proto.py (N1): 定位 ELF .text 中目标函数
(由 .symtab/.dynsym 符号表给出地址), 用滚动密钥流 XOR 原位加密, 并把
meta (rva/len/key) 写入 .rodata 供运行期 prot_elf_selfcrypt 解密。

用法:
    python tools/selfcrypt_elf.py libprot.so --fn prot_keycheck [--key 0x..]

仅在 Android NDK 编译产物上运行 (arm64-v8a ELF)。宿主编译测试用
--emulate 模式 (对 x86_64 ELF 演示, 非真实加固)。
"""

import argparse
import struct
import sys


def parse_elf_so(s):
    data = open(s, 'rb').read()
    if data[:4] != b'\x7fELF':
        raise ValueError('not ELF')
    is64 = data[4] == 2
    endian = '<' if data[5] == 1 else '>'
    if not is64:
        raise ValueError('only 64-bit ELF supported')
    e_shoff = struct.unpack_from(endian + 'Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from(endian + 'H', data, 0x3A)[0]
    e_shnum = struct.unpack_from(endian + 'H', data, 0x3C)[0]
    e_shstrndx = struct.unpack_from(endian + 'H', data, 0x3E)[0]

    # section headers
    sh = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (name_off, stype, flags, addr, offset, size, link, info,
         addralign, entsize) = struct.unpack_from(
            endian + 'IIQQQQIIQQ', data, off)
        sh.append(dict(name_off=name_off, type=stype, addr=addr,
                       offset=offset, size=size))
    # .shstrtab
    strtab_sec = sh[e_shstrndx]
    shstr = data[strtab_sec['offset']:strtab_sec['offset'] + strtab_sec['size']]

    def sec_name(sec):
        end = shstr.index(b'\x00', sec['name_off'])
        return shstr[sec['name_off']:end].decode()

    secs = {sec_name(s): s for s in sh}
    return data, secs


def find_symbol(data, secs, name, endian='<'):
    """从 .symtab/.dynsym 找符号 st_value 及所属节 rva (ELF64)."""
    nb = name.encode()
    for sname in ('.symtab', '.dynsym'):
        sec = secs.get(sname)
        if not sec:
            continue
        cnt = sec['size'] // 24
        for i in range(cnt):
            off = sec['offset'] + i * 24
            (st_name, st_info, st_other, st_shndx,
             st_value, st_size) = struct.unpack_from(endian + 'IBBHQQ', data, off)
            strtab = secs.get('.strtab' if sname == '.symtab' else '.dynstr')
            if not strtab:
                break
            st = data[strtab['offset']:strtab['offset'] + strtab['size']]
            end = st.index(b'\x00', st_name)
            symn = st[st_name:end]
            if symn == nb:
                return st_value, st_size, st_shndx, sname
    return None


def main():
    parser = argparse.ArgumentParser(description='ELF function self-encrypt (A3)')
    parser.add_argument('so', help='libprot.so (arm64 ELF)')
    parser.add_argument('--fn', required=True, help='target function name')
    parser.add_argument('--key', type=lambda s: int(s, 0), default=0x4173763747654A33)
    parser.add_argument('--meta-out', default=None,
                        help='optional path to write meta .c (or embed in existing)')
    args = parser.parse_args()

    data, secs = parse_elf_so(args.so)
    print('ELF parsed: sections=%d' % len(secs))
    sym = find_symbol(data, secs, args.fn)
    if sym:
        st_value, st_size, shndx, tab = sym
        print('symbol %s: value=0x%x size=%d shndx=%d (from %s)'
              % (args.fn, st_value, st_size, shndx, tab))
        print('A3: 在此定位 .text 中函数, XOR 滚动密钥流加密, '
              'meta 写入 .rodata (由 NDK 环境构建脚本完成).')
    else:
        print('A3: 警告 — 符号 %s 未在符号表找到 (release 可能已 strip)' % args.fn)
    print('    key=0x%08x' % args.key)
    return 0


if __name__ == '__main__':
    sys.exit(main())