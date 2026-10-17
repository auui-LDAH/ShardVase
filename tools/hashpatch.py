#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
tools/hashpatch.py — PE 段 CRC32 烧录工具  (Lane C, A3 扩展)

Locates the dedicated `.protcrc` section (3 baked-crc markers) inside a PE
file and writes the CRC32 of the target sections (raw data,
PE: .text/.rdata/.pdata; ELF: .text/.rodata/.eh_frame — B2). Original text:
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

import json
import struct
import sys
import zlib

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


# 与 src/integrity.c g_prot_baked_crc 顺序一致
#
# DRILL9 盲区修复（2026-10-04）: 新增第 4 个目标 `PROTCRCX` = `.protxec`
#   （守卫检查器自身所在段）。**顺序即 CRC 表下标顺序**，与
#   src/integrity.c g_prot_baked_crc[] 及平台层 prot_plat_crc_target_name()
#   必须一致；tools/check_crc_targets.py 交叉核对。
MAGICS = (b'PROTCRCP', b'PROTCRCD', b'PROTCRDP', b'PROTCRCX')

# 与 TARGET_NAMES 逐位对齐的**逻辑名**（None = 标准节名, 不参与随机化）。
#
# 为什么需要它（2026-10-04, DRILL9 盲区修复时踩到的坑）:
#   阶段1 起 `.protxec` 的节名也是**每构建随机**的（gen_sections.py 写
#   `#undef PROT_SEC_XEC` + `#define PROT_SEC_XEC ".xxxxxxxx"`）。
#   若这里只用 TARGET_NAMES 的默认名 `.protxec` 去找节，生成路径下
#   `next(...)` 永远返回 None -> 走下方的 "section absent — skip" 分支
#   -> **静默不校验**（CRC 字段恒为 0, 不报错）。这比不修更危险，故必须映射。
TARGET_LOGICAL = (None, None, None, 'protxec')


def resolve_target_names(target_names, section_names):
    """把默认节名按逻辑名替换为本次构建的实际（随机）节名。"""
    out = []
    for default, logical in zip(target_names, TARGET_LOGICAL):
        out.append((section_names.get(logical) or default) if logical else default)
    return tuple(out)


def load_section_names(path):
    """从 gen_sections.py 生成的 JSON 读取随机节名。

    返回 dict: 逻辑名 -> 实际节名。未提供 path 或读取失败时返回 {}，
    调用方回退到旧默认名（向后兼容）。
    """
    if not path:
        return {}
    try:
        with open(path, encoding='ascii') as f:
            data = json.load(f)
        secs = data.get('sections', {})
        if not isinstance(secs, dict):
            return {}
        return secs
    except (OSError, ValueError):
        return {}

def load_magics(path):
    """从 gen_sections.py 的 JSON 读取随机 magic（阶段3: 去自解释标记）。

    返回 (magic_text, magic_rdata, magic_pdata, magic_xec) 的 bytes 元组；
    未提供或读取失败时返回 None -> 调用方回退硬编码 MAGICS（向后兼容）。

    实测依据: src/integrity.c **不检查 magic**（只用 g_prot_baked_crc[]
    的符号顺序），故 magic 随机化对 C 侧零影响。
    """
    if not path:
        return None
    try:
        with open(path, encoding='ascii') as f:
            data = json.load(f)
        mg = data.get('magics', {})
        out = []
        for k in ('text', 'rdata', 'pdata', 'xec'):
            v = mg.get(k)
            if not isinstance(v, str) or len(v) != 16:
                return None
            out.append(bytes.fromhex(v))
        return tuple(out)
    except (OSError, ValueError):
        return None


def load_crc_extra(path):
    """阶段4（第二支柱·完整性覆盖扩展, 2026-10-15）: 读取每构建随机的
    额外 CRC 目标清单。

    JSON 键 'crc_extra': [{'key','name','magic'}, ...]，顺序 = gen_sections
    的 EXTRA_POOL 序（与生成头的表项/名字列表同序）。
    返回 [(magic8bytes, name), ...]；缺失/读取失败返回 []（老 JSON 兼容）。
    """
    if not path:
        return []
    try:
        with open(path, encoding='ascii') as f:
            data = json.load(f)
        out = []
        for item in data.get('crc_extra', []):
            magic_hex = item.get('magic')
            name = item.get('name')
            if (not isinstance(magic_hex, str) or len(magic_hex) != 16 or
                    not isinstance(name, str) or not name):
                continue
            out.append((bytes.fromhex(magic_hex), name))
        return out
    except (OSError, ValueError):
        return []


TARGET_NAMES = ('.text', '.rdata', '.pdata', '.protxec')
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


# ===========================================================================
# ELF 支持（B2，2026-09-25）
#
# ## 为什么需要
#   `hashpatch.py` 原仅支持 PE（`struct` 硬编码 PE 头偏移）——
#   Linux 产物是 **ELF**，需要等价的"解析节表 + 烧录 CRC"能力。
#
# ## 与 PE 的**结构对应**（实测 build/demo_linux）
#   | PE | ELF |
#   |----|-----|
#   | `.text` | `.text` |
#   | `.rdata` | **`.rodata`** |
#   | `.pdata` | **`.eh_frame`**（最近的对应物）|
#   | `.reloc` | **`.rela.dyn`** |
#   | IAT（数据目录 12）| **`.got` / `.got.plt`** |
#   | `.protcrc`（随机名）| 同名随机节（实测 `.dkwt8io`，0x30 = 3×16）|
#
# ## 关键差异（**简化**）
#   · ELF 节头 `sh_size` 即**实际大小**（无 PE 的 VirtualSize/RawSize 之分）
#     -> 不需要 `min(vsize, rawsize)` 逻辑，**更精确**
#   · ELF 用 `sh_addr`/`sh_offset` 表达地址与文件偏移
# ===========================================================================

ELF_TARGET_NAMES = ('.text', '.rodata', '.eh_frame')
ELF_MAGIC_CLASS64 = 2
ELF_MAGIC_LSB = 1


def is_elf(data):
    """是否 ELF64 小端。"""
    return (len(data) >= 64 and data[0:4] == b'\x7fELF'
            and data[4] == ELF_MAGIC_CLASS64 and data[5] == ELF_MAGIC_LSB)


def elf_sections(data):
    """解析 ELF64 节表；返回 list of dicts（含名/地址/偏移/大小/属性）。

    字段与 `pe_sections` **语义对应**，便于共用下游逻辑:
      `virtual_addr` <- sh_addr, `size_raw` <- sh_size,
      `ptr_raw` <- sh_offset, `virtual_size` <- sh_size（ELF 无区分）
    """
    if not is_elf(data):
        raise HashpatchError('not an ELF64-LE file')
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]
    if e_shoff == 0 or e_shnum == 0:
        raise HashpatchError('ELF has no section table')

    def sh(i):
        o = e_shoff + i * e_shentsize
        (nameoff, stype, flags, addr, off, size, link, info,
         align, entsize) = struct.unpack_from('<IIQQQQIIQQ', data, o)
        return {'nameoff': nameoff, 'type': stype, 'flags': flags,
                'addr': addr, 'off': off, 'size': size,
                'align': align, 'entsize': entsize}

    # 节名字符串表
    strtab_off = sh(e_shstrndx)['off'] if e_shstrndx < e_shnum else 0

    secs = []
    for i in range(e_shnum):
        s = sh(i)
        if strtab_off:
            end = data.index(b'\x00', strtab_off + s['nameoff'])
            name = data[strtab_off + s['nameoff']:end].decode('ascii',
                                                              'replace')
        else:
            name = ''
        secs.append({
            'name': name,
            'virtual_size': s['size'],      # ELF: sh_size 即实际大小
            'virtual_addr': s['addr'],
            'size_raw': s['size'],
            'ptr_raw': s['off'],
            'flags': s['flags'],
            'index': i,
            # ⚠️ entsize 必须带出 —— `.rela.dyn` 的条目大小靠它
            #   （实测漏传 -> `KeyError: 'entsize'`）
            'entsize': s['entsize'],
        })
    return secs


def elf_reloc_mask_bytes(data, secs, sec):
    """ELF 的"会被 loader 改写"掩码（对应 PE 的 reloc_mask_bytes）。

    ## 规则（与 PE 侧**同语义**）
      ① `.rela.dyn` / `.rela.plt` 中**会写入**的重定位（R_X86_64_RELATIVE /
         GLOB_DAT / JUMP_SLOT）—— 8 字节槽
      ② `.got` / `.got.plt`（**loader 填充**，等价 PE 的 IAT）
    """
    crc_len = sec['size_raw']
    mask = bytearray(crc_len)

    # ① GOT（等价 IAT）—— loader 写导入地址
    for gname in ('.got', '.got.plt'):
        g = next((s for s in secs if s['name'] == gname), None)
        if g is None or g['size_raw'] == 0:
            continue
        if (sec['virtual_addr'] <= g['virtual_addr'] and
                g['virtual_addr'] + g['size_raw'] <=
                sec['virtual_addr'] + crc_len):
            o = g['virtual_addr'] - sec['virtual_addr']
            mask[o:o + g['size_raw']] = b'\xff' * g['size_raw']

    # ② 重定位表
    for rname in ('.rela.dyn', '.rela.plt'):
        rel = next((s for s in secs if s['name'] == rname), None)
        if rel is None or rel['entsize'] == 0 or rel['size_raw'] == 0:
            continue
        cnt = rel['size_raw'] // rel['entsize']
        for k in range(cnt):
            o = rel['ptr_raw'] + k * rel['entsize']
            if o + rel['entsize'] > len(data):
                break
            r_offset, r_info, _add = struct.unpack_from('<QQq', data, o)
            rtype = r_info & 0xFFFFFFFF
            # 只取**会写入**的类型（与 Windows 只取 type 3/10 对应）
            if rtype in (8, 6, 7):      # RELATIVE / GLOB_DAT / JUMP_SLOT
                w = 8
                if (sec['virtual_addr'] <= r_offset and
                        r_offset + w <= sec['virtual_addr'] + crc_len):
                    oo = r_offset - sec['virtual_addr']
                    mask[oo:oo + w] = b'\xff' * w
    return mask


def elf_compute_section_crc(data, secs, sec):
    """ELF 侧 CRC（与 `compute_section_crc` 同语义）。

    CRC 长度 = `sh_size`（**无** PE 的 vsize/rawsize 之分）。
    掩码: `.rela.dyn` 重定位 + `.got`；再叠加 selfcrypt 排除区间。
    """
    crc_len = sec['size_raw']
    ptr = sec['ptr_raw']
    if ptr + crc_len > len(data):
        raise HashpatchError('ELF section %s raw range exceeds file'
                             % sec['name'])
    mask = elf_reloc_mask_bytes(data, secs, sec)
    raw = bytearray(data[ptr:ptr + crc_len])
    for i, m in enumerate(mask):
        if m:
            raw[i] = 0
    for (mrva, mlen) in EXCLUDE_MASKS:
        if (sec['virtual_addr'] <= mrva and
                mrva + mlen <= sec['virtual_addr'] + crc_len):
            o = mrva - sec['virtual_addr']
            raw[o:o + mlen] = b'\x00' * mlen
    return zlib.crc32(bytes(raw)) & 0xFFFFFFFF, crc_len


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
    sections_json = None
    i = 1
    while i < len(argv):
        if argv[i] == '--mask':
            rva, mlen = argv[i + 1].split(',')
            add_exclude_mask(int(rva, 0), int(mlen, 0))
            i += 2
        elif argv[i] == '--sections-json':
            # 阶段1(第二支柱): 节名每构建随机，需从 gen_sections.py 的 JSON
            # 读实际名。未提供时回退旧名 .protcrc（向后兼容）。
            if i + 1 >= len(argv):
                print('hashpatch: --sections-json needs a path', file=sys.stderr)
                return 2
            sections_json = argv[i + 1]
            i += 2
        else:
            print('hashpatch: unknown arg: %s' % argv[i], file=sys.stderr)
            return 2

    try:
        with open(exe_path, 'rb') as f:
            data = f.read()

        # ## B2（2026-09-25）: 按文件类型**分派**（PE / ELF）
        #   两个路径的**下游逻辑完全相同**（找烧录表 -> 逐条算 CRC -> 烧录），
        #   只有"节表解析 / 掩码规则 / 目标节名"三处按平台不同。
        is_elf_file = is_elf(data)
        secs = elf_sections(data) if is_elf_file else pe_sections(data)
        target_names = ELF_TARGET_NAMES if is_elf_file else TARGET_NAMES
        # 阶段1(第二支柱): 节名每构建随机, 由 gen_sections.py 生成。
        # 未提供 --sections-json 时回退旧名 .protcrc (向后兼容)。
        section_names = load_section_names(sections_json)
        # 阶段1(第二支柱) 补充（2026-10-04）: 节名随机化后**必须**把默认名
        #   换成实际名（`.protxec` 亦随机），否则静默跳过（见 TARGET_LOGICAL）。
        target_names = resolve_target_names(target_names, section_names)
        # 阶段3: magic 随机化（替代硬编码 PROTCRCP/D/P）。
        # 实测: integrity.c 不检查 magic（只用 g_prot_baked_crc[] 的符号顺序），
        # 故 magic 随机化对 C 侧零影响。
        magics_override = load_magics(sections_json)
        active_magics = magics_override if magics_override else MAGICS
        # 阶段4: 额外目标追加在 4 个基础目标之后（PE 随机扩展路径）。
        # ELF 路径不参与（Linux 构建 --extra-crc 0 -> JSON 无 crc_extra）。
        crc_extra = load_crc_extra(sections_json)
        if crc_extra and not is_elf_file:
            active_magics = tuple(active_magics) + tuple(
                m for m, _ in crc_extra)
            target_names = tuple(target_names) + tuple(
                n for _, n in crc_extra)
        elif crc_extra:
            print('hashpatch: crc_extra present but ELF target — ignored '
                  '(Linux 不参与阶段4随机扩展)', file=sys.stderr)
        crc_sec = section_names.get('protcrc')
        cand = [crc_sec] if crc_sec else ['.protcrc']
        prot = next((s for s in secs if s['name'] in cand), None)
        if prot is None:
            raise HashpatchError(
                'no baked-CRC section found in %s '
                '(integrity table missing; expected random name from '
                '--sections-json, or legacy .protcrc)' % exe_path)
        if prot['size_raw'] < ENTRY_SIZE * len(active_magics):
            raise HashpatchError('.protcrc section too small (%d bytes)' %
                                 prot['size_raw'])

        # 阶段4.3 链式 (2026-10-16): prev = 前一**槽位**写入值。
        #   entry0 存 raw; entry i≥1 存 crc32(raw_le4 || prev_le4)。
        #   与 integrity.c 校验端 fold 严格对称 (缺段/跳过 -> 槽位 0)。
        prev = 0
        for i, magic in enumerate(active_magics):
            off = prot['ptr_raw'] + i * ENTRY_SIZE
            if off + ENTRY_SIZE > len(data):
                raise HashpatchError('marker %d out of file range' % i)
            if data[off:off + 8] != magic:
                raise HashpatchError(
                    'marker %d magic mismatch at offset %d (want %r)'
                    % (i, off, magic))

            # 阶段4 附带修复（潜伏缺陷, 2026-10-15 实测确认）:
            #   ELF 路径 target_names 只有 3 项, 而 4-magic JSON 让
            #   active_magics 有 4 项 -> 原代码 target_names[i] 在 i=3 抛
            #   IndexError（不在 main 的 except 白名单里 -> 裸崩）。
            #   运行侧 linux names[] 也是 3 项 -> 下标 3 的烧录 CRC 本就
            #   不被校验。故 i 超界即"该平台不校验此表项"，跳过即可。
            if i >= len(target_names):
                print('hashpatch: entry %d has no target name on this '
                      'platform — skip (CRC left 0)' % i)
                prev = 0      # 链式: 槽位 i 保持 0 -> 下一项折叠 0 (两侧对称)
                continue

            target = next((s for s in secs if s['name'] == target_names[i]), None)
            if target is None:
                print('hashpatch: %s section absent — skip' % target_names[i])
                prev = 0      # 链式: 槽位 i 保持 0 -> 下一项折叠 0 (两侧对称)
                continue

            crc, size_crc = (elf_compute_section_crc(data, secs, target)
                             if is_elf_file else
                             compute_section_crc(data, secs, target))
            # 阶段4.3 链式: entry0 存 raw, i≥1 折叠前一槽位值 (prev)。
            stored = crc if i == 0 else chain_crc(crc, prev)
            field_off = off + 8
            current = struct.unpack_from('<I', data, field_off)[0]

            if current == 0:
                patched = (data[:field_off] + struct.pack('<I', stored) +
                           data[field_off + 4:])
                with open(exe_path, 'wb') as f:
                    f.write(patched)
                data = patched
                print('hashpatch: patched %s crc=0x%08x at offset %d (magic at %d)%s'
                      % (target_names[i], stored, field_off, off,
                         '' if i == 0 else ' [chained]'))
            else:
                if current != stored:
                    raise HashpatchError(
                        '%s crc mismatch: baked=0x%08x, computed=0x%08x raw=0x%08x (%s)'
                        % (target_names[i], current, stored, crc, exe_path))
                print('hashpatch: verified %s crc=0x%08x at offset %d (already baked)'
                      % (target_names[i], current, field_off))
            print('hashpatch: %s raw [%d, +%d) -> crc32 0x%08x%s'
                  % (target_names[i], target['ptr_raw'], size_crc, crc,
                     '' if i == 0 else ' -> chained 0x%08x' % stored))
            prev = stored
    except (HashpatchError, OSError, struct.error) as e:
        print('hashpatch: error: %s' % e, file=sys.stderr)
        return 1
    return 0


def chain_crc(raw, prev):
    """阶段4.3 链式 (2026-10-16): 折叠 = crc32(raw_le4 || prev_le4)。
    与 src/integrity.c 校验端 prot_crc32(fold, 8u) 逐字节一致 (zlib 同语义)。
    entry0 不折叠 (存 raw, protchain_check 只读 entry0)。"""
    return zlib.crc32(struct.pack('<II', raw & 0xFFFFFFFF,
                                  prev & 0xFFFFFFFF)) & 0xFFFFFFFF


if __name__ == '__main__':
    sys.exit(main())
