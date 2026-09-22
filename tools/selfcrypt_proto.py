#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
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
import json
import os
import struct
import sys
import zlib

M64 = (1 << 64) - 1
KS_MUL = 0x5851F42D4C957F2D
KS_ADD = 0x14057B7EF767814F

# 目标函数 (引擎核心; 二期 II-3 扩展)。
# 注意: 加密函数间相互调用必须同组解密 (运行期全组一起解密, D2a 无问题;
# D2b 下用函数组 enter/leave)。
# 顺序 = .pdata 覆盖顺序; 被内联的函数 (vm_kr_*/vm_ks_seek/vm_wd_fill 等)
# 无独立 .pdata 条目, 跳过 (它们在 prot_vm_run 内部, 随其加密)。
DEFAULT_TARGETS = {
    'prot_vm_run': 0,
    'vm_build_keymaps': 0,
    'vm_wb': 0,
    'vm_var': 0,
}
EXT_TARGETS = {
    'prot_vm_blob_load': 1,
    'prot_license_verify': 1,
    'prot_integrity_check_self': 1,
    'prot_antidebug_scan': 1,
}

BLOB_SIZE = 16384  # 二期 II-3: .protcry 容器扩容 (main.c 同步)


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


def load_section_names(path):
    """从 gen_sections.py 生成的 JSON 读取随机节名（阶段1 第二支柱）。

    未提供 path 或读取失败时返回 {} -> 调用方回退旧默认名（向后兼容），
    使旧的构建流程仍然可用。
    """
    if not path:
        return {}
    try:
        with open(path, encoding='ascii') as f:
            data = json.load(f)
        secs = data.get('sections', {})
        return secs if isinstance(secs, dict) else {}
    except (OSError, ValueError):
        return {}


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
    parser.add_argument('--mask-out', dest='mask_out', default=None,
                        help='掩码输出路径 (默认 build/selfcrypt_mask.txt, '
                             'P0 骨架构建用)')
    # 阶段1(第二支柱): 节名每构建随机，故需从 gen_sections.py 的 JSON 读实际名。
    # 未提供时回退旧默认名（.protcry/.protcrypt），保证旧流程仍可用。
    parser.add_argument('--sections-json', dest='sections_json', default=None,
                        help='gen_sections.py 生成的节名映射 JSON'
                             '（阶段1: 节名每构建随机）')
    parser.add_argument('--extra', action='append', default=None,
                        help='额外加密函数名 (组 1, 可多次; S1 纵深扩展)')
    parser.add_argument('--require-all', action='store_true',
                        help='目标函数缺失即报错 (默认: 缺失则跳过并告警). '
                             '组合构建 (阶段 2) 下部分模块不参与编译, 其函数自然'
                             '不在 .map 中, 属预期 —— 默认跳过; 需要严格校验时用本开关')
    args = parser.parse_args(argv)

    if args.disable:
        print('selfcrypt_proto: disabled (no changes)')
        return 0

    try:
        with open(args.exe, 'rb') as f:
            data = bytearray(f.read())
        secs = pe_sections(data)
        text = next((s for s in secs if s['name'] == '.text'), None)
        # 阶段1(第二支柱): 节名每构建随机。未提供 --sections-json 时回退旧名
        # （旧名含 .protcrypt: 源码写 10 字符，PE 截断为 8 字符 .protcry）。
        section_names = load_section_names(
            getattr(args, 'sections_json', None))
        cry_sec = section_names.get('protcry')
        cand2 = [cry_sec] if cry_sec else ['.protcrypt', '.protcry']
        prot = next((s for s in secs if s['name'] in cand2), None)
        if text is None or prot is None:
            raise SelfcryptError('.text or .protcrypt section missing')

        funcs = parse_map_functions(args.map)
        pdata = parse_pdata(data, secs)
        seed = args.seed if args.seed is not None else 0x4E31504245474D21

        entries = []
        targets = dict(DEFAULT_TARGETS)
        targets.update(EXT_TARGETS)
        if args.extra:
            for en in args.extra:
                targets.setdefault(en, 1)
        # 阶段 2 (组合构建): 未参与编译的模块, 其函数不在 .map 中 —— 属预期,
        # 跳过而非报错。--require-all 可恢复旧行为 (严格校验全部目标存在)。
        # 依据: BLUEPRINT §5 阶段 2 的"selfcrypt 与组合的真实耦合点"。
        skipped_targets = []
        dry_count = 0   # dry-run 下命中的目标数 (entries 在 dry-run 不填充)
        for name, group in targets.items():
            if name not in funcs:
                if args.require_all:
                    raise SelfcryptError('function %s not found in map' % name)
                skipped_targets.append(name)
                continue
            rva = funcs[name]
            if rva not in pdata:
                # .pdata 缺失通常是内联/ICF 导致, 与组合无关 -> 始终报错
                # (保持 P0 严格性: 静默漏加密是不可接受的)
                raise SelfcryptError('%s: no .pdata entry (rva=0x%x)' % (name, rva))
            end, _ = pdata[rva]
            size = end - rva
            # 防御 (2026-08-29): pdata 大小不得跨越 .text 段尾 (跨界会写坏
            # 邻节数据 -> 间歇性 TAMPERED/崩溃). 裁剪到段尾并校验下限.
            text_end_rva = text['virtual_addr'] + text['size_raw']
            if rva < text['virtual_addr'] or rva + size > text_end_rva:
                size = text_end_rva - rva if rva < text_end_rva else 0
            if size <= 5 or size > 4096:
                raise SelfcryptError('%s: bad size %d' % (name, size))

            # 页冲突安全网 (2026-08-30): 加密段所在页若与执行流函数 (main)
            # 同页, VP 切 RW 会禁执行 main -> 自伤崩. 警告并跳过该段.
            if 'main' in funcs:
                if (rva >> 12) == (funcs['main'] >> 12):
                    print('selfcrypt_proto: WARN %s shares page 0x%x with main '
                          '(VP self-poison risk) - skipping' % (name, rva >> 12))
                    continue

            toff = text['ptr_raw'] + (rva - text['virtual_addr'])
            body = bytes(data[toff:toff + size])
            cipher = encrypt_bytes(body, seed)

            if args.dry_run:
                print('selfcrypt_proto: [dry] %s rva=0x%x size=%d seed=0x%x'
                      % (name, rva, size, seed))
                dry_count += 1
                continue

            # 原位写密文 (方案 B: 函数不搬移)
            data[toff:toff + size] = cipher
            entries.append((rva, size, seed, zlib.crc32(body) & 0xFFFFFFFF, group))
            print('selfcrypt_proto: %s rva=0x%x size=%d seed=0x%x crc=0x%08x group=%d (in-place)'
                  % (name, rva, size, seed, entries[-1][3], group))

        # 跳过报告: 组合构建下未参与编译的模块, 其函数不在 .map 中。
        # **必须显式报告** —— 静默漏加密会让"加密了几个函数"变得不可审计。
        # 注意: 必须在 --dry-run 提前返回**之前**报告, 否则 dry-run 下看不到。
        if skipped_targets:
            print('selfcrypt_proto: skipped %d target(s) not present in map '
                  '(组合构建预期; 用 --require-all 可改为报错): %s'
                  % (len(skipped_targets), ', '.join(sorted(skipped_targets))))
        # dry-run 下 entries 恒为空 (不入写路径), 用 dry_count 判定实际命中数
        if not entries and dry_count == 0:
            raise SelfcryptError(
                'no target encrypted — 全部目标都不在 .map 中 (组合或构建异常?)')

        if args.dry_run:
            print('selfcrypt_proto: dry-run, no write')
            return 0

        # meta 写入 .protcrypt blob: [count u32][entry*24]
        # entry = { rva u32 | len u32 | key0 u64 | crc u32 | group u32 } (24B)
        hdr = 4 + len(entries) * 24
        if hdr > BLOB_SIZE:
            raise SelfcryptError('meta overflow (%d > %d)' % (hdr, BLOB_SIZE))
        blob_off = prot['ptr_raw']
        data[blob_off:blob_off + 4] = struct.pack('<I', len(entries))
        for i, (rva, size, sd, crc, group) in enumerate(entries):
            e_off = blob_off + 4 + i * 24
            data[e_off:e_off + 24] = struct.pack('<IIQII', rva, size, sd, crc, group)

        with open(args.exe, 'wb') as f:
            f.write(bytes(data))
        print('selfcrypt_proto: patched %s (%d fns in-place, meta@0x%x hdr=%d)'
              % (args.exe, len(entries), blob_off, hdr))
        # 掩码提示 (D1b): 写 build/selfcrypt_mask.txt 供 hashpatch 读取
        mask_path = args.mask_out or 'build/selfcrypt_mask.txt'
        os.makedirs(os.path.dirname(os.path.abspath(mask_path)), exist_ok=True)
        with open(mask_path, 'w', encoding='ascii') as f:
            for rva, size, sd, crc, _g in entries:
                f.write('0x%x,%d\n' % (rva, size))
        print('selfcrypt_proto: MASK written -> %s' % mask_path)
        return 0
    except (SelfcryptError, OSError, struct.error) as e:
        print('selfcrypt_proto: error: %s' % e, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
