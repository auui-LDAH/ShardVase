#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/vmenc.py — VASM 汇编器 + 加密器 + genserial  (Lane C)

Two-pass VASM assembler + rolling-keystream encryptor producing a
prot_vm_image blob, plus a `genserial` subcommand that computes the
expected FNV-1a / xorshift license constants for a serial/machine_id.

Algorithms and CLI are defined in docs/CONTRACT.md (§3, §5).

CLI:
    python tools/vmenc.py assemble <in.vasm> <vm_build.json> <out.c> <out.h>
    python tools/vmenc.py genserial --json <vm_build.json> [--print]
"""

import argparse
import ctypes
import json
import os
import random
import struct
import sys
import zlib

from ctypes import wintypes

M64 = (1 << 64) - 1

# FNV-1a 64 位常量 (machine_id, 与 src/hostid.c 一致)
HOSTID_FNV_BASIS = 0xCBF29CE484222325
HOSTID_FNV_PRIME = 0x100000001B3
HOSTID_M64 = (1 << 64) - 1

# Rolling keystream (CONTRACT §3)
KS_MUL = 0x5851F42D4C957F2D
KS_ADD = 0x14057B7EF767814F

# FNV-1a 64 (CONTRACT §3)
FNV_OFFSET = 14695981039346656037
FNV_PRIME = 1099511628211

# Golden-ratio constant (CONTRACT §3)
GOLDEN = 0x9E3779B97F4A7C15


class VasmError(Exception):
    """Assembler / input error with a human readable message."""


# Instruction table (CONTRACT §4.2): mnemonic -> (opcode, operand_kind)
# operand_kind: None | 'imm32' | 'imm64' | 'rel32'
INSTRUCTIONS = {
    'halt':     (0x00, None),
    'push32':   (0x01, 'imm32'),
    'push64':   (0x02, 'imm64'),
    'dup':      (0x03, None),
    'drop':     (0x04, None),
    'swap':     (0x05, None),
    'add':      (0x06, None),
    'sub':      (0x07, None),
    'mul':      (0x08, None),
    'divu':     (0x09, None),
    'modu':     (0x0A, None),
    'xor':      (0x0B, None),
    'and':      (0x0C, None),
    'or':       (0x0D, None),
    'not':      (0x0E, None),
    'shl':      (0x0F, None),
    'shr':      (0x10, None),
    'cmpeq':    (0x11, None),
    'cmpne':    (0x12, None),
    'cmpltu':   (0x13, None),
    'cmpleu':   (0x14, None),
    'cmpgtu':   (0x15, None),
    'cmpgeu':   (0x16, None),
    'jmp':      (0x17, 'rel32'),
    'jz':       (0x18, 'rel32'),
    'jnz':      (0x19, 'rel32'),
    'call':     (0x1A, 'rel32'),
    'ret':      (0x1B, None),
    'load8':    (0x1C, None),
    'load32':   (0x1D, None),
    'load64':   (0x1E, None),
    'store8':   (0x1F, None),
    'store32':  (0x20, None),
    'store64':  (0x21, None),
    'setbase':  (0x22, None),
    'pushbase': (0x23, None),
    'nop':      (0x24, None),   # Phase 1d
    'lea':      (0x25, 'labs'), # Phase 1d: push 绝对地址 (label/符号)
    'pushr':    (0x26, None),   # Phase 1d: push R (通用寄存器)
    'popr':     (0x27, None),   # Phase 1d: pop -> R
    'setcon':   (0x28, None),   # Phase 1d: pop; CON = (v != 0)
    'pushcon':  (0x29, None),   # Phase 1d: push CON (条件寄存器)
    'callind':  (0x2A, None),   # Phase 1d: pop 目标地址, 压入返回地址后跳转
}

# 1 byte opcode; imm32/rel32/labs add 4 bytes; imm64 adds 8 bytes.
INSN_SIZE = {
    mnem: 1 if kind is None else (5 if kind in ('imm32', 'rel32', 'labs') else 9)
    for mnem, (_op, kind) in INSTRUCTIONS.items()
}

RESERVED_SYMBOLS = frozenset(('EXPECT1', 'EXPECT2'))

OPCODE_SLOTS = 0x2B  # canonical opcode domain: 0x00..0x2A (CONTRACT §4.2)


# ---------------------------------------------------------------------------
# 构建期 opcode 随机化 (ROADMAP Phase 1a)
# 用 img->key[1] 作种子, xorshift64 (CONTRACT §3) + Fisher-Yates 派生置换,
# Python 与 src/vm.c 用同样的确定性算法, 保证两遍还原一致。
# 语义(指令表)不变, 但每个构建产出的字节码字节值都不同。
# ---------------------------------------------------------------------------
def xorshift64(x):
    x &= M64
    x ^= (x << 13) & M64
    x ^= x >> 7
    x ^= (x << 17) & M64
    return x & M64


def make_opcode_permutation(seed):
    """Shuffle array indexed by canonical opcode -> emitted byte.
    Deterministic in `seed` (xorshift64 + Fisher-Yates); src/vm.c rebuilds
    the exact same permutation from the same seed in img->key[1]."""
    x = seed & M64
    pool = list(range(OPCODE_SLOTS))
    for i in range(OPCODE_SLOTS - 1, 0, -1):
        x = xorshift64(x)
        j = x % (i + 1)
        pool[i], pool[j] = pool[j], pool[i]
    return pool


def make_opcode_keymaps(seed):
    """(perm, slot) — ROADMAP Phase 1b 调度间接化用。

    `perm[canon]=emitted_byte` 是 Phase 1a 的取指置换;
    `slot[canon]=dispatch_slot` 是 Phase 1b 追加的第二个置换, 决定规范 opcode
    放进分发表 dt[] 的哪个槽位。两者共用**同一个 xorshift64 流**, 先派生前一个,
    结束时的 rng 状态继续直接派生后一个 —— src/vm.c vm_build_keymaps 用同一
    seed (img->key[1]) 复算, 保证两遍结果逐字节一致。"""
    x = seed & M64
    pool = list(range(OPCODE_SLOTS))
    for i in range(OPCODE_SLOTS - 1, 0, -1):
        x = xorshift64(x)
        j = x % (i + 1)
        pool[i], pool[j] = pool[j], pool[i]
    perm = pool

    pool2 = list(range(OPCODE_SLOTS))
    for i in range(OPCODE_SLOTS - 1, 0, -1):
        x = xorshift64(x)
        j = x % (i + 1)
        pool2[i], pool2[j] = pool2[j], pool2[i]
    slot = [0] * OPCODE_SLOTS
    for i, c in enumerate(pool2):
        slot[c] = i
    return perm, slot


def invert_permutation(perm):
    """inv[perm[i]] = i; all other entries 0xFF (reserved/invalid)."""
    inv = [0xFF] * 256
    for c in range(OPCODE_SLOTS):
        inv[perm[c]] = c
    return inv


# ---------------------------------------------------------------------------
# Keystream / hashing helpers (CONTRACT §3)
# ---------------------------------------------------------------------------
def keystream_byte(k):
    """Advance keystream state, return next key byte."""
    k = (k * KS_MUL + KS_ADD) & M64
    return k, (k >> 56) & 0xFF


def encrypt(plain, seed):
    """Encrypt/decrypt (XOR with rolling keystream) — symmetric."""
    k = seed
    out = bytearray()
    for b in plain:
        k, kb = keystream_byte(k)
        out.append(b ^ kb)
    return bytes(out)


def fnv1a64_serial(serial_ascii):
    h = FNV_OFFSET
    for b in serial_ascii:
        h ^= b
        h = (h * FNV_PRIME) & M64
    return h


def xorshift_mix(x):
    x &= M64
    x ^= (x << 13) & M64
    x ^= x >> 7
    x ^= (x << 17) & M64
    return x & M64


# ---------------------------------------------------------------------------
# VASM parsing / assembling
# ---------------------------------------------------------------------------
def parse_u64(tok, what='operand'):
    """Parse decimal / 0x hex / 0b binary as an unsigned 64-bit value."""
    t = tok.strip()
    if not t:
        raise VasmError('missing %s' % what)
    if t.startswith('0x') or t.startswith('0X'):
        body, base = t[2:], 16
    elif t.startswith('0b') or t.startswith('0B'):
        body, base = t[2:], 2
    else:
        body, base = t, 10
    try:
        v = int(body, base)
    except ValueError:
        raise VasmError("invalid number '%s'" % tok)
    if v > M64:
        raise VasmError("number '%s' out of uint64 range" % tok)
    return v


def parse_symbol_hex(text, name):
    """Parse an '0x...' hex string from the build json."""
    if isinstance(text, int):
        return text & M64
    if not isinstance(text, str):
        raise VasmError("field '%s' in build json must be a hex string" % name)
    s = text.strip()
    if s.startswith('0x') or s.startswith('0X'):
        s = s[2:]
    try:
        return int(s, 16) & M64
    except ValueError:
        raise VasmError("field '%s' in build json is not a hex string: %r" % (name, text))


def load_symbols(build_path):
    with open(build_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    syms = {}
    for key in ('expect1', 'expect2'):
        if key not in data:
            raise VasmError("build json %s is missing field '%s'" % (build_path, key))
        syms['EXPECT1' if key == 'expect1' else 'EXPECT2'] = parse_symbol_hex(data[key], key)
    return syms


def parse_source(text):
    """
    Split source text into statements.
    Returns list of tuples:
      ('label', name)
      ('insn', mnemonic, operand_or_None)
    `;` starts a comment anywhere on the line. Labels occupy a whole line.
    """
    stmts = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split(';', 1)[0].strip()
        if not line:
            continue
        if line.endswith(':'):
            name = line[:-1].strip()
            if not name or not name.replace('_', '').isalnum():
                raise VasmError('line %d: bad label %r' % (lineno, line))
            stmts.append(('label', name))
            continue
        parts = line.split()
        if len(parts) > 2:
            raise VasmError('line %d: too many tokens in %r' % (lineno, line))
        mnem = parts[0].lower()
        if mnem not in INSTRUCTIONS:
            raise VasmError('line %d: unknown mnemonic %r' % (lineno, mnem))
        operand = parts[1] if len(parts) == 2 else None
        stmts.append(('insn', mnem, operand))
    return stmts


def assemble_source(text, symbols, perm=None):
    """
    Two-pass assembly.
    Pass 1: collect label offsets (size of each instruction is fixed).
    Pass 2: encode opcodes + operands; jumps/calls resolve labels to rel32.
    If `perm` is given, the 1-byte opcode is emitted as perm[opcode]
    (operand bytes are untouched). Returns plaintext bytearray.
    """
    stmts = parse_source(text)

    # --- Pass 1: labels ---------------------------------------------------
    labels = {}
    offset = 0
    for st in stmts:
        if st[0] == 'label':
            name = st[1]
            if name in RESERVED_SYMBOLS:
                raise VasmError("label '%s' is reserved" % name)
            if name in labels:
                raise VasmError("duplicate label '%s'" % name)
            labels[name] = offset
        else:
            offset += INSN_SIZE[st[1]]

    # --- Pass 2: encode ----------------------------------------------------
    code = bytearray()
    for st in stmts:
        if st[0] == 'label':
            continue
        mnem, operand = st[1], st[2]
        opcode, kind = INSTRUCTIONS[mnem]
        code.append(perm[opcode] if perm is not None else opcode)
        if kind is None:
            if operand is not None:
                raise VasmError("'%s' takes no operand (got %r)" % (mnem, operand))
        elif kind in ('imm32', 'imm64'):
            if operand is None:
                raise VasmError("'%s' requires an operand" % mnem)
            if operand in symbols:
                v = symbols[operand]
            else:
                v = parse_u64(operand)
            if kind == 'imm32':
                if v > 0xFFFFFFFF:
                    raise VasmError("'%s' imm32 out of range: %s" % (mnem, operand))
                code += struct.pack('<I', v)
            else:
                code += struct.pack('<Q', v)
        elif kind == 'labs':  # Phase 1d: lea — 绝对地址 (绝对 ip, 用于间接 call)
            if operand is None:
                raise VasmError("'%s' requires an operand" % mnem)
            if operand in labels:
                v = labels[operand]
            elif operand in symbols:
                v = symbols[operand]
            else:
                raise VasmError("'%s': unknown label or symbol '%s'" % (mnem, operand))
            if v > 0xFFFFFFFF:
                raise VasmError("'%s': absolute address out of u32: %s" % (mnem, operand))
            code += struct.pack('<I', v)
        else:  # rel32
            if operand is None:
                raise VasmError("'%s' requires a target label" % mnem)
            target = labels.get(operand)
            if target is None:
                raise VasmError("'%s': unknown target '%s'" % (mnem, operand))
            next_ip = len(code) + 4  # address just past the rel32 operand
            rel = target - next_ip
            if not (-(1 << 31) <= rel < (1 << 31)):
                raise VasmError("'%s': rel32 out of range for '%s'" % (mnem, operand))
            code += struct.pack('<i', rel)
    return bytes(code)


# ---------------------------------------------------------------------------
# C output generation
# ---------------------------------------------------------------------------
def format_bytes(data, per_line=12):
    lines = []
    for i in range(0, len(data), per_line):
        chunk = data[i:i + per_line]
        lines.append('    ' + ', '.join('0x%02x' % b for b in chunk) + ',')
    return '\n'.join(lines)


def write_vm_c(out_c, out_h, plaintext, seed, key1, image_name='g_vm_image'):
    cipher = encrypt(plaintext, seed)
    crc = zlib.crc32(plaintext) & 0xFFFFFFFF
    code_len = len(plaintext)

    body = (
        '/* generated by tools/vmenc.py \u2014 do not edit */\n'
        '#include "protect/vm.h"\n'
        '\n'
        'static const uint8_t s_code[] = {\n'
        + format_bytes(cipher) + '\n'
        '};\n'
        '\n'
        'const prot_vm_image g_vm_image = {\n'
        '    s_code,\n'
        '    %du,\n'
        '    { 0x%016xULL, 0x%016xULL },\n'
        '    0x%08xu\n'
        '};\n'
    ) % (code_len, seed, key1, crc)

    header = (
        '#pragma once\n'
        '#include "protect/vm.h"\n'
        '\n'
        'extern const prot_vm_image %s;\n'
    ) % image_name

    body = body.replace('const prot_vm_image g_vm_image = {',
                        'const prot_vm_image %s = {' % image_name)

    with open(out_c, 'w', encoding='utf-8', newline='\n') as f:
        f.write(body)
    with open(out_h, 'w', encoding='utf-8', newline='\n') as f:
        f.write(header)
    return code_len, seed, crc


def cmd_assemble(args):
    with open(args.in_vasm, 'r', encoding='utf-8') as f:
        text = f.read()
    symbols = load_symbols(args.build_json)
    seed = random.getrandbits(64)
    perm_seed = random.getrandbits(64)
    perm, slot = make_opcode_keymaps(perm_seed)
    if sorted(slot) != list(range(OPCODE_SLOTS)):
        raise VasmError('internal: slot permutation is broken')
    plaintext = assemble_source(text, symbols, perm)
    image_name = getattr(args, 'name', None) or 'g_vm_image'
    code_len, seed, crc = write_vm_c(args.out_c, args.out_h, plaintext, seed,
                                     perm_seed, image_name=image_name)
    print('vmenc: assembled %d bytes (opcode perm seed=0x%016x), crc=0x%08x, key=0x%016x'
          % (code_len, perm_seed, crc, seed))
    print('vmenc: wrote %s and %s' % (args.out_c, args.out_h))


# ---------------------------------------------------------------------------
# hostid — 机器标识 (Phase 4), 与 src/hostid.c 完全一致
#   GetVolumeInformationW(C:\) 卷序列号/最大组件/Mfs flags + GetComputerNameW
#   经 FNV-1a 64 折叠。任何一侧改动必须同步。
# ---------------------------------------------------------------------------
def hostid_windows():
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=False)
    max_name = 260  # 计算机名缓冲大小
    comp = ctypes.create_unicode_buffer('', max_name)
    n = wintypes.DWORD(max_name)
    vol_serial = wintypes.DWORD()
    max_len = wintypes.DWORD()
    fs_flags = wintypes.DWORD()

    ret = kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p('C:\\'), None, 0,
        ctypes.byref(vol_serial), ctypes.byref(max_len),
        ctypes.byref(fs_flags), None, 0)
    got_vol = (ret != 0)

    got_comp = kernel32.GetComputerNameW(comp, ctypes.byref(n)) != 0

    h = HOSTID_FNV_BASIS
    if got_vol:
        h ^= vol_serial.value & HOSTID_M64
        h = (h * HOSTID_FNV_PRIME) & HOSTID_M64
        h ^= max_len.value & HOSTID_M64
        h = (h * HOSTID_FNV_PRIME) & HOSTID_M64
        h ^= fs_flags.value & HOSTID_M64
        h = (h * HOSTID_FNV_PRIME) & HOSTID_M64
    if got_comp:
        for c in comp.value:
            h ^= (ord(c) & 0xFFFF) & HOSTID_M64
            h = (h * HOSTID_FNV_PRIME) & HOSTID_M64
    h ^= h >> 32
    return h & HOSTID_M64


def hostid():
    """machine_id 算法 (与 src/hostid.c prot_hostid_get 一致). 返回 64 位整数."""
    if sys.platform == 'win32':
        return hostid_windows()
    return 0  # 非 Windows 兜底 (构建期应在 Windows 上运行)


# ---------------------------------------------------------------------------
# genserial
# ---------------------------------------------------------------------------
def compute_expect(serial, machine_id):
    """License constants — must match demo/license_vm.vasm exactly."""
    h = fnv1a64_serial(serial.encode('ascii'))
    x = xorshift_mix(h ^ (machine_id & M64))
    total = (x + GOLDEN) & M64
    return h, total


def cmd_genserial(args):
    with open(args.json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    serial = data['serial']
    if not isinstance(serial, str):
        raise VasmError('serial must be a string')
    try:
        serial.encode('ascii')
    except UnicodeEncodeError:
        raise VasmError('serial must be ASCII')

    mid = data.get('machine_id', None)
    if mid is None or mid == 0 or mid == "auto":
        # Phase 4: 默认绑定到本机真实机器标识 (与运行期 prot_hostid_get 一致)
        mid = hostid()
    if isinstance(mid, str):
        mid = parse_symbol_hex(mid, 'machine_id')
    elif not isinstance(mid, int):
        raise VasmError('machine_id must be an integer')

    h, total = compute_expect(serial, mid)
    data['expect1'] = '0x%x' % h
    data['expect2'] = '0x%x' % total
    data['machine_id'] = mid

    with open(args.json_path, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write('\n')

    if args.print:
        print('serial     = %s' % serial)
        print('machine_id = %d' % mid)
        print('expect1    = 0x%x' % h)
        print('expect2    = 0x%x' % total)


# ---------------------------------------------------------------------------
def ensure_parent(path):
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='vmenc.py',
        description='VASM assembler + VM image encryptor + genserial (Lane C)')
    sub = parser.add_subparsers(dest='cmd', required=True)

    pa = sub.add_parser('assemble', help='assemble and encrypt a .vasm file')
    pa.add_argument('in_vasm', help='input VASM source')
    pa.add_argument('build_json', help='vm_build.json with expect1/expect2')
    pa.add_argument('out_c', help='output .c file')
    pa.add_argument('out_h', help='output .h file')
    pa.add_argument('--name', default='g_vm_image',
                    help='exported prot_vm_image symbol name (default g_vm_image)')
    pa.set_defaults(func=cmd_assemble)

    pg = sub.add_parser('genserial', help='compute expect1/expect2 for a serial')
    pg.add_argument('--json', dest='json_path', required=True,
                    help='vm_build.json to read/write')
    pg.add_argument('--print', action='store_true',
                    help='print human readable result')
    pg.set_defaults(func=cmd_genserial)

    args = parser.parse_args(argv)
    try:
        if args.cmd == 'assemble':
            ensure_parent(args.out_c)
            ensure_parent(args.out_h)
        args.func(args)
    except VasmError as e:
        print('vmenc: error: %s' % e, file=sys.stderr)
        return 1
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print('vmenc: error: %s' % e, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
