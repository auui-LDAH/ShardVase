#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/vmenc.py — VASM 汇编器 + 加密器 + genserial + RSA 授权签发 (Lane C)

Two-pass VASM assembler + rolling-keystream encryptor producing a
prot_vm_image blob, plus:

  * `genserial` — 计算序列号对应的 FNV-1a/xorshift 期望常量 (serial/machine_id).
  * `keygen`    — 生成 RSA-2048 签名密钥对 (离线, 私钥不入库; e=65537 纯 Python).
  * `sign`      — 对 (serial, machine_id, product_tag) 的 SHA-256 摘要做
                  PKCS#1 v1.5 签名, 输出 license.txt (base64).
  * `pubkey`    — 从私钥文件重导出 BCRYPT_RSAPUBLIC_BLOB C 数组 (嵌入 demo).

RSA 层定位: 见 docs/PRODUCTION.md A1 / docs/THREATMODEL.md §4 —— 让"伪造合法
校验值"从可计算函数 (FNV/xorshift) 变成 RSA 私钥才能签出 (防伪造)。私钥只存
`build/keys/license_priv.json` (gitignore), 绝不提交。

Algorithms and CLI are defined in docs/CONTRACT.md (§3, §5).

CLI:
    python tools/vmenc.py assemble <in.vasm> <vm_build.json> <out.c> <out.h>
    python tools/vmenc.py genserial --json <vm_build.json> [--print]
    python tools/vmenc.py keygen --key-out <priv.json> --blob-out <pub.c>
    python tools/vmenc.py sign   --key <priv.json> --json <vm_build.json> --out <license.txt>
"""

import argparse
import base64
import ctypes
import hashlib
import json
import os
import random
import secrets
import struct
import sys
import zlib

from ctypes import wintypes

M64 = (1 << 64) - 1

# RSA 授权 (A1): 产品标识, 参与签名的载荷 (demo/main.c PROT_LICENSE_PRODUCT 必须一致)
LICENSE_PRODUCT = 'PROT-DEMO-2026'
# 分级授权 (Phase 4): tier 参与签名载荷, 防篡改。0=试用 / 1=正式(默认) / 2=增值
LICENSE_TIER_TRIAL = 0
LICENSE_TIER_FULL = 1
LICENSE_TIER_PREMIUM = 2
LICENSE_TIER_NAMES = {0: 'trial', 1: 'full', 2: 'premium'}
LICENSE_RSA_KEY_BITS = 2048            # modulus 256 字节
RSA_PUB_MAGIC = 0x31415352             # "RSA1" — BCRYPT_RSAPUBLIC_BLOB 头
# PKCS#1 v1.5 SHA-256 DigestInfo 前缀 (EMSA-PKCS1-v1_5, RFC 8017)
DIGEST_INFO_SHA256 = bytes.fromhex('3031300d060960864801650304020105000420')

# 小素数积, 加速确定性筛选 (Miller-Rabin 前先筛)
_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37,
                 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97)

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
    'brk':      (0x2B, None),   # Phase 1d-A4: 断言陷阱 — CON!=0 停机 PROT_ERR_VM_BREAKPOINT
    'move':     (0x2C, 'imm32'),# Phase 1d-A4: R = 零扩展 imm32
    'loadr32':  (0x2D, None),   # Phase 1d-A4: pop off; push mem32[BR + R + off] (寄存器索引寻址)
    'storr32':  (0x2E, None),   # Phase 1d-A4: pop val, pop off; mem32[BR + R + off] = val
}

# 1 byte opcode; imm32/rel32/labs add 4 bytes; imm64 adds 8 bytes.
INSN_SIZE = {
    mnem: 1 if kind is None else (5 if kind in ('imm32', 'rel32', 'labs') else 9)
    for mnem, (_op, kind) in INSTRUCTIONS.items()
}

RESERVED_SYMBOLS = frozenset(('EXPECT1', 'EXPECT2'))

OPCODE_SLOTS = 0x2F  # canonical opcode domain: 0x00..0x2E (CONTRACT §4.2, A4 扩 4 条)


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
    """(perm, slot, sem0, sem1) — ROADMAP Phase 1b 调度间接化 + Phase A2 语义变异。

    `perm[canon]=emitted_byte` 是 Phase 1a 的取指置换;
    `slot[canon]=dispatch_slot` 是 Phase 1b 追加的第二个置换, 决定规范 opcode
    放进分发表 dt[] 的哪个槽位。两者共用**同一个 xorshift64 流**, 先派生前一个,
    结束时的 rng 状态继续直接派生后一个 —— src/vm.c vm_build_keymaps 用同一
    seed (img->key[1]) 复算, 保证两遍结果逐字节一致。

    `sem0`/`sem1` (A2 引擎语义随构建变异): slot 派生结束后, 继续同一 rng 流
    再取两步, 抽 2 个**构建期语义微变开关**:
      sem0 = rng & 1  -> 操作数字节序: 0=LE (现行), 1=BE 高位在前。
            生成侧 (assemble_source) 按 sem0 反转 imm32/imm64/rel32/labs
            操作数字节, 执行侧 (vm.c vm_wfetch32/64) 同步反转, 语义逐位一致。
      sem1 = rng & 3  -> vm_var 等价路径折叠公式 0..3 (仅影响选哪条等价路径,
            不参与语义)。
    C 侧在同一流位置 (slot 之后、C 私有的 var 派生之前) 复算这两步, 保证一致。"""
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

    x = xorshift64(x)
    sem0 = x & 1
    x = xorshift64(x)
    sem1 = x & 3
    return perm, slot, sem0, sem1


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


def assemble_source(text, symbols, perm=None, sem0=0):
    """
    Two-pass assembly.
    Pass 1: collect label offsets (size of each instruction is fixed).
    Pass 2: encode opcodes + operands; jumps/calls resolve labels to rel32.
    If `perm` is given, the 1-byte opcode is emitted as perm[opcode]
    (operand bytes are untouched). If `sem0 != 0` (A2 构建期语义微变: 操作数
    字节序), imm32/imm64/rel32/labs 操作数字节按高位在前 (BE) 写出 ——
    src/vm.c vm_wfetch32/64 在同一构建下同步反转读回, 语义逐位一致。
    Returns plaintext bytearray.
    """
    be = (sem0 & 1) != 0  # A2: 操作数字节序微变

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
                code += struct.pack('>I' if be else '<I', v)
            else:
                code += struct.pack('>Q' if be else '<Q', v)
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
            code += struct.pack('>I' if be else '<I', v)
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
            code += struct.pack('>i' if be else '<i', rel)
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


# VM blob (DBI launcher, 技术债 #3): 镜像二进制格式与 src/blob.c 一致。
#   单镜像 .bin: NAME[16] | CODE_LEN u32 | KEY0 u64 | KEY1 u64 | CRC u32
#                | CODE[CODE_LEN]
#   打包 vm.blob:
#     v0 (旧): MAGIC "PROTVMBL" | COUNT u32 LE | entries... | BLOB_CRC u32
#     v1 (BLOB_SIGN_PLAN, 签名版): MAGIC "PROTVMB1" | COUNT u32 LE |
#         entries... | SIG_LEN u32 | SIG (256B RSA PKCS1 v1.5 SHA-256) |
#         BLOB_CRC u32 (覆盖以上全部)
#   签名消息 = [0, SIG_LEN 字段偏移) (即 MAGIC..entries)。
BLOB_MAGIC = b'PROTVMBL'
BLOB_MAGIC_V1 = b'PROTVMB1'
BLOB_NAME_LEN = 16
BLOB_ENTRY_HDR = 32


def write_vm_bin(bin_out, name, plaintext, seed, key1):
    """写出单镜像二进制 (供 pack 合并)。返回 (code_len, crc)。"""
    cipher = encrypt(plaintext, seed)
    crc = zlib.crc32(plaintext) & 0xFFFFFFFF
    name_b = name.encode('ascii')[:BLOB_NAME_LEN - 1].ljust(
        BLOB_NAME_LEN - 1, b'\x00') + b'\x00'
    entry = (name_b + struct.pack('<I', len(cipher)) +
             struct.pack('<Q', seed) + struct.pack('<Q', key1) +
             struct.pack('<I', crc) + cipher)
    with open(bin_out, 'wb') as f:
        f.write(entry)
    return len(cipher), crc


def cmd_pack(args):
    """合并多个单镜像 .bin 为 vm.blob (加 MAGIC/COUNT/尾部 CRC; --sign 加 RSA 签名)."""
    entries = b''
    for p in args.bins:
        with open(p, 'rb') as f:
            entry = f.read()
        if len(entry) < BLOB_ENTRY_HDR:
            raise VasmError('bin too small: %s' % p)
        entries += entry
    if args.sign:
        with open(args.sign, 'r', encoding='utf-8') as f:
            kd = json.load(f)
        n = int(kd['n'], 16)
        d = int(kd['d'], 16)
        body = BLOB_MAGIC_V1 + struct.pack('<I', len(args.bins)) + entries
        digest = hashlib.sha256(body).digest()
        sig = rsa_sign(d, n, digest)
        blob = body + struct.pack('<I', len(sig)) + sig
        print('vmenc: pack v1 signed (%d-byte sig)' % len(sig))
    else:
        blob = BLOB_MAGIC + struct.pack('<I', len(args.bins)) + entries
        print('vmenc: pack v0 (unsigned; --sign for RSA binding)')
    blob += struct.pack('<I', zlib.crc32(blob) & 0xFFFFFFFF)
    ensure_parent(args.out)
    with open(args.out, 'wb') as f:
        f.write(blob)
    print('vmenc: packed %d images -> %s (%d bytes)'
          % (len(args.bins), args.out, len(blob)))


# ---------------------------------------------------------------------------
# 授权吊销 (I1, 离线黑名单 revoke.blob): 格式与 src/revoke.c 一致。
#   MAGIC "PROTREVK" | VER u32 | COUNT u32
#   | 每条目: SERIAL[48] (NUL 填充) | TIER u32 (0xFF=全 tier) | REVOKED_AT u64
#   | BLOB_CRC u32 (prot_crc32 覆盖以上全部)
# ---------------------------------------------------------------------------
REVOKE_MAGIC = b'PROTREVK'
REVOKE_MAGIC_V1 = b'PROTREV1'
REVOKE_SERIAL_LEN = 48
REVOKE_ENTRY = REVOKE_SERIAL_LEN + 4 + 8


def parse_revoke_blob(path):
    """读取现有 revoke.blob (v0/v1 兼容), 返回 (ver, [entries]). 损坏/缺失 -> VasmError."""
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except OSError as e:
        raise VasmError('cannot read revoke base %s: %s' % (path, e))
    if len(data) < 20 or data[:8] not in (REVOKE_MAGIC, REVOKE_MAGIC_V1) or \
            zlib.crc32(data[:-4]) & 0xFFFFFFFF != \
            struct.unpack_from('<I', data, len(data) - 4)[0]:
        raise VasmError('revoke base %s is corrupt' % path)
    ver = struct.unpack_from('<I', data, 8)[0]
    count = struct.unpack_from('<I', data, 12)[0]
    entries = []
    pos = 16
    for _ in range(count):
        if pos + REVOKE_ENTRY > len(data) - 4:
            raise VasmError('revoke base %s is corrupt (truncated)' % path)
        serial = data[pos:pos + REVOKE_SERIAL_LEN].split(b'\x00', 1)[0]
        tier = struct.unpack_from('<I', data, pos + REVOKE_SERIAL_LEN)[0]
        at = struct.unpack_from('<Q', data, pos + REVOKE_SERIAL_LEN + 4)[0]
        entries.append((serial.decode('ascii', 'replace'), tier, at))
        pos += REVOKE_ENTRY
    return ver, entries


def cmd_revoke(args):
    """生成/追加 revoke.blob: --base 读旧黑名单 (版本+1), --add 追加一条.
    --sign: 输出 v1 签名格式 (BLOB_SIGN_PLAN): MAGIC PROTREV1 + SIG. """
    ver = 1
    entries = []
    if args.base:
        ver, entries = parse_revoke_blob(args.base)
        ver += 1
    if args.add:
        serial = args.add.encode('ascii')
        if len(serial) >= REVOKE_SERIAL_LEN:
            raise VasmError('serial too long for revoke entry (<= %d)'
                            % (REVOKE_SERIAL_LEN - 1))
        tier = args.tier if args.tier is not None else 0xFF
        at = args.at if args.at is not None else 0
        entries.append((serial.decode('ascii'), tier, at))
    if args.force_ver is not None:
        ver = args.force_ver
    magic = REVOKE_MAGIC_V1 if args.sign else REVOKE_MAGIC
    body = (magic + struct.pack('<I', ver) +
            struct.pack('<I', len(entries)))
    for serial, tier, at in entries:
        body += (serial.encode('ascii').ljust(REVOKE_SERIAL_LEN, b'\x00') +
                 struct.pack('<I', tier) + struct.pack('<Q', at))
    if args.sign:
        with open(args.sign, 'r', encoding='utf-8') as f:
            kd = json.load(f)
        n = int(kd['n'], 16)
        d = int(kd['d'], 16)
        digest = hashlib.sha256(body).digest()
        sig = rsa_sign(d, n, digest)
        body += struct.pack('<I', len(sig)) + sig
        print('vmenc: revoke v1 signed (%d-byte sig)' % len(sig))
    blob = body + struct.pack('<I', zlib.crc32(body) & 0xFFFFFFFF)
    ensure_parent(args.out)
    with open(args.out, 'wb') as f:
        f.write(blob)
    print('vmenc: revoke ver=%d entries=%d -> %s (%d bytes)'
          % (ver, len(entries), args.out, len(blob)))


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


def cmd_issue(args):
    """签发 + 强制写签发日志 (OPS §2): 与 sign 相同签名逻辑, 追加 issue-log.csv."""
    with open(args.key_path, 'r', encoding='utf-8') as f:
        kd = json.load(f)
    n = int(kd['n'], 16)
    d = int(kd['d'], 16)
    with open(args.json_path, 'r', encoding='utf-8') as f:
        jd = json.load(f)
    serial = jd['serial']
    mid = args.machine_id_override
    if mid is None:
        mid = jd.get('machine_id', None)
    if mid is None or mid == 0 or mid in ('auto', '0'):
        mid = hostid()
    elif isinstance(mid, str):
        mid = parse_machine_id_override(mid)
    tier = args.tier
    expires = args.expires or 0
    digest = _license_sha256(serial, mid, tier, expires)
    sig = rsa_sign(d, n, digest)
    out = [
        'SERIAL=' + serial,
        'MACHINE_ID=0x%x' % mid,
        'PRODUCT=' + LICENSE_PRODUCT,
        'TIER=%d' % tier,
        'EXPIRES=%d' % expires,
        'SIGNATURE=' + base64.b64encode(sig).decode('ascii'),
        '',
    ]
    ensure_parent(args.license_out)
    with open(args.license_out, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(out))

    # 签发日志 (只增不改, gitignore)
    import datetime
    sha = hashlib.sha256(open(args.license_out, 'rb').read()).hexdigest()
    row = '%s,%s,0x%x,%d,%s,%s,%s\n' % (
        datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
        serial, mid, tier, args.customer, args.note, sha)
    log_path = args.log
    ensure_parent(log_path)
    with open(log_path, 'a', encoding='utf-8', newline='\n') as f:
        f.write(row)
    print('vmenc: issue serial=%s tier=%d expires=%d customer=%s -> %s'
          % (serial, tier, expires, args.customer, args.license_out))
    print('vmenc: issue log appended: %s' % log_path)


def cmd_assemble(args):
    with open(args.in_vasm, 'r', encoding='utf-8') as f:
        text = f.read()
    symbols = load_symbols(args.build_json)
    # RELEASE I3: --seed/--perm-seed 注入确定性种子 (同种子两次构建逐字节一致)
    seed = args.seed if args.seed is not None else random.getrandbits(64)
    perm_seed = args.perm_seed if args.perm_seed is not None \
        else random.getrandbits(64)
    perm, slot, sem0, sem1 = make_opcode_keymaps(perm_seed)
    if sorted(slot) != list(range(OPCODE_SLOTS)):
        raise VasmError('internal: slot permutation is broken')
    plaintext = assemble_source(text, symbols, perm, sem0)
    image_name = getattr(args, 'name', None) or 'g_vm_image'
    code_len, seed, crc = write_vm_c(args.out_c, args.out_h, plaintext, seed,
                                     perm_seed, image_name=image_name)
    bin_out = getattr(args, 'bin_out', None)
    if bin_out:
        if not args.bin_name:
            raise VasmError('--bin-name is required with --bin-out')
        if len(args.bin_name) >= BLOB_NAME_LEN:
            raise VasmError('--bin-name too long (<= %d): %s'
                            % (BLOB_NAME_LEN - 1, args.bin_name))
        write_vm_bin(bin_out, args.bin_name, plaintext, seed, perm_seed)
    print('vmenc: assembled %d bytes (opcode perm seed=0x%016x, sem=[%d,%d]), crc=0x%08x, key=0x%016x'
          % (code_len, perm_seed, sem0, sem1, crc, seed))
    print('vmenc: wrote %s and %s' % (args.out_c, args.out_h))


# ---------------------------------------------------------------------------
# hostid — 机器标识 (Phase 4), 与 src/hostid.c 完全一致
#   GetVolumeInformationW(C:\) 卷序列号/最大组件/Mfs flags + GetComputerNameW
#   经 FNV-1a 64 折叠。任何一侧改动必须同步。
# ---------------------------------------------------------------------------
def hostid_windows():
    """与 src/hostid.c prot_hostid_get 完全一致 (D5 硬件因子):
      卷序列号+计算机名 (原有) + SMBIOS UUID + 磁盘物理序列号 (新增)。
      任何一侧改动必须同步。"""
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

    # D5: MachineGuid (Windows 安装唯一 ID)
    guid = machine_guid_string()
    if guid is not None:
        for b in guid.encode('ascii', 'replace'):
            h ^= b & HOSTID_M64
            h = (h * HOSTID_FNV_PRIME) & HOSTID_M64

    # D5: 磁盘物理序列号 (\\.\PhysicalDrive0 + IOCTL_STORAGE_QUERY_PROPERTY)
    dserial = disk_serial_string()
    if dserial is not None:
        for b in dserial.encode('ascii', 'replace'):
            h ^= b & HOSTID_M64
            h = (h * HOSTID_FNV_PRIME) & HOSTID_M64

    h ^= h >> 32
    return h & HOSTID_M64


def machine_guid_string():
    """HKLM SOFTWARE Microsoft Cryptography MachineGuid (Windows install ID).
    与 src/hostid.c machine_guid 一致; 失败返回 None."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r'SOFTWARE\Microsoft\Cryptography') as k:
            v, _ = winreg.QueryValueEx(k, 'MachineGuid')
            return str(v)
    except Exception:
        return None


def disk_serial_string():
    """系统盘物理序列号 (IOCTL_STORAGE_QUERY_PROPERTY); 失败返回 None.
    与 src/hostid.c disk_serial 一致 (同一 STORAGE_DEVICE_DESCRIPTOR 布局)."""
    try:
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=False)
        kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                         wintypes.DWORD, ctypes.c_void_p,
                                         wintypes.DWORD, wintypes.DWORD,
                                         ctypes.c_void_p]
        kernel32.CreateFileW.restype = ctypes.c_void_p
        kernel32.DeviceIoControl.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p]
        kernel32.DeviceIoControl.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = wintypes.BOOL

        class StorageDeviceDescriptor(ctypes.Structure):
            # 布局与本机 SDK 编译的 STORAGE_DEVICE_DESCRIPTOR 一致
            # (offsetof 实测: Vendor@12 Prod@16 Rev@20 Serial@24 ——
            #  该版本无 DeviceTypeModifier/RemovableMedia/CommandQueueing)
            _pack_ = 1
            _fields_ = [
                ('Version', wintypes.DWORD),
                ('Size', wintypes.DWORD),
                ('DeviceType', wintypes.DWORD),
                ('VendorIdOffset', wintypes.DWORD),
                ('ProductIdOffset', wintypes.DWORD),
                ('ProductRevisionOffset', wintypes.DWORD),
                ('SerialNumberOffset', wintypes.DWORD),
            ]

        IOCTL_STORAGE_QUERY_PROPERTY = 0x2D1400
        INVALID_HANDLE_VALUE = 0xFFFFFFFFFFFFFFFF
        h = kernel32.CreateFileW(ctypes.c_wchar_p('\\\\.\\PhysicalDrive0'), 0,
                                 1 | 2, None, 3, 0, None)
        if h in (None, 0, INVALID_HANDLE_VALUE):
            return None
        try:
            # STORAGE_PROPERTY_QUERY: PropertyId u32 + QueryType u32 +
            # AdditionalParameters[1] (12 字节)
            q = (ctypes.c_ulong * 3)(0, 0, 0)
            buf = ctypes.create_string_buffer(1024)
            ret = wintypes.DWORD(0)
            ok = kernel32.DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
                                          q, ctypes.sizeof(q), buf,
                                          len(buf), ctypes.byref(ret), None)
            if not ok:
                return None
            d = StorageDeviceDescriptor.from_buffer_copy(buf.raw[:64])
            off = d.SerialNumberOffset
            if 0 < off < len(buf.raw) - 1:
                return buf.raw[off:].split(b'\x00', 1)[0].decode('ascii',
                                                                 'replace')
            return None
        finally:
            kernel32.CloseHandle(h)
    except Exception:
        return None


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


def parse_machine_id_override(text):
    """Override 解析: 十进制, 或 0x 前缀十六进制; 保持与 json 整数一致."""
    if isinstance(text, int):
        return text & HOSTID_M64
    s = text.strip()
    base = 16 if (s.startswith('0x') or s.startswith('0X')) else 10
    try:
        if base == 16:
            s = s[2:]
        return int(s, base) & HOSTID_M64 if s else 0
    except ValueError:
        raise VasmError("machine_id override is not an integer: %r" % text)


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

    mid = args.machine_id_override
    if mid is None:
        mid = data.get('machine_id', None)
    if mid is None or mid == 0 or mid in ('auto', '0'):
        # Phase 4: 默认绑定到本机真实机器标识 (与运行期 prot_hostid_get 一致)
        mid = hostid()
    elif isinstance(mid, str) and mid not in ('auto', '0'):
        mid = parse_machine_id_override(mid)
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


# ---------------------------------------------------------------------------
# RSA 授权签发 (ROADMAP Phase A1 / PRODUCTION A1, 纯 Python e=65537)
# 私钥只写 build/keys/license_priv.json (gitignore), 绝不入库;
# 公钥以 BCRYPT_RSAPUBLIC_BLOB 导出为 C 数组嵌入 demo (src/license.c 用 BCrypt 验签)。
# ---------------------------------------------------------------------------
def _is_prime(n):
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if a >= n:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits):
    while True:
        v = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(v):
            return v


def rsa_gen_keypair(bits=LICENSE_RSA_KEY_BITS):
    """RSA-2048 密钥对: (n, e, d). e=65537. p/q 各 1024 位."""
    e = 65537
    while True:
        p = _gen_prime(bits // 2)
        q = _gen_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        n = p * q
        try:
            d = pow(e, -1, phi)
        except ValueError:
            continue  # gcd(e, phi) != 1 重试
        return n, e, d


def rsa_pub_blob(n, e=65537):
    """BCRYPT_RSAPUBLIC_BLOB (Windows 实测布局):
    16 字节头 <IIII> LE + 8 字节对齐填充 + exponent BE + modulus BE.
    exponent 对齐到 8 字节边界后, 长度取位对数 (65537 -> 3 字节 01 00 01)."""
    eb = e.to_bytes((e.bit_length() + 7) // 8, 'big')
    nb = n.to_bytes(LICENSE_RSA_KEY_BITS // 8, 'big')
    return (struct.pack('<IIII', RSA_PUB_MAGIC, LICENSE_RSA_KEY_BITS,
                        len(eb), len(nb)) + b'\x00' * 8 + eb + nb)


def _der_len(n):
    """DER length bytes for value of n bytes (short/long form)."""
    if n < 0x80:
        return bytes([n])
    nb = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(nb)]) + nb


def rsa_pub_spki_der(n, e=65537):
    """SubjectPublicKeyInfo DER (Android JCA X509EncodedKeySpec / iOS SecKey):
       rsaEncryption OID 1.2.840.113549.1.1.1 + BIT STRING RSAPublicKey.
    EXTENSION_PLAN C1: 跨平台公钥 (Android/JCA, iOS/SecKey)。"""
    # RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    eb = e.to_bytes((e.bit_length() + 7) // 8, 'big')
    nb = n.to_bytes(LICENSE_RSA_KEY_BITS // 8, 'big')
    if nb[0] & 0x80:  # modulus 高位为 1 需前置 0 (INTEGER 有符号)
        nb = b'\x00' + nb
    mod_int = b'\x02' + _der_len(len(nb)) + nb
    exp_int = b'\x02' + _der_len(len(eb)) + eb
    rsa_pub = b'\x30' + _der_len(len(mod_int) + len(exp_int)) + mod_int + exp_int
    # AlgorithmIdentifier: rsaEncryption
    oid = b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01'
    alg = b'\x30' + _der_len(len(oid) + 2) + oid + b'\x05\x00'
    # BIT STRING (0 unused bits)
    bit = b'\x03' + _der_len(1 + len(rsa_pub)) + b'\x00' + rsa_pub
    return b'\x30' + _der_len(len(alg) + len(bit)) + alg + bit


def emsa_pkcs1_v1_5(digest_sha256):
    """EMSA-PKCS1-v1_5 编码 (k=256), 接收 32 字节 SHA-256."""
    t = DIGEST_INFO_SHA256 + digest_sha256
    pslen = (LICENSE_RSA_KEY_BITS // 8) - len(t) - 3
    if pslen < 8:
        raise VasmError('emsa pkcs1: insufficient modulus length')
    return b'\x00\x01' + (b'\xff' * pslen) + b'\x00' + t


def rsa_sign(d, n, digest_sha256):
    """私钥 (d, n) 对 32 字节 SHA-256 摘要签名, 返回 256 字节 sig."""
    em = emsa_pkcs1_v1_5(digest_sha256)
    m = int.from_bytes(em, 'big')
    s = pow(m, d, n)
    return s.to_bytes(LICENSE_RSA_KEY_BITS // 8, 'big')


def license_message(serial, machine_id, tier=LICENSE_TIER_FULL, expires=0):
    """签名载荷: serial ascii + LE64(machine_id) + PRODUCT + tier(1B)
    + expires(4B LE, unix, 0=永久) — Phase 4 试用期控制。
    demo/main.c 运行期按同一规则构建 (prot_license_build_message)。"""
    product_b = LICENSE_PRODUCT.encode('ascii')
    return (serial.encode('ascii') + struct.pack('<Q', machine_id) +
            product_b + bytes([tier & 0xFF]) + struct.pack('<I', expires & 0xFFFFFFFF))


def _license_sha256(serial, machine_id, tier=LICENSE_TIER_FULL, expires=0):
    return hashlib.sha256(license_message(serial, machine_id, tier, expires)).digest()


def cmd_keygen(args):
    """生成/复用私钥, 并导出公钥 BCRYPT_RSAPUBLIC_BLOB 为 C 数组."""
    key_path = args.key_out
    if os.path.isfile(key_path):
        with open(key_path, 'r', encoding='utf-8') as f:
            kd = json.load(f)
        n = int(kd['n'], 16)
        e = int(kd['e'])
    else:
        n, e, _d = rsa_gen_keypair()
        d_hex = hex(_d)
        kd = {'n': hex(n), 'e': e, 'd': d_hex, 'bits': LICENSE_RSA_KEY_BITS}
        ensure_parent(key_path)
        with open(key_path, 'w', encoding='utf-8', newline='\n') as f:
            json.dump(kd, f, ensure_ascii=False, indent=2)
            f.write('\n')
        print('vmenc: keygen 2048-bit, n=%d bits' % n.bit_length())
    blob = rsa_pub_blob(n, e)
    lines = [', '.join('0x%02x' % b for b in blob[i:i + 12]) + ','
             for i in range(0, len(blob), 12)]
    body = (
        '/* generated by tools/vmenc.py keygen — do not edit */\n'
        '#include <stdint.h>\n'
        '\n'
        'const uint8_t g_prot_license_pubblob[] = {\n'
        + '\n'.join('    ' + l for l in lines) + '\n'
        '};\n'
        '\n'
        'const size_t g_prot_license_pubblob_len = sizeof(g_prot_license_pubblob);\n'
    )
    ensure_parent(args.blob_out)
    with open(args.blob_out, 'w', encoding='utf-8', newline='\n') as f:
        f.write(body)
    print('vmenc: wrote public-key blob %s (%d bytes)' % (args.blob_out, len(blob)))

    # EXTENSION_PLAN C1: 导出 DER SPKI 公钥 (Android JCA / iOS SecKey)
    if getattr(args, 'blob_out_der', None):
        der = rsa_pub_spki_der(n, e)
        lines_d = [', '.join('0x%02x' % b for b in der[i:i + 12]) + ','
                   for i in range(0, len(der), 12)]
        body_d = (
            '/* generated by tools/vmenc.py keygen — do not edit */\n'
            '#include <stdint.h>\n'
            '\n'
            'const uint8_t g_prot_pubkey_der[] = {\n'
            + '\n'.join('    ' + l for l in lines_d) + '\n'
            '};\n'
            '\n'
            'const size_t g_prot_pubkey_der_len = sizeof(g_prot_pubkey_der);\n'
        )
        ensure_parent(args.blob_out_der)
        with open(args.blob_out_der, 'w', encoding='utf-8', newline='\n') as f:
            f.write(body_d)
        print('vmenc: wrote DER SPKI public key %s (%d bytes)'
              % (args.blob_out_der, len(der)))


def cmd_sign(args):
    """对当前 serial/machine_id/tier (json + --tier) 生成 license.txt (base64 sig)."""
    with open(args.key_path, 'r', encoding='utf-8') as f:
        kd = json.load(f)
    n = int(kd['n'], 16)
    e = int(kd['e'])
    d = int(kd['d'], 16)
    with open(args.json_path, 'r', encoding='utf-8') as f:
        jd = json.load(f)
    serial = jd['serial']
    mid = args.machine_id_override
    if mid is None:
        mid = jd.get('machine_id', None)
    if mid is None or mid == 0 or mid in ('auto', '0'):
        mid = hostid()
    elif isinstance(mid, str):
        mid = parse_machine_id_override(mid)
    tier = args.tier
    expires = args.expires or 0
    digest = _license_sha256(serial, mid, tier, expires)
    sig = rsa_sign(d, n, digest)
    out = [
        'SERIAL=' + serial,
        'MACHINE_ID=0x%x' % mid,
        'PRODUCT=' + LICENSE_PRODUCT,
        'TIER=%d' % tier,
        'EXPIRES=%d' % expires,
        'SIGNATURE=' + base64.b64encode(sig).decode('ascii'),
        '',
    ]
    ensure_parent(args.license_out)
    with open(args.license_out, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(out))
    if args.print:
        print('signed license: serial=%s machine=0x%x product=%s tier=%d (%s) expires=%d'
              % (serial, mid, LICENSE_PRODUCT, tier,
                 LICENSE_TIER_NAMES.get(tier, '?'), expires))
        print('   sig=%s' % ('%d bytes' % len(sig)))
    print('vmenc: wrote %s' % args.license_out)


# ---------------------------------------------------------------------------
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
    pa.add_argument('--bin-out', dest='bin_out', default=None,
                    help='also write single-image binary (for vmenc pack, '
                         'DBI launcher)')
    pa.add_argument('--bin-name', dest='bin_name', default=None,
                    help='image name inside the .bin/blob (short, <=15; '
                         'required with --bin-out)')
    pa.add_argument('--seed', dest='seed', type=lambda s: int(s, 0),
                    default=None,
                    help='deterministic key0 (hex/dec; default random) '
                         '(RELEASE I3 reproducible builds)')
    pa.add_argument('--perm-seed', dest='perm_seed',
                    type=lambda s: int(s, 0), default=None,
                    help='deterministic opcode perm seed key1 (hex/dec; '
                         'default random)')
    pa.set_defaults(func=cmd_assemble)

    pb = sub.add_parser('pack', help='pack single-image bins into vm.blob')
    pb.add_argument('--out', dest='out', required=True,
                    help='output vm.blob')
    pb.add_argument('--sign', dest='sign', default=None,
                    help='RSA private key JSON (keygen output) -> v1 signed '
                         'blob (BLOB_SIGN_PLAN)')
    pb.add_argument('bins', nargs='+',
                    help='single-image .bin files (assemble --bin-out)')
    pb.set_defaults(func=cmd_pack)

    pr = sub.add_parser('revoke', help='generate/append revoke.blob (I1)')
    pr.add_argument('--out', dest='out', required=True,
                    help='output revoke.blob')
    pr.add_argument('--base', dest='base', default=None,
                    help='existing revoke.blob to extend (version +1)')
    pr.add_argument('--sign', dest='sign', default=None,
                    help='RSA private key JSON -> v1 signed revoke '
                         '(BLOB_SIGN_PLAN)')
    pr.add_argument('--add', dest='add', default=None,
                    help='serial to revoke')
    pr.add_argument('--tier', dest='tier', type=int, default=None,
                    help='tier to revoke (0/1/2; default 0xFF = all tiers)')
    pr.add_argument('--at', dest='at', type=int, default=None,
                    help='revoked-at unix timestamp (default 0)')
    pr.add_argument('--force-ver', dest='force_ver', type=int, default=None,
                    help='override blacklist version')
    pr.set_defaults(func=cmd_revoke)

    pg = sub.add_parser('genserial', help='compute expect1/expect2 for a serial')
    pg.add_argument('--json', dest='json_path', required=True,
                    help='vm_build.json to read/write')
    pg.add_argument('--machine-id', dest='machine_id_override', type=str,
                    default=None,
                    help='override machine_id (decimal or 0x hex, or "auto"); '
                         'omit/auto to bind host id (Phase 4)')
    pg.add_argument('--print', action='store_true',
                    help='print human readable result')
    pg.set_defaults(func=cmd_genserial)

    pk = sub.add_parser('keygen', help='generate/reuse RSA-2048 signing keypair')
    pk.add_argument('--key-out', dest='key_out', required=True,
                    help='output private key JSON (gitignored)')
    pk.add_argument('--blob-out', dest='blob_out', required=True,
                    help='output public-key BCRYPT blob .c (embedded)')
    pk.add_argument('--blob-out-der', dest='blob_out_der', default=None,
                    help='output DER SPKI public key .c (Android JCA / iOS '
                         'SecKey, EXTENSION_PLAN C1)')
    pk.set_defaults(func=cmd_keygen)

    ps = sub.add_parser('sign', help='sign serial+machine_id+tier into license.txt')
    ps.add_argument('--key', dest='key_path', required=True,
                    help='private key JSON from keygen')
    ps.add_argument('--json', dest='json_path', required=True,
                    help='vm_build.json with serial/machine_id')
    ps.add_argument('--out', dest='license_out', required=True,
                    help='output license.txt')
    ps.add_argument('--machine-id', dest='machine_id_override', type=str,
                    default=None,
                    help='override machine_id (decimal or 0x hex); omit/auto=hostid')
    ps.add_argument('--tier', dest='tier', type=int, default=LICENSE_TIER_FULL,
                    help='license tier: 0=trial 1=full(default) 2=premium (Phase 4)')
    ps.add_argument('--expires', dest='expires', type=int, default=0,
                    help='expiry unix timestamp (0=permanent; trial control)')
    ps.add_argument('--print', action='store_true',
                    help='print human readable result')
    ps.set_defaults(func=cmd_sign)

    pi = sub.add_parser('issue', help='sign + append-only issue log (OPS §2)')
    pi.add_argument('--key', dest='key_path', required=True,
                    help='private key JSON from keygen')
    pi.add_argument('--json', dest='json_path', required=True,
                    help='vm_build.json with serial/machine_id')
    pi.add_argument('--out', dest='license_out', required=True,
                    help='output license.txt')
    pi.add_argument('--tier', dest='tier', type=int, default=LICENSE_TIER_FULL,
                    help='license tier: 0=trial 1=full(default) 2=premium')
    pi.add_argument('--expires', dest='expires', type=int, default=0,
                    help='expiry unix timestamp (0=permanent; trial control)')
    pi.add_argument('--machine-id', dest='machine_id_override', type=str,
                    default=None,
                    help='override machine_id (decimal or 0x hex); omit/auto=hostid')
    pi.add_argument('--customer', dest='customer', default='-',
                    help='customer id/name for the log')
    pi.add_argument('--note', dest='note', default='',
                    help='free-form note for the log')
    pi.add_argument('--log', dest='log', default='build/issue-log.csv',
                    help='append-only issue log (default build/issue-log.csv)')
    pi.set_defaults(func=cmd_issue)

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
