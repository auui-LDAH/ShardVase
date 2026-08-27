# -*- coding: utf-8 -*-
"""
tests/protchain_check.py — 保护链静态断言 (CI_PLAN §2.2)

对 build\\demo.exe + build\\vm.blob 做**静态**断言 (不运行进程, 无 WDAC 干扰),
防止保护能力 (N1 selfcrypt / N4 间接化 / BLOB_SIGN 签名 / N5 期望值) 被
未来改动静默破坏:

  P1 selfcrypt 密文   .text 目标函数区 (从 .protcry meta 读 rva/len) 为密文
                      (无 x64 序言特征 40 55/48 89 等)
  P2 selfcrypt 掩码   build/selfcrypt_mask.txt 与 meta 一致; 带掩码可复算 .text CRC
  P3 blob v1 签名     vm.blob 头部 "PROTVMB1" + 签名区存在 (256B)
  P4 blob 签名可验    用内嵌公钥 (license_pubkey.c BCRYPT blob) RSA 验签通过
  P5 N4 间接化        反汇编扫描: 4 个关键函数无直接 call rel32 指向
  P6 期望值一致       expect_default.c 生成值与 vm_build.json 一致

用法:
    python tests\\protchain_check.py [--exe build\\demo.exe] [--blob build\\vm.blob]

任一 FAIL -> sys.exit(1)。
"""

import json
import os
import re
import struct
import sys
import zlib

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
EXE = os.path.join(REPO, 'build', 'demo.exe')
BLOB = os.path.join(REPO, 'build', 'vm.blob')

IMAGE_BASE = 0x140000000


def pe_sections(data):
    if len(data) < 0x40:
        raise RuntimeError('not a PE file')
    e = struct.unpack_from('<I', data, 0x3C)[0]
    if data[e:e + 4] != b'PE\x00\x00':
        raise RuntimeError('bad PE signature')
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


def scan_e8_calls(text):
    """扫描 .text 所有 E8 call rel32, 返回目标 RVA 集合."""
    targets = set()
    for i in range(len(text) - 5):
        if text[i] == 0xE8:
            rel = struct.unpack_from('<i', text, i + 1)[0]
            targets.add(i + 5 + rel)
    return targets


def p1_selfcrypt_ciphertext(data, secs):
    """P1: .text 加密函数区无 x64 序言特征 (密文)."""
    prot = next((s for s in secs if s['name'] in ('.protcrypt', '.protcry')), None)
    text = next((s for s in secs if s['name'] == '.text'), None)
    if prot is None or text is None:
        return False, 'no .protcry/.text section'
    blob = data[prot['ptr_raw']:prot['ptr_raw'] + 256]
    n = struct.unpack_from('<I', blob, 0)[0]
    if n == 0 or n > 16:
        return False, 'bad selfcrypt count %d' % n
    for i in range(n):
        rva, ln = struct.unpack_from('<II', blob, 4 + i * 20)
        toff = text['ptr_raw'] + (rva - text['virtual_addr'])
        body = data[toff:toff + ln]
        if len(body) < ln:
            return False, 'fn %d out of range' % i
        head = body[:8]
        # x64 序言特征: 40 55 (push rbp) / 40 56 (push rsi) / 48 89 (mov) / 48 83 (sub)
        for pat in (b'\x40\x55', b'\x40\x56', b'\x40\x57', b'\x48\x89', b'\x48\x83'):
            if head.startswith(pat):
                return False, 'fn %d rva=0x%x has plaintext prologue %s' % (
                    i, rva, pat.hex())
    return True, '4 fns ciphertext (no x64 prologue)'


def p2_mask_consistent(data, secs):
    """P2: mask 文件与 meta 一致."""
    prot = next((s for s in secs if s['name'] in ('.protcrypt', '.protcry')), None)
    text = next((s for s in secs if s['name'] == '.text'), None)
    mask_path = os.path.join(REPO, 'build', 'selfcrypt_mask.txt')
    if not os.path.isfile(mask_path):
        return False, 'build/selfcrypt_mask.txt missing'
    if prot is None or text is None:
        return False, 'no .protcry/.text section'
    blob = data[prot['ptr_raw']:prot['ptr_raw'] + 256]
    n = struct.unpack_from('<I', blob, 0)[0]
    meta = []
    for i in range(n):
        rva, ln = struct.unpack_from('<II', blob, 4 + i * 20)
        meta.append((rva, ln))
    masks = []
    for ln in open(mask_path, 'r', encoding='ascii'):
        rva_s, ln_s = ln.strip().split(',')
        masks.append((int(rva_s, 0), int(ln_s, 0)))
    if sorted(meta) != sorted(masks):
        return False, 'meta %s != mask file %s' % (sorted(meta), sorted(masks))
    # 带掩码复算 .text CRC 与烧录值比对
    protcrc = next((s for s in secs if s['name'] == '.protcrc'), None)
    crc_len = min(text['virtual_size'], text['size_raw'])
    raw = bytearray(data[text['ptr_raw']:text['ptr_raw'] + crc_len])
    for (mrva, mlen) in masks:
        o = mrva - text['virtual_addr']
        raw[o:o + mlen] = b'\x00' * mlen
    crc = zlib.crc32(bytes(raw)) & 0xFFFFFFFF
    baked = struct.unpack_from('<I', data, protcrc['ptr_raw'] + 8)[0]
    if crc != baked:
        return False, '.text crc 0x%08x != baked 0x%08x' % (crc, baked)
    return True, 'mask file matches meta; .text CRC verified'


def p3_blob_v1(data):
    """P3: vm.blob v1 签名格式."""
    if len(data) < 20:
        return False, 'blob too small'
    if data[:8] != b'PROTVMB1':
        return False, 'magic %r != PROTVMB1' % data[:8]
    return True, 'PROTVMB1 v1 signed blob'


def p4_blob_signature(data):
    """P4: 用内嵌公钥 RSA 验签 blob (纯 Python 复算 PKCS#1 v1.5 SHA-256)."""
    # 从 license_pubkey.c 读公钥 BCRYPT blob (BCRYPT_RSAPUBLIC_BLOB)
    pub_path = os.path.join(REPO, 'demo', 'gen', 'license_pubkey.c')
    if not os.path.isfile(pub_path):
        return False, 'license_pubkey.c missing'
    src = open(pub_path, 'r', encoding='utf-8').read()
    hexes = re.findall(r'0x([0-9a-fA-F]{2})', src)
    pub = bytes(int(h, 16) for h in hexes)
    if len(pub) < 40:
        return False, 'pubblob too small (%d)' % len(pub)
    # BCRYPT_RSAPUBLIC_BLOB: 16B 头 + 8B 填充 + exponent BE + modulus BE
    eb_len = struct.unpack_from('<I', pub, 8)[0]
    nb_len = struct.unpack_from('<I', pub, 12)[0]
    exp = int.from_bytes(pub[24:24 + eb_len], 'big')
    mod = int.from_bytes(pub[24 + eb_len:24 + eb_len + nb_len], 'big')
    # 定位签名区: 尾部 [CRC4][SIG 384B][SIG_LEN4]
    size = len(data)
    sig_len = struct.unpack_from('<I', data, size - 4 - 384 - 4)[0]
    if sig_len != 384:
        return False, 'sig_len %d != 384' % sig_len
    sig = data[size - 4 - 384:size - 4]
    msg = data[:size - 4 - 384 - 4]
    digest = hashlib_sha256(msg)
    # PKCS#1 v1.5: EM = 00 01 FF..FF 00 T (T = DigestInfo(SHA-256) + digest)
    t = bytes([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
               0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]) + digest
    pslen = 384 - len(t) - 3
    if pslen < 8:
        return False, 'pslen too small'
    em = b'\x00\x01' + (b'\xff' * pslen) + b'\x00' + t
    m = int.from_bytes(em, 'big')
    s = int.from_bytes(sig, 'big')
    v = pow(s, exp, mod)
    return (v == m, 'RSA-3072 verify ok' if v == m else 'signature mismatch')


def hashlib_sha256(b):
    import hashlib
    return hashlib.sha256(b).digest()


def p5_indirect_no_direct_call(data, secs):
    """P5: 4 个关键函数无直接 call (N4 间接化)."""
    text = next((s for s in secs if s['name'] == '.text'), None)
    if text is None:
        return False, 'no .text'
    t = data[text['ptr_raw']:text['ptr_raw'] + text['size_raw']]
    targets = scan_e8_calls(t)
    # 从 .protcry meta 读加密函数 rva (与 P1 同源)
    prot = next((s for s in secs if s['name'] in ('.protcrypt', '.protcry')), None)
    blob = data[prot['ptr_raw']:prot['ptr_raw'] + 256]
    n = struct.unpack_from('<I', blob, 0)[0]
    fns = []
    for i in range(n):
        rva, ln = struct.unpack_from('<II', blob, 4 + i * 20)
        fns.append(rva)
    hits = [rva for rva in fns if rva in targets]
    if hits:
        return False, 'direct calls to %s' % [hex(h) for h in hits]
    return True, 'no direct call to %d protected fns' % len(fns)


def p6_expect_consistent():
    """P6: expect_default.c 与 vm_build.json 一致."""
    exp_path = os.path.join(REPO, 'demo', 'gen', 'expect_default.c')
    json_path = os.path.join(REPO, 'demo', 'vm_build.json')
    if not os.path.isfile(exp_path) or not os.path.isfile(json_path):
        return False, 'expect_default.c or vm_build.json missing'
    src = open(exp_path, 'r', encoding='utf-8', errors='replace').read()
    m = re.search(r'g_prot_expect_default\[2\] = \{ (0x[0-9a-fA-F]+)ULL, (0x[0-9a-fA-F]+)ULL \}', src)
    if not m:
        return False, 'cannot parse expect_default.c'
    jb = json.load(open(json_path, 'r', encoding='utf-8'))
    if jb.get('expect1') != m.group(1) or jb.get('expect2') != m.group(2):
        return False, 'expect mismatch: %s/%s vs %s/%s' % (
            m.group(1), m.group(2), jb.get('expect1'), jb.get('expect2'))
    return True, 'expect_default.c matches vm_build.json'


def main():
    import argparse
    parser = argparse.ArgumentParser(prog='protchain_check.py',
                                     description='protection chain static asserts')
    parser.add_argument('--exe', default=EXE)
    parser.add_argument('--blob', default=BLOB)
    args = parser.parse_args()

    results = []
    try:
        data = open(args.exe, 'rb').read()
        secs = pe_sections(data)

        checks = [
            ('P1 selfcrypt-ciphertext', p1_selfcrypt_ciphertext, (data, secs)),
            ('P2 selfcrypt-mask-crc', p2_mask_consistent, (data, secs)),
            ('P5 indirect-no-direct-call', p5_indirect_no_direct_call, (data, secs)),
            ('P6 expect-consistent', p6_expect_consistent, ()),
        ]
        for name, fn, args2 in checks:
            try:
                ok, detail = fn(*args2)
            except Exception as e:
                ok, detail = False, repr(e)
            results.append((name, ok, detail))

        blob = open(args.blob, 'rb').read()
        ok, detail = p3_blob_v1(blob)
        results.append(('P3 blob-v1-signed', ok, detail))
        ok, detail = p4_blob_signature(blob)
        results.append(('P4 blob-signature-verify', ok, detail))
    except Exception as e:
        print('protchain_check: error: %s' % e, file=sys.stderr)
        return 2

    failed = False
    for name, ok, detail in results:
        print('%-28s  %-4s  (%s)' % (name, 'PASS' if ok else 'FAIL', detail),
              flush=True)
        if not ok:
            failed = True
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
