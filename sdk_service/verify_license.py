#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
# verify_license.py — 签发自查: 用 DER 公钥验证 license.txt 签名
# 用法: python3 verify_license.py --pub-der-c pub-der.c --license license.txt
# 输出: VALID / 具体失败原因。供签发后立即复查 (本机/服务器通用)。
import argparse
import base64
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import vmenc


def extract_der(path):
    with open(path, 'r', encoding='utf-8') as f:
        text = f.read()
    m = re.search(r'\{([0-9a-fA-FxX,\s]+)\}', text)
    if not m:
        raise vmenc.VasmError('无法在 %s 中找到 C 数组' % path)
    nums = re.findall(r'0[xX][0-9a-fA-F]+', m.group(1))
    return bytes(int(n, 16) for n in nums)


def main():
    ap = argparse.ArgumentParser(description='验证 license.txt 签名是否有效')
    ap.add_argument('--pub-der-c', dest='pub', required=True,
                    help='DER SPKI 公钥 C 数组 (keygen --blob-out-der 产物)')
    ap.add_argument('--license', dest='license', required=True,
                    help='license.txt 路径')
    args = ap.parse_args()

    fields = {}
    with open(args.license, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            k, _, v = line.partition('=')
            fields[k] = v

    sig = base64.b64decode(fields.get('SIGNATURE', ''))
    mid = vmenc.parse_machine_id_override(fields.get('MACHINE_ID', '0'))
    msg = vmenc.license_message(
        fields.get('SERIAL', ''), mid,
        int(fields.get('TIER', '0')), int(fields.get('EXPIRES', '0')))

    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization
    pub = serialization.load_der_public_key(extract_der(args.pub))
    try:
        pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
    except Exception as e:
        print('INVALID: 签名验证失败 (%s)' % type(e).__name__)
        return 1

    print('VALID: SERIAL=%s MACHINE_ID=%s TIER=%s EXPIRES=%s'
          % (fields.get('SERIAL'), fields.get('MACHINE_ID'),
             fields.get('TIER'), fields.get('EXPIRES')))
    return 0


if __name__ == '__main__':
    sys.exit(main())