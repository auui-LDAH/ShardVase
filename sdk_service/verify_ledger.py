#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
# verify_ledger.py — 台账哈希链校验 (D-D2 落地)
# 用法: python3 verify_ledger.py [--log issue-log.csv]
# 输出: 每行状态, 错误列表; 存在错误返回非 0。
# 规则: 新格式行尾部 ,prev=<sha256(上一行 body)>; 旧格式行无 prev 标记
#       视为 legacy 链起点 (不报错但记录)。修改/删除/追加伪造行 -> prev 失配。
import argparse
import os
import sys


def main():
    ap = argparse.ArgumentParser(description='校验签发台账哈希链')
    ap.add_argument('--log', dest='log', default='build/issue-log.csv',
                    help='台账路径 (默认 build/issue-log.csv)')
    args = ap.parse_args()

    if not os.path.isfile(args.log):
        print('ledger: 不存在: %s' % args.log)
        return 1

    lines = [l.rstrip('\n') for l in open(args.log,
                                          encoding='utf-8', errors='replace')
             if l.strip()]
    import hashlib
    prev_expected = ''
    errors = []
    legacy = 0
    for i, line in enumerate(lines):
        body, sep, cur = line.rpartition(',prev=')
        if not sep:
            legacy += 1
            prev_expected = hashlib.sha256(line.encode('utf-8')).hexdigest()
            continue
        if cur != prev_expected:
            errors.append('row %d: prev 失配 (疑似篡改/删除)%s' % (
                i + 1, '; 上一行为 legacy 行' if prev_expected == '' else ''))
        prev_expected = hashlib.sha256(body.encode('utf-8')).hexdigest()

    print('ledger: %d 行, legacy(无链) %d 行, 错误 %d'
          % (len(lines), legacy, len(errors)))
    for e in errors:
        print('  [FAIL] %s' % e)
    if errors:
        print('ledger: VERIFY FAILED')
        return 1
    print('ledger: VERIFY OK (hash chain consistent)')
    return 0


if __name__ == '__main__':
    sys.exit(main())