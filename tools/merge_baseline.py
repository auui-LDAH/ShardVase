#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""merge_baseline.py — 合并填充基线（只增不减）

## 为什么需要（实测教训 2026-09-23）
阶段2 的填充基线最初只在"不存在"时建立一次。当源码变化使某组合变大
（如 §15 把字符串表从 14 条增至 33 条，.rdata 从 0xDBE2 增至 0xDDE2），
旧基线成为**过期目标** -> 其它组合按旧目标填充 -> 组合间尺寸不一致
（实测 minimal 229376 vs full 229888，差 512 字节）。

## 做法
  基线 = max(旧基线, 本次实际)  —— **只增不减**
  这样基线自动跟进"最大组合"，无需人工干预。

用法:
  python tools/merge_baseline.py --baseline <json> --actual <json>
"""
import argparse
import json
import os
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')



def main():
    ap = argparse.ArgumentParser(prog='merge_baseline.py')
    ap.add_argument('--baseline', required=True)
    ap.add_argument('--actual', required=True)
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    act = json.load(open(args.actual, encoding='ascii'))

    if os.path.exists(args.baseline):
        base = json.load(open(args.baseline, encoding='ascii'))
    else:
        base = {'file': 0, 'sections': {}}

    changed = []
    base['file'] = max(base.get('file', 0), act.get('file', 0))

    bs = base.setdefault('sections', {})
    for k, v in act.get('sections', {}).items():
        cur = bs.setdefault(k, {'vsize': 0, 'rawsize': 0})
        for field in ('vsize', 'rawsize'):
            new = v.get(field, 0)
            if new > cur.get(field, 0):
                if not args.quiet:
                    changed.append((k, field, cur.get(field, 0), new))
                cur[field] = new
        # 保留 name 便于诊断（随机名会更新为最新）
        if v.get('name'):
            cur['name'] = v['name']

    with open(args.baseline, 'w', encoding='ascii', newline='\n') as f:
        json.dump(base, f, indent=2)

    if not args.quiet:
        if changed:
            print('merge_baseline: 基线已提升（%d 项）' % len(changed))
            for k, field, old, new in changed[:12]:
                print('  %-12s %s 0x%X -> 0x%X' % (k, field, old, new))
        else:
            print('merge_baseline: 基线无需变更')
    return 0


if __name__ == '__main__':
    sys.exit(main())
