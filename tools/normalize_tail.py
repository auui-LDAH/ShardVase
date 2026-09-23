#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""normalize_tail.py — 文件尾精确填充（W1 差异扩散收尾）

## 目的
让**所有组合**的产物文件大小**完全一致**，消除"文件大小可推断组合"的信号。

## 为什么不能只靠节填充（实测 2026-09-23）
  · 预算按文件级算，但只能花在**节**上 -> 节被链接器对齐到 0x200
  · 且权重分配取整 -> 残余随机 -> 各组合最终大小仍差 512~1024 字节

## 为什么尾部填充是安全的
  · PE 加载器只按 PE 头声明的长度映射 -> 尾部多余字节被忽略
    （阶段2 早期实测: 追加 4096 字节后 rc=0 正常输出）
  · 完整性 CRC 只覆盖 **节**（TARGET_NAMES = .text/.rdata/.pdata）
    -> 尾部不参与校验（已核实 tools/hashpatch.py）

## 插入顺序（关键）
  节填充 -> selfcrypt -> hashpatch -> **本工具** -> 签名
  （必须在 hashpatch 之后：否则 CRC 与最终字节不符；
    必须在签名之前：否则签名失效）

用法:
  python tools/normalize_tail.py <exe> --target <字节> [--seed <hex>]
"""
import argparse
import os
import random
import sys


def main():
    ap = argparse.ArgumentParser(prog='normalize_tail.py')
    ap.add_argument('exe')
    ap.add_argument('--target', type=int, required=True,
                    help='目标文件大小（字节）')
    ap.add_argument('--seed', default=None, help='填充内容种子（hex）')
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    data = bytearray(open(args.exe, 'rb').read())
    cur = len(data)

    if cur == args.target:
        if not args.quiet:
            print('normalize_tail: 无需补齐（已是 %d 字节）' % cur)
        return 0
    if cur > args.target:
        # 超出目标: **不截断**（会破坏 PE）-> 只报告
        if not args.quiet:
            print('normalize_tail: 已超出目标 %d -> %d（不截断）'
                  % (cur, args.target), file=sys.stderr)
        return 0

    rng = random.Random(int(args.seed, 0) if args.seed
                        else random.SystemRandom().getrandbits(64))
    need = args.target - cur
    # 随机内容: 避免零区成为"这是填充"的特征
    data.extend(rng.randrange(1, 256) for _ in range(need))
    with open(args.exe, 'wb') as f:
        f.write(bytes(data))

    if not args.quiet:
        print('normalize_tail: %d -> %d（补 %d 字节）'
              % (cur, args.target, need))
    return 0


if __name__ == '__main__':
    sys.exit(main())
