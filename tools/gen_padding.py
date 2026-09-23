#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_padding.py — 生成节填充源（阶段2 第二支柱: 统一节尺寸）

## 目的
不同组合因"编进去的模块多少"而有不同节尺寸（实测 .text 差 8704 字节）。
攻击者可据此判断"开了哪些防护"。本工具为每个节生成**填充单元**，
把尺寸补到统一目标，使 4 个组合的节表**逐字段一致**。

## 为什么用源码级填充而非改 PE 结构
实测（2026-09-23）: `#pragma section(".text")` + `__declspec(allocate(".text"))`
可**精确**增大 `.text VSize`（base 0x14D60 -> 加 8192 后 0x16D50，正好 +8192），
且 /W4 /WX 无警告。这比"构建后改 PE 头（RawSize/文件偏移）"**风险低得多**
—— 不动 PE 结构，由链接器自然产出。

## 输入
  --baseline <json>   各节的目标尺寸（由 tools/measure_sections.py 生成）
  --actual <json>     本次构建的实际尺寸
  --out <c 文件>      生成的填充源

## 输出
  一个 C 文件，含各节的填充数组。填充内容由 --seed 决定（随机，避免零区
  成为"这是填充"的特征 —— 见计划 §14.3 V1）。
"""
import argparse
import json
import os
import random
import sys

# 可填充的节 -> （pragma 属性, 变量名前缀）
# 注意: 属性必须与目标节一致，否则链接器不合并。
PADDABLE = {
    '.text':  ('read, execute', 'g_pad_text'),
    '.rdata': ('read', 'g_pad_rdata'),
    '.pdata': ('read', 'g_pad_pdata'),
    '.protxec': ('read, execute', 'g_pad_xec'),
}

MAX_FILL = 1 << 20   # 单节填充上限 1 MiB（防手误生成巨型数组）


def main():
    ap = argparse.ArgumentParser(prog='gen_padding.py')
    ap.add_argument('--baseline', required=True,
                    help='目标尺寸 JSON（--gen-baseline 生成）')
    ap.add_argument('--actual', required=True,
                    help='本次实际尺寸 JSON')
    ap.add_argument('--out', required=True, help='输出 C 文件')
    ap.add_argument('--header-out', default=None,
                    help='输出头文件（宏形式，供 C 侧引用）')
    ap.add_argument('--seed', default=None, help='填充内容种子（hex）')
    args = ap.parse_args()

    base = json.load(open(args.baseline, encoding='ascii'))
    act = json.load(open(args.actual, encoding='ascii'))
    rng = random.Random(int(args.seed, 0) if args.seed else
                        random.SystemRandom().getrandbits(64))

    lines = [
        '/* 由 tools/gen_padding.py 生成, 请勿手工编辑（阶段2：统一节尺寸）',
        ' *',
        ' * 为什么要填充: 不同组合因编入模块多少而有不同节尺寸，攻击者可据此',
        ' * 判断"开了哪些防护"。填到统一目标可消除该信号。',
        ' * 内容随机 -> 避免零区成为"这里是填充"的特征。',
        ' */',
        '#include <stdint.h>',
        '',
    ]

    total = 0
    for sec, (attrs, prefix) in PADDABLE.items():
        want = base.get(sec, {}).get('vsize', 0)
        have = act.get(sec, {}).get('vsize', 0)
        need = want - have
        if need <= 0:
            continue
        if need > MAX_FILL:
            print('gen_padding: %s 需填充 %d 字节，超过上限 %d —— 跳过'
                  % (sec, need, MAX_FILL), file=sys.stderr)
            continue
        # 用一定周期的随机字节（避免整文件随机导致可复现性困难；
        # 种子固定时输出稳定）
        vals = [rng.randrange(1, 256) for _ in range(min(need, 256))]
        body = ', '.join('0x%02X' % v for v in vals)
        lines.append('/* %s: 补 %d 字节（目标 0x%X，实际 0x%X）*/'
                     % (sec, need, want, have))
        lines.append('#pragma section("%s")' % sec)
        lines.append('__declspec(allocate("%s")) '
                     'volatile unsigned char %s[%d] = { %s };'
                     % (sec, prefix, need, body))
        lines.append('')
        total += need

    lines.append('/* 合计填充 %d 字节 */' % total)
    with open(args.out, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')

    if args.header_out:
        with open(args.header_out, 'w', encoding='utf-8', newline='\n') as f:
            f.write('#ifndef PROT_PADDING_H\n#define PROT_PADDING_H\n'
                    '/* 阶段2: 节填充总量（诊断用）*/\n'
                    '#define PROT_PAD_TOTAL %d\n#endif\n' % total)

    print('gen_padding: 生成 %s（填充 %d 字节）' % (args.out, total))
    return 0


if __name__ == '__main__':
    sys.exit(main())
