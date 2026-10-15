#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""gen_sections.py — 每构建生成随机的节名与 magic（第二支柱 · 阶段 1+3）

## 目的
产物中的自解释名字（`.protcrc` / `PROTCRCP` 等）会直接告诉攻击者
"这里是完整性校验""这里是密文区"。本脚本每构建生成随机名，消除该线索。

## 实测依据（2026-09-21）
  · `#pragma section(MACRO, read)` **宏可展开** ✓
  · `#pragma code_seg(MACRO)` **宏可展开** ✓
  · 字符串字面量拼接 `PFX SFX` **不可用**（C2059）✗
  => 故用**单一宏**（名字整体作为一个宏），不做拼接。

## 输出
  demo/gen/prot_sections.h —— C 侧用（宏定义）
  demo/gen/prot_sections.json —— 工具侧用（hashpatch/selfcrypt_proto 读取）

## 用法
  python tools/gen_sections.py --seed <hex> [--out-dir demo/gen]
  # 不传 --seed 则随机
"""
import argparse
import hashlib
import json
import os
import random
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


# 需要随机化的节（逻辑名 -> 属性）
# 属性与现有一致（改动属性会影响加载行为，故保持）
SECTION_SPECS = {
    'protxec': ('read', 'execute'),   # src/antidebug.c, crc32.c, integrity.c, selfcrypt.c
    'protcrc': ('read',),             # src/integrity.c, tools/hashpatch.py
    'protcry': ('read', 'write'),     # src/selfcrypt.c, tools/selfcrypt_proto.py
    'protpad': ('read',),             # src/selfcrypt.c
    # ## ⚠️ `fptable` 已**移除**（S3, 2026-09-25）—— **不要再加回来**
    #
    #   核查结论（三处证实是死的）:
    #     ① 本表曾生成 `PROT_SEC_FPT` 宏 -> **全库无任何源文件使用它**
    #     ② `gen_padding` 的对应条目从未产出变量（实测生成的
    #        prot_padding.c 只有 g_pad_crc/cry/pad/rdata/text/xec）
    #     ③ 产物里那个 `.fptable` 段的**生产者是 CRT**:
    #        `?function_pointers` @ `libucrt:winapi_thunks.obj`
    #        （build/demo.map 可见）—— **不是本项目代码**
    #
    #   => 结果为它生成随机名 = "**为不存在之物做映射**"（随机化当然无效）。
    #      这**不是防护缺口**（那节本来就不归我们管），
    #      而是**误导性的死映射** -> 移除 + 留证（本注释）。
}

# 节名首字符必须是 '.'，长度 <= 8（PE 限制）
NAME_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789'


def gen_section_name(rng):
    """生成 8 字符以内的合法 PE 节名（以 '.' 开头）。

    用字母数字混合，避免任何语义暗示（如 prot/crc/cry 等）。
    """
    return '.' + ''.join(rng.choice(NAME_ALPHABET) for _ in range(7))


def gen_magic(rng):
    """生成 8 字节 magic（替代 'PROTCRCP' 等自解释标记）。

    要求:
      · 8 字节（与现有布局一致）
      · 不是可打印 ASCII 串（避免被 strings 直接读出）
      · 高熵（随机构造）
    """
    return bytes(rng.randrange(1, 256) for _ in range(8))


def main():
    ap = argparse.ArgumentParser(description='生成随机节名与 magic')
    ap.add_argument('--seed', default=None,
                    help='随机种子（hex 或十进制）；不传则用系统随机')
    ap.add_argument('--out-dir', default='demo/gen')
    ap.add_argument('--json-out', default=None,
                    help='工具侧 JSON 路径（默认 <out-dir>/prot_sections.json）')
    args = ap.parse_args()

    # 种子: 优先参数，否则系统随机（发布必须随机，见方针 P-5）
    if args.seed is not None:
        try:
            seed = int(args.seed, 16) if args.seed.lower().startswith('0x') \
                else int(args.seed)
        except ValueError:
            print('gen_sections: 无效 seed: %s' % args.seed, file=sys.stderr)
            return 1
    else:
        seed = random.SystemRandom().getrandbits(64)

    rng = random.Random(seed)

    # 生成节名（保证互不相同）
    names = {}
    used = set()
    for logical in SECTION_SPECS:
        for _ in range(100):
            n = gen_section_name(rng)
            if n not in used:
                used.add(n)
                names[logical] = n
                break
        else:
            print('gen_sections: 无法为 %s 生成唯一节名' % logical,
                  file=sys.stderr)
            return 1

    # 生成 magic（每个被校验的节一个）
    #
    # DRILL9 盲区修复（2026-10-04）: 从 3 个（text/rdata/pdata）增为 4 个，
    #   新增 'xec' —— `.protxec` 段（守卫检查器自身所在段）此前不在 CRC 覆盖内。
    #   顺序即 **CRC 表下标顺序**，必须与以下三处保持一致:
    #     · tools/hashpatch.py 的 MAGICS / TARGET_NAMES / ELF_TARGET_NAMES
    #     · src/integrity.c 的 g_prot_baked_crc[] 初始化顺序
    #     · 平台层 prot_plat_crc_target_name()
    #   校验脚本 tools/check_crc_targets.py 会交叉核对这四处（防再次漂移）。
    magics = {k: gen_magic(rng).hex() for k in ('text', 'rdata', 'pdata', 'xec')}

    os.makedirs(args.out_dir, exist_ok=True)

    # ---- C 侧头文件 ----
    hdr = os.path.join(args.out_dir, 'prot_sections_generated.h')
    with open(hdr, 'w', encoding='utf-8', newline='\n') as f:
        f.write('/*\n'
                ' * prot_sections_generated.h — 由 tools/gen_sections.py 生成, 请勿手工编辑\n'
                ' *\n'
                ' * 目的: 消除产物中的自解释名字（.protcrc / PROTCRCP 等）。\n'
                ' * 攻击者看到节名即知"这里是完整性校验"—— 故每构建随机。\n'
                ' *\n'
                ' * 实测依据: #pragma section(MACRO) 与 #pragma code_seg(MACRO)\n'
                ' * 均可展开（字符串拼接则不可用, C2059）。故此处只定义单一宏。\n'
                ' *\n'
                ' * 注意: 本头文件必须用**独立** include guard。早期版本误用与\n'
                ' * 常驻头相同的 PROT_SECTIONS_H，导致常驻头先定义 guard 后本文件\n'
                ' * 被整体跳过，随机节名永不生效（实测踩到，产物仍是 .protxec）。\n'
                ' */\n'
                '#ifndef PROT_SECTIONS_GENERATED_H\n'
                '#define PROT_SECTIONS_GENERATED_H\n\n'
                '/* 随机节名（每构建不同）。先 #undef 默认值以确保覆盖，\n'
                ' * 并避免 C4005 重定义警告（本项目 /WX：警告即错误）。*/\n')
        f.write('#undef PROT_SEC_XEC\n')
        f.write('#define PROT_SEC_XEC  "%s"  /* 原 .protxec */\n' % names['protxec'])
        f.write('#undef PROT_SEC_CRC\n')
        f.write('#define PROT_SEC_CRC  "%s"  /* 原 .protcrc */\n' % names['protcrc'])
        f.write('#undef PROT_SEC_CRY\n')
        f.write('#define PROT_SEC_CRY  "%s"  /* 原 .protcry */\n' % names['protcry'])
        f.write('#undef PROT_SEC_PAD\n')
        f.write('#define PROT_SEC_PAD  "%s"  /* 原 .protpad */\n' % names['protpad'])
        # ## PROT_SEC_FPT 已移除（S3, 2026-09-25）
        #   原先此处生成 `PROT_SEC_FPT` -> **全库无使用者**（死宏）。
        #   产物里的 `.fptable` 是 **CRT 的**（`?function_pointers` @
        #   `libucrt:winapi_thunks.obj`），**本项目不生成该节**。
        #   详见 NAMES 表的注释。
        f.write('\n/* 随机 magic（替代 PROTCRCP/D/P）*/\n')
        f.write('#undef PROT_MAGIC_TEXT\n')
        f.write('#define PROT_MAGIC_TEXT   "%s"\n' % magics['text'])
        f.write('#undef PROT_MAGIC_RDATA\n')
        f.write('#define PROT_MAGIC_RDATA  "%s"\n' % magics['rdata'])
        f.write('#undef PROT_MAGIC_PDATA\n')
        f.write('#define PROT_MAGIC_PDATA  "%s"\n' % magics['pdata'])
        f.write('#undef PROT_MAGIC_XEC\n')
        f.write('#define PROT_MAGIC_XEC    "%s"\n' % magics['xec'])
        # 字节数组形式（供 src/integrity.c 的聚合初始化使用）
        f.write('\n/* magic 的字节数组形式（聚合初始化用）*/\n')
        for key, macro in (('text', 'PROT_MAGIC_TEXT_BYTES'),
                           ('rdata', 'PROT_MAGIC_RDATA_BYTES'),
                           ('pdata', 'PROT_MAGIC_PDATA_BYTES'),
                           ('xec', 'PROT_MAGIC_XEC_BYTES')):
            raw = bytes.fromhex(magics[key])
            body = ', '.join('0x%02X' % b for b in raw)
            f.write('#undef %s\n' % macro)
            f.write('#define %s \\\n    { %s }\n' % (macro, body))
        f.write('\n#endif /* PROT_SECTIONS_GENERATED_H */\n')

    # ---- 工具侧 JSON ----
    jout = args.json_out or os.path.join(args.out_dir, 'prot_sections.json')
    with open(jout, 'w', encoding='ascii', newline='\n') as f:
        json.dump({
            'seed': '0x%016x' % seed,
            'sections': names,
            'magics': magics,
        }, f, indent=2)

    print('gen_sections: seed=0x%016x' % seed)
    for k, v in names.items():
        print('  %-10s -> %s' % (k, v))
    print('  magics: %s' % {k: v[:8] + '..' for k, v in magics.items()})
    print('  输出: %s, %s' % (hdr, jout))
    return 0


if __name__ == '__main__':
    sys.exit(main())
