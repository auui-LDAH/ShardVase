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

# ## 阶段 4（第二支柱 · 完整性覆盖扩展, 2026-10-15）
#
# 目标（PILLAR2_OBSERVABILITY_PLAN §7）: 覆盖从"固定 4 段"扩为
# "**基础 4 段 + 每构建随机 K 段额外目标**"，攻击者无法预知本次构建
# 烧录了哪些段的 CRC（A4 验收: 两次构建的覆盖集合不同）。
#
# ## 候选池（**只收运行期字节稳定的段**）
#
#   · rsrc   —— .rsrc 资源段, 只读, loader 不改写
#   · reloc  —— .reloc 重定位表段, 只读; 段内会被"引用"的字段由
#               两侧一致的 reloc 掩码规则归零（hashpatch.reloc_mask_bytes
#               ↔ integrity.c build_reloc_mask），故稳定
#   · protpad —— 本项目自己的只读填充段（随机节名, 经 sections 映射）
#
# ## 为什么**不收** .data / .protcry / .fptable（诚实边界, 计划 §7.4 风险项）
#   · .data    —— 运行期被全局变量持续改写 -> CRC 必然误报
#   · .protcry —— selfcrypt 密文区, 自身改写触发误报（计划明示风险）
#   · .fptable —— CRT 的段（S3 已考证非本项目代码, 见 SECTION_SPECS 注释）
#
# ## 约定
#   · K 每构建从 1..3 随机（由 --seed 决定 -> 可复现, I3）
#   · 额外目标的 magic 追加在 4 个基础 magic **之后**（下标 4 起），
#     C 侧烧录表 g_prot_baked_crc[] 用生成头的条目数宏对齐
#   · Linux/ELF 侧不参与随机扩展（hashpatch ELF 路径只认 3 个基础名），
#     build.sh 不传 --extra-crc -> 恒为 0（显式不对称, 与判据 ⑥ 同思路）
EXTRA_POOL = ('rsrc', 'reloc', 'protpad')
# 逻辑名 -> 节名来源: None = 标准名('.rsrc'), 'protpad' = sections 映射名
EXTRA_LOGICAL = {'protpad': 'protpad'}


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
    ap.add_argument('--extra-crc', default=None, type=int, metavar='K',
                    help='阶段4: 额外 CRC 目标数 K（0=关闭, 默认每构建随机 '
                         '1..3, 由 seed 决定）。Linux/build.sh 传 0。')
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

    # ## 阶段 4: 每构建随机额外 CRC 目标（见 EXTRA_POOL 注释）
    #   K 由 --extra-crc 显式给（Linux 传 0），否则每构建随机 1..3。
    #   选择用**同一个 rng** -> 同 seed 可复现（I3）。
    #   额外目标按 EXTRA_POOL 顺序排列（不按抽样顺序），
    #   保证 JSON / 生成头 / C 烧录表三处顺序可核对。
    if args.extra_crc is not None:
        k_extra = max(0, min(args.extra_crc, len(EXTRA_POOL)))
    else:
        k_extra = rng.randint(1, len(EXTRA_POOL))
    picked = set(rng.sample(list(EXTRA_POOL), k_extra)) if k_extra else set()
    extra_keys = [p for p in EXTRA_POOL if p in picked]
    extra_names = {k2: ('.' + k2 if k2 not in EXTRA_LOGICAL
                        else names[EXTRA_LOGICAL[k2]])
                   for k2 in extra_keys}
    extra_magics = {k2: gen_magic(rng).hex() for k2 in extra_keys}

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
        # ## 阶段 4 额外目标输出
        #   PROT_CRC_COUNT: C 侧 g_prot_baked_crc[] 数组长度与
        #     prot_plat_crc_target_name() 越界判断、integrity.c 两处
        #     `j < PROT_CRC_COUNT` 循环共用（基座 4 + K）。
        #   PROT_CRC_EXTRA_ENTRIES: 聚合初始化的**表项列表**（逗号分隔,
        #     直接拼进 g_prot_baked_crc[] 初始化器尾部）。
        #   PROT_CRC_EXTRA_TARGET_NAMES: 平台层 names[] 的**名字列表**。
        #     三者顺序均 = EXTRA_POOL 序（见主流程注释），可交叉核对。
        #   Linux 不参与（build.sh 传 --extra-crc 0 → K=0, 两宏空,
        #     显式不对称, 与 check_crc_targets 判据⑥同一理由）。
        f.write('\n/* 阶段 4: 额外 CRC 目标（基座 4 之外, 每构建随机 K 个）*/\n')
        f.write('#undef PROT_CRC_COUNT\n')
        f.write('#define PROT_CRC_COUNT %du\n' % (4 + len(extra_keys)))
        if extra_keys:
            f.write('#undef PROT_CRC_EXTRA_ENTRIES\n')
            entries = []
            for key in extra_keys:
                raw = bytes.fromhex(extra_magics[key])
                body = ', '.join('0x%02X' % b for b in raw)
                entries.append('{ { %s }, 0, 0 }' % body)
            f.write('#define PROT_CRC_EXTRA_ENTRIES \\\n    %s\n'
                    % ', \\\n    '.join(entries))
            f.write('#undef PROT_CRC_EXTRA_TARGET_NAMES\n')
            f.write('#define PROT_CRC_EXTRA_TARGET_NAMES \\\n    %s\n'
                    % ', \\\n    '.join('"%s"' % extra_names[key]
                                        for key in extra_keys))
        else:
            # K=0: 空表项/空名字列表 —— C 侧初始化器允许尾随逗号, 宏为空即回退基座。
            f.write('#undef PROT_CRC_EXTRA_ENTRIES\n')
            f.write('#define PROT_CRC_EXTRA_ENTRIES\n')
            f.write('#undef PROT_CRC_EXTRA_TARGET_NAMES\n')
            f.write('#define PROT_CRC_EXTRA_TARGET_NAMES\n')
        f.write('\n#endif /* PROT_SECTIONS_GENERATED_H */\n')

    # ---- 工具侧 JSON ----
    jout = args.json_out or os.path.join(args.out_dir, 'prot_sections.json')
    with open(jout, 'w', encoding='ascii', newline='\n') as f:
        json.dump({
            'seed': '0x%016x' % seed,
            'sections': names,
            'magics': magics,
            # 阶段 4: 额外目标清单（顺序 = EXTRA_POOL 序）。hashpatch.py
            # 消费此键追加烧录目标; 缺失/空 = 无额外目标（老 JSON 兼容）。
            'crc_extra': [{'key': key, 'name': extra_names[key],
                           'magic': extra_magics[key]}
                          for key in extra_keys],
        }, f, indent=2)

    print('gen_sections: seed=0x%016x' % seed)
    for k, v in names.items():
        print('  %-10s -> %s' % (k, v))
    print('  magics: %s' % {k: v[:8] + '..' for k, v in magics.items()})
    print('  输出: %s, %s' % (hdr, jout))
    return 0


if __name__ == '__main__':
    sys.exit(main())
