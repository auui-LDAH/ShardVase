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
# 属性必须与目标节一致，否则链接器不合并（取自 src/*.c 的现有声明）。
#
# ## 为什么只列这几个（实测边界，2026-09-23）
# 填充**工具链管理的节**会破坏产物:
#   · `.pdata`  -> LNK4078 特性冲突，节被分裂（0x1ADC 变 0x2C4）
#   · `.reloc`  -> LNK4078（真 .reloc 是 DISCARDABLE，属性无法用 pragma 匹配）
#   · `.rsrc`   -> **资源节丢失（变 0）**
#   · `.data`   -> 部分生效但不确定
# 而 `.text` 与 `.rdata` 填充**干净可用**（无警告，尺寸精确）。
#
# 那些节的尺寸是**代码的派生量**（.pdata 随函数数增长），正确的归一化
# 方式是"增加函数"而非"塞数据" —— 属独立工作（见计划 §14.6）。
#
# 值 = (声明方式, pragma 参数, 变量前缀)
#   'section'  -> #pragma section("<名>", <参数>)
#   'code_seg' -> #pragma code_seg("<名>")     ← 必须与源码一致！
#
# **教训（2026-09-23 实测）**: `.protxec` 在源码里用 `code_seg` 声明，
# 若填充时改用 `section`，属性不一致 -> 链接器建两个同名节 ->
# LNK4078 + 节被扭曲（0x48B 变 0x280）。改用 `code_seg` 后干净生效
# （0x47B -> 0x6FC，正好 +641，无警告）。
PADDABLE = {
    # 标准节: **只用 allocate**，不加 #pragma section ——
    # 实测 C4325「忽略标准节的特性」在 /WX 下变错误（2026-09-23）。
    '.text':    ('std', '', 'g_pad_text'),
    '.rdata':   ('std', '', 'g_pad_rdata'),
    # 自定义节用**逻辑名**（实际随机名由 name_map 替换 —— 见 main）
    'protxec':  ('code_seg', '', 'g_pad_xec'),
    'protcrc':  ('section', 'read', 'g_pad_crc'),
    'protcry':  ('section', 'read, write', 'g_pad_cry'),
    'protpad':  ('section', 'read', 'g_pad_pad'),
    # ## `fptable` 已移除（S3, 2026-09-25）
    #   原条目从未产出变量（实测 prot_padding.c 无 g_pad_fpt）——
    #   因为产物里那个 `.fptable` 是 **CRT 的**（`?function_pointers`
    #   @ libucrt:winapi_thunks.obj），**本项目不生成该节**。
    #   详见 tools/gen_sections.py 的 NAMES 注释。
}

# 明确排除（工具链管理，填充会破坏产物）—— 列出以便诊断时可见，
# 而不是静默忽略。
EXCLUDED = {
    '.pdata': '工具链管理（含展开信息，随函数数增长）-> LNK4078',
    '.reloc': '工具链管理（DISCARDABLE 属性无法用 pragma 匹配）-> LNK4078',
    '.rsrc':  '资源节 -> 填充会导致其丢失',
    '.data':  '工具链管理 -> 属性冲突',
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
    ap.add_argument('--quiet', action='store_true',
                    help='静默（构建流程中减少噪音）')
    # W1（差异扩散）: 填充量 = 缺口 + 目标尺寸 × spread_ratio
    #
    # 为什么需要（2026-09-23 实测）: 旧逻辑是"补齐到基线即止"，而基线 =
    # 各组合最大值 -> **full 无需填充** -> per-build 差异仅 0.54%，远低于
    # ">30%" 的目标。且差异集中在 5 个 4KB 块 -> 攻击者 diff 一次即定位。
    #
    # 加入随机增量后，**每个组合**（含 full）都有随机填充区 -> 差异扩散。
    ap.add_argument('--spread-ratio', dest='spread_ratio', type=float,
                    default=0.0,
                    help='差异扩散比例：额外填充 = 目标尺寸 × ratio（0=关闭）')
    ap.add_argument('--min-spread', dest='min_spread', type=int, default=0,
                    help='每节至少额外填充的字节数')
    args = ap.parse_args()

    base = json.load(open(args.baseline, encoding='ascii'))
    act = json.load(open(args.actual, encoding='ascii'))
    rng = random.Random(int(args.seed, 0) if args.seed else
                        random.SystemRandom().getrandbits(64))

    # 读节名映射：把逻辑名（protcrc）换成实际随机名（.4ahve8v）
    name_map = {}
    j = os.path.join(os.path.dirname(args.actual), 'prot_sections.json')
    if not os.path.exists(j):
        # ## ⚠️ 第二级回退 = **flat 旧路径**（S4 审计, 2026-09-25）
        #   A 阶段按平台分目录后这里**未跟着改** —— 它是"兜底"分支:
        #   首选 `os.path.dirname(args.actual)/prot_sections.json`（**平台正确**），
        #   只有该文件缺失时才回退到 `demo/gen/prot_sections.json`（**flat 遗留**，
        #   内容可能是**另一平台**的 -> 节名映射错配）。
        #   => 回退值保留（不破坏既有调用），但**记录为不可信**；
        #      调用方应保证首选路径存在（build.sh/build.ps1 都传平台 actual）。
        j = 'demo/gen/prot_sections.json'
    if os.path.exists(j):
        try:
            name_map = json.load(open(j, encoding='ascii')).get('sections', {})
        except (OSError, ValueError):
            name_map = {}
    if not args.quiet and name_map:
        print('gen_padding: 节名映射 %s' % name_map)

    lines = [
        '/* 由 tools/gen_padding.py 生成（阶段2: 统一节尺寸与集合）',
        ' * 请勿手工编辑。',
        ' *',
        ' * 为什么填充: 不同组合因编入模块多少而有不同节尺寸（实测 .text 差 8704',
        ' * 字节），攻击者可据此判断"开了哪些防护"。填到统一目标可消除该信号。',
        ' *',
        ' * 为什么内容随机: 全零区本身是特征（"这里是被填充的"），故用伪随机',
        ' * 字节；种子由构建种子派生，保证可复现（repro_check）。',
        ' */',
        '#include <stdint.h>',
        # ## ⚠️ B 阶段（2026-09-25）实测教训: **必须 include 宏定义头**
        #
        #   我把节语法改为 `PROT_ALLOCATE_PLAIN` / `PROT_SECTION_BEGIN` /
        #   `PROT_CODE_SEG` 等宏，却**忘了让生成物 include 定义它们的头**
        #   （`protect/prot_compiler.h`）。
        #
        #   **后果**: 宏**未定义** -> MSVC 把它们当作**隐式函数声明**
        #   （函数式宏的写法 `NAME("x")` 恰好像函数调用）——
        #   于是
        #     `PROT_ALLOCATE_PLAIN(".rdata") volatile unsigned char
        #      g_pad_rdata[N] = { ... };`
        #   被解析成**两个语句**（一个调用 + 一个**独立的数组定义**），
        #   **填充数据完全没进目标节** ->
        #   节尺寸**不再归一化** -> **M1 从 1.1% 退化到 100%**。
        #
        #   **由 `migration_gate` 抓到**（严谨二分: 每次测量先确认构建
        #   真的成功 —— 否则"构建失败 + 旧 map"会给出假象）。
        #
        #   **教训**: **改生成器的输出语法时，必须同步检查生成物的
        #   include 是否齐备** —— 否则"语法看着对，语义没了"。
        '#include "protect/prot_compiler.h"'
        '   /* PROT_ALLOCATE_* / PROT_SECTION_* / PROT_CODE_SEG */',
        '',
    ]

    bs = base.get('sections', {})
    as_ = act.get('sections', {})

    # ------------------------------------------------------------------
    # W1 差异扩散: **总量固定 + 分布随机**
    #
    # 设计教训（2026-09-23 实测）: 初版按"每节 × ratio 再随机"实现，
    # 结果**跨组合大小又不一致了**（275456/278016/281088）—— 因为起点
    # （各组合实际尺寸）不同，各自加随机增量后总量自然不同。
    #
    # 归一化与扩散**并不矛盾**，只要区分:
    #   · **总量**必须固定（= 基线总量 × (1+ratio)，与组合无关）-> 归一化 ✓
    #   · **分布**每构建随机（把增量随机分配到各节）        -> 扩散 ✓
    #
    # 故随机性作用于"**分配比例**"，而非"**总量**"。
    # ------------------------------------------------------------------
    # 目标总量: 用**基线文件大小**（历史最大值，只增不减）作为统一目标。
    #
    # 为什么不用"各节 VSize 之和"（初版做法）: 那会漏掉**不可填充节**
    # （.data/.pdata/.reloc）的缺口 —— 它们随代码量变化，minimal 天然更小，
    # 而预算只能花在可填节上 -> 各组合最终大小仍差（实测 512 字节）。
    #
    # 改用 baseline.file（= 历史最大组合的实际文件大小）作目标:
    #   · 它对**所有组合**是同一个值 -> 大小一致 ✓
    #   · 只增不减（merge_baseline 保证）-> 不会因当前组合小而缩水
    #
    # 注: 基线文件大小含 PE 头与节对齐，故按"文件级"补偿而不仅是"节级"。
    base_total = base.get('file', 0) or sum(v.get('vsize', 0) for v in bs.values())
    target_total = int(base_total * (1.0 + args.spread_ratio)) \
        if args.spread_ratio > 0 else base_total
    actual_total = sum(v.get('vsize', 0) for v in as_.values())
    budget = max(target_total - actual_total, 0)   # 本次要补的**总预算**

    # 可填节列表（决定预算如何在它们之间分配）
    fillable = [s for s in sorted(bs)
                if bs[s].get('vsize', 0) > 0 and s in PADDABLE]
    # 随机权重 -> 随机分布（权重每构建不同，总量恒定）
    weights = {s: rng.random() + 0.15 for s in fillable} if fillable else {}
    wsum = sum(weights.values()) or 1.0

    filled, created, total = [], [], 0

    # 1) 先满足**各节基线**（归一化硬约束，不可随机）
    need_map = {}
    for sec in fillable:
        wv = bs[sec].get('vsize', 0)
        have = as_.get(sec, {}).get('vsize', 0)
        if wv > have:
            need_map[sec] = wv - have

    # 2) 剩余预算按随机权重分配（纯扩散部分）
    used = sum(need_map.values())
    rest = max(budget - used, 0)
    if rest > 0 and fillable:
        for sec in fillable:
            share = int(rest * weights[sec] / wsum)
            if share > 0:
                need_map[sec] = need_map.get(sec, 0) + share

    skipped = []
    for sec in sorted(bs):
        wv = bs[sec].get('vsize', 0)
        if wv <= 0:
            continue
        spec = PADDABLE.get(sec)
        if spec is None:
            have0 = as_.get(sec, {}).get('vsize', 0)
            if wv > have0:
                skipped.append((sec, wv - have0))
            continue
        decl, attrs, prefix = spec
        # 逻辑名 -> 实际节名（随机）；标准节保持不变
        real = sec if sec.startswith('.') else name_map.get(sec, '.%s' % sec)
        have = as_.get(sec, {}).get('vsize', 0)
        need = need_map.get(sec, 0)
        if need <= 0:
            continue
        if need > MAX_FILL:
            if not args.quiet:
                print('gen_padding: %s 需补 %d 字节，超上限 —— 跳过'
                      % (sec, need), file=sys.stderr)
            continue

        # 生成**完整**的初值序列。
        #
        # ⚠️ 严重教训（W5 实测发现 2026-09-23）: 初版只给前 64 个初值，
        # 其余用 ', 0' 收尾 -> C 语言把**剩余 N-64 字节零初始化** ->
        # 产生**大段零区**，实测:
        #     .hyz8aoa  熵 1.081  零字节 90.4%
        #     .5rusy22  熵 0.162  零字节 98.9%
        #     .p7tqvqd  熵 0.104  零字节 99.3%
        #     .dlx1lap  熵 0.050  零字节 99.7%
        # 窗口级剖面 **88~95% 的窗口熵 < 0.1**。
        #
        # 后果: 攻击者一条熵扫描即可圈出全部填充区、滤掉噪声、
        #       只留真实代码 -> "68% 差异率"的实际防护**大幅缩水**
        #       （差异确实多，但**差异的位置**被零区直接标出）。
        #
        # 修法: 给出**与 need 等长**的随机初值（无零区）。
        #   源码体积代价: 每字节约 6 字符 -> 19531 字节 ≈ 117KB 生成文件。
        #   **可接受**（生成物不入仓库；且只在构建期存在）。
        #   无运行期成本（纯静态数据）。
        vals = [rng.randrange(1, 256) for _ in range(need)]
        body = ', '.join('0x%02X' % v for v in vals)
        lines.append('/* %s: %s %d 字节（目标 0x%X，实际 0x%X）*/'
                     % (real, '创建' if have == 0 else '补齐', need, wv, have))
        # 声明方式必须与源码一致，否则属性冲突 -> LNK4078（实测教训）
        #
        # ## B 阶段（2026-09-25）: 产出**跨平台**语法
        #
        # **问题**: 原实现**硬编码 MSVC 语法**
        #   （`#pragma section` + `__declspec(allocate)`）——
        #   gcc 报 `unknown-pragmas` / `unknown type name 'allocate'`
        #   -> **Linux 构建失败**。
        #
        # **修法**: 用 `prot_compiler.h` 的宏（`PROT_SECTION_BEGIN` /
        #   `PROT_ALLOCATE`），它们**按编译器展开**:
        #     MSVC: `__pragma(section(...))` + `__declspec(allocate(...))`
        #     gcc : 空 + `__attribute__((section(...)))`
        #
        # **为什么要 include 而非复制宏**: 单一来源（避免两处定义漂移）。
        if decl == 'std':
            # 标准节的**正确写法**（MSVC 实测三种写法后确定）:
            #   ① **只用 allocate，不加 #pragma section**（本实现）——
            #      实测 `#pragma section(".text")` 会触发
            #      **C4325「忽略标准节的特性」** -> `/WX` 下**变错误**。
            #   ② 带属性 -> 同 C4325
            #   ③ 仅 allocate 无 pragma -> **正确**
            #
            # ## ⚠️ B 阶段（2026-09-25）实测教训 —— 我**差点搞错**
            #   我给"标准节"引入了 `PROT_SECTION_PLAIN(sec)` 宏，
            #   它在 MSVC 下展开为 `__pragma(section(sec))` ——
            #   **正是上面 ① 说的 C4325 写法**！
            #
            #   后果: 构建仍能通过（`section(".text")` 不带属性时
            #     MSVC **只警告 C4325**，而我误以为它安全），
            #     但 **节的属性/大小语义变了** ->
            #     **M1 地址复用率从 6.7% 退化到 100%**
            #     （由 `migration_gate` 抓到）。
            #
            #   => **标准节只 emit `PROT_ALLOCATE_PLAIN(sec)`**
            #      （MSVC 展开为 `__declspec(allocate(sec))`，无 pragma）。
            #
            # ## gcc 侧
            #   `PROT_ALLOCATE_PLAIN` 展开为**空**（标准节不能用
            #   `__attribute__((section))`）-> 填充变量落**默认节**。
            #   **已知限制**: Linux 侧的标准节尺寸**不因填充而统一**
            #   （B 阶段如实记录；需时可用链接脚本实现）。
            lines.append('PROT_ALLOCATE_PLAIN("%s") '
                         'volatile unsigned char %s[%d] = { %s };'
                         % (real, prefix, need, body))
        elif decl == 'code_seg':
            lines.append('PROT_CODE_SEG("%s")' % real)
            lines.append('PROT_ALLOCATE("%s") '
                         'volatile unsigned char %s[%d] = { %s };'
                         % (real, prefix, need, body))
            lines.append('PROT_CODE_SEG_END()')   # 复位，避免影响后续
        else:
            # 自定义节 —— 用**可变参数**宏（属性必须是**标识符**，不能加引号）
            lines.append('PROT_SECTION_BEGIN("%s"%s)'
                         % (real, (', ' + attrs) if attrs else ''))
            lines.append('PROT_ALLOCATE("%s") '
                         'volatile unsigned char %s[%d] = { %s };'
                         % (real, prefix, need, body))
        lines.append('')
        total += need
        if have == 0:
            created.append(sec)
        else:
            filled.append((sec, need))

    lines.append('/* 合计填充 %d 字节；补齐 %d 节，创建 %d 个缺失节 */'
                 % (total, len(filled), len(created)))
    with open(args.out, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')

    if getattr(args, 'header_out', None):
        with open(args.header_out, 'w', encoding='utf-8', newline='\n') as f:
            f.write('#ifndef PROT_PADDING_H\n#define PROT_PADDING_H\n'
                    '/* 阶段2: 节填充总量（诊断用）*/\n'
                    '#define PROT_PAD_TOTAL %d\n#endif\n' % total)

    print('gen_padding: 生成 %s（填充 %d 字节）' % (args.out, total))
    return 0


if __name__ == '__main__':
    sys.exit(main())
