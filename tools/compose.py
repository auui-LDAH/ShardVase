#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
tools/compose.py — 组合驱动构建 (阶段 2)

依据 docs/BLUEPRINT.md 阶段 2 与 docs/MODULAR_ARCH.md §4:
把一个「拼装图」(compositions/<name>.json) 转成构建所需的产物:

  1. demo/gen/prot_modconfig.h  —— 生成 PROT_MOD_<NAME> 宏,
     宿主 (demo/main.c) 据此条件编译各模块调用段
  2. 源文件列表 (stdout 或 --list-out) —— build.ps1 据此决定编译哪些 src/*.c
  3. 定义列表 (--defines-out) —— /DPROT_MOD_<NAME> 参数

设计要点 (P2): 未选中的模块**既不编译也不链接**, 而非提供空桩 ——
桩会被链接进产物, 且桩本身是可被 patch 的攻击面 (见 BLUEPRINT §5 阶段 2)。

用法:
    python tools/compose.py minimal --header-out demo/gen/prot_modconfig.h
    python tools/compose.py standard --sources-out build/_srcs.txt
    python tools/compose.py --list
"""

import argparse
import json
import os
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
REGISTRY = os.path.join(REPO, 'modules.json')
COMPOSITIONS = os.path.join(REPO, 'compositions')

# 宿主 (demo/main.c) 无条件依赖的基础模块 —— **实测更新 (2026-09-20 批2 后)**。
#
# 方法: 逐个尝试排除每个模块 (连带反向依赖闭包), 由**链接器**判定可排除性。
# 批2 完成 antidebug/integrity 条件编译后的实测结果:
#
#   可排除 (5): antidebug, dbiguard, integrity, syscall, vmdetect
#   不可排除 (8) —— 及其真实缺失符号:
#     blob       prot_vm_blob_load            (宿主直接调用)
#     hostid     prot_hostid_get              (间接表 + 宿主)
#     license    prot_license_verify / _build_message
#     revoke     prot_revoke_check            (间接表硬引用)
#     selfcrypt  prot_selfcrypt_blob / init / enter / leave
#     strcrypt   prot_str_get / prot_str_decrypt
#     vm         prot_vm_run                  (间接表 + 核心链)
#     indirect   prot_indirect_resolve        (宿主 PROT_INDIRECT_CALL)
#
# 批1 (仅 vmdetect/dbiguard 可排除) 时此表为 11 项; 批2 后收敛为 8 项。
#
# ⚠️ **L3 修正（2026-09-23）: 这是【demo 宿主】的下限，不是普遍规律**
#
#   上表来自 `demo/main.c` 的硬引用实测。**换宿主则下限不同**:
#     · `examples/tool_demo` 有自己的 main（不用间接化）
#       -> 不需要 `indirect`，但旧实现**强制补入** -> 构建失败
#       （`LNK2001: load_and_verify_license`，
#        因 `indirect_table.c` 硬编码 demo 的宿主函数名 + 私有类型 `demo_mem`）
#
#   故本常量改为 **demo 的默认下限**；组合可通过 `host_substrate`
#   声明自己的下限（见 resolve() 的 `_host_substrate`）。
#
#   这是本项目**第四次**"硬编码列表"问题的收尾:
#     ① SOURCE_ORDER      -> W3.3 拓扑排序
#     ② INFRA_HEADERS     -> R20 自动发现
#     ③ 构建脚本源文件列表 -> L3 compose 驱动
#     ④ **SUBSTRATE 宿主下限 -> 本次（改为按宿主可声明）**
SUBSTRATE = ['blob', 'hostid', 'indirect', 'license', 'revoke',
             'selfcrypt', 'strcrypt', 'vm']

# 可排除的模块 (供文档与测试引用)
EXCLUDABLE = ['antidebug', 'dbiguard', 'integrity', 'syscall', 'vmdetect']


def load_registry():
    with open(REGISTRY, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_composition(name):
    p = os.path.join(COMPOSITIONS, name + '.json')
    if not os.path.isfile(p):
        return None
    with open(p, 'r', encoding='utf-8') as f:
        return json.load(f)


def closure(mods, reg):
    """依赖闭包: 选中的模块必须连带其 deps。"""
    out = set(mods)
    changed = True
    while changed:
        changed = False
        for n in list(out):
            for d in reg['modules'].get(n, {}).get('deps', []):
                if d not in out:
                    out.add(d)
                    changed = True
    return out


# 编译顺序 (P2 布局敏感): **必须与改造前的 build.ps1 硬编码顺序一致**。
#
# 实测教训 (2026-09-20, -Composition 集成时发现): 若改用字母序编译,
# 链接顺序变化 -> .text 布局变化 -> 加密段与 main 的**页关系**变化 ->
# selfcrypt 的页冲突安全网跳过 vm_var -> 加密函数由 8 个降为 6 个。
# 即: 源文件顺序是**语义相关**的, 不是无关紧要的排列。
#
# 本列表的顺序 = 2026-09-20 之前 build.ps1 第 271 行的硬编码顺序。
# 新增模块须**追加到末尾**, 不得重排 (重排会改变布局并触发上述回归)。
SOURCE_ORDER = [
    'vm', 'vm_rekey', 'crc32', 'antidebug', 'integrity', 'strcrypt',
    'hostid', 'license', 'syscall', 'blob', 'revoke', 'vmdetect',
    'dbiguard', 'indirect', 'selfcrypt',
]


def topo_order(names, reg):
    """W3.3(2026-09-23): 用协议 `ordering` 字段做**拓扑排序**。

    ## 为什么替代 SOURCE_ORDER
      旧实现用**全局硬编码列表** `SOURCE_ORDER` 决定链接顺序 ->
      第三方模块**无法声明自己的先后约束**（只能被动地"追加到末尾"）。
      W2 给每个模块加了 `ordering: {after, before, priority}`，
      本函数据此排序，使顺序成为**协议可表达的属性**。

    ## 算法
      1. 建图: after=[X] 表示 X 必须先于本模块；before=[Y] 表示本模块先于 Y
      2. **Kahn 拓扑排序**，同层内按 `priority`（小者先）再按名字排序
         -> 确定性（同名同 priority -> 同顺序）
      3. 无 `ordering` 的模块用**默认 priority** 参与排序
      4. 若成环（理论上 modcheck R12 已拦截），退化为
         "priority + 名字"排序并报告（**不静默**）

    ## 与 SOURCE_ORDER 的关系
      `SOURCE_ORDER` 保留为**回退基线**: 对无 `ordering` 声明的模块，
      用它在列表中的位置作为 priority 来源 -> 保证**既有布局不变**。
    """
    # 默认 priority: 取自 SOURCE_ORDER 的位置（保持既有布局），
    # 不在列表中的排到最后（与旧行为一致: "新增模块追加末尾"）。
    def default_prio(name):
        try:
            # W3.3: 与声明的 priority **同量纲**（index×10），
            # 否则 0~14 与 10~90 混用会打乱顺序（实测教训）。
            return SOURCE_ORDER.index(name) * 10
        except ValueError:
            return (len(SOURCE_ORDER) + 10) * 10

    def info_of(name):
        if name in reg['modules']:
            m = reg['modules'][name]
        elif name in reg.get('primitives', {}):
            m = reg['primitives'][name]
        else:
            return None
        o = m.get('ordering') or {}
        return {
            'after': list(o.get('after', [])),
            'before': list(o.get('before', [])),
            'prio': o.get('priority', default_prio(name)),
        }

    nodes = {n for n in names if info_of(n) is not None}
    # ⚠️ **缓存** info 对象: info_of() 每次返回**新字典** -> 对其赋值不会保留。
    # （初版直接 info_of(b)['must_after'].add(n) -> KeyError，因为新字典里
    #   还没有 must_after 键。2026-09-23 实测修正。）
    info = {n: info_of(n) for n in nodes}

    # ⚠️ **`deps` 不参与链接顺序图**（2026-09-23 实测修正）
    #
    # 初版把 `deps` 当作"被依赖者先"的边 -> 产生**假环**:
    #   `integrity.deps` 含 `selfcrypt`（它需要 selfcrypt 的**掩码豁免**，
    #    属**运行时能力**依赖），而 `selfcrypt.ordering.after` 含 `integrity`
    #    （链接顺序）。
    #   => 两个语义不同的关系被混在一张图里 -> 报"环"。
    #
    # **结论**: `deps` = **能力依赖**（运行时），`ordering` = **链接顺序**。
    # 二者语义不同，不可混用。链接顺序只由 `ordering` + `priority` 决定。
    for n in sorted(nodes):
        info[n]['must_after'] = set(x for x in info[n]['after'] if x in nodes)
    for n in sorted(nodes):
        for b in info[n]['before']:
            if b in nodes:
                info[b]['must_after'].add(n)

    # Kahn（同层按 priority -> 名字，保证确定性）
    indeg = {n: len(info[n]['must_after']) for n in nodes}
    import heapq
    ready = [(info[n]['prio'], n) for n in nodes if indeg[n] == 0]
    heapq.heapify(ready)
    out, placed = [], set()
    while ready:
        _, n = heapq.heappop(ready)
        if n in placed:
            continue
        placed.add(n)
        out.append(n)
        for m in sorted(nodes):
            if m in placed or n not in info[m]['must_after']:
                continue
            indeg[m] -= 1
            if indeg[m] == 0:
                heapq.heappush(ready, (info[m]['prio'], m))

    cycle = sorted(nodes - placed)
    return out, cycle


def shuffle_sources(srcs, seed_hex):
    """按**构建种子**确定性地打乱源文件**链接顺序**（B 阶段，2026-09-25）。

    ## 为什么需要（**设计冲突的解法**）
      `gen_padding.py` 的填充把各节尺寸**归一化到统一 baseline**
      （防"组合指纹" —— 攻击者据节大小判断开了哪些防护）。
      但那让**函数地址跨构建固定** -> `migration_gate` 的 M1
      （地址复用率）退化为 **100%**（攻击者硬编码的地址跨构建仍有效）。

      **两个目标本质上看似互斥**:
        · 防组合指纹 -> 需**节大小稳定**
        · 防地址复用 -> 需**布局变化**

      **实测发现（vm_unit 手工实验）**:
    ```
      源文件顺序 A: .text=94880
      源文件顺序 B: .text=94880   <- **完全相同**
      符号 RVA 不同: 963/2257 (42.7%)  <- **地址抖动**
    ```
      => **顺序变化不改节大小，但改函数布局** —— **两者兼得**。

    ## 原理
      · **节大小**由"代码总量"决定 -> 顺序**不影响**
      · **函数地址**由"链接顺序"决定 -> 顺序**影响**
      => 天然解耦。

      ## 为什么比 `spread_ratio` 更优
        `spread_ratio` 试图用"填充量随机"制造抖动 —— 但那**同时改变节大小**
        （与归一化直接冲突）。顺序随机化**不动大小、只动布局**。

    ## 确定性（**关键 —— 保证可复现构建**）
      用种子派生的 PRNG（同种子 -> 同顺序）——
      否则 `repro_check`（同种子必须产出相同字节）会失败。

    ## 诚实边界
      · 只影响**链接顺序**，**不改任何源码语义**
      · 单源文件组合**无抖动**（如实：无可打乱的）
      · `.rdata` 仍会有**小差异**（实测 40 字节）——
       合并数据的布局连锁效应，量级远小于 `.text`
    """
    if not seed_hex or len(srcs) < 2:
        return srcs

    # 解析种子（接受 0x 前缀 / 纯 hex）
    s = seed_hex.strip()
    if s.lower().startswith('0x'):
        s = s[2:]
    try:
        seed = int(s, 16)
    except ValueError:
        return srcs   # 非法种子 -> 不打乱（**不静默改变语义**）

    # xorshift64* —— 与项目其它工具同族的确定性 PRNG
    state = (seed ^ 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF

    def nxt():
        nonlocal state
        state ^= (state << 13) & 0xFFFFFFFFFFFFFFFF
        state ^= state >> 7
        state ^= (state << 17) & 0xFFFFFFFFFFFFFFFF
        return state

    # ## ⚠️ 曾经的"钉住"已**撤掉**（2026-09-25）
    #
    # 我曾把 3 个"产出自定义节"的文件（selfcrypt/integrity/antidebug）
    # **固定在清单末尾**，试图缓解 selfcrypt 的页自伤崩溃。
    #
    # **实测证明它不足且有害**:
    #   · 不足: 4 个布局仍崩 3 个
    #   · **有害**: 钉住使它们的地址**必然不变** —— 实测 M1 残留
    #     14.7%（19 个未变函数**全部来自这 3 个文件**）
    #
    # **真正的修法**在 `src/selfcrypt.c`（先 RX 后 flush + RW 窗口
    #   恒用 EXECUTE_READWRITE），已实测 4 盐 × e2e + attacks = **0 失败**。
    # => 缓解手段撤掉，恢复**全量打乱**。
    out = list(srcs)
    # Fisher-Yates（确定性版本）
    for i in range(len(out) - 1, 0, -1):
        j = nxt() % (i + 1)
        out[i], out[j] = out[j], out[i]
    return out
    return out


def ordered_sources(names, reg):
    """按**协议 ordering**（拓扑）排序源文件；无声明时回退 SOURCE_ORDER。

    ## W3.3 变更（2026-09-23）
      旧实现: 纯 `SOURCE_ORDER` 硬编码列表 -> 第三方模块无法声明先后。
      新实现: 先做**拓扑排序**（用模块的 `ordering` 字段 + `deps`），
              同层内用 `SOURCE_ORDER` 的位置作为 priority ->
              **既有布局保持不变**（已实测: 源文件顺序与改动前一致）。

    可同时接受模块名与原语名 (crc32 / vm_rekey) —— 两者都在注册表中。
    """
    def src_of(name):
        if name in reg['modules']:
            return reg['modules'][name]['source'].replace('\\', '/')
        if name in reg.get('primitives', {}):
            return reg['primitives'][name]['source'].replace('\\', '/')
        return None

    ordered, cycle = topo_order(set(names), reg)
    if cycle:
        # modcheck R12 应已拦截；此处**不静默** —— 报告并继续
        import sys as _sys
        print('compose: 警告: ordering 成环 %s -> 该组按 priority 排序'
              % ', '.join(cycle), file=_sys.stderr)

    srcs = []
    seen = set()
    for name in ordered:
        if name in names:
            s = src_of(name)
            if s:
                srcs.append(s)
                seen.add(name)
    # 兜底: 未在注册表中找到顺序信息的（理论上不会发生）
    for name in sorted(set(names) - seen):
        s = src_of(name)
        if s:
            srcs.append(s)
    return srcs


def resolve(comp, reg):
    """拼装图 -> (最终模块集, 源文件列表, 自动补入的模块, 错误列表)"""
    errors = []
    declared = list(comp.get('modules', []))

    unknown = [m for m in declared if m not in reg['modules']]
    if unknown:
        errors.append('拼装图含未登记模块: %s' % ', '.join(unknown))
        return set(), [], [], errors

    # 依赖闭包
    full = closure(declared, reg)

    # 宿主下限 (substrate): 该宿主的 main 无条件调用这些模块。
    # 自动补入而**不是**报错 (便利性), 但必须在 auto_added 中如实报告。
    #
    # L3: 下限**按宿主可声明** —— 组合 JSON 的 `host_substrate` 覆盖默认值。
    #   · 未声明 -> 用 demo 的 SUBSTRATE（**既有组合行为逐字不变**）
    #   · 已声明 -> 用组合自己的下限（新宿主 / 第三方工具）
    _substrate = comp.get('host_substrate')
    if _substrate is None:
        _substrate = SUBSTRATE
    full |= set(_substrate)

    # 自动补入 = 闭包 + 下限 中所有未显式声明的部分
    auto_added = sorted(full - set(declared))

    # 源文件按 SOURCE_ORDER 排序 (保持既有 .text 布局; 见该常量注释)
    # 注意: 原语 (crc32/vm_rekey) 也在 SOURCE_ORDER 中, 故一并按序处理。
    excl = set(comp.get('exclude_primitives', []))
    with_prims = set(full)
    for pname in reg.get('primitives', {}):
        if pname not in excl:
            with_prims.add(pname)

    srcs = ordered_sources(with_prims, reg)

    # W3.5: 冲突检查（**只警告不阻塞**）
    #
    # ## 为什么此前不检查、现在为何仍不阻塞
    #   · 此前 compose **完全不检查冲突** —— 组合的问题要等到 modcheck
    #     才发现（构建已跑完）。
    #   · 但**不能阻塞**: `compositions/full.json` 明确写着"故意包含已知
    #     冲突，用于演示 modcheck 的组合校验能力" -> 阻塞会破坏既有行为。
    #   => 在此**提前告知**（构建早期），但把"是否致命"留给 modcheck。
    try:
        import compat as _compat
        _errs, _warns, _infos, _conf = _compat.check_conflicts(
            reg, sorted(full | with_prims), auto_added=auto_added)
        for _w in _warns:
            print('compose: [冲突] %s' % _w)
        for _i in _infos:
            print('compose: [提示] %s' % _i)
        if _conf:
            _plan = _compat.apply_resolutions(reg, _conf)
            for _c in _plan['conditions']:
                print('compose: [共存条件] %s' % _c)
    except ImportError:
        pass      # compat 不可用时不影响构建（保守）

    # 注意: **不可**再 sorted() —— 顺序是语义相关的 (决定 .text 布局,
    # 进而决定加密段与 main 的页关系)。见 SOURCE_ORDER 注释。
    return full, srcs, auto_added, errors


def gen_header(mods, comp_name, reg):
    """生成 prot_modconfig.h (宿主条件编译依据)。"""
    lines = [
        '/*',
        ' * prot_modconfig.h — 由 tools/compose.py 生成, 请勿手工编辑',
        ' *',
        ' * 组合: %s' % comp_name,
        ' * 生成自: modules.json + compositions/%s.json' % comp_name,
        ' *',
        ' * 宿主 (demo/main.c) 依据 PROT_MOD_<NAME> 条件编译各模块调用段。',
        ' * 未定义的模块: 既不编译也不链接 (P2: 不用空桩, 避免桩成为攻击面)。',
        ' */',
        '#ifndef PROT_MODCONFIG_H',
        '#define PROT_MODCONFIG_H',
        '',
        '/* 已启用模块 */',
    ]
    for m in sorted(mods):
        lines.append('#define PROT_MOD_%-14s 1  /* %s */'
                     % (m.upper(), ','.join(reg['modules'][m]['caps'])))

    lines.append('')
    lines.append('/* 未启用模块 (宿主应 #ifdef 排除其调用) */')
    disabled = sorted(set(reg['modules']) - set(mods))
    if disabled:
        for m in disabled:
            lines.append('/* #undef PROT_MOD_%s */' % m.upper())
    else:
        lines.append('/* (无 — 全模块已启用) */')

    lines.append('')
    lines.append('#define PROT_COMPOSITION_NAME "%s"' % comp_name)
    lines.append('')
    lines.append('#endif /* PROT_MODCONFIG_H */')
    return '\n'.join(lines) + '\n'


def list_compositions():
    if not os.path.isdir(COMPOSITIONS):
        return []
    return sorted(f[:-5] for f in os.listdir(COMPOSITIONS) if f.endswith('.json'))


def main():
    ap = argparse.ArgumentParser(description='组合驱动构建')
    ap.add_argument('composition', nargs='?', help='拼装图名 (compositions/<name>.json)')
    ap.add_argument('--profile', default=None,
                    help='W3.2: 策略文件 (profiles/*.json) —— '
                         '用户给策略而非模块列表')
    ap.add_argument('--plan-out', dest='plan_out', default=None,
                    help='W3.4: 结构化构建计划输出路径 (JSON)')
    ap.add_argument('--header-out', help='输出 prot_modconfig.h')
    ap.add_argument('--sources-out', help='输出源文件列表 (每行一个)')
    ap.add_argument('--defines-out', help='输出 /D 定义列表 (空格分隔)')
    ap.add_argument('--list', action='store_true', help='列出全部拼装图')
    ap.add_argument('--show', action='store_true', help='打印解析结果')
    # B 阶段（2026-09-25）: 按构建种子**确定性打乱**源文件链接顺序。
    #
    # 用途: 同时满足"节大小归一化"（防组合指纹）与"函数地址抖动"
    #      （防破解迁移）。详见 shuffle_sources() 的注释。
    ap.add_argument('--shuffle-seed', dest='shuffle_seed', default=None,
                    help='按此种子确定性打乱源文件顺序（如 0x1234abcd）')
    # ## 为什么需要 --extra（2026-09-25 实测根因）
    #   build.ps1 原把 `demo/main.c`/`demo/gen/*.c` **固定追加**在
    #   打乱清单之后 -> 尾部文件的前缀是"打乱区的**总和**"（恒定）->
    #   **尾部符号位置必然锁死**（实测 255 个字符串字面量 + main.c
    #   的符号全部不变）。
    #   => 尾部文件也须**并入统一打乱**。
    ap.add_argument('--extra', action='append', default=[],
                    dest='extras',
                    help='额外源文件（并入清单后**一起打乱**，可重复）')
    args = ap.parse_args()

    # W3.2: 策略驱动 —— 用户给**策略**，本工具求解出组合
    #
    # 实现: 求解后**合成一个内存中的组合**，再走原有 resolve() 路径 ->
    # 保留单一代码路径（所有校验/补入/排序逻辑一致，避免行为分叉）。
    if args.profile:
        import solve_profile as _sp
        ppath = args.profile
        if not os.path.isabs(ppath) and not os.path.exists(ppath):
            ppath = os.path.join(REPO, ppath)
        if not os.path.exists(ppath):
            print('compose: 策略文件不存在 %s' % ppath, file=sys.stderr)
            return 1
        _reg = load_registry()
        _prof = json.load(open(ppath, encoding='utf-8'))
        _r = _sp.solve(_prof, _reg)
        if args.plan_out:
            with open(args.plan_out, 'w', encoding='utf-8', newline='\n') as _f:
                json.dump(_r, _f, indent=2, ensure_ascii=False)
                _f.write('\n')
            print('compose: 构建计划 -> %s' % args.plan_out)
        # 合成临时组合（内存）
        comp = {
            'name': _r['profile'] or 'profile',
            'description': '由策略求解: %s' % _prof.get('description', ''),
            'modules': _r['selected'],
            '_from_profile': args.profile,
            '_strategy': _r['strategy'],
        }
        if not getattr(args, 'quiet', False):
            print('compose: 策略 %s -> %d 个模块（%d 个被排除）'
                  % (_r['profile'], len(_r['selected']), len(_r['excluded'])))
            for _c in _r['conflicts']:
                print('compose: 冲突 %s <-> %s : %s'
                      % (_c['a'], _c['b'], _c['resolution'][:60]))
        _full, _srcs, _auto, _errs = resolve(comp, _reg)
        if _errs:
            for _e in _errs:
                print('compose: [X] %s' % _e, file=sys.stderr)
            return 1
        if args.header_out:
            # 注意: gen_header() **返回字符串**，由调用方写文件（非自写）。
            _hdr = gen_header(_full, comp['name'], _reg)
            with open(args.header_out, 'w', encoding='utf-8', newline='\n') as _f:
                _f.write(_hdr)
            print('compose: 条件编译头 -> %s' % args.header_out)
        if args.sources_out:
            # B 阶段: 尾部文件并入后**统一打乱**（见 --extra 注释）
            _srcs = _srcs + list(args.extras)
            _srcs = shuffle_sources(_srcs, args.shuffle_seed)
            with open(args.sources_out, 'w', encoding='utf-8', newline='\n') as _f:
                _f.write('\n'.join(_srcs) + '\n')
            print('compose: 源文件清单 -> %s (%d 个)' % (args.sources_out,
                                                         len(_srcs)))
        else:
            for _s in _srcs:
                print(_s)
        return 0

    reg = load_registry()

    if args.list:
        for n in list_compositions():
            c = load_composition(n) or {}
            mods, srcs, auto, errs = resolve(c, reg)
            print('%-12s %-46s %d 模块 %d 源文件'
                  % (n, c.get('description', ''), len(mods), len(srcs)))
        return 0

    if not args.composition:
        ap.error('需要指定拼装图名 (或 --list)')

    comp = load_composition(args.composition)
    if comp is None:
        print('compose: 拼装图 %r 不存在' % args.composition, file=sys.stderr)
        return 1

    mods, srcs, auto, errs = resolve(comp, reg)
    for e in errs:
        print('compose: %s' % e, file=sys.stderr)
    if errs:
        return 1

    if args.show:
        print('组合: %s' % args.composition)
        print('  模块 (%d): %s' % (len(mods), ', '.join(sorted(mods))))
        print('  自动补入: %s' % (', '.join(auto) or '(无)'))
        print('  源文件 (%d):' % len(srcs))
        for s in srcs:
            print('     %s' % s)

    if args.header_out:
        out = os.path.join(REPO, args.header_out) if not os.path.isabs(args.header_out) \
            else args.header_out
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, 'w', encoding='utf-8', newline='\n') as f:
            f.write(gen_header(mods, args.composition, reg))

    if args.sources_out:
        # B 阶段: 尾部文件并入后**统一打乱**（见 --extra 注释）
        srcs = srcs + list(args.extras)
        srcs = shuffle_sources(srcs, args.shuffle_seed)
        with open(args.sources_out, 'w', encoding='ascii', newline='\n') as f:
            for s in srcs:
                f.write(s + '\n')

    if args.defines_out:
        with open(args.defines_out, 'w', encoding='ascii', newline='\n') as f:
            f.write(' '.join('/DPROT_MOD_%s' % m.upper() for m in sorted(mods)))

    return 0


if __name__ == '__main__':
    sys.exit(main())
