#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
tools/doccheck.py — 对外材料数字漂移检查 (阶段5 M5)

背景 (2026-09-20): 核对对外材料时发现 4 类漂移 —— "0 破防点"模糊表述、
release_check 11/11(实为13)、攻防轮次口径不一(8+ vs 6)、以及
tests/attack_sdk_matrix.py 的 SDK drill 标识硬编码 bug。

这些漂移的共同特征: **文档里的数字没人核对**。本工具把能自动核对的
数字固化下来 —— 与 modcheck/drills 同样的思路 (工具强制 > 人工纪律)。

检查项:
  1. publish/ 与 docs/marketing/ 中不得出现"0 破防"这类模糊表述
  2. release_check N/N 的 N 必须等于实际门禁项数
  3. 攻防轮次口径必须与 docs/ATTACK_DRILL*.md 的实际数量一致
  4. 引用的文件路径必须存在
  5. 已知的"合法例外"白名单 (如 vmcalc "流程测试 11/11" 不是门禁项)

用法:
    python tools/doccheck.py            # 检查
    python tools/doccheck.py --list     # 列出所有被检查的数字
"""

import argparse
import glob
import os
import re
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

# --- 扫描范围 (Q3, 2026-10-02: 消除片段式覆盖面) ---
#
# ## 旧范围为什么不够
# 旧 TARGETS 只有 publish/ + docs/marketing/ (16 文件)。实测:
#   * 库内门禁项数断言共 219 处, 其中 **119 处**是 `N 项` 形态 ——
#     旧正则 `release_check N/N` 完全抓不到 (`docs/HANDOVER.md:194` 的
#     "release_check 现为 12 项" 这类写法全部漏检)。
#   * 死链规则在当前范围内**从未触发过**: 全库 25 条死链**全部在 docs/**,
#     对外材料 0 条 —— 该规则此前只具装饰性。
#
# ## 为什么不能简单地扩到 docs/**
# 实测: 在全部 docs/**/*.md 上跑同一引擎 -> 31 条"真缺陷"跨 15 文件,
# 其中 12 个是**非**元数据文件。原因: 大量历史文档的标题**从不带日期**
# (docs/OSS_TAIL_PLAN.md 的 `门禁 14/14`、docs/PLATFORM_EXPANSION_PLAN.md
# 的 `门禁 14/14`、docs/BLUEPRINT.md:640 的 `release_check 11/11` …),
# 它们记录的**是当时的真实值** —— 改成现值即**篡改历史**。
#
# ## 故: 范围 = 对外材料 + 根目录 front door + **显式自称现时**的内部文档
# `> **最后核实**: <日期> · 方法: … · 提交 <sha>` 是文档对"我自称现时"
# 的**显式自声明**。声明是承重的: 无此声明不得纳入检查 (新文档默认不被
# 检查, 是有意为之 —— 想被检查就先声明)。实测 24 文件 / 88 处数字断言,
# 残留 2 条真缺陷, 零噪声。
#
# ## 2026-10-06 补: 自声明式扫描面的**结构性盲区**
# 自声明是 opt-in, 而"现值口径"是**应然** —— 凡声称现值的都该被守。
# 二者不匹配的后果: 一个**自称权威、读者当下照着做**的文件, 只要不写
# `最后核实` 就永久不被检查。实测 `README.md:132` 的
# `跑 **36 项**（默认; 加 -With* 后共 **39 项**）` 改成 `37` ⇒ doccheck
# 仍 rc=0、零报错 (`README.md` 不在面内)。
# 修法不是"多写几处自声明"(仍是人眼的纪律), 而是把**恒为现时**的那类
# 从"自声明"改成"位置推导": 根目录 `*.md` + `.github/*.md` 与
# `publish/` 同理 —— 它们是读者**当下照着做**的说明, 不是历史快照。
# 实测并入 8 文件后 **0 新错误**, 目标数 24 -> 32。
# 未纳入的仍是历史快照 (`docs/阶段总结-*.md` / `docs/STAGE_AUDIT.md`
# / `docs/BLUEPRINT.md` 等) —— 它们记的是**当时的真实值**, 纳入即篡改历史。
VERIFIED_META = re.compile(r'^>\s*\*\*最后核实\*\*', re.M)


def header_declares_current(text):
    """头部块(首个 `## ` 之前)是否含 `最后核实` 元数据。

    限定头部块是必要的: 正文里**提到**该元数据的行(如勘查表
    `| docs/HANDOVER.md:237 | ... |`)不构成自声明。
    """
    cut = text.find('\n## ')
    head = text if cut < 0 else text[:cut]
    return bool(VERIFIED_META.search(head))


def build_targets():
    # 根目录 front door + .github 模板 —— 它们**恒为"现时"**, 与 publish/ 同理:
    # README / CONTRIBUTING / 展示文档 是读者**当下照着做**的说明, 不是历史快照;
    # PR 模板每次开 PR 都被复制进一条新记录。
    #
    # 2026-10-06 实测: `README.md:132` 的 `跑 **36 项**（默认…共 **39 项**）`
    # 此前**无人守** —— 把它改成 `37` 后 doccheck 仍 rc=0, 零报错。
    # 根因: 自声明式扫描面(`> **最后核实**`)对**不写该元数据**的文件永久失明,
    # 而"现值口径"是应然(凡声称现值都该被守), 二者不匹配。
    # 实测并入后 0 新错误(8 文件), 故并入。
    ts = sorted(glob.glob(os.path.join(REPO, '*.md')))
    ts += sorted(glob.glob(os.path.join(REPO, '.github', '*.md')))
    ts += sorted(glob.glob(os.path.join(REPO, 'publish', '*.md')))
    ts += sorted(glob.glob(os.path.join(REPO, 'docs', 'marketing', '*.md')))
    for f in sorted(glob.glob(os.path.join(REPO, 'docs', '**', '*.md'),
                             recursive=True)):
        try:
            t = open(f, encoding='utf-8', errors='replace').read()
        except OSError:
            continue
        if header_declares_current(t):
            ts.append(f)
    return sorted(set(ts))


# 对外材料 —— 恒为"现时" (它们随同步发布, 读者就是当下的人)
PUBLIC_MATERIAL = tuple(
    os.path.join(REPO, d).replace('\\', '/')
    for d in (os.path.join('publish'), os.path.join('docs', 'marketing')))

TARGETS = build_targets()

# 模糊/误导性表述 (必须不出现)
#
# 注意: 需要排除"引用/否定"语境 —— 例如
#   > 我们不写"0 破防" —— 那是模糊表述。
# 这句话本身是**正确**的 (它在批评该表述), 不应被判为违规。
# 判据: 命中位置附近若出现否定词(不/勿/非/避免)或引号包裹, 则跳过。
VAGUE_PATTERNS = [
    (r'0\s*破防', '模糊表述"0 破防"—— 应改为公开列出显式破防项'),
    (r'不可破解', '违反项目立场(不承诺永不破解)'),
    (r'100%\s*防', '绝对化表述'),
]

# 否定/引用语境关键词 (命中点前 20 字符内出现即视为"在讨论该表述"而非"使用它")
NEGATION = re.compile(r'不写|不说|勿用|避免|反对|不是|而非|所谓|声称|禁止')

# 引号: 命中被引号包裹时也视为引用
QUOTES = ('"', '"', '「', '『', "'", "'")


def _is_quoted_or_negated(text, start, end):
    """判断命中是否为引用/否定语境。"""
    # 前 24 字符内的否定词
    pre = text[max(0, start - 24):start]
    if NEGATION.search(pre):
        return True
    # 引号包裹 (命中紧邻引号)
    if start > 0 and text[start - 1] in QUOTES:
        return True
    if end < len(text) and text[end] in QUOTES:
        return True
    return False

# 合法例外: 这些"N/N"不是门禁项, 不应被 release_check 规则误判
#   golden 6/6       = c2vasm golden 样例
#   流程测试 11/11   = vmcalc flow test
EXEMPT_NN = re.compile(r'golden|流程测试|样例')

# --- 数字漂移判据 (Q3) ---
#
# ## 形态: 从 `N/N` 放宽到 `N/N` **和** `N 项`
# 实测全库门禁项数断言 219 处, 其中 `N 项` 形态 **119 处** —— 旧正则
# `release_check[^\n]*?(\d+)/(\d+)` 对它们**完全不可见**
# (如 `docs/HANDOVER.md:194` 的 "release_check 现为 12 项")。
#
# ## 比的是**分母**, 不是分子
# 实测范围内 34 处 `N/M` 里 16 处 N != M, 全部是"通过数/总数"对:
#   docs/PLATFORM_ISOLATION_PLAN.md:532  「门禁 21/22（唯一失败=未提交）」
#   docs/HANDOVER.md:473                 「一次门禁报 1/29 未通过」
#   docs/DEBUG_CONSOLE_PLAN.md:224       「已交付并入库门禁（30 / 32)」
# 语义上门禁项数**只可能是分母**。旧实现比较 `m.group(2)` —— 方向本就对。
#
# ## 容差 {40, 37}
# 总数 40 / 默认调用 37 都是合法现值 (3 项由 -With* 控制, 默认不跑)。
# 沿用轮次规则的先例: 允许"全量"与"默认"两种口径。
# 2026-10-02: 33/30 -> 34/31 (新增 `加密封装窗口 (window_check)`, §2.16/T11)。
# 2026-10-03: 34/31 -> 35/32 (新增 `判定多副本等价性 (replica_check)`, R3.2-c)。
# 2026-10-04: 35/32 -> 36/33 (新增 `CRC 目标表一致性 (crc_targets)`,
#   `docs/ATTACK_DRILL9.md` §5 的 `.protxec` 盲区收口)。
# 2026-10-05: 36/33 -> 37/34 (新增 `静态未定义名审计 (undef_check)`;
#   `tests/e2e.py` T3 的 `DebugAttacher` 孤儿调用与 `guard_selftest` 的
#   `cont`/`exit_pol` 两起"只在失败路径上执行"的 NameError 催生)。
# 2026-10-06: 37/34 -> 38/35 (新增 `Android 交叉编译 (android_compile_check)`;
#   用真 NDK r28 交叉编译才发现 Android 侧**从未被编译过** ——
#   `tools/attacker/android_jniptrace/` 两个 patcher 自 `c941c9c` 起
#   从未被任何目标编译，`examples/cross_platform/android/` 从未过
#   `-Wall -Wextra -Werror`。判据锚定**声明的最低 API 21**，因为
#   裸 `process_vm_writev` 在 api23+ 完全看不见（bionic 的
#   `__INTRODUCED_IN(23)`）。默认跑、不 gated => GATE_DEFAULT 同步 +1)。
# 2026-10-06: 38/35 -> 39/36 (新增 `selfcrypt 驻留期密文态
#   (selfcrypt_residency)`; 补的正是 `docs/HANDOVER.md` §2.35.6 **自己记名**
#   的诚实边界: D2c 修法（`c2666b9`）当时只有一次性手工探针（脚本在
#   gitignored 的 `build/` 下）=> 这条不变量**回归了不会有测试变红**。
#   判据 = 驻留窗口内 selfcrypt **组 0**（VM 引擎调用链）各条目内存字节
#   必须**逐字节等于磁盘密文**; 组 1（EXT 组）不在判据内，因为看门狗每轮
#   自己开/关一次 EXT 窗口（`src/integrity.c:188`/`:256`），窗口内它就该是明文。
#   默认跑、不 gated => GATE_DEFAULT 同步 +1)。
# 2026-10-08: 39/36 -> 40/37 (新增 `selfcrypt meta 布局四方一致
#   (selfcrypt_meta)`; 补的是 `docs/N1_PHASE2_PLAN.md:36` **自己写下的**
#   人工承诺「meta 布局改动必须同步 selfcrypt_proto.py（写）与
#   selfcrypt.c（读）、integrity.c build_selfcrypt_mask（读 rva/len 偏移），
#   三侧一致」—— 四方没有任何代码在读两侧并比较。实测三类漂移中，
#   `SC_ENTRY_GROUP_OFF` 20->16 与 C 侧 `SC_ENTRY_SIZE` 24u->20u
#   两类**没有任何检查会红**（protchain 绿、e2e 30/30 绿），因为
#   `tests/protchain_check.py:336`/`:368` 把 group 解出来又丢掉（写作 `_grp`）。
#   判据由 `struct.pack` 的格式串**推导**步长与逐字段偏移，不抄字面量。
#   默认跑、不 gated => GATE_DEFAULT 同步 +1)。
# 2026-10-09: 40/37 -> 41/38 (新增 `休眠自检审计 (selftest_audit)`; 承 §2.42:
#   `docs/PROTOCOL_GOVERNANCE.md:174-175` 的强制纪律只说了工具"能自证会抓错",
#   没有说"自证必须被执行" —— 全量对账查出 6 个工具 (genpaths / hostgen /
#   identity / migration_cost / solve_profile / observability) 登记了自检、
#   写了负向用例、却**没有任何执行者**。判据用 AST 判"登记" + 在入口清单里做
#   可达链搜索判"被执行", 并且本项自己就是那 6 个自检的执行者。
#   默认跑、不 gated => GATE_DEFAULT 同步 +1)。
# 2026-10-09: 41/38 -> 42/39 (新增 `Studio 契约 (studio)`, docs/STUDIO_PLAN.md ST0;
#   它是 `tools/studio_core.py` + `tools/studio_cli.py` 两个自检的执行者。
#   承上一项同一教训: 这两个工具刚建好、自检刚写绿, 若不同时接线, 它们会在
#   落地那一刻就变成新的"登记了自检却无人执行"。`studio_cli` 的自检验的是
#   **进程边界**(退出码三态 0/1/2、坏请求行不中断会话)——只测函数测不出来。
#   默认跑、不 gated => GATE_DEFAULT 同步 +1)。
# 2026-10-10: 42/39 -> 43/40 (新增 `Studio 外壳 (studio_server)`, ST5; 判据分两层
#   且**两层不同源** —— 合成 UI 测服务端自身, 最后一条才检查真实 studio/ 资产。
#   若拆成"只测合成 UI", 资产被删掉时门禁会全绿, 那是"检查器只在自己造的输入上
#   正确"的经典失效。默认跑、不 gated => GATE_DEFAULT 同步 +1)。
# 2026-10-10: 43/40 -> 44/41 (新增 `文件编码 (bom_check)`; 补的是**已存在的纪律**
#   —— `docs/HANDOVER.md:152-153` 与 `CONTRIBUTING.md` 都写了「含非 ASCII 的
#   `.ps1` 必须带 BOM」, `tools/bom.py` 也提供了工具, 但**没有任何判据在看它**。
#   实测反例 `tools/attacker/winpe_sympatcher/build.ps1` 无 BOM, PS 5.1 把它的
#   中文注释读成乱码。判据**只判 `.ps1`**: 全库交叉表 .ps1 14/1、.c 7/65、
#   .json 0/16 —— 后两者分布是散的, 判它们只会把既有无害状态判成失败。
#   默认跑、不 gated => GATE_DEFAULT 同步 +1)。
GATE_TOTAL = 46
GATE_DEFAULT = 43
GATE_OK = (GATE_TOTAL, GATE_DEFAULT)

RE_GATE_NN = re.compile(r'(?:release_check|门禁)[^\n]{0,24}?(\d+)\s*/\s*(\d+)')
# `门禁 **33** 项` 的 `**` 会打断 `(\d+)\s*项`, 故必须允许结束的强调标记
RE_GATE_N  = re.compile(
    r'(?:release_check|门禁)[^\n]{0,24}?(\d+)(?:\*\*)?\s*项')

# 沿革记录 (`11/15/22/26/31 → **33**`) —— 记的是"曾经是这些值", 不是现值
RE_DELTA = re.compile(r'(?:→|->|⇒)')
DELTA_WORDS = re.compile(r'现为|曾|旧值?|已过期|后为')

# 单条"第 N 项" —— 是序号不是总数
RE_ORDINAL = re.compile(r'第\s*\d+\s*项')

# 转述他文: **必须带行号**才是转述别处
#   `docs/HANDOVER.md:237 门禁 32 项`  <- 转述 docs 里某个位置
# 反例 (初版写成"任何路径"过宽): `方法: tools/docclaim_check.py + 门禁 26 项`
# 因提到一个 `.py` 就被豁免了**本文档自己**过期的元数据 —— 收窄后正确暴露。
RE_XREF = re.compile(r'[\w\-/.]+\.(?:md|py|ps1|c|h|yml|json|txt):\d+')

# 计划/验收语境: 计划表(以及其"验收/交付"列)里的门禁项数是**当时的验收
# 标准**, 不是对现值的声明。
#   docs/PLATFORM_ISOLATION_PLAN.md:328  `| A-c | ... | Windows 门禁 22 项全通过 |`
#   docs/CONTINUATION_PLAN.md:397        `**Q5 验收**: docs/ATTACK_DRILL9.md 存在...`
# 反例(必须仍然报错): docs/HANDOVER.md:355 位于 `| 优先级 | 项 | 状态 |` 表,
# 表头无验收/交付列 -> 仍被正确判为过期。故判据必须看**表头**, 不能只看"是表格行"。
RE_PLAN_COL = re.compile(r'验收|交付|目标|标准')

# 日期: 2019-2099 之间的 YYYY-MM-DD
RE_DATE = re.compile(r'\b20[1-9]\d-\d{2}-\d{2}\b')
FENCE = '```'
RE_HEADING = re.compile(r'^(#{1,6})\s+(.*)$')

# --- 「恒为现时」文档集 (§2.54) ---
#
# 与 `build_targets()` 的四个 glob 组**逐字对应**(根目录 / .github / publish /
# docs/marketing)。这些文件的性质是: 读者**当下照着做**的说明, 通篇没有
# "当时的真值" 这种语境 —— 故其中代码块**不是历史转录的容器**, 而是读者
# 会**原样复制去执行**的命令、或复制进 PR 的模板。
#
# ⚠️ 这正是 `in_code` 一刀切豁免的盲区。实测(2026-10-09):
#   `CONTRIBUTING.md:67` `# 一键门禁（36 项，…共 39 项）`
#   `CONTRIBUTING.md:95` `- [ ] release_check 36/36 PASS（默认）`
#   `README.md:107`      `… # 36 项门禁（默认；共 39 项）`
# 三行都在扫描面内、真值早已是 41/38, 却因 `in_code` 被判"代码块"**永久豁免**:
# 把它们改成任意数字, doccheck 仍 rc=0 零报错(与 `README.md:132` 并入扫描面
# 之前那次 §2.40 同类: 事实可得, 但没有任何判据在用它)。
#
# ⚠️ **刻意不含** `docs/**` 的自声明文件(写 `> **最后核实**` 的那些):
# 它们自称"现时", 但正文里带日期的历史小节与程序输出转录极多
# (`docs/HANDOVER.md` 一处就有 60+ 处代码块内命中)。把它们并入判据会要求
# **篡改历史记录**才变绿 —— 那是 §2.40 反向守卫在防的同一类错误。
#
# 实测: 上述 4 组共 25 个文件, 代码块内的门禁项数命中**仅 4 处, 且全部是
# 现值声明, 0 处程序输出转录** ⇒ 立此判据当前**零误报**。
CURRENT_FACING = re.compile(
    r'^(?:[^/]+\.md'
    r'|\.github/[^/]+\.md'
    r'|publish/[^/]+\.md'
    r'|docs/marketing/[^/]+\.md)$')


def is_current_facing(rel):
    """该文档是否属于「恒为现时」集合(通篇无历史语境)。"""
    return bool(CURRENT_FACING.match((rel or '').replace('\\', '/')))



# --- 扫描面**外**的「自称权威」文档 (§2.55) ---
#
# §2.54 修的是**面内**代码块里的现值声明; 这一条修的是**面外**那一半。
#
# 实测(2026-10-09, build/_faceall.py + build/_blame55.py):
#   面外 93 个 `.md` 里含门禁项数声明者 **10 文件 / 19 条**, 其中 18 条是历史
#   计划文件里写死的旧值(11 / 14 / 18 / 21)。把它们并入扫描面会要求**篡改历史
#   文档**才变绿 —— 那是 §2.40 反向守卫在防的同一类错误。
#
# 但 `docs/BLUEPRINT.md` 不是历史记录: 头部写
#   `> 版本：2026-09-20 v1 · 状态：**总纲**（路线图与验收标准的单一来源）`
# 而 `:128` 的 `| 发布门禁（39 项，默认 36） | 是**有人当现值在维护**的:
#   `git log -1 -L 128,128:docs/BLUEPRINT.md` = **`7062039`**, 即"门禁第 39 项"
#   落地那次提交, 它亲手把 `38 项，默认 35` 改成 `39 项，默认 36`。
#   该文件不在面内 => 这个数字**再也没有任何判据在看**, 到 §2.51/§2.53 之后
#   真值已是 41/38 而它仍写 39/36。
#
# => 判据的**目标函数**不是"让面外文件也有判据"(那会要求篡改历史), 而是:
#      **面外 交 自称权威** => 其门禁项数声明必须对账。
#
# 措辞选型实测(build/_p55pick.py, 只看头部前 8 行):
#   * 加粗 `总纲|单一来源|单一事实源` -> 面外唯一天然命中 BLUEPRINT;
#   * `总纲` 是**弱词**: `docs/ADVANCED.md:6` / `docs/ADVANCED2.md:6` 那句是
#     「关联：`docs/BUSINESS.md`（总纲）」= **引用别人**, 不是自称 => 不用它;
#   * `单一来源|单一事实源` 是**自称权威的专有措辞**: 全库任意位置仅 9 处,
#     其中**头部仅 1 处**(`docs/BLUEPRINT.md:3`), 其余 8 处是正文架构讨论
#     => 用它, 判据"零误报且不为零命中"。
#   * 刻意**不加**"排除头部含 `关联` 者"这一条: 那会让命中降到 **0**
#     (BLUEPRINT 头部 `:5` 正是关联行) —— 让判据精确到**永不触发**同样是失效。
SELF_AUTHORITATIVE = re.compile(
    r'(?:\*\*\s*)?(单一来源|单一事实源)(?:\s*\*\*)?')
AUTH_HEAD_LINES = 8
AUTH_SKIP_DIRS = ('.git', '.vs', 'archive', 'node_modules', 'build', 'dist',
                  '__pycache__')


def self_authoritative_head(text, lines=AUTH_HEAD_LINES):
    """头部前 `lines` 行(跳过代码块)是否自称"单一来源/单一事实源"。"""
    inside = False
    for l in text.split('\n')[:lines]:
        if l.lstrip().startswith(FENCE):
            inside = not inside
            continue
        if inside:
            continue
        if SELF_AUTHORITATIVE.search(l):
            return True
    return False


def self_authoritative_files():
    """扫描面**外**、头部自称权威的 `.md`(相对路径, 已排序)。

    ⚠️ 返回空列表**不等于**"没有漂移" —— 调用方必须把它当"锚点可能整体消失"
       处理(措辞被改 / 扫描器坏了 / 仓库根不对)。见
       `check_self_authoritative_claims()` 的判据①。

    `build/` 必须排除: 它装着发布暂存与产物副本, 里面会有这些 `.md` 的拷贝,
    否则判据会在副本上重复开火。
    """
    inside_set = set(os.path.normcase(x) for x in TARGETS)
    found = []
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in AUTH_SKIP_DIRS]
        for fn in files:
            if not fn.lower().endswith('.md'):
                continue
            p = os.path.join(root, fn)
            if os.path.normcase(p) in inside_set:
                continue          # 面内文件已由主循环覆盖, 不重复判
            rel = os.path.relpath(p, REPO).replace('\\', '/')
            try:
                tx = open(p, encoding='utf-8', errors='replace').read()
            except OSError:
                continue
            if self_authoritative_head(tx):
                found.append(rel)
    return sorted(found)


def check_self_authoritative_claims(docs=None, gate=None, rounds=None):
    """面外「自称权威」文档里的门禁项数声明必须与真值一致 (§2.55)。

    ## 判据
      ① 待判集合**非空**(锚点守卫: 措辞被改 / 扫描器坏了 -> FAIL, 不得读成
         "没有漂移");
      ② 集合内每份文档的门禁项数声明(`N/N` 与 `N 项` 两形态, **比分母**)必须
         落在 `GATE_OK` 内。判定走 `check_text()` —— 与生产**同一条**路径,
         故 `沿革`/`序号`/`转述他文`/`自带日期` 等豁免照旧生效。

    ## 参数
      `docs=None`    -> 自行枚举(`self_authoritative_files()`);
      `docs={rel:t}` -> **直接作为待判集合**(调用方保证它由"面外+自称权威"滤出;
                        自检用这个入口逐条测判据, 滤网另有用例直接断言)。

    ## ⚠️ 刻意**不**把这几份文件并入 `TARGETS`
    它们会同时触发模糊表述与死链判据, 而那些是**历史文档的既成事实**
    (实测 `docs/BLUEPRINT.md` 另有 4 条模糊表述报错), 一并要求修改等于篡改
    历史(§2.40 反向守卫同类)。本判据只取两条门禁项数判据的报错。

    ## 诚实边界
      * 若哪天把 `docs/BLUEPRINT.md:128` 那行**整个删掉**, 本判据不会报错 ——
        它守的是"写了就必须对", **不是**"必须写";
      * 滤网只看头部 `AUTH_HEAD_LINES` 行, 把自称挪到正文深处的写法会漏
        (但这也意味着它不再是"头部自称权威"的文档);
      * 只判门禁**项数**, 不判这几份文档的其它数字(版本号/轮次/日期)。
    """
    if docs is None:
        rels = self_authoritative_files()
        docs = []
        for rel in rels:
            try:
                tx = open(os.path.join(REPO, rel.replace('/', os.sep)),
                          encoding='utf-8', errors='replace').read()
            except OSError:
                continue
            docs.append((rel, tx))
    else:
        docs = sorted(docs.items())
    if not docs:
        return ['全库/注入面里找不到"面外 + 头部自称权威"的文档 —— '
                '判据①失去锚点(措辞被改或扫描器坏了, '
                '**不得**读成"没有漂移")']
    if gate is None:
        gate = actual_gate_count()
    if rounds is None:
        rounds = actual_rounds()
    errors = []
    for rel, tx in docs:
        exc = {}
        e, _w, _c = check_text(rel, tx, gate, rounds, exc)
        errors.extend(x for x in e if '门禁项数声称' in x)
    return errors


class DocView(object):
    """按行提供语境判断 (标题栈 / 代码块 / 豁免)。

    `exempt(line_no, text, m)` 返回豁免类别名, 或 None (应判为现时断言)。

    ## 标题栈为什么必须存在
    初版只看"最近一个上级标题是否带日期" -> `## 2.5 当前验收状态（2026-08-30
    增量）` 下的无日期 `### 构建与回归` 会把带日期的父语境**清空**, 于是
    `docs/HANDOVER.md:87` 的 `11/11` 被误判为现时。改为**栈**: 任一祖先带
    日期即为历史语境。
    """

    def __init__(self, text, path):
        self.text = text
        self.lines = text.splitlines()
        self.path = path
        self.stack = []          # [(level, title, has_date)]
        self.in_fence = False
        self.hist = []           # 每行是否处于历史(带日期)语境
        self.in_code = []        # 每行是否在代码块内
        # 命中偏移 -> 行号 的查找表
        self.starts = [0]
        for l in self.lines[:-1]:
            self.starts.append(self.starts[-1] + len(l) + 1)
        self._walk()

    def line_of(self, pos):
        """偏移 -> 0-based 行号 (二分)。"""
        lo, hi = 0, len(self.starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo

    def _walk(self):
        stack, inside = [], False
        for l in self.lines:
            if l.lstrip().startswith(FENCE):
                self.hist.append(any(h for _, _, h in stack))
                self.in_code.append(True)
                inside = not inside
                continue
            # ⚠️ 代码块内的 `#` 是注释, 不是标题。
            #    漏掉这个 guard -> 文档里的 shell 注释被当成 H1, 把带日期的
            #    父标题**挤出栈** -> 历史行被误判成现时。
            if not inside:
                m = RE_HEADING.match(l)
                if m:
                    lvl = len(m.group(1))
                    while stack and stack[-1][0] >= lvl:
                        stack.pop()
                    stack.append((lvl, m.group(2).strip(),
                                  bool(RE_DATE.search(l))))
                    self.hist.append(any(h for _, _, h in stack))
                    self.in_code.append(False)
                    continue
            self.hist.append(any(h for _, _, h in stack))
            self.in_code.append(inside)

    def plan_ctx(self, i, m):
        """命中是否处于"计划/验收"语境 —— 记的是验收标准, 不是现值。

        两种形态:
          * 行内: 命中点**之前**出现 `验收/交付/目标/标准`
            (docs/CONTINUATION_PLAN.md:397 `**Q5 验收**: docs/ATTACK_DRILL9.md ...`)
          * 表格: 命中所在**列**的表头是 `验收/交付/目标/标准`
            (docs/PLATFORM_ISOLATION_PLAN.md:328 `| A-c | ... | Windows 门禁 22 项全通过 |`)

        ⚠️ 必须按**列**判断, 不能"是表格行就豁免": docs/HANDOVER.md:355 所在
        表头是 `| 优先级 | 项 | 状态 |` (无验收列) -> 仍被正确判为过期。
        """
        line = self.lines[i]
        off = m.start() - self.starts[i]
        if RE_PLAN_COL.search(line[:off]):
            return True
        # 向上找到本表格的首行
        j = i
        while j >= 0 and '|' in self.lines[j]:
            j -= 1
        head = j + 1
        if head + 1 >= len(self.lines) or head >= i:
            return False
        # 表头下一行必须是分隔行, 否则不是表格
        if not re.match(r'^\s*\|[\s:|\-]+\|\s*$', self.lines[head + 1]):
            return False
        col = line.count('|', 0, off)
        cells = self.lines[head].split('|')
        return 0 <= col < len(cells) and bool(RE_PLAN_COL.search(cells[col]))

    def exempt(self, i, m, kind):
        """i: 0-based 行号; m: 命中 match; kind: 'nn'|'nge'|'link'|'vague'."""
        line = self.lines[i]
        if self.in_code[i]:
            # §2.54: 「恒为现时」文档里的代码块**不是历史转录的容器**。
            # 它们的围栏装的是读者会原样复制去执行的命令、或复制进 PR 的模板,
            # 现值声明恰恰常写在那里 (`README.md:107` 的行内 shell 注释、
            # `CONTRIBUTING.md:95` 的 PR 模板勾选框)。一刀切豁免会让这些
            # 声明**永久失明** —— 改成任意数字都 rc=0。
            # ⚠️ 只收窄 `nn`/`nge`(门禁项数)两类, 且**只限**这 25 个文件;
            #    `docs/**` 的自声明历史文档不受影响(那里的围栏确实装转录)。
            if not (kind in ('nn', 'nge') and is_current_facing(self.path)):
                return '代码块'
            # 落到下方与正文同一条判定路径 —— 沿革/序号/转述他文等豁免照旧生效。
        elif self.hist[i]:
            return '日期语境'
        if not self.in_code[i] and RE_DATE.search(line):
            # 行自带日期 => "截至 DATE 已核实" 的历史 attestation
            return '自带日期'
        if self.in_code[i] and RE_DATE.search(line):
            # 现时文件代码块里**自带日期**的行仍是历史 attestation
            # (如 README 的变更记录段), 一并放行。
            return '自带日期'
        if kind in ('nn', 'nge'):
            # 计划/验收表里的项数 = 验收标准
            if self.plan_ctx(i, m):
                return '计划验收'
            # 沿革记录: 记的是历史值序列
            if RE_DELTA.search(line) or DELTA_WORDS.search(line):
                return '沿革'
            # 序号: 窗口必须覆盖 "第 N 项" 整段
            # ⚠️ 右界曾是固定 m.start()+8 -> `门禁默认第 20 项` 的 `项`
            #    落在窗口外, 该条被漏判。改为 m.end()+2。
            win = line[max(0, m.start() - 6):m.end() + 2]
            if RE_ORDINAL.search(win):
                return '序号'
            # 转述他文(必须带行号)
            if RE_XREF.search(line):
                return '转述他文'
        return None


# --- 规划中的交付物 (死链规则的唯一合法例外) ---
#
# 实测全库 25 条死链**全部在 docs/**, publish/ 与 docs/marketing/ **0 条** ——
# 即该规则在旧范围内从未真正生效过。普查后这 25 条**没有一条是真缺陷**:
#   * 前向引用: docs/ATTACK_DRILL9.md 是 Q5 的**待交付物**;
#     tools/cost_model.py / tools/pack_release.ps1 / tools/gate_lock.ps1 等
#     都是计划中尚未实施的工具。
#   * 显式声明: docs/CONTINUATION_PLAN.md:368 `docs/ATTACK_DRILL9.md`
#     —— **该文件当前不存在**。 规则却把这句话本身判成了死链。
#   * 示意/占位: docs/项目文件分类-2026-08-30.md 的 `docs/XXX.md`、`docs/plan/`。
#
# 故判据必须区分"引用一个**已存在**文件"(要报) 与"规划一个**尚未创建**的
# 交付物"(不报)。区分依据 = 该行是否有"计划/待交付/不存在/输出/未来"语境。
PLANNED = re.compile(
    r'当前不存在|尚未创建|待交付|待创建|计划中|规划|将新增|未来|输出(?:\s*)[:：]'
    r'|不存在|未实施|待实现|TODO|待办|交付物|示意|占位|例如|形如')

# --- 部署布局 (用于相对链接解析) ---
#
# 关键: docs/marketing/X.md 部署到**公开仓库根目录** X.md,
# 而 ISSUE_TEMPLATE_*.yml 部署到 .github/ISSUE_TEMPLATE/*.yml。
# 因此同一相对路径在"本地"与"GitHub"两处解析结果不同 ——
# 曾产生真实死链 (boundaries.md 的 ../../.github/... 在仓库根会越界)。
#
# 处理原则: 跨越"文档所在目录"的链接一律用**绝对 URL**,
# 使其在本地渲染、GitHub、自建博客三处都有效。
DEPLOY_MAP = {
    'docs/marketing/README.md':        ('ShardVase-docs', 'README.md'),
    'docs/marketing/boundaries.md':    ('ShardVase-docs', 'boundaries.md'),
    'docs/marketing/attack-record.md': ('ShardVase-docs', 'attack-record.md'),
    'docs/marketing/landing.html':     ('ShardVase-website', 'index.html'),
}

# 各公开仓库的实际文件清单 (与 gh api tree 核对过)
PUBLIC_FILES = {
    'ShardVase-docs': {
        'README.md', 'attack-record.md', 'boundaries.md', 'landing.html',
        '.github/ISSUE_TEMPLATE/consult.yml',
        '.github/ISSUE_TEMPLATE/eval.yml',
        '.github/ISSUE_TEMPLATE/security.yml',
    },
}


def check_deployed_links():
    """按 GitHub 渲染规则校验 marketing 文档的相对链接。

    返回 (errors, checked)。
    """
    from urllib.parse import urljoin
    errors = []
    checked = 0
    for local, (repo, pubpath) in DEPLOY_MAP.items():
        p = os.path.join(REPO, local)
        if not os.path.isfile(p):
            continue
        text = open(p, encoding='utf-8').read()
        base = 'https://github.com/OWNER/%s/blob/main/%s' % (repo, pubpath)
        for m in re.finditer(r'\[([^\]]{1,24})\]\(([^)\s]+)\)', text):
            href = m.group(2)
            if href.startswith(('http://', 'https://')):
                continue
            checked += 1
            path = href.partition('#')[0]
            resolved = urljoin(base, path) if path else base
            marker = '/OWNER/%s/' % repo
            if marker not in resolved:
                ln = text[:m.start()].count('\n') + 1
                errors.append(
                    '%s:%d 相对链接越出仓库根: %s '
                    '(该文件部署到 %s 根目录 -> 请改用绝对 URL)'
                    % (local, ln, href, repo))
                continue
            rel = resolved.split(marker)[-1]
            # 关键: 仓库内的**文件**链接必须落在 blob/main/ 之下。
            # 只用 urljoin 不够 —— 对 `../../x` 它会折叠掉 blob/main/
            # 但仍保留仓库名, 结果形如 `ShardVase-docs/x` (看着像仓库内,
            # 实际是 GitHub 上的目录路径, 渲染为 404)。
            # 这是本检查器初版的漏洞 (负向测试发现)。
            if 'issues' in rel:
                continue
            if not rel.startswith('blob/main/'):
                ln = text[:m.start()].count('\n') + 1
                errors.append(
                    '%s:%d 相对链接越出文档目录 (部署后 404): %s '
                    '-> %s (请改用绝对 URL)'
                    % (local, ln, href, rel))
                continue
            f = rel[len('blob/main/'):]
            if f and f not in PUBLIC_FILES.get(repo, set()):
                ln = text[:m.start()].count('\n') + 1
                errors.append('%s:%d 部署后目标不存在: %s -> %s'
                              % (local, ln, href, f))
    return errors, checked


def actual_gate_count():
    """release_check.ps1 的实际门禁项数 = `Check` 调用点数。

    ## ⚠️ 这里曾有硬编码 `+1`（2026-10-01 移除）

    原实现:

        n = len(re.findall(r"^\\s*Check '", open(p, encoding='utf-8').read(), re.M))
        # +1: codesign.pfx 存在时的签名 pass++ 项
        return n + 1

    那个 `+1` 是在**猜**"签名提示项必然存在"。它与
    `tools/docclaim_check.py` 的另一种错误（非锚定正则把注释里的
    `Check 'X'` 误算成一项）**刚好凑出同一个 31** —— 于是
    `publish/*.md` / doccheck / docclaim 三方一致却**三方都错**。

    根因不在检查器而在被测脚本: `tools/release_check.ps1` 的签名块当时是普通
    `if`，"pfx 存在但未签名"分支只 `$script:pass++` 不打印 `[ok]`，
    于是项数既**比证据行多 1**、又**环境相关**。已改为真正的 `Check`
    （任何环境都产出 `[ok]` 行），故这里的 `+1` 假设必须删除 ——
    判据里**不允许存在"某个项必然在"的硬编码假设**。
    """
    p = os.path.join(REPO, 'tools', 'release_check.ps1')
    if not os.path.isfile(p):
        return None
    t = open(p, encoding='utf-8-sig').read()
    # 行锚定（唯一结构形态）: 行首可空白 + Check + 引号。
    # 非锚定形态已 5 次假阳性（最近一次把 L79 注释里的示例算成一项）。
    return len(re.findall(r"(?m)^\s*Check\s+'", t))


def _ps_scan(text):
    """逐行返回 `(行号, 本行净 '{' 数, 本行净 '}' 数, 行末深度, 去注释去字符串后的文本, 原始行)`。

    ## 为什么不用真解析器
    `tools/release_check.ps1` 没有 here-string（`@'` / `@"`）也没有块注释（`<#`），
    所以"去字符串 + 去行注释 + 数括号"足够精确。**这个前提是被断言的**：
    `check_gate_structure()` 若在文件里搜到这三者会**直接 FAIL**，而不是拿一个
    不可靠的扫描结果去静默放行（"未验证 != 通过"）。

    ## ⚠️ 为什么要同时返回**原始行**（2026-10-01，本函数第一版的真实缺陷）
    第一版只用"去字符串后的文本"做匹配，于是 `Check 'X' {` 变成 `Check {`
    —— 而判据正则写的是 `^\\s*Check\\s+'`，**永远匹配不上，一个 `Check` 都数不到**，
    守卫恒返回"无错误"。用**负向测试**（人为回退修复、确认守卫会 FAIL）才暴露:
    当时注入 bug 后守卫仍打印"32 项均为顶层语句"。教训: **一个从未被负向测试
    证明过会 FAIL 的守卫，等于没有守卫** —— 它会安静地给出虚假的安全感。
    => 结构匹配一律对**原始行**做；括号计数才用去字符串后的文本。
    """
    rows = []
    depth = 0
    for ln, raw in enumerate(text.splitlines(), 1):
        cleaned = []
        j = 0
        quote = None
        while j < len(raw):
            ch = raw[j]
            if quote == "'":
                if ch == "'":
                    if j + 1 < len(raw) and raw[j + 1] == "'":
                        j += 2
                        continue
                    quote = None
                j += 1
                continue
            if quote == '"':
                if ch == '`':
                    j += 2
                    continue
                if ch == '"':
                    if j + 1 < len(raw) and raw[j + 1] == '"':
                        j += 2
                        continue
                    quote = None
                j += 1
                continue
            if ch == '#':
                break
            if ch == "'":
                quote = "'"
                j += 1
                continue
            if ch == '"':
                quote = '"'
                j += 1
                continue
            cleaned.append(ch)
            j += 1
        c = ''.join(cleaned)
        op, cl = c.count('{'), c.count('}')
        depth += op - cl
        rows.append((ln, op, cl, depth, c, raw))
    return rows


def check_gate_structure():
    """断言每个 `Check` 在**默认调用**下都会运行（结构判据）。

    ## 为什么需要（2026-10-01，真实事故）
    提交 `abc5edc` 把一整段注释块插进了 `if ($WithMigration) {` 的 body 里，
    **吃掉了它原本的 `} else {`** —— 于是门禁第 24~33 项（含"文档断言一致性"
    与"门禁日志自检"自己）**全部被嵌套进 `if ($WithMigration)`**，
    只有显式传 `-WithMigration` 才跑。实测证据（同一脚本、同一台机器）:

        · 不带任何开关                                  -> `PASS: 19 项`
        · `-WithSkeleton -WithMutation -WithMigration`  -> `PASS: 30 项`

    即**默认调用下门禁静默跳过约 10 项，而 PASS 文案照打** —— 违反本项目
    反复记名的"未验证 != 通过"。**既有两个数门禁项数的检查器都没抓住**:
    当时的 `docclaim`、`gate_log` 都只数 `Check` 的**出现次数**
    （当时 32 个全对），**没有一个断言它们在顶层**；更糟的是这两项**自己就落在
    被嵌套的区间里**，复发时根本不会运行。

    > 注: 上面的项序号是**当时**的（32 项时代：`docclaim` 第 27 项、
    > `gate_log` 第 32 项）。2026-10-03 新增
    > `加密封装窗口 (window_check)` 插在 `protchain P1-P6` 之后，
    > 其后所有项序号 +1 ⇒ 现为第 28 项 / 第 33 项。判据本身与序号无关。

    ## 判据
    每个 `if ($With*)` 的 body 里**最多只能有它自己那一个 `Check`**。
    多出来的必然是"被注释块吞掉 `} else {`"这一类结构事故 —— 因为 `$With*`
    的意义就是"只控制它自己那一个可选门禁项"，任何其它项被罩进去都是**事故**
    而非设计。这个判据不依赖"哪些项本该是有条件的"这类容易过时的清单。
    """
    p = os.path.join(REPO, 'tools', 'release_check.ps1')
    if not os.path.isfile(p):
        return []
    text = open(p, encoding='utf-8-sig').read()

    errors = []
    # 前提断言: 扫描器的适用条件若被破坏，宁可 FAIL 也不静默给错结果。
    for pat, why in ((r"@'", "here-string @'"), (r'@"', 'here-string @"'),
                     (r'<#', '块注释 <#')):
        if re.search(pat, text):
            errors.append('tools/release_check.ps1 含 %s -> 结构扫描器前提被破坏'
                          '（需改用真解析器）；本判据**不做猜测**' % why)
    if errors:
        return errors

    rows = _ps_scan(text)
    # ⚠️ 一律对**原始行**（第 6 列）做结构匹配；第 5 列是去过字符串的文本，
    #    用它匹配 `Check '` 会一个都数不到（见 _ps_scan 文档里的真实缺陷）。
    n_check = 0
    for idx, (ln, op, _cl, depth, _c, raw) in enumerate(rows):
        if re.match(r"^\s*Check\s+'", raw):
            n_check += 1
        m = re.match(r"^\s*if\s*\(\s*(\$With\w+)\s*\)\s*\{", raw)
        if not m:
            continue
        name = m.group(1)
        base = depth - op          # 进入 if 之前的深度
        inner = []
        for ln2, _o2, _c2, d2, _c2s, raw2 in rows[idx + 1:]:
            if d2 <= base:
                break
            if re.match(r"^\s*Check\s+'", raw2):
                inner.append(ln2)
        if len(inner) > 1:
            errors.append(
                'tools/release_check.ps1:%d `if (%s)` 的 body 里有 %d 个 '
                '`Check`（L%s）—— 只有它自己那一个是有意的；'
                '其余是被结构事故罩进去的，**默认调用下不会运行**。'
                '典型成因: 一段注释块被插进 if body，吃掉了 `} else {`'
                % (ln, name, len(inner), ', '.join('L%d' % x for x in inner)))

    # 自证: 一个 `Check` 都数不到，说明扫描器或判据本身坏了 —— 宁 FAIL 不静默通过。
    if n_check == 0:
        errors.append('tools/release_check.ps1 结构扫描数到 **0** 个 `Check` '
                      '-> 扫描器或判据本身已失效（"未验证 != 通过"）；'
                      '不要把它读成"没有结构问题"')
    return errors



def check_fence_balance(docs=None):
    """断言扫描面内每个 `.md` 的 ``` 围栏**配平**（结构判据）。

    ## 为什么需要（2026-10-08，真实事故）
    `DocView._walk()`（`:281-304`）用一个**布尔 `inside` 翻转**来判"这一行是否
    在代码块内"。这个实现在**围栏总数为偶数**时正确，但只要总数是**奇数**，
    从那个未配对的围栏起，后面所有行的 `in_code` 语义**整体反转** ——
    代码块内的行被判成"代码块外"、块外的判成"块内"。

    实测（`docs/HANDOVER.md`，HEAD `ab04716`）：围栏 **283 条（奇数）**，
    于是 `:6671`（在 ``` 块内，围栏 `:6670`/`:6673`）被判 `in_code=False`，
    里面的 `[release_check] FAIL: 1/36 未通过` 被当成**现值断言**报出来
    （`门禁项数声称 36, 实际 40`）。**那条报错指向的是受害者，不是病因** ——
    真正的病因是一个孤立的 ```（`:5839`），它是 `da5f906` 插入 §2.46.10 时
    多写的一行，使全文奇偶从那一刻起坏掉。

    ⚠️ 关键教训: 奇偶坏掉**不会**让 doccheck 报"围栏不配平"，它只会让
    **代码块豁免整类失效** —— 于是报出来的是若干看似无关的数字漂移，
    而真正的病因（多了一个 ```）没有任何判据在看。这类"判据悄悄失效比判据
    报错更危险"与本仓库 §2.36.8 / §2.38 / §2.40 / §2.42 / §2.45 / §2.46
    / §2.48 的**同型缺陷第 9 例**：事实（围栏数）可得，无判据在用它。

    ## 判据（两条，任一无锚点即 FAIL，不读成"没有漂移"）
    ① 围栏总数**必须是偶数**（奇 ⇒ 必有未配对者 ⇒ `in_code` 从某行起反转）；
    ② **带 info string 的围栏必须落在偶数序号**（`.md` 里带语言标记的
       ``` 只可能是**开启**围栏 ⇒ 它的序号必为偶数）。这条比 ① 更锐:
       总数偶数但配对错位（例如多了个裸 ``` 又少了个开围栏）时 ① 绿而 ② 红。

    `docs=None` 时读真实 `TARGETS`；自检传 `{rel: text}` 绕开文件系统。
    """
    errors = []
    if docs is None:
        docs = []
        for p in TARGETS:
            rel = os.path.relpath(p, REPO).replace('\\', '/')
            try:
                docs.append((rel, open(p, encoding='utf-8').read()))
            except OSError:
                continue
    else:
        docs = sorted(docs.items())
    for rel, t in docs:
        rows = []
        for i, l in enumerate(t.split('\n'), 1):
            if l.lstrip().startswith(FENCE):
                s = l.lstrip()[len(FENCE):].strip()
                rows.append((i, s, l))
        if not rows:
            continue
        if len(rows) % 2:
            last = rows[-1]
            errors.append(
                '%s 的 ``` 围栏总数 %d 是**奇数** -> 从某一处起 `in_code` 语义'
                '整体反转（代码块豁免整类失效）。最后一个围栏在 :%d；'
                '先找那个多出来的孤立 ```（§2.51 的成因是插新节时多写了一行）'
                % (rel, len(rows), last[0]))
        for k, (ln, info, raw) in enumerate(rows):
            if info and k % 2 == 1:
                errors.append(
                    '%s:%d 是带语言标记的围栏（info=%r）却落在**奇数序号** '
                    '#%d（0-based）-> 配对已错位（带标记的只能是开启围栏）。'
                    '说明此前某处多了一个 ``` 或少了一个开启围栏'
                    % (rel, ln, info, k))
    return errors


# ============================ 节序判据 ============================
#
# ## 为什么需要（2026-10-12，真实事故）
# `docs/HANDOVER.md` 的 §2.64 整块（251 行）被**插在版本行之后**：读者读到
# `*2026-10-12 v53*` 会以为文件结束了，而 §2.64（日期 2026-10-10，比 §2.77 早）
# 孤零零躺在文件尾。同一份材料里还有 `### 2.70.11` 排在 `### 2.70.10` 之前。
#
# ⚠️ 关键：**这件事没有任何判据在看**。全库搜 `版本行` / `LAST_VER` /
# `_VER_RE` / `20\d\d-\d\d-\d\d v` 在 `*.py`/`*.ps1`/`*.yml`/`*.json` 内
# **0 命中** ⇒ 版本行是纯人读的记号，节序也纯人读。于是它只能靠有人在
# 整理时偶然看见 —— 这是 §2.36.8 / §2.38 / §2.40 / §2.42 / §2.45 / §2.46
# / §2.48 / §2.54 的**同型缺陷第 N 例**：事实（标题序号）可得，无判据用它。
#
# ## 判据
# 分组 = `(标题层级, 父编号)`（`2.64.3` 的父是 `2.64`；`2.64` 的父是 `2`）。
# **同组内的子序号必须严格递增**（相等也违规 —— 实测 `docs/CONTRACT.md`
# 曾有两份 `### 6.2 策略`，且内容已分叉）。
#
# ## 三条排除规则（每一类都对应实测到的假阳性）
# ① 跳过 ``` / ~~~ 围栏内的行（`tools/attacker/android_jniptrace/README.md`
#    的 `# 3.` / `# 1.` 是 fenced bash 里的命令注释，不是编号标题）；
# ② 「单级整数 + 空格 + 非标点」判为**数量词**而非编号
#    （`ShardVase-展示文档.md:109` 的 `### 5 个公开突破`）；
# ③ `num` 后紧跟字母 ⇒ 排除（`docs/HANDOVER.md:322` 的 `### 4.2b 运维踩坑`）。
#    两条合起来把「15 处违规」收敛到「12 处真违规」，零假阳性。
#
# ## 扫描面是**自带**的，不是 `TARGETS`
# 实测：12 处里 `TARGETS`（33 份）只看得到 2 处 —— `docs/CONTRACT.md` /
# `docs/STUDIO_PROTOCOL.md` / `docs/DEFENSE_DEEPEN_PLAN.md` 都在面外
# （它们刻意不写 `> **最后核实**` 元数据）。若沿用 `TARGETS`，这条判据
# 会**自称守住了节序而实际只看 2/12** —— 那是 §2.40「扫描面自声明」同一类错误。
# 故走独立的全库 `.md` 走查（排除 `build`/`archive`/`dist`/`demo` 等）。
#
# ⚠️ 两条**失锚守卫**：文件数与兄弟组数都不得低于下限。
#    走查路径写错、或 `SKIP` 集合把 `docs` 也吃掉时，计数会静默趋零 ——
#    那时「违规 0 处」是**测不到**，不是**没问题**。
#
# ⚠️ 这两个下限**刻意留有余量**，与 §2.49 的「紧贴当前值」相反。
#    差别在**失效模式**：§2.49 防的是「用例批次被掏空」，缺口是
#    `几条`，余量会让它对小缺口失明；本判据防的是「走查面/分组键
#    写坏」，坏的幅度是**数量级** —— 实测把 `docs` 排除后 95 份 → 8 份，
#    分组键若塌掉则 427 组 → 约 95 组。故余量不会让守卫失明，
#    而紧贴当前值会给「新增一个编号小节」加税，反而催生
#    「顺手把数字调大」的坏习惯。
#    当前实测值：**95 份 / 427 组**（2026-10-12）。
HEAD_NUM = re.compile(r'^(#{1,6})[ \t]+(\d+(?:\.\d+)*)')
HEAD_SEPS = '.、)）:：'
HEAD_SKIP = frozenset(('.git', 'build', 'dist', 'archive', 'node_modules',
                       '__pycache__', 'demo'))
_HEAD_FILES_MIN = 60
_HEAD_GROUPS_MIN = 300


def numbered_heading(raw):
    """这一行是编号标题吗？是则返回 `(层级, 'x.y.z')`，否则 None。

    排除规则见上方 ②③ —— **必须在这里**，不能放到调用方，
    否则自检用例与生产走查会用两套口径。
    """
    m = HEAD_NUM.match(raw)
    if not m:
        return None
    num = m.group(2)
    sep = raw[m.end(2):m.end(2) + 1]
    if sep.isalnum() or sep == '_':
        return None                      # ③ "4.2b" 的后缀字母
    if not ((sep == '') or sep.isspace() or (sep in HEAD_SEPS)):
        return None                      # 标点不属于任何一种编号分隔符
    if '.' not in num and sep not in HEAD_SEPS:
        return None                      # ② "5 个公开突破" 是数量词
    return len(m.group(1)), num


def heading_order(docs=None):
    """收集扫描面上的编号标题。`docs=None` 时走**自带**的全库 `.md` 走查。

    返回 `[(rel, [(层级, 'x.y.z', 行号, 该行文本), ...]), ...]`。
    """
    if docs is not None:
        src = sorted(docs.items())
    else:
        src = []
        for root, dirs, files in os.walk(REPO):
            dirs[:] = [d for d in dirs if d not in HEAD_SKIP]
            for f in sorted(files):
                if not f.endswith('.md'):
                    continue
                p = os.path.join(root, f)
                rel = os.path.relpath(p, REPO).replace('\\', '/')
                try:
                    t = open(p, encoding='utf-8', errors='replace').read()
                except OSError:
                    continue
                src.append((rel, t))
    out = []
    for rel, t in src:
        hs = []
        infence = False
        for i, raw in enumerate(t.split('\n'), 1):
            s = raw.strip()
            if s.startswith(FENCE) or s.startswith('~~~'):
                infence = not infence           # ① 围栏内一律不算
                continue
            if infence:
                continue
            got = numbered_heading(raw)
            if got:
                hs.append((got[0], got[1], i, raw.strip()))
        if hs:
            out.append((rel, hs))
    return out


def check_heading_order(docs=None, min_files=None, min_groups=None):
    """断言扫描面内每份 `.md` 的**同级兄弟序号严格递增**（结构判据）。

    `docs=None` ⇒ 全库走查；自检传 `{rel: text}` 走同一口径。
    `min_files`/`min_groups` 默认取模块级紧贴值；自检必须传小值
    （合成材料只有 1-2 份文件 ⇒ 否则"失去锚点"会污染全部用例，
    §2.63 记过同型的 `tools/bom_check.py::_MIN_PS1` 坑）。
    """
    errors = []
    files = heading_order(docs)
    floor_f = _HEAD_FILES_MIN if min_files is None else min_files
    floor_g = _HEAD_GROUPS_MIN if min_groups is None else min_groups
    if len(files) < floor_f:
        errors.append(
            '节序判据失去锚点：只看到 %d 份含编号标题的 `.md`，低于下限 %d。'
            '走查路径或 `HEAD_SKIP` 可能已写坏 —— 此时"违规 0 处"是'
            '**测不到**，不是"没问题"' % (len(files), floor_f))
        return errors
    ngroups = 0
    for rel, hs in files:
        groups = {}
        for lvl, num, ln, raw in hs:
            parts = num.split('.')
            groups.setdefault((lvl, '.'.join(parts[:-1])), []).append(
                (parts[-1], ln, raw))
        for (lvl, parent), items in sorted(groups.items()):
            ngroups += 1
            tag = '##' * lvl
            for i in range(1, len(items)):
                a_prev, ln_prev, raw_prev = items[i - 1]
                a, ln, raw = items[i]
                if int(a) <= int(a_prev):
                    errors.append(
                        '%s 的第 %d 级兄弟组 `%s` 序号出序：:L%d 的 `%s` 之后'
                        '又是 :L%d 的 `%s`（%s）—— 同级序号必须严格递增。'
                        '若是"追加式记录"文档，应把新节接**下一号**并放在文末，'
                        '不要回头插旧号'
                        % (rel, lvl, parent or '(顶层)', ln_prev, raw_prev[:60],
                           ln, raw[:60],
                           '编号重复' if int(a) == int(a_prev) else '号变小'))
    if ngroups < floor_g:
        errors.append(
            '节序判据失去锚点：只组出 %d 个兄弟组，低于下限 %d —— '
            '分组键可能已写坏' % (ngroups, floor_g))
    return errors


def gated_check_names():
    """`if ($With*)` body 内的 `Check` 名集合 —— **默认调用下不跑**的那些。

    ## 为什么由结构推导，而不是硬编码名单
    当前是 3 项（`mutate_check` / `skeleton_check` / `migration_gate`）。
    硬编码这 3 个名字的写法会在**下一次新增可选门禁**时静默失效：

      · 新项不在 README 清单里（正确，因为它默认不跑），
        也不在硬编码的 gated 集合里（错误）-> 判据把"正确的省略"误报成漏项；
      · 若有人真的把新项补进 README，硬编码集合反而**放行**。

    **名单是会被漂移的东西，结构不是。** 同一条教训见 `selftest()` 里
    把漂移字面量由 `GATE_TOTAL` 推导的注释（那里已实际失效 3 次）。

    `check_gate_structure()` 已断言「每个 `if ($With*)` body 里最多一个
    `Check`」，故这里取 body 内的 Check 名是**良定义**的。

    返回 `None` 表示**扫描器前提被破坏**（文件里出现 here-string 或块注释）
    -> 调用方必须报错，**不得**把它当成"没有 gated 项"（那会让全部默认项
    被当成 gated，判据静默失效）。
    """
    p = os.path.join(REPO, 'tools', 'release_check.ps1')
    if not os.path.isfile(p):
        return None
    text = open(p, encoding='utf-8-sig').read()
    for pat in (r"@'", r'@"', r'<#'):
        if re.search(pat, text):
            return None
    rows = _ps_scan(text)
    names = set()
    for idx, (ln, op, _cl, depth, _c, raw) in enumerate(rows):
        if not re.match(r"^\s*if\s*\(\s*\$With\w+\s*\)\s*\{", raw):
            continue
        base = depth - op
        for ln2, _o2, _c2, d2, _c2s, raw2 in rows[idx + 1:]:
            if d2 <= base:
                break
            m2 = re.match(r"^\s*Check\s+'([^']+)'", raw2)
            if m2:
                names.add(m2.group(1))
    return names


def gate_threshold_constants(src=None):
    """从 `tools/migration_gate.py` 现读 M1/M3 阈值常量 —— **唯一真值源**。

    返回 `(consts, why)`，`consts = {'M3': 12.0, 'M1': 12.0}`。
    `why` 非空 = 解析前提不成立（常量被改名/换写法）；调用方必须报错，
    **不得**当成"没有阈值可对账" —— 那会让判据静默失明。
    """
    if src is None:
        p = os.path.join(REPO, 'tools', 'migration_gate.py')
        if not os.path.isfile(p):
            return None, 'tools/migration_gate.py 不存在 —— 阈值对账失去真值源'
        src = open(p, encoding='utf-8').read()
    out = {}
    for tag, nm in (('M3', 'MAX_M3'), ('M1', 'MAX_M1')):
        m = re.search(r'(?m)^%s\s*=\s*([\d.]+)' % nm, src)
        if not m:
            return None, ('在 tools/migration_gate.py 里读不到常量 `%s` '
                          '—— 阈值对账的真值源被改动，本判据不做猜测' % nm)
        out[tag] = float(m.group(1))
    return out, None


# 阈值声明的**唯一形态**：`<= N%` / `≤ N%`。
#
# ⚠️ 刻意**不**匹配「阈值 12%」这种裸写法 —— 实测（build/_threshprobe2.py）
#    两处文档里都有**叙述性**提到旧值 25% 的句子
#    （tools/migration_gate.py:24 「阈值 **12%**，不是初版的 25%」、
#     tools/release_check.ps1:651 「阈值是 **12%** 不是 25%」），
#    按裸数字匹配会把历史叙述当现值判，要求篡改叙述来变绿。
_LE_PCT = re.compile(r'(?:<=|≤)\s*(\d+(?:\.\d+)?)\s*%')


def _threshold_claims(text, base=1):
    """抽「M3/M1 … `<= N%`」形态的阈值声明 → `[(行号, 指标, 值, 原文)]`。

    `base` = `text` 首行的**绝对**行号，供调用方按被抽取片段报出真实行号。
    指标取该行里 `<=` **之前最近**的那一个 M1/M3 —— 一行写两个指标时不会错配。
    """
    out = []
    for i, ln in enumerate(text.split('\n'), base):
        for m in _LE_PCT.finditer(ln):
            head = ln[:m.start()]
            tags = [t for t in ('M3', 'M1') if t in head]
            if not tags:
                continue
            out.append((i, tags[-1], float(m.group(1)), ln.strip()))
    return out


def _comment_block_before(text, anchor, window=40):
    """取 `anchor` 行上方、**含 `<= N%` 形态阈值声明**的那一段连续 `#` 注释块。

    返回 `(块文本, 块首绝对行号)`；`(None, None)` = 找不到。

    为什么不"从 anchor 直接往上收连续 `#` 行"（2026-10-06 实测踩到）：
    `release_check.ps1` 里注释块与 `Check` 之间**隔着 `if ($WithMigration) {`**，
    直接往上收会立刻停在 `if` 行、收到空块，于是判据对**两个**指标都报
    "找不到声明" —— 看起来像文档漂移，实际是定位器坏了（同 §2.37.6 那条：
    **探针的错会伪装成被测对象的性质**）。

    故改成**内容锚定**：先在 anchor 上方 `window` 行内找到最近的
    `#` 开头的阈值声明行，再向上/向下扩到该注释块的边界。
    不硬编码行号，注释块增删几行不影响。
    """
    lines = text.split('\n')
    idx = None
    for i, ln in enumerate(lines):
        if anchor in ln:
            idx = i
            break
    if idx is None:
        return None, None
    seed = None
    for i in range(idx - 1, max(-1, idx - 1 - window), -1):
        if lines[i].lstrip().startswith('#') and _LE_PCT.search(lines[i]):
            seed = i
            break
    if seed is None:
        return None, None
    lo = seed
    while lo - 1 >= 0 and lines[lo - 1].lstrip().startswith('#'):
        lo -= 1
    hi = seed
    while hi + 1 < len(lines) and lines[hi + 1].lstrip().startswith('#'):
        hi += 1
    return '\n'.join(lines[lo:hi + 1]), lo + 1


def check_threshold_claims(gate_src=None, ps_src=None, consts=None):
    """M1/M3 阈值常量 vs 两处文档声明的一致性（**常量 → 文档**，非反向）。

    ## 为什么需要（2026-10-06，§2.43.6 自己记名的空白）
    §2.43 把 `tools/migration_gate.py` docstring 与 `tools/release_check.ps1`
    注释里的旧阈值 **25% 修成 12%** —— 但那次修复**没有机器判据**：

      · `MAX_M3` / `MAX_M1` 的唯一消费者是**它们自己的** `--selftest`
        （`tools/migration_gate.py:220-225` 写的是 `MAX_M3`, 不是字面量），
        故自检**永远绿**就算文档写错；
      · 文档里的数字**没有任何检查器在读**。

    => 下次谁改常量（或改回阈值），两处文档会**再次静默过期**，而
    `--selftest` 依旧全绿 —— 它证明的是"阈值判定逻辑能抓错",
    **不是**"文档写的阈值是对的"。这与 §2.36.8 / §2.38 / §2.40 同型:
    **事实可得, 但没有任何判据在用它。**

    ## 判据
      ① `tools/migration_gate.py` **模块 docstring** 里 M3 / M1 各至少有一条
         `<= N%` 声明，且值 == 对应常量；
      ② `tools/release_check.ps1` 里迁移成本项的 `#` 注释块同样两条；
      ③ 任一面数到 **0** 条声明 ⇒ FAIL（锚点消失，不得读成"没有漂移"）；
      ④ 常量读不到 ⇒ FAIL（真值源被改动，不猜）。

    刻意**只判这两个面**：它们是 §2.43 实际修过的地方。`tools/migration_cost.py`
    无阈值；`attacks.json` / 其它文档里的性能与成本叙述**不在判据内**（诚实边界）。
    """
    if consts is None:
        consts, why = gate_threshold_constants(gate_src)
        if why:
            return [why]

    if gate_src is None:
        gp = os.path.join(REPO, 'tools', 'migration_gate.py')
        if not os.path.isfile(gp):
            return ['tools/migration_gate.py 不存在 —— 阈值对账失去对象']
        gate_src = open(gp, encoding='utf-8').read()
    if ps_src is None:
        pp = os.path.join(REPO, 'tools', 'release_check.ps1')
        if not os.path.isfile(pp):
            return ['tools/release_check.ps1 不存在 —— 阈值对账失去对象']
        ps_src = open(pp, encoding='utf-8-sig').read()

    errors = []

    def _verdict(claims, label):
        for tag in ('M3', 'M1'):
            got = [c for c in claims if c[1] == tag]
            if not got:
                errors.append('%s: 找不到 `%s … <= N%%` 形态的阈值声明 —— '
                              '判据对 %s 失去锚点，不得读成"没有漂移"'
                              % (label, tag, tag))
                continue
            for ln, _t, v, raw in got:
                if v != consts[tag]:
                    errors.append(
                        '%s:%d %s 阈值写作 %g%%，但真值源 `MAX_%s` = %g%% '
                        '—— 文档已漂移 (%s)'
                        % (label, ln, tag, v, tag, consts[tag], raw[:70]))

    # 面 1: 真值源**自己**的模块 docstring（= 第一个三引号块）
    m = re.search(r'"""(.*?)"""', gate_src, re.S)
    if not m:
        errors.append('tools/migration_gate.py: 找不到模块 docstring —— '
                      '阈值表述面消失，不做猜测')
    else:
        base = gate_src[:m.start(1)].count('\n') + 1
        _verdict(_threshold_claims(m.group(1), base),
                 'tools/migration_gate.py docstring')

    # 面 2: release_check.ps1 迁移成本项的注释块（结构定位，不硬编码行号）
    blk, bno = _comment_block_before(ps_src, "Check '迁移成本 (migration_gate)'")
    if blk is None:
        errors.append('tools/release_check.ps1: 找不到 `Check \'迁移成本 '
                      '(migration_gate)\'` —— 注释块定位锚点消失，不做猜测')
    else:
        _verdict(_threshold_claims(blk, bno),
                 'tools/release_check.ps1 迁移成本注释块')

    return errors


# `.github/workflows/ci.yml` 门禁**项数口径**的三种声明形态。
#
# ⚠️ 为什么 `RE_GATE_N` / `RE_GATE_NN` 兜不住这三行（2026-10-06 实测）：
#    那两个正则都以 `(?:release_check|门禁)` 为**前缀锚**，而 ci.yml 的口径句
#    写的是「静态 `Check` 调用点 **37** 个」/「要求"34 项全绿"」—— 行里既无
#    `release_check` 也无 `门禁` ⇒ 两正则对该文件**零命中**；且 `.yml` 从来
#    不在 `build_targets()` 的扫描面内（面内 33 个全是 `.md`）。
#    两层都失明 => 只锚定这一个文件、用它的**专有措辞**做判据。
#    （实测命中面：`静态调用点`→:111、`默认运行`→:111、`要求N项全绿`→:115；
#      :110 的历史叙述「静态 36 / 默认 33」**刻意不匹配** —— 那是"曾经如此"。）
_CI_FORMS = (
    ('静态调用点',
     re.compile(r'静态\s*`Check`\s*调用点\s*\*{0,2}(\d+)\*{0,2}\s*个'), 'total'),
    ('默认运行',
     re.compile(r'默认运行\s*\*{0,2}(\d+)\*{0,2}\s*项'), 'default'),
    ('要求N项全绿',
     re.compile(r'要求\s*["“]?\s*\*{0,2}(\d+)\*{0,2}\s*项全绿'), 'default'),
    # ⚠️ 第四形态（2026-10-09 补）: `release_check 覆盖 N 项 (默认 M)。`
    #    它在 `ci.yml:67` 一直写着，且在第 40 项落地后就**已过期**（39/36
    #    而真值 40/37）却无人报 —— 因为上面三种措辞都不覆盖它。
    #    教训: **判据的措辞面比真值面窄**，就会留下一块静默区。
    #    把它写成**一次捕获两个数**（`both`）而不是拆成两条，是因为
    #    两个数在同一句里，拆开会让"缺一个数"变成"少一条形态"。
    ('覆盖N项默认M',
     re.compile(r'覆盖\s*\*{0,2}(\d+)\*{0,2}\s*项\s*\(\s*默认\s*'
                r'\*{0,2}(\d+)\*{0,2}\s*\)'), 'both'),
)


def _gate_counts(ps_src=None):
    """现读 `tools/release_check.ps1` → `(总项数, 默认跑项数)`；`(None, None)` = 读不到。"""
    if ps_src is None:
        p = os.path.join(REPO, 'tools', 'release_check.ps1')
        if not os.path.isfile(p):
            return None, None
        ps_src = open(p, encoding='utf-8-sig').read()
    n = len(re.findall(r"(?m)^\s*Check\s+'", ps_src))
    opt = len(re.findall(r"(?m)^\s*if\s*\(\s*\$With\w+\s*\)", ps_src))
    return n, n - opt


def ci_count_claims(ci_src=None, total=None, default=None):
    """`ci.yml` 注释里的门禁项数 vs `release_check.ps1` 的**现数**。

    ## 为什么需要（2026-10-06）
    `ci.yml:110-115` 用文字写了项数口径，是给读 CI 的人解释"为什么会看到
    `[skip]`"的关键背景。它 **不在任何扫描面内、也不被任何正则看见**，
    于是**每次新增门禁项都会静默过期一次**，只能靠人偶然看见。实测这条
    缺陷已连犯三次（`2d16b61` 35/32→36/33、`bc68b11` 36/33→37/34，之后
    `7062039` 两次新增门禁项没再动它，停在 37/34 而真值已是 39/36）。
    `:110` 那句「此前写的是过期的「静态 36 / 默认 33」」本身就是自证。
    => 与 §2.36.8 / §2.38 / §2.40 / §2.42 / §2.45 同型第 6 次：
    **事实可得，但没有任何判据在用它。**

    ## 判据
      ① `静态 Check 调用点 N 个` ⇒ N == 总项数；
      ② `默认运行 N 项` ⇒ N == 默认跑项数；
      ③ `要求"N 项全绿"` ⇒ N == 默认跑项数；
      ④ 任一形态数到 **0** 条 ⇒ FAIL（措辞改了、判据失去锚点，
         **不得**读成"没有漂移"）；
      ⑤ 任一形态多处出现则**逐处**判（不只看第一处）；
      ⑥ `覆盖 N 项 (默认 M)` ⇒ N == 总项数 **且** M == 默认跑项数
         （2026-10-09 补 —— 该形态在 `:67` 写着且已过期，此前无人报）。

    `total` / `default` 可显式传入（自检用）；省略则现读真值源。
    """
    if total is None or default is None:
        t, d = _gate_counts()
        if t is None:
            return ['tools/release_check.ps1 不存在 —— ci.yml 项数口径失去真值源']
        total, default = t, d
    if ci_src is None:
        p = os.path.join(REPO, '.github', 'workflows', 'ci.yml')
        if not os.path.isfile(p):
            return ['.github/workflows/ci.yml 不存在 —— 项数口径对账失去对象']
        ci_src = open(p, encoding='utf-8').read()

    errors = []
    for label, rx, kind in _CI_FORMS:
        hits = [(ci_src[:m.start()].count('\n') + 1, m) for m in rx.finditer(ci_src)]
        if not hits:
            errors.append('.github/workflows/ci.yml: 找不到「%s」形态的项数声明 '
                          '—— 判据失去锚点，不得读成"没有漂移"' % label)
            continue
        for ln, m in hits:
            if kind == 'both':
                pairs = ((int(m.group(1)), total, '静态 Check 调用点'),
                         (int(m.group(2)), default,
                          '默认跑的项数（总 %d − -With* %d）' % (total, total - default)))
            else:
                want = total if kind == 'total' else default
                what = ('静态 Check 调用点' if kind == 'total'
                        else '默认跑的项数（总 %d − -With* %d）'
                             % (total, total - default))
                pairs = ((int(m.group(1)), want, what),)
            for v, want, what in pairs:
                if v != want:
                    errors.append('.github/workflows/ci.yml:%d 「%s」写作 %d，'
                                  '但真值 = %d（%s）—— 注释已漂移'
                                  % (ln, label, v, want, what))
    return errors


# `tools/ci_sim.ps1` 与 `.github/workflows/ci.yml` 的**工具集**比对。
#
# ⚠️ 为什么按**工具 basename** 比而不是按**步骤名**比（2026-10-06 实测）：
#    两侧的步骤名措辞本来就不同（`:45 Run e2e suite (T1-T30)` vs
#    `Step 'e2e T1-T30'`；`:68 Module contract (modcheck)` vs
#    `Step '模块契约 (modcheck)'`）—— 按名字比会得到一片假差异；
#    路径风格也不同（`tools/modcheck.py` vs `tools\modcheck.py`）。
#    唯一稳定可比且**机器可判**的键是**文件 basename**。
_TOOL_RE = re.compile(r'([A-Za-z0-9_\-]+\.(?:py|ps1|exe))')

# ci_sim **刻意不跑**的 ci.yml 步骤（各有理由，见 `tools/ci_sim.ps1:13-19`）。
# 列进来 = 显式豁免，漏掉依赖 = FAIL。加项必须写理由。
_CI_SIM_EXEMPT = {
    'mutate_check.py': '本机实测 187s，耗时级别不同（CI 与 -WithMutation 负责）',
    'migration_gate.py': '本机实测 108s，且 M3 有工具链抖动'
                         '（本机 15.6% FAIL / CI 6.2% PASS，§2.43）'
                         '—— 本地跑会把 CI 的绿读成红',
    # 这里**刻意不写项数**：写死过一次（"门禁自己含 39 项"），第 40 项落地后
    # 它就静默过期了 —— 而这个文件不在 doccheck 自己的 TARGETS 里（只扫 .md），
    # 任何计数判据都看不见它。§2.39 的取向：数字无信息量就删掉，别改成新数字。
    'release_check.ps1': '门禁本体：`ci_sim` 已经跑了一遍 Build，嵌套跑会重复构建'
                         '且职责重叠（门禁本体含全部检查项 + Release 构建）。'
                         'CI 侧由 `:127 Full release gate` 负责',
}

# `Step '<名>' { ... }` 的 body 提取。**必须只扫 body，不能扫全文** ——
# 见 `ci_sim_tool_sets()` 的注释（注释里的工具名会让判据以为"已经跑了"）。
_STEP_HEAD = re.compile(r"^\s*Step\s+'")


def _step_body_tools(text):
    """只收集 `Step` 块 **body** 里的工具 basename（注释行不算）。

    ⚠️ 为什么不能扫全文（2026-10-06 实测，本轮自己踩的坑）：本文件在
    `tools/ci_sim.ps1:18` / `:94` 的**注释**里写了 `release_check.ps1`，
    而"刻意排除"的 `mutate_check` / `migration_gate` 写的是不带后缀的
    短名 —— 于是扫全文时 `release_check.ps1` **看起来已被覆盖**，
    判据对**恰好是那个真缺口**失明；同时豁免项检查（判据②）也因注释
    里的短名而侥幸不触发。这与 §2.40「扫描面自声明」是同一类错误：
    **声明本身被当成了覆盖**。
    """
    out = set()
    lines = text.replace('\r\n', '\n').split('\n')
    depth = 0
    for l in lines:
        if _STEP_HEAD.match(l):
            depth = l.count('{') - l.count('}')
            for t in _TOOL_RE.findall(l):
                out.add(t)
            continue
        if depth > 0:
            body = l.split('#', 1)[0]          # 行内注释也剥掉
            for t in _TOOL_RE.findall(body):
                out.add(t)
            depth += l.count('{') - l.count('}')
    return out


def ci_sim_tool_sets(ci_src=None, sim_src=None):
    """现读 ci.yml 的 `build-and-verify` job 与 `ci_sim.ps1` → `(ci_tools, sim_tools)`。

    `ci_tools` = `{basename: 首次出现行号}`（只取该 job 的 `run:` 行）；
    `sim_tools` = basename 集合（**只取 `Step` 块 body**，注释不算 ——
    理由见 `_step_body_tools()`）。`(None, None)` = 读不到真值源。
    """
    if ci_src is None:
        cp = os.path.join(REPO, '.github', 'workflows', 'ci.yml')
        if not os.path.isfile(cp):
            return None, None
        ci_src = open(cp, encoding='utf-8').read()
    if sim_src is None:
        sp = os.path.join(REPO, 'tools', 'ci_sim.ps1')
        if not os.path.isfile(sp):
            return None, None
        sim_src = open(sp, encoding='utf-8-sig').read()

    lines = ci_src.replace('\r\n', '\n').split('\n')
    start = next((i for i, l in enumerate(lines)
                  if l.startswith('  build-and-verify:')), None)
    if start is None:
        return None, None
    end = start + 1
    while end < len(lines):
        l = lines[end]
        if (l.startswith('  ') and not l.startswith('   ')
                and l.rstrip().endswith(':') and l.strip()):
            break
        end += 1

    ci_tools = {}
    i = start
    while i < end:
        m = re.match(r'^\s+run:\s*(.*)$', lines[i])
        if m:
            body = m.group(1).strip()
            if body and body != '|':
                for t in _TOOL_RE.findall(body):
                    ci_tools.setdefault(t, i + 1)
            else:
                j = i + 1
                while j < end:
                    if lines[j].strip() == '' or lines[j].startswith(' ' * 10):
                        for t in _TOOL_RE.findall(lines[j].strip()):
                            ci_tools.setdefault(t, j + 1)
                        j += 1
                    else:
                        break
                i = j - 1
        i += 1

    return ci_tools, _step_body_tools(sim_src)


def ci_sim_sync(ci_src=None, sim_src=None, exempt=None):
    """`ci_sim.ps1` 与 ci.yml `build-and-verify` 的**工具集**覆盖差。

    ## 为什么需要（2026-10-06）
    `tools/ci_sim.ps1:6` 一直写着「步骤映射 (保持与 ci.yml 同步; 每次改
    ci.yml 必须同步这里)」—— 这是**人工承诺，无任何机器判据**。实测：
    ci.yml 该 job 用 16 个工具，ci_sim 只覆盖 14 个，缺的恰是
    `modcheck.py` / `drills.py` / `doccheck.py` / `conformance.py` /
    `skeleton_check.py` 五步（前三者 + conformance 合计 <0.5s，没有
    "为省时间而排除"的理由），且**从未跑过门禁本体** `release_check.ps1`。
    => 与 §2.36.8 / §2.38 / §2.40 / §2.42 / §2.45 / §2.46 同型第 7 次。

    ## 判据
      ① ci.yml 该 job 里出现、`ci_sim.ps1` 里**没有**的工具，若不豁免 ⇒ FAIL；
      ② `_CI_SIM_EXEMPT` 里列的豁免项若**在 ci_sim 里出现了** ⇒ FAIL
         （豁免过期，必须删掉，否则会掩盖真的漏项）；
      ③ 任一侧数到 **0** 个工具 ⇒ FAIL（解析前提被破坏，不得读成"没有差异"）。
    """
    if ci_src is None or sim_src is None:
        ct, st = ci_sim_tool_sets(ci_src, sim_src)
        if ct is None:
            return ['ci.yml 的 build-and-verify job 或 tools/ci_sim.ps1 不存在 '
                    '—— 同步判据失去真值源']
        ci_tools, sim_tools = ct, st
    else:
        ci_tools, sim_tools = ci_src, sim_src
    if exempt is None:
        exempt = _CI_SIM_EXEMPT

    errors = []
    if not ci_tools:
        errors.append('.github/workflows/ci.yml 的 build-and-verify job 里数到 0 个工具 '
                      '—— 判据失去锚点，不得读成"没有差异"')
    if not sim_tools:
        errors.append('tools/ci_sim.ps1 里数到 0 个工具 —— 判据失去锚点，'
                      '不得读成"没有差异"')
    if errors:
        return errors

    missing = sorted(set(ci_tools) - sim_tools)
    for t in missing:
        if t in exempt:
            continue
        errors.append('tools/ci_sim.ps1 缺 ci.yml 的步骤（工具 `%s`，ci.yml:%d）'
                      '——:6 声明"保持与 ci.yml 同步"，但该工具从未在本模拟器执行；'
                      '要么补 Step，要么加进 _CI_SIM_EXEMPT 并写明理由' % (t, ci_tools[t]))
    for t in sorted(exempt):
        if t in sim_tools:
            errors.append('tools/ci_sim.ps1 的豁免项 `%s` 其实**已经跑了** '
                          '—— 豁免过期，必须从 _CI_SIM_EXEMPT 删掉'
                          '（留着一个已经满足的豁免会掩盖真的漏项）' % t)
    return errors


def parse_readme_gate_list(text):
    """从 `README.md` 抽出"默认跑的全部 N 项"清单块的成员名。

    返回 `(names, declared, why)`。`why` 非空 = **解析前提不成立**（结构被
    改动），`names` 为 `None` —— 调用方必须报错，**不得**当成空清单：
    空清单会让"漏项"判据对每一项都命中，看起来像几十条错误，
    实际是解析器坏了（"探针的错会伪装成被测对象的性质"，§2.37.6）。

    两列 ASCII 排版靠 `[ok]` 切分即可 —— 右列的前置空格由 `strip()` 吃掉。
    2026-10-06 实测：按 `[ok]` 切分得 36 条；改用"前瞻吃右列"的正则只得 20 条。
    """
    m = re.search(r'默认跑的全部\s*(\d+)\s*项[：:]\s*\n```\n(.*?)```', text, re.S)
    if not m:
        return None, None, ('README.md 里找不到「默认跑的全部 N 项：」+ 围栏'
                            '清单块 —— 判据前提被破坏，不做猜测')
    declared = int(m.group(1))
    body = m.group(2)
    if '[ok]' not in body:
        return None, None, ('README.md 的门禁清单块里没有任何 `[ok]` 行 '
                            '—— 结构被改动，不做猜测')
    names = [x.strip() for x in body.split('[ok]')[1:]]
    return [x for x in names if x], declared, None


_GATE_TAIL_PAREN = re.compile(r'\s*\([^()]*\)\s*$')


def _gate_base(s):
    """门禁项名的**基名** —— 去掉尾部括注、压平空白。

    README 的清单为两列对齐做了**有意的缩写**，已记名两处：

      `manifest.json 版本非占位`                 -> `版本非占位`
      `Release 构建 (build.ps1 -Config Release)` -> `Release 构建 (build.ps1)`

    两者在基名层面都是「README 名是源名的**连续子串**」。判据就取这一条。
    """
    s = re.sub(r'\s+', ' ', s).strip()
    prev = None
    while prev != s:
        prev = s
        s = _GATE_TAIL_PAREN.sub('', s).strip()
    return s


def _gate_match(rbase, cbase):
    """README 清单项的基名是否指向某个门禁项 —— 连续子串，且基名非空。

    空基名会匹配一切，故显式排除；过短的基名会同时命中多项，
    由调用方的「恰好 1 条」判据报成**歧义**，而不是静默放行。
    """
    return bool(rbase) and rbase in cbase


def check_readme_gate_list(text=None, checks=None, gated=None):
    """README.md 的"默认跑的全部 N 项"清单 —— **成员集合**必须与结构一致。

    ## 为什么需要（2026-10-06）
    `tools/doccheck.py` 一直只判**计数**（`36` / `39` 这两个数字），
    不判**成员**。实测（`build/_readmelist.py`）证明当前 36 条成员与
    「39 个 `Check` − 3 个 `-With*` 控制项」**完全一致** —— 但这一致性
    **没有任何门禁在守**：漏列一项而数字仍写 36，doccheck 不会红。
    同型于 §2.36.8（补了清单但没换机制）与 §2.38（语法检查枚举只覆盖 23/95）。

    ## 判据（五条，全部由事实推导，无硬编码名单）
      ① 清单条数 == `Check` 总数 − gated 项数（两边都是**算出来的**）
      ② 每个默认跑项在清单里**恰好**命中一条（0 条 = 漏项；>1 条 = 歧义）
      ③ 清单里每一条都**恰好**命中一个默认跑项（0 条 = 幽灵项 / 措辞漂移）
      ④ gated 项**不得**出现在"默认跑"清单里（它默认不跑，列进去是错的）
      ⑤ 散文里那个 `N` 也必须等于默认跑项数 —— 见下。

    ②③ 各要求"恰好 1"，合起来即**双向唯一匹配** —— 这比"存在某个匹配"
    强得多，后者会被一个足够短的清单项蒙混过关。

    ## ⑤ 为什么散文里的数字要单独判（2026-10-06 实测补）
    判据 ① 比的是**清单条数**（数出来的），**不是**那句散文里写的 `N`。
    实测（`build/_readmenum_mut.py`）：把 `README.md:132` 的
    `**36 项**（默认` 改成 `**37 项**`、**清单一个字都不动**，
    `doccheck` 仍然 **rc=0、无任何报错** —— 那时 `declared`（37）已被
    `parse_readme_gate_list` 解析出来，却在调用处被写成 `_declared` **丢弃**。
    解析出来了却不判，等于没解析；这与 §2.36.8/§2.38 同型：
    **事实可得，但没有任何判据在用它**。

    ## 诚实边界
      · 只覆盖 `README.md` 这一处清单。其它文档里的门禁枚举**不在判据内**：
        实测（`build/_scanface_gap.py`）doccheck 的扫描面是**自声明**的
        （`build_targets()` 只收头部带 `> **最后核实**` 的 `docs/**`），
        故 `README.md` / `CONTRIBUTING.md` / `docs/阶段总结-*.md` 等
        **42 个文件**里含现时值计数的位置**全部在扫描面之外**，无人守。
      · 匹配用基名的连续子串来容忍 README 的排版缩写；它**不是**模糊匹配，
        但过短的基名会命中多项 -> 由 ② 的 ">1 = 歧义" 报出来。
      · **只判成员集合，不判排版**（两列对齐、`[ok]` 前缀、缩写本身）。
        排版确实只能靠人维护；成员不该。
    """
    if text is None:
        p = os.path.join(REPO, 'README.md')
        if not os.path.isfile(p):
            return ['README.md 不存在 —— 门禁清单成员判据失去对象']
        text = open(p, encoding='utf-8').read()

    names, declared, why = parse_readme_gate_list(text)
    if why:
        return ['README.md 门禁清单: ' + why]

    if checks is None:
        p = os.path.join(REPO, 'tools', 'release_check.ps1')
        if not os.path.isfile(p):
            return ['tools/release_check.ps1 不存在 —— 成员判据失去基准']
        checks = re.findall(r"(?m)^\s*Check\s+'([^']+)'",
                            open(p, encoding='utf-8-sig').read())
    if gated is None:
        gated = gated_check_names()
        if gated is None:
            return ['README.md 门禁清单: release_check.ps1 的结构扫描前提被'
                    '破坏 -> 无法确定哪些项受 -With* 控制；本判据**不做猜测**']

    # 自证: 任一侧数到 0 说明判据或扫描器坏了 —— 宁 FAIL 不静默通过。
    if not checks:
        return ['README.md 门禁清单: 从 release_check.ps1 数到 **0** 个 `Check` '
                '-> 扫描器已失效，不要读成"没有漏项"']
    if not names:
        return ['README.md 门禁清单: 清单块里数到 **0** 条成员 '
                '-> 解析已失效，不要读成"没有漏项"']

    default = [c for c in checks if c not in gated]
    errors = []

    if len(names) != len(default):
        errors.append(
            'README.md 清单 %d 条，但默认跑的门禁项有 %d 项'
            '（%d 个 Check − %d 个 -With* 控制项）—— 计数或成员已漂移'
            % (len(names), len(default), len(checks), len(gated)))

    # ⑤ 散文里的数字（与 ① 数出来的清单条数是**两件事**）。
    # 2026-10-06 实测：只改这个数字、清单不动，旧判据完全失明。
    if declared is not None and declared != len(default):
        errors.append(
            'README.md 散文声称「默认跑的全部 %d 项」，但实际默认跑 %d 项'
            '（%d 个 Check − %d 个 -With* 控制项）—— 散文数字已漂移'
            % (declared, len(default), len(checks), len(gated)))

    rbase = [(n, _gate_base(n)) for n in names]
    cbase = [(n, _gate_base(n)) for n in default]

    for cn, cb in cbase:
        hit = [rn for rn, rb in rbase if _gate_match(rb, cb)]
        if not hit:
            errors.append('README.md 未列出默认跑的门禁项 `%s`（清单漏项）' % cn)
        elif len(hit) > 1:
            errors.append('README.md 里有 %d 条清单项都指向门禁项 `%s`（%s）'
                          ' —— 匹配歧义，判据无法判定'
                          % (len(hit), cn, '、'.join(hit)))

    for rn, rb in rbase:
        hit = [cn for cn, cb in cbase if _gate_match(rb, cb)]
        if not hit:
            errors.append('README.md 清单项 `%s` 在 release_check.ps1 里没有'
                          '对应项（幽灵项或措辞漂移）' % rn)
        elif len(hit) > 1:
            errors.append('README.md 清单项 `%s` 同时命中 %d 个门禁项（%s）'
                          ' —— 匹配歧义' % (rn, len(hit), '、'.join(hit)))

    for gn in sorted(gated):
        gb = _gate_base(gn)
        hit = [rn for rn, rb in rbase if _gate_match(rb, gb)]
        if hit:
            errors.append('README.md 的"默认跑"清单里出现了受 -With* 控制的项 '
                          '`%s`（以 %s 形式）—— 它默认不跑，不该列进去'
                          % (gn, '、'.join(hit)))
    return errors


def actual_rounds():
    """docs/ATTACK_DRILL*.md 的实际轮次数量。"""
    docs = glob.glob(os.path.join(REPO, 'docs', 'ATTACK_DRILL*.md'))
    return len(docs)


def check_publish_links():
    """校验 publish/ 内部互链 (该目录发布到自建博客, 文件并排)。

    约定: publish/X.md 之间应写**同目录相对路径** (如 `07-攻防记录.md`),
    而非 `../../publish/X.md` —— 后者在博客渲染时会越界 404。
    (实测发现: 06-诚实边界.md 曾用错误形式, 其余文件均正确。)
    """
    errors = []
    checked = 0
    pub = os.path.join(REPO, 'publish')
    if not os.path.isdir(pub):
        return errors, checked
    for name in sorted(os.listdir(pub)):
        if not name.endswith('.md'):
            continue
        p = os.path.join(pub, name)
        text = open(p, encoding='utf-8').read()
        for m in re.finditer(r'\[([^\]]{1,24})\]\(([^)\s]+)\)', text):
            href = m.group(2)
            if href.startswith(('http://', 'https://', '#')):
                continue
            checked += 1
            ln = text[:m.start()].count('\n') + 1
            target = href.partition('#')[0]
            if not target:
                continue
            resolved = os.path.normpath(os.path.join(pub, target))
            rel = os.path.relpath(resolved, pub)
            if rel.startswith('..'):
                errors.append(
                    'publish/%s:%d 链接越出 publish/ : %s '
                    '(该目录发布为并排文件 -> 请用同目录路径)'
                    % (name, ln, href))
            elif not os.path.exists(resolved):
                errors.append('publish/%s:%d 目标不存在: %s'
                              % (name, ln, href))
    return errors, checked


def check_issue_links():
    """校验 Issue 链接的"语义 <-> 模板"匹配。

    背景 (2026-09-21 实测): Issue 模板只存在于 **ShardVase-docs** 仓库。
    两个真实错误被此检查发现:
      1. 演示包 README 指向 ShardVase-demo/issues/new —— 该仓库无模板,
         用户点进去只有空白 Issue
      2. 「接入咨询」链接误用 eval.yml 模板 (应为 consult.yml)

    检查三条:
      · 目标仓库必须有 Issue 模板
      · template= 参数必须存在于该仓库
      · 标签语义与模板类型一致 (评估->eval / 咨询->consult / 安全->security)
    """
    import glob as _glob
    errors = []
    checked = 0

    # 有 Issue 模板的仓库 (与 gh api tree 核对过)
    templated = {'ShardVase-docs': {'eval.yml', 'consult.yml', 'security.yml'}}

    EXPECT = [
        (('评估申请', '申请评估', '评估授权', '申请授权'), 'eval.yml'),
        (('接入咨询', '咨询'), 'consult.yml'),
        (('漏洞报告', '报告漏洞', 'security', '安全'), 'security.yml'),
    ]

    files = set()
    for pat in ('*/*.md', '*/*.html', 'docs/**/*.md', 'prot_sdk/**/*.md'):
        for f in _glob.glob(os.path.join(REPO, pat), recursive=True):
            if os.path.isfile(f):
                files.add(f)

    pat_md = re.compile(r'\[([^\]]{1,30})\]\((https://github[^)\s]*issues/new[^)\s]*)\)')
    pat_html = re.compile(r'<a[^>]*href="(https://github[^"]*issues/new[^"]*)"[^>]*>([^<]{1,30})</a>')

    for f in sorted(files):
        rel = os.path.relpath(f, REPO)
        if '\\build\\' in f or '/build/' in f.replace('\\', '/'):
            pass          # build/ 未入库, 但仍检查（打包用）
        try:
            text = open(f, encoding='utf-8', errors='replace').read()
        except OSError:
            continue
        found = [(m.group(1), m.group(2)) for m in pat_md.finditer(text)]
        found += [(m.group(2), m.group(1)) for m in pat_html.finditer(text)]
        for label, url in found:
            checked += 1
            m = re.match(r'https://github\.com/auui-LDAH/([\w-]+)/issues/new', url)
            if not m:
                continue
            repo = m.group(1)
            ln = text[:text.find(url)].count('\n') + 1
            if repo not in templated:
                errors.append('%s:%d Issue 链接指向无模板的仓库 %s: %s'
                              % (rel, ln, repo, url[:60]))
                continue
            tm = re.search(r'template=([\w.]+)', url)
            tmpl = tm.group(1) if tm else None
            if tmpl and tmpl not in templated[repo]:
                errors.append('%s:%d 仓库 %s 无模板 %s'
                              % (rel, ln, repo, tmpl))
                continue
            exp = None
            for keys, tpl in EXPECT:
                if any(k in label for k in keys):
                    exp = tpl
                    break
            if exp and tmpl != exp:
                errors.append('%s:%d「%s」链接用了 %s, 应为 %s'
                              % (rel, ln, label.strip(), tmpl or '(无)', exp))
    return errors, checked


def check_text(rel, t, gate, rounds, exc, exists=None):
    """对单个文档文本跑规则 1–4, 返回 (errors, warnings, checked)。

    抽成函数是为了让 `--selftest` 能在**内存里的改动副本**上跑同一套判据 ——
    负向测试必须走与生产**完全同一条**代码路径, 否则测的是另一个实现。

    `exists(path)` 可注入, 供自检伪造文件存在性 (默认查真实仓库)。
    """
    if exists is None:
        exists = lambda p: os.path.exists(os.path.join(REPO, p))  # noqa: E731
    errors, warnings, checked = [], [], 0
    view = DocView(t, rel)

    def _hit(m, kind):
        """返回 (0-based 行号, 豁免类别)。"""
        i = view.line_of(m.start())
        return i, view.exempt(i, m, kind)

    # --- 1. 模糊表述 (排除引用/否定语境) ---
    for pat, why in VAGUE_PATTERNS:
        for m in re.finditer(pat, t):
            if _is_quoted_or_negated(t, m.start(), m.end()):
                continue
            i, why_ex = _hit(m, 'vague')
            if why_ex:
                exc[why_ex] = exc.get(why_ex, 0) + 1
                continue
            errors.append('%s:%d 出现%s' % (rel, i + 1, why))

    # --- 2. 门禁项数: `N/N` 与 `N 项` 两种形态, 比分母 ---
    for m in re.finditer(RE_GATE_NN, t):
        checked += 1
        claim = int(m.group(2))
        if claim in GATE_OK:
            continue
        i, why_ex = _hit(m, 'nn')
        if why_ex:
            exc[why_ex] = exc.get(why_ex, 0) + 1
            continue
        if gate is not None:
            errors.append('%s:%d 门禁项数声称 %d, 实际 %d'
                          % (rel, i + 1, claim, gate))
    for m in re.finditer(RE_GATE_N, t):
        checked += 1
        claim = int(m.group(1))
        if claim in GATE_OK:
            continue
        # `第 N 项` 是序号, 不是总数 —— 直接放行, 不进豁免统计
        win = t[max(0, m.start() - 6):m.end() + 2]
        if RE_ORDINAL.search(win):
            continue
        i, why_ex = _hit(m, 'nge')
        if why_ex:
            exc[why_ex] = exc.get(why_ex, 0) + 1
            continue
        if gate is not None:
            errors.append('%s:%d 门禁项数声称 %d 项, 实际 %d'
                          % (rel, i + 1, claim, gate))

    # --- 3. 轮次口径 ---
    for m in re.finditer(r'(\d+)\s*\+?\s*轮(?:正式|完整|攻防|演练)?', t):
        claim = int(m.group(1))
        i = view.line_of(m.start())
        # 只检查"攻防演练轮次"这类主口径 (排除"第一轮/第二轮"表格行)
        if re.search(r'第[一二三四五六七八九十\d]+轮',
                     t[max(0, m.start()-6):m.start()+8]):
            continue
        why_ex = view.exempt(i, m, 'round')
        if why_ex:
            exc[why_ex] = exc.get(why_ex, 0) + 1
            continue
        checked += 1
        if claim not in (rounds, rounds - 1) and '矩阵' in t[m.start():m.start()+30]:
            warnings.append('%s:%d 轮次声称 %d, 实际 %d (请确认口径)'
                            % (rel, i + 1, claim, rounds))

    # --- 4. 引用的仓库内路径 (死链是错误, 不是警告) ---
    for m in re.finditer(r'`((?:docs|tools|tests|src|include|prot_sdk|publish|drills|compositions)/[\w\-./]+)`', t):
        checked += 1
        if exists(m.group(1)):
            continue
        i = view.line_of(m.start())
        # 规划中的交付物 / 显式声明不存在 —— 不是死链
        if PLANNED.search(view.lines[i]):
            exc['规划交付物'] = exc.get('规划交付物', 0) + 1
            continue
        # 验收条件里的路径 = 尚待交付的目标 (docs/CONTINUATION_PLAN.md:397)
        if view.plan_ctx(i, m):
            exc['计划验收'] = exc.get('计划验收', 0) + 1
            continue
        errors.append('%s:%d 引用路径不存在: %s'
                      % (rel, i + 1, m.group(1)))
    return errors, warnings, checked


def selftest():
    """负向自检: 判据**必须在真缺陷出现时报错**, 且**不得**把合规写法误报。

    为什么必须有: 本工具的判据含 7 类豁免, 豁免越多越容易"宽到什么都不报"。
    只验"仓库当前 PASS"是不够的 —— 一个恒返回空的检查器也能 PASS。
    故每个规则都配一条**注入缺陷 -> 必须 FAIL** 的用例。
    """
    cases = []          # (名称, 文本, 期望错误数)

    def case(name, text, n):
        cases.append((name, text, n))

    # --- 数字漂移: `N/N` 与 `N 项` 两种形态都必须抓到 ---
    # 判据: 漂移字面量必须**不在** {GATE_TOTAL, GATE_DEFAULT} 里。
    #
    # ⚠️ 这些字面量**由 GATE_TOTAL/GATE_DEFAULT 推导, 不再硬编码**。
    #    硬编码版本每轮项数递增都会静默失效, 已实际发生 3 次:
    #      · 32 曾是合法默认值, 34/31 之后 32 变成漂移 (当时手工重挑);
    #      · 2026-10-05 (36/33 -> 37/34): `34 项` 变成合法默认值 (手工重挑);
    #      · 2026-10-06 (37/34 -> 38/35): `35 项` 变成合法默认值 → 两条
    #        "必须报错"的用例零报错而自检失败。**这次是门禁抓到的**:
    #        主检 `doccheck` 仍 PASS, 但 `--selftest` FAIL 5/20, 红在
    #        `对外材料 (doccheck)` 项上 —— 且是在 `f4b27f4` 提交**之后**。
    #    教训: 判据里凡是"必须不落在某集合内"的常量, 都应由那个集合推导。
    #    否则它是一次性的: 集合一动, 判据就悄悄失去判别力而**不报错**。
    #    注: 漂移用例失效**不会**让主检变红, 只在 --selftest 里失败;
    #    门禁已把 `--selftest` 串在主检之前, 故改计数必须先过自检这一关。
    DRIFT = max(GATE_TOTAL, GATE_DEFAULT) + 1
    assert DRIFT not in (GATE_TOTAL, GATE_DEFAULT), '漂移字面量不得落在容差内'
    case('N/N 漂移', '门禁 %d/%d 全通过\n' % (DRIFT, DRIFT), 1)
    case('N 项漂移', 'release_check %d 项全通过\n' % DRIFT, 1)
    case('N 项 + 强调漂移', '门禁 **%d** 项\n' % DRIFT, 1)
    case('正确值不报', '门禁 %d/%d 全通过\nrelease_check %d 项\n'
         % (GATE_TOTAL, GATE_TOTAL, GATE_DEFAULT), 0)
    # 比分母, 不是分子: 分母对即放行 (分子是"通过数", 任意值都合法)
    case('分母正确/分子是失败数 -> 放行',
         '门禁 21/%d（唯一失败=未提交）\n' % GATE_TOTAL, 0)
    case('分母错误 -> 必报', '门禁 %d/%d\n' % (GATE_TOTAL, DRIFT), 1)
    # 豁免必须仍然生效 (否则"多报"也是判据失效)
    case('代码块内 -> 豁免', '```\n门禁 11/11\n```\n', 0)
    case('带日期的历史标题 -> 豁免', '## 2.5 验收（2026-08-30 增量）\n门禁 11/11\n', 0)
    case('沿革 -> 豁免', '门禁项数 11/15/22/26/31/36 → **%d**\n' % GATE_TOTAL, 0)
    case('序号 -> 豁免', '门禁默认第 20 项\n', 0)
    case('自带日期 -> 豁免', '门禁 **26** 项 · 2026-09-29\n', 0)
    case('转述他文(带行号) -> 豁免', 'docs/HANDOVER.md:237 门禁 32 项\n', 0)
    case('计划验收列 -> 豁免', '| 子阶段 | 内容 | 验收 |\n|---|---|---|\n| A-c | x | 门禁 22 项全通过 |\n', 0)
    case('无验收列的表 -> 必须报', '| 优先级 | 项 | 状态 |\n|---|---|---|\n| 剩余待办 | 门禁 11/11 绿 | 待 |\n', 1)

    # --- 模糊表述 ---
    case('模糊表述', '累计 0 破防点\n', 1)
    case('否定语境 -> 豁免', '> **我们不写"0 破防"** —— 那是模糊表述。\n', 0)
    case('合规写法(显式破防 N 项) -> 不报', '累计 BLOCKED 54 / 显式破防 5 项\n', 0)

    # --- 死链 ---
    case('死链', '见 `docs/NO_SUCH_FILE_XYZ.md`\n', 1)
    case('规划交付物 -> 豁免', '输出：`tools/no_such_tool_xyz.py`\n', 0)
    case('验收条件里的路径 -> 豁免', '**Q5 验收**: `docs/no_such_drill_xyz.md` 存在\n', 0)

    # --- 判据的判据: 把真实仓库里**已声明现值**的正确值改坏, 必须报错 ---
    # 内存副本, 不落盘: 自检不得改动工作区。
    rel = 'publish/01-关于ShardVase.md'
    fails = []
    try:
        real = open(os.path.join(REPO, rel), encoding='utf-8').read()
    except OSError:
        real = None

    for name, text, want in cases:
        exc = {}
        e, w, c = check_text('<selftest>', text, GATE_TOTAL, 8, exc,
                             exists=lambda p: False)
        got = len(e)
        if got != want:
            fails.append('%s: 期望 %d 条错误, 实际 %d 条 (%s)'
                         % (name, want, got, e[:1]))

    # 真实文档用例必须走**真实的**存在性判断 (否则它自身的链接全成死链),
    # 且只改一处数字, 预期错误数恰好为 1。
    # 锚点同样**由 GATE_TOTAL 推导** —— 硬编码 `37/37` 会在计数上调后
    # 静默失去锚点 (2026-10-06 实际发生: 文档已改 38/38, 而这里仍找 37/37),
    # 故 bad 取 DRIFT 值 (已断言不在容差内), 而不是某个凭记忆挑的数字。
    real_case = None
    if real is None:
        fails.append('%s 不可读 —— 负向用例失去锚点' % rel)
    else:
        for good, bad in (('%d/%d' % (GATE_TOTAL, GATE_TOTAL), '%d/%d' % (DRIFT, DRIFT)),
                          ('%d 项' % GATE_TOTAL, '%d 项' % DRIFT)):
            if good in real:
                real_case = ('真实文档 %s: %s -> %s 必须报' % (rel, good, bad),
                             real.replace(good, bad))
                break
        else:
            fails.append('%s 里既无 `%d/%d` 也无 `%d 项` —— '
                         '负向用例失去锚点, 请改用其他已声明现值的文档'
                         % (rel, GATE_TOTAL, GATE_TOTAL, GATE_TOTAL))
    if real_case:
        cases.append(real_case + (1,))
        exc = {}
        e, _, _ = check_text(rel, real_case[1], GATE_TOTAL, 8, exc)
        if len(e) != 1:
            fails.append('%s: 期望 1 条错误, 实际 %d 条 (%s)'
                         % (real_case[0], len(e), e[:2]))

    # --- README 门禁清单的**成员集合**（计数之外的判据）---
    #
    # 计数有下面那套数字漂移判据兜；**成员**此前无人断言 —— 漏列一项而
    # 总数仍写 36，doccheck 不会红（2026-10-06 实测确认）。
    # 一个"漏一项也不报"的成员判据只是恒真的装饰，故逐条注入缺陷。
    #
    # ⚠️ 基准（`Check` 名 / gated 集合 / README 原文）全部**从仓库现读**，
    #    不抄字面量：抄下来的清单会在下次增项时静默失去锚点 ——
    #    这正是上面 `DRIFT` 那段注释记的三次失效的同一条教训。
    _rcp = os.path.join(REPO, 'tools', 'release_check.ps1')
    _rdp = os.path.join(REPO, 'README.md')
    _all, _gated, _rd = None, None, None
    try:
        _all = re.findall(r"(?m)^\s*Check\s+'([^']+)'",
                          open(_rcp, encoding='utf-8-sig').read())
        _gated = gated_check_names()
        _rd = open(_rdp, encoding='utf-8').read()
    except OSError:
        pass

    gl_cases = []
    if not _all or not _gated or _rd is None:
        fails.append('README 门禁清单用例失去基准（读不到 release_check.ps1 '
                     '或 README.md）—— 判据未被负向验证，不得视为通过')
    else:
        _default = [c for c in _all if c not in _gated]

        def _mk(names, declared=None):
            # declared 默认取 names 条数（绝大多数用例要测的是**成员**）；
            # 要单独测散文数字时显式传入。
            d = len(names) if declared is None else declared
            body = ''.join('[ok] %s\n' % n for n in names)
            return '默认跑的全部 %d 项：\n```\n%s```\n' % (d, body)

        gl_cases = [
            ('真实 README 清单 -> 不报', _rd, 0, None),
            ('漏列一项 -> 必须报', _mk(_default[1:]), 3, '未列出'),
            ('幽灵项 -> 必须报',
             _mk(_default[1:] + ['幽灵门禁项 (no_such)']), 2, '幽灵'),
            ('gated 项混进默认清单 -> 必须报',
             _mk(_default + sorted(_gated)), 8, '不该列进去'),
            ('散文数字漂移（清单不动）-> 必须报',
             _mk(_default, declared=len(_default) + 1), 1, '散文'),
            ('清单块结构被破坏 -> 必须报',
             '默认跑的全部 36 项：\n没有围栏\n', 1, '前提'),
        ]

    for name, text, want, kw in gl_cases:
        e = check_readme_gate_list(text=text, checks=_all, gated=_gated)
        if len(e) != want:
            fails.append('%s: 期望 %d 条错误, 实际 %d 条 (%s)'
                         % (name, want, len(e), e[:2]))
        elif kw and not any(kw in x for x in e):
            fails.append('%s: 报错文案里没有关键词 %r，无法判定报的是对的原因'
                         ' (%s)' % (name, kw, e[:2]))

    # --- 门禁阈值常量 vs 文档声明（§2.43.6 记名的空白）---
    #
    # 与 README 清单同一纪律: 基准**从仓库现读**, 并逐条注入缺陷证明判据
    # 有判别力。只写正例(=0)会让"恒不报错"的实现也通过。
    #
    # ⚠️ 刻意**不**把常量改成"错的"再指望文档报错 —— 判据方向是
    #    **常量 -> 文档**: 常量是真值源。故负向用例改的是**文档**那一侧,
    #    以及"真值源读不到"这一前提破坏。
    def _mk_gate(m3c=12.0, m1c=12.0, doc_m3=12, doc_m1=12, keep_const=True):
        d = '"""migration_gate.py — 测试用\n\n## 阈值\n'
        if doc_m3 is not None:
            d += '  | **M3 保护函数命中** | 55.9%% | 5.9%% | **<= %g%%** |\n' % doc_m3
        if doc_m1 is not None:
            d += '  | M1 地址复用率 | — | 1.1%% | <= %g%% |\n' % doc_m1
        d += '"""\n'
        if keep_const:
            d += 'MAX_M3 = %g\nMAX_M1 = %g\n' % (m3c, m1c)
        return d

    def _mk_ps(doc_m3=12, doc_m1=12, anchor=True):
        s = '# 判据（实测标定）:\n'
        if doc_m3 is not None:
            s += '#   M3 保护函数特征命中率 <= %g%%\n' % doc_m3
        if doc_m1 is not None:
            s += '#   M1 地址复用率 <= %g%%\n' % doc_m1
        if anchor:
            s += ("if ($WithMigration) {\n"
                  "    Check '迁移成本 (migration_gate)' {\n"
                  "        $true\n    }\n}\n")
        else:
            s += 'Write-Host "本文件没有迁移成本项"\n'
        return s

    th_cases = [
        ('真实仓库阈值声明 -> 不报', None, None, None, 0, None),
        ('docstring 里 M3 阈值漂移(12->15) -> 必须报',
         _mk_gate(doc_m3=15), _mk_ps(), None, 1, '漂移'),
        ('docstring 里 M3 声明整条消失 -> 必须报',
         _mk_gate(doc_m3=None), _mk_ps(), None, 1, '失去锚点'),
        ('真值源常量读不到(改名) -> 必须报',
         _mk_gate(keep_const=False), _mk_ps(), None, 1, '真值源'),
        ('release_check 注释块 M1 漂移(12->25) -> 必须报',
         _mk_gate(), _mk_ps(doc_m1=25), None, 1, '漂移'),
        ('release_check 注释块锚点消失 -> 必须报',
         _mk_gate(), _mk_ps(anchor=False), None, 1, '锚点消失'),
        ('常量改 15、文档仍 12 -> 两处各报一条',
         _mk_gate(m3c=15.0), _mk_ps(), None, 2, '漂移'),
    ]
    for name, _g, _p, _c, want, kw in th_cases:
        e = check_threshold_claims(gate_src=_g, ps_src=_p, consts=_c)
        if len(e) != want:
            fails.append('%s: 期望 %d 条错误, 实际 %d 条 (%s)'
                         % (name, want, len(e), e[:2]))
        elif kw and not any(kw in x for x in e):
            fails.append('%s: 报错文案里没有关键词 %r，无法判定报的是对的原因'
                         ' (%s)' % (name, kw, e[:2]))

    # --- ci.yml 门禁项数口径用例（第四个入口 `ci_count_claims`）---
    #
    # 同样必须一起打印、一起计数（否则"暗处运行、看起来不存在"）。
    # 四条形态各有负向：任何一个数字漂了都必须报；措辞整条消失也必须报。
    def _mk_ci(call=None, default=None, allgreen=None, cover=None, cdef=None):
        s = '# ## 项数口径（测试用）\n'
        if call is not None:
            s += '#   静态 `Check` 调用点 **%d** 个；' % call
        if default is not None:
            s += '默认运行 **%d** 项\n' % default
        if allgreen is not None:
            s += '# ## 为什么允许 `[skip]` 而不是要求"%d 项全绿"\n' % allgreen
        if cover is not None or cdef is not None:
            s += '# release_check 覆盖 %d 项 (默认 %d)。\n' % (cover or 0, cdef or 0)
        return s

    # 现值 43/40（2026-10-11 第 46 项落地）；`cover` 形态在 `ci.yml:67`。
    ci_cases = [
        ('真实仓库 ci.yml 项数口径 -> 不报', None, None, None, 0, None),
        ('ci.yml 静态调用点漂移(41->39) -> 必须报',
         _mk_ci(call=39, default=38, allgreen=38, cover=41, cdef=38),
         41, 38, 1, '静态调用点'),
        ('ci.yml 默认运行漂移(38->34) -> 必须报',
         _mk_ci(call=41, default=34, allgreen=38, cover=41, cdef=38),
         41, 38, 1, '默认运行'),
        ('ci.yml 要求N项全绿漂移(38->34) -> 必须报',
         _mk_ci(call=41, default=38, allgreen=34, cover=41, cdef=38),
         41, 38, 1, '要求N项全绿'),
        # ⚠️ 第四形态（2026-10-09 补）: `覆盖 N 项 (默认 M)` —— 它在 `:67`
        #    一直写着且已过期很久却无人报，因为前三种措辞都不覆盖它。
        ('ci.yml 覆盖N项默认M 的总数漂移(41->39) -> 必须报',
         _mk_ci(call=41, default=38, allgreen=38, cover=39, cdef=38),
         41, 38, 1, '覆盖N项默认M'),
        ('ci.yml 覆盖N项默认M 的默认数漂移(38->36) -> 必须报',
         _mk_ci(call=41, default=38, allgreen=38, cover=41, cdef=36),
         41, 38, 1, '覆盖N项默认M'),
        # ⚠️ 期望 **5** 而不是 4：第四形态一句里有两个数，两个都漂就**各报一条**
        #    （`kind='both'` 的设计如此 —— 拆成两条独立形态会让"缺一个数"
        #    退化成"少一条形态"，反而看不见）。前三形态各 1 条 + 本形态 2 条 = 5。
        ('ci.yml 四处全漂 -> 5 条（覆盖形态两个数各一条）',
         _mk_ci(call=39, default=34, allgreen=34, cover=39, cdef=34),
         41, 38, 5, '漂移'),
        ('ci.yml 口径句整条消失 -> 必须报（四条形态各一条）',
         '# 本文件没有项数口径\n', 41, 38, 4, '失去锚点'),
    ]
    for name, _ci, _t, _d, want, kw in ci_cases:
        e = ci_count_claims(ci_src=_ci, total=_t, default=_d)
        if len(e) != want:
            fails.append('%s: 期望 %d 条错误, 实际 %d 条 (%s)'
                         % (name, want, len(e), e[:2]))
        elif kw and not any(kw in x for x in e):
            fails.append('%s: 报错文案里没有关键词 %r，无法判定报的是对的原因'
                         ' (%s)' % (name, kw, e[:2]))

    # --- ci_sim.ps1 与 ci.yml 工具集同步用例（第五个入口 `ci_sim_sync`）---
    #
    # 同样必须一起打印、一起计数（否则"暗处运行、看起来不存在"）。
    # 五个方向：真仓库不报 / 漏工具必报 / 豁免项已在 sim 里必须报（豁免过期）/
    # 两侧任一数到 0 个工具必须报（解析前提破坏，不得读成"没有差异"）。
    def _mk_sim(ci_tools, sim_tools):
        # 入口接受**已解析**的 (dict, set) —— 绕开文件读取，只测判据本身。
        return ({t: 10 for t in ci_tools}, set(sim_tools))

    _base_ci = ['modcheck.py', 'e2e.py']
    _base_sim = ['modcheck.py', 'e2e.py']
    sim_cases = [
        ('真实仓库 ci_sim 工具集 -> 不报', None, None, None, 0, None),
        ('ci_sim 漏掉 ci.yml 的一个工具 -> 必须报',
         *_mk_sim(_base_ci, ['e2e.py']), None, 1, '缺 ci.yml 的步骤'),
        ('ci.yml 侧数到 0 个工具 -> 必须报',
         *_mk_sim([], _base_sim), None, 1, '失去锚点'),
        ('ci_sim 侧数到 0 个工具 -> 必须报',
         *_mk_sim(_base_ci, []), None, 1, '失去锚点'),
        ('豁免项(mutate_check.py)已在 ci_sim 里跑了 -> 必须报',
         *_mk_sim(['mutate_check.py'], ['mutate_check.py']), None, 1, '豁免过期'),
    ]
    for name, _cst, _sst, _ex, want, kw in sim_cases:
        if _cst is None:
            e = ci_sim_sync()
        else:
            e = ci_sim_sync(ci_src=_cst, sim_src=_sst, exempt=_CI_SIM_EXEMPT)
        if len(e) != want:
            fails.append('%s: 期望 %d 条错误, 实际 %d 条 (%s)'
                         % (name, want, len(e), e[:2]))
        elif kw and not any(kw in x for x in e):
            fails.append('%s: 报错文案里没有关键词 %r，无法判定报的是对的原因'
                         ' (%s)' % (name, kw, e[:2]))

    # ⚠️ 注释里的工具名**不得**算作"已覆盖"（2026-10-06 本轮自己踩的坑）：
    #    `tools/ci_sim.ps1:18` / `:94` 的注释提到 `release_check.ps1`，
    #    扫全文时会让判据以为它已被覆盖 —— 而它**恰恰**是当时唯一的真缺口。
    #    这条用例走 `_step_body_tools()` 本身（不是 `ci_sim_sync`），
    #    因为它测的是**扫描面**，不是判据。
    _scn = ("# 注释里提到 release_check.ps1 与 mutate_check.py\n"
            "Step 'real' {\n"
            "    & $py tools\\modcheck.py --all-compositions  # 行内注释: mutate_check.py\n"
            "}\n")
    _got = _step_body_tools(_scn)
    if _got != {'modcheck.py'}:
        fails.append('ci_sim 扫描面守卫: `_step_body_tools` 把注释里的工具名也算进去了 '
                     '（得到 %s；只应得到 {\'modcheck.py\'}）—— '
                     '注释里的提及会让判据以为该步骤已被覆盖'
                     % sorted(_got))

    # --- 扫描面自身的守卫 ---
    # 上面所有用例都建立在"该文件**在面内**"之上。若扫描面哪天把根目录
    # 悄悄移出去, 判据会**全绿而失明** —— 判据的判据没了。
    # 2026-10-06 实测: README.md 曾长期不在面内, 而 doccheck 一直 PASS。
    # 故把"恒为现时的 front door 必须在面内"本身断言成用例。
    _must = ['README.md', 'CONTRIBUTING.md', '.github/PULL_REQUEST_TEMPLATE.md']
    for _m in _must:
        if os.path.join(REPO, _m.replace('/', os.sep)) not in TARGETS:
            fails.append('扫描面守卫: `%s` 不在 TARGETS 内 —— '
                         '它是恒为现时的 front door, 移出即失明' % _m)

    # --- 反向守卫: 按**文件名**推导的"历史快照"不得进入扫描面 ---
    #
    # 2026-10-06 实测: 全库文件名含日期的 Markdown 共 6 个
    # (docs/迁移核验-2026-09-20.md / docs/阶段总结-2026-08-30.md /
    #  docs/阶段总结-2026-09-29.md / docs/阶段总结-2026-09-30.md /
    #  docs/阶段总结-2026-10-06.md / docs/项目文件分类-2026-08-30.md),
    # **6 个全部在面外**, 且逐一核对全是历史快照; 反之面内 33 个无一带日期。
    # 两侧收敛 => "含日期 => 历史" 可判定。若哪天把这种文件放进面内,
    # 它的**当时值**会被当**现值**判, 判据会要求篡改历史文档来变绿。
    # (反面: 不带日期的历史文档无法由此识别, 那是人判断的残余。)
    _dated = re.compile(r'20\d\d[-_]?\d\d[-_]?\d\d')
    for _p in TARGETS:
        if _dated.search(os.path.basename(_p)):
            fails.append('扫描面守卫: `%s` 文件名含日期, 却出现在 TARGETS 内 —— '
                         '它记的是当时的真实值, 放进面内会要求篡改历史文档'
                         % os.path.relpath(_p, REPO).replace(os.sep, '/'))

    # --- 围栏配平用例（第六个入口 `check_fence_balance`）---
    #
    # 同样必须一起打印、一起计数（否则"暗处运行、看起来不存在"）。
    # 四个方向：配平不报 / 奇数总数必报 / 总数偶数但带标记围栏错位必报 /
    # 空文档不算（没有围栏不是"没漂移"，只是这份文档不适用该判据）。
    def _mk_fence(blocks=1, extra_bare=0, info='python'):
        s = ['# 文档', '']
        for _ in range(blocks):
            s += ['%s%s' % (FENCE, info), 'x = 1', FENCE, '']
        for _ in range(extra_bare):
            s += ['%s' % FENCE, '']
        return '\n'.join(s) + '\n'

    # ⚠️ 这个用例必须**总数偶数**且**只有一个**带标记的围栏落在奇数序号，
    #    才能只触发判据②（第一版把总数写成奇数 ⇒ 两条判据同时开火报 2 条，
    #    用例自己 FAIL —— 探针的构造错会伪装成判据错，§2.37.6 同型）。
    #    构造: 1 条裸 + 1 条**带标记(落在奇数序号, BAD)** + 4 条裸 = 6 条。
    _misaligned = (FENCE + '\n' + FENCE + 'python\nx = 1\n' + FENCE + '\n'
                   + FENCE + '\n' + FENCE + '\n' + FENCE + '\n')
    fc_cases = [
        ('围栏配平(1 个带标记块) -> 不报', _mk_fence(1), 0, None),
        ('围栏配平(3 个带标记块, 共 6 条) -> 不报', _mk_fence(3), 0, None),
        ('多一个孤立 ``` (总数奇数) -> 必须报', _mk_fence(1, 1), 1, '奇数'),
        ('总数偶数但带标记围栏在奇数序号 -> 必须报',
         _misaligned, 1, '奇数序号'),
        ('空文档(无围栏) -> 不报', '# 只有文字\n', 0, None),
    ]
    for name, _t, want, kw in fc_cases:
        e = check_fence_balance(docs={'t.md': _t})
        if len(e) != want:
            fails.append('%s: 期望 %d 条错误, 实际 %d 条 (%s)'
                         % (name, want, len(e), e[:2]))
        elif kw and not any(kw in x for x in e):
            fails.append('%s: 报错文案里没有关键词 %r，无法判定报的是对的原因'
                         ' (%s)' % (name, kw, e[:2]))

    # --- 第七个入口: 「恒为现时」文档里代码块内的门禁项数 (§2.54) ---
    #
    # 判据本体在 `DocView.exempt()` 里 —— 它**收窄**了「代码块」一刀切豁免。
    # 故用例必须走 `check_text`(生产同一条路径), 且**同时**构造
    # 现时文件与非现时文件两种 rel, 才能证明收窄**只**打在现时文件上。
    #
    # ⚠️ 反例(cf3)是本批**最重要**的一条: 若哪天有人把收窄推广到 `docs/**`,
    #    `docs/HANDOVER.md` 那 60+ 处代码块内的历史转录会全部变红 ——
    #    判据会要求**篡改历史记录**才变绿 (§2.40 反向守卫同一类错误)。
    def _mk_cf(rel, body):
        return rel, '说明文字：\n\n```\n%s\n```\n' % body

    cf_cases = [
        ('现时文件代码块内项数 = 真值 -> 不报',
         # ⚠️ 真值**由 GATE_TOTAL 推导**, 不写字面量: 计数上调一次
         #    (41/38 -> 42/39) 就会让这条**本该通过**的用例变红。实测踩过。
         _mk_cf('README.md', '# 门禁 %d 项' % GATE_TOTAL), 0, None),
        ('现时文件代码块内项数漂移(41->36) -> 必须报',
         _mk_cf('README.md', '# 门禁 36 项'), 1, '声称 36 项'),
        ('现时文件代码块内 N/N 漂移(41/41->36/36) -> 必须报',
         _mk_cf('CONTRIBUTING.md', 'release_check 36/36 PASS'), 1, '声称 36'),
        ('非现时文件(docs/**)代码块内同一漂移 -> 不报（历史转录）',
         _mk_cf('docs/HANDOVER.md', '# 门禁 36 项'), 0, None),
        ('现时文件代码块内带 → 的沿革 -> 不报',
         _mk_cf('README.md', '# 门禁 21/22 → 33 项'), 0, None),
        ('现时文件代码块内"第 N 项"序号 -> 不报',
         _mk_cf('README.md', '# 门禁默认第 20 项'), 0, None),
        ('现时文件代码块内转述他文(带行号) -> 不报',
         _mk_cf('README.md', '# 见 docs/HANDOVER.md:237 门禁 32 项'), 0, None),
    ]
    for name, (rel, _t), want, kw in cf_cases:
        _exc = {}
        e, _w, _c = check_text(rel, _t, GATE_TOTAL, actual_rounds(), _exc)
        if len(e) != want:
            fails.append('%s: 期望 %d 条错误, 实际 %d 条 (%s)'
                         % (name, want, len(e), e[:2]))
        elif kw and not any(kw in x for x in e):
            fails.append('%s: 报错文案里没有关键词 %r，无法判定报的是对的原因'
                         ' (%s)' % (name, kw, e[:2]))
        elif want == 0 and rel.startswith('docs/') and not _exc.get('代码块'):
            # ⭐ 反向守卫：非现时文件**只**能靠"代码块"豁免不报。
            #    若哪天把收窄推广到 docs/**, 这条立刻变红 —— 那正是
            #    "判据会要求篡改历史记录才变绿" 的错误 (§2.40 同一类)。
            fails.append('%s: 期望"代码块"豁免计数 >= 1, 实际 %r —— '
                         '非现时文件的转录必须仍被代码块豁免兜住' % (name, _exc))
        elif want == 0 and _c < 1:
            fails.append('%s: 判据一次都没跑（checked=0）—— 用例是假绿, '
                         '证明不了收窄生效' % name)
        elif want > 0 and _exc.get('代码块'):
            fails.append('%s: 既报了错又记了"代码块"豁免 %r —— 两者互斥'
                         % (name, _exc))

    # --- 第八个入口: 扫描面**外**「自称权威」文档的门禁项数 (§2.55) ---
    #
    # 判据本体是 `check_self_authoritative_claims()`(内部走 `check_text`),
    # 外加**滤网** `self_authoritative_head()` —— 两者都必须有负向证据。
    #
    # ⚠️ 用例 sa4 是本批**最重要**的一条: 面外但**不**自称权威的文件必须不报,
    #    否则判据会要求篡改 18 条历史计划文件里的旧值才变绿 —— 那正是
    #    §2.40 反向守卫在防的同类错误。
    #
    # 三种 kind:
    #   'c' 判据本体(docs= 直接传入)  'p' 滤网+判据组合  'h' 只测滤网
    # ⚠️ 两个数**都由 GATE_TOTAL / GATE_DEFAULT 推导**, 不写字面量:
    #    真值一变, 写死的"漂移样例"可能恰好等于新真值 ⇒ "必须报"这条
    #    会静默失效 (2026-10-09 计数 41/38 -> 42/39 时实测踩到)。
    _SA_TRUE = ('| 发布门禁（%d 项，默认 %d） | \u2705 |'
                % (GATE_TOTAL, GATE_DEFAULT))
    _DRIFT_T = GATE_TOTAL - 2
    _DRIFT_D = GATE_DEFAULT - 2
    assert (_DRIFT_T, _DRIFT_D) != GATE_OK, '漂移样例不得等于真值'
    _SA_DRIFT = ('| 发布门禁（%d 项，默认 %d） | \u2705 |'
                 % (_DRIFT_T, _DRIFT_D))
    _SA_HEAD = '> 版本：2026-09-20 v1 · 状态：**总纲**（路线图的单一来源）'

    def _mk_sa(rel, head, body=''):
        txt = (head + '\n\n' + body + '\n') if body else (head + '\n')
        return {rel: txt}

    sa_cases = [
        ('sa1 面外自称权威 + 项数漂移 -> 必须报', 'c',
         _mk_sa('docs/A.md', _SA_HEAD, _SA_DRIFT), 1, '声称 %d 项' % _DRIFT_T),
        ('sa2 面外自称权威 + 项数 = 真值 -> 不报', 'c',
         _mk_sa('docs/A.md', _SA_HEAD, _SA_TRUE), 0, None),
        ('sa3 两文件一漂移一正确 -> 恰 1 条', 'c',
         dict(list(_mk_sa('docs/A.md', '# A\n\n> 单一来源', _SA_DRIFT).items())
              + list(_mk_sa('docs/B.md', '# B\n\n> 单一事实源', _SA_TRUE).items())),
         1, 'docs/A.md'),
        ('sa4 滤网+判据: 面外但**未**自称权威 -> 不报（历史计划文件）', 'p',
         _mk_sa('docs/C.md', '# C\n\n> 版本：2026-09-20 v1', _SA_DRIFT), 0, None),
        ('sa5 带 → 的沿革 -> 不报', 'c',
         _mk_sa('docs/A.md', '# A\n\n> 单一来源', '门禁 21/22 → 33 项'),
         0, None),
        ('sa6 「后为」的漂移记录 -> 不报（DELTA_WORDS 已含 后为）', 'c',
         _mk_sa('docs/A.md', '# A\n\n> 单一来源',
                '| 2 | `release_check 11/11` | 实际 **13**（后为 14） |'),
         0, None),
        ('sa7 待判集合为空 -> 必须报（失锚守卫）', 'c', {}, 1, '失去锚点'),
        ('sa8 滤网: 不加粗的 `单一来源` -> 认', 'h',
         '# A\n\n> 这是唯一的单一来源\n', 0, None),
        ('sa9 滤网: 第 13 行才出现 -> 不认（只看头部）', 'h',
         '# C\n' + '\n' * 12 + '> 单一来源\n', 1, '滤网不认'),
        ('sa10 滤网: 「关联：`docs/B.md`（总纲）」是引用 -> 不认', 'h',
         '# D\n\n> 关联：`docs/B.md`（总纲）\n', 1, '滤网不认'),
    ]
    for name, kind, payload, want, kw in sa_cases:
        if kind == 'c':
            e = check_self_authoritative_claims(docs=payload)
        elif kind == 'p':
            sel = {r: tx for r, tx in payload.items()
                   if self_authoritative_head(tx)}
            e = check_self_authoritative_claims(docs=sel) if sel else []
        else:
            e = [] if self_authoritative_head(payload) else ['滤网不认']
        if len(e) != want:
            fails.append('%s: 期望 %d 条错误, 实际 %d 条 (%s)'
                         % (name, want, len(e), e[:2]))
        elif kw and not any(kw in x for x in e):
            fails.append('%s: 报错文案里没有关键词 %r，无法判定报的是对的原因'
                         ' (%s)' % (name, kw, e[:2]))

    # --- 第九个入口: 节序（同级兄弟序号严格递增, §2.78）---
    #
    # 判据本体是 `check_heading_order()`。本批的**价值在反例**：
    # 出身是 `docs/HANDOVER.md` 的 §2.64 被插在版本行之后、以及
    # `docs/CONTRACT.md` 的两份 `### 6.2`。三条排除规则（围栏内 / 数量词 /
    # 后缀字母）各配一条反例，否则改坏排除规则时**没有用例会红**。
    #
    # ⚠️ `ho5`/`ho6` 是失锚守卫用例：走查面写坏时必须报"失去锚点"，
    #    不能报"违规 0 处"。
    def _mk_ho(body, rel='docs/T.md'):
        return {rel: body}

    ho_cases = [
        ('ho1 同级递增 -> 不报',
         _mk_ho('# T\n\n## 1. A\n\n## 2. B\n\n## 3. C\n'), 0, None),
        ('ho2 顶层出序(3 之后又是 1) -> 必须报',
         _mk_ho('# T\n\n## 1. A\n\n## 3. C\n\n## 1. A\n'), 1, '序号出序'),
        ('ho3 编号重复(两份 6.2) -> 必须报',
         _mk_ho('# T\n\n## 6. S\n\n### 6.1 a\n\n### 6.2 b\n\n### 6.2 c\n'),
         1, '编号重复'),
        ('ho4 子节出序(2.70.11 在 2.70.10 之前) -> 必须报',
         _mk_ho('# T\n\n## 2. P\n\n### 2.70.11 a\n\n### 2.70.10 b\n'),
         1, '序号出序'),
        ('ho5 围栏内的 "# 3." 是命令注释 -> 不报（排除规则①）',
         _mk_ho('# T\n\n## 1. A\n\n## 2. B\n\n```bash\n# 3. 验证\n# 1. 编译\n```\n'),
         0, None),
        ('ho6 "### 5 个公开突破" 是数量词 -> 不报（排除规则②）',
         _mk_ho('# T\n\n### 5 个公开突破\n\n### 1. 攻击防御同源\n'), 0, None),
        ('ho7 "### 4.2b 运维踩坑" 后缀字母 -> 不报（排除规则③）',
         # ⚠️ 必须带一个真编号标题：否则整份材料没有编号标题 ⇒ 判据会报
         #    "失去锚点"，用例就测不到排除规则本身了（探针的构造错会
         #    伪装成判据错，§2.37.6 同型）。
         _mk_ho('# T\n\n## 1. A\n\n### 4.2b 运维踩坑\n\n### 4 个迭代教训\n'),
         0, None),
        ('ho8 扫描面为空 -> 必须报（失锚守卫）',
         _mk_ho('# T\n\n没有编号标题\n'), 1, '失去锚点'),
        ('ho9 兄弟组太少 -> 必须报（失锚守卫）',
         _mk_ho('# T\n\n## 1. A\n', rel='docs/U.md'), 1, '失去锚点'),
    ]
    for name, _ho_docs, want, kw in ho_cases:
        if name.startswith('ho9'):
            # 只有 1 个兄弟组 ⇒ 下限设为 2 必须开火
            e = check_heading_order(docs=_ho_docs, min_files=1, min_groups=2)
        else:
            e = check_heading_order(docs=_ho_docs, min_files=1, min_groups=0)
        if len(e) != want:
            fails.append('%s: 期望 %d 条错误, 实际 %d 条 (%s)'
                         % (name, want, len(e), e[:2]))
        elif kw and not any(kw in x for x in e):
            fails.append('%s: 报错文案里没有关键词 %r，无法判定报的是对的原因'
                         ' (%s)' % (name, kw, e[:2]))

    print('=== doccheck 自检 ===')
    bad = set(f.split(':')[0] for f in fails)
    for name, text, want in cases:
        print('  [%s] %s (期望 %d 条)'
              % ('X' if name in bad else 'ok', name, want))
    # README 门禁清单成员用例走另一个入口（`check_readme_gate_list`），
    # 不能塞进 `cases`（那批会经 `check_text` 跑**数字漂移**判据，语义不同）。
    # 但**必须一起打印、一起计数** —— 否则它们只是暗处运行、看起来不存在。
    for name, _text, want, _kw in gl_cases:
        print('  [%s] %s (期望 %d 条)'
              % ('X' if name in bad else 'ok', name, want))
    # 阈值对账用例走第三个入口（`check_threshold_claims`），同样必须一起
    # 打印、一起计数 —— 否则它们只是暗处运行、看起来不存在。
    for name, _g, _p, _c, want, _kw in th_cases:
        print('  [%s] %s (期望 %d 条)'
              % ('X' if name in bad else 'ok', name, want))
    # ci.yml 项数口径用例走第四个入口（`ci_count_claims`），同样必须一起
    # 打印、一起计数 —— 否则它们只是暗处运行、看起来不存在。
    for name, _ci, _t, _d, want, _kw in ci_cases:
        print('  [%s] %s (期望 %d 条)'
              % ('X' if name in bad else 'ok', name, want))
    # ci_sim 工具集同步用例走第五个入口（`ci_sim_sync`），同样必须一起
    # 打印、一起计数 —— 否则它们只是暗处运行、看起来不存在。
    for name, _cst, _sst, _ex, want, _kw in sim_cases:
        print('  [%s] %s (期望 %d 条)'
              % ('X' if name in bad else 'ok', name, want))
    # 围栏配平用例走第六个入口（`check_fence_balance`），同样必须一起
    # 打印、一起计数 —— 否则它们只是暗处运行、看起来不存在。
    for name, _t, want, _kw in fc_cases:
        print('  [%s] %s (期望 %d 条)'
              % ('X' if name in bad else 'ok', name, want))
    # 「恒为现时」代码块内项数用例走第七个入口（`check_text` 的代码块豁免
    # 收窄），同样必须一起打印、一起计数 —— 否则它们只是暗处运行、
    # 看起来不存在。
    for name, _rel_t, want, _kw in cf_cases:
        print('  [%s] %s (期望 %d 条)'
              % ('X' if name in bad else 'ok', name, want))
    # 面外自称权威用例走第八个入口（`check_self_authoritative_claims`
    # + 滤网 `self_authoritative_head`），同样必须一起打印、一起计数 ——
    # 否则它们只是暗处运行、看起来不存在。
    for name, _k, _p, want, _kw in sa_cases:
        print('  [%s] %s (期望 %d 条)'
              % ('X' if name in bad else 'ok', name, want))
    # 节序用例走第九个入口（`check_heading_order`），同样必须一起打印、
    # 一起计数 —— 否则它们只是暗处运行、看起来不存在。
    for name, _h, want, _kw in ho_cases:
        print('  [%s] %s (期望 %d 条)'
              % ('X' if name in bad else 'ok', name, want))
    total = (len(cases) + len(gl_cases) + len(th_cases) + len(ci_cases)
             + len(sim_cases) + len(fc_cases) + len(cf_cases)
             + len(sa_cases) + len(ho_cases))

    # --- ⚠️ 自检自身的守卫: 批次不得被静默掏空（2026-10-06）---
    #
    # `total` 与 `neg` 都是**由长度算出来的** ⇒ 删掉一个批次、或清空它的项，
    # 只会让打印的数字**变小**，**不会**报错 —— "PASS: 20 项" 与 "PASS: 45 项"
    # 长得一样绿，而人不会记得该是多少。§2.48 刚证明过这类
    # **"声明被当成覆盖"** 的错误有多容易发生（注释里提一句工具名，
    # 判据就以为它被覆盖了）。
    #
    # 判据要求**非空 + 总数下限**，不写每个批次的精确条数：
    # 精确条数每次加用例都要改，一定会过期；而下限只会被"新增用例"抬高，
    # **不会**因正常演进失效 —— 它只在"有批次被掏空"时开火。
    #
    # ⚠️ 下限**必须紧贴当前值**，不能留余量（2026-10-06 负向实测）：
    #   我第一版写 `_TOTAL_FLOOR = 40`（当前 45，留 5 条余量），
    #   负向用例"把 sim_cases 从 5 条砍到 1 条"实测报 **`PASS: 41`** ——
    #   **仍然全绿**。留余量恰恰使守卫对自己要防的那件事失明。
    #   故下限 = **当前精确值**：删任何一条用例都必须显式改这个数字
    #   （删用例是重大动作，值得被强制看见），而新增用例只会让它更高。
    _BATCHES = (('cases', cases), ('gl_cases', gl_cases), ('th_cases', th_cases),
                ('ci_cases', ci_cases), ('sim_cases', sim_cases),
                ('fc_cases', fc_cases), ('cf_cases', cf_cases),
                ('sa_cases', sa_cases), ('ho_cases', ho_cases))
    for _bn, _bl in _BATCHES:
        if not _bl:
            fails.append('自检批次 `%s` 被清空 —— `total` 由长度导出, '
                         '空批次不会报错只会让数字变小（且该批判据完全失去'
                         '负向验证）。要么恢复用例, 要么删掉整批并同步 total/neg'
                         % _bn)
    _TOTAL_FLOOR = 78
    if total < _TOTAL_FLOOR:
        fails.append('自检用例总数 %d 低于下限 %d —— 有用例被删或被掏空。'
                     '（下限**紧贴当前值**：删用例须显式下调此数字并说明理由）'
                     % (total, _TOTAL_FLOOR))

    if fails:
        for f in fails:
            print('  [X] %s' % f)
        print('[doccheck-selftest] FAIL (%d/%d)' % (len(fails), total))
        return 1
    # 数一数用例构成: 期望 != 0 的是负向注入, 期望 == 0 的是合规豁免。
    neg = (len([c for c in cases if c[2]])
           + len([c for c in gl_cases if c[2]])
           + len([c for c in th_cases if c[4]])
           + len([c for c in ci_cases if c[4]])
           + len([c for c in sim_cases if c[4]])
           + len([c for c in fc_cases if c[2]])
           + len([c for c in cf_cases if c[2]])
           + len([c for c in sa_cases if c[3]])
           + len([c for c in ho_cases if c[2]]))
    print('[doccheck-selftest] PASS: %d 项（%d 项负向注入 / %d 项合规豁免）'
          % (total, neg, total - neg))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog='doccheck.py',
                                 description='对外材料数字漂移检查')
    ap.add_argument('--list', action='store_true', help='列出被检查的数字')
    ap.add_argument('--selftest', action='store_true',
                    help='负向自检: 注入缺陷必须报错, 合规写法不得误报')
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    errors = []
    warnings = []
    checked = 0

    gate = actual_gate_count()
    rounds = actual_rounds()

    if args.list:
        print('被检查的数字:')
        print('  release_check 实际门禁项数 = %s' % gate)
        print('  docs/ATTACK_DRILL*.md 轮次数 = %s' % rounds)
        print('  检查目标文件: %d 个' % len(TARGETS))
        return 0

    print('=== 对外材料数字漂移检查 ===')
    print('  基准: 门禁 %s 项, 轮次 %s 个' % (gate, rounds))
    print()

    # --- 0. 门禁结构断言（**必须最先跑**，见 check_gate_structure 的文档）---
    #
    # ⚠️ `_n` / `_opt` 在这里**先算**，不能只写在下面那个 `else` 分支里：
    #    0b 的 README 清单判据也要用它们，而结构断言**失败时**（`else` 不执行）
    #    仍会走到 0b -> 那里引用未绑定名会 `NameError`，把"结构错了"这条
    #    真错误替换成一个崩溃。结构断言红的时候正是最需要看清 0b 结论的时候。
    _src = open(os.path.join(REPO, 'tools', 'release_check.ps1'),
                encoding='utf-8-sig').read()
    _n = len(re.findall(r"(?m)^\s*Check\s+'", _src))
    # `$With*` 可控的项默认不跑 —— 这是**设计**，不是事故：
    # 判据是"每个 if ($With*) 的 body 里最多一个 Check"，落在 if 外的一律默认必跑。
    _opt = len(re.findall(r"(?m)^\s*if\s*\(\s*\$With\w+\s*\)", _src))

    struct = check_gate_structure()
    if struct:
        errors.extend(struct)
    else:
        print('  [ok] 门禁结构: %d 项均为顶层语句，无被嵌套项；'
              '其中 %d 项由 -With* 显式开关控制（默认不跑），默认调用跑 %d 项'
              % (_n, _opt, _n - _opt))

    # --- 0b. README 门禁清单的**成员集合**（计数之外的那一半）---
    # 计数由下面的数字漂移判据兜；**成员**此前无人断言（漏一项而数字仍对 -> 不红）。
    rem = check_readme_gate_list()
    if rem:
        errors.extend(rem)
    else:
        _names, _decl, _ = parse_readme_gate_list(
            open(os.path.join(REPO, 'README.md'), encoding='utf-8').read())
        print('  [ok] README 门禁清单: %d 条成员与默认跑的 %d 项双向唯一匹配'
              % (len(_names or []), _n - _opt))

    # --- 0c. 门禁**阈值**常量 vs 文档声明（§2.43.6 记名的空白）---
    # §2.43 把旧阈值 25% 修成 12%，但那次修复没有机器判据 —— 两处文档里的
    # 数字无人读，`--selftest` 只证明"阈值判定逻辑能抓错"、不证明文档对得上。
    thr = check_threshold_claims()
    if thr:
        errors.extend(thr)
    else:
        _tc, _ = gate_threshold_constants()
        print('  [ok] 迁移成本阈值: M3/M1 = %g%% / %g%% 与 '
              'migration_gate.py docstring、release_check.ps1 注释块一致'
              % (_tc['M3'], _tc['M1']))

    # --- 0d. ci.yml 里的门禁**项数口径**（既不在扫描面内，也不被计数正则看见）---
    # §2.45 补的是"阈值常量 vs 文档"，这一条补的是"项数 vs CI 注释"：
    # `.github/workflows/ci.yml` 从来不在 `build_targets()` 的面内，且它的
    # 口径句不含 `release_check` / `门禁` 二字 ⇒ 两个计数正则都失明。
    # 实测这条缺陷已连犯三次（见函数文档），每次新增门禁项都会静默过期。
    cic = ci_count_claims()
    if cic:
        errors.extend(cic)
    else:
        _ct, _cd = _gate_counts()
        print('  [ok] ci.yml 项数口径: 静态调用点 %d / 默认运行 %d 与 '
              'release_check.ps1 现数一致' % (_ct, _cd))

    # --- 0e. ci_sim.ps1 与 ci.yml 的**工具集**同步（`:6` 的人工承诺无判据）---
    # `tools/ci_sim.ps1:6` 写着「保持与 ci.yml 同步; 每次改 ci.yml 必须同步这里」，
    # 但实测该文件从未跑门禁本体、且缺 5 个 ci.yml 步骤（见函数文档）。
    # 与 0/0b/0c/0d 同型第 7 次：事实可得，但没有任何判据在用它。
    sse = ci_sim_sync()
    if sse:
        errors.extend(sse)
    else:
        _cst, _sst = ci_sim_tool_sets()
        print('  [ok] ci_sim 工具集: %d / %d 个与 ci.yml build-and-verify 覆盖一致 '
              '(%d 项显式豁免并写明理由)'
              % (len(set(_cst) & _sst), len(_cst), len(_CI_SIM_EXEMPT)))

    # --- 0f. 扫描面内 `.md` 的 ``` 围栏必须配平（§2.51 发现的新成因）---
    # `DocView._walk()` 靠单个布尔翻转判 `in_code` ⇒ 围栏奇偶坏掉时
    # **代码块豁免整类失效**，而报出来的却是看似无关的数字漂移。
    # 判据必须先看住"结构本身是否配平"，否则后续判据的结论不可信。
    fbe = check_fence_balance()
    if fbe:
        errors.extend(fbe)
    else:
        _nf = 0
        for _p in TARGETS:
            try:
                _tx = open(_p, encoding='utf-8').read()
            except OSError:
                continue
            if any(l.lstrip().startswith(FENCE) for l in _tx.split('\n')):
                _nf += 1
        print('  [ok] 围栏配平: %d 份文档的 ``` 总数为偶数且带标记的围栏'
              '均在偶数序号' % _nf)

    # --- 0g. 扫描面**外**「自称权威」文档的门禁项数（§2.55）---
    # §2.54 修了面内代码块那一半; 这一半修的是"有人当现值在维护、却因不在
    # 面内而无人对账"的声明。实测唯一命中 `docs/BLUEPRINT.md` —— 第 39 项
    # 落地那次提交(`7062039`)亲手改过它的 `:128`, 之后无人再看, 到本轮真值
    # 已是 41/38 而它仍写 39/36。
    # ⚠️ 判据①是失锚守卫: 集合为空**必须报错**, 不得读成"没有漂移"。
    sac = check_self_authoritative_claims()
    if sac:
        errors.extend(sac)
    else:
        _sa_l = self_authoritative_files()
        print('  [ok] 面外自称权威文档: %d 份（%s）门禁项数与真值一致'
              % (len(_sa_l), '、'.join(_sa_l)))

    # --- 0h. 节序：同级兄弟序号必须严格递增（§2.78）---
    # 与 0f（围栏配平）并列：都是**结构类**判据，都不走 `check_text` 的
    # 数字漂移路径。扫描面是**自带的全库 `.md`**，不是 `TARGETS` ——
    # 实测 12 处违规里 TARGETS 只看得到 2 处（`docs/CONTRACT.md` /
    # `docs/STUDIO_PROTOCOL.md` / `docs/DEFENSE_DEEPEN_PLAN.md` 都在面外）。
    ho = check_heading_order()
    if ho:
        errors.extend(ho)
    else:
        _ho_f = heading_order()
        _ho_n = sum(len(h) for _r, h in _ho_f)
        print('  [ok] 节序: %d 份文档 / %d 个编号标题的兄弟序号严格递增'
              % (len(_ho_f), _ho_n))

    exc = {}
    for f in TARGETS:
        rel = os.path.relpath(f, REPO).replace('\\', '/')
        try:
            t = open(f, encoding='utf-8').read()
        except OSError:
            continue
        e, w, c = check_text(rel, t, gate, rounds, exc)
        errors.extend(e)
        warnings.extend(w)
        checked += c

    # --- 5. 部署后的相对链接 (按 GitHub 渲染规则) ---
    # 这类死链只在部署后才暴露 —— 本地渲染正常, 上线后越界。
    derr, dchecked = check_deployed_links()
    checked += dchecked
    errors.extend(derr)

    # --- 6. publish/ 内部互链 (发布到自建博客, 文件并排) ---
    perr, pchecked = check_publish_links()
    checked += pchecked
    errors.extend(perr)

    # --- 7. Issue 链接语义 <-> 模板匹配 ---
    ierr, ichecked = check_issue_links()
    checked += ichecked
    errors.extend(ierr)

    # --- 内网信息防泄漏（D: 2026-09-23）---
    #
    # ## 为什么需要
    #   内网拓扑（Tailscale IP + 端口）**可被直接利用**。
    #   对外目录（publish/ / docs/marketing/）会**随同步发布到公开仓库**
    #   -> 那里出现内网 IP 是**必须拦截**的。
    #   内部文档出现则提示脱敏（运维需要真实值时可从内部配置获取）。
    #
    # 规则:
    #   D1 对外目录含内网 IP      -> **error**（会泄漏）
    #   D2 内部文档含内网 IP      -> warning（建议脱敏）
    import re as _re
    # CGNAT 网段（RFC 6598）内的**具体**地址才敏感。
    #
    # ⚠️ **排除网段标识本身**（2026-09-23 实测误报）:
    #   `100.64.0.0` / `100.64.0.0/10` 是**公开标准**的网段标识，
    #   不含任何拓扑信息（任何 Tailscale 用户在都在此段）-> 不该报警。
    #   初版把它当敏感地址 -> 在"脱敏示例"文档里误报。
    _IP = _re.compile(
        r'\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d+\.\d+\b'
        r'(?!/10)')      # 排除 "x.x.x.x/10" 这种网段写法
    _SEGMENT_ONLY = {'100.64.0.0'}   # 网段标识，非具体地址
    _PUBLIC_DIRS = ('publish', 'docs/marketing')
    _scanned = 0
    for _root, _dirs, _files in os.walk('.'):
        _r = _root.replace('\\', '/').lstrip('./')
        if any(s in _r for s in ('.git', 'archive', 'node_modules',
                                 'build/release-staging')):
            continue
        for _fn in _files:
            if not _fn.endswith(('.md', '.html')):
                continue
            _p = os.path.join(_root, _fn).replace('\\', '/')
            try:
                _txt = open(_p, encoding='utf-8', errors='replace').read()
            except OSError:
                continue
            _hits = [h for h in _IP.findall(_txt)
                     if h not in _SEGMENT_ONLY]
            # 同一行里若只是"/10"网段写法，也不计（已由负向 lookahead 处理）
            if not _hits:
                continue
            _scanned += 1
            _is_pub = _p.lstrip('./').startswith(_PUBLIC_DIRS)
            if _is_pub:
                errors.append('%s: **对外目录含内网 IP** %s（会随同步泄漏）'
                              % (_p, sorted(set(_hits))[:3]))
            else:
                warnings.append('%s: 含内网 IP %s（建议脱敏为 '
                                '<TAILSCALE_IP>）'
                                % (_p, sorted(set(_hits))[:3]))
    if _scanned == 0:
        print('  [ok] 内网信息检查: 未发现内网 IP')

    for e in errors:
        print('  [X] %s' % e)

    for w in warnings:
        print('  [!] %s' % w)
    print()
    print('  检查数字 %d 处, 错误 %d, 警告 %d' % (checked, len(errors), len(warnings)))
    if exc:
        # 豁免**必须显式打印** —— 静默豁免 = 无人复查的后门。
        # 豁免突然变多说明判据正在被削弱, 应能在日志里立刻看到。
        print('  豁免 %d 处: %s'
              % (sum(exc.values()),
                 ' / '.join('%s %d' % (k, exc[k])
                            for k in sorted(exc, key=lambda x: -exc[x]))))
    print()


    print('[doccheck] %s' % ('FAIL' if errors else 'PASS'))
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
