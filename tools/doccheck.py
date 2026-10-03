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
# ## 故: 范围 = 对外材料 + **显式自称现时**的内部文档
# `> **最后核实**: <日期> · 方法: … · 提交 <sha>` 是文档对"我自称现时"
# 的**显式自声明**。声明是承重的: 无此声明不得纳入检查 (新文档默认不被
# 检查, 是有意为之 —— 想被检查就先声明)。实测 24 文件 / 88 处数字断言,
# 残留 2 条真缺陷, 零噪声。
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
    ts = sorted(glob.glob(os.path.join(REPO, 'publish', '*.md')))
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
# ## 容差 {34, 31}
# 总数 34 / 默认调用 31 都是合法现值 (3 项由 -With* 控制, 默认不跑)。
# 沿用轮次规则的先例: 允许"全量"与"默认"两种口径。
# 2026-10-02: 33/30 -> 34/31 (新增 `加密封装窗口 (window_check)`, §2.16/T11)。
GATE_TOTAL = 34
GATE_DEFAULT = 31
GATE_OK = (GATE_TOTAL, GATE_DEFAULT)

RE_GATE_NN = re.compile(r'(?:release_check|门禁)[^\n]{0,24}?(\d+)\s*/\s*(\d+)')
# `门禁 **33** 项` 的 `**` 会打断 `(\d+)\s*项`, 故必须允许结束的强调标记
RE_GATE_N  = re.compile(
    r'(?:release_check|门禁)[^\n]{0,24}?(\d+)(?:\*\*)?\s*项')

# 沿革记录 (`11/15/22/26/31 → **33**`) —— 记的是"曾经是这些值", 不是现值
RE_DELTA = re.compile(r'(?:→|->|⇒)')
DELTA_WORDS = re.compile(r'现为|曾|旧值?|已过期')

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
            return '代码块'
        if self.hist[i]:
            return '日期语境'
        if RE_DATE.search(line):
            # 行自带日期 => "截至 DATE 已核实" 的历史 attestation
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
    case('N/N 漂移', '门禁 32/32 全通过\n', 1)
    case('N 项漂移', 'release_check 32 项全通过\n', 1)
    case('N 项 + 强调漂移', '门禁 **32** 项\n', 1)
    case('正确值不报', '门禁 34/34 全通过\nrelease_check 31 项\n', 0)
    # 比分母, 不是分子: `门禁 21/34` 是"通过 21 / 共 34", 分母对即放行
    case('分母正确/分子是失败数 -> 放行', '门禁 21/34（唯一失败=未提交）\n', 0)
    case('分母错误 -> 必报', '门禁 33/22\n', 1)
    # 豁免必须仍然生效 (否则"多报"也是判据失效)
    case('代码块内 -> 豁免', '```\n门禁 11/11\n```\n', 0)
    case('带日期的历史标题 -> 豁免', '## 2.5 验收（2026-08-30 增量）\n门禁 11/11\n', 0)
    case('沿革 -> 豁免', '门禁项数 11/15/22/26/31 → **33**\n', 0)
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
    real_case = None
    if real is None:
        fails.append('%s 不可读 —— 负向用例失去锚点' % rel)
    else:
        for good, bad in (('34/34', '32/32'), ('34 项', '32 项')):
            if good in real:
                real_case = ('真实文档 %s: %s -> %s 必须报' % (rel, good, bad),
                             real.replace(good, bad))
                break
        else:
            fails.append('%s 里既无 `34/34` 也无 `34 项` —— '
                         '负向用例失去锚点, 请改用其他已声明现值的文档' % rel)
    if real_case:
        cases.append(real_case + (1,))
        exc = {}
        e, _, _ = check_text(rel, real_case[1], GATE_TOTAL, 8, exc)
        if len(e) != 1:
            fails.append('%s: 期望 1 条错误, 实际 %d 条 (%s)'
                         % (real_case[0], len(e), e[:2]))

    print('=== doccheck 自检 ===')
    bad = set(f.split(':')[0] for f in fails)
    for name, text, want in cases:
        print('  [%s] %s (期望 %d 条)'
              % ('X' if name in bad else 'ok', name, want))
    if fails:
        for f in fails:
            print('  [X] %s' % f)
        print('[doccheck-selftest] FAIL (%d/%d)' % (len(fails), len(cases)))
        return 1
    # 数一数用例构成: 期望 != 0 的是负向注入, 期望 == 0 的是合规豁免。
    neg = len([c for c in cases if c[2]])
    print('[doccheck-selftest] PASS: %d 项（%d 项负向注入 / %d 项合规豁免）'
          % (len(cases), neg, len(cases) - neg))
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
    struct = check_gate_structure()
    if struct:
        errors.extend(struct)
    else:
        _src = open(os.path.join(REPO, 'tools', 'release_check.ps1'),
                    encoding='utf-8-sig').read()
        _n = len(re.findall(r"(?m)^\s*Check\s+'", _src))
        # `$With*` 可控的项默认不跑 —— 这是**设计**，不是事故：
        # 判据是"每个 if ($With*) 的 body 里最多一个 Check"，落在 if 外的一律默认必跑。
        _opt = len(re.findall(r"(?m)^\s*if\s*\(\s*\$With\w+\s*\)", _src))
        print('  [ok] 门禁结构: %d 项均为顶层语句，无被嵌套项；'
              '其中 %d 项由 -With* 显式开关控制（默认不跑），默认调用跑 %d 项'
              % (_n, _opt, _n - _opt))

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
