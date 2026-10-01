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

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

# 被检查的对外材料
TARGETS = sorted(glob.glob(os.path.join(REPO, 'publish', '*.md'))) + \
          sorted(glob.glob(os.path.join(REPO, 'docs', 'marketing', '*.md')))

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
    **吃掉了它原本的 `} else {`** —— 于是门禁第 23~32 项（含"文档断言一致性"
    与"门禁日志自检"自己）**全部被嵌套进 `if ($WithMigration)`**，
    只有显式传 `-WithMigration` 才跑。实测证据（同一脚本、同一台机器）:

        · 不带任何开关                                  -> `PASS: 19 项`
        · `-WithSkeleton -WithMutation -WithMigration`  -> `PASS: 30 项`

    即**默认调用下门禁静默跳过约 10 项，而 PASS 文案照打** —— 违反本项目
    反复记名的"未验证 != 通过"。**既有两个数门禁项数的检查器都没抓住**:
    第 26 项 `docclaim`、第 31 项 `gate_log` 都只数 `Check` 的**出现次数**
    （32 个全对），**没有一个断言它们在顶层**；更糟的是这两项**自己就落在
    被嵌套的区间里**，复发时根本不会运行。

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


def main(argv=None):
    ap = argparse.ArgumentParser(prog='doccheck.py',
                                 description='对外材料数字漂移检查')
    ap.add_argument('--list', action='store_true', help='列出被检查的数字')
    args = ap.parse_args(argv)

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
        _n = len(re.findall(r"(?m)^\s*Check\s+'",
                            open(os.path.join(REPO, 'tools', 'release_check.ps1'),
                                 encoding='utf-8-sig').read()))
        print('  [ok] 门禁结构: %d 项均为顶层语句（默认调用下都会运行）' % _n)

    for f in TARGETS:
        rel = os.path.relpath(f, REPO)
        try:
            t = open(f, encoding='utf-8').read()
        except OSError:
            continue

        # --- 1. 模糊表述 (排除引用/否定语境) ---
        for pat, why in VAGUE_PATTERNS:
            for m in re.finditer(pat, t):
                if _is_quoted_or_negated(t, m.start(), m.end()):
                    continue
                ln = t[:m.start()].count('\n') + 1
                errors.append('%s:%d 出现%s' % (rel, ln, why))

        # --- 2. release_check N/N ---
        for m in re.finditer(r'release_check[^\n]*?(\d+)/(\d+)', t):
            checked += 1
            claim = int(m.group(2))
            if gate is not None and claim != gate:
                ln = t[:m.start()].count('\n') + 1
                errors.append('%s:%d release_check 声称 %d, 实际 %d'
                              % (rel, ln, claim, gate))

        # --- 3. 轮次口径 ---
        for m in re.finditer(r'(\d+)\s*\+?\s*轮(?:正式|完整|攻防|演练)?', t):
            claim = int(m.group(1))
            # 只检查"攻防演练轮次"这类主口径 (排除"第一轮/第二轮"表格行)
            if re.search(r'第[一二三四五六七八九十\d]+轮', t[max(0, m.start()-6):m.start()+8]):
                continue
            checked += 1
            if claim not in (rounds, rounds - 1) and '矩阵' in t[m.start():m.start()+30]:
                ln = t[:m.start()].count('\n') + 1
                warnings.append('%s:%d 轮次声称 %d, 实际 %d (请确认口径)'
                                % (rel, ln, claim, rounds))

        # --- 4. 引用的仓库内路径 (死链是错误, 不是警告) ---
        for m in re.finditer(r'`((?:docs|tools|tests|src|include|prot_sdk|publish|drills|compositions)/[\w\-./]+)`', t):
            checked += 1
            if not os.path.exists(os.path.join(REPO, m.group(1))):
                ln = t[:m.start()].count('\n') + 1
                errors.append('%s:%d 引用路径不存在: %s'
                              % (rel, ln, m.group(1)))

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
    print()


    print('[doccheck] %s' % ('FAIL' if errors else 'PASS'))
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
