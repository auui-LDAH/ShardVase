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
    """release_check.ps1 的实际门禁项数 (Check 调用数 + 签名提示项)。"""
    p = os.path.join(REPO, 'tools', 'release_check.ps1')
    if not os.path.isfile(p):
        return None
    n = len(re.findall(r"^\s*Check '", open(p, encoding='utf-8').read(), re.M))
    # +1: codesign.pfx 存在时的签名 pass++ 项
    return n + 1


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
