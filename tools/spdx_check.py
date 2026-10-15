#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""spdx_check.py — 「随开源分发的源码必须带 SPDX 标识」的机器判据

## 为什么需要它（2026-10-15，NEXT_STAGE_REVIEW ②）

`tools/add_license_headers.py` 早已能补 SPDX 头，AGPL-3.0 第 5 条也要求
分发时保留许可证声明 —— 但**没有任何判据在看它**：
`tools/release_check.ps1` 的 46 项 Checks 里 SPDX 出现 0 次。
后果实测：旧 glob 是两级定层（`src/*.c` + `include/protect/*.h`），
36 个 .c/.h 缺 SPDX 全部躺在 glob 之外（tools/attacker/、tests/c2vasm_cases/、
prot_sdk/skeleton/、examples/cross_platform/android/ …）**无人知晓**。

这是 §2.36.8 家族的下一环：「事实可获得、但没有判据使用它」。

## 判据（3 条）

① 范围内每个源文件的前 600 字节内必须有 `SPDX-License-Identifier`
   （范围 = add_license_headers.py 的 glob：src/ include/ tests/ tools/
     examples/ prot_sdk/ sdk_service/ demo/*.c，递归；排除
     demo/gen/ archive/ dist/ build/ build_artifacts/ —— 生成物与不发行物）
② **glob 缺口守卫**: 遍历范围内目录，任何 .c/.h/.py 文件**不在 glob 集合里**
   -> 报错。这一条把「glob 缺口」从"下一次审计才发现"变成"当场红" ——
   与本轮修的缺陷同型，判据必须能拦住它的复发。
③ 扫描面非空且不低于下限（**失锚即失败** —— glob 若因路径写错匹配到 0 个文件，
   判据①会"零违反"而看起来全绿）。
④ （仅真实仓库）与 add_license_headers.py 的 C_FILES+PY_FILES 集合逐一相等 ——
   防两套 glob 漂移（判据说合格、工具却没覆盖；或反之）。

## 用法

    python tools/spdx_check.py            # 扫真实仓库
    python tools/spdx_check.py --quiet    # 只出结论
    python tools/spdx_check.py --selftest # 负向自检
"""
import argparse
import glob as globmod
import io
import os
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SPDX_TAG = 'SPDX-License-Identifier'
# 与 add_license_headers.has_spdx 同一口径: 头必须在文件**开头**附近
_MAX_POS = 600

# 与 add_license_headers.py 共用的 glob（⚠️ 若那边改了范围，判据④会当场发现漂移）
_C_PATTERNS = ('src/**/*.c', 'include/**/*.h', 'tests/**/*.c',
               'tools/**/*.c', 'tools/**/*.h',
               'examples/**/*.c', 'examples/**/*.h',
               'prot_sdk/**/*.c', 'prot_sdk/**/*.h',
               'sdk_service/**/*.c', 'demo/*.c', 'demo/*.h')
_PY_PATTERNS = ('tools/**/*.py', 'tests/**/*.py', 'examples/**/*.py',
                'prot_sdk/**/*.py', 'sdk_service/**/*.py')
_EXCLUDE_PARTS = ('demo/gen', 'archive', 'dist', 'build', 'build_artifacts')

# 门禁扫描面下限（真实仓库实测 183；紧贴减 33，允许正常增删，不允许塌缩）
_MIN_FILES = 150

# glob 缺口守卫的遍历面: (目录, 检查的扩展名集合)
# demo 只查顶层 .c/.h（demo/gen 是生成物，生成头注明「请勿手工编辑」）
_GAP_DIRS = ('src', 'include', 'tests', 'tools', 'examples', 'prot_sdk',
             'sdk_service')


def _in_scope(path):
    p = path.replace('\\', '/')
    return not any(p.startswith('%s/' % x) or ('/%s/' % x) in p
                   for x in _EXCLUDE_PARTS)


def glob_set(root):
    """按判据①的范围收集文件（相对路径, 正斜杠, 排序）。"""
    out = set()
    cwd = os.getcwd()
    try:
        os.chdir(root)
        for pat in _C_PATTERNS + _PY_PATTERNS:
            for f in globmod.glob(pat, recursive=True):
                f = f.replace('\\', '/')
                if _in_scope(f):
                    out.add(f)
    finally:
        os.chdir(cwd)
    return sorted(out)


def gap_files(root, in_glob):
    """判据②: 范围内目录里存在、却不在 glob 集合里的源文件。

    demo 只看顶层（demo/gen 是生成物）；其余目录递归。
    """
    gaps = []
    for d in _GAP_DIRS:
        base = os.path.join(root, d)
        if not os.path.isdir(base):
            continue
        if d == 'demo':
            for f in sorted(os.listdir(base)):
                p = os.path.join(base, f)
                if os.path.isfile(p) and f.endswith(('.c', '.h')):
                    rel = ('%s/%s' % (d, f)).replace('\\', '/')
                    if rel not in in_glob:
                        gaps.append(rel)
            continue
        for cur, dirs, files in os.walk(base):
            dirs[:] = [x for x in dirs if x not in ('__pycache__', '.git')]
            for f in sorted(files):
                if not f.endswith(('.c', '.h', '.py')):
                    continue
                rel = os.path.relpath(os.path.join(cur, f), root)
                rel = rel.replace('\\', '/')
                if not _in_scope(rel):
                    continue
                if rel not in in_glob:
                    gaps.append(rel)
    return sorted(gaps)


def judge(repo=REPO, min_files=None):
    """返回 (errors, files, detail)。"""
    floor = _MIN_FILES if min_files is None else min_files
    errors = []
    files = glob_set(repo)
    missing = []
    for rel in files:
        raw = io.open(os.path.join(repo, rel), 'rb').read(_MAX_POS + 3)
        try:
            text = raw.decode('utf-8-sig', errors='replace')
        except Exception:
            text = ''
        if SPDX_TAG not in text:
            missing.append(rel)
            errors.append('%s: 前 %d 字节内无 %s 标识'
                          % (rel, _MAX_POS, SPDX_TAG))
    # ② glob 缺口
    gaps = gap_files(repo, set(files))
    for rel in gaps:
        errors.append('%s: 在范围内目录却**不在 glob 集合**里 —— glob 缺口'
                      '（判据①对它完全失明）' % rel)
    # ③ 失锚守卫
    if len(files) < floor:
        errors.append(
            '扫描面只有 %d 个文件（下限 %d）—— 判据失去锚点。'
            'glob 写错会匹配到 0 个文件, 那时"零违反"看起来像"全绿"。'
            % (len(files), floor))
    # ④ 与工具侧 glob 一致性（仅真实仓库）
    if repo == REPO:
        try:
            import add_license_headers as alh  # noqa: N812 — 同目录工具
            tool = {f.replace('\\', '/') for f in alh.C_FILES + alh.PY_FILES}
            ours = set(files)
            only_tool = sorted(tool - ours)
            only_ours = sorted(ours - tool)
            for rel in only_tool:
                errors.append('%s: add_license_headers.py 覆盖但 spdx_check '
                              '不覆盖 —— 两套 glob 漂移' % rel)
            for rel in only_ours:
                errors.append('%s: spdx_check 覆盖但 add_license_headers.py '
                              '不覆盖 —— 工具补不了这个文件的头' % rel)
        except ImportError:
            errors.append('无法 import add_license_headers —— 判据④（两套 '
                          'glob 一致性）未能运行')
    detail = {'missing': len(missing), 'gaps': len(gaps), 'total': len(files)}
    return errors, files, detail


def selftest(quiet=False):
    import tempfile
    fails = []
    n = 0
    lines = []

    def check(name, cond, detail=''):
        nonlocal n
        n += 1
        lines.append('  %s %-60s %s'
                     % ('ok ' if cond else '**FAIL**', name, detail))
        if not cond:
            fails.append(name)

    with tempfile.TemporaryDirectory() as d:
        def mk(rel, text):
            p = os.path.join(d, rel.replace('/', os.sep))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            io.open(p, 'wb').write(text.encode('utf-8'))

        # 1 正例: 带 SPDX -> 通过
        mk('src/a.c', '/* SPDX-License-Identifier: AGPL-3.0-or-later */\nint a;\n')
        mk('tools/t.py', '# SPDX-License-Identifier: AGPL-3.0-or-later\nX = 1\n')
        e, files, det = judge(d, min_files=2)
        check(u'正例: 带 SPDX -> 通过', not e, 'errors=%s' % e[:1])

        # 2 负例: 无 SPDX -> 必报
        mk('src/b.c', 'int b;\n')
        e, files, det = judge(d, min_files=2)
        check(u'**负向** 无 SPDX -> 必报',
              len(e) == 1 and 'src/b.c' in e[0] and SPDX_TAG in e[0],
              'errors=%s' % e[:1])
        os.remove(os.path.join(d, 'src', 'b.c'))

        # 3 负例: SPDX 在 600 字节之后 -> 必报（头部必须在开头附近）
        mk('src/c.c', ('// x\n' * 200) + '// SPDX-License-Identifier: AGPL-3.0-or-later\n')
        e, files, det = judge(d, min_files=2)
        check(u'**负向** SPDX 深埋在 600 字节后 -> 必报',
              len(e) == 1 and 'src/c.c' in e[0], 'errors=%s' % e[:1])
        os.remove(os.path.join(d, 'src', 'c.c'))

        # 4 BOM 文件: utf-8-sig 口径不得误报
        p = os.path.join(d, 'src', 'bom.c')
        io.open(p, 'wb').write(b'\xef\xbb\xbf/* SPDX-License-Identifier: '
                               b'AGPL-3.0-or-later */\nint x;\n')
        e, files, det = judge(d, min_files=2)
        check(u'BOM + SPDX -> 通过（不得误报）', not e, 'errors=%s' % e[:1])
        os.remove(p)

        # 5 glob 缺口: 真实缺口场景 —— sdk_service 的 .h 不在 glob 里
        #    （_C_PATTERNS 有 sdk_service/**/*.c 但无 **/*.h；而 _GAP_DIRS
        #     含 sdk_service）。递归 glob 能覆盖的子目录不是缺口，别自欺。
        mk('sdk_service/sub/gap.h', 'int n;\n')
        e, files, det = judge(d, min_files=2)
        check(u'**负向** glob 缺口（sdk_service/sub/gap.h 不在 glob）-> 必报',
              any('gap' in x and u'缺口' in x for x in e), 'errors=%s' % e[:1])
        os.remove(os.path.join(d, 'sdk_service', 'sub', 'gap.h'))

        # 6 失锚: 空扫描面必须失败（不是"零违反"）
        for cur, dirs, fs in os.walk(d, topdown=False):
            for f in fs:
                os.remove(os.path.join(cur, f))
            for x in dirs:
                os.rmdir(os.path.join(cur, x))
        e, files, det = judge(d, min_files=1)
        check(u'**失锚** 扫描面为空 -> 必须失败（不是"零违反"）',
              any(u'失去锚点' in x for x in e), 'errors=%s' % e[:1])

    # 7 真实仓库活断言: 当前状态。有真实违反时它是红的，修掉后才绿。
    e, files, det = judge(REPO)
    check(u'真实仓库: 范围内源文件全部带 SPDX',
          det['missing'] == 0, 'missing=%d total=%d %s'
          % (det['missing'], det['total'], e[:1] if e else ''))
    check(u'真实仓库: 无 glob 缺口', det['gaps'] == 0,
          'gaps=%d %s' % (det['gaps'], e[:1] if e else ''))
    check(u'真实仓库: 扫描面 %d >= 下限 %d' % (det['total'], _MIN_FILES),
          det['total'] >= _MIN_FILES)

    if not quiet:
        sys.stdout.write('=== spdx_check 自检 ===\n')
        for l in lines:
            sys.stdout.write(l + '\n')
    if fails:
        sys.stdout.write('[spdx_check-selftest] FAIL: %s\n' % '; '.join(fails))
        return 1
    sys.stdout.write('[spdx_check-selftest] PASS: %d 项（含 3 项负向 + 1 项失锚）\n'
                     % n)
    return 0


def main():
    ap = argparse.ArgumentParser(prog='spdx_check.py')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--quiet', action='store_true')
    a = ap.parse_args()
    if a.selftest:
        return selftest(quiet=a.quiet)
    errors, files, det = judge()
    if errors:
        for x in errors:
            sys.stdout.write('[X] %s\n' % x)
        sys.stdout.write('[spdx_check] FAIL: %d 处（扫 %d 个文件）\n'
                         % (len(errors), det['total']))
        return 1
    if not a.quiet:
        sys.stdout.write('[ok] 随开源分发的 %d 个源文件全部带 SPDX '
                         '（无 glob 缺口）\n' % det['total'])
    return 0


if __name__ == '__main__':
    sys.exit(main())
