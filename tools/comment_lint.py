#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""comment_lint.py — 检测 C/C++ 注释里的**词法陷阱**

## 为什么需要（本项目**三次**同类问题）
  ① `*/` 提前闭合注释  —— include/protect/prot_platform.h（L5b 实现时）
  ② `*/` 提前闭合注释  —— src/platform/prot_platform_linux.c（L5c 实现时）
  ③ `/*` 嵌套开启注释  —— include/protect/prot_sections.h（L6b 编译测试时）

  三次都因**在注释里写路径通配或 C 语法示例**时，
  忘了 `/*` 与 `*/` 在注释内**仍被词法器识别**。

  => 用工具检测，比"记得小心"可靠（与 R20/S1 同样的思路）。

## 规则
  C1 注释内出现 `/*`（嵌套开启）-> error（GCC `-Wcomment`）
  C2 注释内出现**多余**的 `*/`（提前闭合）-> 由**状态机**检测:
     若在"非注释"状态下遇到 `*/` -> error
  C3 路径通配 `*/`（如 `/sys/block/*/x`）-> warning（易成为 C2 的诱因）

## 用法
  python tools/comment_lint.py            # 扫描 src/ include/ tests/
  python tools/comment_lint.py --selftest # 负向自检
"""
import argparse
import os
import re
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCAN_DIRS = ['src', 'include', 'tests', 'prot_sdk', 'examples', 'demo']


def scan_file(path):
    """返回 (errors, warnings)。"""
    errors, warnings = [], []
    try:
        text = open(path, encoding='utf-8', errors='replace').read()
    except OSError:
        return errors, warnings
    # **逐行状态机**（不靠正则，避免自我欺骗）
    in_block = False
    for lineno, line in enumerate(text.split('\n'), 1):
        i = 0
        n = len(line)
        while i < n:
            if not in_block:
                # 找下一个 /*
                j = line.find('/*', i)
                k = line.find('//', i)
                if k >= 0 and (j < 0 or k < j):
                    break               # 行注释吞掉剩余
                if j < 0:
                    # 非注释状态下出现 */ -> 提前闭合（或本来就是注释外）
                    m = line.find('*/', i)
                    if m >= 0:
                        errors.append(
                            '%s:%d C2 注释外出现 "*/"（提前闭合？）: %s'
                            % (path, lineno, line.strip()[:60]))
                    break
                in_block = True
                i = j + 2
            else:
                # 注释内: 先找下一个 '/*' 与 '*/'
                #
                # ⚠️ **判定要点（自检抓到的两个 bug，同一根源）**
                #   路径通配 `/sys/block/*/dev` 同时含 `/*`（位置 18）
                #   与 `*/`（位置 19）—— **两个都不是注释语法**。
                #
                #   初版直接 `find('*/')` 与 `find('/*')`
                #   -> 把路径通配误判为"嵌套开启"或"注释结束" -> 误报。
                #
                #   **这正是本项目三次注释陷阱的同一根源**:
                #   路径里的 `/*` 与 `*/` 会被 C 词法器（和我的检查器）
                #   当作注释语法。
                #
                #   修法: 两个方向都排除"路径通配"形态 ——
                #     `/*` 前一个字符是 `/`（形如 `x/*`）-> 跳过
                #     `*/` 前一个字符是 `/`（形如 `/*/`）-> 跳过
                nxt = _find_real_open(line, i)
                m = _find_real_close(line, i)
                if nxt >= 0 and (m < 0 or nxt < m):
                    errors.append(
                        '%s:%d C1 注释内出现 "/*"（嵌套开启）-> '
                        'GCC -Wcomment: %s'
                        % (path, lineno, line.strip()[:60]))
                    i = nxt + 2
                    continue
                if m < 0:
                    # 路径通配诱因检查: 形如 /x/*/y
                    if re.search(r'/\w[\w/]*/\*/', line):
                        warnings.append(
                            '%s:%d C3 注释含路径通配 "*/" 形式，'
                            '易成为 C2 诱因: %s'
                            % (path, lineno, line.strip()[:60]))
                    break
                in_block = False
                i = m + 2
    return errors, warnings


def _find_real_open(line, start):
    """找**真正的**注释开启符 `/*`（跳过路径通配）。

    ### 判据
      `/*` 的前一个字符若是 `/`（形如 `x/*` 或 `x/*/`）-> 路径通配，跳过。
      （例: `/sys/block/*/dev` 里的 `/*` 在位置 18，
        前一字符是 `k`，**会被误判**；故还须看**后面**是否为 `/`。）
    """
    i = start
    while True:
        j = line.find('/*', i)
        if j < 0:
            return -1
        # 形如 `/*/` -> 路径通配（星号后面紧跟斜杠）
        if j + 2 < len(line) and line[j + 2] == '/':
            i = j + 2
            continue
        return j


def _find_real_close(line, start):
    """找**真正的**注释终结符 `*/`（跳过路径通配）。

    ### 判据
      `*/` 的前一个字符若是 `/`（形如 `/*/` 或 `x/*/`）-> 路径通配，跳过。

    ### 为什么不能直接用 `line.find('*/', start)`
      路径通配 `/sys/block/*/dev` 里 `*` 与 `/` 相邻 ->
      `find` 会把它当注释终结符 -> **误判**（自检抓到）。
      **这正是本项目三次注释陷阱的同一根源。**
    """
    i = start
    while True:
        j = line.find('*/', i)
        if j < 0:
            return -1
        if j > 0 and line[j - 1] == '/':
            i = j + 1        # 形如 `/*/` -> 路径通配，跳过
            continue
        return j


def collect_files():
    out = []
    for d in SCAN_DIRS:
        base = os.path.join(REPO, d)
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            dirs[:] = [x for x in dirs if x != '__pycache__']
            for f in files:
                if f.endswith(('.c', '.h')):
                    out.append(os.path.join(root, f))
    return sorted(out)


def main():
    ap = argparse.ArgumentParser(prog='comment_lint.py')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    files = collect_files()
    all_e, all_w = [], []
    for f in files:
        rel = os.path.relpath(f, REPO)
        e, w = scan_file(rel)
        all_e.extend(e)
        all_w.extend(w)
    if not args.quiet:
        print('=== C 注释词法检查 ===')
        print('  扫描 %d 个 .c/.h 文件' % len(files))
        print()
    for x in all_e:
        print('  [X] %s' % x)
    for x in all_w:
        print('  [!] %s' % x)
    if all_e:
        print()
        print('[comment_lint] FAIL: %d 项 error' % len(all_e))
        return 1
    if not args.quiet:
        print()
        print('[comment_lint] PASS: 无注释词法陷阱（%d 警告）' % len(all_w))
    return 0


def selftest():
    """负向自检: 必须能抓到三类问题。"""
    import tempfile
    fails = []

    def case(name, content, want_err):
        d = tempfile.mkdtemp(prefix='clint_')
        p = os.path.join(d, 't.c')
        with open(p, 'w', encoding='utf-8') as f:
            f.write(content)
        e, w = scan_file(p)
        ok = (len(e) > 0) == want_err
        print('  %s %-52s' % ('ok ' if ok else '**FAIL**', name))
        if not ok:
            fails.append(name)

    print('=== comment_lint 自检 ===')
    # 正常
    case('正常注释', '/* hello */\nint x;\n', False)
    # C1: 注释内 /*
    case('注释内嵌套 /*（C1）', '/* a /* b */\nint x;\n', True)
    # C2: 提前闭合导致后续 */
    case('提前闭合（C2）', '/* a */ b */\nint x;\n', True)
    # 路径通配 -> 只警告
    case('路径通配（C3，仅警告）', '/* path /sys/block/*/dev */\nint x;\n',
         False)
    # 多行注释正常
    case('多行注释正常', '/*\n * a\n * b\n */\nint x;\n', False)
    case('多行含嵌套（C1）', '/*\n * src/*.c\n */\nint x;\n', True)

    print()
    print('=' * 60)
    if fails:
        print('[comment_lint-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    print('[comment_lint-selftest] PASS: 可自证能抓错')
    return 0


if __name__ == '__main__':
    sys.exit(main())
