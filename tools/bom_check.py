#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bom_check.py — 「含中文的 .ps1 必须带 BOM」的机器判据。

## 为什么需要它

`docs/HANDOVER.md:152-153` 早就写了这条纪律，`CONTRIBUTING.md:126` 也写了，
`tools/bom.py` 提供了工具 —— **但没有任何判据在看它**。
后果实测（2026-10-10，§2.62.7）：

    PS 5.1 读 tools/attacker/winpe_sympatcher/build.ps1 的第一行
      实际: # build.ps1 U+9225 U+003F U+93CB U+52EB U+7F13 WinPE-SymPatcher
            (U+93C0 U+5A5A U+69FB U+5BB8 U+30E5 U+53FF, U+6D60 U+5470 U+569C U+93C8
             U+5909 U+9A87 U+9417 U+2542 U+7D28 U+7F01 U+003F)

(上面"实际"一行按仓库惯例写成**码点**而不是字形 —— 写字形会让门禁第 20 项
`mojibake_check` 把这段证据本身判成新的坏行。`tools/mojibake.py` 的 `_cp()`
就是为这个目的存在的。)
      应为: # build.ps1 — 构建 WinPE-SymPatcher (攻防工具, 仅自有产物演练)

即 PS 5.1 按 ANSI/GBK 解读那些 UTF-8 字节 ⇒ 全是乱码。那个文件今天**仍然能跑**，
只因为 6 行中文**全在注释里**；一旦有人把中文写进 `throw '中文'` 或
`Write-Host '中文'`，就会得到一堆莫名其妙的解析/运行错误（同 `72b75eb` 的症状）。

## 判据（**只有一条**，因为只有它实测站得住）

    含非 ASCII 字节的 `.ps1` 必须带 UTF-8 BOM（EF BB BF）

**为什么只判 `.ps1`**（先量后改，2026-10-10 全库实测）:

| 扩展名 | 有非ASCII+BOM | 有非ASCII 无BOM |
|---|---|---|
| `.ps1` | **14** | **1** |
| `.c`   | 7 | 65 |
| `.json`| 0 | 16 |

`.c` / `.json` 的分布是**散的**（`.c` 大多数无 BOM 且正常）⇒ 对它们判 BOM
只会把既有的、无害的状态判成失败（同类错误见 `docs/HANDOVER.md` §2.62.5：
把卫生判据换成 glob 会当场报 11 条与本轮无关的既有违反）。
**`.ps1` 是唯一一个"约定已经形成为不变量"的扩展名**，因为 PS 5.1 的解析器
真的会因此读错中文，而 C 编译器 / `json.loads` 都按 UTF-8 处理，BOM 与否无影响。

## 为什么**不判**「非 .ps1 不得带 BOM」

全库有 **10** 个非 `.ps1` 文件带 BOM，其中 8 个是 `src/*.c`（由
`tools/add_license_headers.py` 写入，其 `read_src`/`write_src` 的 docstring
**明确**写了「必须保留 BOM … 属无谓改动, 应保留原状」）。
把它们判成失败等于要求一次**无收益的大范围改写**（同 §2.62.6 对 CRLF 的结论）。

## 为什么**不判** CRLF

`docs/HANDOVER.md:2741` 曾写「`.ps1` 的 CRLF-only 是仓库硬不变量」——
**实测是错的**（§2.62.6）：15 个 `.ps1` 里只有 **6** 个是全 CRLF，7 个是纯 LF，
且 `git ls-files --eol` 显示它们是 `i/lf w/lf`（`.gitattributes` 虽声明
`*.ps1 eol=crlf`，检出时并未转换）。⇒ CRLF 不是不变量，判它只会制造字节 diff。

用法:
    python tools/bom_check.py            # 扫全库
    python tools/bom_check.py --quiet    # 只出结论
    python tools/bom_check.py --selftest # 负向自检（含失锚守卫）
"""
import argparse
import io
import os
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BOM = b'\xef\xbb\xbf'

# 扫描面：**不跳过任何源码目录** —— 本条不变量对"哪个目录"没有意见。
# 但跳过构建产物与第三方（`build` 下是我们自己生成的中间物,
# 它们由生成器保证, 且会随构建消失, 判它们只会让门禁在构建后变红）。
SKIP_DIRS = {'.git', '.vs', 'archive', 'node_modules', '__pycache__',
             'build', 'dist', '.vscode', '.idea'}

# 判据②的守卫下限：全库实测 15 个 .ps1。留 1 个余量会在"有人删掉一半"时失明，
# 故紧贴实测值减 2（允许正常增删，不允许塌缩）。
_MIN_PS1 = 13


def walk_ps1(repo=REPO):
    out = []
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in sorted(files):
            if f.lower().endswith('.ps1'):
                out.append(os.path.join(root, f))
    return sorted(out)


def judge(repo=REPO, min_ps1=None):
    """返回 (errors, checked, detail)。

    判据① 含非 ASCII 的 .ps1 必须带 BOM。
    判据② 扫描面非空且不低于下限（**失锚即失败** —— 若 os.walk 因为路径/权限
          问题什么都不返回，判据①会"零违反"而看起来全绿）。

    `min_ps1=None` 表示用真实仓库的下限 `_MIN_PS1`。自检传 1（临时目录里本来就
    只有一两个文件）—— **这一条是我自己踩过的**：下限若不随扫描面收敛，自检的
    前四个用例会被"失去锚点"这条报错污染，看起来像判据本身坏了。
    """
    floor = _MIN_PS1 if min_ps1 is None else min_ps1
    errors = []
    ps1 = walk_ps1(repo)
    checked = 0
    n_na = 0
    for p in ps1:
        raw = io.open(p, 'rb').read()
        bom = raw[:3] == BOM
        try:
            t = raw.decode('utf-8-sig')
        except UnicodeDecodeError as e:
            errors.append('%s: 不是合法 UTF-8 (%s)'
                          % (os.path.relpath(p, repo).replace('\\', '/'), e))
            checked += 1
            continue
        na = [c for c in t if ord(c) > 127]
        checked += 1
        if na and not bom:
            rel = os.path.relpath(p, repo).replace('\\', '/')
            sample = ''.join(na[:12])
            errors.append(
                '%s: 含 %d 个非 ASCII 字符但**无 BOM** —— PowerShell 5.1 会按 '
                'ANSI/GBK 解析, 中文变乱码 (样例: %s)'
                % (rel, len(na), sample))
            n_na += 1
    if len(ps1) < floor:
        errors.append(
            '扫描面只有 %d 个 .ps1（下限 %d）—— 判据失去锚点。'
            '空扫描面会让"零违反"看起来像"全绿", 故此处必须失败。'
            % (len(ps1), floor))
    return errors, checked, {'ps1': len(ps1), 'no_bom_with_nonascii': n_na}


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
        def mk(name, text, bom):
            p = os.path.join(d, name)
            data = text.encode('utf-8')
            if bom:
                data = BOM + data
            io.open(p, 'wb').write(data)
            return p

        # 1 正例: 有中文 + 有 BOM
        mk('a.ps1', u'# 中文注释\nWrite-Host 1\n', True)
        e, c, det = judge(d, min_ps1=1)
        check(u'有中文 + 有 BOM -> 通过', not e, 'errors=%d' % len(e))

        # 2 负例: 有中文 + 无 BOM  <- 本判据存在的全部理由
        mk('b.ps1', u'# 中文注释\nWrite-Host 1\n', False)
        e, c, det = judge(d, min_ps1=1)
        check(u'**负向** 有中文 + 无 BOM -> 必须报',
              len(e) == 1 and 'b.ps1' in e[0] and u'无 BOM' in e[0],
              'errors=%s' % e[:1])

        # 3 纯 ASCII 无 BOM -> 合法（不得误报）
        os.remove(os.path.join(d, 'b.ps1'))
        os.remove(os.path.join(d, 'a.ps1'))
        mk('c.ps1', 'Write-Host 1\n', False)
        e, c, det = judge(d, min_ps1=1)
        check(u'纯 ASCII 无 BOM -> 通过（不得误报）', not e, 'errors=%s' % e[:1])

        # 4 非 ASCII 但非中文（如 → ·）同样需要 BOM —— 判据按字节, 不按"汉字"
        mk('d.ps1', u'# arrow -> \u2192 \u00b7\n', False)
        e, c, det = judge(d, min_ps1=1)
        check(u'非 ASCII 非汉字（→ ·）无 BOM -> 必须报（判据按非 ASCII, 不按汉字）',
              len(e) == 1, 'errors=%d' % len(e))

        # 5 失锚守卫: 空扫描面必须失败（否则"零违反"看起来像全绿）
        for f in os.listdir(d):
            os.remove(os.path.join(d, f))
        e, c, det = judge(d, min_ps1=1)
        check(u'**失锚** 扫描面为空 -> 必须失败（不是"零违反"）',
              any(u'失去锚点' in x for x in e), 'errors=%s' % e[:1])

    # 6 真实仓库: 当前状态。这一条**故意**是"活断言" —— 仓库里真有一个违反时它是红的,
    #   修掉之后才是绿的。它不是恒真用例（恒真用例只是装饰）。
    e, c, det = judge(REPO)
    check(u'真实仓库: 含中文的 .ps1 全部带 BOM',
          not e, 'ps1=%d na_no_bom=%d %s'
          % (det['ps1'], det['no_bom_with_nonascii'],
             ('errors=%s' % e[:1]) if e else ''))
    check(u'真实仓库: 扫描面 %d 个 .ps1 >= 下限 %d'
          % (det['ps1'], _MIN_PS1), det['ps1'] >= _MIN_PS1)

    if not quiet:
        sys.stdout.write('=== bom_check 自检 ===\n')
        for l in lines:
            sys.stdout.write(l + '\n')
    if fails:
        sys.stdout.write('[bom_check-selftest] FAIL: %s\n' % '; '.join(fails))
        return 1
    sys.stdout.write('[bom_check-selftest] PASS: %d 项（含 2 项负向 + 1 项失锚）\n'
                     % n)
    return 0


def main():
    ap = argparse.ArgumentParser(prog='bom_check.py')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--quiet', action='store_true')
    a = ap.parse_args()
    if a.selftest:
        return selftest(quiet=a.quiet)
    errors, checked, det = judge()
    if errors:
        for x in errors:
            sys.stdout.write('[X] %s\n' % x)
        sys.stdout.write('[bom_check] FAIL: %d 处（扫 %d 个 .ps1）\n'
                         % (len(errors), det['ps1']))
        return 1
    if not a.quiet:
        sys.stdout.write('[ok] 含非 ASCII 的 .ps1 全部带 BOM'
                         '（扫 %d 个 .ps1）\n' % det['ps1'])
    return 0


if __name__ == '__main__':
    sys.exit(main())
