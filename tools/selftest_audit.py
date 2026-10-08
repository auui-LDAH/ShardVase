#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""selftest_audit.py — **登记了自检的工具必须真的有执行者**（2026-10-08）

## 被检查的不变量

    「凡在 argparse 里登记了自检（`--selftest` 旗标、或 `selftest` 子命令）的工具，
      必须能从**构建/门禁/CI 入口**到达，并且是**带着自检参数**被调用。」

## 为什么需要（这不是纪律问题，是**纪律被写下但从未被执行**）

`docs/PROTOCOL_GOVERNANCE.md:174-175` 逐字写着：

    **全部带 `--selftest` 的工具都能自证"会抓错"** —— 这是门禁失效事件
    （2026-09-23，7/13 项曾静默通过）后确立的**强制纪律**。

这句话要求的是「**能**自证」。它没有要求「**自证被执行**」，于是出现了一个
从未被任何人看见的缺口（2026-10-08 实测）：

    6 个工具登记了自检、自检也确实能抓错（全部 rc=0 PASS），
    但**全库没有任何入口以自检参数调用过它们** —— 一次都没有。

    ① tools/genpaths.py         --selftest   17 条用例 / 3 条负向
    ② tools/hostgen.py          --selftest   19 条用例
    ③ tools/identity.py         --selftest   12 条用例
    ④ tools/migration_cost.py   --selftest   15 条用例
    ⑤ tools/solve_profile.py    --selftest   13 条用例
    ⑥ tools/observability.py    selftest     10 条用例（子命令形态）
    合计运行成本 0.40 s，且不写任何仓库文件（实测 `git status` 干净）。

  => 「能抓错」是**属性**，「被抓错时有人知道」才是**保护**。写下的纪律
     与生效的纪律之间的差额，正是本文件要堵的东西 —— 与 §2.36.8（枚举清单）、
     §2.38（语法检查步）、§2.40（扫描面自声明）、§2.42（休眠自检）、
     §2.46（ci.yml 项数）、§2.52（围栏配平）同型。

## 判据

  ① 每个登记了自检的 `tools/*.py`，都必须有**执行者**；
  ② 执行者必须在 `HARNESS`（门禁 / ci_sim / ci_linux / build.ps1 / workflows）
     **或其可达链**上（例如 `vmc_linux.py` 的执行者是 `verify_linux_runtime.py`，
     而后者由 `ci_linux.ps1` 调用）；
  ③ 执行者调用它时**必须带自检参数**（`--selftest` / `selftest`）；
  ④ 注释与 **docstring** 都不算执行者（`_strip_comments` + `_strip_docstrings`）；
     见 §2.48 的教训：我自己的注释曾把"声明"读成"覆盖"。
     实测补充: 首版只剥 `#` 注释 ⇒ `tools/doccheck.py:855` 的 docstring
     把 `migration_cost.py` 误判成有执行者，而它**确实是孤儿**。
  ⑤ 锚点消失即 FAIL —— **失锚不得读成"没有孤儿"**（§2.45 / §2.46 同纪律）。

## 含负向自检

    `--selftest` 对**合成文本**做 8 条变异（不碰仓库文件），每条都必须被抓：
      M1 登记了自检、全库无人调用           -> 必须报孤儿
      M2 只在**注释**里被提到                -> 必须报孤儿（④）
      M3 入口调用它但**不带**自检参数        -> 必须报孤儿（③）
      M4 入口带自检参数调用                 -> 不得报
      M5 传递可达（A 带自检调 B，B 带自检调 C）-> 不得报
      M6 传递但中间那跳**不带**自检参数      -> 必须报孤儿
      M7 子命令形态（`X.py selftest`）       -> 不得报
      M8 只在 **docstring** 里被提到          -> 必须报孤儿

## 用法

    python tools/selftest_audit.py [--quiet] [--selftest] [--list]

退出码: 0 = 无孤儿; 1 = 存在孤儿; 2 = SKIP（工具目录缺失）

## 诚实边界

  ① 本判据判的是「**可达性**」，不是「执行结果」—— 它不会知道那个自检
     跑起来是否真的通过。真正跑它们的是门禁第 41 项本体（它逐条执行
     过去的 6 个孤儿自检），两者互补。
  ② `HARNESS` 是**手写清单**：新增一个门禁入口（例如新的 `*.ps1`）而不
     登记进来，本判据看不见它。这是清单类判据的共同边界。
  ③ 判定按**逻辑语句**切分（变量中转窗口 = `INDIRECT_STMTS = 8` 条语句），
     不按字符距离。首版用「400 字符窗口」，把相邻两行的不同命令
     （`& $py tools\a.py --quiet` 与 `& $py tools\b.py --selftest`）读成
     同一次调用，导致 M3 用例自己 FAIL —— **判定必须按语句做**。
     取向仍是**宁可误报**：误报会逼人显式接线，漏报则回到「写下的纪律」。
  ④ 不检查自检的**质量**（用例数、是否覆盖负向）。§2.53 记录的三次
     「探针口径错伪装成被测对象性质」说明这类判断仍需人读。
"""

import argparse
import ast
import io
import os
import re
import sys

# --------------------------------------------------------------------------
# 路径推导: 从本文件位置向上找含 tools/winproc.py 的目录。
#   统一用 tools/winproc.py 封装（CREATE_NO_WINDOW + STARTUPINFO/SW_HIDE）。
_os_hw = os.path.dirname(os.path.abspath(__file__))
while _os_hw and not os.path.isfile(os.path.join(_os_hw, 'tools', 'winproc.py')):
    _nxt = os.path.dirname(_os_hw)
    if _nxt == _os_hw:
        break
    _os_hw = _nxt
REPO = _os_hw

# 入口清单（判据②）。手写 —— 见诚实边界②。
HARNESS = (
    'tools/release_check.ps1',
    'tools/ci_sim.ps1',
    'tools/ci_linux.ps1',
    'build.ps1',
    '.github/workflows/ci.yml',
    '.github/workflows/ci-linux.yml',
)

SCAN_DIRS = ('tools', 'tests')

# 工具名与自检参数之间允许隔的逻辑行数（变量中转形态，判据③）。
#   不走字符距离窗口 —— 见 _cover_in_text 的实测教训。
INDIRECT_STMTS = 8

# 子命令形态的自检参数名。
SUB_SELFTEST = 'selftest'

_RE_PYNAME = re.compile(r'([A-Za-z_][\w\-]*\.py)')


def _read(path):
    with io.open(path, 'r', encoding='utf-8-sig', errors='replace') as fh:
        return fh.read()


def _strip_docstrings(text):
    """把 **docstring 行**整行清空（判据④）。

    只清 `ast.Expr(Constant(str))` 形态 —— 也就是模块/类/函数的文档串。
    **不清普通的字符串字面量**：`os.path.join(REPO, 'tools', 'vmc_linux.py')`
    里的路径就是**代码**，正是判据要找的东西。

    ## 为什么需要（实测）
    首版只剥 `#` 注释，于是 `tools/doccheck.py:855` 的 docstring 里那句
    「`tools/migration_cost.py`」与同函数后文某个 `--selftest` 落进同一条
    语句窗口 ⇒ `migration_cost.py` 被判成**有执行者**，而它**确实是孤儿**。
    ⇒ 与本工具 docstring 判据④要防的是同一件事: 「被声明」不得读成「被执行」。
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return text
    lines = text.splitlines()
    kill = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            for ln in range(node.lineno, (node.end_lineno or node.lineno) + 1):
                kill.add(ln)
    return '\n'.join('' if (i + 1) in kill else l
                      for i, l in enumerate(lines))


def _strip_comments(text):
    """去掉整行注释与行内 `#` 之后的注释（判据④）。

    只做**保守**剥离：不解析字符串字面量，故 `#"` 之类会多剥一点，
    取向仍是"宁可漏掉一个执行者"——但那会让判据**报孤儿**，不是静默变绿。
    """
    out = []
    for line in text.splitlines():
        s = line.lstrip()
        if s.startswith('#') or s.startswith('//'):
            out.append('')
            continue
        i = line.find('#')
        out.append(line[:i] if i >= 0 else line)
    return '\n'.join(out)


def declares_selftest(path):
    """AST 判定: 返回 None / '--selftest' / 'selftest'。

    用 AST 而不是文本 —— 文本会把 `selftest()` 函数定义读成"登记了自检"。
    """
    try:
        tree = ast.parse(_read(path))
    except (SyntaxError, ValueError):
        return None
    flag = sub = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, 'attr', None)
        for a in node.args:
            if not isinstance(a, ast.Constant):
                continue
            if name == 'add_argument' and a.value == '--selftest':
                flag = True
            if name == 'add_parser' and a.value == SUB_SELFTEST:
                sub = True
    if flag:
        return '--selftest'
    if sub:
        return SUB_SELFTEST
    return None


def _selftest_pat(kind):
    """自检参数的两种形态。"""
    if kind == '--selftest':
        return ('--selftest',)
    return ("'selftest'", '"selftest"', ' selftest', '\tselftest')


def _statements(body):
    """按**逻辑行**切分: 括号深度归零处才断句（含反引号续行）。

    这一步是判据③的关键 —— 只用字符距离会把
        `& $py tools\\a.py --quiet`
        `& $py tools\\b.py --selftest`
    里的 a.py 也判成"带自检参数被调用"（相邻两行距离极近，但**不是同一条命令**）。
    实测出处: 本文件 `--selftest` 用例 M3 首跑即因此误判为覆盖。
    """
    out, buf, depth = [], [], 0
    for line in body.splitlines():
        buf.append(line)
        depth += line.count('(') + line.count('[') + line.count('{')
        depth -= line.count(')') + line.count(']') + line.count('}')
        if depth <= 0 and not line.rstrip().endswith('`'):
            depth = 0
            out.append('\n'.join(buf))
            buf = []
    if buf:
        out.append('\n'.join(buf))
    return out


_RE_ASSIGN = re.compile(r'^\s*\$?([A-Za-z_]\w*)\s*=')


def _cover_in_text(text, tool, kind):
    """`text` 里是否**带着自检参数**引用了 `tool`（判据③④）。

    返回 `(语句序号, 带旗标的那条语句)` —— 后者供判据④比对旗标。

    两条接受路径:

      (a) **同一逻辑行**内含工具名与自检参数 —— `& $py tools\\x.py --selftest`；
      (b) **变量中转** —— 工具名出现在赋值右侧（`vmc_py = os.path.join(...`
          换行 `'vmc_linux.py')`），且该变量在随后的逻辑行里带着自检参数被使用。

    路径 (b) 是必要的: `tools/vmc_linux.py` 的执行者
    （`tools/verify_linux_runtime.py:507`/`:509`）正是这种两跳形态。

    ⚠️ 首版走字符距离窗口 —— 它会把
        `& $py tools\\a.py --quiet`
        `& $py tools\\b.py --selftest`
    里的 a.py 也判成"带自检参数被调用"（相邻两行距离极近，**但不是同一条命令**）。
    本文件 `--selftest` 的 M3 用例首跑即因此误判为覆盖（`孤儿 0（期望 1）`）。
    ⇒ 判定必须**按语句**做，不能按字符距离。
    """
    # 先剥 docstring 再剥 # 注释。PS1/YAML 不是 Python，ast.parse 会抛
    # SyntaxError，`_strip_docstrings` 原样返回 —— 无需分派。
    body = _strip_comments(_strip_docstrings(text))
    if not body.strip():
        return None
    pats = _selftest_pat(kind)

    stmts = _statements(body)
    for idx, st in enumerate(stmts):
        if tool not in st:
            continue
        if any(p in st for p in pats):
            return idx, st
        m = _RE_ASSIGN.match(st)
        if not m:
            continue
        var = m.group(1)
        for nxt in stmts[idx + 1:idx + 1 + INDIRECT_STMTS]:
            if var in nxt and any(p in nxt for p in pats):
                return idx, nxt
    return None


def executors(tools, sources):
    """返回 {tool: [出处, ...]}。sources = {rel: text}（已含 HARNESS 与 py 文件）。"""
    hits = {}
    # 第一轮: 直达（任何文件带参数引用某工具）
    for rel, text in sorted(sources.items()):
        base = os.path.basename(rel)
        for tool, kind in tools.items():
            if base == tool:
                continue                        # 自指不算执行者
            det = _cover_in_text(text, tool, kind)
            if det is not None:
                hits.setdefault(tool, []).append((rel, det[1]))
    # 第二轮: 从 HARNESS 出发的**可达链**（判据②）
    reach = set()
    queue = [h for h in HARNESS if h in sources]
    while queue:
        cur = queue.pop()
        if cur in reach:
            continue
        reach.add(cur)
        text = sources[cur]
        for m in _RE_PYNAME.finditer(_strip_comments(_strip_docstrings(text))):
            for rel in sources:
                if os.path.basename(rel) == m.group(1) and rel not in reach:
                    queue.append(rel)
    covered = {}
    for tool, srcs in hits.items():
        # srcs 的元素是 (出处, 带旗标语句)；可达链只看出处。
        r = [(s, st) for s, st in srcs if s in reach]
        if r:
            covered[tool] = r
    return covered, reach


def load_sources():
    """读 HARNESS + SCAN_DIRS 下的 .py（工具目录缺失 -> None = SKIP）。"""
    sources = {}
    for h in HARNESS:
        p = os.path.join(REPO, h)
        if os.path.isfile(p):
            sources[h] = _read(p)
    for d in SCAN_DIRS:
        dd = os.path.join(REPO, d)
        if not os.path.isdir(dd):
            return None
        for f in sorted(os.listdir(dd)):
            if f.endswith('.py'):
                sources['%s/%s' % (d, f)] = _read(os.path.join(dd, f))
    if not any(h in sources for h in HARNESS):
        return None
    return sources


_RE_LONGFLAG = re.compile(r'(?<![\w-])(--[A-Za-z][\w-]*)')


def argparse_options(tool, td, sources):
    """AST 读出工具登记的**长旗标**集合。返回 `(flags, subs)` 或 `None`（判不了）。

    `None` 表示"无法判定"（源码既不在 sources 里、盘上也没有，或不是合法
    Python）—— 调用方必须**跳过**，不得读成"没问题"、也不得读成"有问题"。
    """
    text = None
    for rel, tx in sources.items():
        if os.path.basename(rel) == tool:
            text = tx
            break
    if text is None:
        p = os.path.join(td, tool)
        if not os.path.isfile(p):
            return None
        text = _read(p)
    try:
        tree = ast.parse(text.lstrip('\ufeff'))
    except (SyntaxError, ValueError):
        return None
    opts, subs = set(), set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        nm = getattr(node.func, 'attr', None)
        if nm not in ('add_argument', 'add_parser'):
            continue
        for a in node.args:
            if not (isinstance(a, ast.Constant) and isinstance(a.value, str)):
                continue
            if a.value.startswith('--'):
                opts.add(a.value)
            elif nm == 'add_parser':
                subs.add(a.value)
    return opts, subs


def _invocation_segment(text, start):
    """从 `start`（工具名首次出现处）截到**命令边界**。

    边界 = `;` / `|` / 物理换行（行尾反引号表示续行，不算断句）。

    ## 为什么不能直接用整条语句（实测，2026-10-09）
    `_statements()` 按括号深度断句，而 PowerShell 格式串 `("{0}" -f $x)`
    里的 `{0}` 会让深度**永久抬高**（`{` 未配对）⇒ `release_check.ps1`
    整个文件被并成**一条语句** ⇒ 判据④在这条巨型语句里扫到
    `--all-compositions`（modcheck 的）与 `--install`（wsl 的），
    **全算到 `android_compile_check.py` 头上** —— 三条彻头彻尾的假阳性。
    ⇒ 旗标归属必须**按调用**取。
    """
    i, n = start, len(text)
    while i < n:
        c = text[i]
        if c in ';|':
            break
        if c == '\n':
            j = i - 1
            while j >= start and text[j] in ' \t':
                j -= 1
            if j >= start and text[j] == '`':
                i += 1
                continue
            break
        i += 1
    return text[start:i]


def flag_errors(tools, covered, sources, td):
    """判据④：覆盖语句里出现的每个长旗标，都必须被该工具登记过。

    2026-10-09 实测出处: 门禁第 41 项首跑 `identity.py: error: unrecognized
    arguments: --quiet` —— 我给 6 个孤儿统一加了 `--quiet`，只有 2 个登记过。
    「有没有执行者」判住了，「执行得对不对」没人判。
    """
    errs = []
    for tool in sorted(covered):
        opts = argparse_options(tool, td, sources)
        if opts is None:
            continue                        # 判不了 -> 跳过（见 docstring）
        known, _subs = opts
        for rel, st in covered[tool]:
            # 只取**该调用本身**那一段（见 _invocation_segment 的实测教训）。
            for pos in [m.start() for m in re.finditer(re.escape(tool), st)]:
                seg = _invocation_segment(st, pos)
                for f in sorted(set(_RE_LONGFLAG.findall(seg))):
                    if f not in known:
                        errs.append('%s 以 %s 调用 tools/%s，但它没有登记这个参数 '
                                    '(已登记: %s)'
                                    % (rel, f, tool,
                                       ' '.join(sorted(known)) or '无'))
    return errs


def audit(sources, tool_dir=None):
    """返回 (orphans, tools, reach)。orphans = [(tool, kind), ...]。"""
    tool_dir = tool_dir or os.path.join(REPO, 'tools')
    tools = {}
    for f in sorted(os.listdir(tool_dir)):
        if not f.endswith('.py'):
            continue
        k = declares_selftest(os.path.join(tool_dir, f))
        if k:
            tools[f] = k
    covered, reach = executors(tools, sources)
    orphans = [(t, k) for t, k in sorted(tools.items()) if t not in covered]
    return orphans, tools, reach


def verify(sources, tool_dir=None):
    """返回 [(判据名, ok, 详情), ...]。"""
    checks = []
    orphans, tools, reach = audit(sources, tool_dir)
    checks.append(('① 登记了自检的工具数 > 0（失锚守卫）', bool(tools),
                   '%d 个工具登记了自检' % len(tools)
                   if tools else '一个都没登记 -> 探测失效（失锚不得读成"没有孤儿"）'))
    root = [h for h in HARNESS if h in sources]
    checks.append(('② 入口清单可达（失锚守卫）', bool(root),
                   '入口 %d 个，可达文件 %d 个' % (len(root), len(reach))
                   if root else '一个入口都没读到 -> 判据②空转'))
    if not tools or not root:
        return checks
    checks.append(('③ 无孤儿：每个登记了自检的工具都有执行者', not orphans,
                   '孤儿 %d 个: %s' % (len(orphans),
                                       ', '.join('%s(%s)' % t for t in orphans[:6]))
                   if orphans else
                   '%d 个工具全部可从入口以自检参数到达' % len(tools)))
    # ④ 「有执行者」不等于「调用参数正确」（2026-10-09 实测补齐）
    td = tool_dir or os.path.join(REPO, 'tools')
    cov, _r2 = executors(tools, sources)
    ferr = flag_errors(tools, cov, sources, td)
    checks.append(('④ 执行者传入的旗标都已登记', not ferr,
                   '; '.join(ferr[:3]) if ferr else
                   '%d 个执行者的调用旗标全部已登记' % len(cov)))
    return checks


# --------------------------------------------------------------------------
# 合成用例（自检用，不碰仓库文件）
_F_HDR = "import argparse\nap = argparse.ArgumentParser()\n"


def _t_decl(flag=True):
    return _F_HDR + ("ap.add_argument('--selftest', action='store_true')\n"
                     if flag else "")


def _mk_cases():
    """返回 [(name, sources, want_orphans), ...]（want 为**孤儿个数**）。"""
    cases = []

    # M1 登记了但无人调用 -> 1 个孤儿
    cases.append(('M1 登记自检、无人调用 -> 必须报孤儿',
                  {'tools/a.py': _t_decl(),
                   'tools/release_check.ps1': '& $py tools\\b.py --selftest\n',
                   'tools/b.py': _t_decl(),
                   'tools/c.py': _F_HDR},
                  1))
    # M2 只在注释里被提到 -> 1 个孤儿（判据④）
    cases.append(('M2 只在注释里被提到 -> 必须报孤儿',
                  {'tools/a.py': _t_decl(),
                   'tools/release_check.ps1':
                       '# & $py tools\\a.py --selftest  (示例)\n'
                       '& $py tools\\b.py --selftest\n',
                   'tools/b.py': _t_decl()},
                  1))
    # M3 入口调用但不带自检参数 -> 1 个孤儿（判据③）
    cases.append(('M3 被调用但不带自检参数 -> 必须报孤儿',
                  {'tools/a.py': _t_decl(),
                   'tools/release_check.ps1':
                       '& $py tools\\a.py --quiet\n& $py tools\\b.py --selftest\n',
                   'tools/b.py': _t_decl()},
                  1))
    # M4 入口带自检参数调用 -> 0
    cases.append(('M4 入口带自检参数调用 -> 不得报',
                  {'tools/a.py': _t_decl(),
                   'tools/release_check.ps1': '& $py tools\\a.py --selftest\n'},
                  0))
    # M5 传递可达 -> 0（判据②）
    cases.append(('M5 传递可达（入口->A->C 均带自检）-> 不得报',
                  {'tools/release_check.ps1': '& $py tools\\a.py --selftest\n',
                   'tools/a.py': _t_decl() + (
                       "import subprocess\n"
                       "subprocess.run(['tools/c.py', '--selftest'])\n"),
                   'tools/c.py': _t_decl()},
                  0))
    # M6 传递但中间那跳不带自检参数 -> C 是孤儿
    cases.append(('M6 传递但中间一跳不带自检参数 -> 必须报孤儿',
                  {'tools/release_check.ps1': '& $py tools\\a.py --selftest\n',
                   'tools/a.py': _t_decl(),
                   'tools/c.py': _t_decl(),
                   'tools/d.py': _t_decl() + (
                       "import subprocess\n"
                       "subprocess.run(['tools/c.py', '--quiet'])\n")
                   },
                  2))
    # M7 子命令形态 -> 0
    cases.append(('M7 子命令形态（X.py selftest）-> 不得报',
                  {'tools/a.py': _F_HDR + "sub.add_parser('selftest')\n",
                   'tools/release_check.ps1': '& $py tools\\a.py selftest\n'},
                  0))
    # M8 只在 docstring 里被提到 -> 必须报孤儿（判据④的 docstring 面）
    #   ⚠️ docstring 必须放进**可达的 Python 入口**（tools/entry.py）。
    #      首版把它放进 release_check.ps1（PowerShell）—— `ast.parse` 抛
    #      SyntaxError ⇒ `_strip_docstrings` 原样返回 ⇒ 根本没剥 ⇒ 用例
    #      自己报「孤儿 0（期望 1）」，**看起来像判据没有判别力**。
    #      这是「探针的错伪装成被测对象的性质」的第 21 次。
    _entry_doc = (
        '"""entry — 说明: 本工具要与 tools/c.py 一起跑 --selftest。"""\n'
        'import argparse\n'
        "ap = argparse.ArgumentParser()\n"
        "ap.add_argument('--selftest', action='store_true')\n")
    cases.append(('M8 只在 docstring 里被提到 -> 必须报孤儿',
                  {'tools/release_check.ps1': '& $py tools\\entry.py --selftest\n',
                   'tools/entry.py': _entry_doc,
                   'tools/c.py': _t_decl()},
                  1))
    return cases


def _mk_flag_cases():
    """判据④ 的合成用例: [(name, sources, want_errs), ...]。

    这里 `want` 是**旗标错误条数**，与 `_mk_cases` 的孤儿数不同 ——
    两族用例分开跑，避免把一个的数当另一个的期望。
    """
    cases = []
    # F1 入口传了工具没登记的 --quiet -> 1 条
    cases.append(('F1 传入未登记的旗标 -> 必须报',
                  {'tools/a.py': _t_decl() +
                      "ap.add_argument('--verbose', action='store_true')\n",
                   'tools/release_check.ps1':
                       '& $py tools\\a.py --selftest --quiet\n'},
                  1))
    # F2 只传已登记的 -> 0
    cases.append(('F2 只传已登记的旗标 -> 不得报',
                  {'tools/a.py': _t_decl(),
                   'tools/release_check.ps1':
                       '& $py tools\\a.py --selftest\n'},
                  0))
    # F3 工具登记了 --quiet 再传 -> 0（防"一律报"）
    cases.append(('F3 工具登记过 --quiet 后再传 -> 不得报',
                  {'tools/a.py': _t_decl() +
                      "ap.add_argument('--quiet', action='store_true')\n",
                   'tools/release_check.ps1':
                       '& $py tools\\a.py --selftest --quiet\n'},
                  0))
    # F4 别的工具的旗标不得算到本工具头上（这正是真实仓库的首跑假阳性）
    cases.append(('F4 同一语句里别的工具的旗标 -> 不得算到本工具',
                  {'tools/a.py': _t_decl(),
                   'tools/b.py': _t_decl() +
                       "ap.add_argument('--all-compositions', action='store_true')\n",
                   'tools/release_check.ps1':
                       '& $py tools\\a.py --selftest; & $py tools\\b.py '
                       '--all-compositions\n'},
                  0))
    # F5 工具源码不可解析 -> 跳过、不得报（防"判不了读成有问题"）
    cases.append(('F5 工具源码不可解析 -> 必须跳过、不得报',
                  {'tools/a.py': _t_decl(),
                   'tools/z.py': 'this is ( not python\n',
                   'tools/release_check.ps1':
                       '& $py tools\\z.py --selftest --quiet\n'},
                  0))
    return cases


def _flag_errors_from_sources(sources):
    """合成源的判据④: 工具面 = sources 里的 tools/*.py。"""
    tools = {}
    for rel, text in sources.items():
        if not rel.startswith('tools/') or not rel.endswith('.py'):
            continue
        base = os.path.basename(rel)
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and getattr(node.func, 'attr', None) == 'add_argument'
                    and any(isinstance(a, ast.Constant)
                            and a.value == '--selftest' for a in node.args)):
                tools[base] = '--selftest'
    covered, _reach = executors(tools, sources)
    return flag_errors(tools, covered, sources, None)


def selftest():
    """负向自检: 对合成文本做变异，逐条必须被抓。"""
    cases = _mk_cases()
    bad, caught = [], 0
    for name, sources, want in cases:
        # tool_dir 不存在 -> audit 走 sources 里的 tools/ 文件名
        try:
            got_orphans, tools, _reach = _audit_from_sources(sources, want)
        except Exception as e:                      # noqa: BLE001
            got_orphans, tools = -1, {}
            print('  [XX] %s -> 探针异常: %r' % (name, e))
            bad.append(name)
            continue
        ok = (got_orphans == want)
        if ok:
            caught += 1
        else:
            bad.append(name)
        print('  [%s] %s -> 孤儿 %s（期望 %s, 工具 %d 个）'
              % ('ok' if ok else 'XX', name,
                 got_orphans if got_orphans >= 0 else 'ERR', want, len(tools)))

    fcases = _mk_flag_cases()
    for name, sources, want in fcases:
        try:
            errs = _flag_errors_from_sources(sources)
        except Exception as e:                      # noqa: BLE001
            errs = ['探针异常: %r' % e]
        ok = (len(errs) == want)
        if ok:
            caught += 1
        else:
            bad.append(name)
        print('  [%s] %s -> 旗标错误 %d 条（期望 %d）%s'
              % ('ok' if ok else 'XX', name, len(errs), want,
                 ('' if ok else ' :: ' + '; '.join(errs[:2]))))

    total = len(cases) + len(fcases)
    print('[selftest-audit-selftest] %d/%d 变异被抓' % (caught, total))
    return 0 if caught == total else 1


def _audit_from_sources(sources, _want):
    """合成源的 audit：工具面 = sources 里的 tools/*.py。"""
    tools = {}
    for rel, text in sources.items():
        if not rel.startswith('tools/') or not rel.endswith('.py'):
            continue
        base = os.path.basename(rel)
        tmp = os.path.join(REPO, '_synth_%s' % base)
        # 不写盘：直接用 AST 判定内存文本
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        flag = sub = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, 'attr', None)
            for a in node.args:
                if not isinstance(a, ast.Constant):
                    continue
                if name == 'add_argument' and a.value == '--selftest':
                    flag = True
                if name == 'add_parser' and a.value == SUB_SELFTEST:
                    sub = True
        if flag:
            tools[base] = '--selftest'
        elif sub:
            tools[base] = SUB_SELFTEST
    covered, _reach = executors(tools, sources)
    orphans = [(t, k) for t, k in sorted(tools.items()) if t not in covered]
    return len(orphans), tools, _reach


def main(argv=None):
    ap = argparse.ArgumentParser(description='自检执行者对账（登记了自检的工具必须真的有执行者）')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--list', action='store_true', help='列出全部工具与执行者')
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    sources = load_sources()
    if sources is None:
        print('[selftest-audit] SKIP: 缺少入口或工具目录')
        return 2

    checks = verify(sources)
    failed = [c for c in checks if not c[1]]
    if args.list:
        orphans, tools, _reach = audit(sources)
        covered, _r = executors(tools, sources)
        for t in sorted(tools):
            print('  %-26s %-12s %s' % (t, tools[t],
                                        ', '.join(r for r, _st in covered.get(t, []))
                                        or '**无执行者**'))
    if not args.quiet:
        for name, ok, detail in checks:
            print('  [%s] %s  (%s)' % ('ok' if ok else 'XX', name, detail))
    if failed:
        print('[selftest-audit] FAIL: %d/%d 条判据未通过' % (len(failed), len(checks)))
        orphans, _t, _r = audit(sources)
        for t, k in orphans:
            print('  [XX] 孤儿: tools/%s 登记了 %s 但没有任何入口（含可达链）以自检参数调用它'
                  % (t, k))
        return 1
    if not args.quiet:
        print('[selftest-audit] PASS: %d 条判据全通过' % len(checks))
    return 0


if __name__ == '__main__':
    sys.exit(main())
