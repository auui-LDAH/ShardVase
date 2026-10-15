#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
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
  ⑤ 自检函数体里必须**存在能产生 FAIL 的结构**（`if` / `assert` /
     `fail|err|bad` 上的 `.append|.extend|.add`）—— 「被执行」不等于「会失败」。
     2026-10-11 实测：`tools/replica_check.py::selftest` /
     `tools/prot_dbg.py::selftest` 与 `selftest_live` 的**整段函数体被掏空后**，
     `--selftest` 仍然 **rc=0**，有的连一行输出都没有 ⇒ 门禁逐项全绿。
     ④ 判住了"调用得对不对"，⑤ 才判"跑起来会不会红"。
  ⑥ 有用例批次的工具，必须为批次**声明一个下限**（名字含 `FLOOR`/`MIN_`）
     并把它**用在比较里** —— 「会失败」不等于「跑够了」。
     2026-10-12 实测：`tools/gate_results.py` 的收尾统计是
     `npass == len(cases)`、`tools/vm_debug.py` 是 `failed = [c for c in cases]`，
     **把 `cases` 清空**后二者分别打印 `PASS: 0 条（含 0 条负向）` 与
     `PASS: 0 条 (含 0 条负向)` 并 **rc=0** —— 门禁全绿。
     ⑤ 看不见这种掏空（函数体里的 `if` 一个都没少），必须靠下限。
     出处与实测三例见 §2.75；`tools/studio_proto_check.py` 的 `_BATCH_FLOORS`
     与 `tools/doccheck.py` 的 `_TOTAL_FLOOR` 是已有的两个正面例子。
     **配对是「同一函数」级的**（`_floor_paired`）：下限名必须与该批次的
     `len(...)` 出现在**同一个函数体**里。首版是**文件级**的
     （「文件里有任一下限被比较」），2026-10-12 被反例打掉 ——
     `tools/selfcrypt_residency_check.py` 的 `MIN_SAMPLES = 10`（判据③ 的
     采样轮数下限，在 `judge()` 里被比较）满足了它，于是删掉 `_MUT_FLOOR`
     声明**或**删掉守卫行，判据都仍然 PASS（`build/_mutc6.py` A/B 双 rc=0）。
     一般化：**「文件里有任一下限被比较」不等于「这个批次的下限被比较」**。
     同一条 `Compare` 级的配对则太严：三张 `mutations` 表的守卫是
     `if total < _MUT_FLOOR`，而 `total = len(mutations)` 是**另一条语句**。
  ⑦ 锚点消失即 FAIL —— **失锚不得读成"没有孤儿"**（§2.45 / §2.46 同纪律）。

## 含负向自检

    `--selftest` 对**合成文本**做 27 条变异（不碰仓库文件），每条都必须被抓：
      M1 登记了自检、全库无人调用           -> 必须报孤儿
      M2 只在**注释**里被提到                -> 必须报孤儿（④）
      M3 入口调用它但**不带**自检参数        -> 必须报孤儿（③）
      M4 入口带自检参数调用                 -> 不得报
      M5 传递可达（A 带自检调 B，B 带自检调 C）-> 不得报
      M6 传递但中间那跳**不带**自检参数      -> 必须报孤儿
      M7 子命令形态（`X.py selftest`）       -> 不得报
      M8 只在 **docstring** 里被提到          -> 必须报孤儿
      F1-F5 判据④ 的旗标面（未登记旗标 / 已登记 / 同语句别的工具 / 不可解析）
      B1-B4 判据⑤ 的体面（有 if 不得报 / 掏空必报 / 只有 pass 必报 / 入口调别的函数必报）
      F1-F5 判据⑥ 的下限面（见下）

    判据⑥ 的十条（`_mk_floor_cases` + `_mk_mut_cases`，名字与判据④ 重号，按批次区分）：
      F1 有下限声明且用在比较里            -> 不得报
      F2 有批次但**没有任何**下限声明      -> 必须报（清空批次后 `0 == 0` 仍绿）
      F3 声明了下限却**没用在比较里**      -> 必须报
      F4 没有用例批次                      -> 不适用（不得报、也不计入）
      F5 批次工具数低于**扫描面下限**      -> 必须报
      F6 变异表形态但无下限声明            -> 必须报
      F7 变异表形态且有下限参与比较        -> 不得报
      F8 只在 `except` 里的临时表          -> 不得当成批次（清空即 `0 == 0` 的另一种形状）
      F9 同函数里另有的**扫描面名单**表    -> 不得当成批次（`doccheck.py::_must` 形态）
      F10 下限与批次**不在同一函数**       -> 必须报（文件级配对的假合格面，
                                              `selfcrypt_residency_check.py::MIN_SAMPLES` 形态）

## 用法

    python tools/selftest_audit.py [--quiet] [--selftest] [--list]

退出码: 0 = 无孤儿; 1 = 存在孤儿 / 有自检体不可能失败 / 批次没有下限;
        2 = SKIP（工具目录缺失）

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
  ⑤ 判据⑤ 是**静态**判定：它只知道"体里存在能失败的结构"，不知道
     那些结构**真的会被触发**（可能 `if` 的条件恒假）。它也看不见
     「用例被删掉一半但函数体仍有 if」—— 那需要**下限守卫**
     （见 `tools/studio_proto_check.py` 的 `_BATCH_FLOORS` / §2.75）。
     两者互补：守卫防"少几条"，本判据防"整段空"。
  ⑥ 判据⑤ 只对**能解析的 Python 源码**生效。判不了（源码不可解析）
     一律**跳过**，不得读成"有问题"。
  ⑦ 判据⑥ 只看**源代码**：它判的是「批次有没有声明下限并拿它比较」，
     不判那个下限**数值合不合理**（`_ST_FLOOR = 1` 也能过本判据）。
     数值是否紧贴当前用例数，仍靠人读 —— 但 `_FLOOR_FILES_MIN` 这类
     **扫描面下限**能防住"文件被跳过"这一整类静默降级。
  ⑧ 判据⑥ 识别批次靠名字形态（`case|cases|checks|ck` 且被 append 等），
     改名（例如 `items`）会让它静默不适用。`_FLOOR_FILES_MIN` 是对这种
     静默的兜底：批次工具**总数**下降即报。
     `_mutation_batches` 认的是「非空 List 字面量 + `for` 遍历 + `len()` 参与
     比较」，也靠形态 —— 变异表改名（例如 `probes`）同样会静默不适用；
     收窄后的第三条（比较里必须含**该候选者**或其 `len()` 派生名）能排除
     `doccheck.py::_must` / `vm_debug.py::VASM`，但**不保证**排除所有
     「长得像批次但不是批次」的表。
  ⑨ 判据⑥ 的配对是**同一函数**级的（`_floor_paired`），所以
     「下限在该函数里被比较」不等价于「那条比较判的就是这个批次的长度」：
     `tools/vm_debug.py` 的 `VASM` 在 `selftest()` 里被 `ncov == len(VASM)`
     比较，而它真正的下限其实是同函数的 `_ST_FLOOR`。本判据判的是
     「**有一个与该批次同函数的长度下限存在**」，不是「那个数字是为它写的」。
     数值合理性、以及「下限是否真的在守这个批次」仍需人读（见 ⑦）。
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


# --------------------------------------------------------------------------
# 判据⑤: 自检函数体里必须**存在能产生 FAIL 的结构**（2026-10-11）
#
# 取向**宁可误报**：判成"能失败"只会少报一个问题；判成"不能失败"才会让
# 被掏空的批次静默变绿 —— 而后者正是本判据要防的唯一后果。
_FAIL_CALLS = ('append', 'extend', 'add')
_FAIL_WORDS = ('fail', 'err', 'bad', 'problem', 'missing', 'miss', 'warn')


def _mentions_selftest(test):
    """`if` 的条件里是否提到自检（`args.selftest` / `'selftest'` / `selftest`）。"""
    for n in ast.walk(test):
        if isinstance(n, ast.Attribute) and n.attr == 'selftest':
            return True
        if isinstance(n, ast.Name) and 'selftest' in n.id:
            return True
        if (isinstance(n, ast.Constant) and isinstance(n.value, str)
                and n.value == SUB_SELFTEST):
            return True
    return False


def _entry_fns(tree):
    """取自检分支里**被调用的顶层函数名**。返回 `(names, how)`。

    为什么不是"所有名字里带 selftest 的函数"：那会把 `_selftest_pat()`
    这类**纯辅助函数**也当成用例批，一个没有 `if` 的辅助函数会误报。
    判据⑤ 要问的是"**入口跑的那批**会不会失败"，所以先找到入口分支。

    `how` 取值：
      `main-branch`  —— 从 `main()` 里提到自检的 `if` 分支内取到调用（首选）
      `no-branch`    —— 有 `main()` 但找不到自检分支（子命令形态）⇒ 调用方回退
      `no-main`      —— 连 `main()` 都没有 ⇒ 调用方回退
    """
    main = None
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and n.name in ('main', '_main'):
            main = n
            break
    if main is None:
        return set(), 'no-main'
    names, found = set(), False
    for n in ast.walk(main):
        if not isinstance(n, ast.If) or not _mentions_selftest(n.test):
            continue
        found = True
        for c in ast.walk(n):
            if isinstance(c, ast.Call):
                nm = getattr(c.func, 'id', None)
                if nm:
                    names.add(nm)
    if not found:
        return set(), 'no-branch'
    return names, 'main-branch'


def _fallback_fns(tree):
    """回退面：顶层 `*selftest*` 函数名（仅当 `_entry_fns` 拿不到分支时用）。"""
    return set(n.name for n in tree.body
               if isinstance(n, ast.FunctionDef) and 'selftest' in n.name)


def _can_fail(fn):
    """函数体（含嵌套）里是否存在**能产生 FAIL** 的结构。返回 `(bool, why)`。

    三种结构：
      ① `assert`
      ② `if`         —— 最常见形态是 `if bad: fails.append(...)`
      ③ 名字含 fail/err/bad/... 的列表上的 `.append/.extend/.add`

    ## 为什么 `if` 就算（实测出处）
    全库 43 个自检函数**全部**至少有 `if` 或 `assert`；反过来，被掏空成
    `return 0` 的函数**一个都没有**。⇒ 这条判据在对当前仓库**零误报**，
    而它能抓住「整段函数体被掏空」这一种真实故障（§2.75 实测三例）。
    """
    for n in ast.walk(fn):
        if isinstance(n, ast.Assert):
            return True, 'assert'
    for n in ast.walk(fn):
        if isinstance(n, ast.If):
            return True, 'if'
    for n in ast.walk(fn):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            if n.func.attr in _FAIL_CALLS:
                try:
                    tgt = ast.unparse(n.func.value).lower()
                except Exception:                       # noqa: BLE001
                    tgt = ''
                if any(w in tgt for w in _FAIL_WORDS):
                    return True, '.%s on %s' % (n.func.attr, tgt[:40])
    return False, ''


def body_check(tools, sources, tool_dir=None):
    """判据⑤: 返回 `(problems, checked)`。

    `tools` = `{basename: kind}`（来自 `audit()` 或合成源）。
    `problems` = `[(tool, fn, why), ...]` —— 自检批的体里**找不到**能失败的结构。
    `checked` = 实际检查过的函数个数（**失锚守卫**用）。

    判不了的（源码不可解析 / 拿不到函数体）一律**跳过**，不猜（边界⑥）。
    """
    problems, checked = [], 0
    for f in sorted(tools):
        text = None
        for rel, tx in sources.items():
            if os.path.basename(rel) == f:
                text = tx
                break
        if text is None:
            if not tool_dir:
                continue
            p = os.path.join(tool_dir, f)
            if not os.path.isfile(p):
                continue
            text = _read(p)
        try:
            tree = ast.parse(text.lstrip('\ufeff'))
        except (SyntaxError, ValueError):
            continue                                # 判不了 -> 跳过（边界⑥）
        defs = dict((n.name, n) for n in tree.body
                    if isinstance(n, ast.FunctionDef))
        names, how = _entry_fns(tree)
        if how != 'main-branch':
            names = _fallback_fns(tree)
            how = how + '+fallback'
        hit = [nm for nm in sorted(names) if nm in defs]
        if not hit:
            continue                                # 拿不到函数体 -> 跳过，不猜
        for nm in hit:
            checked += 1
            ok, _why = _can_fail(defs[nm])
            if not ok:
                problems.append((f, nm, how))
    return problems, checked


# --------------------------------------------------------------------------
# 判据⑥：用例批次必须有**声明过的下限**并被用在比较里。
#
# 「跑了」「会失败」「跑够了」是三件事：判据③ 答第一问，⑤ 答第二问，
# ⑥ 答第三问。实测（§2.75）：`tools/gate_results.py` 与 `tools/vm_debug.py`
# 的收尾统计是 `npass == len(cases)` / `failed = [c for c in cases ...]`
# —— 都是**长度或筛选**，于是把批次清空得到 `0 == 0` / 空列表，
# 打印 `PASS: 0 条（含 0 条负向）` 并 **rc=0**，门禁全绿。
_BATCH_RE = re.compile(r'(case|cases|checks|ck)$', re.I)
_FLOOR_RE = re.compile(r'FLOOR|_MIN|MIN_')
# 仓库里**有用例批次**的工具数下限。紧贴当前值（7 个），不留余量：
#   留余量的守卫对「一个批次文件被改坏/被跳过」失明 —— 2026-10-12 实测，
#   把 `tools/gate_results.py` 的守卫行删掉会顺带弄出 IndentationError，
#   该文件于是被 `floor_check` 跳过，`checked` 从 4 静默降到 3 而判据仍然 PASS。
#   ⚠️ 新增一个有用例批次的工具时，必须同步上调此数字。
#   4 -> 7（2026-10-12，§2.76）：`_batch_vars` 之外补了 `_mutation_batches`，
#   于是 `check_crc_targets.py` / `selfcrypt_meta_check.py` /
#   `selfcrypt_residency_check.py` 三张 `mutations` 表也进入扫描面。
#   ⚠️ 收窄 `_mutation_batches` 的第三条之后（同一天），`doccheck.py::_must`
#   与 `vm_debug.py::VASM` 不再被算成批次，但**工具数仍是 7**（这两个文件
#   本来就已经因为 `cases` 计入）—— 所以这个数字不需要跟着改。
#   7 -> 10（2026-10-12，§2.77）：判据⑥ 又认了两种形态 —— **循环驱动表**
#   （`_loop_batches`：`modcheck.py` / `studio_server.py`）与**计数器型**
#   （`_counter_batches`：`studio_proto_check.py` / `studio_ui_check.py`）。
#   ⚠️ 这次**必须**跟着改：本数字的作用是「一个批次文件被改坏/被跳过时判据
#   自己会红」，而 `build/_mutc6.py` 的 B 注入正是靠那条通路
#   （删守卫行 → IndentationError → 该文件被 `continue` 跳过 → `checked` 掉 1）。
#   留在 7 时实测后果：`selfcrypt_meta_check.py` 的 B 注入 `checked` 从 10 掉到
#   9，仍 ≥ 7，**判据 rc=0 静默放过**（本轮真发生过，见 §2.77.7）。
_FLOOR_FILES_MIN = 10

# 本文件自检的用例总数下限（§2.49 形状：`total` 由长度导出，清空一批不会报错，
# 只会让数字变小）。紧贴当前值，不留余量 —— 留余量会让它对「掏空一批」失明。
#   22 -> 25（2026-10-12，§2.76）：判据⑥ 的变异表形态 F6/F7/F8。
#   25 -> 27（同日）：F9（同函数另有的名单表不得算批次）/ F10（下限与批次
#   不在同一函数必须报）—— 两条都是这次收窄口径后才成立的判别力。
#   27 -> 34（2026-10-12，§2.77）：F11-F17 七条 —— 循环驱动表（有/无下限、
#   名字不匹配的名单表）、计数器型（有/无下限、dict 键下限、同函数里
#   **不相干**的下限比较必须报）。F13 与 F17 分别钉住本轮新增的两条
#   收窄规则，F15/F16 钉住两条严格配对口径。
_ST_FLOOR = 34


def _batch_vars(tree, fns):
    """自检入口函数体里被 append/extend/add 的、名字像用例批次的 list。"""
    out = set()
    for n in ast.walk(tree):
        if not isinstance(n, ast.FunctionDef) or n.name not in fns:
            continue
        for x in ast.walk(n):
            if isinstance(x, ast.Call) and isinstance(x.func, ast.Attribute) \
                    and x.func.attr in _FAIL_CALLS:
                v = x.func.value
                if isinstance(v, ast.Name) and _BATCH_RE.search(v.id):
                    out.add(v.id)
    return out


def _mutation_batches(tree, fns):
    """自检入口里的**变异表**形态：清空它也会让自检静默变绿。

    形态（全部条件都要满足，且**只看入口函数体的直接语句**）：
      ① `N = [ <非空 List 字面量> ]` 是入口函数体的一条直接语句；
      ② 入口里有 `for ... in N:`（`ast.For`，**不含**推导式）；
      ③ `len(N)` 参与比较，或 `d = ... len(N) ...` 而 `d` 参与比较。

    ## 为什么要这条（2026-10-12 实测，§2.76）
    `_batch_vars` 只认名字以 `case|cases|checks|ck` 结尾的批次，于是
    `tools/check_crc_targets.py` / `tools/selfcrypt_meta_check.py` /
    `tools/selfcrypt_residency_check.py` 三张 `mutations` 表**游离在判据⑥
    之外**。实测把 `mutations` 清成 `[]`，三者仍然 rc=0，且报文与基线
    **逐字相同**（连 `PASS: 0 条` 都不打，比 `cases` 形态更隐蔽）。

    ## 为什么②要求 `ast.For` 且①要求**直接语句**
    只看 `ast.walk` 会收进 `except` 分支里的临时表
    （`except Exception as e: res = [('crash', False, repr(e))]`）——
    那种表被推导式遍历、名字也出现在比较里，却与「用例批次」无关。
    收窄后全库命中 3 个工具，**恰好**是实测同病的那三个。
    """
    hits = set()
    for n in ast.walk(tree):
        if not isinstance(n, ast.FunctionDef) or n.name not in fns:
            continue
        direct = set()
        for st in n.body:
            if isinstance(st, ast.Assign) and isinstance(st.value, ast.List) \
                    and st.value.elts:
                for t in st.targets:
                    if isinstance(t, ast.Name):
                        direct.add(t.id)
        if not direct:
            continue
        iterated = set()
        for x in ast.walk(n):
            if isinstance(x, ast.For) and isinstance(x.iter, ast.Name):
                iterated.add(x.iter.id)
        cand = direct & iterated
        if not cand:
            continue
        derived = {}
        for x in ast.walk(n):
            if isinstance(x, ast.Assign) and (_len_names(x.value) & cand):
                for t in x.targets:
                    if isinstance(t, ast.Name):
                        derived.setdefault(t.id, set()).update(
                            _len_names(x.value) & cand)
        comp = _compared_names(n)
        for nm in cand:
            if nm in comp:
                hits.add(nm)
                continue
            # ③ 派生名必须**能追回这个候选者**才算命中。首版写的是
            #    `nm in comp or (derived & comp)` —— 后半个条件与 `nm` 无关：
            #    只要函数里**任何**一个候选者有「len -> 变量 -> 比较」的通路，
            #    整个函数的所有候选者就都算命中。实测后果（2026-10-12）：
            #    `tools/doccheck.py:2100` 的**扫描面守卫名单** `_must` 与
            #    `tools/vm_debug.py:1328` 的**覆盖面名单** `VASM` 被当成用例
            #    批次 —— 它们靠的都是同一个函数里 `cases` 的那条通路。
            for d, srcs in derived.items():
                if nm in srcs and d in comp:
                    hits.add(nm)
                    break
    return hits


_VOTE_WORDS = ('fail', 'err', 'bad', 'problem', 'miss', 'warn')


def _loop_vote(node):
    """循环体里有没有**判定器**：`case(...)` 调用，或对失败累加器 append 等。"""
    for x in ast.walk(node):
        if not isinstance(x, ast.Call):
            continue
        nm = getattr(x.func, 'id', None) or getattr(x.func, 'attr', None)
        if nm == 'case':
            return True
        if isinstance(x.func, ast.Attribute) and x.func.attr in _FAIL_CALLS \
                and isinstance(x.func.value, ast.Name) \
                and any(w in x.func.value.id.lower() for w in _VOTE_WORDS):
            return True
    return False


def _direct_assigns(body):
    """函数体**直接语句**上的 `N = [ <非空 List 字面量> ]`，穿透一层 try/with。

    穿透是必须的：`tools/studio_server.py` 的 `_wcases` 定义在 `try:` 里
    （`finally` 里 `shutil.rmtree`）；只看 `fn.body` 会漏掉它。
    """
    out, stack = set(), list(body)
    while stack:
        st = stack.pop()
        if isinstance(st, ast.Assign) and isinstance(st.value, ast.List) \
                and st.value.elts:
            for t in st.targets:
                if isinstance(t, ast.Name):
                    out.add(t.id)
        if isinstance(st, (ast.Try, ast.With)):
            stack.extend(st.body)
            stack.extend(getattr(st, 'finalbody', []) or [])
            if isinstance(st, ast.Try):
                for h in st.handlers:
                    stack.extend(h.body)
    return out


def _loop_batches(tree, fns):
    """**循环驱动的用例表**：清空它，自检静默少跑几条而 rc 仍是 0。

    形态（四个条件全要）：
      ① `N = [ <非空 List 字面量> ]` 是入口函数体（穿透一层 try/with）的直接语句；
      ② 入口里有 `for ... in N:`；
      ③ **`N` 匹配既有的名字约定** `_BATCH_RE`（`case|cases|checks|ck$`）；
      ④ 循环体里有判定器（`case(...)` 或对失败累加器 append）。

    ## 为什么要③（2026-10-12 试算，§2.77）
    只有①②④时，`tools/doccheck.py:2100 _must`（**扫描面守卫名单**）、
    `tools/vm_debug.py:1328 VASM`（**覆盖面名单**）与 `vm_debug.py pairs`
    都会被收成「用例批次」—— 它们的循环体里也有失败 append。
    加③ 之后精确命中实测同病的那两个（`tools/modcheck.py::CASES`、
    `tools/studio_server.py::_wcases`）—— 两者的循环体**都调用 `case()`**，
    而 `_must`/`VASM` 不调。名字约定本就是本工具判据⑥ 的既有词汇，
    复用它而不是新造一条「表里装的是什么」的语义判断。
    """
    hits = set()
    for n in ast.walk(tree):
        if not isinstance(n, ast.FunctionDef) or n.name not in fns:
            continue
        lits = set(x for x in _direct_assigns(n.body) if _BATCH_RE.search(x))
        if not lits:
            continue
        for x in ast.walk(n):
            if isinstance(x, ast.For) and isinstance(x.iter, ast.Name) \
                    and x.iter.id in lits and _loop_vote(x):
                hits.add(x.iter.id)
    return hits


def _counter_batches(tree, fns):
    """**计数器型用例批次**：`N = 0` + `N += 1`，名字匹配 `_BATCH_RE`。

    清空这种批次的表现与清空列表**不同**：列表型会打出 `PASS: 0 项`（判据⑥
    注释里的 `cases` 形态），计数器型则是 `PASS: 0 项` 或**连项数都不打**，
    且 rc 恒 0（`tools/studio_ui_check.py` 实测：在 `def case(` 体首插
    `return` ⇒ `PASS: 0 项（含 0 项负向注入）` + **rc=0**）。

    `N += 1` 用的是 `ast.AugAssign(Add)`：它同时覆盖 `ncase += 1` 与
    `caught += 1`，但只有①③把范围收到「名字像用例批次的计数器」上。
    """
    hits = set()
    for n in ast.walk(tree):
        if not isinstance(n, ast.FunctionDef) or n.name not in fns:
            continue
        zeroed, bumped = set(), set()
        for x in ast.walk(n):
            if isinstance(x, ast.Assign) and isinstance(x.value, ast.Constant) \
                    and x.value.value == 0:
                for t in x.targets:
                    if isinstance(t, ast.Name):
                        zeroed.add(t.id)
            if isinstance(x, ast.AugAssign) and isinstance(x.op, ast.Add) \
                    and isinstance(x.target, ast.Name):
                bumped.add(x.target.id)
        for nm in zeroed & bumped:
            if _BATCH_RE.search(nm):
                hits.add(nm)
    return hits


def _count_names(tree, batch):
    """`batch` 的**计数转世名**：`total = len(batch)` / `total = ncase` 之类。

    计数器没有 `len()`，它的长度判定是 `total = ncase` 然后 `total < FLOOR`
    —— 所以「这个批次的下限被比较了吗」这条问句，对计数器必须追一层赋值。
    """
    seen = set([batch])
    changed = True
    while changed:
        changed = False
        for x in ast.walk(tree):
            if not isinstance(x, ast.Assign):
                continue
            srcs = _len_names(x.value)
            for s in ast.walk(x.value):
                if isinstance(s, ast.Name):
                    srcs.add(s.id)
            if not (srcs & seen):
                continue
            for t in x.targets:
                if isinstance(t, ast.Name) and t.id not in seen:
                    seen.add(t.id)
                    changed = True
    return seen


def _floor_paired_count(tree, batch, decl):
    """**严格**配对（计数器形态）：同一个函数里，某条 `Compare` 同时含
    「批次的计数转世名」与「下限名」—— 例如 `if total < _ST_FLOOR:`。

    与 `_floor_paired` 的区别：后者只要求「同函数里有 `len(<批次>)` **且**
    同函数里有下限参与某条比较」，两半可以互不相干。实测出处（§2.77）：
    `tools/vm_debug.py` 的 `VASM` 靠的就是这种不相干 —— `ncov == len(VASM)`
    与 `len(cases) < _ST_FLOOR` 是两条不同的语句，于是 `VASM` 被算成
    「有下限的批次」。这条严格口径**只加不改**：现有 7 个批次的判定一律
    仍走 `_floor_paired`，避免把 §2.76 已记名的语义差异重新判成红。
    """
    names = _count_names(tree, batch)
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Compare):
                continue
            have = set()
            for side in [n.left] + list(n.comparators):
                for sub in ast.walk(side):
                    if isinstance(sub, ast.Name):
                        have.add(sub.id)
                    if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) \
                            and sub.func.id == 'len' and len(sub.args) == 1 \
                            and isinstance(sub.args[0], ast.Name):
                        have.add(sub.args[0].id)
            if (have & names) and (have & decl):
                return True
    return False


def _floor_dict_keys(tree, decl):
    """下限名指向的 **dict 字面量**的字符串键。

    出典 `tools/studio_proto_check.py:74 _BATCH_FLOORS = {'解析器': 5, ...}`
    —— 下限按批次名分条存放，值就是每组的下限。
    """
    out = set()
    for n in ast.walk(tree):
        if not isinstance(n, ast.Assign):
            continue
        tgt = n.targets[0] if n.targets else None
        if not (isinstance(tgt, ast.Name) and tgt.id in decl):
            continue
        for x in ast.walk(n.value):
            if isinstance(x, ast.Dict):
                for k in x.keys:
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        out.add(k.value)
    return out


def _floor_paired_key(tree, batch, decl):
    """**字面量键**配对：`容器['键'] = <批次的计数转世名>`，而 `'键'` 正是某个
    下限 dict 里的键（`_BATCH_FLOORS`）。

    这条是实测逼出来的（§2.77）：`tools/studio_proto_check.py` 的下限判定
    写在**另一个函数** `_floors_ok()` 里（`n < floor`），批次函数本身只把
    自己报的条数塞进 `counts['命令集合']`。若没有这条，它会被判成
    「声明了下限但没有配对比较」—— 而它恰恰是全仓库下限纪律最严的工具之一。
    ⚠️ 这条规则**精确**：实测只有 `ncase` 命中；`tools/studio_ui_check.py`
    的 `ncase` 装的是一个**渲染下限**表 `MIN_TEXT_ELS = {'gen': 8, ...}`，
    键名与批次名毫无关系 ⇒ 正确地不命中（它就是真的缺下限，见 §2.77）。
    """
    keys = _floor_dict_keys(tree, decl)
    if not keys:
        return False
    for x in ast.walk(tree):
        if not isinstance(x, ast.Assign):
            continue
        if not (isinstance(x.value, ast.Name) and x.value.id in _count_names(tree, batch)):
            continue
        for t in x.targets:
            if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) \
                    and isinstance(t.slice.value, str) and t.slice.value in keys:
                return True
    return False


def _len_names(node):
    """`node` 里所有 `len(X)` 的 `X`（只认裸名字）。"""
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) \
                and n.func.id == 'len' and len(n.args) == 1 \
                and isinstance(n.args[0], ast.Name):
            out.add(n.args[0].id)
    return out


def _compared_names(node):
    """出现在某个 `ast.Compare` 里的名字（含 `len(名字)` 的参数位）。"""
    out = set()
    for n in ast.walk(node):
        if not isinstance(n, ast.Compare):
            continue
        for side in [n.left] + list(n.comparators):
            for sub in ast.walk(side):
                if isinstance(sub, ast.Name):
                    out.add(sub.id)
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) \
                        and sub.func.id == 'len' and len(sub.args) == 1 \
                        and isinstance(sub.args[0], ast.Name):
                    out.add(sub.args[0].id)
    return out


def _floor_decls(tree):
    """**任意作用域**里被赋值的、名字含 FLOOR|_MIN 的变量。

    ⚠️ 必须扫全树而不是只看 `tree.body`：`tools/doccheck.py` 的
    `_TOTAL_FLOOR = 69` 写在 `selftest()` **函数体内**，只看模块级会漏判。
    """
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Assign, ast.AnnAssign)):
            tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
            for t in tgts:
                if isinstance(t, ast.Name) and _FLOOR_RE.search(t.id):
                    out.add(t.id)
    return out


def _floor_paired(tree, batch, decl):
    """与**这个批次**配对的下限名: 哪个函数里有 `len(batch)`，该函数里被比较的 `decl`。

    ## 为什么要按批次配对（2026-10-12 实测，§2.76）
    首版是文件级的: `decl = _floor_decls(tree)` 非空、且 `_floor_compared(tree, decl)`
    非空 —— **两半互不相干**。实测反例: `tools/selfcrypt_residency_check.py` 里
    有一个与批次无关的常量 `MIN_SAMPLES = 10`（`:109`，判据③ 的采样轮数下限），
    它既被 `_FLOOR_RE` 的 `MIN_` 命中，又确实出现在 `judge()` 的比较里
    （`:192 len(samples) >= MIN_SAMPLES`）⇒ **删掉 `_MUT_FLOOR` 声明、或删掉
    守卫行，判据都仍然 PASS**（`build/_mutc6.py` A/B 两注入 rc=0）。
    一般化: **「文件里有任一下限被比较」不等于「这个批次的下限被比较」**。

    ## 口径是「同一函数」而不是「同一条 `Compare`」（三轮试算的结论）
    同一条 `Compare` 太严: 三张 `mutations` 表的守卫是
    `if total < _MUT_FLOOR`，而 `total = len(mutations)` 是**另一条语句**
    ⇒ 会误杀 `tools/check_crc_targets.py` / `tools/selfcrypt_meta_check.py`
    / `tools/selfcrypt_residency_check.py` 三个**已经装好下限**的文件。
    文件级太松: 见上。⇒ 取中间态，并要求 `len(batch)` 是**直接**出现
    （不追派生名）—— 派生的理由见 `_mutation_batches` 的注释；`tools/vm_debug.py`
    的 `ncov == len(VASM)` 证明「有 `len()` 在比较里」并不蕴含「这是那个批次的下限」，
    所以这里必须严格: 下限与批次的**字面**长度判定同处一个函数。
    """
    out = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if batch not in _len_names(fn):
            continue
        for n in ast.walk(fn):
            if not isinstance(n, ast.Compare):
                continue
            for side in [n.left] + list(n.comparators):
                for sub in ast.walk(side):
                    if isinstance(sub, ast.Name) and sub.id in decl:
                        out.add(sub.id)
                    elif isinstance(sub, ast.Subscript) and \
                            isinstance(sub.value, ast.Name) and sub.value.id in decl:
                        out.add(sub.value.id)
    return out


def floor_check(tools, sources, tool_dir=None, min_files=None):
    """判据⑥: 返回 `(problems, checked)`。

    `problems` = `[(tool, batch, why), ...]`。
    `checked`  = 实际检查过的**有用例批次的工具**个数（失锚守卫用）；
                 没有批次的工具不计入 —— 判据对它们不适用。

    `min_files` 是**扫描面下限**：识别到的批次工具数少于它，本身就是一条
    problem。理由（2026-10-12 实测）：把一个批次文件的守卫行删掉会顺带弄出
    `IndentationError`，该文件于是被本函数 `continue` 跳过，`checked` 从 4
    静默降到 3、判据仍然 PASS —— **判据对自己的扫描面失明**。
    `min_files=None` 时用模块级 `_FLOOR_FILES_MIN`；合成用例传 1。
    """
    floor = _FLOOR_FILES_MIN if min_files is None else min_files
    problems, checked = [], 0
    for f in sorted(tools):
        text = None
        for rel, tx in sources.items():
            if os.path.basename(rel) == f:
                text = tx
                break
        if text is None:
            if not tool_dir:
                continue
            p = os.path.join(tool_dir, f)
            if not os.path.isfile(p):
                continue
            text = _read(p)
        try:
            tree = ast.parse(text.lstrip('\ufeff'))
        except (SyntaxError, ValueError):
            continue                                # 判不了 -> 跳过（边界⑥）
        names, _how = _entry_fns(tree)
        if not names:
            names = _fallback_fns(tree)
        bvars = _batch_vars(tree, names) | _mutation_batches(tree, names) \
            | _loop_batches(tree, names) | _counter_batches(tree, names)
        if not bvars:
            continue                                # 没有批次 -> 不适用
        checked += 1
        decl = _floor_decls(tree)
        if not decl:
            problems.append((f, ','.join(sorted(bvars)), '没有任何 FLOOR/_MIN 声明'))
            continue
        unpaired = []
        for b in sorted(bvars):
            if _floor_paired(tree, b, decl):
                continue
            # 计数器型（`total = ncase` 后比较）与「下限按批次名存进 dict」
            # 两种形态各有一条严格口径 —— 见两个函数的 docstring（§2.77）。
            if _floor_paired_count(tree, b, decl) or _floor_paired_key(tree, b, decl):
                continue
            unpaired.append(b)
        if unpaired:
            problems.append((f, ','.join(unpaired),
                             '声明了 %s 但没有与该批次配对的比较'
                             '（同一个函数里要有 `len(<批次>)` 且有下限参与比较）'
                             % ','.join(sorted(decl))))
    if checked < floor:
        problems.append(('扫描面', 'batch-files',
                         '只识别到 %d 个用例批次，低于下限 %d —— 有文件被改坏/'
                         '被跳过/批次被删（下限紧贴当前值：删批次须显式下调）'
                         % (checked, floor)))
    return problems, checked


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
    # ⑤ 「被执行」不等于「会失败」（2026-10-11 实测补齐）
    #
    #   出处: `tools/replica_check.py::selftest` / `tools/prot_dbg.py::selftest`
    #   与 `selftest_live` 的**整段函数体被掏空**后，`--selftest` 仍然 rc=0，
    #   有的连一行输出都没有。判据①-④ 全部只问"有没有人调用它"，
    #   没有一条问"它跑起来会不会红"。⇒ 补⑤。
    bprob, bchecked = body_check(tools, sources, td)
    if bchecked == 0:
        detail = ('一个自检函数体都没解析到 -> 判据⑤空转'
                  '（失锚不得读成"都能失败"）')
    elif bprob:
        detail = '; '.join('%s::%s(%s)' % p for p in bprob[:4])
    else:
        detail = '%d 个自检函数体里都有能产生 FAIL 的结构' % bchecked
    checks.append(('⑤ 自检函数体里存在能产生 FAIL 的结构', bchecked > 0 and not bprob,
                   detail))
    # ⑥ 「会失败」不等于「跑够了」（2026-10-12 实测补齐）
    #
    #   出处: `tools/gate_results.py` 与 `tools/vm_debug.py` 的收尾统计
    #   分别是 `npass == len(cases)` 与 `failed = [c for c in cases ...]`，
    #   把 `cases` 清空后打印 `PASS: 0 条（含 0 条负向）` 并 **rc=0**。
    #   ⑤ 看不见这种掏空（函数体里 `if` 还在）。⇒ 补⑥：批次必须有下限。
    fprob, fchecked = floor_check(tools, sources, td)
    if fchecked == 0:
        fdetail = ('一个用例批次都没识别到 -> 判据⑥空转'
                   '（失锚不得读成"都有下限"）')
    elif fprob:
        fdetail = '; '.join('%s(%s: %s)' % p for p in fprob[:4])
    else:
        fdetail = '%d 个用例批次都有声明过的下限, 且用在比较里' % fchecked
    checks.append(('⑥ 用例批次声明了下限并参与比较', fchecked > 0 and not fprob,
                   fdetail))
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


def _tools_from_sources(sources):
    """合成源的工具面: `{basename: kind}`（与 `_audit_from_sources` 同口径）。"""
    tools = {}
    for rel, text in sources.items():
        if not rel.startswith('tools/') or not rel.endswith('.py'):
            continue
        base = os.path.basename(rel)
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
    return tools


# 判据⑤ 的合成素材: `main()` 里提到自检、并调用一个批函数。
def _t_body_ok(name='selftest'):
    return _t_decl() + (
        "def %s():\n"
        "    bad = []\n"
        "    if 1:\n"
        "        bad.append('x')\n"
        "    return 0 if not bad else 1\n"
        "\n"
        "def main():\n"
        "    if args.selftest:\n"
        "        return %s()\n" % (name, name))


def _t_body_empty(name='selftest'):
    return _t_decl() + (
        "def %s():\n"
        "    return 0\n"
        "\n"
        "def main():\n"
        "    if args.selftest:\n"
        "        return %s()\n" % (name, name))


def _t_body_pass(name='selftest'):
    return _t_decl() + (
        "def %s():\n"
        "    pass\n"
        "\n"
        "def main():\n"
        "    if args.selftest:\n"
        "        return %s()\n" % (name, name))


def _mk_body_cases():
    """判据⑤ 的合成用例: [(name, sources, want_problems), ...]。"""
    cases = []
    # B1 体里有 if + 失败列表 -> 不得报
    cases.append(('B1 自检体里有 if/失败列表 -> 不得报',
                  {'tools/a.py': _t_body_ok(),
                   'tools/release_check.ps1': '& $py tools\\a.py --selftest\n'},
                  0))
    # B2 体被掏空成 return 0 -> 必须报（真实事故形态）
    cases.append(('B2 自检体被掏空成 `return 0` -> 必须报',
                  {'tools/a.py': _t_body_empty(),
                   'tools/release_check.ps1': '& $py tools\\a.py --selftest\n'},
                  1))
    # B3 体里只有 pass -> 必须报
    cases.append(('B3 自检体里只有 `pass` -> 必须报',
                  {'tools/a.py': _t_body_pass(),
                   'tools/release_check.ps1': '& $py tools\\a.py --selftest\n'},
                  1))
    # B4 有自检函数、但入口分支调用的是**别的**函数 -> 必须报
    #    （判据⑤ 判的是"入口跑的那批"，不是"任何叫 selftest 的函数"）
    cases.append(('B4 入口调用的不是那个函数 -> 必须报（判的是入口跑的那批）',
                  {'tools/a.py': _t_decl() + (
                      "def selftest():\n"
                      "    bad = []\n"
                      "    if 1:\n"
                      "        bad.append('x')\n"
                      "    return 0 if not bad else 1\n"
                      "\n"
                      "def realcase():\n"
                      "    return 0\n"
                      "\n"
                      "def main():\n"
                      "    if args.selftest:\n"
                      "        return realcase()\n"),
                   'tools/release_check.ps1': '& $py tools\\a.py --selftest\n'},
                  1))
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


def _t_loop_nofloor():
    """**循环驱动表**（名字匹配 `_BATCH_RE`、循环体调 `case()`）但无下限 -> 必须报。

    真实形态 `tools/modcheck.py::CASES` 与 `tools/studio_server.py::_wcases`：
    清空它们后 rc 仍是 0，`modcheck` 连报文都一字不变，
    `studio_server` 只静默从 `PASS: 28 项` 缩水成 `PASS: 22 项`。
    """
    return _t_decl() + (
        "def selftest():\n"
        "    CASES = [('R10', 'x'), ('R11', 'y')]\n"
        "    for rule, needle in CASES:\n"
        "        case(rule, True)\n"
        "    return 0\n"
        "\n"
        "def main():\n"
        "    if args.selftest:\n"
        "        return selftest()\n")


def _t_loop_floor():
    """循环驱动表 + 下限参与比较 -> 不得报（F11 的反面，防「一律报」）。"""
    return _t_decl() + (
        "_ST_FLOOR = 2\n"
        "\n"
        "def selftest():\n"
        "    CASES = [('R10', 'x'), ('R11', 'y')]\n"
        "    for rule, needle in CASES:\n"
        "        case(rule, True)\n"
        "    total = len(CASES)\n"
        "    if total < _ST_FLOOR:\n"
        "        return 1\n"
        "    return 0\n"
        "\n"
        "def main():\n"
        "    if args.selftest:\n"
        "        return selftest()\n")


def _t_loop_namemismatch():
    """★ **名字不匹配 `_BATCH_RE`** 的名单表 -> **不得**当成用例批次。

    真实形态 `tools/doccheck.py:2100` 的 `_must`（扫描面守卫名单）与
    `tools/vm_debug.py:1328` 的 `VASM`（覆盖面名单）：它们也「被 `for` 遍历」
    且循环体里向失败累加器 append，但**不是用例批次**。
    若没有名字约定这一条，本判据会把它们要求一个 FLOOR —— 假阳性。

    ⚠️ 期望 `checked == 0`：本 fixture 里一个批次都不该被认出来。
    """
    return _t_decl() + (
        "def selftest():\n"
        "    fails = []\n"
        "    _must = ['README.md', 'CONTRIBUTING.md']\n"
        "    for _m in _must:\n"
        "        if not _m:\n"
        "            fails.append('扫描面守卫: %s' % _m)\n"
        "    return 0 if not fails else 1\n"
        "\n"
        "def main():\n"
        "    if args.selftest:\n"
        "        return selftest()\n")


def _t_count_nofloor():
    """**计数器型**批次（`ncase = 0` + `ncase += 1`）无下限 -> 必须报。

    真实形态 `tools/studio_ui_check.py::ncase`：在 `def case(` 体首插
    `return` ⇒ 打印 `PASS: 0 项（含 0 项负向注入）` 而 **rc 仍是 0**
    —— 比列表型更隐蔽，它连「少了几条」都不显示。
    """
    return _t_decl() + (
        "def selftest():\n"
        "    fails = []\n"
        "    ncase = 0\n"
        "\n"
        "    def case(name, ok):\n"
        "        nonlocal ncase\n"
        "        ncase += 1\n"
        "        if not ok:\n"
        "            fails.append(name)\n"
        "\n"
        "    case('a', True)\n"
        "    case('b', True)\n"
        "    total = ncase\n"
        "    return 0 if not fails else 1\n"
        "\n"
        "def main():\n"
        "    if args.selftest:\n"
        "        return selftest()\n")


def _t_count_floor():
    """计数器 + `total = ncase` 后与下限比较 -> 不得报（严格配对的正例）。

    这一条是 `_floor_paired_count()` 的存在理由：计数器没有 `len()`，
    它的长度判定是「先快照成 `total`，再比较」——
    宽松口径 `_floor_paired` 对它是**永远不成立**的（找不到 `len(ncase)`）。
    """
    return _t_decl() + (
        "_ST_FLOOR = 2\n"
        "\n"
        "def selftest():\n"
        "    fails = []\n"
        "    ncase = 0\n"
        "\n"
        "    def case(name, ok):\n"
        "        nonlocal ncase\n"
        "        ncase += 1\n"
        "        if not ok:\n"
        "            fails.append(name)\n"
        "\n"
        "    case('a', True)\n"
        "    total = ncase\n"
        "    if total < _ST_FLOOR:\n"
        "        return 1\n"
        "    return 0 if not fails else 1\n"
        "\n"
        "def main():\n"
        "    if args.selftest:\n"
        "        return selftest()\n")


def _t_count_dictkey():
    """计数器 + 下限**按批次名存进 dict** -> 不得报。

    真实形态 `tools/studio_proto_check.py`：`_BATCH_FLOORS = {'解析器': 5, ...}`
    是模块级 dict，判据写在**另一个函数** `_floors_ok()` 里（`n < floor`），
    批次函数只把自己报的条数塞进 `counts['解析器']`。
    它是全仓库下限纪律最严的工具之一，绝不能判成「缺下限」。
    """
    return _t_decl() + (
        "_BATCH_FLOORS = {'解析器': 5, '命令集合': 9}\n"
        "\n"
        "def _floors_ok(counts):\n"
        "    for name in _BATCH_FLOORS:\n"
        "        floor = _BATCH_FLOORS.get(name)\n"
        "        n = counts.get(name, 0)\n"
        "        if n < floor:\n"
        "            return False\n"
        "    return True\n"
        "\n"
        "def selftest(counts=None):\n"
        "    fails = []\n"
        "    ncase = 0\n"
        "\n"
        "    def case(name, ok):\n"
        "        nonlocal ncase\n"
        "        ncase += 1\n"
        "        if not ok:\n"
        "            fails.append(name)\n"
        "\n"
        "    case('a', True)\n"
        "    if counts is not None:\n"
        "        counts['解析器'] = ncase\n"
        "    return 0 if not fails else 1\n"
        "\n"
        "def main():\n"
        "    if args.selftest:\n"
        "        return selftest()\n")


def _t_count_unrelated():
    """★ 计数器批次 + 同函数里**别的不相干**下限比较 -> **必须报**。

    真实形态 `tools/vm_debug.py` 的 `VASM`：`ncov == len(VASM)` 是覆盖面判定，
    与 `len(cases) < _ST_FLOOR` 是**两条不同的语句**。宽松口径
    （「同函数内有 `len(批次)` 且有下限参与某条比较」）会把 `VASM` 算成
    「有下限的批次」—— 本条用例就是钉住这个假合格面。
    """
    return _t_decl() + (
        "_ST_FLOOR = 2\n"
        "\n"
        "def selftest():\n"
        "    fails = []\n"
        "    ncase = 0\n"
        "    other = [1, 2, 3]\n"
        "\n"
        "    def case(name, ok):\n"
        "        nonlocal ncase\n"
        "        ncase += 1\n"
        "        if not ok:\n"
        "            fails.append(name)\n"
        "\n"
        "    case('a', True)\n"
        "    if len(other) < _ST_FLOOR:\n"
        "        return 1\n"
        "    return 0 if not fails else 1\n"
        "\n"
        "def main():\n"
        "    if args.selftest:\n"
        "        return selftest()\n")


def _t_floor_ok():
    """批次 + 下限声明 + 用在比较里 -> 合规。"""
    return _t_decl() + (
        "_ST_FLOOR = 3\n"
        "\n"
        "def selftest():\n"
        "    cases = []\n"
        "    cases.append(('a', True, ''))\n"
        "    if len(cases) < _ST_FLOOR:\n"
        "        return 1\n"
        "    return 0 if all(c[1] for c in cases) else 1\n"
        "\n"
        "def main():\n"
        "    if args.selftest:\n"
        "        return selftest()\n")


def _t_floor_none():
    """批次但**没有任何下限声明** —— 清空批次后 `0 == 0` 仍绿（真实事故形态）。"""
    return _t_decl() + (
        "def selftest():\n"
        "    cases = []\n"
        "    cases.append(('a', True, ''))\n"
        "    npass = sum(1 for _n, ok, _d in cases if ok)\n"
        "    return 0 if npass == len(cases) else 1\n"
        "\n"
        "def main():\n"
        "    if args.selftest:\n"
        "        return selftest()\n")


def _t_floor_unused():
    """声明了下限却**没用在比较里**（只赋值，比较的是别的东西）-> 必须报。"""
    return _t_decl() + (
        "_ST_FLOOR = 3\n"
        "\n"
        "def selftest():\n"
        "    cases = []\n"
        "    cases.append(('a', True, ''))\n"
        "    failed = [c for c in cases if not c[1]]\n"
        "    return 0 if len(failed) == 0 else 1\n"
        "\n"
        "def main():\n"
        "    if args.selftest:\n"
        "        return selftest()\n")


def _t_floor_nobatch():
    """没有用例批次 -> 判据⑥ 不适用（不得报问题，也不得计入 checked）。"""
    return _t_decl() + (
        "def selftest():\n"
        "    if 1:\n"
        "        return 1\n"
        "    return 0\n"
        "\n"
        "def main():\n"
        "    if args.selftest:\n"
        "        return selftest()\n")


def _mk_floor_cases():
    """判据⑥ 的合成用例: `[(name, sources, want_problems, want_checked, min_files)]`。

    `min_files` 一律传 1：合成源里只有 1 个批次工具，用仓库下限 4 会把
    每条合规用例都判成「扫描面不足」—— **守卫的阈值必须与它守卫的扫描面同源**
    （§2.63 记过的同型坑）。
    """
    out = [
        ('F1 有下限声明且用在比较里 -> 不得报', _t_floor_ok(), 0, 1, 1),
        ('F2 有批次但没有任何下限声明 -> 必须报', _t_floor_none(), 1, 1, 1),
        ('F3 声明了下限却没用在比较里 -> 必须报', _t_floor_unused(), 1, 1, 1),
        # F4：一个批次都没有 —— 判据对本文件不适用，扫描面下限也传 0。
        #     （真实仓库里 `checked == 0` 由 `verify()` 自己的失锚分支拦住。）
        ('F4 没有用例批次 -> 不适用（不得报，也不计入）', _t_floor_nobatch(), 0, 0, 0),
        # ★ F5：扫描面本身低于下限 -> 必须报（判据⑥ 对自己的扫描面失明的反面）
        ('F5 批次工具数低于扫描面下限 -> 必须报', _t_floor_ok(), 1, 1, 2),
        # ★ F11：**循环驱动表**（名字匹配 _BATCH_RE、循环体调 case()）无下限
        #    -> 必须报。出典 `tools/modcheck.py::CASES` / `tools/studio_server.py::_wcases`
        ('F11 循环驱动表无下限 -> 必须报', _t_loop_nofloor(), 1, 1, 1),
        # ★ F12：同形态 + 下限参与比较 -> 不得报（F11 的反面，防「一律报」）
        ('F12 循环驱动表有下限 -> 不得报', _t_loop_floor(), 0, 1, 1),
        # ★ F13：**名字不匹配约定**的名单表 -> 不得当成批次（期望 checked == 0）。
        #    出典 `tools/doccheck.py::_must`（扫描面守卫名单）/ `tools/vm_debug.py::VASM`
        #    （覆盖面名单）—— 没有名字约定这一条，判据会对它们要求一个 FLOOR
        ('F13 名字不匹配的名单表 -> 不得当成批次', _t_loop_namemismatch(), 0, 0, 0),
        # ★ F14：**计数器型**批次无下限 -> 必须报。出典 `tools/studio_ui_check.py::ncase`
        #    （比列表型更隐蔽：`PASS: 0 项` 而 rc 仍是 0）
        ('F14 计数器型无下限 -> 必须报', _t_count_nofloor(), 1, 1, 1),
        # ★ F15：计数器 + `total = ncase` + 比较 -> 不得报。
        #    这条钉住 `_floor_paired_count()`：计数器没有 `len()`，
        #    宽松口径 `_floor_paired` 对**永远**不成立
        ('F15 计数器有下限（快照后比较）-> 不得报', _t_count_floor(), 0, 1, 1),
        # ★ F16：计数器 + 下限按**批次名**存进 dict -> 不得报。
        #    出典 `tools/studio_proto_check.py`（下限判定写在另一个函数 `_floors_ok()`）
        ('F16 计数器 + 下限 dict 键 -> 不得报', _t_count_dictkey(), 0, 1, 1),
        # ★ F17：计数器 + 同函数里**别的不相干**下限比较 -> **必须报**。
        #    钉住 `tools/vm_debug.py::VASM` 那个假合格面：
        #    `ncov == len(VASM)` 与 `len(cases) < _ST_FLOOR` 是两条不同的语句
        ('F17 计数器 + 不相干下限比较 -> 必须报', _t_count_unrelated(), 1, 1, 1),
    ]
    return [(n, {'tools/a.py': s,
                 'tools/release_check.ps1': '& $py tools\\a.py --selftest\n'},
             wp, wc, mf) for (n, s, wp, wc, mf) in out]


def _t_mut_nofloor():
    """**变异表**形态但没有下限 —— 清空后 `caught == total` 变成 `0 == 0`（真实事故）。"""
    return _t_decl() + (
        "def selftest():\n"
        "    mutations = [\n"
        "        ('M1', 'a'),\n"
        "        ('M2', 'b'),\n"
        "    ]\n"
        "    caught = 0\n"
        "    for label, _p in mutations:\n"
        "        caught += 1\n"
        "    total = len(mutations)\n"
        "    return 0 if caught == total else 1\n"
        "\n"
        "def main():\n"
        "    if args.selftest:\n"
        "        return selftest()\n")


def _t_mut_floor():
    """同一个形态 + 下限声明并参与比较 -> 合规。"""
    return _t_decl() + (
        "_MUT_FLOOR = 2\n"
        "\n"
        "def selftest():\n"
        "    mutations = [\n"
        "        ('M1', 'a'),\n"
        "        ('M2', 'b'),\n"
        "    ]\n"
        "    caught = 0\n"
        "    for label, _p in mutations:\n"
        "        caught += 1\n"
        "    total = len(mutations)\n"
        "    if total < _MUT_FLOOR:\n"
        "        return 1\n"
        "    return 0 if caught == total else 1\n"
        "\n"
        "def main():\n"
        "    if args.selftest:\n"
        "        return selftest()\n")


def _t_mut_except_only():
    """★ 表只在 `except` 分支里建、被**推导式**遍历 -> **不得**当成用例批次。

    这是 `_mutation_batches` 为什么要求「`ast.For` 遍历」且「赋值是函数体的
    直接语句」的原因：真实工具里
        `except Exception as e: res = [('crash', False, repr(e))]`
    完全满足「非空 List 字面量 + 被遍历 + 参与比较」，但那是**异常兜底表**，
    与「用例批次」无关。放宽后本判据会对它要求一个 FLOOR 声明 —— 假阳性。

    ⚠️ 这个 fixture 里**刻意不出现** `cases`/`checks` 这类名字：一旦出现，
    判据会因为**那个**名字报「没有下限」，于是本用例就测不到 `res` 了
    （第一版即如此：`cases` 让它报 1 条，看起来像"收窄没生效"）。
    期望 `checked == 0` —— 一个批次都不认。
    """
    return _t_decl() + (
        "def selftest():\n"
        "    caught = 0\n"
        "    total = 1\n"
        "    if total < 1:\n"
        "        return 1\n"
        "    try:\n"
        "        raise ValueError('x')\n"
        "    except Exception as e:\n"
        "        res = [('crash', False, repr(e))]\n"
        "    caught = len([c for c in res if c[1]])\n"
        "    return 0 if caught == len(res) else 1\n"
        "\n"
        "def main():\n"
        "    if args.selftest:\n"
        "        return selftest()\n")


def _t_batch_scanlist():
    """★ 函数里**另有一个**「非空 List 字面量 + `for` 遍历」的表（扫描面守卫名单）
    -> **不得**把它当成用例批次。

    真实形态 `tools/doccheck.py:2100`：
        `_must = ['README.md', 'CONTRIBUTING.md', '.github/PULL_REQUEST_TEMPLATE.md']`
        `for _m in _must:` … `fails.append('扫描面守卫: …')`
    它满足①②，第三条之所以在首版成立，是因为同函数里 `cases` 有
    「`len(cases)` -> `total` -> 比较」的通路，而首版的 `derived & comp`
    **与候选者无关** ⇒ 函数里任何一个候选者命中，`_must` 就跟着命中。
    期望：`cases` 是唯一批次，`_must` 不算 —— 有问题的是首版，这条用例就是它。
    """
    return _t_decl() + (
        "_ST_FLOOR = 2\n"
        "\n"
        "def selftest():\n"
        "    cases = []\n"
        "    cases.append(('a', True, ''))\n"
        "    _must = ['README.md', 'CONTRIBUTING.md']\n"
        "    for _m in _must:\n"
        "        cases.append(('扫描面 %s' % _m, True, ''))\n"
        "    total = len(cases)\n"
        "    if total < _ST_FLOOR:\n"
        "        return 1\n"
        "    return 0 if all(c[1] for c in cases) else 1\n"
        "\n"
        "def main():\n"
        "    if args.selftest:\n"
        "        return selftest()\n")


def _t_mut_other_floor():
    """★ 批次没有自己的下限，但文件里**另一个函数**有下限被比较 -> 必须报。

    真实形态 `tools/selfcrypt_residency_check.py`：批次是 `selftest()` 里的
    `mutations`（守卫 `if total < _MUT_FLOOR`），而 `MIN_SAMPLES = 10` 是
    `judge()` 里判据③ 的采样轮数下限（`:192 len(samples) >= MIN_SAMPLES`）。
    首版「文件里任一 decl 出现在任一比较里」被它满足 ⇒ 删 `_MUT_FLOOR`
    或删守卫行，判据都仍然 PASS（`build/_mutc6.py` A/B 两注入 rc=0）。
    """
    return _t_decl() + (
        "MIN_SAMPLES = 10\n"
        "\n"
        "def judge(samples):\n"
        "    return len(samples) >= MIN_SAMPLES\n"
        "\n"
        "def selftest():\n"
        "    mutations = [\n"
        "        ('M1', 'a'),\n"
        "        ('M2', 'b'),\n"
        "    ]\n"
        "    caught = 0\n"
        "    for label, _p in mutations:\n"
        "        caught += 1\n"
        "    total = len(mutations)\n"
        "    return 0 if caught == total else 1\n"
        "\n"
        "def main():\n"
        "    if args.selftest:\n"
        "        return selftest()\n")


def _mk_mut_cases():
    """判据⑥ 的**变异表**形态用例: [(name, sources, want_problems, want_checked, min_files)]。"""
    out = [
        # ★ 变异表无下限 -> 必须报（2026-10-12 实测同病：三张 mutations 表）
        ('F6 变异表形态但无下限声明 -> 必须报', _t_mut_nofloor(), 1, 1, 1),
        # 变异表 + 下限 -> 不得报
        ('F7 变异表形态且有下限参与比较 -> 不得报', _t_mut_floor(), 0, 1, 1),
        # ★ 只在 except 分支里的临时表不得被当成批次（收窄的判别力）
        #   一个批次都不认 -> checked 必须为 0，min_files 也传 0
        ('F8 只在 except 里的临时表 -> 不得当成批次', _t_mut_except_only(), 0, 0, 0),
        # ★ F9：同函数里另有「非空 List + for」的表（扫描面名单）不得算批次
        ('F9 同函数另有的名单表 -> 不得当成批次', _t_batch_scanlist(), 0, 1, 1),
        # ★ F10：下限在**别的函数**里被比较 -> 必须报（首版的假合格面，
        #        真实事故 `tools/selfcrypt_residency_check.py` 的 MIN_SAMPLES）
        ('F10 下限与批次不在同一函数 -> 必须报', _t_mut_other_floor(), 1, 1, 1),
    ]
    return [(n, {'tools/a.py': s,
                 'tools/release_check.ps1': '& $py tools\\a.py --selftest\n'},
             wp, wc, mf) for (n, s, wp, wc, mf) in out]


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
    bcases = _mk_body_cases()
    for name, sources, want in bcases:
        try:
            tools = _tools_from_sources(sources)
            bprob, _checked = body_check(tools, sources)
            got = len(bprob)
        except Exception as e:                      # noqa: BLE001
            got = -1
            print('  [XX] %s -> 探针异常: %r' % (name, e))
            bad.append(name)
            continue
        ok = (got == want)
        if ok:
            caught += 1
        else:
            bad.append(name)
        print('  [%s] %s -> 体问题 %s 条（期望 %d）'
              % ('ok' if ok else 'XX', name,
                 got if got >= 0 else 'ERR', want))

    total += len(bcases)
    fcases6 = _mk_floor_cases()
    for name, sources, want_p, want_c, minf in fcases6:
        try:
            tools = _tools_from_sources(sources)
            fprob, fchecked = floor_check(tools, sources, min_files=minf)
            got, gotc = len(fprob), fchecked
        except Exception as e:                      # noqa: BLE001
            got, gotc = -1, -1
            print('  [XX] %s -> 探针异常: %r' % (name, e))
            bad.append(name)
            continue
        ok = (got == want_p and gotc == want_c)
        if ok:
            caught += 1
        else:
            bad.append(name)
        print('  [%s] %s -> 下限问题 %s 条 / checked %s（期望 %d / %d）'
              % ('ok' if ok else 'XX', name,
                 got if got >= 0 else 'ERR', gotc if gotc >= 0 else 'ERR',
                 want_p, want_c))

    total += len(fcases6)
    mcases = _mk_mut_cases()
    for name, sources, want_p, want_c, minf in mcases:
        try:
            tools = _tools_from_sources(sources)
            mprob, mchecked = floor_check(tools, sources, min_files=minf)
            got, gotc = len(mprob), mchecked
        except Exception as e:                      # noqa: BLE001
            got, gotc = -1, -1
            print('  [XX] %s -> 探针异常: %r' % (name, e))
            bad.append(name)
            continue
        ok = (got == want_p and gotc == want_c)
        if ok:
            caught += 1
        else:
            bad.append(name)
        print('  [%s] %s -> 下限问题 %s 条 / checked %s（期望 %d / %d）'
              % ('ok' if ok else 'XX', name,
                 got if got >= 0 else 'ERR', gotc if gotc >= 0 else 'ERR',
                 want_p, want_c))

    total += len(mcases)
    if total < _ST_FLOOR:
        print('[selftest-audit-selftest] FAIL: 自检用例只有 %d 条，低于下限 %d —— '
              '有用例被删或被掏空（下限紧贴当前值：删用例须显式下调此数字）'
              % (total, _ST_FLOOR))
        return 1
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
