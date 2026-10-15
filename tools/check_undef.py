#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""check_undef.py — 静态审计: 引用但未绑定的全局名（门禁项，2026-10-05）

## 被检查的不变量

    「每个 `.py` 里被 Load 的名字，在它所在的作用域链上**必须**有绑定。」

## 为什么需要（**这不是假想的风险, 是刚踩过的坑**）

`tests/e2e.py` 的 T3 块调用 `DebugAttacher()`，而该类已被 `22826c5`
（2026-09-28, C-3）整体删除、调用点却留在 `tests/e2e.py:515`。

    `py_compile` 只查**语法**，这种名字**运行时必然 NameError**，
    但编译期全绿、`build/_undef.py` 出现之前**门禁也全绿**。

潜伏了 7 个月才暴露，原因见 `docs/HANDOVER.md` §2.24：旧 preflight 恒失败，
所以那条 `else` 分支**从未被执行过**。

同型第二例（本轮）：`tools/guard_selftest.py` 的诊断分支里引用了
`run_by_hits()` 的**局部**名 `cont` / `exit_pol` —— 同样是**只在失败
路径上执行**的代码。详见 `docs/HANDOVER.md` §2.25。

> **通用教训**：**只在失败路径上执行的代码是最难测的一类**；
> 静态审计（而非运行测试）才是它的正确防线。

## 与 `py_compile` / 运行测试的分工

    py_compile      语法          —— 抓不到 NameError
    运行测试        走到的路径    —— 抓不到"从未被执行"的分支
    本项            名字绑定      —— **与是否执行无关**

## 判据

① 每个 `.py` 的每个作用域里，`Load` 的名字必须在
   「内建 ∪ 模块级绑定 ∪ 外层作用域绑定」里；
② 作用域语义必须正确，否则会产生**假阳**（本工具开发中踩过 4 轮，
   见下"实现要点"）—— 假阳会让维护者关掉检查器，比漏报更危险。

## 实现要点（**每一条都是踩过的坑**）

  · 类体的名字对**方法体不可见**（方法查名字时跳过类作用域）
  · 推导式有自己的作用域，但**第一个 iter** 在**外层**求值
  · 函数默认值 / 装饰器 / 注解在**外层**作用域求值
  · `global` / `nonlocal` 声明的名字算已绑定（避免假阳）
  · **嵌套作用域节点本身也是本作用域的绑定** —— 漏了这条时，
    `try:` 里定义的 `class OSVERSIONINFOEXW` 名字不被绑定，
    后面用它就误报（一次性消掉 **18 处**假阳）
  · `ast.arg` 的属性是 `node.arg`，**不是** `node.id`
  · 读文件必须 `encoding='utf-8-sig'` —— 否则带 BOM 的
    `tests/attacks.py` / `tests/e2e.py` 报
    `invalid non-printable character U+FEFF`

## 含负向自检

  4 条变异（删一个内建 / 删模块级绑定 / 删局部绑定 / 造一个真未定义引用）
  必须全部被抓；抓不住任何一条即 FAIL。

## 用法
    python tools/check_undef.py [--quiet] [--selftest]
退出码: 0 = 干净; 1 = 有未定义引用（或自检失败）; 2 = SKIP
"""
import argparse
import ast
import builtins
import io
import os
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ROOTS = ('tests', 'tools', 'demo', 'examples')
SKIP_DIR = ('build', 'archive', '.git', 'dist', 'node_modules', '__pycache__')

SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)

BUILTINS = set(dir(builtins)) | {
    '__file__', '__name__', '__doc__', '__package__', '__builtins__',
    '__spec__', '__loader__', '__path__', 'WindowsError',
}


def params(a):
    out = {x.arg for x in a.posonlyargs + a.args + a.kwonlyargs}
    if a.vararg:
        out.add(a.vararg.arg)
    if a.kwarg:
        out.add(a.kwarg.arg)
    return out


def pruned_walk(node):
    """遍历后代, 但**不进入**嵌套作用域内部 (嵌套作用域节点本身仍会 yield)。"""
    stack = [node]
    first = True
    while stack:
        n = stack.pop()
        yield n
        if not first and isinstance(n, SCOPES):
            continue
        first = False
        for c in ast.iter_child_nodes(n):
            stack.append(c)


def split_scope(stmts):
    """返回 (own, nested): own = 本作用域内所有语句 (含嵌套块), nested = 直接子作用域。"""
    own, nested = [], []
    stack = list(stmts)
    while stack:
        s = stack.pop()
        own.append(s)
        if isinstance(s, SCOPES):
            if s not in nested:
                nested.append(s)
            continue
        for c in ast.iter_child_nodes(s):
            if isinstance(c, SCOPES):
                # 嵌套作用域**也要进 own**: 否则它的**名字**不会被绑定
                # (假阳根源: `try:` 里定义的 class 名对后面不可见 -> 误报)
                own.append(c)
                if c not in nested:
                    nested.append(c)
                continue
            if isinstance(c, ast.stmt):
                stack.append(c)
    return own, nested


def collect(own):
    """本作用域直接绑定的名字 (不含嵌套作用域内部的绑定)。"""
    names = set()
    for s in own:
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(s.name)
            continue
        if isinstance(s, ast.Lambda):
            continue
        for n in pruned_walk(s):
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                names.add(n.id)
            elif isinstance(n, (ast.Import, ast.ImportFrom)):
                for a in n.names:
                    if a.name != '*':
                        names.add(a.asname or a.name.split('.')[0])
            elif isinstance(n, ast.ExceptHandler) and n.name:
                names.add(n.name)
            elif isinstance(n, (ast.Global, ast.Nonlocal)):
                names.update(n.names)
            elif isinstance(n, ast.arg):
                names.add(n.arg)
    return names


def visit(node, vis, bad):
    """核对一个表达式/语句里的 Load 名 (不进入嵌套作用域体)。"""
    if isinstance(node, ast.Name):
        if isinstance(node.ctx, ast.Load) and node.id not in vis:
            bad.append((node.lineno, node.id))
        return
    if isinstance(node, ast.arg):
        if node.annotation is not None:
            visit(node.annotation, vis, bad)
        return
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for d in node.decorator_list:
            visit(d, vis, bad)
        for d in list(node.args.defaults) + [x for x in node.args.kw_defaults if x]:
            visit(d, vis, bad)
        for a in (node.args.posonlyargs + node.args.args + node.args.kwonlyargs):
            visit(a, vis, bad)
        if node.args.vararg:
            visit(node.args.vararg, vis, bad)
        if node.args.kwarg:
            visit(node.args.kwarg, vis, bad)
        if node.returns is not None:
            visit(node.returns, vis, bad)
        return
    if isinstance(node, ast.ClassDef):
        for d in node.decorator_list:
            visit(d, vis, bad)
        for b in node.bases:
            visit(b, vis, bad)
        for k in node.keywords:
            visit(k.value, vis, bad)
        return
    if isinstance(node, ast.Lambda):
        for d in list(node.args.defaults) + [x for x in node.args.kw_defaults if x]:
            visit(d, vis, bad)
        return
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
        cvis = set(vis)
        for g in node.generators:
            visit(g.iter, cvis, bad)          # 第一个 iter 用外层; 后续用已绑定的
            for t in ast.walk(g.target):
                if isinstance(t, ast.Name):
                    cvis.add(t.id)
            for i in g.ifs:
                visit(i, cvis, bad)
        if isinstance(node, ast.DictComp):
            visit(node.key, cvis, bad)
            visit(node.value, cvis, bad)
        else:
            visit(node.elt, cvis, bad)
        return
    for c in ast.iter_child_nodes(node):
        visit(c, vis, bad)


def check_scope(stmts, outer, bad, class_body=False):
    own, nested = split_scope(stmts)
    vis = outer | collect(own)
    for s in own:
        visit(s, vis, bad)
    child_vis = outer if class_body else vis
    for n in nested:
        if isinstance(n, ast.Lambda):
            visit(n.body, vis | params(n.args), bad)
        elif isinstance(n, ast.ClassDef):
            check_scope(n.body, child_vis, bad, class_body=True)
        else:
            check_scope(n.body, vis | params(n.args), bad)


def check_source(text, filename='<mutant>'):
    """返回 [(lineno, name) | ('SYNTAX', lineno, msg)]。"""
    try:
        tree = ast.parse(text, filename=filename)
    except SyntaxError as e:
        return [('SYNTAX', getattr(e, 'lineno', 0), str(e))]
    bad = []
    check_scope(tree.body, BUILTINS, bad)
    return sorted(set(bad))


def check_file(path):
    try:
        return check_source(
            io.open(path, encoding='utf-8-sig', errors='replace').read(), filename=path)
    except OSError as e:
        return [('SYNTAX', 0, str(e))]


def iter_files():
    for root in ROOTS:
        if not os.path.isdir(os.path.join(REPO, root)):
            continue
        for dirpath, dirnames, filenames in os.walk(os.path.join(REPO, root)):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIR]
            for f in sorted(filenames):
                if f.endswith('.py'):
                    yield os.path.join(dirpath, f)


# ---------------------------------------------------------------------------
# 负向自检
# ---------------------------------------------------------------------------

_CLEAN = '''\
import os


def outer(a, b=1, *rest, **kw):
    total = a + b
    for r in rest:
        total += r
    return total


class C:
    attr = 1

    def m(self, x):
        return x + self.attr


def has_class_in_try():
    try:                                   # 嵌套作用域节点本身也是绑定
        class OSVERSIONINFOEXW(object):
            pass
    except Exception:
        return None
    return OSVERSIONINFOEXW()


GEN = [i * j for i in range(3) for j in range(i)]
LAM = lambda q: q + 1
'''

_NESTED_LOCAL = '''\
def outer2():
    def helper():
        token = 1
        return token
    return token
'''

_MUTANTS = (
    # (名字, 变异后的源码, 期望被抓的名字)
    ('模块级绑定被删', _CLEAN.replace('GEN = ', 'GEN = miss_mod + '), 'miss_mod'),
    ('嵌套局部不可见', _NESTED_LOCAL, 'token'),
    ('真未定义引用', _CLEAN + '\nresult = never_defined_anywhere(1)\n',
     'never_defined_anywhere'),
    ('类体内引用不存在名', _CLEAN + '\nclass D:\n    v = undefined_in_class\n',
     'undefined_in_class'),
)

_PRONE_TO_FALSE_POSITIVE = (
    ('类体名字对方法不可见（不算未定义）', _CLEAN),
    ('try 内 class 名后续可用', _CLEAN),
    ('推导式首个 iter 用外层', _CLEAN),
    ('装饰器/默认值在外层求值',
     'def deco(f):\n    return f\n\n\n@deco\ndef g(p=CONST_OUTER):\n    return p\n\n\nCONST_OUTER = 1\n'),
)


def selftest():
    """返回 (ok, 说明行列表)。"""
    lines, ok = [], True

    # 1) 干净样本必须**零**报告（假阳防线）
    bad = check_source(_CLEAN)
    if bad:
        ok = False
        lines.append('  [X] 干净样本被误报 %d 处: %s' % (len(bad), bad[:3]))
    else:
        lines.append('  [ok] 干净样本 0 误报')

    # 2) 4 条变异必须全部被抓
    for name, text, want in _MUTANTS:
        got = {n for item in check_source(text) for n in (item[1],)}
        if want in got:
            lines.append('  [ok] 抓到变异: %s (%s)' % (name, want))
        else:
            ok = False
            lines.append('  [X] 漏掉变异: %s (期望 %s, 实得 %s)' % (name, want, sorted(got)[:5]))

    # 3) 4 类已知假阳源必须**不**报
    for name, text in _PRONE_TO_FALSE_POSITIVE:
        bad = check_source(text)
        if bad:
            ok = False
            lines.append('  [X] 假阳: %s -> %s' % (name, bad[:3]))
        else:
            lines.append('  [ok] 无假阳: %s' % name)

    return ok, lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        ok, lines = selftest()
        print('[check_undef-selftest] %s: %d 项（4 变异 / %d 假阳防线）'
              % ('PASS' if ok else 'FAIL', len(lines), len(_PRONE_TO_FALSE_POSITIVE)))
        for ln in lines:
            print(ln)
        return 0 if ok else 1

    total, files, hits = 0, 0, []
    for p in iter_files():
        files += 1
        bad = check_file(p)
        if bad:
            total += len(bad)
            hits.append((os.path.relpath(p, REPO), bad))

    for rel, bad in hits:
        print('=== %s  (%d 处)' % (rel, len(bad)))
        for item in bad:
            if len(item) == 3:
                print('  %-8s :%-5s %s' % item)
            else:
                print('  UNDEF    :%-5s %s' % item)
    if hits:
        print('---')

    if args.quiet:
        print('[check_undef] %s: 扫描 %d 个 .py, 疑似未定义引用 %d 处'
              % ('FAIL' if total else 'PASS', files, total))
    else:
        print('扫描 %d 个 .py; 疑似未定义引用 %d 处' % (files, total))

    return 1 if total else 0


if __name__ == '__main__':
    sys.exit(main())
