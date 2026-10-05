#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
tools/window_check.py — **解密窗口覆盖检查** (T11 / §2.16 根因级门禁)

## 被检查的不变量

    **每一个对 selfcrypt 加密目标的调用点, 在执行它时该目标必须已解密。**

D2b (`PROT_SELFCRYPT_D2B`) 下加密目标在"间隙"里是**磁盘密文**, 只有落在同组
`prot_selfcrypt_enter(G)` / `leave(G)` 之间的调用才安全。窗口之外的调用执行的是
**密文** —— 后果完全取决于密文首字节: 恰好是 `0xC3`(`ret`) 就静默空转, 否则崩
(`0xC0000005`)。**这就是 T11** (2026-10-02)。

## 为什么需要它 (P5 看不见这件事)

`tests/protchain_check.py` 的 P5 (`indirect-no-direct-call`) 判的是
「**不得直接 `E8` 调用加密目标**」—— 只扫 `0xE8` 字节 (`scan_e8_calls`)。
而 T11 那处是 `volatile` 函数指针调用 (`call rax`), 从设计上就在 P5 视野之外;
`demo/main.c:544` 那种**窗口内**的直接 `E8` 调用则**一直合法** (P5 也一直放行)。
⇒ 真正的错不在"怎么调用", 而在"**在不在窗口里**", 这条不变量此前**无任何静态检查**。

同日发现的同型违规 (`docs/HANDOVER.md` §2.16):
  · `demo/main.c:614`        `apply_policy` 的 `else` 分支 (窗口外裸调用)
  · `prot_sdk/skeleton/app_main.c:555` / `:624`  骨架仍是修复前的老写法
根因: `src/antidebug.c:548` 的 `prot_antidebug_scan` 是组 1 加密目标, 而
`prot_antidebug_apply_policy` **自身不是加密目标、也不开窗口** ⇒ 它的**每个**调用点
都必须自带窗口。

## 判据 (静态近似, 互递归不动点)

记 `covered(f, G)` = 函数 f 执行时组 G 必已解密:
  · f **本身是**组 G 的加密目标              -> True (责任移交 f 的调用者)
  · 否则: f 在作用域内**至少有一个**调用点, 且**全部**调用点都落在组 G 窗口内 -> True
  (真正入口如 `main` / 线程入口无调用点 -> 判 False, 即"没有人为你开窗口")

记 `requires(f)` = 使 f 内部（含传递）出现"未被本地窗口覆盖"的目标调用所需的组集合。

**违规** = 调用点 s (在 f 内, 调用 c) 且 G ∈ (targets(c) ∪ requires(c)) 且
           s 不在 f 的组 G 窗口内 且 not covered(f, G)。

已核对本仓真实代码的判定 (不得产生假阳性):
  · `src/blob.c:185`   调 `prot_license_verify` — 调用者 `prot_vm_blob_load` **是**组 1
                       目标 -> 判合法 (责任移交 main.c:711-726 的窗口)
  · `src/revoke.c:136` 调 `prot_license_verify` — 调用者不是目标, 但其**唯一**调用点
                       `demo/main.c:826` 在组 1 窗口内 -> `covered` 为真 -> 合法
  · `demo/main.c:476`  调 `prot_license_verify` — 同理 (`main.c:793` 在窗口内)
  · `demo/main.c:611`  在 `sc_ext_enter()` 窗口内 -> 合法
  · `demo/main.c:614`  `else` 分支裸调用 -> **违规** (本节要抓的那处)
  · `vm_wb`/`vm_var`/`vm_build_keymaps` 在 `prot_vm_run` 内互调 -> 调用者是组 0 目标 -> 合法

## 作用域 (为什么是这三个目录)

只检查**构建管线真的跑 `tools/selfcrypt_proto.py`** 的宿主 + 它们链接的模块:
  · `src/**`       —— 模块本体 (`build.ps1` 与 `build_skeleton.ps1` 共用)
  · `demo/**`      —— `build.ps1` 的宿主
  · `prot_sdk/skeleton/**` —— `build_skeleton.ps1` 的宿主
**不**检查 `examples/tool_demo`(其 `build_example.ps1` **不调** selfcrypt_proto =>
函数是明文, 恒无害) 与 `tests/**`、`archive/**`。骨架当前恒为 D2a (窗口空转) =>
那里的违规是**潜伏**的; 仍要修, 因为 D2b 只是一个编译开关。

## CLI
    python tools/window_check.py [--verbose] [--json out.json] [--selftest]
退出码: 0 = 不变量成立; 1 = 存在违规。
"""

import argparse
import ast
import io
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from winproc import run as _run  # noqa: F401  (保持与其它工具的导入面一致)
except Exception:  # pragma: no cover - 直接脚本运行时不需要
    pass

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SCOPE_DIRS = ('src', os.path.join('src', 'platform'), 'demo',
              os.path.join('prot_sdk', 'skeleton'))

GROUP_CONSTS = {
    'PROT_SELFCRYPT_GROUP_VM': 0,
    'PROT_SELFCRYPT_GROUP_EXT': 1,
}
GROUP_NAMES = {0: 'VM', 1: 'EXT'}

ENTER = 'prot_selfcrypt_enter'
LEAVE = 'prot_selfcrypt_leave'

# 控制关键字/内建: 不是被调函数, 不参与调用图
NOT_A_CALL = frozenset("""
if for while switch return sizeof do else defined
""".split())


# --------------------------------------------------------------------------
# 单一事实来源: 加密目标清单从 tools/selfcrypt_proto.py 读 (不硬编码)
# --------------------------------------------------------------------------
def load_targets(path=None):
    """从 tools/selfcrypt_proto.py 的 DEFAULT_TARGETS / EXT_TARGETS 抽 {name: group}。

    **不硬编码**: 该文件是加密目标清单的单一事实来源; 硬编码会在目标增删时静默失准。
    """
    path = path or os.path.join(REPO, 'tools', 'selfcrypt_proto.py')
    tree = ast.parse(io.open(path, encoding='utf-8').read())
    out = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if not names or names[0] not in ('DEFAULT_TARGETS', 'EXT_TARGETS'):
            continue
        if not isinstance(node.value, ast.Dict):
            continue
        for k, v in zip(node.value.keys, node.value.values):
            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                grp = 0
                if isinstance(v, ast.Constant) and isinstance(v.value, int):
                    grp = v.value
                out[k.value] = grp
    return out


def load_slot_symbols(path=None):
    """modules.json 的 indirect_slots -> {槽位ID: 符号名} (间接调用的真实目标)。"""
    path = path or os.path.join(REPO, 'modules.json')
    d = json.loads(io.open(path, encoding='utf-8').read())
    slots = d.get('indirect_slots', {})
    out = {}
    for k, v in slots.items():
        if k.startswith('_') or not isinstance(v, dict):
            continue
        sym = v.get('symbol')
        if sym:
            out[k] = sym
    return out


# --------------------------------------------------------------------------
# C 源码解析 (词法级, 够用: 本仓代码风格极规整, /W4 /WX)
# --------------------------------------------------------------------------
def strip_comments(text):
    """把注释清零 (保留换行与列位置)。

    **必须做**: 注释里的示例代码会被词法匹配当成真代码 —— 缺陷 8 的
    `tools/winproc.py` 文档字符串就是这样造出"自己依赖自己"的假阳性的。
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        if text[i] == '/' and i + 1 < n and text[i + 1] == '*':
            j = text.find('*/', i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != '\n':
                    out[k] = ' '
            i = j
        elif text[i] == '/' and i + 1 < n and text[i + 1] == '/':
            j = text.find('\n', i)
            j = n if j < 0 else j
            for k in range(i, j):
                if out[k] != '\n':
                    out[k] = ' '
            i = j
        else:
            i += 1
    return ''.join(out)


SIG_RE = re.compile(r'^([A-Za-z_][\w \t\*]*?)\s+(\*?\w+)\s*\(')


def parse_functions(path):
    """切函数体: 返回 [{name, path, sl, el, body, static}] (行号 1-based)。"""
    raw = io.open(path, encoding='utf-8', errors='replace').read()
    code = strip_comments(raw)
    lines = code.split('\n')
    funcs = []
    i, n = 0, len(lines)
    while i < n:
        m = SIG_RE.match(lines[i])
        if m and not lines[i].lstrip().startswith('#'):
            j, depth, found = i, 0, False
            while j < n and j < i + 12:
                depth += lines[j].count('(') - lines[j].count(')')
                if '{' in lines[j]:
                    found = True
                    break
                if ';' in lines[j] and depth <= 0:
                    break
                j += 1
            if found and depth <= 0:
                name = m.group(2)
                if name not in NOT_A_CALL:
                    d, k, started = 0, j, False
                    while k < n:
                        d += lines[k].count('{') - lines[k].count('}')
                        if '{' in lines[k]:
                            started = True
                        if started and d <= 0:
                            break
                        k += 1
                    prefix = ' '.join(lines[i:j + 1]).split(name)[0]
                    # 函数体起点 = 第一个深度平衡的 '{'。
                    # **不能按"整行"挖签名** —— `src/vm.c:643`
                    # `static prot_status vm_h_add(prot_vm_rt* s)  { return vm_rt_binop(s, 0x06); }`
                    # 是**单行函数**, 于是 `vm_rt_binop(...)` 与 `{` 同行, 整行被当签名
                    # 跳过 ⇒ `vm_rt_binop` 从未出现在 called_names 里, 被误判成"真入口"。
                    brace_ln = j + 1
                    brace_col = lines[j].index('{') + 1
                    funcs.append({
                        'name': name,
                        'path': path,
                        'sl': i + 1,
                        'el': k + 1,
                        'body': '\n'.join(lines[i:k + 1]),
                        'static': bool(re.search(r'\bstatic\b', prefix)),
                        'body_ln': brace_ln,      # 1-based
                        'body_col': brace_col,    # 该行内的列 (0-based 起)
                    })
                    i = k + 1
                    continue
        i += 1
    return funcs


def in_sig(func, ln, col):
    """(行, 列) 是否落在函数签名区(即 `{` 之前)。"""
    if ln < func['body_ln']:
        return True
    if ln == func['body_ln'] and col < func['body_col']:
        return True
    return False


def scope_files(root=None):
    root = root or REPO
    out = []
    for d in SCOPE_DIRS:
        p = os.path.join(root, d)
        if not os.path.isdir(p):
            continue
        for fn in sorted(os.listdir(p)):
            if fn.endswith('.c'):
                out.append(os.path.join(p, fn))
    return out


# --------------------------------------------------------------------------
# 窗口 / 调用点
# --------------------------------------------------------------------------
def parse_group_arg(arg):
    arg = arg.strip()
    if arg in GROUP_CONSTS:
        return GROUP_CONSTS[arg]
    if re.fullmatch(r'0x[0-9A-Fa-f]+|\d+', arg):
        return int(arg, 0)
    return None


ENTER_LEAVE_RE = re.compile(r'\b(' + ENTER + '|' + LEAVE + r')\s*\(([^)]*)\)')


def window_events(func):
    """函数体内**按行**的窗口事件 [(line, col, kind, group)]，kind ∈ {'+','-'}。"""
    ev = []
    for k, line in enumerate(func['body'].split('\n')):
        ln = func['sl'] + k
        for m in ENTER_LEAVE_RE.finditer(line):
            if in_sig(func, ln, m.start()):
                continue
            g = parse_group_arg(m.group(2))
            if g is None:
                continue
            ev.append((ln, m.start(), '+' if m.group(1) == ENTER else '-', g))
    return ev


def depth_at(func, events, line, col):
    """query 点之前 (行优先, 同行按列) 各组的净深度。"""
    d = {}
    for (ln, cl, kind, g) in events:
        if ln < line or (ln == line and cl < col):
            d[g] = d.get(g, 0) + (1 if kind == '+' else -1)
    return d


CALL_RE = re.compile(r'\b([A-Za-z_]\w*)\s*\(')
INDIRECT_CALL_RE = re.compile(r'\bPROT_INDIRECT_CALL\s*\(\s*(PROT_INDIRECT_\w+)')


def prepare(func, wrapper_enter, wrapper_leave, aliases, slots, target_names):
    """给函数挂上 `sites` 与 `events`, 返回该函数。

    **宿主包装必须同时变成窗口事件** —— `sc_ext_enter()` 不是
    `prot_selfcrypt_enter`, 不会被 `window_events` 认出来; 首版漏了这一步,
    于是"经包装开窗"在判据眼里深度恒为 0 (selftest 实测 1 项 FAIL)。
    """
    func['sites'] = call_sites(func, wrapper_enter, wrapper_leave, aliases,
                               slots, target_names)
    ev = window_events(func)
    for s in func['sites']:
        if s['how'] != 'window':
            continue
        kind = '+' if s['name'] in wrapper_enter else '-'
        ev.append((s['line'], s['col'], kind, s['group']))
    ev.sort()
    func['events'] = ev
    return func


def call_sites(func, wrapper_enter, wrapper_leave, aliases, slots, target_names):
    """函数内全部调用点 [{line,col,name,group_hint}]。

    展开三类"看起来不是目标、实际是"的调用:
      · 宿主包装 `sc_ext_enter()` / `sc_ext_leave()`  -> 窗口原语
      · 函数指针别名 `g_ad_scan_fn(&ad)`             -> 已解析为某目标 (**T11 那处**)
      · `PROT_INDIRECT_CALL(PROT_INDIRECT_X, ...)`   -> indirect_slots 的符号

    **签名行整行跳过** —— 否则 `int main(int argc, char** argv)` 会被读成
    "调用 main()" (首版实测: demo/main.c:489 与 :404 各一条假阳性)。
    """
    sites = []
    for k, line in enumerate(func['body'].split('\n')):
        ln = func['sl'] + k
        for m in CALL_RE.finditer(line):
            if in_sig(func, ln, m.start()):
                continue
            name = m.group(1)
            if name in NOT_A_CALL:
                continue
            if name in (ENTER, LEAVE, 'PROT_INDIRECT_CALL'):
                continue
            if name in wrapper_enter or name in wrapper_leave:
                g = wrapper_enter.get(name, wrapper_leave.get(name))
                sites.append({'line': ln, 'col': m.start(), 'name': name,
                              'how': 'window', 'group': g})
                continue
            if name in aliases:
                sites.append({'line': ln, 'col': m.start(), 'name': aliases[name],
                             'how': 'fptr:' + name})
                continue
            if name in target_names:
                sites.append({'line': ln, 'col': m.start(), 'name': name,
                              'how': 'direct'})
                continue
            sites.append({'line': ln, 'col': m.start(), 'name': name, 'how': 'plain'})

    # `PROT_INDIRECT_CALL` 实测**跨行** —— `demo/main.c:793` 与 `:826` 都是
    # `PROT_INDIRECT_CALL(\n    PROT_INDIRECT_LICENSE, ...`。逐行扫会漏掉
    # **全部**间接站点, 连锁后果: 被间接调用的宿主函数 `load_and_verify_license`
    # / `prot_revoke_check` 不再出现在 called_names 里, 于它们被判成"真入口"
    # (is_self) 而把自身内部的合法调用报成违规 (首版 12 处里有 2 处)。
    # ⇒ 必须按**函数体全文**扫。
    #
    # ⚠️ `modules.json` 的槽位键**没有** `PROT_INDIRECT_` 前缀 (实测:
    # `{"LICENSE": {...}, "VM_RUN": {...}, "REVOKE": ..., "HOSTID": ...}`),
    # 而源码里写的是 `PROT_INDIRECT_LICENSE`。首版直接 `slots.get(m.group(1))`
    # 恒为 None ⇒ **所有间接站点被静默丢弃**, `load_and_verify_license` /
    # `prot_revoke_check` 三处内部调用被误报。⇒ 必须剥前缀再查。
    for m in INDIRECT_CALL_RE.finditer(func['body']):
        ln = func['sl'] + func['body'].count('\n', 0, m.start())
        if in_sig(func, ln, 0):
            continue
        key = m.group(1)
        if key not in slots and key.startswith('PROT_INDIRECT_'):
            key = key[len('PROT_INDIRECT_'):]
        sym = slots.get(key)
        if sym:
            sites.append({'line': ln, 'col': 0, 'name': sym,
                          'how': 'indirect:' + m.group(1)})
    return sites


def body_only(func):
    """函数的**纯正文**文本 (签名与 `{` 之前的部分全部去掉)。

    一律用这个而不是 `func['body']`: 签名里同名标识符会被词法匹配当成调用
    (首版 `demo/main.c:489` / `:404` 与一串 `vm_h_*` 的假阳性), 而单行函数
    (`src/vm.c:643`) 的正文与签名**同行**, 按行挖会连正文一起挖掉。
    """
    out = []
    for k, line in enumerate(func['body'].split('\n')):
        ln = func['sl'] + k
        if ln < func['body_ln']:
            continue
        if ln == func['body_ln']:
            out.append(line[func['body_col'] - 1:])
        else:
            out.append(line)
    return '\n'.join(out)


# 函数指针调用: `dt[slot[c]](&rt)` / `g_routes[i](...)` / `(*fn)(...)`
FPTR_CALL_RE = re.compile(r'(?:\]|\)|\*\s*\w+)\s*\(')


def indirect_call_groups(funcs, targets):
    """{文件: {组}} —— 该文件里有"某组的加密目标"体内出现函数指针调用。

    用途: `src/vm.c` 的 `prot_vm_run`(组 0 目标) 体内有 `dt[slot[canon]](&rt)`
    (`src/vm.c:1087`), 而 `g_routes[]` 表里装的是 `vm_h_*` 系列 -> 这些 helper
    的**调用者在静态上不可解析**。它们运行时确实在组 0 已解密的状态下执行
    (被 prot_vm_run 调入), 若不认这一点就会把整个 VM 内部报成违规
    (首版 71 处里的大半)。

    ⚠️ 这只是"该文件里存在表驱动派发"的**粗筛**, 不能直接当豁免依据 ——
    必须再确认函数名**真的在表里**(见 `file_scope_table_names`)。首版拿它当
    豁免依据, 结果 `src/integrity.c` 整个文件被打上组 1 标记, 于是
    `watchdog_thread` 体内那处**真正执行密文的** `g_ad_scan_fn(&ad)` 被无条件
    赦免 —— 门禁对 T11 本身失效 (由 `build/_wc_negctl.py` 的负向对照抓出)。
    """
    out = {}
    for f in funcs:
        if f['name'] not in targets:
            continue
        if FPTR_CALL_RE.search(body_only(f)):
            out.setdefault(f['rel'], set()).add(targets[f['name']])
    return out


def file_scope_table_names(text, funcs_of_file):
    """{标识符} —— 出现在**文件作用域聚合初始化表**里 (即不在任何函数体内)。

    这是"经路由表进入"的**真正成员判据**: `src/vm.c:965-1013` 的
    `static const prot_vm_route g_routes[PROT_VM_OP_COUNT] = { vm_h_halt, ... }`
    在文件作用域, 不在任何函数体内; 而 `watchdog_thread` 只作为
    `prot_plat_thread_create(watchdog_thread, ...)` 的**实参**出现 (在函数体内),
    **不该**被算成入表。

    实现: 把所有函数体清零后, 找 `= { ... }` 并收集其中的标识符。
    """
    out = list(text)
    starts = [0]
    for i, ch in enumerate(text):
        if ch == '\n':
            starts.append(i + 1)

    def off(ln, col=0):
        return starts[ln - 1] + col if ln - 1 < len(starts) else len(text)

    for f in funcs_of_file:                       # 清掉函数体 (含签名)
        a = off(f['sl'], 0)
        b = min(off(f['el'] + 1, 0), len(out))
        for k in range(a, b):
            if out[k] != '\n':
                out[k] = ' '

    names = set()
    scope = ''.join(out)
    for m in re.finditer(r'=\s*\{([^{}]*)\}', scope):
        for idm in re.finditer(r'\b([A-Za-z_]\w*)\b', m.group(1)):
            names.add(idm.group(1))
    return names


def find_wrappers(funcs, target_names):
    """识别宿主对 selfcrypt 窗口的薄封装 -> {wrapper_name: group}。

    判据: 正文内**仅**有一次 enter/leave 调用且参数是组常量
    (demo/main.c:91-99 与 prot_sdk/skeleton/app_main.c:140-148 就是这个形状),
    且除去这次窗口调用与 `return`/类型名后不再有别的调用。
    """
    we, wl = {}, {}
    for f in funcs:
        ev = window_events(f)
        if len(ev) != 1:
            continue
        _ln, _c, kind, g = ev[0]
        rest = ENTER_LEAVE_RE.sub(' ', body_only(f))
        rest = re.sub(r'\breturn\b', ' ', rest)
        rest = re.sub(r'\bprot_status\b', ' ', rest)
        rest = re.sub(r'\bvoid\b', ' ', rest)
        if CALL_RE.search(rest):
            continue
        (we if kind == '+' else wl)[f['name']] = g
    return we, wl


def find_fptr_aliases(all_text, target_names):
    """文件/全局作用域: `= prot_antidebug_scan;` 形式的函数指针初始化 -> {变量: 目标}。

    **这是 T11 能被静态抓住的关键**: `src/integrity.c:142`
    `static prot_ad_scan_fn volatile g_ad_scan_fn = prot_antidebug_scan;`
    —— 之后 `g_ad_scan_fn(&ad)` 就是一次组 1 目标调用。
    """
    aliases = {}
    pat = re.compile(r'\b(\w+)\s*(?:\[[^\]]*\])?\s*=\s*&?\s*(' +
                     '|'.join(target_names) + r')\s*;')
    for m in pat.finditer(all_text):
        aliases[m.group(1)] = m.group(2)
    return aliases


def blank_signatures(text, funcs_of_file):
    """把本文件每个函数的**签名区**(起始行到 `{` 之前)用空格替换, 等长保留换行。

    取地址判据必须先把签名挖掉, 否则 `static prot_status vm_rt_binop(...)`
    这行**定义**本身就满足"出现但不带调用括号" ⇒ 每个 static helper 都被
    误判成"入表"。首版在整份文件上裸搜, 得到 `vm_rt_binop taken=False`
    (该 True) 而真正的 `vm_h_*` 又因单行函数被整行挖进签名 (该 True 却 False)
    —— 两个方向同时错。
    """
    out = list(text)
    starts = [0]
    for i, ch in enumerate(text):
        if ch == '\n':
            starts.append(i + 1)

    def off(ln, col=0):
        return starts[ln - 1] + col if ln - 1 < len(starts) else len(text)

    for f in funcs_of_file:
        a = off(f['sl'], 0)
        b = min(off(f['body_ln'], f['body_col'] - 1), len(out))
        for k in range(a, b):
            if out[k] != '\n':
                out[k] = ' '
    return ''.join(out)


def taken_addresses(file_text, funcs_of_file, names):
    """{函数名} 中被**取地址/入表**(出现但不带调用括号)的那些。

    用途: `src/vm.c` 的 `vm_h_*` 系列只通过 `g_routes[]` 路由表
    (`src/vm.c:1087 rc = dt[slot[canon]](&rt);`) 进入, 正文里**没有调用点**。

    ⚠️ **必须扫整份文件(挖掉所有签名后), 不能只看函数正文** —— 路由表
    `static const prot_vm_route g_routes[...] = { vm_h_add, ... }` 位于
    `src/vm.c:965-1013`, 是**文件作用域**的, 不在任何函数体内; 只看正文
    会把 19 处 VM helper 互调全报成违规。
    """
    stripped = blank_signatures(file_text, funcs_of_file)
    out = set()
    for name in names:
        if re.search(r'\b' + re.escape(name) + r'\b(?!\s*\()', stripped):
            out.add(name)
    return out


# --------------------------------------------------------------------------
# 判定
# --------------------------------------------------------------------------
def analyze(root=None, verbose=False):
    targets = load_targets(os.path.join(root or REPO, 'tools', 'selfcrypt_proto.py'))
    slots = load_slot_symbols(os.path.join(root or REPO, 'modules.json'))
    target_names = set(targets)

    files = scope_files(root)
    funcs = []
    for p in files:
        funcs.extend(parse_functions(p))

    all_text = '\n'.join(strip_comments(io.open(p, encoding='utf-8',
                                                errors='replace').read())
                         for p in files)
    aliases = find_fptr_aliases(all_text, target_names)
    wrapper_enter, wrapper_leave = find_wrappers(funcs, target_names)

    def rel(p):
        return os.path.relpath(p, root or REPO).replace('\\', '/')

    # 每个函数的窗口事件与调用点
    for f in funcs:
        prepare(f, wrapper_enter, wrapper_leave, aliases, slots, target_names)
        f['rel'] = rel(f['path'])
        f['key'] = (f['rel'], f['name'], f['sl'])

    # 名字 -> 定义列表 (同名可有多份: 如 antidebug.c 的 win/linux 两版)
    defs = {}
    for f in funcs:
        defs.setdefault(f['name'], []).append(f)

    # 作用域内的调用边: caller key -> [site]
    edges = {}
    for f in funcs:
        for s in f['sites']:
            if s['how'] == 'window':
                continue
            if s['name'] in defs or s['name'] in target_names or s['name'] in slots.values():
                edges.setdefault(f['key'], []).append(s)

    direct_callers = {}
    for f in funcs:
        for s in f['sites']:
            if s['how'] == 'window':
                continue
            direct_callers.setdefault(s['name'], []).append((f, s))
    called_names = set(direct_callers)

    # --- ambient(f): f 的**整个函数体**都被认为"已打开"的组 -------------------
    #  · f 自身是加密目标          -> 组 targets[f] (调用者负责开窗, 这是契约:
    #    进了目标函数体, 它自己那一组必然是解密态)
    #  · f 只经路由表被间接调用    -> 装它的表在哪个**目标**函数里被 call, 就是
    #    那个组。`src/vm.c` 的 `prot_vm_run`(组 0) 体内有 `dt[slot[c]](&rt)`,
    #    而表里是 `vm_h_*` 系列 —— 它们的调用者在静态上不可解析, 但运行时确实
    #    在组 0 已解密的状态下执行。**不认这一点就会把整个 VM 内部报成违规
    #    (首版 71 处里的大半)。**
    route_groups = indirect_call_groups(funcs, targets)

    # 取地址判定: 名字在**某份源文件**里出现却不带调用括号。
    # ⚠️ 两个方向都会错, 必须**逐文件、先挖掉签名**:
    #   · 看整份文件裸搜 -> **定义行** `static prot_status vm_rt_binop(...)`
    #     也算"出现但不带括号", 每个 static helper 恒判 True;
    #   · 只看函数正文   -> 单行函数被整行挖进签名 (`src/vm.c:643` 的
    #     `vm_h_add`) 判不出来, 且文件作用域的 `g_routes[]` 表压根不在正文里。
    # ⇒ `taken_addresses(整份文件, 该文件的函数列表, names)`。
    per_file = {}
    for p in files:
        per_file[rel(p)] = (io.open(p, encoding='utf-8', errors='replace').read(),
                            [f for f in funcs if f['path'] == p])

    def addr_is_taken(f):
        text, fl = per_file[f['rel']]
        return f['name'] in taken_addresses(text, fl, {f['name']})

    # 入表判定: 名字**真的出现在该文件的文件作用域初始化表里**。
    # ⚠️ 这是本轮负向对照抓出的假阴性的修法: `route_groups` 是**文件**级
    #    粗筛 ("该文件里存在表驱动派发"), 拿它当**函数**级的豁免依据, 就会让
    #    `src/integrity.c` 里**恰好与组 1 目标同处一个文件**的 `watchdog_thread`
    #    无端获得组 1 ambient, 于是 `:216` 那处**真正执行磁盘密文**的
    #    `g_ad_scan_fn(&ad)` 被无条件赦免 —— 门禁对 T11 本身失明
    #    (`build/_wc_negctl.py` 实测: 修复前的树也只报同样 3 处 §2.16)。
    #    豁免必须落到"这个函数名真的在表里"这一粒度。
    table_names = {}
    for r_, (text, fl) in per_file.items():
        table_names[r_] = file_scope_table_names(text, fl)

    def in_scope_table(f):
        return f['name'] in table_names.get(f['rel'], set())

    # 同名遮蔽: `src/vm.c` 的 `dt[slot[canon]](&rt)` 调的是 `g_routes[]` 表内的
    # 函数, 目标在静态上不可解析; 但若某 helper 的名字**也在别处被直接调用**,
    # 就不能靠名字把它算成"经路由表进入"(否则它的调用点会被无条件赦免)。
    shadowed = set()
    for f in funcs:
        if f['rel'] in route_groups and f['name'] in called_names and not f['static']:
            shadowed.add(f['name'])

    ambient = {}
    for f in funcs:
        a = set()
        if f['name'] in targets:
            a.add(targets[f['name']])
        if (f['static'] and f['name'] not in called_names
                and f['name'] not in shadowed
                and addr_is_taken(f) and in_scope_table(f)):
            a |= route_groups.get(f['rel'], set())
        ambient[f['key']] = a

    def open_at(f, s):
        """站点 s 处**实际**已打开的组 = 词法深度 + ambient。"""
        d = depth_at(f, f['events'], s['line'], s['col'])
        return {g for g, n in d.items() if n > 0} | ambient[f['key']]

    def required_by(s):
        """执行站点 s 的调用目标时, 必须已打开的组。

        · 目标是加密目标 -> 它自己那一组 (它内部的需求由它自己上报, 见 SELF,
          **不向调用者转嫁**, 否则同一处缺陷会被重复归因)
        · 目标是作用域内普通函数 -> 它的 requires (责任向上传递)
        """
        if s['name'] in targets:
            return {targets[s['name']]}
        gs = set()
        for d in defs.get(s['name'], []):
            gs |= requires[d['key']]
        return gs

    # --- requires(f) 不动点 --------------------------------------------------
    # "[进入 f 时] 必须由外部打开的组"。责任逐层上推, 最终落在 SELF 上。
    requires = {f['key']: set() for f in funcs}
    for _ in range(len(funcs) + 2):
        changed = False
        for f in funcs:
            need = set(requires[f['key']])
            for s in f['sites']:
                if s['how'] == 'window':
                    continue
                for g in required_by(s):
                    if g not in open_at(f, s):
                        need.add(g)
            if need != requires[f['key']]:
                requires[f['key']] = need
                changed = True
        if not changed:
            break

    # --- 违规上报点: SELF = 加密目标 ∪ 作用域内没有被调用者的函数(真入口) ------
    # 中间函数不上报 —— 它们的 requires 会推到调用者身上, 由调用点判定。
    # (否则 `src/antidebug.c:548` 那处"apply_policy 内部调 scan"会被误报:
    #  apply_policy 的**每一个**调用点都必须自带窗口, 责任在调用者。)
    is_self = set()
    for f in funcs:
        if f['name'] in targets or f['name'] not in called_names:
            is_self.add(f['key'])

    violations = []
    for f in funcs:
        if f['key'] not in is_self:
            continue
        for s in f['sites']:
            if s['how'] == 'window':
                continue
            for g in sorted(required_by(s) - open_at(f, s)):
                violations.append({
                    'file': f['rel'], 'line': s['line'], 'col': s['col'],
                    'caller': f['name'], 'callee': s['name'], 'group': g,
                    'how': s['how'],
                })

    violations.sort(key=lambda v: (v['file'], v['line']))
    return {
        'targets': targets, 'slots': slots, 'aliases': aliases,
        'wrappers_enter': wrapper_enter, 'wrappers_leave': wrapper_leave,
        'functions': len(funcs), 'files': [rel(p) for p in files],
        'violations': violations,
        # key 是 (文件, 函数, 起始行) 元组, 不能直接进 JSON -> 折成 "file:name:line"
        'requires': {'%s:%s:%d' % k: sorted(v) for k, v in requires.items() if v},
    }


def main(argv=None):
    ap = argparse.ArgumentParser(prog='window_check.py', add_help=True)
    ap.add_argument('--verbose', action='store_true', help='打印目标/别名/包装等中间结果')
    ap.add_argument('--json', dest='json_out', default=None, help='把结论写到 JSON')
    ap.add_argument('--selftest', action='store_true', help='内建负向/正向对照')
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    r = analyze(verbose=args.verbose)
    if args.verbose:
        print('加密目标 (%d):' % len(r['targets']))
        for n in sorted(r['targets']):
            print('   grp=%d %s' % (r['targets'][n], n))
        print('函数指针别名: %s' % (r['aliases'] or '(无)'))
        print('窗口包装: enter=%s leave=%s' % (r['wrappers_enter'], r['wrappers_leave']))
        print('作用域: %d 文件 / %d 函数' % (len(r['files']), r['functions']))
        print()

    print('[window_check] 作用域 %d 文件 / %d 函数; 加密目标 %d 个'
          % (len(r['files']), r['functions'], len(r['targets'])))
    if args.json_out:
        io.open(args.json_out, 'w', encoding='utf-8').write(
            json.dumps(r, ensure_ascii=False, indent=1))

    if not r['violations']:
        print('[window_check] PASS: 全部加密目标调用点都在配对 enter/leave 窗口内')
        return 0

    print('[window_check] FAIL: %d 处窗口外调用 (D2b 下执行的是密文)'
          % len(r['violations']))
    for v in r['violations']:
        print('  [X] %s:%d:%d  %s() 内调用 %s()  —— 缺组 %d(%s) 窗口 (%s)'
              % (v['file'], v['line'], v['col'], v['caller'], v['callee'],
                 v['group'], GROUP_NAMES.get(v['group'], '?'), v['how']))
    print('[window_check] 提示: 加密目标必须在 prot_selfcrypt_enter(G)/leave(G) 之间调用;'
          ' 若调用者本身是组 G 目标, 则责任在其调用者。')
    print('[window_check] 详见 docs/HANDOVER.md §2.16 与 src/integrity.c 的 T11 注释。')
    return 1


# --------------------------------------------------------------------------
def selftest():
    """对照: 合成片段上验证判据 (不依赖当前代码树状态)。"""
    import tempfile
    import shutil

    fails = []

    def case(name, ok):
        print('  %s %s' % ('ok  ' if ok else 'FAIL', name))
        if not ok:
            fails.append(name)

    targets = {'prot_antidebug_scan': 1, 'prot_vm_run': 0}

    def build(src):
        tmp = tempfile.mkdtemp(prefix='windowchk_')
        try:
            p = os.path.join(tmp, 't.c')
            io.open(p, 'w', encoding='utf-8').write(src)
            fs = parse_functions(p)
            we, wl = find_wrappers(fs, set(targets))
            al = find_fptr_aliases(strip_comments(src), set(targets))
            for f in fs:
                prepare(f, we, wl, al, {}, set(targets))
            return fs, we, wl, al
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    print('=== window_check selftest ===')

    # 1. 裸调用 -> 应被识别为"未在窗口内"
    fs, _, _, _ = build(
        'void f(void)\n{\n    prot_antidebug_scan(0);\n}\n')
    s = fs[0]['sites'][0]
    d = depth_at(fs[0], fs[0]['events'], s['line'], s['col'])
    case('裸调用无窗口', d.get(1, 0) == 0)

    # 2. 窗口内调用 -> 深度 > 0
    fs, we, wl, _ = build(
        'void f(void)\n{\n    prot_selfcrypt_enter(1);\n'
        '    prot_antidebug_scan(0);\n    prot_selfcrypt_leave(1);\n}\n')
    s = [x for x in fs[0]['sites'] if x['name'] == 'prot_antidebug_scan'][0]
    d = depth_at(fs[0], fs[0]['events'], s['line'], s['col'])
    case('窗口内调用深度为 1', d.get(1, 0) == 1)

    # 3. leave 之后 -> 深度回到 0 (T11 的形状)
    fs, _, _, _ = build(
        'void f(void)\n{\n    prot_selfcrypt_enter(1);\n'
        '    prot_selfcrypt_leave(1);\n    prot_antidebug_scan(0);\n}\n')
    s = [x for x in fs[0]['sites'] if x['name'] == 'prot_antidebug_scan'][0]
    d = depth_at(fs[0], fs[0]['events'], s['line'], s['col'])
    case('leave 之后调用深度为 0 (= T11 形状)', d.get(1, 0) == 0)

    # 4. 宿主包装识别 (sc_ext_enter -> 组 1)
    fs, we, wl, _ = build(
        'static prot_status sc_ext_enter(void) '
        '{ return prot_selfcrypt_enter(PROT_SELFCRYPT_GROUP_EXT); }\n'
        'static void sc_ext_leave(void) '
        '{ prot_selfcrypt_leave(PROT_SELFCRYPT_GROUP_EXT); }\n'
        'void f(void)\n{\n    sc_ext_enter();\n    prot_antidebug_scan(0);\n'
        '    sc_ext_leave();\n}\n')
    case('包装 enter 解析为组 1', we.get('sc_ext_enter') == 1)
    case('包装 leave 解析为组 1', wl.get('sc_ext_leave') == 1)
    f = [x for x in fs if x['name'] == 'f'][0]
    s = [x for x in f['sites'] if x['name'] == 'prot_antidebug_scan'][0]
    d = depth_at(f, f['events'], s['line'], s['col'])
    case('经包装的窗口内调用深度为 1', d.get(1, 0) == 1)

    # 5. 函数指针别名 (T11 的 g_ad_scan_fn 形状)
    fs, _, _, al = build(
        'typedef int (*scan_fn)(void*);\n'
        'static scan_fn volatile g_ad_scan_fn = prot_antidebug_scan;\n'
        'void f(void)\n{\n    g_ad_scan_fn(0);\n}\n')
    case('函数指针别名解析到目标',
         al.get('g_ad_scan_fn') == 'prot_antidebug_scan')
    s = [x for x in fs[0]['sites'] if x['name'] == 'prot_antidebug_scan'
         and x['how'].startswith('fptr:')]
    case('别名调用被当作目标调用', len(s) == 1)

    # 6. 注释里的调用不算 (缺陷 8 的教训)
    fs, _, _, _ = build(
        '/* prot_antidebug_scan(0); 这是注释里的示例 */\n'
        'void f(void)\n{\n    (void)0;\n}\n')
    case('注释中的调用被忽略',
         not [x for x in fs[0]['sites'] if x['name'] == 'prot_antidebug_scan'])

    # 7. 真实代码树: 作用域/目标清单非空
    #
    # **不硬编码目标数**(2026-10-05 修): 原为 `len(r['targets']) == 8` +
    #   `sorted(values) == [0,0,0,0,1,1,1,1]`。S1 把 `prot_revoke_check`
    #   补入 EXT_TARGETS(8 -> 9)后, 这两条自检即失效 —— 与
    #   `load_targets()` 存在的理由(§"单一事实来源, 不硬编码, 硬编码会在
    #   目标增删时静默失准")完全同型。改为**与源声明比对** + 只断言
    #   分组结构性质(非空、仅 0/1、两组都出现), 增删目标时自动跟随。
    r = analyze()
    _src = load_targets()
    case('目标清单与 selfcrypt_proto 声明一致',
         sorted(r['targets']) == sorted(_src))
    case('目标分组仅 0/1 且两组均非空',
         set(_src.values()) <= {0, 1} and 0 in _src.values()
         and 1 in _src.values())
    case('作用域含 demo 与 skeleton',
         any('demo/main.c' in f for f in r['files'])
         and any('prot_sdk/skeleton/app_main.c' in f for f in r['files']))

    print()
    if fails:
        print('[window_check-selftest] FAIL: %d 项' % len(fails))
        for f in fails:
            print('   - ' + f)
        return 1
    print('[window_check-selftest] PASS: 判据与解析均按预期')
    return 0


if __name__ == '__main__':
    sys.exit(main())
