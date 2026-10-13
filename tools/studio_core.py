#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/studio_core.py — Studio 的**纯逻辑层**（ST0.1，2026-10-09）。

## 先读这段再改
`docs/STUDIO_PLAN.md` §2 的**边界 1 = 后端先行**: 任何能力必须先能
**无头调用**并产出**机器可读**结果, UI 只是消费者。本模块就是那个"后端":
**零 UI、零全局状态**, 可 `import` 后在测试里直接调（同既有纪律:
`prot_sdk/wizard/prot_wizard.py` 的 docstring「核心函数与 GUI 解耦」）。

## 本模块**不重复实现**任何既有能力
它只做三件事:
  1. **收口** —— 把散落的 CLI 能力收成 python 函数（调既有实现, 不复制逻辑）
  2. **结构化** —— 把文本输出转成 JSON 可序列化的 dict（供面板消费）
  3. **统一契约** —— 统一错误形态（`StudioError`）+ 统一协议版本

  模块集求解   -> `tools/solve_profile.py` 的 `solve()`（**唯一实现**）
  依赖闭包/拓扑 -> `tools/compose.py` 的 `closure()` / `topo_order()`
  冲突检查      -> `tools/compat.py` 的 `check_conflicts()`
  模块契约      -> `modules.json`（**唯一真值源**）
  门禁静态清单  -> `tools/release_check.ps1` 的 `Check` 调用点
  受开关控制的项 -> `tools/doccheck.py` 的 `gated_check_names()`

## 为什么"不把常量抄进来"（§2.44.8 / §2.53 教训）
同一事实写在两处 -> 一处改了另一处**静默过期**, 且没有任何检查器会变红。
故本模块**运行时读** `modules.json` / `profiles/*.json` /
`tools/release_check.ps1`, 不把它们的值硬编码。沿用既有纪律:
`tools/genpaths.py` 是"生成物路径的单一来源", 本模块同理是
"Studio 能力清单的单一来源"。

## 用法（库）
    import studio_core as sc
    r = sc.dispatch('plan.solve', {'profile': 'balanced'})

## 诚实边界（**不得**在别处被读成"已实现"）
  · `debug.vm` 自 ST4 起为 `ready`（反汇编/单步/源码行号断点/视图）;
    主机级断点仍属 ST3, `ui` 仍属 ST5, **均未做**。
  · `gate.items` 读的是 `Check` 的**静态清单**, **不是运行结果**。
    运行结果机读化是 ST2 的范围（今天门禁结果只有 PowerShell 转录）。
  · 本模块**会**启动子进程（ST1 起 `build_events()` 跑 `build.ps1`, ST3 起 `_prot_dbg_run()` 跑 `prot_dbg.py`）。
    故"纯库、零 I/O 副作用"只对**查询类**命令成立 —— 那些命令（`ping`/`capabilities`/`plan.*`/`modules.list`/`gate.items`/`vm.*`/`test.gate.results`）确实不碰外部状态, 而 `build.run` / `debug.*` 会。这条区分是 ST3 之前写错的地方。
"""
import io
import itertools
import json
import os
import re
import struct
import sys
import threading

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, 'tools'))

#: NDJSON 协议版本（**改契约必须+1**; 客户端按它决定能否解析）
PROTOCOL_VERSION = 1
#: Studio 自身版本（**与构建产物版本无关**）
STUDIO_VERSION = '0.1.0'


class StudioError(Exception):
    """统一错误形态（供 NDJSON 出口序列化）。

    `code` 是**机读**的稳定标识（面板据此分支）; `message` 是给人读的;
    `detail` 承载上下文（哪个命令、哪个字段、候选值）。三者都必须可 JSON 序列化。
    """

    def __init__(self, code, message, detail=None):
        Exception.__init__(self, message)
        self.code = code
        self.message = message
        self.detail = detail

    def to_dict(self):
        return {'code': self.code, 'message': self.message,
                'detail': self.detail}


# --- 路径与读取（**全部运行时读, 不缓存**）---------------------------------

def read_json(path, what=None):
    """读一个 JSON 文件; 失败抛 `StudioError`（**不返回 None**）。

    为什么不静默返回 None: 面板拿到 None 会显示空列表, 与"文件真的空"
    无法区分 —— 正是本项目反复记名的"失锚不静默"。
    """
    if not os.path.isabs(path):
        path = os.path.join(REPO, path)
    if not os.path.exists(path):
        raise StudioError('E_NOT_FOUND', '%s 不存在' % (what or path),
                          {'path': path})
    try:
        with io.open(path, encoding='utf-8') as f:
            return json.load(f)
    except ValueError as e:
        raise StudioError('E_PARSE', '%s 解析失败: %s' % (what or path, e),
                          {'path': path})


def registry():
    """模块契约（`modules.json`）。**唯一真值源**, 不复制。"""
    return read_json('modules.json', '模块契约 modules.json')


def profile_names():
    """可用策略名（`profiles/*.json`, 去掉 `_` 前缀与 `_index.json`）。"""
    pdir = os.path.join(REPO, 'profiles')
    if not os.path.isdir(pdir):
        return []
    return sorted(f[:-5] for f in os.listdir(pdir)
                  if f.endswith('.json') and not f.startswith('_'))


def load_profile(name):
    """按名加载策略。名可带或不带 `.json`（**不猜路径**）。

    ⚠️ 类型守卫是**独立的**一步（自检实测）: 只判 `if not name` 会漏掉
    **非空非字符串**（如 `['balanced']`）—— 那种输入会走到 `name.endswith`
    抛 `AttributeError`, 出口变成 `E_INTERNAL`, 面板据此显示的就不是
    "你传错了参数"而是"Studio 内部故障"。两者必须区分。
    """
    if not isinstance(name, str):
        raise StudioError('E_BAD_ARGS', 'profile 必须是字符串',
                          {'given': name, 'type': type(name).__name__,
                           'available': profile_names()})
    if not name:
        raise StudioError('E_BAD_ARGS', 'plan.solve 需要 profile 名',
                          {'given': name, 'available': profile_names()})
    base = name[:-5] if name.endswith('.json') else name
    path = os.path.join(REPO, 'profiles', base + '.json')
    return read_json(path, '策略 %s' % base), base


# --- 门禁静态清单 ----------------------------------------------------------

def _gate_source():
    path = os.path.join(REPO, 'tools', 'release_check.ps1')
    if not os.path.exists(path):
        raise StudioError('E_NOT_FOUND', 'tools/release_check.ps1 不存在',
                          {'path': path})
    with io.open(path, encoding='utf-8-sig') as f:
        return f.read()


def gate_items():
    """门禁项的**静态**清单（名 + 行号 + 是否由 `-With*` 开关控制）。

    ⚠️ 这是**声明**, 不是**运行结果**。运行结果机读化属 ST2。

    「受开关控制」的集合**不在本文件里重新推导** —— 它与
    `tools/doccheck.py` 的结构派生（`gated_check_names`）必须一致,
    故直接复用它（单一实现）。它返回 None 表示该源文件含 here-string /
    块注释, 无法结构推导 —— 如实报 `gated: null` 而**不猜**。
    """
    src = _gate_source()
    items = []
    # ⚠️ `^\s*` 里的 `\s` **包含换行** —— 那样前导空行也进入匹配, `m.start()`
    #    落在空行上, 行号整体偏 1（实测 46 项里有 6 项指向的行根本没有 Check:
    #    295/304/1231/1285/1329 与另一处）。改成 `[ \t]*` 把换行排除。
    #    这条 off-by-one 一直没被发现, 是因为行号此前**没有任何消费者**;
    #    ST5.5 让面板拿它去跳转, 才有判据回源核对（见 selftest 的同名用例）。
    for m in re.finditer(r"(?m)^[ \t]*Check\s+'([^']+)'", src):
        items.append({'name': m.group(1),
                      'line': src[:m.start()].count('\n') + 1})

    gated = None
    why = None
    try:
        import doccheck as _dc
        _dc.REPO = REPO
        names = _dc.gated_check_names()
        if names is None:
            why = ('release_check.ps1 含 here-string 或块注释, '
                   'doccheck.gated_check_names() 无法结构推导')
        else:
            gated = sorted(names)
    except Exception as e:                                # pragma: no cover
        why = 'gated_check_names() 不可用: %s' % e

    if gated is not None:
        gs = set(gated)
        for it in items:
            it['gated'] = it['name'] in gs
    return {
        'items': items,
        'total': len(items),
        'gated': gated,
        'default': (len(items) - len(gated)) if gated is not None else None,
        'source': 'tools/release_check.ps1',
        'kind': 'static-declaration',   # ← 机读标注: **不是运行结果**
        'why_no_gated_breakdown': why,
    }


# --- 能力清单（**诚实边界所在**）-------------------------------------------

def capabilities():
    """Studio 后端各能力的**就绪度**。

    `ready` / `partial` / `planned` 三态, 每一项都带 `evidence`
    （可核查的落点, 不是形容词）。面板据 `status` 决定是否启用入口 ——
    **`planned` 的项不得渲染成可用**。
    """
    def cap(status, backend, evidence, note=None, **extra):
        d = {'status': status, 'backend': backend, 'evidence': evidence}
        if note:
            d['note'] = note
        d.update(extra)
        return d

    return {
        'protocol_version': PROTOCOL_VERSION,
        'studio_version': STUDIO_VERSION,
        'repo': REPO,
        'capabilities': {
            'generate.plan': cap(
                'ready', 'tools/solve_profile.py',
                'solve() 返回结构化计划（含每模块为何被选/被排除）',
                step='ST0'),
            'generate.modules': cap(
                'ready', 'modules.json',
                '13 个模块的 caps/deps/maturity/known_limits',
                step='ST0'),
            'test.gate.items': cap(
                'ready', 'tools/release_check.ps1',
                'Check 静态清单 + -With* 开关归属',
                step='ST0',
                note='这是**声明**不是**运行结果**'),
            'test.gate.results': cap(
                'ready', 'tools/gate_results.py',
                '门禁结果历史（NDJSON）: latest / list / verify / diff / trend',
                step='ST2',
                note='verify 读**实际日志行**做独立对账, 不信任门禁自己的计数器'),
            'generate.build': cap(
                'partial', 'tools/studio_core.py',
                'build_events() 流式事件（plan/line/exit/done）；'
                '**默认不启动** —— 需 confirm: true',
                step='ST1',
                note='不带 confirm 只回计划: 一次完整构建是分钟级副作用操作; '
                     'config 取 ' + ' / '.join(BUILD_CONFIGS) +
                     '（Debug 产物入 build/debug, 发布产物不受影响）'),
            'generate.graph': cap(
                'ready', 'tools/compose.py + tools/compat.py',
                '依赖闭包 + 拓扑序 + 冲突边（复用, 不重写）',
                step='ST1'),
            'debug.host': cap(
                'partial', 'tools/prot_dbg.py',
                '只读: doctor/sym/mask/exit（ST3.1, 零进程）；'
                '活体: read/patch/watch/stack（ST3.3 + ST5.4b, 需 confirm）—— '
                '宿主侧仍**无断点/单步/反汇编**',
                step='ST3',
                note='工具自身 OpenProcess 可能触发目标反调试（实测 219）; '
                     '每条活体响应都带 antidebug_interference 机读字段（ST3.4）。'
                     '`debug.stack` 自 ST5.4b 起可用 —— 判据是**栈扫描 + '
                     '`call` 判别**，不是 Windows unwind；每股带 '
                     'reliable/dirty_reason，不完整时如实标注。'),
            'debug.stack': cap(
                'partial', 'tools/prot_dbg.py:cmd_stack',
                '宿主侧调用栈：按线程枚举（Toolhelp32）+ 取上下文'
                '（SuspendThread/GetThreadContext）+ 分块扫栈 + `call` 判别；'
                'map 符号化，每股带 reliable/dirty_reason',
                step='ST5.4b',
                note='**不是** Windows 官方展开（is_windows_unwind=false）：'
                     '没有 unwind 解释器，只认「前一指令是 call」的返回地址 —— '
                     '**宁可少报，不可错报**（一张错的调用栈会被当成证据，'
                     '与 VM 侧 call_stack 同一契约）。已知假阴性：'
                     '栈上被内联/尾部调用消除的帧、以及非 call 返回的帧。'),
            'debug.vm': cap(
                'ready', 'tools/vm_debug.py',
                '反汇编(含真实镜像 key1 逆置换) / 单步 / 源码行号断点 / 栈+寄存器'
                '视图 / 源码高亮 / 调试会话(继续·单步·步过·重启) / 影子调用栈',
                step='ST4',
                note='ST4.1 的 .vasm 行号表是 sidecar, 发布产物不携带。'
                     '主机级断点仍属 ST3（未做）。ST5.4 的会话活在**服务进程内**。'),
            'ui.jump': cap(
                'ready', 'tools/studio_core.py:cmd_src_show',
                '问题/门禁结果逐项带 src+src_line（join 声明行）, '
                'src.show 只读定位到行并高亮',
                step='ST5.5',
                note='落点是 release_check.ps1 的 `Check` 声明行, 不是失败'
                     '现场的行 —— 证据原文里没有 file:line（实测历史日志 '
                     '非 [ok] 行 6495 条, 含 file:line 的 0 条）'),
            'ui': cap(
                'ready', 'tools/studio_server.py + studio/',
                '本地浏览器外壳（零依赖, 只绑 127.0.0.1, 一次性令牌）: '
                '生成/测试/VM/主机/模块/关于 六视图',
                step='ST5',
                note='VM 视图自 ST5.3/ST5.4 起支持源码高亮 + 行号 + 断点槽 + '
                     '调试工具条 + 调用栈（会话活在**服务进程内**）; '
                     '自 ST5.5 起问题面板可点击跳转到源码行'),
        },
    }


# --- 命令实现 --------------------------------------------------------------

GATE_QUERIES = ('latest', 'list', 'verify', 'diff', 'trend')


def cmd_test_gate_results(args):
    """门禁结果的**历史查询**（ST2.3 / ST2.4）。

    复用 `tools/gate_results.py` —— 那是门禁日志解析的**唯一实现**。
    这里不重写解析: 重写会漂移成两套口径, 而漂移的那一套会安静地给出
    另一组数字（同 `vm_reduce.py` 与 `vm_debug.py` 的教训）。

    query 取值（缺省 `latest`）:
      latest  最近一轮已完成的结果（逐项）
      list    发现的轮次（含"只有 .log、没有 .ndjson"的历史轮次）
      verify  文本出口 vs NDJSON 出口**逐项**对账（独立于门禁自己的对照）
      diff    两次运行的差异（需 a / b 参数）
      trend   历次运行的通过数时间线
    """
    import gate_results as _gr

    q = args.get('query') or 'latest'
    if not isinstance(q, str):
        raise StudioError('E_BAD_ARGS', 'query 必须是字符串',
                          {'given': type(q).__name__, 'available': list(GATE_QUERIES)})
    if q not in GATE_QUERIES:
        raise StudioError('E_BAD_ARGS', 'query 取值非法',
                          {'given': q, 'available': list(GATE_QUERIES)})
    log_dir = args.get('dir') or _gr.LOG_DIR
    if not os.path.isdir(log_dir):
        raise StudioError('E_NOT_FOUND', '日志目录不存在', {'dir': log_dir})

    def _stem(spec):
        p = spec if os.path.isabs(spec) else os.path.join(log_dir, spec)
        for ext in ('.log', '.ndjson'):
            if p.endswith(ext):
                p = p[:-len(ext)]
        return p

    if q == 'list':
        rows = []
        for stem in _gr.discover(log_dir):
            r = _gr.load_run(stem, log_dir)
            rows.append({'run': r['name'], 'log': bool(r.get('log')),
                         'ndjson': bool(r.get('ndjson')),
                         'done': bool(r.get('done', False)),
                         'load_errors': r.get('load_errors') or []})
        return {'query': q, 'dir': log_dir, 'runs': rows, 'count': len(rows)}

    if q == 'trend':
        rows = _gr.trend(_gr.discover(log_dir), log_dir)
        rows.reverse()
        return {'query': q, 'dir': log_dir, 'trend': rows, 'count': len(rows)}

    if q == 'diff':
        a, b = args.get('a'), args.get('b')
        if not a or not b:
            raise StudioError('E_BAD_ARGS', 'diff 需要 a 与 b 两个轮次名',
                              {'a': a, 'b': b})
        ra, rb = _gr.load_run(_stem(a), log_dir), _gr.load_run(_stem(b), log_dir)
        changes, summ = _gr.diff_runs(ra, rb)
        return {'query': q, 'a': ra['name'], 'b': rb['name'],
                'changes': changes, 'summary': summ, 'count': len(changes)}

    if q == 'verify':
        spec = args.get('run')
        run = _gr.load_run(_stem(spec), log_dir) if spec else _gr.pick_latest(log_dir)
        if run is None:
            raise StudioError('E_NOT_FOUND',
                              '找不到同时有 .log 与 .ndjson 的轮次 —— 无法对账',
                              {'dir': log_dir,
                               'hint': 'ST2.1 之前的历史轮次只有 .log; 这是诚实边界'})
        ok, problems, info = _gr.verify_run(run)
        return {'query': q, 'ok': ok, 'info': info, 'problems': problems}

    # latest（默认）
    run = _gr.pick_latest(log_dir)
    if run is None:
        raise StudioError('E_NOT_FOUND',
                          '找不到同时有 .log 与 .ndjson 的轮次',
                          {'dir': log_dir,
                           'hint': 'ST2.1 之前的历史轮次只有 .log; 这是诚实边界, 不是缺陷'})
    # ST5.5: 逐项附上**可跳转的落点**。键是 `name`, 不是序号 ——
    # 声明与结果两侧都按名字来（实测历史 868 条 NDJSON 行 100% 能 join 回
    # 声明）, 序号只在各自文件里连续, 跨文件没有意义。
    decl = {it['name']: it['line'] for it in gate_items()['items']}
    items = []
    for r in (run.get('rows') or []):
        nm = r.get('name')
        items.append({'seq': r.get('seq'), 'name': nm,
                      'status': r.get('status'), 'seconds': r.get('seconds'),
                      'why': r.get('why'),
                      # 跳转落点: 声明行（`Check '...'` 在 release_check.ps1 里）。
                      # join 不上就**如实给 None** —— 猜一个行号比不给更糟:
                      # 面板会稳定地跳到错误的位置, 而那个位置总是"有内容"。
                      'src': 'tools/release_check.ps1' if nm in decl else None,
                      'src_line': decl.get(nm)})
    return {'query': 'latest', 'run': run['name'],
            'pass_n': run.get('pass_n'),
            'counts_text': run.get('counts_text'),
            'counts_json': run.get('counts_json'),
            'jump_unresolved': sorted(n for n in
                                      (r.get('name') for r in (run.get('rows') or []))
                                      if n not in decl),
            'items': items,
            'count': len(run.get('rows') or [])}



# --- 源码定位（ST5.5: 问题面板点击跳转的落点）-------------------------------

#: `src.show` 一次返回的最大行数（面板要上下文, 不是整文件）
SRC_WINDOW_MAX = 400
#: `src.show` 默认上下各取多少行
SRC_CONTEXT = 12


def _safe_repo_path(path):
    """把 `rel` 解析成 **REPO 内** 的绝对路径；越界一律拒绝（返回 (ap, rel)）。

    与 `tools/studio_server.py:safe_join()` 同一套四步（归一 → normpath →
    realpath → 前缀比对），但**刻意不共用实现**：那个函数服务静态资产，
    越界对它的正确读法是"资源不存在"；这里服务源码定位，越界必须报
    `路径在仓库之外` —— 否则面板会把"你让我读仓库外的任意路径"显示成
    "文件不存在"，而排查会去查文件名拼写。
    """
    if not isinstance(path, str) or not path.strip():
        raise StudioError('E_BAD_ARGS', '需要 path 参数（仓库内相对路径）',
                          {'given': path, 'type': type(path).__name__})
    p = path.replace('\\', '/').strip().lstrip('/')
    root = os.path.realpath(REPO)
    ap = os.path.realpath(os.path.join(root, p))
    if ap != root and not ap.startswith(root + os.sep):
        raise StudioError('E_BAD_ARGS', '路径在仓库之外', {'given': path})
    if not os.path.isfile(ap):
        raise StudioError('E_NOT_FOUND', '文件不存在',
                          {'path': os.path.relpath(ap, root).replace('\\', '/')})
    return ap, os.path.relpath(ap, root).replace('\\', '/')


def _int_arg(args, key, default=0):
    """取一个整数参数 —— 类型错时报**参数错**, 不让 `ValueError` 逃出去。

    裸 `int(args.get(...))` 会把 `'x'` 变成 `ValueError`。那个异常不是
    `StudioError`, envelope 会把它归类成 `E_INTERNAL` —— 面板于是显示
    "Studio 内部故障", 而正确读法是"我传错了参数"。
    """
    v = args.get(key, default)
    if v is None:
        return default
    if isinstance(v, bool) or not isinstance(v, int):
        try:
            return int(v)
        except (TypeError, ValueError):
            raise StudioError('E_BAD_ARGS', '%s 必须是整数' % key,
                              {'given': v, 'type': type(v).__name__})
    return v


def cmd_src_show(args):
    """读仓库内某个**文本文件**的一段行（ST5.5 的跳转落点）。

    与 `vm.source` 的分工: 那个只认 `.vasm`, 给的是高亮/断点语义; 这个是
    **通用只读定位** —— 门禁失败项指向的是 `tools/release_check.ps1` 里的
    `Check` 行, 不是 `.vasm`。

    三处刻意的设计:

    - **必须回报 `total`**。只返回窗口时, "文件只有 25 行"与"我只给了 25 行"
      在响应里长得一样; 面板会把截断显示成文件结尾。
    - **`hit` 由服务端算**, 不让前端拿 `line` 自己比 —— 前端比错的后果是
      "高亮错行", 而那看起来像文件内容错了。
    - **二进制不当成错误**, 如实标 `binary: True` 并**不返回 lines**:
      门禁也可能指向 `.ndjson`/`.log` 之类的产物, 报错会让跳转在这些项上
      直接失效, 而正确行为是"打开了, 但这不是文本"。
    """
    ap, rel = _safe_repo_path(args.get('path'))
    line = _int_arg(args, 'line', 0)
    ctx = _int_arg(args, 'context', SRC_CONTEXT)
    if ctx < 0:
        raise StudioError('E_BAD_ARGS', 'context 不能为负', {'given': ctx})

    data = io.open(ap, 'rb').read()
    binary = b'\x00' in data[:4096]
    text = data.decode('utf-8-sig', 'replace')
    rows = text.split('\n')
    if rows and rows[-1] == '':
        rows = rows[:-1]
    total = len(rows)

    if line < 0:
        raise StudioError('E_BAD_ARGS', 'line 不能为负', {'given': line})
    if line > total:
        # 越界**如实报**, 不夹到末尾 —— 夹住会让"行号过期"看起来像"读到了"。
        raise StudioError('E_NOT_FOUND',
                          'line %d 超出 %s 的行数 %d' % (line, rel, total),
                          {'path': rel, 'line': line, 'total': total})
    if line == 0:
        start, hit = 1, 0          # 不带行号 = 从文件头开始, 不高亮任何行
    else:
        start, hit = max(1, line - ctx), line
    end = min(total, (line or 1) + ctx)
    window = rows[start - 1:end]
    truncated = len(window) > SRC_WINDOW_MAX
    if truncated:
        window = window[:SRC_WINDOW_MAX]
        end = start + SRC_WINDOW_MAX - 1

    out = {'path': rel,
           'abs': ap,
           'line': hit,
           'start': start,
           'end': end,
           'total': total,
           'truncated': truncated,
           'window_max': SRC_WINDOW_MAX,
           'binary': binary,
           'backend': 'tools/studio_core.py:cmd_src_show'}
    if not binary:
        out['lines'] = [{'n': start + i, 'text': s, 'hit': (start + i) == hit}
                        for i, s in enumerate(window)]
    return out


def cmd_ping(args):
    """最小握手: 客户端用它确认协议版本与仓库位置。"""
    return {'protocol_version': PROTOCOL_VERSION,
            'studio_version': STUDIO_VERSION,
            'repo': REPO,
            'platform': 'win' if os.name == 'nt' else 'linux',
            'python': sys.version.split()[0]}


def cmd_capabilities(args):
    """Studio 各能力的**现状与边界**（ready / partial / planned, 含为什么）。"""
    return capabilities()


def cmd_plan_list(args):
    """列出可用策略（profiles/*.json 的元数据；坏掉的策略标注 broken 而非隐藏）。"""
    out = []
    for n in profile_names():
        try:
            p = read_json(os.path.join('profiles', n + '.json'))
        except StudioError:
            # 单个策略坏掉不应让整个列表消失 —— 但要**如实标注**。
            out.append({'name': n, 'broken': True})
            continue
        out.append({'name': n,
                    'description': p.get('description', ''),
                    'threats': p.get('threats', []),
                    'strength': p.get('strength'),
                    'performance_budget': p.get('performance_budget')})
    return {'profiles': out, 'count': len(out)}


def cmd_plan_solve(args):
    """策略 -> 结构化构建计划（复用 `solve_profile.solve`, **不重写**）。"""
    import solve_profile as _sp
    prof, name = load_profile(args.get('profile'))
    reg = registry()
    r = _sp.solve(prof, reg)
    # 附上渲染好的文本计划: 面板既能画图, 也能原样显示（**同一份真值**）
    r = dict(r)
    r['_profile_file'] = 'profiles/%s.json' % name
    r['_text'] = _sp.fmt_plan(r, verbose=bool(args.get('verbose', True)))
    return r


def cmd_modules_list(args):
    """列出模块契约（读 `modules.json`; 含成熟度/依赖/冲突/成本, **不重写注册表**）。"""
    reg = registry()
    mods = reg.get('modules', {})
    out = []
    for n, m in sorted(mods.items()):
        out.append({
            'name': n,
            'maturity': m.get('maturity'),
            'caps': sorted(m.get('caps', [])),
            'deps': sorted(m.get('deps', [])),
            'conflicts_with': sorted(m.get('conflicts_with', []) or []),
            'cost': None,                    # 由 solve_profile.COST 提供
            'header': m.get('header'),
            'source': m.get('source'),
            # ST1.3: 面板要显示"这个模块的边界在哪", 而不只是 id 与依赖。
            # 缺 `known_limits` 会让 UI 把每个模块都渲染成"无已知局限" ——
            # 那是**静默的谎**, 比不显示更坏(项目的 P4 诚实边界纪律)。
            'known_limits': list(m.get('known_limits', []) or []),
            'evidence': list(m.get('evidence', []) or []),
            'ordering': m.get('ordering') or {},
            'phases': list(m.get('phases', []) or []),
            'consumes': list(m.get('consumes', []) or []),
            'produces': list(m.get('produces', []) or []),
            'modifies_text': bool(m.get('modifies_text', False)),
            'verifies_text': bool(m.get('verifies_text', False)),
            'needs_writable_dir': bool(m.get('needs_writable_dir', False)),
            'page_align': m.get('page_align'),
            'host_hooks': list(m.get('host_hooks', []) or []),
            'abi_version': m.get('abi_version'),
        })
    try:
        import solve_profile as _sp
        for it in out:
            it['cost'] = _sp.COST.get(it['name'], 'low')
    except Exception:
        pass                                  # 成本是附加信息, 缺失不致命
    return {'modules': out, 'count': len(out),
            'primitives': sorted(reg.get('primitives', {})),
            'maturity_scale': reg.get('_maturity_scale') or {},
            'protocol_version': reg.get('_protocol_version'),
            'format_version': reg.get('_format_version'),
            'source': 'modules.json'}


def cmd_plan_graph(args):
    """依赖闭包 + 拓扑序 + 冲突边（ST1.4）。

    ## 三个复用, 一个都不重写
      · 依赖闭包 -> `tools/compose.py` 的 `closure()`
      · 拓扑排序 -> `tools/compose.py` 的 `topo_order()`（**返回 (order, cycle)**,
        不是列表 —— 把它当列表用会拿到元组, 且 `cycle` 那一半永远看不到）
      · 冲突检测 -> `tools/compat.py` 的 `check_conflicts()`（**返回四元组**
        (errors, warnings, infos, conflicts), 冲突在**第 4 个**位置）

    参数: `profile`（策略名, 走 solve_profile 求解）或 `modules`（模块名列表）。
    两者都给时 `modules` 优先 —— 面板里"手动改过之后再画图"是常见动作。
    """
    import compose as _cp
    import compat as _compat

    reg = registry()
    names = args.get('modules')
    if names is None:
        prof = args.get('profile')
        if not prof:
            raise StudioError('E_BAD_ARGS', '需要 profile 或 modules 之一',
                              {'available_profiles': profile_names()})
        if not isinstance(prof, str):
            raise StudioError('E_BAD_ARGS', 'profile 必须是字符串',
                              {'given': type(prof).__name__})
        import solve_profile as _sp
        # load_profile 返回**元组** (profile_dict, base_name) —— 不是 dict。
        # 直接 `_sp.solve(load_profile(x), reg)` 会把元组喂进 solve, 报
        # `AttributeError: 'tuple' object has no attribute 'get'`, 且错在
        # solve_profile 内部, 看起来像那边坏了。
        pf, _pfname = load_profile(prof)
        r = _sp.solve(pf, reg)
        names = list(r.get('selected') or [])
        src = {'kind': 'profile', 'profile': _pfname,
               'profile_file': 'profiles/%s.json' % _pfname}
    else:
        if not isinstance(names, (list, tuple)) or not all(
                isinstance(x, str) for x in names):
            raise StudioError('E_BAD_ARGS', 'modules 必须是字符串列表',
                              {'given': type(names).__name__})
        names = list(names)
        src = {'kind': 'modules'}

    if not names:
        # 两种情况**必须分开**:
        #   · `modules: []`  -> 调用方确实什么都没给 => 参数错误
        #   · `profile` 解得 0 个模块 -> **合法结果**(实测
        #     profiles/minimal-cost.json 就是: threat `piracy` 推导所需能力
        #     `respond`, 而没有任何模块提供它) => 返回空图 + 说明原因。
        # 把它报成参数错误会让面板说"你传错了参数", 而真相是
        # "这个策略什么都不选" —— 后者才是用户需要看见的信息。
        if src['kind'] == 'profile':
            return {'source': src, 'requested': [], 'selected': [],
                    'auto_added': [], 'nodes': [], 'edges': [],
                    'order_edges': [], 'topo': [], 'cycle': [],
                    'conflicts': [], 'errors': [], 'warnings': [], 'infos': [],
                    'topo_dep_violations': [],
                    'relations': {},
                    'notes': ['策略 %r 求解出 **0 个模块** —— 这是求解器的'
                              '**合法结果**, 不是错误。'
                              '常见原因: 该策略声明的威胁推导出的所需能力'
                              '没有任何模块提供(或全部被策略约束排除)。'
                              '用 plan.solve 看逐模块的排除理由。' % src['profile']],
                    'backend': 'tools/compose.py + tools/compat.py'}
        raise StudioError('E_BAD_ARGS', 'modules 是空列表 —— 没有模块可画',
                          {'modules': names})

    known = set(reg.get('modules', {})) | set(reg.get('primitives', {}))
    unknown = sorted(set(names) - known)
    if unknown:
        raise StudioError('E_BAD_ARGS', '含未登记模块',
                          {'unknown': unknown, 'known_count': len(known)})

    full = sorted(_cp.closure(names, reg))
    order, cycle = _cp.topo_order(full, reg)
    errors, warnings, infos, conflicts = _compat.check_conflicts(reg, set(full))

    mods = reg.get('modules', {})
    edges = []
    for n in full:
        for d in mods.get(n, {}).get('deps', []):
            if d in full:
                edges.append({'from': d, 'to': n, 'kind': 'dep',
                              'relation': 'dep'})
    # 冲突边**直接来自 check_conflicts 的结论**, 不从注册表自己推。
    # 实测教训: integrity/selfcrypt 同时有两条冲突 —— `kind='declared'`
    # (声明冲突: integrity 校验 .text 而 selfcrypt 原地改写) 与
    # `kind='derived'`(派生冲突: 两者都要求页对齐)。若按**模块对**去重,
    # 派生冲突会被整条吞掉, 而图上就只剩一条线 —— 面板据此会以为
    # "只有一处冲突"。故按 (a, b, kind) 去重。
    seen_c = set()
    for c in conflicts:
        key = (c.get('a'), c.get('b'), c.get('kind'))
        if key in seen_c:
            continue
        seen_c.add(key)
        edges.append({'from': c.get('a'), 'to': c.get('b'),
                      'kind': 'conflict', 'relation': 'conflict',
                      'conflict_kind': c.get('kind'),
                      'reason': c.get('reason'),
                      'resolution': c.get('resolution'),
                      'severity': c.get('severity')})

    # 链接顺序边: 来自 `ordering.after`/`before` —— **这才是 topo 遵循的关系**。
    # 与 `edges` 的 dep 边语义不同(见 `relations`), 故分开给。
    # 同一约束常被两侧各说一遍(`vm.before=[blob]` 与
    # `blob.ordering.after=[vm]`)⇒ 必须按 (from,to) **去重**, 否则
    # 面板会画 5 条箭头表示 3 个约束(实测 paranoid-analysis: decl=3 out=5)。
    order_edges, _seen_oe = [], set()
    for n in full:
        o = mods.get(n, {}).get('ordering') or {}
        for x in (o.get('after') or []):
            if x in full and (x, n) not in _seen_oe:
                _seen_oe.add((x, n))
                order_edges.append({'from': x, 'to': n, 'relation': 'order'})
        for y in (o.get('before') or []):
            if y in full and (n, y) not in _seen_oe:
                _seen_oe.add((n, y))
                order_edges.append({'from': n, 'to': y, 'relation': 'order'})

    # 如实列出"按 topo 排列时方向相反的 dep 边" —— **不是错误**, 是这条
    # 语义差异的机读证据(每个组合实测都有 2 条: selfcrypt->integrity,
    # syscall->antidebug)。面板据此可以只显示其中一张图, 或并排显示。
    _pos = {n: i for i, n in enumerate(order)}
    dep_violations = [{'from': e['from'], 'to': e['to']}
                      for e in edges if e['kind'] == 'dep'
                      and _pos.get(e['from'], -1) > _pos.get(e['to'], -1)]

    return {'source': src, 'requested': sorted(names), 'selected': full,
            'order_edges': order_edges,
            'topo_dep_violations': dep_violations,
            'relations': {
                'dep': '能力依赖(运行时): 本模块需要对方的**运行时能力**。'
                       '**不决定链接顺序。**',
                'order': '链接顺序: 来自 ordering.after/before。'
                         'topo 只遵循这一种关系。',
                'conflict': '冲突(声明 + 派生), 见 conflicts。',
                'why_not_mixed':
                    '两种关系语义不同, 混在一张图里会产生**假环**。'
                    'compose.topo_order 的注释逐字记录了 2026-09-23 的实测: '
                    'integrity.deps 含 selfcrypt(需其掩码豁免) 而 '
                    'selfcrypt.ordering.after 含 integrity(链接顺序) -> '
                    '报"环"。故本响应把两者分开, 并把方向相反的 dep 边'
                    '如实列在 topo_dep_violations 里 —— 那不是错误。',
            },
            'auto_added': sorted(set(full) - set(names)),
            'nodes': [{'name': n,
                       'maturity': mods.get(n, {}).get('maturity'),
                       'modifies_text': bool(mods.get(n, {}).get('modifies_text', False)),
                       'verifies_text': bool(mods.get(n, {}).get('verifies_text', False)),
                       'is_primitive': n not in mods}
                      for n in full],
            'edges': edges,
            'topo': list(order), 'cycle': list(cycle),
            'conflicts': [{'kind': c.get('kind'), 'a': c.get('a'), 'b': c.get('b'),
                           'reason': c.get('reason'), 'resolution': c.get('resolution'),
                           'severity': c.get('severity')} for c in conflicts],
            'errors': list(errors), 'warnings': list(warnings), 'infos': list(infos),
            'backend': 'tools/compose.py + tools/compat.py'}


# 流式命令: 不在 COMMANDS 里 —— 它们**一个请求产出多行响应**, 形态不同。
STREAM_COMMANDS = ('build.run', 'debug.watch')

# build.ps1 的失败诊断首行判据（与 build.ps1 自己的 "build FAILED:" 措辞对齐,
# 但不依赖它: 有些失败是 PowerShell 自己的错误记录, 形如 "... : 消息"）。
_BUILD_DIAG = re.compile(
    r'(?i)build FAILED|FAILED:|error|错误|异常|Exception|cannot|failed')


# build.ps1 -Config 的三个取值（ST3.2 起）。**这是唯一清单** —— 面板的下拉框
# 与这里的元组必须一致, 否则 ST3.2 的 Debug 构建从 Studio 里根本调不到,
# 而那种缺口不会让任何判据变红（面板只是少一个选项）。
BUILD_CONFIGS = ('Dev', 'Release', 'Debug')


def build_argv(args):
    """把参数翻成 build.ps1 的命令行（**只拼装, 不执行**; 便于面板先展示）。

    三态与 build.ps1 自己的校验 (`-Config must be Dev, Release or Debug`)
    逐字一致 —— 面板报 `E_BAD_ARGS` 时必须与 CLI 报的是同一件事,
    两处各写一套取值就会出现「CLI 能跑、面板说参数错」。
    """
    cfg = args.get('config') or 'Dev'
    if cfg not in BUILD_CONFIGS:
        raise StudioError('E_BAD_ARGS', 'config 必须是 %s' % ' / '.join(BUILD_CONFIGS),
                          {'given': cfg, 'allowed': list(BUILD_CONFIGS)})
    argv = ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', os.path.join(REPO, 'build.ps1'), '-Config', cfg]
    if args.get('composition'):
        argv += ['-Composition', str(args['composition'])]
    if args.get('machine_id'):
        argv += ['-MachineId', str(args['machine_id'])]
    if args.get('user_id'):
        argv += ['-UserId', str(args['user_id'])]
    if args.get('seeds_file'):
        argv += ['-SeedsFile', str(args['seeds_file'])]
    for k, flag in (('skip_smoke', '-SkipSmoke'), ('no_d2b', '-NoD2b'),
                    ('skip_sign', '-SkipSign')):
        if args.get(k):
            argv.append(flag)
    return argv


def build_events(args):
    """流式构建（ST1.2）—— **生成器**, 逐条 yield 事件 dict。

    诚实设计（读这段再改）:

    1. **不带 `confirm: true` 就只给计划, 不启动构建。** 一次完整构建是分钟级
       的副作用操作, 而 `build.ps1` 会**改写 build/ 下的产物**。让一个面板
       点击直接触发它, 与项目的"先计划后执行"纪律相反。故默认 `plan_only`,
       要真跑必须显式 `confirm`。
    2. **失败必须带诊断首行**。退出码 1 本身对面板没有信息量;
       故扫描输出, 取第一个像诊断的行一并回传（找不到就如实说找不到,
       **不编造**）。
    3. 进程用 `stderr=STDOUT` 合并 —— 实测 PowerShell 的原生命令错误走 stderr,
       而 `build.ps1` 的自述进度走 stdout; 分开读会让事件顺序错乱。
    """
    import subprocess

    argv = build_argv(args)
    yield {'event': 'plan', 'argv': argv, 'cwd': REPO,
           'confirm_required': not bool(args.get('confirm'))}

    if not args.get('confirm'):
        yield {'event': 'done', 'started': False,
               'note': '未启动构建（需要 confirm: true）—— 这是刻意的安全默认'}
        return

    yield {'event': 'start', 'argv': argv}
    p = subprocess.Popen(argv, cwd=REPO, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    diag = None
    n_lines = 0
    try:
        for bline in p.stdout:
            line = bline.decode('utf-8', 'replace').rstrip('\r\n')
            if not line.strip():
                continue
            n_lines += 1
            if diag is None and _BUILD_DIAG.search(line):
                diag = line.strip()
            tag = None
            if line.startswith('build: '):
                tag = 'build'
            yield {'event': 'line', 'text': line, 'tag': tag}
    finally:
        p.stdout.close()
        rc = p.wait()
    yield {'event': 'exit', 'rc': rc, 'lines': n_lines,
           'first_diag': diag}
    yield {'event': 'done', 'started': True, 'ok': rc == 0, 'rc': rc,
           'first_diag': diag}



def cmd_gate_items(args):
    """列出 `tools/release_check.ps1` 的**静态** Check 清单（声明, 不是运行结果）。"""
    return gate_items()


def cmd_vm_images(args):
    """列出 vm.blob 里的镜像（名/长度/种子/CRC; 调试入口的索引）。"""
    import vm_reduce as _vr
    blob = args.get('blob') or os.path.join(REPO, 'build', 'vm.blob')
    if not os.path.exists(blob):
        raise StudioError('E_NOT_FOUND', 'vm.blob 不存在', {'blob': blob})
    data = io.open(blob, 'rb').read()
    if data[:8] != b'PROTVMB1':
        raise StudioError('E_PARSE', '不是 v1 blob (magic=%r)' % data[:8],
                          {'blob': blob})
    count = struct.unpack_from('<I', data, 8)[0]
    pos = 12
    out = []
    for _ in range(count):
        nm = data[pos:pos + 16].split(b'\x00', 1)[0].decode('ascii')
        code_len = struct.unpack_from('<I', data, pos + 16)[0]
        key0 = struct.unpack_from('<Q', data, pos + 20)[0]
        key1 = struct.unpack_from('<Q', data, pos + 28)[0]
        crc = struct.unpack_from('<I', data, pos + 36)[0]
        out.append({'name': nm, 'code_len': code_len,
                    'key0': '0x%016x' % key0, 'key1': '0x%016x' % key1,
                    'crc': '0x%08x' % crc, 'offset': pos})
        pos += 40 + code_len
    return {'blob': blob, 'count': len(out), 'images': out,
            'backend': 'tools/vm_debug.py'}


def cmd_vm_disasm(args):
    """反汇编一个镜像或一个 `.vasm`（调试器入口）。

    `source='blob'` 走**真实产物**路径（key1 逆置换）;
    `source='asm'` 就地汇编 `.vasm`（规范 opcode, 不需要种子）。
    """
    import vm_debug as _vd
    where = args.get('source', 'blob')
    if where not in ('blob', 'asm'):
        raise StudioError('E_BAD_ARGS', "source 必须是 'blob' 或 'asm'",
                          {'given': where})
    if where == 'asm':
        path = args.get('asm')
        if not path:
            raise StudioError('E_BAD_ARGS', "source='asm' 需要 asm 参数",
                              {'given': args})
        ap = path if os.path.isabs(path) else os.path.join(REPO, path)
        if not os.path.exists(ap):
            raise StudioError('E_NOT_FOUND', '.vasm 不存在', {'asm': ap})
        try:
            code, off_to_line, _info = _vd.load_from_asm(ap)
        except Exception as e:                              # noqa: BLE001
            raise StudioError('E_PARSE', '汇编失败: %s' % e, {'asm': ap})
        key1 = None
        src = path
    else:
        name = args.get('name')
        blob = args.get('blob') or os.path.join(REPO, 'build', 'vm.blob')
        if not name:
            raise StudioError('E_BAD_ARGS', "source='blob' 需要 name 参数",
                              {'given': args})
        try:
            code, key1, _k0, _crc = _vd.load_from_blob(blob, name)
        except Exception as e:                              # noqa: BLE001
            raise StudioError('E_NOT_FOUND',
                              '取镜像 %r 失败: %s' % (name, e),
                              {'blob': blob, 'name': name})
        off_to_line = {}
        src = '%s:%s' % (os.path.relpath(blob, REPO).replace('\\', '/'), name)
    try:
        insns, sem0 = _vd.disassemble(code, key1)
    except Exception as e:                                  # noqa: BLE001
        raise StudioError('E_PARSE', '反汇编失败: %s' % e, {'src': src})
    for r in insns:
        r['line'] = off_to_line.get(r['off'])
    return {'source': src, 'code_len': len(code), 'count': len(insns),
            'sem0': sem0, 'has_lines': bool(off_to_line),
            'insns': insns}


# --- 主机级调试（ST3：包装 tools/prot_dbg.py）-------------------------------

PROT_DBG = os.path.join(REPO, 'tools', 'prot_dbg.py')

#: prot_dbg 的只读子命令（第 1 步，**零进程**：不 OpenProcess、不 attach）
DBG_READONLY = ('doctor', 'sym', 'mask', 'exit')
#: prot_dbg 的活体子命令（第 2 步，会**拉起或附着**目标进程）
DBG_LIVE = ('read', 'patch', 'watch')


def _prot_dbg_run(cli, timeout=120.0):
    """跑一次 `tools/prot_dbg.py` 并取回它的 `--json` 产物。

    为什么走**子进程 + --json** 而不是 import 它的内部函数:

    1. **唯一实现路径。** 参数拼装、错误码解释、符号解析、掩码归属判定
       都已经在 `prot_dbg.py` 里写过一遍。在 core 里再写一遍, 就等于把
       "什么算成功"定义两次 —— 两套口径中漂移的那一套会安静地给出另一组
       数字（同 ST4.2 的 `vm_reduce` 教训）。
    2. **验收要求"与 CLI 输出一致"** 时, 子进程是唯一能自证这件事的做法:
       我拿到的就是 CLI 自己写下的那一份。
    3. 代价是每次 ~0.12 s 的进程启动（实测 doctor/sym/mask/exit 都是 0.11
       ~ 0.15 s）, 对面板可忽略。

    ⚠ **`cli_rc` 是结果, 不是异常。** 只有两种情形抛异常:
      · `rc == 2` -> `E_BAD_ARGS`。那是 prot_dbg 自己的**用法**错误,
        即 core 把 argv 拼错了。把它读成数据结果, 面板会显示
        "符号不在 map 中"而真相是参数写错了 —— 这正是要分开的理由。
      · 完全读不到 JSON（工具在写盘前就死了）-> `E_INTERNAL`。
    其余（`rc == 0` 与 `rc == 1`）一律**如实返回** `cli_rc` / `cli_ok`,
    由调用方决定怎么渲染。`rc == 1` 的含义是"工具跑完了, 结论是负的"
    （符号不在 map、退出码未知、doctor 发现产物缺失）—— 那是**信息**,
    不是故障。
    """
    import subprocess
    import tempfile

    if not os.path.exists(PROT_DBG):
        raise StudioError('E_NOT_FOUND', 'prot_dbg.py 不存在',
                          {'path': PROT_DBG})
    fd, jp = tempfile.mkstemp(prefix='studio_protdbg_', suffix='.json')
    os.close(fd)
    argv = ([sys.executable, '-X', 'utf8', PROT_DBG] + [str(x) for x in cli]
            + ['--quiet', '--json', jp])
    rec = {'backend': 'tools/prot_dbg.py', 'argv': argv[2:], 'cli_rc': None,
           'cli_ok': False, 'payload': None, 'stderr': '', 'timeout_s': None}
    try:
        try:
            p = subprocess.run(argv, cwd=REPO, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=timeout)
            rec['cli_rc'] = p.returncode
            rec['stderr'] = p.stderr.decode('utf-8', 'replace').strip()
        except subprocess.TimeoutExpired:
            rec['timeout_s'] = timeout
            rec['stderr'] = 'prot_dbg.py 超时 (%gs) -> 如实报告, 不假装有结果' % timeout
            raise StudioError(
                'E_TIMEOUT', 'prot_dbg.py 超时',
                {'argv': rec['argv'], 'timeout_s': timeout,
                 'note': '活体命令会跑满 --seconds 观察窗口, 故超时上限随窗口放大'})
        raw = io.open(jp, 'rb').read()
        if not raw.strip():
            raise StudioError(
                'E_INTERNAL', 'prot_dbg --json 没有写出任何内容',
                {'argv': rec['argv'], 'cli_rc': rec['cli_rc'],
                 'stderr': rec['stderr'][:400]})
        try:
            rec['payload'] = json.loads(raw.decode('utf-8'))
        except ValueError as e:
            raise StudioError('E_PARSE', 'prot_dbg --json 不是合法 JSON: %s' % e,
                              {'argv': rec['argv'], 'bytes': len(raw)})
        if rec['cli_rc'] == 2:
            raise StudioError(
                'E_BAD_ARGS', 'prot_dbg 用法错误 (rc=2) -> core 拼错了 argv',
                {'argv': rec['argv'], 'stderr': rec['stderr'][:400],
                 'why_not_data': 'rc=2 是用法错误, 不是数据结果'})
        rec['cli_ok'] = rec['cli_rc'] == 0
        # `step` = prot_dbg 自己的阶段号（1 = 只读 / 2 = 活体）。**从工具
        # 自己的产物里取**, 而不是 core 按命令行猜 —— 面板要靠它决定
        # "这次有没有碰目标进程", 猜错会让只读操作被渲染成危险操作。
        rec['step'] = rec['payload'].get('step')
        return rec
    finally:
        try:
            os.remove(jp)
        except OSError:
            pass


def _dbg_common(args):
    """`--exe` / `--map` 透传（面板可以指向非默认产物）。"""
    out = []
    for key, flag in (('exe', '--exe'), ('map', '--map')):
        v = args.get(key)
        if v:
            out += [flag, str(v)]
    return out


def _dbg_names(args, key, what):
    """取一组名字; **空 = 调用方没说 -> 错误**（不是"没有结果"）。"""
    v = args.get(key)
    if v is None:
        v = []
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, (list, tuple)):
        raise StudioError('E_BAD_ARGS', '%s 必须是字符串或字符串数组' % key,
                          {'given': type(v).__name__})
    out = [str(x) for x in v]
    if not out:
        raise StudioError(
            'E_BAD_ARGS', '%s 为空 -> 不知道该%s什么' % (key, what),
            {'given': args, 'note': '"没说"与"没有"是两件事: 前者是调用方'
                                   '的错误, 后者才是结果'})
    return out


def cmd_debug_doctor(args):
    """（ST3.1）主机级只读体检：产物/map/掩码**解析链路**。不打开进程。"""
    rec = _prot_dbg_run(['doctor'] + _dbg_common(args))
    doc = (rec['payload'] or {}).get('doctor') or {}
    rec['summary'] = {'ok': doc.get('ok'), 'syms': doc.get('syms'),
                      'mask_regions': doc.get('mask_regions'),
                      'n_errors': len(doc.get('errors') or []),
                      'n_warns': len(doc.get('warns') or [])}
    rec['opened_process'] = False
    return rec


def cmd_debug_sym(args):
    """（ST3.1）符号 -> RVA / 链接时 VA / `.text` 内偏移 / 掩码归属。"""
    names = _dbg_names(args, 'symbols', '查')
    rec = _prot_dbg_run(['sym'] + names + _dbg_common(args))
    tab = (rec['payload'] or {}).get('sym') or {}
    rec['symbols'] = tab
    rec['missing'] = sorted(n for n, v in tab.items() if v is None)
    rec['opened_process'] = False
    return rec


def cmd_debug_mask(args):
    """（ST3.1）掩码区清单；**给了符号时 prot_dbg 会转成 sym 查询**。

    ⚠ 这是 prot_dbg 的真实行为（`cmd_mask` 在 `names` 非空时直接
    `return cmd_sym(...)`), 故 `payload` 的键会从 `mask` 变成 `sym`。
    core **如实透出**这件事（`payload_key`）, 而不是替调用方抹平 ——
    抹平会让"我要看全区, 你只给了我一个符号"这件事变得看不出来。
    """
    names = args.get('symbols')
    if isinstance(names, str):
        names = [names]
    cli = ['mask'] + ([str(x) for x in names] if names else []) + _dbg_common(args)
    rec = _prot_dbg_run(cli)
    pay = rec['payload'] or {}
    rec['payload_key'] = next((k for k in ('mask', 'sym') if k in pay), None)
    rec['opened_process'] = False
    return rec


def cmd_debug_exit(args):
    """（ST3.1）退出码 -> 语义（表来自 `include/protect/*.h`, 解析而非硬编码）。"""
    codes = args.get('codes')
    if codes is None:
        codes = []
    if not isinstance(codes, (list, tuple)):
        codes = [codes]
    codes = [str(c) for c in codes]
    if not codes:
        raise StudioError('E_BAD_ARGS', 'codes 为空 -> 不知道该解释哪个退出码',
                          {'given': args})
    rec = _prot_dbg_run(['exit'] + codes)
    rec['codes'] = (rec['payload'] or {}).get('exit') or {}
    rec['unknown'] = sorted(k for k, v in rec['codes'].items()
                            if not (v or {}).get('known'))
    rec['opened_process'] = False
    return rec


def _need_confirm(args, what, argv):
    """活体命令的**安全闸**。

    为什么单独一个错误码而不是 `E_BAD_ARGS`: 参数没有错, 少的是**授权**。
    报成 E_BAD_ARGS 会让面板显示"你传错了参数", 而正确动作是弹一个
    "要拉起 demo 进程吗"的确认 —— 报错文案决定 UI 行为（同 §2.59 里
    `E_STREAM_CMD` 与 `E_UNKNOWN_CMD` 必须分开的理由）。
    """
    if args.get('confirm'):
        return
    raise StudioError('E_CONFIRM_REQUIRED',
                      '%s 会拉起动/附着目标进程 -> 必须显式 confirm: true' % what,
                      {'what': what, 'argv': argv, 'given': args,
                       'how': '这是刻意的安全默认, 与 build.run 同一纪律'})


def cmd_debug_read(args):
    """（ST3.3）读目标进程内存。**需 `confirm: true`**（会拉起/附着进程）。"""
    names = _dbg_names(args, 'symbols', '读')
    n = args.get('length')
    cli = ['read', names[0], '--len', str(int(n) if n else 16)] + _dbg_common(args)
    _need_confirm(args, 'read（打开目标进程）', cli)
    if args.get('pid'):
        cli += ['--pid', str(int(args['pid']))]
    rec = _prot_dbg_run(cli, timeout=180.0)
    rec['read'] = (rec['payload'] or {}).get('read')
    rec['opened_process'] = True
    return rec


def cmd_debug_patch(args):
    """（ST3.3）改写目标进程内存。**需 `confirm: true`**（这是写入）。"""
    names = _dbg_names(args, 'symbols', '改')
    cli = ['patch', names[0]] + _dbg_common(args)
    if args.get('bytes'):
        cli += ['--bytes', str(args['bytes'])]
    if args.get('nop'):
        cli += ['--nop', str(int(args['nop']))]
    if args.get('restore'):
        cli += ['--restore']
    _need_confirm(args, 'patch（写入目标进程内存）', cli)
    if args.get('pid'):
        cli += ['--pid', str(int(args['pid']))]
    rec = _prot_dbg_run(cli, timeout=180.0)
    rec['patch'] = (rec['payload'] or {}).get('patch')
    rec['opened_process'] = True
    return rec


def cmd_debug_stack(args):
    """（ST5.4b）宿主侧调用栈。**需 `confirm: true`**（会拉起/附着进程）。

    与 `debug.read` / `debug.patch` 同一安全等级：都会打开目标进程
    （本工具用 OpenProcess/ReadProcessMemory，**本身就是调试行为**，
    可能被 demo 自己的反调试检测到）。故走同一个 `_need_confirm` 闸门。

    ⚠️ 三条必须如实转达的边界（**不得被 core 抹平**）：
      1. `method` 是 `stack-scan + call-discriminator`，**不是** Windows 的
         unwind（`is_windows_unwind=False` 由 prot_dbg 自报，core 只转发）。
      2. 每条线程带 `reliable` / `dirty_reason`；`reliable=False` 时
         那股调用栈是**不完整的**（栈中间有洞），不是"没有帧"。
      3. 某个线程 `frames` 为空是**合法结果**（例如该线程睡在 ntdll 里，
         栈上没有任何落在本映像内的返回地址）—— 不是"取不到"。
    """
    cli = ['stack'] + _dbg_common(args)
    n = args.get('scan_bytes')
    if n:
        cli += ['--len', str(int(n))]
    _need_confirm(args, 'stack（打开目标进程读线程栈）', cli)
    if args.get('pid'):
        cli += ['--pid', str(int(args['pid']))]
    rec = _prot_dbg_run(cli, timeout=180.0)
    p = rec['payload'] or {}
    st = p.get('stack') or {}
    rec['stack'] = st
    rec['opened_process'] = True
    # 把"哪几股是不完整的"提出来 —— 面板要据此显示告警，而不是
    # 让用户从 32 帧里自己发现某股少了几层。**不提级、不改写原文**：
    # dirty_reason 原样来自 prot_dbg。
    threads = st.get('threads') or []
    rec['unreliable_threads'] = [
        {'tid': t.get('tid'), 'dirty_reason': t.get('dirty_reason')}
        for t in threads if not t.get('reliable')]
    rec['empty_threads'] = [t.get('tid') for t in threads
                            if not (t.get('frames') or [])]
    return rec


def debug_watch_events(args):
    """（ST3.3）`watch` 的**流式**形态 —— 生成器, 逐条 yield 事件。

    诚实设计（读这段再改）:

    1. **不带 `confirm: true` 只给计划。** 同 `build.run`: watch 会拉起一个
       demo 进程并跑满观察窗口, 是有副作用且秒级的操作。
    2. **采样事件的文本是 prot_dbg 自己的输出**, core 只逐行转发,
       **不重新解析**成结构化采样。理由: 重新解析会制造第二套口径, 而它
       漂移时不会报错 —— 只会安静地少报几次变化。结构化结果来自工具
       自己写的 `--json`（`changes` / `n_changes` / `first` / `last`）。
       故**每次采样都有一条事件**这件事由 `plan` 的 `interval`/`seconds`
       与 `result` 的 `changes` 共同表达, 而不是假装我解析了它们。
    3. `interval` / `seconds` 在 `plan` 事件里**结构化可见**（ST3.3 的验收
       点就是这一条）。
    """
    import subprocess

    names = _dbg_names(args, 'symbols', '观测')
    n = args.get('length')
    interval = float(args.get('interval') or 0.0)
    seconds = float(args.get('seconds') or 0.0)
    cli = (['watch', names[0], '--len', str(int(n) if n else 4)]
           + _dbg_common(args))
    if interval:
        cli += ['--interval', str(interval)]
    if seconds:
        cli += ['--seconds', str(seconds)]
    for pn in (args.get('patch') or []):
        cli += ['--patch', str(pn)]
    if args.get('pid'):
        cli += ['--pid', str(int(args['pid']))]
    if args.get('no_keep_alive'):
        cli += ['--no-keep-alive']

    confirm = bool(args.get('confirm'))
    yield {'event': 'plan', 'cmd': 'debug.watch', 'argv': cli, 'cwd': REPO,
           'sym': names[0], 'len': int(n) if n else 4,
           'interval': interval or None, 'seconds': seconds or None,
           'prepatch': [str(x) for x in (args.get('patch') or [])],
           'confirm_required': not confirm,
           'note': 'interval/seconds 为 null 表示用 prot_dbg 的默认值'}
    if not confirm:
        yield {'event': 'done', 'started': False,
               'note': '未启动观测（需要 confirm: true）—— 刻意不替调用方做决定'}
        return

    if not os.path.exists(PROT_DBG):
        yield {'event': 'exit', 'rc': None, 'error': 'prot_dbg.py 不存在'}
        yield {'event': 'done', 'started': True, 'ok': False}
        return

    fd, jp = None, None
    import tempfile
    fd, jp = tempfile.mkstemp(prefix='studio_watch_', suffix='.json')
    os.close(fd)
    argv = [sys.executable, '-X', 'utf8', PROT_DBG] + cli + ['--json', jp]
    # 超时上限随观察窗口放大 —— 否则长窗口会被看门狗式地砍掉,
    # 而"被砍掉"与"观察完成"在事件里长得一样。
    budget = (seconds or 6.0) + 120.0
    yield {'event': 'start', 'argv': argv[2:], 'timeout_s': budget}
    n_lines = 0
    rc = None
    try:
        p = subprocess.Popen(argv, cwd=REPO, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        try:
            for bline in p.stdout:
                line = bline.decode('utf-8', 'replace').rstrip('\r\n')
                if not line.strip():
                    continue
                n_lines += 1
                yield {'event': 'line', 'text': line,
                       'tag': 'sample' if line.lstrip().startswith('[') else None}
        finally:
            p.stdout.close()
            rc = p.wait()
    except Exception as e:                                       # noqa: BLE001
        yield {'event': 'line', 'text': 'core 侧异常: %s: %s'
                                         % (type(e).__name__, e), 'tag': 'error'}
    finally:
        result = None
        try:
            if jp and os.path.exists(jp):
                rawb = io.open(jp, 'rb').read()
                if rawb.strip():
                    result = json.loads(rawb.decode('utf-8'))
        except (OSError, ValueError) as e:
            result = {'__unreadable__': '%s: %s' % (type(e).__name__, e)}
        if jp:
            try:
                os.remove(jp)
            except OSError:
                pass
        yield {'event': 'result', 'rc': rc, 'lines': n_lines,
               'interval': interval or None, 'seconds': seconds or None,
               'watch': (result or {}).get('watch'),
               'antidebug_interference':
                   (result or {}).get('antidebug_interference'),
               'raw_ok': (result or {}).get('ok')}
        yield {'event': 'done', 'started': True, 'ok': rc == 0, 'rc': rc}



# --- VM 源码视图与调试会话（ST5.3 / ST5.4）------------------------------------
#
# 这两组命令的后端**全部**在 `tools/vm_debug.py` 里: `source_view()` 给逐行
# 高亮 + 行号 + 断点槽, `Session` 给"跨调用活着的解释器"。本层只做三件事:
# 参数守卫、把 `VmError` 翻成稳定的 `E_*` 码、把会话存起来。
#
# ⚠️ 会话表是**进程内**的（`_SESSIONS`）。`tools/studio_cli.py --cmd` 每次是
# 一个新进程 ⇒ 那条路径上"下断点"和"单步"会落在两个不同的表里。这不是
# 缺陷, 是进程模型的直接后果; CLI 的 session 模式与 Studio 外壳（同一个
# HTTP 服务进程）才跨调用有效。**如实写在协议文档里**, 不让调用方去猜。

_SESSIONS = {}
_SESSION_LOCK = threading.Lock()
#: 会话 id 的计数器。**单调递增**, 不复用 —— 复用一个已关闭的 id 会让面板
#: 手里那个过期的 id 突然指向一个新会话（它看起来"又能用了", 但状态是别人的）。
_SESSION_SEQ = itertools.count(1)
#: 会话表上限 —— 面板每次"打开"都建一个会话, 不设上限就是内存泄漏。
#: 满了就丢**最旧**的（面板重新打开一次即可, 不影响正确性）。
SESSION_MAX = 32


def _vm_source_path(args):
    """把 `source_view` 要读的 `.vasm` 解析成绝对路径（**不猜**）。"""
    path = args.get('asm')
    if not isinstance(path, str) or not path:
        raise StudioError('E_BAD_ARGS', 'vm.source 需要 asm 参数（.vasm 路径）',
                          {'given': args.get('asm')})
    ap = path if os.path.isabs(path) else os.path.join(REPO, path)
    if not os.path.exists(ap):
        raise StudioError('E_NOT_FOUND', '.vasm 不存在', {'asm': ap})
    return ap


def cmd_vm_source(args):
    """读一个 `.vasm` 的**逐行视图**（ST5.3 的断点槽 + 高亮数据）。

    后端 `tools/vm_debug.py:source_view()`。行号表由**汇编器现算** ——
    `.vasm` 的偏移与种子无关（ST4.1），所以不需要任何构建产物。

    汇编不过**不是**错误: 源码照样返回, 错误在 `assemble_error` 里。
    （若在这里抛出去, 面板就只能显示"打不开", 而用户要看的正是那段源码。）
    """
    import vm_debug as _vd
    ap = _vm_source_path(args)
    try:
        view = _vd.source_view(ap)
    except OSError as e:
        raise StudioError('E_NOT_FOUND', '读 .vasm 失败: %s' % e, {'asm': ap})
    view['rel'] = os.path.relpath(ap, REPO).replace('\\', '/')
    view['backend'] = 'tools/vm_debug.py:source_view'
    return view


def _vm_load(args):
    """载入 (code, key1, off_to_line, line_to_asm, src, kind) —— 与 `vm.disasm` 同源。

    **刻意与 `cmd_vm_disasm` 共用同一段解析**: 会话若能载入一个与反汇编视图
    不同的字节序列, 面板上的行号就会与它单步走的位置对不上 —— 那种错很难
    看出来, 因为两边各自都"有数字"。
    """
    import vm_debug as _vd
    where = args.get('source', 'asm')
    if where not in ('blob', 'asm'):
        raise StudioError('E_BAD_ARGS', "source 必须是 'blob' 或 'asm'",
                          {'given': where})
    if where == 'asm':
        ap = _vm_source_path(args)
        try:
            code, off_to_line, info = _vd.load_from_asm(ap)
        except Exception as e:                              # noqa: BLE001
            raise StudioError('E_PARSE', '汇编失败: %s' % e, {'asm': ap})
        lta = {ln: mn for (_o, ln, mn) in info.get('lines', [])}
        return (code, None, off_to_line, lta,
                os.path.relpath(ap, REPO).replace('\\', '/'), 'asm')
    name = args.get('name')
    if not name:
        raise StudioError('E_BAD_ARGS', "source='blob' 需要 name 参数",
                          {'given': args})
    blob = args.get('blob') or os.path.join(REPO, 'build', 'vm.blob')
    try:
        code, key1, _k0, _crc = _vd.load_from_blob(blob, name)
    except Exception as e:                                  # noqa: BLE001
        raise StudioError('E_NOT_FOUND', '取镜像 %r 失败: %s' % (name, e),
                          {'blob': blob, 'name': name})
    return (code, key1, {}, {},
            '%s:%s' % (os.path.relpath(blob, REPO).replace('\\', '/'), name),
            'blob')


def _vm_error(e):
    """把 `vm_debug.VmError` 翻成 `StudioError`（**保留机读 reason**）。

    reason 直接进 `detail['reason']` —— 面板据它分支（`no-line-table` 要
    显示"这个会话没有行号表", `bad-breakpoint` 要显示"这个行号不对"）。
    混成一个 `E_BAD_ARGS` 会让两件不同的事长得一样。
    """
    code = 'E_BAD_ARGS' if e.reason in ('no-line-table', 'bad-breakpoint',
                                        'bad-session') else 'E_VM'
    return StudioError(code, e.detail or e.reason,
                       {'reason': e.reason, 'ip': getattr(e, 'ip', None)})


def _session_id(args, required=True):
    sid = args.get('session')
    if sid is None:
        if required:
            raise StudioError('E_BAD_ARGS', '这条命令需要 session',
                              {'given': args})
        return None
    if not isinstance(sid, str):
        raise StudioError('E_BAD_ARGS', 'session 必须是字符串',
                          {'given': sid})
    with _SESSION_LOCK:
        s = _SESSIONS.get(sid)
    if s is None:
        raise StudioError('E_NOT_FOUND', '会话不存在或已过期',
                          {'session': sid, 'known': len(_SESSIONS),
                           'why': '会话活在 Studio 服务进程内; 重启服务或'
                                  '换一个进程都会让旧 id 失效'})
    return sid


def cmd_vm_open(args):
    """开一个调试会话（ST5.4 的工具条都挂在它上面）。

    `source='asm'`（默认）⇒ **有行号表**, 能按源行号下断点;
    `source='blob'` ⇒ 没有行号表, `breakpoints_supported` 如实为 False
    （不退化成"按偏移下断点却仍叫行号"）。
    """
    import vm_debug as _vd
    code, key1, otl, lta, src, kind = _vm_load(args)
    mem_size = args.get('mem_size')
    if mem_size is not None and not isinstance(mem_size, int):
        raise StudioError('E_BAD_ARGS', 'mem_size 必须是整数', {'given': mem_size})
    sess = _vd.Session(code, key1, otl, lta, src=src, kind=kind,
                       mem_size=mem_size)
    sid = 'vm-%d' % (next(_SESSION_SEQ),)
    with _SESSION_LOCK:
        # 满了丢最旧的 —— 会话是**可重建**的（重新 open 一次即可）,
        # 所以这里丢东西不会丢用户的工作, 只会丢一个 id。
        while len(_SESSIONS) >= SESSION_MAX:
            _SESSIONS.pop(next(iter(_SESSIONS)))
        _SESSIONS[sid] = sess
    st = sess.state()
    st['session'] = sid
    st['backend'] = 'tools/vm_debug.py:Session'
    return st


def cmd_vm_state(args):
    """只读当前会话状态（**不前进**）。面板每次操作后都调它刷新。"""
    sid = _session_id(args)
    with _SESSION_LOCK:
        s = _SESSIONS[sid]
    st = s.state()
    st['session'] = sid
    return st


def _vm_vmerror():
    import vm_debug as _vd
    return _vd.VmError


def cmd_vm_continue(args):
    """“继续”：跑到断点 / 停机 / 步数上限。"""
    sid = _session_id(args)
    with _SESSION_LOCK:
        s = _SESSIONS[sid]
    ms = args.get('max_steps')
    try:
        s.run_until_stop(max_steps=ms if isinstance(ms, int) else None)
    except _vm_vmerror() as e:
        raise _vm_error(e)
    st = s.state()
    st['session'] = sid
    return st


def cmd_vm_step(args):
    """“单步”：恰好一条指令（断点**不**拦截单步 —— 用户已经在这里了）。"""
    sid = _session_id(args)
    with _SESSION_LOCK:
        s = _SESSIONS[sid]
    try:
        s.step_once()
    except _vm_vmerror() as e:
        raise _vm_error(e)
    st = s.state()
    st['session'] = sid
    return st


def cmd_vm_step_over(args):
    """“步过”：跨过一条 `call`。被调函数**内部**的断点仍然命中。"""
    sid = _session_id(args)
    with _SESSION_LOCK:
        s = _SESSIONS[sid]
    try:
        s.step_over()
    except _vm_vmerror() as e:
        raise _vm_error(e)
    st = s.state()
    st['session'] = sid
    return st


def cmd_vm_restart(args):
    """“重启”：回到初态, **保留断点**。"""
    sid = _session_id(args)
    with _SESSION_LOCK:
        s = _SESSIONS[sid]
    s.restart()
    st = s.state()
    st['session'] = sid
    return st


def cmd_vm_breakpoints(args):
    """设置 / 增减 / 清空断点（按**源行号**；无行号表则如实拒绝）。

    支持两种形态: `lines`（整体替换, 空列表 = 全清）或 `add`/`remove`。
    两者同时给 ⇒ 报错 —— 顺序会有歧义, 而面板不该靠猜知道"先加还是先替换"。
    """
    sid = _session_id(args)
    with _SESSION_LOCK:
        s = _SESSIONS[sid]
    has_lines = 'lines' in args and args.get('lines') is not None
    has_edit = ('add' in args) or ('remove' in args)
    if has_lines and has_edit:
        raise StudioError('E_BAD_ARGS',
                          'lines 与 add/remove 不能同时给（顺序有歧义）',
                          {'given': sorted(args)})
    try:
        if has_lines:
            lines = args.get('lines')
            if not isinstance(lines, (list, tuple)):
                raise StudioError('E_BAD_ARGS', 'lines 必须是数组',
                                  {'given': lines})
            s.set_breakpoints(lines)
        elif has_edit:
            for ln in (args.get('add') or []):
                s.add_breakpoint(ln)
            for ln in (args.get('remove') or []):
                s.clear_breakpoint(ln)
        else:
            raise StudioError('E_BAD_ARGS',
                              '需要 lines 或 add/remove 之一',
                              {'given': sorted(args)})
    except _vm_vmerror() as e:
        raise _vm_error(e)
    st = s.state()
    st['session'] = sid
    return st


def cmd_vm_close(args):
    """关掉会话并释放它（面板关标签页时调）。对不存在的 id **也成功**。"""
    sid = args.get('session')
    if not isinstance(sid, str) or not sid:
        raise StudioError('E_BAD_ARGS', 'session 必须是非空字符串',
                          {'given': sid})
    with _SESSION_LOCK:
        existed = _SESSIONS.pop(sid, None) is not None
    return {'session': sid, 'closed': True, 'existed': existed}


# --- 注册表 ----------------------------------------------------------------

COMMANDS = {
    'ping': cmd_ping,
    'capabilities': cmd_capabilities,
    'plan.list': cmd_plan_list,
    'plan.solve': cmd_plan_solve,
    'modules.list': cmd_modules_list,
    'gate.items': cmd_gate_items,
    'src.show': cmd_src_show,
    'vm.images': cmd_vm_images,
    'vm.disasm': cmd_vm_disasm,
    'vm.source': cmd_vm_source,
    'vm.open': cmd_vm_open,
    'vm.state': cmd_vm_state,
    'vm.continue': cmd_vm_continue,
    'vm.step': cmd_vm_step,
    'vm.stepOver': cmd_vm_step_over,
    'vm.restart': cmd_vm_restart,
    'vm.breakpoints': cmd_vm_breakpoints,
    'vm.close': cmd_vm_close,
    'test.gate.results': cmd_test_gate_results,
    'plan.graph': cmd_plan_graph,
    'debug.doctor': cmd_debug_doctor,
    'debug.sym': cmd_debug_sym,
    'debug.mask': cmd_debug_mask,
    'debug.exit': cmd_debug_exit,
    'debug.read': cmd_debug_read,
    'debug.patch': cmd_debug_patch,
    'debug.stack': cmd_debug_stack,
}


def stream_events(cmd, args=None):
    """流式命令 -> **生成器**, 逐条产出事件 dict。

    为什么单独一条通路: 流式命令一个请求产出**多行**响应, 与 `dispatch()`
    的"一问一答"形态不同。若把它们塞进 `COMMANDS`, 调用方会拿到一个
    生成器却当成 dict 用 —— 那种错会以
    `AttributeError: 'generator' object has no attribute 'get'`
    的形式出现在**调用方**里, 看起来像调用方自己写错了。
    """
    if cmd not in STREAM_COMMANDS:
        raise StudioError('E_BAD_ARGS', '不是流式命令',
                          {'cmd': cmd,
                           'stream_commands': list(STREAM_COMMANDS)})
    args = args if isinstance(args, dict) else {}
    if cmd == 'build.run':
        return build_events(args)
    if cmd == 'debug.watch':
        return debug_watch_events(args)
    raise StudioError('E_UNKNOWN_CMD', '流式命令未实现', {'cmd': cmd})


def dispatch(cmd, args=None):
    """执行一条命令, **返回可 JSON 序列化的 dict**。

    未知命令抛 `StudioError('E_UNKNOWN_CMD')` —— 并**列出候选**,
    因为面板与脚本都会因拼错名字而撞上它（§2.53 的"失锚不静默"）。
    """
    if cmd not in COMMANDS:
        # 流式命令走另一条通路 —— 必须**分开报**。报成 E_UNKNOWN_CMD
        # 会让面板把"这个命令要流式调用"读成"我把名字拼错了", 于是它
        # 去翻 available 列表(里面当然没有), 而不是改成流式调用。
        if cmd in STREAM_COMMANDS:
            raise StudioError(
                'E_STREAM_CMD',
                '%r 是流式命令, 请用 stream_events() 或 CLI 流式入口' % (cmd,),
                {'cmd': cmd, 'stream_commands': list(STREAM_COMMANDS)})
        raise StudioError('E_UNKNOWN_CMD', '未知命令 %r' % (cmd,),
                          {'cmd': cmd, 'available': sorted(COMMANDS)})
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise StudioError('E_BAD_ARGS', 'args 必须是对象',
                          {'type': type(args).__name__})
    return COMMANDS[cmd](args)


def envelope(cmd, args=None, req_id=None):
    """把 `dispatch` 包成 NDJSON 响应对象（**唯一出口形态**）。

    成功: `{"id":..,"ok":true,"data":{..}}`
    失败: `{"id":..,"ok":false,"error":{"code","message","detail"}}`
      —— 失败**不抛给调用方**, 因为流式会话里一条命令失败不应终止整个会话。
    请求 id 原样回传（客户端靠它配对）。
    """
    try:
        data = dispatch(cmd, args)
        return {'id': req_id, 'ok': True, 'data': data}
    except StudioError as e:
        return {'id': req_id, 'ok': False, 'error': e.to_dict()}
    except Exception as e:                                # pragma: no cover
        return {'id': req_id, 'ok': False,
                'error': {'code': 'E_INTERNAL',
                          'message': '%s: %s' % (type(e).__name__, e),
                          'detail': {'cmd': cmd}}}


# --- 自检 ------------------------------------------------------------------
#
# 纪律（2026-09-23 门禁失效事件后确立, 见 docs/PROTOCOL_GOVERNANCE.md）:
#   **检查器必须自证"会抓错"** —— 只报"全 ok"的自检没有价值。
# 故下面每个能力都配一条**负向**用例。

def selftest(quiet=False):
    fails = []
    lines = []

    def case(name, ok, detail=''):
        if not quiet:
            lines.append('  %s %-56s %s'
                         % ('ok ' if ok else '**FAIL**', name, detail))
        if not ok:
            fails.append(name)

    def raises(fn, code):
        """负向辅助: 必须抛 StudioError 且 code 匹配（**不能只是"抛了异常"**）。"""
        try:
            fn()
        except StudioError as e:
            return e.code == code, e.code
        except Exception as e:
            return False, '%s(%s)' % (type(e).__name__, e)
        return False, 'no-raise'

    if not quiet:
        lines.append('=== studio_core 自检 ===')
        lines.append('--- 1. ping / capabilities ---')
    r = dispatch('ping')
    case('ping 回传协议版本', r.get('protocol_version') == PROTOCOL_VERSION)
    case('ping 含 repo 与平台', bool(r.get('repo')) and bool(r.get('platform')))
    caps = dispatch('capabilities')
    # 用 >= 而非 ==: 能力项随阶段增加(ST0/ST2/ST4/ST1 各加过)。写死数字会在
    # 下次加项时变成噪音, 而真正要守的三件事是下面三条 + evidence/step 两条。
    # 下限紧贴当前值(9), 不留余量 —— 留余量会让它对"能力项被删掉"失明。
    case('capabilities 至少 9 项能力',
         len(caps.get('capabilities', {})) >= 9,
         'count=%d' % len(caps.get('capabilities', {})))
    # ⭐ ST5 落地后 `ui` 变 ready —— 这是**最后一个** planned 项, 所以下面这条
    # 断言必须随实施一起改（与 generate.build / generate.graph /
    # test.gate.results / debug.vm 同一处理）: 不改它要么永远红, 要么（更坏）
    # 被改成永真。改成"先断言存在、再断言取值"的形态, 并**顺带**守住状态
    # 词表 —— `status` 拼错（如 `'Ready'`）原先没有任何判据看得见, 而面板
    # 是拿它决定入口启不启用的。
    _capst = {k: c.get('status') for k, c in caps['capabilities'].items()}
    case('ui 自 ST5 起为 ready（本地浏览器外壳已落地）',
         caps['capabilities'].get('ui', {}).get('status') == 'ready',
         'status=%s' % caps['capabilities'].get('ui', {}).get('status'))
    _bad_st = sorted(k for k, v in _capst.items()
                     if v not in ('ready', 'partial', 'planned'))
    case('能力 status 只取 ready/partial/planned 三态（拼错会被抓住）',
         not _bad_st, '坏值: %s' % _bad_st)
    case('generate.build 自 ST1 起为 partial（能流式, 默认不启动）',
         caps['capabilities'].get('generate.build', {}).get('status') == 'partial')
    case('generate.graph 自 ST1 起为 ready（复用 compose/compat）',
         caps['capabilities'].get('generate.graph', {}).get('status') == 'ready')
    # ST2 落地后 test.gate.results 变 ready —— 同 debug.vm 的处理:
    # 断言存在再断言取值, 且未完成的项**不得**混进 ready。
    case('test.gate.results 自 ST2 起为 ready',
         caps['capabilities'].get('test.gate.results', {}).get('status') == 'ready')
    # ST4 落地后 debug.vm 变 ready —— 但 `partial` 的 debug.host 与 **任何**
    # 未声明为 ready 的项都不许出现在"已完成"里。这条断言跟着能力一起演进，
    # 且**先断言存在**再断言取值（否则改名会让它静默变成永真）。
    case('debug.vm 自 ST4 起为 ready',
         caps['capabilities'].get('debug.vm', {}).get('status') == 'ready')
    case('debug.host 仍如实标为 partial（主机级断点未做）',
         caps['capabilities'].get('debug.host', {}).get('status') == 'partial')
    # ST5.4b 落地后新增 debug.stack 能力项。同其它阶段的处理: 先断言存在
    # 再断言取值。**刻意不把它标成 ready**: 它没有 unwind 解释器,
    # 只有栈扫描 + call 判别 ⇒ 假阴性是**已知的**, 标 ready 会让面板
    # 暗示"这是完整的调用栈"。
    case('debug.stack 自 ST5.4b 起存在且如实标 partial（非 unwinder）',
         caps['capabilities'].get('debug.stack', {}).get('status') == 'partial')
    case('debug.stack 的 backend 点名 cmd_stack（可核查的落点）',
         'cmd_stack' in (caps['capabilities'].get('debug.stack', {})
                         .get('backend') or ''))
    case('debug.stack 的 note 声明"不是 Windows 官方展开"',
         '不是' in (caps['capabilities'].get('debug.stack', {})
                    .get('note') or ''))
    case('debug.host 的 evidence 已列出 stack（ST5.4b 的接线不回退）',
         'stack' in (caps['capabilities'].get('debug.host', {})
                     .get('evidence') or ''))
    case('每项能力都有 evidence（不是形容词）',
         all(c.get('evidence') for c in caps['capabilities'].values()))
    case('每项能力都有 step（知道属于哪个阶段）',
         all(c.get('step') for c in caps['capabilities'].values()))
    # BUILD_CONFIGS 与 build.ps1 的校验点必须一致。**这是我自己刚引入的一条
    # "必须同步"承诺**: 我把 build.ps1:185 的三取值抄进了本文件, 两处各写一套
    # 就会出现「CLI 能跑、面板说参数错」。判据现读 build.ps1 的取值表, 不抄写
    # —— 抄写的话两处一起漂移时它照样绿。
    _bs = os.path.join(REPO, 'build.ps1')
    _want = None
    if os.path.isfile(_bs):
        _m = re.search(
            r'\$Config\s+-notin\s+@\(([^)]*)\)',
            io.open(_bs, encoding='utf-8-sig', errors='replace').read())
        if _m:
            _want = tuple(re.findall(r"'([^']+)'", _m.group(1)))
    case('BUILD_CONFIGS 与 build.ps1 -Config 校验一致（失锚即失败）',
         _want is not None and _want == BUILD_CONFIGS,
         'build.ps1=%s core=%s' % (_want, BUILD_CONFIGS))

    if not quiet:
        lines.append('--- 2. 策略求解（复用 solve_profile, 不重写）---')
    pl = dispatch('plan.list')
    case('plan.list 至少 4 个策略', pl['count'] >= 4, 'count=%d' % pl['count'])
    sol = dispatch('plan.solve', {'profile': 'balanced'})
    case('plan.solve 返回 selected/excluded/reasons',
         all(k in sol for k in ('selected', 'excluded', 'reasons')))
    case('selected ∩ excluded 为空（2026-09-23 缺陷回归）',
         not (set(sol['selected']) & set(sol['excluded'])))
    case('每个选中模块都有理由', all(sol['reasons'].get(m)
                                for m in sol['selected']))
    case('plan.solve 附文本计划（同一份真值）',
         bool(sol.get('_text')) and '构建计划' in sol['_text'])
    a = dispatch('plan.solve', {'profile': 'balanced'})
    b = dispatch('plan.solve', {'profile': 'balanced'})
    case('同输入两次调用结果一致（无隐藏状态）',
         json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True))

    if not quiet:
        lines.append('--- 3. 模块契约（读 modules.json, 不抄常量）---')
    ml = dispatch('modules.list')
    reg = registry()
    case('modules.list 与 modules.json 条数一致',
         ml['count'] == len(reg['modules']),
         '%d vs %d' % (ml['count'], len(reg['modules'])))
    case('每个模块都带 maturity 与 caps',
         all(m['maturity'] and m['caps'] for m in ml['modules']))

    if not quiet:
        lines.append('--- 4. 门禁静态清单 ---')
    gi = dispatch('gate.items')
    _src = _gate_source()
    _n = len(re.findall(r"(?m)^\s*Check\s+'", _src))
    case('gate.items 条数与源文件 Check 数一致',
         gi['total'] == _n, '%d vs %d' % (gi['total'], _n))
    case('gate.items 机读标注它不是运行结果',
         gi['kind'] == 'static-declaration')
    case('gated 归属可推导（default = total - gated）',
         gi['gated'] is not None
         and gi['default'] == gi['total'] - len(gi['gated']),
         'total=%d gated=%s' % (gi['total'], gi['gated']))

    if not quiet:
        lines.append('--- 4a. 源码定位（ST5.5: 问题面板的跳转落点）---')
    # `src.show` 是 ST5.5 新增的**通用只读定位**原语 —— `vm.source` 只认
    # `.vasm`, 而门禁项指向的是 `tools/release_check.ps1` 里的 `Check` 行。
    _me = 'tools/studio_core.py'
    _sv = dispatch('src.show', {'path': _me, 'line': 1, 'context': 2})
    case('src.show 读到自身文件第 1 行', _sv.get('line') == 1
         and len(_sv.get('lines') or []) == 3,
         'lines=%d' % len(_sv.get('lines') or []))
    case('src.show 恰一行被标为 hit（高亮由服务端算, 不让前端比）',
         sum(1 for x in _sv['lines'] if x.get('hit')) == 1
         and _sv['lines'][0].get('hit') is True)
    # ⭐ 只给窗口会让"文件只有 25 行"与"我只给了 25 行"长得一样 —— 面板会把
    #   截断显示成文件结尾。所以 `total` 必须在场, 且**大于**窗口长度。
    case('src.show 回报 total（否则截断会被显示成文件结尾）',
         isinstance(_sv.get('total'), int)
         and _sv['total'] > len(_sv['lines']),
         'total=%s window=%s' % (_sv.get('total'), len(_sv.get('lines') or [])))
    _sv0 = dispatch('src.show', {'path': _me})
    case('src.show 不给 line 时从文件头开始且不高亮任何行',
         _sv0.get('line') == 0 and _sv0.get('start') == 1
         and not any(x.get('hit') for x in _sv0.get('lines') or []))
    # 越界**如实报**, 不夹到末尾 —— 夹住会让"行号过期"看起来像"读到了"。
    _bad, _bc = raises(lambda: dispatch('src.show',
                                        {'path': _me, 'line': 10 ** 7}),
                       'E_NOT_FOUND')
    case('src.show 行号越界如实报错（不夹到末尾）', _bad is True, _bc)
    # 仓库外路径必须报**参数错**而不是"文件不存在": 后者会让排查去查拼写。
    _out, _oc = raises(lambda: dispatch('src.show', {'path': '../../etc/passwd'}),
                       'E_BAD_ARGS')
    case('src.show 拒绝仓库外的路径（报参数错, 不报文件不存在）',
         _out is True, _oc)
    # 类型错也要落在参数错上 —— 裸 int() 的 ValueError 会逃成 E_INTERNAL,
    # 面板于是显示"Studio 内部故障", 而正确读法是"我传错了参数"。
    _ty, _tc = raises(lambda: dispatch('src.show', {'path': _me, 'line': 'x'}),
                      'E_BAD_ARGS')
    case('src.show 的 line 类型错报参数错（不逃成 E_INTERNAL）',
         _ty is True, _tc)
    # 门禁也可能指向 .ndjson/.log 这类产物 ⇒ 二进制**不当错误**。
    _bin = os.path.join(REPO, 'build', '_st71bin.bin')
    try:
        with io.open(_bin, 'wb') as f:
            f.write(b'\x00\x01\x02hello')
        _sb = dispatch('src.show', {'path': 'build/_st71bin.bin', 'line': 1})
    finally:
        try:
            os.remove(_bin)
        except OSError:
            pass
    case('src.show 二进制如实标 binary 且不返回 lines（不当错误）',
         _sb.get('binary') is True and 'lines' not in _sb,
         'binary=%s keys=%s' % (_sb.get('binary'), sorted(_sb)[:6]))

    if not quiet:
        lines.append('--- 4b. VM 调试（ST4: 复用 vm_debug, 不重写解释器）---')
    vi = dispatch('vm.images')
    case('vm.images 列出 4 个镜像（build/vm.blob）',
         vi['count'] == 4, 'count=%d' % vi['count'])
    case('vm.images 每条含 name/len/key1/crc',
         all(all(k in im for k in ('name', 'code_len', 'key1', 'crc'))
             for im in vi['images']))
    # 反汇编必须与 .vasm **源码条数**一致 —— 这是 key1 逆置换真的对了的判据,
    # 不是"能跑"。镜像长度对不上会被 vm_debug 拒绝, 所以这里再对一次条数。
    da = dispatch('vm.disasm', {'source': 'blob', 'name': 'verify'})
    case('vm.disasm(blob:verify) 解出 15 条（= license_verify.vasm 指令数）',
         da['count'] == 15, 'count=%d' % da['count'])
    case('vm.disasm 每条含 off/mnem/size',
         all(all(k in r for k in ('off', 'mnem', 'size'))
             for r in da['insns']))
    case('vm.disasm 停机前首条是 push32（可读的反汇编, 不是垃圾）',
         da['insns'][0]['mnem'] == 'push32', da['insns'][0]['mnem'])
    # blob 路径没有行号表 ⇒ line 必须如实为 None, **不许编一个 0**。
    case('blob 反汇编无行号表时 line 如实为 None（不编造）',
         all(r.get('line') is None for r in da['insns']))
    asm = dispatch('vm.disasm', {'source': 'asm',
                                 'asm': 'tests/unit_vm_brk.vasm'})
    case('vm.disasm(asm) 解出 7 条并带源行号',
         asm['count'] == 7 and asm['has_lines'],
         'count=%d has_lines=%s' % (asm['count'], asm['has_lines']))
    case('vm.disasm(asm) 行号是有序的（可用于断点）',
         [r['line'] for r in asm['insns']] == sorted(
             r['line'] for r in asm['insns']))
    ok, got = raises(lambda: dispatch('vm.disasm', {'source': 'nope'}),
                     'E_BAD_ARGS')
    case('**负向**: source 非法 -> E_BAD_ARGS', ok, got)
    ok, got = raises(lambda: dispatch('vm.disasm', {'source': 'blob'}),
                     'E_BAD_ARGS')
    case('**负向**: blob 路径缺 name -> E_BAD_ARGS（不猜默认镜像）', ok, got)
    ok, got = raises(lambda: dispatch('vm.disasm',
                                      {'source': 'blob', 'name': 'nope'}),
                     'E_NOT_FOUND')
    case('**负向**: 不存在的镜像 -> E_NOT_FOUND', ok, got)

    # --- 4b2. VM 源码视图 + 调试会话（ST5.3 / ST5.4）-----------------------
    if not quiet:
        lines.append('--- 4b2. VM 源码视图 + 调试会话（ST5.3/ST5.4）---')
    sv = dispatch('vm.source', {'asm': 'tests/unit_vm_brk.vasm'})
    case('vm.source 给出逐行视图 + 断点槽',
         sv.get('line_count') == 16 and sv.get('breakpoint_key') == 'line',
         'lines=%s key=%s' % (sv.get('line_count'), sv.get('breakpoint_key')))
    case('vm.source 的 executable_lines 恰是可汇编的那些行（7 条）',
         len(sv.get('executable_lines') or []) == 7,
         sv.get('executable_lines'))
    case('vm.source 每行都带 kind/tokens/breakable（面板据此渲染）',
         all(all(k in r for k in ('line', 'text', 'kind', 'tokens',
                                  'breakable')) for r in sv['rows']))
    # ⭐ 断点槽必须**只有**可执行行亮起: 标签/注释/空行上给槽位会让用户
    #   下一个永远命不中的断点, 而他还以为自己设上了。
    case('断点槽只在可执行行亮起（注释/标签/空行不可下）',
         all(r['breakable'] == (r['line'] in (sv['executable_lines'] or []))
             for r in sv['rows']))
    # ⭐ 高亮词表**从汇编器现读**, 所以条数必须等于 OPCODE_SLOTS。
    case('vm.source 的助记符词表 = 汇编器的 47 条（现读, 不硬编码）',
         len(sv.get('mnemonics') or []) == 47,
         'count=%s' % len(sv.get('mnemonics') or []))
    ok, got = raises(lambda: dispatch('vm.source', {}), 'E_BAD_ARGS')
    case('**负向**: vm.source 缺 asm -> E_BAD_ARGS', ok, got)
    ok, got = raises(lambda: dispatch('vm.source', {'asm': 'no/such.vasm'}),
                     'E_NOT_FOUND')
    case('**负向**: vm.source 路径不存在 -> E_NOT_FOUND（不猜）', ok, got)

    # 会话: 用**真实可执行**的 .vasm（有行号表 ⇒ 支持断点）。
    so = dispatch('vm.open', {'asm': 'tests/unit_vm_brk.vasm'})
    _s1 = so['session']
    case('vm.open(asm) 建会话且如实支持断点',
         so['breakpoints_supported'] is True
         and so['session_kind'] == 'asm' and so['terminated'] is False)
    case('vm.open 初态 line_at_ip 是可执行行',
         so['line_at_ip'] in (sv['executable_lines'] or []),
         'line_at_ip=%s' % so['line_at_ip'])
    # 断点: 设 → 继续 → 必须停在那一行。
    _bl = (sv['executable_lines'] or [])[2]
    sb = dispatch('vm.breakpoints', {'session': _s1, 'lines': [_bl]})
    case('vm.breakpoints 设断点后回显它',
         sb['breakpoints'] == [_bl], sb['breakpoints'])
    cn = dispatch('vm.continue', {'session': _s1})
    case('vm.continue 命中断点（line_at_ip == 所设行, 且带停机原因）',
         cn['line_at_ip'] == _bl and cn['hit_breakpoint'] == _bl
         and cn['stop_reason'] == 'user-break',
         'line=%s hit=%s reason=%s' % (cn['line_at_ip'], cn['hit_breakpoint'],
                                       cn['stop_reason']))
    # 单步 / 重启 / 关会话。
    st1 = dispatch('vm.step', {'session': _s1})
    case('vm.step 状态里仍带 session（面板不必自己记）',
         st1.get('session') == _s1)
    rs = dispatch('vm.restart', {'session': _s1})
    # ⭐ 重启**保留断点** —— 悄悄清掉会让用户以为断点丢了。
    case('vm.restart 回到初态且**保留**断点',
         rs['breakpoints'] == [_bl] and rs['terminated'] is False,
         'bp=%s term=%s' % (rs['breakpoints'], rs['terminated']))
    cl = dispatch('vm.close', {'session': _s1})
    case('vm.close 关掉会话', cl.get('closed') is True and cl.get('existed') is True)
    ok, got = raises(lambda: dispatch('vm.state', {'session': _s1}),
                     'E_NOT_FOUND')
    case('**负向**: 关掉后旧 session -> E_NOT_FOUND（不复用 id）', ok, got)
    ok, got = raises(lambda: dispatch('vm.step', {}), 'E_BAD_ARGS')
    case('**负向**: 缺 session -> E_BAD_ARGS', ok, got)
    ok, got = raises(lambda: dispatch('vm.state', {'session': 123}), 'E_BAD_ARGS')
    case('**负向**: session 非字符串 -> E_BAD_ARGS', ok, got)

    # ⭐ blob 会话**没有行号表**: 必须如实拒绝按行号下断点, 且错误码是
    #   `no-line-table` 而不是 `bad-breakpoint`（两件事不同: 会话根本不能按
    #   行号下 vs 这个行号不对）。面板据 reason 显示不同的解释。
    bo = dispatch('vm.open', {'source': 'blob', 'name': 'verify'})
    _s2 = bo['session']
    case('vm.open(blob) 如实标 breakpoints_supported=False（不退化）',
         bo['breakpoints_supported'] is False
         and bo['session_kind'] == 'blob')
    try:
        dispatch('vm.breakpoints', {'session': _s2, 'lines': [1]})
        _nlt = None
    except StudioError as e:
        _nlt = (e.detail or {}).get('reason')
    case('**负向**: blob 会话按行号下断点 -> reason=no-line-table',
         _nlt == 'no-line-table', _nlt)
    # 越界行号的 reason 必须是 bad-breakpoint（**不是** no-line-table）。
    try:
        dispatch('vm.breakpoints', {'session': _s2, 'lines': [1]})
    except StudioError:
        pass
    _s3 = dispatch('vm.open', {'asm': 'tests/unit_vm_brk.vasm'})['session']
    try:
        dispatch('vm.breakpoints', {'session': _s3, 'lines': [1]})
        _bb = None
    except StudioError as e:
        _bb = (e.detail or {}).get('reason')
    case('**负向**: 不可执行行号 -> reason=bad-breakpoint（与上条不同码）',
         _bb == 'bad-breakpoint', _bb)
    ok, got = raises(lambda: dispatch('vm.breakpoints',
                                      {'session': _s3, 'lines': [1],
                                       'add': [2]}),
                     'E_BAD_ARGS')
    case('**负向**: lines 与 add 同时给 -> E_BAD_ARGS（顺序有歧义）', ok, got)
    dispatch('vm.close', {'session': _s2})
    dispatch('vm.close', {'session': _s3})
    # 关一个不存在的会话**也算成功**（面板关标签页时不该因此报错）。
    case('vm.close 对未知 id 也成功（幂等, 不报错）',
         dispatch('vm.close', {'session': 'vm-nope'}).get('existed') is False)

    if not quiet:
        lines.append('--- 4c. 门禁结果历史（ST2: 复用 gate_results, 不重写解析）---')
    gl = dispatch('test.gate.results', {'query': 'list'})
    case('test.gate.results(list) 列出轮次', gl.get('count', 0) >= 1)
    case('轮次行有 log/ndjson 两个布尔（历史轮次如实标 False）',
         all(isinstance(x.get('log'), bool) and isinstance(x.get('ndjson'), bool)
             for x in gl['runs']))
    gt = dispatch('test.gate.results', {'query': 'trend'})
    case('test.gate.results(trend) 每轮一条且计数非负',
         all(isinstance(x.get(k), int) and x[k] >= 0
             for x in gt['trend'] for k in ('pass', 'fail', 'skip', 'not-run')))
    # ⭐ trend 的零值必须是 0 而不是 None —— 一次全 not-run 的运行 pass 是 0,
    #   不是"不知道"。面板会把 None 渲染成空白（这条曾在 gate_results 里真错过）。
    case('trend 不含 None（缺失键补 0）',
         all(all(x.get(k) is not None for k in ('pass', 'fail', 'skip', 'not-run'))
             for x in gt['trend']))
    gv = dispatch('test.gate.results', {'query': 'verify'})
    case('test.gate.results(verify) 报 ok 且无 problems',
         gv.get('ok') is True and gv.get('problems') == [])
    g1 = dispatch('test.gate.results', {'query': 'latest'})
    case('test.gate.results(latest) 逐项带 name/status',
         g1.get('count', 0) >= 1
         and all(x.get('name') and x.get('status') for x in g1['items']))
    # ⭐ 这里**不能**拿 `pass_n` 做断言。`pass_n` 来自 `[release_check] PASS: N 项
    #   检查全通过` 那一句（`tools/gate_results.py:56 RE_PASSN`），而门禁失败时
    #   写的是 `[release_check] FAIL: N/M 未通过` ⇒ **失败轮的 `pass_n` 恒为 None**
    #   （`gate_results.py:162-163`）。于是 `None == <int>` 必假，而
    #   `pick_latest` 读的是**最近一轮已完成**的轮次 ⇒ 只要上一轮门禁是红的，
    #   本项就恒假 —— **一次失败会让门禁永久红下去，直到有人用一轮绿覆盖它**。
    #   这是同型缺陷第 12 次: **断言用了只在成功路径上有定义的量**。
    #   改用两个出口**都在场**的量: 文本出口与 NDJSON 出口各自的 pass 计数。
    #   （历史轮次里 FAIL 行的分母 `pass+fail` 本身口径就不稳定 —— 实测
    #   `20260930_221104` 写 `1/31` 而 pass+fail=30 ⇒ 也不能反推 `pass_n`。）
    case('latest 的两个出口 pass 计数一致（同一真值, 两处表述）',
         (g1.get('counts_text') or {}).get('pass')
         == (g1.get('counts_json') or {}).get('pass'),
         'text=%s json=%s' % ((g1.get('counts_text') or {}).get('pass'),
                              (g1.get('counts_json') or {}).get('pass')))
    # ⭐ ST5.5: 逐项带跳转落点。**光有行号不算数** —— 行号必须真的指向
    #   那一项。判据取"拿行号回源文件读回那一行, 它得写着该项的名字",
    #   这把"有个数字"升级成"这个数字对"。join 键是 `name`(两侧都按名字),
    #   实测历史 868 条 NDJSON 行 100% 能 join 回声明。
    _gl = _gate_source().split('\n')
    _jumped = [x for x in g1['items'] if x.get('src_line')]
    _bad_line = []
    for _x in _jumped:
        _ln = _gl[_x['src_line'] - 1] if _x['src_line'] - 1 < len(_gl) else ''
        if _x['name'] not in _ln or 'Check' not in _ln:
            _bad_line.append('%s@%s' % (_x['name'], _x['src_line']))
    case('latest 逐项带 src/src_line, 且行号回源后确实写着该项',
         bool(_jumped) and not _bad_line,
         '带落点 %d/%d; 对不上: %s' % (len(_jumped), len(g1['items']),
                                      _bad_line))
    # **负向**: 上一条必须能对"行号指错"判假 —— 否则它只是装饰。
    #   复核那一行在错位后会怎样: 取一个项的落点 +1, 必须被上面那条逻辑抓到。
    if _jumped:
        _shift = _jumped[0]
        _ln2 = _gl[_shift['src_line']] if _shift['src_line'] < len(_gl) else ''
        case('（负向）落点 +1 后上面那条判据会判假 —— 它对此敏感',
             not (_shift['name'] in _ln2 and 'Check' in _ln2),
             'line+1 = %r' % _ln2[:60])
    case('latest 的 jump_unresolved 如实列出 join 不上的名字',
         isinstance(g1.get('jump_unresolved'), list),
         'unresolved=%s' % (g1.get('jump_unresolved'),))
    # **负向**: 上一条表达式必须能对"两出口打架"的一轮判假 —— 否则它只是装饰。
    # 用合成的一对 .log/.ndjson（文本 2 个 pass / JSON 1 个 pass）验证判别力。
    import shutil as _sh
    import tempfile as _tf
    _td = _tf.mkdtemp(prefix='studio_twxo_')
    try:
        _stem = os.path.join(_td, 'release_check_29991231_235959')
        io.open(_stem + '.log', 'w', encoding='utf-8', newline='\n').write(
            'Windows PowerShell transcript start\n'
            '[ok]  A\n[ok]  B\n[X]  C\n'
            '[release_check] FAIL: 1/3 未通过\n')
        io.open(_stem + '.ndjson', 'w', encoding='utf-8', newline='\n').write(
            ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in (
                {'seq': 1, 'name': 'A', 'status': 'pass'},
                {'seq': 2, 'name': 'B', 'status': 'error'},
                {'seq': 3, 'name': 'C', 'status': 'error'})))
        _bad = dispatch('test.gate.results', {'query': 'latest', 'dir': _td})
        case('**负向**: 两个出口 pass 打架时该表达式为假（断言不是装饰）',
             ((_bad.get('counts_text') or {}).get('pass')
              != (_bad.get('counts_json') or {}).get('pass')),
             'text=%s json=%s' % ((_bad.get('counts_text') or {}).get('pass'),
                                  (_bad.get('counts_json') or {}).get('pass')))
    finally:
        _sh.rmtree(_td, ignore_errors=True)
    # 负面: query 非法 / 非字符串 / 目录不存在 / diff 缺参
    ok, got = raises(lambda: dispatch('test.gate.results', {'query': 'nope'}),
                     'E_BAD_ARGS')
    case('**负向**: query 非法 -> E_BAD_ARGS（不静默回落 latest）', ok, got)
    ok, got = raises(lambda: dispatch('test.gate.results', {'query': ['latest']}),
                     'E_BAD_ARGS')
    case('**负向**: query 传非字符串 -> E_BAD_ARGS 而非 E_INTERNAL', ok, got)
    ok, got = raises(lambda: dispatch('test.gate.results',
                                      {'query': 'list', 'dir': 'no/such/dir'}),
                     'E_NOT_FOUND')
    case('**负向**: 日志目录不存在 -> E_NOT_FOUND', ok, got)
    ok, got = raises(lambda: dispatch('test.gate.results',
                                      {'query': 'diff', 'a': 'x'}), 'E_BAD_ARGS')
    case('**负向**: diff 缺 b -> E_BAD_ARGS', ok, got)


    # --- 4d. 生成面板（ST1: 复用 compose / compat / solve_profile, 不重写）---
    ml = dispatch('modules.list')
    _by = {m['name']: m for m in ml['modules']}
    # ST1.3 的验收原话点名了 known_limits。缺它 UI 会把每个模块渲染成
    # "无已知局限" —— 那是**静默的谎**, 比不显示更坏(P4 诚实边界纪律)。
    case('modules.list 暴露 known_limits（ST1.3 规格点名）',
         all('known_limits' in m for m in ml['modules']))
    case('至少一个模块真的写了已知局限（不是空字段凑数）',
         bool(_by.get('vm', {}).get('known_limits')),
         'vm=%d 条' % len(_by.get('vm', {}).get('known_limits') or []))
    case('modules.list 带 maturity_scale（分级的**依据**, 不是形容词）',
         bool(ml.get('maturity_scale', {}).get('_why_breached')))
    case('modules.list 的字段与 modules.json 对齐（不复制常量）',
         all(k in _by.get('integrity', {})
             for k in ('deps', 'conflicts_with', 'ordering', 'phases',
                       'consumes', 'produces', 'evidence')))

    g = dispatch('plan.graph', {'profile': 'balanced'})
    _nodes = [n['name'] for n in g['nodes']]
    case('plan.graph(profile) 覆盖 requested + auto_added',
         set(_nodes) == set(g['selected']),
         'nodes=%d selected=%d auto=%d' % (len(_nodes), len(g['selected']),
                                           len(g['auto_added'])))
    case('plan.graph 拓扑序覆盖全部节点（无遗漏）',
         sorted(g['topo']) == sorted(_nodes))
    case('plan.graph 依赖无环（cycle 为空）', not g['cycle'])
    case('plan.graph 有依赖边（否则图画不出来）', bool(g['edges']))
    # integrity 声明了与 selfcrypt 的冲突(原地改写 .text), 故只要 integrity
    # 被选中就必然出现一条 conflict 边 —— 这是"冲突可视化"的实际用例。
    # 边与冲突不必**等基数** —— 一条"模块对"可以有两种冲突(声明 + 派生)。
    # 真正要守的是"每条冲突都画得出来", 且边能区分两种来源。
    _ce = [e for e in g['edges'] if e['kind'] == 'conflict']
    case('plan.graph 每条冲突都有对应的边（不丢冲突）',
         len(_ce) == len(g['conflicts']),
         'edges=%d conflicts=%d' % (len(_ce), len(g['conflicts'])))
    case('plan.graph 冲突边带 conflict_kind（声明 vs 派生可区分）',
         all(e.get('conflict_kind') for e in _ce) if _ce else True,
         'kinds=%s' % sorted({e.get('conflict_kind') for e in _ce}))
    case('plan.graph 派生冲突未被按模块对去重吞掉',
         len({e['conflict_kind'] for e in _ce}) >= 2 if len(_ce) >= 2 else True,
         'kinds=%s' % sorted({e.get('conflict_kind') for e in _ce}))
    case('plan.graph 冲突边带 resolution（不只报错, 还说怎么办）',
         all(c.get('resolution') for c in g['conflicts']) if g['conflicts'] else True)
    case('plan.graph 区分 primitive 与 module 节点',
         all(n['is_primitive'] == (n['name'] not in {m['name'] for m in ml['modules']})
             for n in g['nodes']))

    # modules 优先于 profile: 面板里"手动改过之后再画图"是常见动作。
    g2 = dispatch('plan.graph', {'profile': 'balanced', 'modules': ['crc32']})
    case('plan.graph 里 modules 优先于 profile（手动改动能画图）',
         g2['source']['kind'] == 'modules' and g2['selected'] == ['crc32'],
         'kind=%s selected=%s' % (g2['source']['kind'], g2['selected']))

    # --- ST1.4 ⭐ 两种关系必须**分开陈述**（2026-09-23 的设计结论）---
    # `tools/compose.py:topo_order` 的注释逐字: 「deps 不参与链接顺序图…
    # deps = 能力依赖（运行时）, ordering = 链接顺序。二者语义不同, 不可混用。」
    # 我在 build/_st1_xcheck.py 里曾断言"拓扑序里每条 dep 边 from 都在 to 前"
    # ⇒ 7 条 FAIL —— **我断言了一条设计明确拒绝的性质**。
    # 于是 plan.graph 分两套边 + 一句说明: 面板若把 dep 边画进顺序图,
    # 画出来的是**自相矛盾的图**（实测每个组合两处相反）。
    case('plan.graph 每条边都带 relation（面板据此分三种图）',
         all(e.get('relation') in ('dep', 'conflict') for e in g['edges']),
         'relations=%s' % sorted({e.get('relation') for e in g['edges']}))
    case('plan.graph 给出 order_edges（拓扑序真正遵循的关系）',
         bool(g.get('order_edges')))
    _oe = [(e['from'], e['to']) for e in (g.get('order_edges') or [])]
    case('plan.graph order_edges 无重复（否则箭头多于约束）',
         len(_oe) == len(set(_oe)), 'n=%d uniq=%d' % (len(_oe), len(set(_oe))))
    _pos = {n: i for i, n in enumerate(g['topo'])}
    case('plan.graph 拓扑序对 order 关系合法（dep 不参与, 故不在此判）',
         not [1 for (f, t) in _oe if _pos.get(f, -1) > _pos.get(t, -1)])
    case('plan.graph 说明 dep 与 order 为何不可混用（否则被读成算错了）',
         bool((g.get('relations') or {}).get('why_not_mixed')))
    case('plan.graph 如实列出 topo_dep_violations（是证据, 不是错误）',
         isinstance(g.get('topo_dep_violations'), list))

    # ⭐ 策略求解出 **0 个模块** 是**合法结果**, 不是参数错误。
    # 实测 profiles/minimal-cost.json: threat `piracy` 推导所需能力 `respond`,
    # 而 13 个模块没有一个提供它 ⇒ selected=[]（plan.solve 同样如此）。
    # 报成 E_BAD_ARGS 会让面板说"你传错了参数", 而真相是"这个策略什么都不选"。
    ge = dispatch('plan.graph', {'profile': 'minimal-cost'})
    case('plan.graph 策略解得空集 -> 合法空图（不是 E_BAD_ARGS）',
         ge['selected'] == [] and ge['nodes'] == [] and bool(ge.get('notes')),
         'notes=%d' % len(ge.get('notes') or []))
    case('plan.graph 空集时仍带 source（面板知道是谁解出来的）',
         ge['source'].get('kind') == 'profile')
    case('**负向**: plan.graph 显式给空 modules -> 仍是 E_BAD_ARGS',
         raises(lambda: dispatch('plan.graph', {'modules': []}), 'E_BAD_ARGS'))


    # --- ST1.2 流式构建: 只拼装/只出计划, **默认不启动** ---
    argv = build_argv({'config': 'Dev'})
    case('build_argv 默认 Dev 且指向 build.ps1',
         'build.ps1' in argv[-3] or any('build.ps1' in a for a in argv),
         ' '.join(argv[-4:]))
    case('build_argv 带上 composition 等参数',
         '-Composition' in build_argv({'composition': 'minimal'})
         and '-SkipSmoke' in build_argv({'skip_smoke': True}))
    ev = list(build_events({}))
    case('build_events 不带 confirm 只回计划, 不启动构建',
         ev[0]['event'] == 'plan' and ev[0]['confirm_required']
         and not any(e['event'] == 'start' for e in ev),
         'events=%s' % [e['event'] for e in ev])
    case('build_events 的 done 如实说明没启动（不是假装跑过）',
         ev[-1].get('started') is False and bool(ev[-1].get('note')))

    case('**负向**: plan.graph 含未登记模块 -> E_BAD_ARGS',
         raises(lambda: dispatch('plan.graph', {'modules': ['no_such_mod']}),
                'E_BAD_ARGS'))
    case('**负向**: plan.graph 空集合 -> E_BAD_ARGS（无法画图）',
         raises(lambda: dispatch('plan.graph', {'modules': []}), 'E_BAD_ARGS'))
    case('**负向**: plan.graph 两参数都不给 -> E_BAD_ARGS',
         raises(lambda: dispatch('plan.graph', {}), 'E_BAD_ARGS'))
    case('**负向**: build_argv 非法 config -> E_BAD_ARGS',
         raises(lambda: build_argv({'config': 'Prod'}), 'E_BAD_ARGS'))
    case('**负向**: plan.graph 的 modules 非字符串列表 -> E_BAD_ARGS',
         raises(lambda: dispatch('plan.graph', {'modules': 'crc32'}),
                'E_BAD_ARGS'))
    if not quiet:
        lines.append('--- 4e. 主机级调试（ST3: 包装 prot_dbg, 不重写解析）---')
    dr = dispatch('debug.doctor')
    case('debug.doctor 返回 step=1 与 backend',
         dr.get('step') == 1 and dr.get('backend') == 'tools/prot_dbg.py')
    case('debug.doctor 如实标注**没有打开进程**',
         dr.get('opened_process') is False)
    case('debug.doctor 保留工具原始 payload（"与 CLI 一致"可自证）',
         isinstance((dr.get('payload') or {}).get('doctor'), dict))
    case('debug.doctor 摘要字段齐全（ok/syms/mask_regions）',
         all(k in (dr.get('summary') or {})
             for k in ('ok', 'syms', 'mask_regions', 'n_errors', 'n_warns')))
    ds = dispatch('debug.sym', {'symbols': ['g_wd_interval']})
    case('debug.sym 已知符号带 rva/va',
         (ds['symbols'].get('g_wd_interval') or {}).get('rva'))
    case('debug.sym 无缺失时 missing 为空', ds.get('missing') == [])
    dsb = dispatch('debug.sym', {'symbols': ['g_wd_interval', 'no_such_xyz']})
    case('debug.sym 未知符号如实例在 missing（不静默）',
         dsb.get('missing') == ['no_such_xyz'] and dsb.get('cli_ok') is False)
    case('debug.sym 单字符串也能当 symbols（面板常见形态）',
         dispatch('debug.sym', {'symbols': 'g_wd_interval'})['symbols']
         .get('g_wd_interval') is not None)
    de = dispatch('debug.exit', {'codes': ['219']})
    case('debug.exit 已知码 known=True',
         (de['codes'].get('219') or {}).get('known') is True)
    deu = dispatch('debug.exit', {'codes': ['4242']})
    case('debug.exit 未知码 known=False 且 cli_rc=1（**是结果, 不是异常**）',
         (deu['codes'].get('4242') or {}).get('known') is False
         and deu.get('cli_rc') == 1 and deu.get('cli_ok') is False)
    dm = dispatch('debug.mask', {})
    case('debug.mask 无符号时 payload_key=mask', dm.get('payload_key') == 'mask')
    dms = dispatch('debug.mask', {'symbols': ['g_sc_d2b_enabled']})
    case('debug.mask 带符号时如实透出 payload_key=sym（工具的委托行为）',
         dms.get('payload_key') == 'sym')
    dd = dispatch('debug.doctor', {'exe': 'build/no_such_product.exe'})
    case('debug.doctor 产物缺失 -> 是**返回的负结果**（cli_rc=1）而不是异常',
         dd.get('cli_rc') == 1 and (dd.get('summary') or {}).get('ok') is False)
    # ---- 活体: 安全闸必须是自己的错误码, 不能与"参数写错"混同 ----
    ok, got = raises(lambda: dispatch('debug.read', {'symbols': ['g_wd_interval']}),
                     'E_CONFIRM_REQUIRED')
    case('**负向**（安全闸）: debug.read 无 confirm -> E_CONFIRM_REQUIRED',
         ok, got)
    ok, got = raises(lambda: dispatch('debug.patch',
                                      {'symbols': ['g_wd_interval']}),
                     'E_CONFIRM_REQUIRED')
    case('**负向**（安全闸）: debug.patch 无 confirm -> E_CONFIRM_REQUIRED',
         ok, got)
    ok, got = raises(lambda: dispatch('debug.sym', {'symbols': []}),
                     'E_BAD_ARGS')
    case('**负向**: debug.sym 空 symbols -> E_BAD_ARGS（"没说"不是"没有"）',
         ok, got)
    ok, got = raises(lambda: dispatch('debug.exit', {'codes': []}),
                     'E_BAD_ARGS')
    case('**负向**: debug.exit 空 codes -> E_BAD_ARGS', ok, got)
    # ---- 流式 watch: 间隔与窗口必须在事件里可见 ----
    wev = []
    for _e in stream_events('debug.watch',
                            {'symbols': ['g_wd_interval'], 'interval': 0.5,
                             'seconds': 2.0}):
        wev.append(_e)
    case('debug.watch 首事件是 plan 且带 interval/seconds（ST3.3 验收点）',
         wev[0].get('event') == 'plan' and wev[0].get('interval') == 0.5
         and wev[0].get('seconds') == 2.0)
    case('debug.watch 不带 confirm 只给计划, 不启动（末事件 started=False）',
         wev[-1].get('event') == 'done' and wev[-1].get('started') is False
         and not any(e.get('event') == 'start' for e in wev))
    case('debug.watch 的 plan 里 prepatch 结构化可见',
         wev[0].get('prepatch') == [])
    ok, got = raises(lambda: dispatch('debug.watch', {'symbols': ['x']}),
                     'E_STREAM_CMD')
    case('**负向**: debug.watch 走 dispatch -> E_STREAM_CMD（不是 UNKNOWN）',
         ok, got)

    if not quiet:
        lines.append('--- 5. **负向**（必须能抓错）---')
    ok, got = raises(lambda: dispatch('no.such.cmd'), 'E_UNKNOWN_CMD')
    case('**负向**: 未知命令 -> E_UNKNOWN_CMD', ok, got)
    e = None
    try:
        dispatch('no.such.cmd')
    except StudioError as ex:
        e = ex
    case('**负向**: 未知命令的错误里**列出候选**（不失锚）',
         bool(e) and e.detail and len(e.detail.get('available', [])) >= 5)
    ok, got = raises(lambda: dispatch('plan.solve', {}), 'E_BAD_ARGS')
    case('**负向**: 缺 profile -> E_BAD_ARGS', ok, got)
    ok, got = raises(lambda: dispatch('plan.solve', {'profile': 'nope'}),
                     'E_NOT_FOUND')
    case('**负向**: 不存在的策略 -> E_NOT_FOUND', ok, got)
    ok, got = raises(lambda: dispatch('plan.solve', {'profile': []}),
                     'E_BAD_ARGS')
    case('**负向**（无静默回退）: profile 传非字符串 -> E_BAD_ARGS 而非 E_INTERNAL',
         ok, got)
    ok, got = raises(lambda: dispatch('ping', ['not', 'a', 'dict']),
                     'E_BAD_ARGS')
    case('**负向**: args 非对象 -> E_BAD_ARGS', ok, got)
    ok, got = raises(lambda: read_json('no/such/file.json'), 'E_NOT_FOUND')
    case('**负向**: 读缺失 JSON -> E_NOT_FOUND（不返回 None）', ok, got)

    if not quiet:
        lines.append('--- 6. envelope（NDJSON 响应形态）---')
    ev = envelope('ping', {}, req_id=7)
    case('成功包: ok=true 且 id 原样回传',
         ev['ok'] is True and ev['id'] == 7 and 'data' in ev)
    ev2 = envelope('no.such.cmd', {}, req_id='x')
    case('失败包: ok=false 且含 code/message/detail（**不抛异常**）',
         ev2['ok'] is False and ev2['id'] == 'x'
         and all(k in ev2['error'] for k in ('code', 'message', 'detail')))
    case('失败包可 JSON 序列化', bool(json.dumps(ev2, ensure_ascii=False)))
    case('成功包可 JSON 序列化', bool(json.dumps(ev, ensure_ascii=False)))

    if not quiet:
        lines.append('')
        lines.append('=' * 66)
    if fails:
        print('\n'.join(lines))
        print('[studio_core-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    if not quiet:
        print('\n'.join(lines))
    print('[studio_core-selftest] PASS: 契约/能力/门禁清单/负向均可自证')
    return 0


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog='studio_core.py')
    ap.add_argument('--list', action='store_true', help='列命令')
    ap.add_argument('--call', help='调用一条命令（stdin 传 args JSON）')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest(args.quiet)
    if args.list:
        for k in sorted(COMMANDS):
            d = (COMMANDS[k].__doc__ or '').strip().splitlines()
            print('%-16s %s' % (k, d[0] if d else ''))
        return 0
    if args.call:
        raw = sys.stdin.read()
        try:
            a = json.loads(raw) if raw.strip() else {}
        except ValueError as e:
            print(json.dumps(envelope(None, None, None), ensure_ascii=False))
            sys.stderr.write('args 不是合法 JSON: %s\n' % e)
            return 1
        print(json.dumps(envelope(args.call, a), ensure_ascii=False))
        return 0
    ap.print_help()
    return 0


if __name__ == '__main__':
    sys.exit(main())
