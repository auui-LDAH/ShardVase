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
  · 本模块**不启动进程**（那是 `studio_cli.py` / ST1-ST3 的事）。
"""
import io
import json
import os
import re
import struct
import sys

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
    for m in re.finditer(r"(?m)^\s*Check\s+'([^']+)'", src):
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
                'planned', 'tools/release_check.ps1',
                '今天只有 PowerShell 转录, 无结构化结果',
                step='ST2',
                note='门禁结果机读化（文本 + NDJSON 双出口, 同轮对照）'),
            'generate.build': cap(
                'planned', 'build.ps1',
                '构建可跑, 但无流式进度事件',
                step='ST1'),
            'debug.host': cap(
                'partial', 'tools/prot_dbg.py',
                'sym/mask/exit/read/patch/watch 已可用; 无断点/单步/反汇编',
                step='ST3',
                note='工具自身 OpenProcess 可能触发目标反调试（实测 219）'),
            'debug.vm': cap(
                'ready', 'tools/vm_debug.py',
                '反汇编(含真实镜像 key1 逆置换) / 单步 / 源码行号断点 / 栈+寄存器视图',
                step='ST4',
                note='ST4.1 的 .vasm 行号表是 sidecar, 发布产物不携带。'
                     '主机级断点仍属 ST3（未做）'),
            'ui': cap(
                'planned', '（无）',
                '全库零前端痕迹',
                step='ST5',
                note='本机 npm 不可用 ⇒ 默认本地浏览器 + 零依赖'),
        },
    }


# --- 命令实现 --------------------------------------------------------------

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
            'conflicts_with': sorted(m.get('conflicts_with', [])),
            'cost': None,                    # 由 solve_profile.COST 提供
            'header': m.get('header'),
            'source': m.get('source'),
        })
    try:
        import solve_profile as _sp
        for it in out:
            it['cost'] = _sp.COST.get(it['name'], 'low')
    except Exception:
        pass                                  # 成本是附加信息, 缺失不致命
    return {'modules': out, 'count': len(out),
            'primitives': sorted(reg.get('primitives', {})),
            'protocol_version': reg.get('_protocol_version'),
            'format_version': reg.get('_format_version'),
            'source': 'modules.json'}


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


# --- 注册表 ----------------------------------------------------------------

COMMANDS = {
    'ping': cmd_ping,
    'capabilities': cmd_capabilities,
    'plan.list': cmd_plan_list,
    'plan.solve': cmd_plan_solve,
    'modules.list': cmd_modules_list,
    'gate.items': cmd_gate_items,
    'vm.images': cmd_vm_images,
    'vm.disasm': cmd_vm_disasm,
}


def dispatch(cmd, args=None):
    """执行一条命令, **返回可 JSON 序列化的 dict**。

    未知命令抛 `StudioError('E_UNKNOWN_CMD')` —— 并**列出候选**,
    因为面板与脚本都会因拼错名字而撞上它（§2.53 的"失锚不静默"）。
    """
    if cmd not in COMMANDS:
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
    case('capabilities 含 8 项能力',
         len(caps.get('capabilities', {})) == 8)
    case('planned 项如实标注（ui / test.gate.results / generate.build）',
         all(caps['capabilities'][k]['status'] == 'planned'
             for k in ('ui', 'test.gate.results', 'generate.build')))
    # ST4 落地后 debug.vm 变 ready —— 但 `partial` 的 debug.host 与 **任何**
    # 未声明为 ready 的项都不许出现在"已完成"里。这条断言跟着能力一起演进，
    # 且**先断言存在**再断言取值（否则改名会让它静默变成永真）。
    case('debug.vm 自 ST4 起为 ready',
         caps['capabilities'].get('debug.vm', {}).get('status') == 'ready')
    case('debug.host 仍如实标为 partial（主机级断点未做）',
         caps['capabilities'].get('debug.host', {}).get('status') == 'partial')
    case('每项能力都有 evidence（不是形容词）',
         all(c.get('evidence') for c in caps['capabilities'].values()))
    case('每项能力都有 step（知道属于哪个阶段）',
         all(c.get('step') for c in caps['capabilities'].values()))

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
