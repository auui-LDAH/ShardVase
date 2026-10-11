# -*- coding: utf-8 -*-
"""对账 `docs/STUDIO_PROTOCOL.md` 的命令清单与 `tools/studio_core.py` 的注册表。

## 为什么需要这个工具

`docs/STUDIO_PROTOCOL.md:92` 曾经写的是 `items[]`，而后端发的是
`capabilities{}`。前端**照着文档写**，于是「关于」页从 ST5 起一直是空的
（详见 `docs/HANDOVER.md` §2.68）。修完之后留了一个同类洞：

**协议文档是「契约」，但没有任何判据在对账它。** 实测两个方向：

* 从文档里删掉一条真命令（`plan.list`）⇒ `doccheck` / `studio_core --selftest` /
  `studio_server --selftest` / `docclaim_check` **四个全绿**；
* 重命名代码里的命令 ⇒ 只有 `studio_core --selftest` 自己的内部断言会红，
  而那一条**读的是代码，不是文档**。

⇒ 「文档说了什么」与「代码实现了什么」今天没有任何一处交叉验证。

## 判据

1. **命令集合双向一致**：文档 §5 表格 + §5.1 流式命令 == `COMMANDS` ∪ `STREAM_COMMANDS`。
   两个方向都要查 —— 只查一个方向会漏掉「文档里留下了一条已经不存在的命令」。
2. **声明的 `名称[]` / `名称{}` 键必须真的存在**于该命令的载荷里。
   这是 `loadCaps` 缺陷的形状，且**只提取无歧义形态**：`items[]` / `capabilities{}`。
   不碰裸反引号标识符 —— 那一列里混着枚举值（`latest`）、函数名
   （`solve_profile.solve()`）与字面量（`E_BAD_ARGS`），按它们对账会要求
   篡改正确的文档才变绿。

## 三态

* 找不到文档 / 解析出 0 行 ⇒ `rc=1`（**失锚不静默**），不是 SKIP。
* 有差异 ⇒ `rc=1`，逐条打印。
* 一致 ⇒ `rc=0`。

本工具**不启浏览器、不跑构建**，纯读文件 + 调用 `dispatch()` 的只读命令。
"""

import argparse
import io
import os
import re
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
if os.path.join(REPO, 'tools') not in sys.path:
    sys.path.insert(0, os.path.join(REPO, 'tools'))

RC_OK = 0
RC_FAIL = 1

DOC_REL = 'docs/STUDIO_PROTOCOL.md'

# 表格里一个数据行形如:  | `cmd` | args | data |
_ROW = re.compile(r'^\|\s*`([^`]+)`\s*\|(.*)$')

# 只认「无歧义的键形态」：标识符后面紧跟 [] 或 {}。
_DECL_KEY = re.compile(r'`([A-Za-z_][A-Za-z0-9_]*)(\[\]|\{\})`')

# §5.1 标题形如: ### 5.1 流式命令（`build.run` / `debug.watch`）—— ...
_STREAM_HEAD = re.compile(r'^###\s*5\.1\b.*$', re.M)

# 单元格里的转义竖线：Markdown 表格用 `\|` 表示字面竖线。
_ESC_PIPE = '\x00PIPE\x00'

# ---- 请求侧（args 列）对账 -------------------------------------------------
# args 列里的键：`symbols[]` / `exe?` / `confirm` —— 三种形态都要认。
_ARG_KEY = re.compile(r'`([A-Za-z_][A-Za-z0-9_]*)(\[\])?(\?)?`')

# studio_core 的「键为空」报文：'%s 为空 -> 不知道该%s什么' % (key, what)
_EMPTY_NAMED = re.compile(r'([A-Za-z_][A-Za-z0-9_]*) 为空')

# 按文档 args 列造参数时，判断每个键该给什么类型的值。
# ⚠️ 这些表是**探针口径**，不是契约：给错类型只会让 dispatch 抛别的错，
#   而下面的两条判据都只看「报错有没有点到键名」，所以类型猜错不会造成假阳性。
_ARG_LIST_KEYS = frozenset(('symbols', 'codes', 'lines', 'add', 'remove', 'modules'))
_ARG_INT_KEYS = frozenset(('length', 'max_steps', 'mem_size', 'run',
                           'a', 'b', 'interval', 'seconds'))
_ARG_LIST_VALUE = {'symbols': ['main'], 'modules': ['vm'], 'lines': [1],
                   'add': [2], 'remove': [2], 'codes': ['219']}
_ARG_STR_VALUE = {'asm': 'tests/unit_vm.vasm', 'source': 'asm', 'name': 'main',
                  'profile': 'balanced', 'query': 'latest',
                  'exe': 'build/demo.exe', 'map': 'build/demo.map',
                  'dir': 'build/logs', 'blob': 'build/vm.blob',
                  'session': 'no-such', 'pid': 0, 'restore': True,
                  'nop': True, 'bytes': '90', 'patch': '90'}


def _cells(row_body):
    """把一个数据行切成单元格。先保护 `\\|`，再按 `|` 切。"""
    return [c.strip() for c in row_body.replace('\\|', _ESC_PIPE).split('|')]


def parse_doc(text):
    """解析协议文档，返回 {'rows': {cmd: {'line','args','data'}}, 'stream': [cmd]}。

    解析不出任何命令行时返回空 dict —— 调用方必须把它当**失败**（失锚），
    不能当成「文档里没有命令」而静默通过。
    """
    lines = text.split('\n')
    rows = {}
    # 表头 = 同时含 `cmd` 与 `args` 的行，之后紧跟分隔行，然后才是数据行。
    start = None
    for i, l in enumerate(lines):
        if l.startswith('| `cmd` |') and '`args`' in l:
            start = i
            break
    if start is not None:
        j = start + 2
        while j < len(lines) and lines[j].startswith('|'):
            m = _ROW.match(lines[j])
            if m:
                cells = _cells(lines[j][1:])
                rows[m.group(1)] = {
                    'line': j + 1,
                    'args': cells[1] if len(cells) > 1 else '',
                    'data': cells[2] if len(cells) > 2 else '',
                }
            j += 1

    stream = []
    m = _STREAM_HEAD.search(text)
    if m:
        # 只取标题那一行里的反引号命令名。
        head_line = lines[text[:m.start()].count('\n')]
        for c in re.findall(r'`([a-z][A-Za-z0-9_.]*)`', head_line):
            if '.' in c:
                stream.append(c)
    return {'rows': rows, 'stream': stream}


def code_commands():
    """代码侧的权威命令集。"""
    import studio_core as sc
    plain = set(sc.COMMANDS)
    stream = set(getattr(sc, 'STREAM_COMMANDS', ()) or ())
    return plain, stream


def _asm_sample():
    for cand in ('tests/unit_vm.vasm', 'demo/vm_prog.vasm'):
        if os.path.isfile(os.path.join(REPO, cand)):
            return cand
    return None


def _asm_args(source=None):
    """`vm.source` / `vm.disasm` 要一个 asm 路径 —— 用仓库里真实存在的那个。

    `vm.disasm` 的 `source` 缺省是 `'blob'`（那条路要 `name`，要真产物），
    所以显式给 `source='asm'`。没有样本时返回 {}，命令会抛 StudioError
    落进 skipped（**不猜**一个假路径）。
    """
    a = _asm_sample()
    if not a:
        return {}
    d = {'asm': a}
    if source:
        d['source'] = source
    return d


# 让「零参跑不动」的命令也能被验证形状：只补齐**跑得动**的最小参数。
# 每一条都写在源码里（不猜），且只用于只读命令。
SAMPLE_ARGS = {
    'plan.solve': {'profile': 'balanced'},
    'plan.graph': {'profile': 'balanced'},
    'test.gate.results': {'query': 'latest'},
    'debug.sym': {'symbols': ['main']},
    'debug.mask': {'symbols': ['main']},
    'debug.exit': {'codes': [0]},
    'vm.source': _asm_args(),
    'vm.disasm': _asm_args('asm'),
    # 只读：读的是本工具自己的文件（ST5.5 的 src.show，`lines[]` 是它的声明键）
    'src.show': {'path': 'tools/studio_core.py', 'line': 1},
}


def declared_keys(row):
    """从 data 列里提取无歧义的 `名称[]` / `名称{}` 键。"""
    return sorted({m.group(1) for m in _DECL_KEY.finditer(row.get('data', ''))})


# `X[]` / `X{}`：**容器声明**。空花括号表示「以名字为键的表」（值是声明形状）。
_CONTAINER_KEY = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)(\[\]|\{\})$')

# `summary{a, b}`：父键**内联**子键 —— 子键在对象**自身**上，不是它某一层的值。
_INLINE_SUBS = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\{(.*)\}$')

# data 列里的一个反引号词元。
_BACKTICK = re.compile(r'`([^`]*)`')

# 子键名后缀：`tokens[][2]` / `list[]` —— 判前剥掉。
_SUB_SUFFIX = re.compile(r'(?:\[\])|(?:\[\d+\])$')


def _sub_names(blob):
    """从 `{ok, syms, note?, tokens[][2]}` 的花括号内部取子键。

    返回 `[(名字, 是否可选)]`。**只认标识符** —— 花括号里的散文（`{略}`）
    一律丢弃，避免把说明文字当成键名（§2.70 记过宽化扫描面的 9 条假阳性）。
    """
    out = []
    for raw in blob.split(','):
        s = raw.strip()
        if not s:
            continue
        opt = s.endswith('?')
        if opt:
            s = s[:-1].strip()
        while True:
            m = _SUB_SUFFIX.search(s)
            if not m:
                break
            s = s[:m.start()].strip()
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', s) and (s, opt) not in out:
            out.append((s, opt))
    return out


def declared_shapes(cell):
    """data 列里用 `{...}` 写出的子键集合。

    返回 `[(parent, kind, [(名字, 可选)])]`，`parent` 为 None = 悬空块
    （文档写了一个花括号子键表，但它不属于任何已声明的容器）。

    ⭐ 为什么需要它：`_DECL_KEY` 要求反引号**紧跟** `[]`/`{}`，于是

      - `` `summary{ok, syms, ...}` ``（父键内联子键）
      - `` `items[]` `{name, line, gated}` ``（数组元素键）

    两种写法都**结构上匹配不到** ⇒ 把它们全改成垃圾名字，判据照样全绿。
    实测见 §2.72：改坏 5 个 `summary` 子键与 20 个 `modules[]` 元素键，
    报错都是 0 条。

    kind ∈ `arr`（元素）/ `vals`（以名字为键的表的值）/ `self`（对象自身）。
    """
    out = []
    last = None              # (parent, kind) —— 最近一个容器声明
    for m in _BACKTICK.finditer(cell):
        t = m.group(1).strip()
        if t.startswith('{') and t.endswith('}'):
            subs = _sub_names(t[1:-1])
            if subs:
                if last is None:
                    out.append((None, 'self', subs))
                else:
                    out.append((last[0], last[1], subs))
            continue
        mc = _CONTAINER_KEY.match(t)
        if mc:
            last = (mc.group(1), 'arr' if mc.group(2) == '[]' else 'vals')
            continue
        mi = _INLINE_SUBS.match(t)
        if mi:
            subs = _sub_names(mi.group(2))
            if subs:
                out.append((mi.group(1), 'self', subs))
    return out


def arg_keys(row):
    """从 args 列里提取参数键名（`symbols[]` / `exe?` / `confirm` 三种形态）。"""
    cell = row.get('args', '')
    # 只看第一个备选（`a` | `b`）：备选是「二选一」，全给反而互相冲突。
    alt = cell.split(_ESC_PIPE)[0]
    out = []
    for m in _ARG_KEY.finditer(alt):
        k = m.group(1)
        if k not in out:
            out.append(k)
    return out


def arg_probe_value(key, is_list):
    """按文档声明给一个「非空」的值 —— 类型猜错不会造成假阳性（见 _ARG_* 注释）。"""
    if is_list or key in _ARG_LIST_KEYS:
        return _ARG_LIST_VALUE.get(key, [0])
    if key in _ARG_INT_KEYS:
        return 1
    return _ARG_STR_VALUE.get(key, 'x')


def args_from_doc(row):
    """用**文档自己声明的** args 造一份参数字典。

    ⚠️ **绝不给 `confirm`**：`debug.read` / `debug.patch` 的文档就声明了
    `confirm`，而 `_need_confirm()` 只看真假值 —— 给一个真值等于让判据
    在门禁里**真的去附着目标进程**。不给 ⇒ 那两个命令停在
    `E_CONFIRM_REQUIRED`（不点名键名 ⇒ 天然不会被误判成漂移）。
    """
    cell = row.get('args', '')
    alt = cell.split(_ESC_PIPE)[0]
    out = {}
    for m in _ARG_KEY.finditer(alt):
        k, is_list = m.group(1), bool(m.group(2))
        if k in out or k == 'confirm':
            continue
        out[k] = arg_probe_value(k, is_list)
    return out


def source_literals(path=None):
    """studio_core.py 里出现过的字符串字面量 —— 词法臂的判据面。"""
    p = path or os.path.join(REPO, 'tools', 'studio_core.py')
    try:
        src = io.open(p, encoding='utf-8').read()
    except OSError:
        return None
    lits = set(re.findall(r"'([A-Za-z_][A-Za-z0-9_]*)'", src))
    lits |= set(re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"', src))
    return lits


def judge_args(doc, plain, literals=None, behavior=True, dispatch_fn=None,
               stream=()):
    """纯函数：请求侧对账。返回 `(problems, info)`。

    两条臂互补，缺一条就会漏掉一个方向：

    - **词法臂**：文档声明的键名必须作为字面量出现在 `studio_core.py` 里。
      抓「文档写错名字」（方向 A）。
    - **行为臂**：按**文档声明的键**造参数喂 `dispatch()`；如果报错说
      「<某键> 为空」，而那个键**正是我刚按文档给的**，说明代码读的是另一个
      名字。抓「代码改了读的键名」（方向 B）。

    为什么要两条：词法臂只在**新名字**从未出现过时命中（把 `codes` 改成
    `codez` 时，`codes` 作为字面量在别处（自检里）仍然存在 ⇒ 词法臂不红）；
    行为臂则在报错**不点名**时命中不了（代码把键改名后静默取了缺省值）。
    实测两个方向各有一臂独占命中 —— 见 §2.70。
    """
    problems = []
    info = {}
    rows = (doc or {}).get('rows') or {}
    if not rows:
        return ['%s 里解析不出任何命令行 —— 请求侧对账失去锚点' % DOC_REL], info
    if literals is None:
        literals = source_literals()
    if literals is None:
        return ['读不到 tools/studio_core.py —— 请求侧对账失去锚点'], info

    stream = set(stream or ())
    lex_hits = 0
    beh_hits = 0
    judged = 0
    for c in sorted(rows):
        if c in stream or c not in plain:
            continue
        keys = arg_keys(rows[c])
        if not keys:
            continue
        judged += 1
        miss = [k for k in keys if k not in literals]
        if miss:
            lex_hits += 1
            problems.append('%s:%d 为 %s 声明了参数 `%s`，但 `tools/studio_core.py` '
                            '里没有这个名字的字面量 —— 文档把参数名写错了？'
                            '（照着文档写的调用方会拿到缺省值/报参数缺失）'
                            % (DOC_REL, rows[c]['line'], c, '`, `'.join(miss)))
        # 行为臂：只对**只读**命令真的调一次 dispatch()。
        # 写类命令（debug.patch 之类）会被 confirm 拦住，报错不点名键名 ⇒ 天然不命中。
        if not behavior or dispatch_fn is None:
            continue
        given = args_from_doc(rows[c])
        supplied = [k for k in keys if given.get(k) not in (None, '', [], {})]
        if not supplied:
            continue
        try:
            dispatch_fn(c, given)
            continue
        except Exception as e:
            msg = str(e)
        named = [k for k in _EMPTY_NAMED.findall(msg) if k in supplied]
        if named:
            beh_hits += 1
            problems.append('%s:%d 的 %s：按文档给了 `%s`，代码却说它为空 —— '
                            '代码读的键名与文档不一致'
                            % (DOC_REL, rows[c]['line'], c, '`, `'.join(named)))
    info['arg_judged'] = judged
    info['arg_lex'] = lex_hits
    info['arg_beh'] = beh_hits
    if judged == 0:
        problems.append('一条命令的 args 列都没解析出参数 —— '
                        '请求侧对账失去锚点，不能当通过')
    return problems, info


def judge(doc, plain, stream, check_payload=True, sample_args=None,
          check_shapes=True):
    """纯函数：返回 `(problems, info)`。空 problems 表示一致。"""
    problems = []
    info = {}
    sample_args = SAMPLE_ARGS if sample_args is None else sample_args

    rows = (doc or {}).get('rows') or {}
    doc_stream = (doc or {}).get('stream') or []

    # ---- 失锚守卫：两侧都不能是空的 ----
    if not rows:
        problems.append('%s 里解析不出任何命令行 —— 判据失去锚点'
                        '（表格格式变了？只剩流式命令？）' % DOC_REL)
    if not plain:
        problems.append('studio_core.COMMANDS 是空的 —— 判据失去锚点')
    if problems:
        return problems, info

    code_all = set(plain) | set(stream)
    doc_all = set(rows) | set(doc_stream)
    info['code'] = len(code_all)
    info['doc'] = len(doc_all)

    # ---- ① 双向集合一致 ----
    only_code = sorted(code_all - doc_all)
    only_doc = sorted(doc_all - code_all)
    for c in only_code:
        problems.append('命令 %s 在代码里注册了，但协议文档 §5 里没有 '
                        '（文档漏项：新命令必须写进契约）' % c)
    for c in only_doc:
        problems.append('协议文档 §5 声称有命令 %s，但代码里没有 '
                        '（文档陈旧：删掉命令时必须同步改文档）' % c)

    # ---- ② 声明的 []/{ } 键必须真的存在于载荷 ----
    verified = 0
    skipped = []
    if check_payload:
        import studio_core as sc
        for c in sorted(rows):
            keys = declared_keys(rows[c])
            if not keys or c not in plain:
                continue
            args = dict(sample_args.get(c, {}))
            try:
                payload = sc.dispatch(c, args)
            except Exception as e:
                skipped.append('%s(%s)' % (c, type(e).__name__))
                continue
            if not isinstance(payload, dict):
                problems.append('%s 的载荷不是对象（%s）—— 无法对账声明键'
                                % (c, type(payload).__name__))
                continue
            verified += 1
            for k in keys:
                if k not in payload:
                    problems.append('文档 %s:%d 为 %s 声明了 `%s[]`/`%s{}`，'
                                    '但载荷里没有这个键 —— 照着文档写的消费方会读到 '
                                    'undefined（§2.68 的 loadCaps 就是这个形状）'
                                    % (DOC_REL, rows[c]['line'], c, k, k))
        info['verified'] = verified
        info['skipped'] = skipped
        if verified == 0:
            problems.append('一条命令的载荷都没能对账（全部需要参数？）—— '
                            '判据失去锚点，不能当通过')

    info['only_code'] = only_code
    info['only_doc'] = only_doc

    # ---- ③ 花括号子键（`summary{a,b}` / `items[]` `{a,b}`）----
    # 与 ② 同属「响应侧」，但落点算法不同（② 是 `k in payload`，③ 要先
    # 按 `[]`/`{}` 判定往下走一层）⇒ 分成两条判据，缺一条就漏一个方向。
    if check_payload and check_shapes:
        sp, sinfo = judge_shapes(doc, plain, sample_args=sample_args)
        problems.extend(sp)
        info.update(sinfo)
    return problems, info


def _elem_dict(payload, parent, kind):
    """按 kind 从载荷里取出「一组应当带这些子键的对象」。

    - `arr`：`parent` 是列表 ⇒ 取**每个**元素（元素可能形状不一，
      所以返回列表而不是一个）。
    - `vals`：`parent` 是「以名字为键的表」 ⇒ 取**每个**值。
    - `self`：`parent` 就是那个对象本身。

    返回 `(objs, why)`：`why` 非空表示取不到（父键缺失/类型不对），
    调用方必须**报错**而不是静默跳过 —— 否则文档写错父键名时，
    这条判据会退化成「什么都查不到 = 通过」。
    """
    if parent not in payload:
        return [], '载荷里没有父键 `%s`' % parent
    v = payload[parent]
    if kind == 'self':
        if not isinstance(v, dict):
            return [], '`%s` 不是对象（%s）' % (parent, type(v).__name__)
        return [v], ''
    if kind == 'arr':
        if not isinstance(v, list):
            return [], '`%s` 不是数组（%s）' % (parent, type(v).__name__)
        objs = [e for e in v if isinstance(e, dict)]
        if not objs and v:
            return [], '`%s` 的元素不是对象' % parent
        return objs, ''
    if kind == 'vals':
        if not isinstance(v, dict):
            return [], '`%s` 不是对象（%s）' % (parent, type(v).__name__)
        objs = [e for e in v.values() if isinstance(e, dict)]
        return objs, ''
    return [], '未知的声明形态 %r' % kind


def judge_shapes(doc, plain, sample_args=None, require_anchor=True):
    """纯函数：**花括号子键**对账。返回 `(problems, info)`。

    与 `judge()` 的 ② 是同一条判据的两半：② 查「顶层键在不在」，
    这里查「声明的子键在不在」。分开写是因为两者的**落点算法不同** ——
    顶层键直接 `k in payload`，子键要先按 `[]`/`{}` 判定往下走几层。
    """
    problems = []
    info = {}
    sample_args = SAMPLE_ARGS if sample_args is None else sample_args
    rows = (doc or {}).get('rows') or {}
    if not rows:
        return ['%s 里解析不出任何命令行 —— 响应子键对账失去锚点' % DOC_REL], info

    import studio_core as sc
    has_shapes = any(declared_shapes(r.get('data', '')) for r in rows.values())
    checked = 0
    keys_checked = 0
    skipped = []
    for c in sorted(rows):
        shapes = declared_shapes(rows[c].get('data', ''))
        if not shapes or c not in plain:
            continue
        try:
            payload = sc.dispatch(c, dict(sample_args.get(c, {})))
        except Exception as e:
            skipped.append('%s(%s)' % (c, type(e).__name__))
            continue
        if not isinstance(payload, dict):
            continue
        checked += 1
        for parent, kind, subs in shapes:
            if parent is None:
                problems.append('文档 %s:%d 的 %s：有一个 `{...}` 子键表，'
                                '但它前面没有任何 `名称[]`/`名称{}` 容器声明 —— '
                                '读的人不知道这些子键属于谁'
                                % (DOC_REL, rows[c]['line'], c))
                continue
            objs, why = _elem_dict(payload, parent, kind)
            if why:
                problems.append('文档 %s:%d 的 %s 声明了 `%s%s` 的子键，但%s '
                                '—— 照着文档写的消费方会读不到东西'
                                % (DOC_REL, rows[c]['line'], c, parent,
                                   '[]' if kind == 'arr' else
                                   ('{}' if kind == 'vals' else ''),
                                   why))
                continue
            if not objs:
                # 空数组：没有元素就无从核对。如实计数，不静默当通过。
                skipped.append('%s(%s 为空)' % (c, parent))
                continue
            for name, opt in subs:
                keys_checked += 1
                missing = [i for i, o in enumerate(objs) if name not in o]
                if missing and not opt:
                    idx = ', '.join(str(i) for i in missing[:4])
                    if len(missing) > 4:
                        idx += ' 等 %d 个' % len(missing)
                    problems.append('文档 %s:%d 的 %s 声明 `%s` 带子键 `%s`，'
                                    '但第 %s 个元素里没有 —— 照着文档写的消费方'
                                    '会读到 undefined（§2.68 的 loadCaps 就是这个形状）'
                                    % (DOC_REL, rows[c]['line'], c, parent, name,
                                       idx))
    info['shape_cmds'] = checked
    info['shape_keys'] = keys_checked
    info['shape_skipped'] = skipped
    # 失锚守卫：文档里**有**花括号子键表，却一条都没能对账 ⇒ 不能当通过。
    # 反过来（文档里根本没有这种写法）是正常的沉默，不报。
    if require_anchor and has_shapes and checked == 0:
        problems.append('文档里有花括号子键表，但一条命令的响应子键都没能对账'
                        '（全部需要参数？）—— 判据失去锚点，不能当通过')
    return problems, info


# ---------------------------------------------------------------- 自检

def _fixture(cmds=('ping', 'plan.list'), stream=('build.run',)):
    """造一份最小的「文档解析结果」。返回 doc（不是元组 —— 调用方全都要用它）。"""
    rows = {}
    for i, c in enumerate(cmds):
        rows[c] = {'line': 90 + i, 'args': '—', 'data': '`items[]`'}
    return {'rows': rows, 'stream': list(stream)}


def selftest(quiet=False):
    """造坏输入喂 judge() —— 证明判据**会**红。"""
    fails = []
    ncase = 0
    nneg = 0

    def case(name, doc, plain, stream, want, sub=None, **kw):
        nonlocal ncase, nneg
        ncase += 1
        if not want:
            nneg += 1
        probs, _info = judge(doc, plain, stream, **kw)
        got = not probs
        good = (got == want)
        det = 'problems=%s' % (probs[:1] if probs else [])
        if good and sub is not None:
            good = any(sub in p for p in probs)
            if not good:
                det += ' (缺少子串 %r)' % sub
        if not good:
            fails.append('%-50s want_ok=%s %s' % (name, want, det))
        elif not quiet:
            print('  ok  %-50s %s' % (name, det))

    base = _fixture(cmds=('ping', 'plan.list'), stream=('build.run',))
    # 合规：代码与文档一致，且关掉载荷对账（自检不依赖真实后端）
    case('合规（两侧一致）-> 通过', base, {'ping', 'plan.list'}, {'build.run'},
         True, check_payload=False)

    # ★ 本轮真缺陷形状：文档声明 items[] 而载荷没有
    case('★ 文档声明 items[] 但载荷没有 -> 必须报',
         base, {'ping', 'plan.list'}, {'build.run'}, False,
         'loadCaps', check_payload=True,
         sample_args={})
    # 承上：所有命令都需要参数 ⇒ 一条都没对账上 ⇒ 必须报失锚。
    # ⚠️ fixture 必须让每条命令都 **跑不动**，否则先撞上的是键缺失那条。
    # 声明键必须用 []/{ } 形态，否则 declared_keys() 返回空、循环直接跳过，
    # 就到不了「一条都没对账上」那条守卫。
    needs_args = _fixture(cmds=('vm.state', 'vm.continue'), stream=())
    needs_args['rows']['vm.state']['data'] = '`session{}`'
    needs_args['rows']['vm.continue']['data'] = '`stop_reason{}`'
    case('载荷一条都没对账上 -> 必须报（失锚）',
         needs_args, {'vm.state', 'vm.continue'}, set(), False,
         '失去锚点', check_payload=True, sample_args={})

    # 代码有、文档没有
    case('代码新命令没写进文档 -> 必须报',
         base, {'ping', 'plan.list', 'plan.newthing'}, {'build.run'}, False,
         '文档漏项', check_payload=False)
    # 文档有、代码没有
    case('文档留下已删命令 -> 必须报',
         base, {'ping'}, {'build.run'}, False, '文档陈旧', check_payload=False)
    # 流式命令：代码注册了、文档漏了（fixture 的 stream 里有 build.run,
    # 所以这里必须把它从**文档**里删掉，而不是从代码里删）
    case('文档漏掉流式命令 -> 必须报',
         _fixture(cmds=('ping', 'plan.list'), stream=()),
         {'ping', 'plan.list'}, {'build.run'}, False, '文档漏项',
         check_payload=False)

    # 失锚：文档解析不出行
    case('文档解析出 0 行 -> 必须报（失锚）',
         {'rows': {}, 'stream': ['build.run']}, {'ping', 'plan.list'}, set(),
         False, '失去锚点', check_payload=False)
    # 失锚：代码侧为空
    case('代码命令表为空 -> 必须报（失锚）',
         base, set(), {'build.run'}, False, '失去锚点', check_payload=False)
    # 失锚：流式命令不在文档里，但表格正常 —— 上面的 case 已覆盖；再补一条
    # 「文档表格为空但流式有」的独立形态
    case('文档只有流式命令、没有表格 -> 必须报（失锚）',
         {'rows': {}, 'stream': ['build.run']}, {'ping'}, {'build.run'},
         False, '失去锚点', check_payload=False)

    total = ncase
    if fails:
        print('[studio_proto_check-selftest] FAIL: %d/%d' % (len(fails), total))
        for f in fails:
            print('  [X] %s' % f)
        return RC_FAIL
    if not quiet:
        print('[studio_proto_check-selftest] PASS: %d 项（含 %d 项负向注入）'
              % (total, nneg))
    return RC_OK


# ---------------------------------------------------------------- 响应子键自检

def _shape_fixture(cells, cmds=None):
    """造一份只关心 data 列花括号写法的 doc。"""
    names = list(cmds or ['ping'])
    rows = {}
    for i, c in enumerate(names):
        rows[c] = {'line': 90 + i, 'args': '—', 'data': cells[i]}
    return {'rows': rows, 'stream': []}


def shape_selftest(quiet=False):
    """造坏输入喂 judge_shapes() —— 证明这条判据**会**红。

    ⚠️ 每个用例都自带一份**补丁后的 dispatch**（`patch` 参数），而不是靠真实
    后端 ——否则「改了 studio_core 的载荷形状」会让用例红，而这恰恰是判据
    要检测的东西，不是判据自身的缺陷。
    """
    fails = []
    ncase = 0
    nneg = 0
    import studio_core as sc

    real_dispatch = sc.dispatch

    def run(doc, plain, patch=None, require_anchor=True):
        orig = sc.dispatch
        if patch is not None:
            def fake(cmd, args, _p=patch, _o=orig):
                if cmd in _p:
                    return _p[cmd]
                return _o(cmd, args)
            sc.dispatch = fake
        try:
            return judge_shapes(doc, plain, sample_args={},
                                require_anchor=require_anchor)
        finally:
            sc.dispatch = orig

    def case(name, doc, plain, want, sub=None, patch=None, anchor=True):
        nonlocal ncase, nneg
        ncase += 1
        if not want:
            nneg += 1
        probs, _info = run(doc, plain, patch, anchor)
        got = not probs
        good = (got == want)
        det = 'problems=%s' % (probs[:1] if probs else [])
        if good and sub is not None:
            good = any(sub in p for p in probs)
            if not good:
                det += ' (缺少子串 %r)' % sub
        if not good:
            fails.append('%-52s want_ok=%s %s' % (name, want, det))
        elif not quiet:
            print('  ok  %-52s %s' % (name, det))

    # ---- 合规 ----
    case('合规：`items[]` + 元素键全在 -> 通过',
         _shape_fixture(['`items[]` `{name, line}`'], ['ping']), {'ping'},
         True, patch={'ping': {'items': [{'name': 'a', 'line': 1}]}})
    case('合规：`cap{...}` 值表 + 子键全在 -> 通过',
         _shape_fixture(['`cap{}`，每项 `{status, backend}`'], ['ping']),
         {'ping'}, True,
         patch={'ping': {'cap': {'x': {'status': 'ready', 'backend': 'b'}}}})
    case('合规：父键内联 `summary{a, b}` -> 通过',
         _shape_fixture(['`summary{ok, n_warns}`'], ['ping']), {'ping'},
         True, patch={'ping': {'summary': {'ok': True, 'n_warns': 0}}})

    # ---- ★ 本轮发现的两种不可见形态，各来一条 ----
    case('★ 父键内联 `summary{n_warnz}`：子键不存在 -> 必须报',
         _shape_fixture(['`summary{ok, n_warnz}`'], ['ping']), {'ping'},
         False, 'n_warnz', patch={'ping': {'summary': {'ok': True,
                                                       'n_warns': 0}}})
    case('★ 数组元素键 `{name, gatedd}`：元素里没有 -> 必须报',
         _shape_fixture(['`items[]` `{name, gatedd}`'], ['ping']), {'ping'},
         False, 'gatedd', patch={'ping': {'items': [{'name': 'a',
                                                     'gated': True}]}})

    # ---- 父键问题 ----
    case('父键不在载荷里 -> 必须报（不是静默）',
         _shape_fixture(['`missing[]` `{name}`'], ['ping']), {'ping'},
         False, '没有父键', patch={'ping': {'items': []}})
    case('父键类型不对（声明数组、实际是对象）-> 必须报',
         _shape_fixture(['`items[]` `{name}`'], ['ping']), {'ping'},
         False, '不是数组', patch={'ping': {'items': {'name': 'a'}}})
    case('悬空花括号（前面没有容器声明）-> 必须报',
         _shape_fixture(['逐项 `{name, line}`'], ['ping']), {'ping'},
         False, '没有任何', patch={'ping': {'items': [{'name': 'a'}]}})

    # ---- 可选子键：不在不算错 ----
    case('可选子键 `note?` 不在元素里 -> 不算错（不是负向）',
         _shape_fixture(['`items[]` `{name, note?}`'], ['ping']), {'ping'},
         True, patch={'ping': {'items': [{'name': 'a'}]}})
    case('可选子键 `note?` 存在也不算错',
         _shape_fixture(['`items[]` `{name, note?}`'], ['ping']), {'ping'},
         True, patch={'ping': {'items': [{'name': 'a', 'note': 'x'}]}})
    case('子键后缀 `tokens[][2]` 剥掉后按 `tokens` 判 -> 通过',
         _shape_fixture(['`rows[]` `{line, tokens[][2]}`'], ['ping']),
         {'ping'}, True,
         patch={'ping': {'rows': [{'line': 1, 'tokens': [['a', 0]]}]}})

    # ---- 失锚 ----
    case('文档里没有花括号写法 -> 沉默（不是失锚）',
         _shape_fixture(['`items[]`'], ['ping']), {'ping'}, True,
         patch={'ping': {'items': []}}, anchor=True)
    case('文档里有花括号写法、却一条都没对账 -> 必须报（失锚）',
         _shape_fixture(['`items[]` `{name}`'], ['ping']), set(), False,
         '失去锚点', patch={'ping': {'items': [{'name': 'a'}]}})
    case('文档解析出 0 行 -> 必须报（失锚）',
         {'rows': {}, 'stream': []}, {'ping'}, False, '失去锚点')

    total = ncase
    if fails:
        print('[studio_proto_check-selftest] FAIL: %d/%d' % (len(fails), total))
        for f in fails:
            print('  [X] %s' % f)
        return RC_FAIL
    if not quiet:
        print('[studio_proto_check-selftest] PASS: %d 项（含 %d 项负向注入）'
              % (total, nneg))
    return RC_OK


# ---------------------------------------------------------------- 请求侧自检

def _arg_fixture(args_cells, cmds=None):
    """造一份只关心 args 列的 doc。"""
    names = list(cmds or ['plan.solve'])
    rows = {}
    for i, c in enumerate(names):
        rows[c] = {'line': 90 + i, 'args': args_cells[i], 'data': '`x`'}
    return {'rows': rows, 'stream': []}


def arg_selftest(quiet=False):
    """造坏输入喂 judge_args() —— 证明两条臂**各自**会红。"""
    fails = []
    ncase = 0
    nneg = 0
    # 词法臂用一份「代码里真的有这些字面量」的假 literals；
    # 行为臂用假的 dispatch_fn（不碰真实后端）。
    lits = {'profile', 'session', 'codes', 'query'}

    def case(name, doc, want, sub=None, no_lits=False, **kw):
        nonlocal ncase, nneg
        ncase += 1
        if not want:
            nneg += 1
        global source_literals
        saved = source_literals
        if no_lits:
            # 模拟「读不到源码」：让真值源返回 None（**不**传一个假 literals，
            # 否则测的是「传进来的东西」，不是「真值源读不到」）。
            source_literals = lambda path=None: None
            kw.setdefault('literals', None)
        else:
            kw.setdefault('literals', lits)
        try:
            probs, _info = judge_args(doc, {'plan.solve'}, **kw)
        finally:
            source_literals = saved
        got = not probs
        good = (got == want)
        det = 'problems=%s' % (probs[:1] if probs else [])
        if good and sub is not None:
            good = any(sub in p for p in probs)
            if not good:
                det += ' (缺少子串 %r)' % sub
        if not good:
            fails.append('%-52s want_ok=%s %s' % (name, want, det))
        elif not quiet:
            print('  ok  %-52s %s' % (name, det))

    def ok_dispatch(cmd, a):
        return {}

    def empty_codes(cmd, a):
        raise RuntimeError('codes 为空 -> 不知道该解释哪个退出码')

    # 合规：声明了代码里真有的字面量，dispatch 也不报「为空」。
    case('合规（声明键都在代码里）-> 通过',
         _arg_fixture(['`profile`']), True, behavior=True, dispatch_fn=ok_dispatch)

    # 方向 A：文档把参数名写错（代码里没有这个字面量）-> 词法臂必须报。
    case('★ 文档声明了代码里没有的参数名 -> 词法臂必须报',
         _arg_fixture(['`profilz`']), False, '文档把参数名写错了',
         behavior=True, dispatch_fn=ok_dispatch)

    # 方向 B：代码读的键与文档不一致（报错点名我刚给的键）-> 行为臂必须报。
    case('★ 按文档给的值、代码却说它为空 -> 行为臂必须报',
         _arg_fixture(['`codes[]`']), False, '代码读的键名与文档不一致',
         behavior=True, dispatch_fn=empty_codes)

    # ★ 承上：同一份输入，**关掉行为臂**就没判别力了 —— 证明两条臂缺一不可。
    case('★ 同输入关掉行为臂 -> 词法臂抓不到（证明两臂互补）',
         _arg_fixture(['`codes[]`']), True, behavior=False)

    # 失锚：一条命令都没解析出 args
    case('所有命令的 args 都为空 -> 必须报（失锚）',
         _arg_fixture(['—']), False, '失去锚点',
         behavior=False)
    # 失锚：文档解析不出任何命令行
    case('文档里没有命令行 -> 必须报（失锚）',
         {'rows': {}, 'stream': []}, False, '失去锚点', behavior=False)
    # 失锚：读不到源码
    case('读不到 studio_core.py -> 必须报（失锚）',
         _arg_fixture(['`profile`']), False, '失去锚点',
         behavior=False, no_lits=True)

    total = ncase
    if fails:
        print('[studio_proto_check-selftest] FAIL: %d/%d' % (len(fails), total))
        for f in fails:
            print('  [X] %s' % f)
        return RC_FAIL
    if not quiet:
        print('[studio_proto_check-selftest] PASS: %d 项（含 %d 项负向注入）'
              % (total, nneg))
    return RC_OK


# ---------------------------------------------------------------- 文档解析自检

def _parse_selftest(quiet=False):
    """解析器自身的用例：转义竖线不能把列切断。"""
    fails = []
    doc = parse_doc(
        '| `cmd` | `args` | `data`（要点） |\n'
        '|---|---|---|\n'
        '| `debug.mask` | `symbols[]` \\| `rva,len`, `exe?` | `mask{}` |\n'
        '| `ping` | — | `a` / `b` |\n')
    row = doc['rows'].get('debug.mask')
    checks = [
        ('转义竖线不切断列：命令名解析正确', row is not None),
        ('转义竖线不切断列：args 含 rva,len', bool(row) and 'rva,len' in row['args']),
        ('转义竖线不切断列：data 是第 3 列', bool(row) and row['data'] == '`mask{}`'),
        ('行号正确', bool(row) and row['line'] == 3),
        ('声明键提取', row is not None and declared_keys(row) == ['mask']),
    ]
    for name, ok in checks:
        if not ok:
            fails.append(name)
        elif not quiet:
            print('  ok  %s' % name)
    if fails:
        print('[studio_proto_check-selftest] FAIL: %d' % len(fails))
        for f in fails:
            print('  [X] %s' % f)
        return RC_FAIL
    return RC_OK


# ---------------------------------------------------------------- 本体

def main(argv=None):
    ap = argparse.ArgumentParser(prog='studio_proto_check.py')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--no-payload', action='store_true',
                    help='跳过「声明键必须存在」那一条（只查命令集合）')
    ap.add_argument('--no-args', action='store_true',
                    help='跳过请求侧（args 列）对账')
    args = ap.parse_args(argv)

    if args.selftest:
        rc1 = _parse_selftest(args.quiet)
        rc2 = selftest(args.quiet)
        rc3 = arg_selftest(args.quiet)
        rc4 = shape_selftest(args.quiet)
        return RC_FAIL if (rc1 or rc2 or rc3 or rc4) else RC_OK

    doc_path = os.path.join(REPO, DOC_REL.replace('/', os.sep))
    if not os.path.isfile(doc_path):
        sys.stdout.write('[studio_proto_check] FAIL: 找不到 %s —— 判据失去锚点\n' % DOC_REL)
        return RC_FAIL
    text = io.open(doc_path, encoding='utf-8').read()
    doc = parse_doc(text)
    plain, stream = code_commands()

    problems, info = judge(doc, plain, stream, check_payload=not args.no_payload)
    # 请求侧（args 列）对账：除非显式 --no-args，否则一并查。
    ainfo = {'arg_judged': 0, 'arg_lex': 0, 'arg_beh': 0}
    if not args.no_args:
        import studio_core as sc
        ap, ainfo = judge_args(doc, plain, stream=stream,
                               dispatch_fn=sc.dispatch)
        problems += ap
    if problems:
        sys.stdout.write('[studio_proto_check] FAIL: %d 条\n' % len(problems))
        for p in problems:
            sys.stdout.write('  [X] %s\n' % p)
        return RC_FAIL
    sys.stdout.write('[studio_proto_check] PASS: 命令 %d 条（文档 %d 条）双向一致；'
                     '声明键对账 %s 条命令%s；响应子键对账 %s 条命令 / %d 个子键%s；'
                     '参数键对账 %d 条命令'
                     '（词法臂 %d / 行为臂 %d 命中）\n'
                     % (info['code'], info['doc'], info.get('verified', 0),
                        ('，%d 条因需要参数未对账' % len(info['skipped']))
                        if info.get('skipped') else '',
                        info.get('shape_cmds', 0), info.get('shape_keys', 0),
                        ('，%d 条因空数组/需要参数未对账'
                         % len(info['shape_skipped']))
                        if info.get('shape_skipped') else '',
                        ainfo.get('arg_judged', 0), ainfo.get('arg_lex', 0),
                        ainfo.get('arg_beh', 0)))
    return RC_OK


if __name__ == '__main__':
    sys.exit(main())
