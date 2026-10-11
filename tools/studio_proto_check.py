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
}


def declared_keys(row):
    """从 data 列里提取无歧义的 `名称[]` / `名称{}` 键。"""
    return sorted({m.group(1) for m in _DECL_KEY.finditer(row.get('data', ''))})


def judge(doc, plain, stream, check_payload=True, sample_args=None):
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
    args = ap.parse_args(argv)

    if args.selftest:
        rc1 = _parse_selftest(args.quiet)
        rc2 = selftest(args.quiet)
        return RC_FAIL if (rc1 or rc2) else RC_OK

    doc_path = os.path.join(REPO, DOC_REL.replace('/', os.sep))
    if not os.path.isfile(doc_path):
        sys.stdout.write('[studio_proto_check] FAIL: 找不到 %s —— 判据失去锚点\n' % DOC_REL)
        return RC_FAIL
    text = io.open(doc_path, encoding='utf-8').read()
    doc = parse_doc(text)
    plain, stream = code_commands()

    problems, info = judge(doc, plain, stream, check_payload=not args.no_payload)
    if problems:
        sys.stdout.write('[studio_proto_check] FAIL: %d 条\n' % len(problems))
        for p in problems:
            sys.stdout.write('  [X] %s\n' % p)
        return RC_FAIL
    sys.stdout.write('[studio_proto_check] PASS: 命令 %d 条（文档 %d 条）双向一致；'
                     '声明键对账 %s 条命令%s\n'
                     % (info['code'], info['doc'], info.get('verified', 0),
                        ('，%d 条因需要参数未对账' % len(info['skipped']))
                        if info.get('skipped') else ''))
    return RC_OK


if __name__ == '__main__':
    sys.exit(main())
