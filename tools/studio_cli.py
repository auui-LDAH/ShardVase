#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/studio_cli.py — Studio 的 **NDJSON 会话入口**（ST0.2，2026-10-09）。

## 它是什么
`docs/STUDIO_PLAN.md` §2 的**边界 2 = 契约统一**: Studio 后端对外只有
**一套**契约 —— **每行一个 JSON 对象的事件流**（NDJSON）。

**为什么是 NDJSON 而不是"一个 JSON 文件"**: 调试天生是**流式**的
（断点命中、单步、日志、退出各是一个时刻）。一次性 JSON 表达不了
"停在断点、等下一个命令"这件事, 除非把协议改成请求/响应双工 ——
而 NDJSON over stdio 本身就是双工的, 且**任何语言都能实现客户端**
（面板、测试、shell 管道、未来的 VSCode 扩展都用它）。

## 用法

**一、会话模式（长驻, 供面板/编辑器用）** -- 默认
    python tools/studio_cli.py
  从 stdin 逐行读**请求**, 向 stdout 逐行写**响应**:

    请求:  {"id": 1, "cmd": "ping", "args": {}}
    响应:  {"id": 1, "ok": true, "data": {...}}
    响应:  {"id": 2, "ok": false, "error": {"code": "...", ...}}

  · `id` 由客户端给, **原样回传**（客户端靠它配对; 缺省为 null）
  · 一条命令失败**不终止会话** —— 出错的那行报错, 后面继续
  · 无 `id` 也可以（`{"cmd":"ping"}`）—— 便于手工 echo 一行试

**二、单发模式（供脚本/CI, 不用管道）**
    python tools/studio_cli.py --cmd ping
    python tools/studio_cli.py --cmd plan.solve --args '{"profile":"balanced"}'
  ⇒ 打印**一行** NDJSON 后退出。退出码: 0 成功 / 1 命令失败 /
    2 用法或输入错误（**与门禁的 SKIP 语义一致**, 见下）。

**三、命令清单**
    python tools/studio_cli.py --list
    python tools/studio_cli.py --selftest

## 为什么入口要与 core 分开
core 是**纯库**（可以被任意调用方 import, 无 I/O 副作用）;
本文件是**进程边界**（stdin/stdout、退出码、协议握手）。
分开之后: 门禁可以只测 core（快、无进程）, 而协议行为由本文件的
`--selftest` 通过**真的起子进程**来验证（自证能抓错）。

## 退出码约定（与门禁三态一致）
  `0` = 成功; `1` = 命令失败（有结果, 但 ok=false）;
  `2` = **用法/输入错误**（协议层用不了）—— 门禁侧应把 2 读成 SKIP,
  把 1 读成 FAIL。**不要把 2 读成通过**（`未验证 != 通过`）。

## 已知边界（诚实记录）
  · 本入口**不解析**多行 JSON 请求: 一行一个对象。跨行的 JSON 会被判
    为输入错误（`E_BAD_LINE`）—— 这是刻意的, 因为"行"就是消息边界。
  · 输出**强制 ASCII 关闭**（`ensure_ascii=False`）⇒ 中文可读;
    消费方必须按 UTF-8 解码（Windows 控制台默认 GBK 会乱码,
    故读写都用显式 UTF-8, 见 `_in_stream` / `_out_stream`）。
  · 会话模式**不含超时/心跳**: 面板断开即 EOF。心跳留给 ST5 需要时再加。
"""
import argparse
import io
import json
import os
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, 'tools'))

import studio_core as sc                                     # noqa: E402

RC_OK = 0
RC_CMD_FAIL = 1
RC_USAGE = 2


def _in_stream():
    """stdin 的**显式 UTF-8** 文本流。

    为什么不直接用 `sys.stdin`: Windows 上它的编码取决于控制台代码页
    （实测常为 GBK）, 会让含中文的请求行解析失败或乱码。
    """
    try:
        return io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8',
                                errors='replace', newline='')
    except AttributeError:                                   # pragma: no cover
        return sys.stdin


def _out_stream():
    try:
        return io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8',
                                errors='replace', newline='\n', write_through=True)
    except AttributeError:                                   # pragma: no cover
        return sys.stdout


def parse_request(line):
    """一行文本 -> 请求对象; **失败抛 StudioError**（不静默跳过）。

    校验三件事: ① 必须是 JSON 对象 ② 必须有 `cmd` ③ `args` 若存在须是对象。
    每一件的失败都**给出机读 code**, 因为面板要据此把这一行标红。
    """
    s = line.strip()
    if not s:
        raise sc.StudioError('E_BAD_LINE', '空请求行',
                             {'raw': line[:200]})
    try:
        obj = json.loads(s)
    except ValueError as e:
        raise sc.StudioError('E_BAD_LINE', '请求行不是合法 JSON: %s' % e,
                             {'raw': s[:200]})
    if not isinstance(obj, dict):
        raise sc.StudioError('E_BAD_LINE', '请求必须是 JSON 对象',
                             {'type': type(obj).__name__, 'raw': s[:200]})
    cmd = obj.get('cmd')
    if cmd is None:
        raise sc.StudioError('E_BAD_LINE', '请求缺少 cmd 字段',
                             {'keys': sorted(obj), 'raw': s[:200]})
    if not isinstance(cmd, str):
        raise sc.StudioError('E_BAD_LINE', 'cmd 必须是字符串',
                             {'type': type(cmd).__name__})
    args = obj.get('args', {})
    if not isinstance(args, dict):
        raise sc.StudioError('E_BAD_LINE', 'args 必须是对象',
                             {'type': type(args).__name__})
    return obj.get('id'), cmd, args


def respond(req_id, cmd, args):
    """执行并返回**响应对象**（永不抛异常 —— 流式会话里一条失败不终止会话）。"""
    try:
        return sc.envelope(cmd, args, req_id)
    except sc.StudioError as e:                              # pragma: no cover
        return {'id': req_id, 'ok': False, 'error': e.to_dict()}
    except Exception as e:                                   # pragma: no cover
        return {'id': req_id, 'ok': False,
                'error': {'code': 'E_INTERNAL',
                          'message': '%s: %s' % (type(e).__name__, e),
                          'detail': {'cmd': cmd}}}


def dumps(obj):
    """统一的响应序列化（**非 ASCII 转义关闭**）。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=False)


def session(inp=None, out=None, err=None):
    """会话主循环。返回**退出码**。

    规则:
      · 每一行读到一个请求 -> 写一行响应（**顺序严格对应**）
      · 请求行非法 -> 写一行 `ok=false` 响应（id 取不到就是 null）,
        **继续读下一行**
      · EOF -> 正常结束（rc=0）, 即使之前有失败的命令
      · 取消(KeyboardInterrupt) -> rc=0, 不打印 traceback
    """
    inp = inp if inp is not None else _in_stream()
    out = out if out is not None else _out_stream()
    err = err if err is not None else sys.stderr
    n_req = n_fail = 0
    try:
        for line in inp:
            if not line.strip():
                continue
            n_req += 1
            try:
                req_id, cmd, args = parse_request(line)
            except sc.StudioError as e:
                n_fail += 1
                out.write(dumps({'id': None, 'ok': False,
                                 'error': e.to_dict()}) + '\n')
                continue
            resp = respond(req_id, cmd, args)
            if not resp.get('ok'):
                n_fail += 1
            out.write(dumps(resp) + '\n')
    except KeyboardInterrupt:                                # pragma: no cover
        err.write('[studio_cli] 会话被中断\n')
    err.write('[studio_cli] 会话结束: 请求 %d / 失败 %d\n' % (n_req, n_fail))
    return RC_OK


def one_shot(cmd, args_text=None):
    """单发模式: 打印一行 NDJSON, 返回退出码。"""
    try:
        args = json.loads(args_text) if args_text else {}
    except ValueError as e:
        print(dumps({'id': None, 'ok': False,
                     'error': {'code': 'E_BAD_ARGS',
                               'message': '--args 不是合法 JSON: %s' % e,
                               'detail': {'raw': (args_text or '')[:200]}}}))
        return RC_USAGE
    if not isinstance(args, dict):
        print(dumps({'id': None, 'ok': False,
                     'error': {'code': 'E_BAD_ARGS',
                               'message': '--args 必须是 JSON 对象',
                               'detail': {'type': type(args).__name__}}}))
        return RC_USAGE
    resp = respond(None, cmd, args)
    print(dumps(resp))
    return RC_OK if resp.get('ok') else RC_CMD_FAIL


# --- 自检 ------------------------------------------------------------------
#
# 纪律: **检查器必须自证"会抓错"**。本自检**真的起子进程**跑单发模式
# （协议行为只能靠真进程验证 —— 会话循环一旦接错管道, 只测函数是测不出来的）。

def selftest(quiet=False):
    import subprocess
    fails = []
    lines = []

    def case(name, ok, detail=''):
        if not quiet:
            lines.append('  %s %-58s %s'
                         % ('ok ' if ok else '**FAIL**', name, detail))
        if not ok:
            fails.append(name)

    py = sys.executable
    cli = os.path.join(REPO, 'tools', 'studio_cli.py')

    def run(stdin_text=None, argv=()):
        kw = {'cwd': REPO, 'stdout': subprocess.PIPE,
              'stderr': subprocess.PIPE}
        if stdin_text is None:
            kw['stdin'] = subprocess.DEVNULL
        else:
            kw['stdin'] = subprocess.PIPE
        p = subprocess.Popen([py, '-X', 'utf8', cli] + list(argv), **kw)
        if stdin_text is None:
            o, e = p.communicate()
        else:
            o, e = p.communicate(stdin_text.encode('utf-8'))
        return (p.returncode,
                (o or b'').decode('utf-8', 'replace'),
                (e or b'').decode('utf-8', 'replace'))

    if not quiet:
        lines.append('=== studio_cli 自检 ===')
        lines.append('--- 1. 单发模式 ---')
    rc, o, e = run(argv=('--cmd', 'ping'))
    case('--cmd ping rc=0', rc == RC_OK, 'rc=%d' % rc)
    case('输出**恰好一行** NDJSON', len([x for x in o.splitlines()
                                         if x.strip()]) == 1)
    try:
        obj = json.loads(o.strip())
        ok_j = obj.get('ok') is True and 'data' in obj
    except ValueError:
        ok_j = False
    case('该行是合法 JSON 且 ok=true', ok_j)

    rc, o, e = run(argv=('--cmd', 'plan.solve',
                         '--args', '{"profile":"balanced"}'))
    case('--cmd plan.solve rc=0', rc == RC_OK, 'rc=%d' % rc)
    case('plan.solve 结果含 selected', 'selected' in o)

    if not quiet:
        lines.append('--- 2. 失败与用法错误**必须区分退出码** ---')
    rc, o, e = run(argv=('--cmd', 'no.such.cmd'))
    case('**负向**: 未知命令 rc=1（命令失败, 不是用法错误）',
         rc == RC_CMD_FAIL, 'rc=%d' % rc)
    case('**负向**: 未知命令仍输出合法响应包',
         json.loads(o.strip()).get('ok') is False)
    rc, o, e = run(argv=('--cmd', 'ping', '--args', '{not json'))
    case('**负向**: --args 坏 JSON rc=2（用法错误 -> 门禁应读成 SKIP）',
         rc == RC_USAGE, 'rc=%d' % rc)
    rc, o, e = run(argv=('--cmd', 'ping', '--args', '[]'))
    case('**负向**: --args 非对象 rc=2', rc == RC_USAGE, 'rc=%d' % rc)

    if not quiet:
        lines.append('--- 3. 会话模式（真管道）---')
    reqs = ('{"id":1,"cmd":"ping"}\n'
            '{"id":2,"cmd":"no.such.cmd"}\n'
            '{"id":3,"cmd":"capabilities"}\n')
    rc, o, e = run(stdin_text=reqs)
    outs = [x for x in o.splitlines() if x.strip()]
    case('会话 rc=0（**失败的命令不终止会话**）', rc == RC_OK, 'rc=%d' % rc)
    case('3 个请求 -> 3 行响应且顺序对应', len(outs) == 3, 'n=%d' % len(outs))
    ids = []
    for x in outs:
        try:
            ids.append(json.loads(x).get('id'))
        except ValueError:
            ids.append(None)
    case('id 原样回传 [1,2,3]', ids == [1, 2, 3], repr(ids))
    oks = [json.loads(x).get('ok') for x in outs]
    case('第 2 条 ok=false, 其余 ok=true', oks == [True, False, True], repr(oks))

    if not quiet:
        lines.append('--- 4. 非法请求行（**不失锚, 逐行报**）---')
    rc, o, e = run(stdin_text=('not json\n'
                               '{"cmd":123}\n'
                               '{"args":{}}\n'
                               '[]\n'
                               '{"id":9,"cmd":"ping"}\n'))
    outs = [x for x in o.splitlines() if x.strip()]
    case('5 行输入 -> 5 行响应（坏行**不被跳过**）', len(outs) == 5,
         'n=%d' % len(outs))
    codes = []
    for x in outs:
        try:
            j = json.loads(x)
            codes.append(j.get('error', {}).get('code') if not j.get('ok')
                         else 'OK')
        except ValueError:
            codes.append('BADJSON')
    case('四条坏行的 code 均为 E_BAD_LINE',
         codes[:4] == ['E_BAD_LINE'] * 4, repr(codes))
    case('最后一条好行仍正常执行', codes[4] == 'OK', repr(codes))

    if not quiet:
        lines.append('--- 5. 空行与 EOF ---')
    rc, o, e = run(stdin_text='\n\n\n')
    case('**负向**: 纯空行 -> 0 行响应（空行不是请求）',
         len([x for x in o.splitlines() if x.strip()]) == 0)
    rc, o, e = run(stdin_text='')
    case('EOF 立即到达 -> rc=0', rc == RC_OK, 'rc=%d' % rc)

    if not quiet:
        lines.append('--- 6. 命令清单与 core 一致（**不失锚**）---')
    rc, o, e = run(argv=('--list',))
    case('--list rc=0', rc == RC_OK)
    # 注意: **必须按 JSON 解析, 不能按空格切**。`json.dumps` 默认分隔符是
    # `', '` / `': '`, 用 `split()[0]` 会切出 `{"cmd":` 这种碎片 —— 本自检
    # 首跑正是这么失败的（判据报"清单不一致", 而 CLI 输出其实是对的）。
    listed = set()
    nodoc = []
    for x in o.splitlines():
        if not x.strip():
            continue
        j = json.loads(x)
        listed.add(j['cmd'])
        # 面板靠 `--list` 的 doc 显示命令说明; 空 doc 会让 UI 出现一行空白,
        # 且**没有任何检查会红** ⇒ 这里直接断言非空（失锚不静默）。
        if not (j.get('doc') or '').strip():
            nodoc.append(j['cmd'])
    case('--list 的每条命令都有说明（不为空）', not nodoc, repr(nodoc))
    case('--list 覆盖 core.COMMANDS 全部命令',
         listed == set(sc.COMMANDS), repr(sorted(listed ^ set(sc.COMMANDS))))

    if not quiet:
        lines.append('--- 7. 中文不被 ASCII 转义（面板可读）---')
    rc, o, e = run(argv=('--cmd', 'gate.items'))
    # 必须**两条都成立**: ① 输出里真的有中文（原样可读）② 没有 \uXXXX 转义。
    # 只判其一都可能假绿 —— 例如 `A and B or C` 这种写法的优先级会让它永远通过。
    case('中文原样可读（含真实中文门禁名）', '模块契约' in o)
    case('**未**被转义成 \\uXXXX', '\\u' not in o)

    if not quiet:
        lines.append('')
        lines.append('=' * 68)
    if fails:
        print('\n'.join(lines))
        print('[studio_cli-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    if not quiet:
        print('\n'.join(lines))
    print('[studio_cli-selftest] PASS: 单发/会话/坏行/退出码均可自证')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog='studio_cli.py')
    ap.add_argument('--cmd', help='单发模式: 执行一条命令后退出')
    ap.add_argument('--args', help='单发模式: 命令参数（JSON 对象文本）')
    ap.add_argument('--list', action='store_true', help='列命令（NDJSON）')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--version', action='store_true')
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest(args.quiet)
    if args.version:
        print(dumps({'protocol_version': sc.PROTOCOL_VERSION,
                     'studio_version': sc.STUDIO_VERSION}))
        return RC_OK
    if args.list:
        for k in sorted(sc.COMMANDS):
            d = (sc.COMMANDS[k].__doc__ or '').strip().splitlines()
            print(dumps({'cmd': k, 'doc': d[0] if d else ''}))
        return RC_OK
    if args.cmd:
        return one_shot(args.cmd, args.args)
    return session()


if __name__ == '__main__':
    sys.exit(main())
