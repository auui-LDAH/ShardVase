#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""gate_results.py — 门禁结果的**历史 / 差异 / 独立对账**（ST2.4, 2026-10-10）。

## 为什么需要它
`tools/release_check.ps1` 自 ST2.1 起同时产出两个出口:
  * 文本 (PowerShell transcript, `build/logs/release_check_<ts>.log`) —— 给人读的,
    也是 `tools/docclaim_check.py` T7 不变量的锚;
  * NDJSON (`build/logs/release_check_<ts>.ndjson`) —— 给面板与历史趋势读的。
门禁**自己**在总结处做了一次"双面对照", 但那比的是 JSON 计数与文本侧**计数器**
（同一来源）—— 它能抓"某个分支改了文本却忘了记录", **抓不到**"某天有人给
`Write-Host` 加了新行却既没记 JSON 也没加计数器"。

本工具补的正是那一环: 它去读 transcript 里的**实际行**, 与 NDJSON 的**实际行**
逐项对账。这就是 `docs/STUDIO_PLAN.md` D7 说的"**独立**对账"。

## 三个子命令
  --verify          取最近一轮**已完成**的门禁, 逐项对账并校验 T7 不变量
  --diff A B        两次运行的差异（新失败 / 新通过 / 状态变化）
  --trend           历次运行的通过数时间线
  --list            列出发现的运行（log/ndjson 配对情况）

## 诚实边界（必须与代码一致）
  1. 只认 `build/logs/` 下的 `release_check_*`；`ci_linux_*` 不在本工具范围。
  2. 对账要求**同一轮**同时有 `.log` 与 `.ndjson`。ST2.1 之前的历史轮次只有
     `.log` —— 那不是缺陷, 本工具如实报"无配对"而不是编一个。
  3. `--verify` 只看**已完成**的轮次（有 `[release_check] PASS:` 或 `FAIL:` 行）。
     未完成的轮次一律判 SKIP（rc=2），**不判失败**——"没跑完"与"跑错了"是两回事。
  4. 不做时间序列的**趋势推断**（不拟合、不预测），只如实列出。
"""
import argparse
import glob
import io
import json
import os
import re
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
LOG_DIR = os.path.join(REPO, 'build', 'logs')

# 文本证据行的**行首**锚。
# ⚠️ 这四条刻意与 `tools/docclaim_check.py` T7 的四条正则**同形** —— 本工具数出来的
# 行数必须**就是** T7 数出来的那个数, 否则"对账"会在两套口径之间打架:
#     nok   = ^\[ok\]                 nx    = ^\[X\]
#     nskip = ^\[skip\] .*—— 前置不满足   ninfo = ^\[info\] .*未运行
# 特别地 `[info]` **不要求**"名字与未运行之间有空格"(门禁里三条 gated 未运行行就
# 写成了 `检查器变异测试未运行 ...`), 我第一版写成 `\s+未运行` 会把它们**全漏掉**。
RE_OK = re.compile(r'^\[ok\]\s+(?P<n>.*?)\s*$')
RE_X = re.compile(r'^\[X\]\s+(?P<n>.*?)\s*$')
RE_SKIP = re.compile(r'^\[skip\]\s+(?P<n>.*?)—— 前置不满足')
RE_INFO = re.compile(r'^\[info\]\s+(?P<n>.*?)未运行')
RE_DONE = re.compile(r'\[release_check\] (PASS|FAIL):')
RE_PASSN = re.compile(r'\[release_check\] PASS: (\d+) 项检查全通过')

# 状态到文本记号的映射（与 release_check.ps1 的 Add-GateResult 一一对应）
STATUS_OF = {'[ok]': 'pass', '[X]': 'fail', '[skip]': 'skip', '[info]': 'not-run'}


class GateError(Exception):
    def __init__(self, code, message, detail=None):
        Exception.__init__(self, message)
        self.code = code
        self.message = message
        self.detail = detail

    def to_dict(self):
        d = {'code': self.code, 'message': self.message}
        if self.detail is not None:
            d['detail'] = self.detail
        return d


# ── 解析 ────────────────────────────────────────────────────────────────────
def parse_evidence(text):
    """按**行首**锚抽出证据行, 返回 [(marker, name), ...]（保持出现顺序）。

    ⚠️ 顺序与名字都要留 —— 只比计数会让"两条互换名字"静默通过。
    """
    out = []
    for line in text.split('\n'):
        line = line.rstrip('\r')
        for rx, mk in ((RE_OK, '[ok]'), (RE_X, '[X]'),
                       (RE_SKIP, '[skip]'), (RE_INFO, '[info]')):
            m = rx.match(line)
            if m:
                nm = m.group('n').strip()
                # `[X]  NAME: 消息` 形态 —— 切掉冒号及其后的诊断
                if mk == '[X]' and ': ' in nm:
                    nm = nm.split(': ', 1)[0].strip()
                out.append((mk, nm))
                break
    return out


def read_text(path):
    """读文本出口（PowerShell transcript）。

    ⚠️ transcript **是带 BOM 的** —— 实测 `build/logs/release_check_*.log` 与
    `ci_linux_*.log` 前 3 字节都是 `ef bb bf`（`Start-Transcript` 就是这么写的）。
    所以这里**接受** BOM 并剥掉它。（我第一版把它当硬错误，于是本工具对**所有**
    真实日志都直接抛异常 —— "把正常形态当成损坏"是同一类探针口径错的反面。）
    BOM 只在 NDJSON 出口上是硬错误：那里每行都要能独立 `json.loads`。
    """
    raw = io.open(path, 'rb').read()
    if raw[:3] == b'\xef\xbb\xbf':
        raw = raw[3:]
    return raw.decode('utf-8', 'replace')


def load_ndjson(path):
    """读 NDJSON。**BOM 是硬错误** —— 那会让面板的逐行解析在第一行就崩。

    缺失/空文件都抛, **不返回空列表**: 面板拿到空列表会显示"0 项", 与
    "真的没有结果"无法区分（同 `studio_core.read_json` 的纪律）。
    """
    if not os.path.exists(path):
        raise GateError('E_NOT_FOUND', 'NDJSON 不存在', {'path': path})
    raw = io.open(path, 'rb').read()
    if raw[:3] == b'\xef\xbb\xbf':
        raise GateError('E_BOM', 'NDJSON 带 UTF-8 BOM（每行都必须能独立 json.loads）',
                        {'path': path})
    if not raw.strip():
        raise GateError('E_EMPTY', 'NDJSON 是空文件 —— 出口静默失败了',
                        {'path': path})
    rows, bad = [], []
    for i, line in enumerate(raw.decode('utf-8').split('\n'), 1):
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except Exception as e:
            bad.append({'line': i, 'error': str(e)})
            continue
        if not isinstance(r, dict) or 'name' not in r or 'status' not in r:
            bad.append({'line': i, 'error': '缺 name/status 字段'})
            continue
        rows.append(r)
    if bad:
        raise GateError('E_PARSE', 'NDJSON 有 %d 行解析失败' % len(bad),
                        {'path': path, 'bad': bad[:5]})
    return rows


def load_run(stem, log_dir=None):
    """读一轮（stem = 不含扩展名的完整路径前缀），返回 dict。"""
    d = log_dir or LOG_DIR
    log = stem + '.log'
    nd = stem + '.ndjson'
    r = {'stem': stem,
         'name': os.path.basename(stem),
         'log': log if os.path.exists(log) else None,
         'ndjson': nd if os.path.exists(nd) else None,
         'load_errors': []}
    if r['log']:
        try:
            t = read_text(log)
            r['evidence'] = parse_evidence(t)
            r['done'] = bool(RE_DONE.search(t))
            m = RE_PASSN.search(t)
            r['pass_n'] = int(m.group(1)) if m else None
            r['counts_text'] = {}
            for mk, _n in r['evidence']:
                s = STATUS_OF[mk]
                r['counts_text'][s] = r['counts_text'].get(s, 0) + 1
        except Exception as e:
            # 单个坏文件不得让整个列表崩掉 —— 如实记下并继续。
            r['load_errors'].append('log: %s' % e)
            r['done'] = False
    if r['ndjson']:
        try:
            r['rows'] = load_ndjson(nd)
            r['counts_json'] = {}
            for row in r['rows']:
                s = row.get('status')
                r['counts_json'][s] = r['counts_json'].get(s, 0) + 1
        except Exception as e:
            r['load_errors'].append('ndjson: %s' % e)
    return r


def discover(log_dir=None):
    """列出运行（按时间倒序）。只有 .log 的老轮次也列出 —— 如实标注无配对。"""
    d = log_dir or LOG_DIR
    stems = set()
    for p in glob.glob(os.path.join(d, 'release_check_*.log')):
        stems.add(p[:-len('.log')])
    for p in glob.glob(os.path.join(d, 'release_check_*.ndjson')):
        stems.add(p[:-len('.ndjson')])
    return sorted(stems, reverse=True)


# ── 对账（本工具的核心）──────────────────────────────────────────────────────
def verify_run(run):
    """对一轮做逐项对账。返回 (ok, problems, info)。**不做静默回退**。

    判据:
      ① 文本与 NDJSON 的证据行**条数相同**;
      ② 逐项**顺序与名字相同**, 且记号与 status 一一对应
         （pass<->[ok] / fail|error<->[X] / skip<->[skip] / not-run<->[info]）;
      ③ T7 不变量: 文本证据行数 == NDJSON 行数;
      ④ `PASS: N 项检查全通过` 的 N == JSON 的 pass 数
         —— ⚠️ **只在 PASS 轮可判**: 失败轮写的是 `FAIL: N/M 未通过`, 那一句里
         **没有** `pass` 的真值。而且失败行的分母口径**历史上不稳定**（实测
         `release_check_20260930_221104` 写 `1/31` 而 counts_text 的 pass+fail = 30）
         ⇒ **不反推 `pass_n`**（反推等于编造一个被测对象从未承诺过的数字）。
         失败轮照旧跑判据①②③ —— 那三条是**逐项**的, 与轮次成败无关,
         故"本轮门禁红"与"两个出口互相打架"是两件不同的事。
    """
    problems = []
    info = {'run': run['name']}
    for e in (run.get('load_errors') or []):
        problems.append('读取失败: %s' % e)
    if not run.get('log'):
        problems.append('无 .log（文本出口缺失）')
    if not run.get('ndjson'):
        problems.append('无 .ndjson（ST2.1 之前的历史轮次没有这个出口）')
    if run.get('load_errors'):
        return False, problems, info
    if problems:
        return False, problems, info
    if not run.get('done'):
        return False, ['本轮**未完成**（没有 [release_check] PASS/FAIL 行）'], info

    ev = run['evidence']
    rows = run['rows']
    info['text_lines'] = len(ev)
    info['json_lines'] = len(rows)
    info['counts_text'] = run['counts_text']
    info['counts_json'] = run['counts_json']

    if len(ev) != len(rows):
        problems.append('行数不等: 文本 %d vs NDJSON %d' % (len(ev), len(rows)))

    n = min(len(ev), len(rows))
    for i in range(n):
        mk, tname = ev[i]
        row = rows[i]
        jname = row.get('name')
        want = {'pass': '[ok]', 'fail': '[X]', 'error': '[X]',
                'skip': '[skip]', 'not-run': '[info]'}.get(row.get('status'))
        if tname != jname:
            problems.append('第 %d 项名字不同: 文本 %r vs JSON %r' % (i + 1, tname, jname))
        if want != mk:
            problems.append('第 %d 项(%s)记号不同: 文本 %s vs JSON status=%s(应 %s)'
                            % (i + 1, jname, mk, row.get('status'), want))

    if run.get('pass_n') is not None:
        jp = run['counts_json'].get('pass', 0)
        if run['pass_n'] != jp:
            problems.append('PASS 文案 N=%d 但 JSON pass=%d' % (run['pass_n'], jp))
        info['pass_n'] = run['pass_n']
    else:
        # 失败轮: `pass_n` 无定义（见 docstring 判据④）。**如实记下"无法对账"**,
        # 而不是静默跳过 —— 静默跳过会让这条判据在红轮上"看起来通过了"。
        info['pass_n'] = None
        info['pass_n_why'] = '非 PASS 轮: 汇总行不含 pass 真值, 不反推'
    return (not problems), problems, info


def pick_latest(log_dir=None, only_complete=True):
    for stem in discover(log_dir):
        if not os.path.exists(stem + '.ndjson'):
            continue
        r = load_run(stem, log_dir)
        if only_complete and not r.get('done'):
            continue
        return r
    return None


# ── 差异 ────────────────────────────────────────────────────────────────────
def diff_runs(a, b):
    """两次运行的状态差异。返回 (列表, 摘要)。按名字对齐（不假设行序）。"""
    da = {r['name']: r.get('status') for r in (a.get('rows') or [])}
    db = {r['name']: r.get('status') for r in (b.get('rows') or [])}
    for _mk, nm in (a.get('evidence') or []):
        da.setdefault(nm, None)
    for _mk, nm in (b.get('evidence') or []):
        db.setdefault(nm, None)
    changes = []
    for nm in sorted(set(da) | set(db)):
        sa, sb = da.get(nm), db.get(nm)
        if sa != sb:
            changes.append({'name': nm, 'from': sa, 'to': sb})
    summ = {}
    for c in changes:
        k = '%s->%s' % (c['from'], c['to'])
        summ[k] = summ.get(k, 0) + 1
    return changes, summ


def trend(stems, log_dir=None):
    """历次运行时间线。

    ⚠️ `dict.get(k)` 对**缺失键**返回 None，而"该项本轮未出现"与"这一轮不存在"
    是两回事 —— 面板上 `None` 会被渲染成空白/未知。所以缺键一律补 0：
    一次全 `not-run` 的运行 `pass` 是 **0**，不是"不知道"。
    """
    out = []
    for stem in stems:
        r = load_run(stem, log_dir)
        if r.get('counts_json'):
            c = r['counts_json']
            pp, fl = c.get('pass', 0), c.get('fail', 0) + c.get('error', 0)
            sk, nr = c.get('skip', 0), c.get('not-run', 0)
        else:
            c = r.get('counts_text', {})
            # 文本侧的 'fail' 键把 [X] 的两种来源合并了（fail 与 error 同记 [X]）
            pp, fl = c.get('pass', 0), c.get('fail', 0)
            sk, nr = c.get('skip', 0), c.get('not-run', 0)
        out.append({'run': r['name'].replace('release_check_', ''),
                    'done': bool(r.get('done', False)),
                    'pass': pp, 'fail': fl, 'skip': sk, 'not-run': nr,
                    'has_ndjson': bool(r.get('ndjson'))})
    return out


# ── CLI ─────────────────────────────────────────────────────────────────────
def _emit(obj, as_json):
    if as_json:
        sys.stdout.write(json.dumps(obj, ensure_ascii=False, indent=1, sort_keys=True) + '\n')
    return obj


def cmd_list(log_dir, as_json):
    rows = []
    for stem in discover(log_dir):
        r = load_run(stem, log_dir)
        rows.append({'run': r['name'], 'log': bool(r.get('log')),
                     'ndjson': bool(r.get('ndjson')), 'done': r.get('done', False)})
    if as_json:
        _emit(rows, True)
    else:
        print('%-34s %-5s %-7s %s' % ('run', 'log', 'ndjson', 'done'))
        for x in rows:
            print('%-34s %-5s %-7s %s' % (x['run'], x['log'], x['ndjson'], x['done']))
    return 0


def cmd_verify(log_dir, as_json, only=None):
    if only:
        r = load_run(os.path.join(log_dir, only[:-4]) if only.endswith('.log')
                     else (only[:-7] if only.endswith('.ndjson') else only), log_dir)
    else:
        r = pick_latest(log_dir)
    if r is None:
        msg = '在 %s 下找不到**同时**有 .log 与 .ndjson 的轮次 —— 无法对账' % log_dir
        if as_json:
            _emit({'ok': False, 'error': {'code': 'E_NOT_FOUND', 'message': msg}}, True)
        else:
            print('[gate_results] SKIP: %s' % msg)
        return 2
    ok, problems, info = verify_run(r)
    if as_json:
        _emit({'ok': ok, 'info': info, 'problems': problems}, True)
    else:
        print('轮次: %s' % info.get('run'))
        print('  文本证据行 %s 条 / NDJSON %s 行' % (info.get('text_lines'), info.get('json_lines')))
        print('  文本计数: %s' % info.get('counts_text'))
        print('  JSON 计数: %s' % info.get('counts_json'))
        for p in problems:
            print('  [X] %s' % p)
        print('[gate_results] %s' % ('PASS: 文本与 NDJSON 逐项一致' if ok else
                                     'FAIL: %d 处不一致' % len(problems)))
    return 0 if ok else 1


def cmd_diff(a, b, log_dir, as_json):
    def _load(spec):
        p = spec
        if not os.path.isabs(p):
            p = os.path.join(log_dir, spec)
        if p.endswith('.log') or p.endswith('.ndjson'):
            p = p[:p.rindex('.')]
        return load_run(p, log_dir)
    ra, rb = _load(a), _load(b)
    changes, summ = diff_runs(ra, rb)
    if as_json:
        _emit({'a': ra['name'], 'b': rb['name'], 'changes': changes, 'summary': summ}, True)
    else:
        print('%s  ->  %s' % (ra['name'], rb['name']))
        if not changes:
            print('  无差异')
        for c in changes:
            print('  %-40s %s -> %s' % (c['name'], c['from'], c['to']))
        print('  摘要: %s' % (summ or '{}'))
    return 0


def cmd_trend(log_dir, as_json):
    rows = trend(discover(log_dir), log_dir)
    rows.reverse()
    if as_json:
        _emit(rows, True)
    else:
        print('%-34s %5s %5s %5s %8s  %s' % ('run', 'pass', 'fail', 'skip', 'not-run', 'ndjson'))
        for x in rows:
            print('%-34s %5s %5s %5s %8s  %s' % (
                x['run'], x['pass'], x['fail'], x['skip'], x['not-run'], x['has_ndjson']))
    return 0


# ── 自检 ────────────────────────────────────────────────────────────────────
def selftest(quiet=False):
    """负向为主: 每条"必须报错"的用例都真的制造出那个错误。"""
    import shutil
    import tempfile
    cases = []

    def case(name, ok, det=''):
        cases.append((name, bool(ok), det))

    tmp = tempfile.mkdtemp(prefix='gate_results_st_')
    try:
        def mk(name, text):
            p = os.path.join(tmp, name)
            io.open(p, 'w', encoding='utf-8', newline='\n').write(text)
            return p

        def mk_bom(name, text):
            p = os.path.join(tmp, name)
            io.open(p, 'wb').write(b'\xef\xbb\xbf' + text.encode('utf-8'))
            return p

        LOG_OK = ('Windows PowerShell transcript start\n'
                  '[ok]  A\n[ok]  B\n[info] C 未运行 (加开关启用) — 未验证 != 通过\n'
                  '[json] 3 项 -> x.ndjson\n'
                  '[release_check] PASS: 2 项检查全通过\n'
                  'Windows PowerShell transcript end\n')
        # ⚠️ transcript 里以 [ok]/[X] **开头**的行才是证据行; 缩进的不算
        INDENT = ('      | [ok]  这是诊断缩进行, 不得被算成证据\n')

        def ndjson(rows):
            return ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows)

        ROWS_OK = [{'seq': 1, 'name': 'A', 'status': 'pass', 'seconds': 0.1, 'why': None},
                   {'seq': 2, 'name': 'B', 'status': 'pass', 'seconds': 0.2, 'why': None},
                   {'seq': 3, 'name': 'C', 'status': 'not-run', 'seconds': 0, 'why': '开关'}]

        def run_pair(logtext, rows, tag):
            stem = os.path.join(tmp, 'release_check_%s' % tag)
            io.open(stem + '.log', 'w', encoding='utf-8', newline='\n').write(logtext)
            io.open(stem + '.ndjson', 'w', encoding='utf-8', newline='\n').write(ndjson(rows))
            return load_run(stem, tmp)

        # 1 干净的一对 -> 对账通过
        r = run_pair(LOG_OK, ROWS_OK, 'clean')
        ok, probs, info = verify_run(r)
        case('1 干净的一对 -> 逐项一致', ok and not probs, str(probs))

        # 2 缩进的诊断行不得被算成证据行
        r2 = run_pair(LOG_OK + INDENT, ROWS_OK, 'indent')
        ok2, probs2, _i = verify_run(r2)
        case('2 缩进的 [ok] 诊断行不算证据行（否则行数会多 1）',
             ok2 and not probs2, 'probs=%s' % probs2)

        # 3 NDJSON 带 BOM -> 必须抛 E_BOM
        p = mk_bom('release_check_bom.ndjson', ndjson(ROWS_OK))
        mk('release_check_bom.log', LOG_OK)
        try:
            load_ndjson(p)
            case('3 NDJSON 带 BOM -> 必须报 E_BOM', False, '没有报错')
        except GateError as e:
            case('3 NDJSON 带 BOM -> 必须报 E_BOM', e.code == 'E_BOM', e.code)

        # 4 NDJSON 空文件 -> 必须报 E_EMPTY（不得静默当 0 项）
        p = mk('release_check_empty.ndjson', '')
        try:
            load_ndjson(p)
            case('4 NDJSON 空文件 -> 必须报 E_EMPTY（不得静默成 0 项）', False, '没有报错')
        except GateError as e:
            case('4 NDJSON 空文件 -> 必须报 E_EMPTY（不得静默成 0 项）',
                 e.code == 'E_EMPTY', e.code)

        # 5 少一行 -> 必须报
        r5 = run_pair(LOG_OK, ROWS_OK[:2], 'short')
        ok5, probs5, _i = verify_run(r5)
        case('5 NDJSON 少一行 -> 必须报行数不等', (not ok5) and any('行数不等' in x for x in probs5),
             str(probs5))

        # 6 名字被换 -> 必须报（只比计数会漏）
        rows6 = [dict(x) for x in ROWS_OK]
        rows6[1]['name'] = 'B_renamed'
        r6 = run_pair(LOG_OK, rows6, 'rename')
        ok6, probs6, _i = verify_run(r6)
        case('6 名字被换 -> 必须报（只比计数会静默通过）',
             (not ok6) and any('名字不同' in x for x in probs6), str(probs6))

        # 7 状态被换（文本 pass / JSON not-run）-> 必须报
        rows7 = [dict(x) for x in ROWS_OK]
        rows7[1]['status'] = 'not-run'
        r7 = run_pair(LOG_OK, rows7, 'status')
        ok7, probs7, _i = verify_run(r7)
        case('7 状态被换 -> 必须报记号不同',
             (not ok7) and any('记号不同' in x for x in probs7), str(probs7))

        # 8 PASS 文案的数字与 JSON pass 不符 -> 必须报
        r8 = run_pair(LOG_OK.replace('PASS: 2 项', 'PASS: 3 项'), ROWS_OK, 'passn')
        ok8, probs8, _i = verify_run(r8)
        case('8 PASS 文案 N 与 JSON pass 不符 -> 必须报',
             (not ok8) and any('PASS 文案' in x for x in probs8), str(probs8))

        # 9 未完成的轮次 -> 判"未完成", 不判"不一致"（两回事）
        r9 = run_pair('Windows PowerShell transcript start\n[ok]  A\n', ROWS_OK, 'unfinished')
        ok9, probs9, _i = verify_run(r9)
        case('9 未完成的轮次 -> 必须报"未完成"（不是"不一致"）',
             (not ok9) and any('未完成' in x for x in probs9), str(probs9))

        # 10 只有 .log（ST2.1 之前的历史轮次）-> 如实报无配对, 不得当通过
        stem = os.path.join(tmp, 'release_check_oldonly')
        io.open(stem + '.log', 'w', encoding='utf-8', newline='\n').write(LOG_OK)
        r10 = load_run(stem, tmp)
        ok10, probs10, _i = verify_run(r10)
        case('10 只有 .log -> 必须报无 .ndjson（不得当通过）',
             (not ok10) and any('.ndjson' in x for x in probs10), str(probs10))

        # 11 目录里没有任何配对 -> pick_latest 必须返回 None（调用方据此 SKIP）
        empty = os.path.join(tmp, 'emptydir')
        os.makedirs(empty, exist_ok=True)
        case('11 无任何配对 -> pick_latest 返回 None（调用方据此 SKIP rc=2）',
             pick_latest(empty) is None)

        # 12 diff: 两次运行的差异要能列出（含"新失败"）
        rowsA = [{'seq': 1, 'name': 'A', 'status': 'pass'},
                 {'seq': 2, 'name': 'B', 'status': 'pass'},
                 {'seq': 3, 'name': 'C', 'status': 'pass'}]
        rowsB = [{'seq': 1, 'name': 'A', 'status': 'pass'},
                 {'seq': 2, 'name': 'B', 'status': 'fail'},
                 {'seq': 3, 'name': 'C', 'status': 'pass'}]
        ra = run_pair(LOG_OK, rowsA, 'dA')
        rb = run_pair(LOG_OK, rowsB, 'dB')
        ch, sm = diff_runs(ra, rb)
        case('12 diff 能列出"新失败"', (len(ch) == 1 and ch[0]['name'] == 'B'
                                    and ch[0]['to'] == 'fail'), str(ch))

        # 13 trend: 每轮一条, 数值来自 JSON（无 JSON 时退回文本）
        tr = trend([ra['stem'], rb['stem']], tmp)
        case('13 trend 每轮一条', len(tr) == 2 and all('pass' in x for x in tr), str(tr))

        # 13b ⭐ trend 的零值必须补 0 而不是 None —— 一次全 not-run 的运行
        #     pass 是 **0**，不是"不知道"。面板会把 None 渲染成空白。
        rowsZ = [{'seq': 1, 'name': 'A', 'status': 'not-run'},
                 {'seq': 2, 'name': 'B', 'status': 'not-run'}]
        rz = run_pair(LOG_OK.replace('[ok]  A\n[ok]  B\n', ''), rowsZ, 'zerofill')
        tz = trend([rz['stem']], tmp)[0]
        case('13b trend 缺失键补 0 而不是 None（全 not-run 的 pass 是 0）',
             tz['pass'] == 0 and tz['fail'] == 0 and tz['skip'] == 0
             and tz['not-run'] == 2, str(tz))

        # 14 解析器: 汇总行不得被当成逐项证据
        sumline = ('[skip] 3 项因前置不满足未验证（未验证 != 通过）\n'
                   '[skip] X —— 前置不满足，本项未验证（未验证 != 通过）\n')
        ev14 = parse_evidence(sumline)
        case('14 [skip] 汇总行不算证据, 只数逐项行',
             len(ev14) == 1 and ev14[0][1] == 'X', str(ev14))

        # 15 [X] 带诊断消息 -> 名字要切干净
        ev15 = parse_evidence('[X]  某项: 检查写法错误（末值非布尔: True）\n')
        case('15 [X] 带诊断消息 -> 名字切在第一个 ": " 之前',
             len(ev15) == 1 and ev15[0][1] == '某项', str(ev15))

        # 16 ⭐ 失败轮: 判据④**无法执行**, 必须如实记为"不反推"而不是静默跳过。
        #    这一条是 §2.64 的直接来源: `pass_n` 只在 PASS 轮有定义, 拿它做
        #    "两个出口一致"的断言 ⇒ 每一轮红门禁之后那个断言都必假。
        LOG_FAIL = ('[ok]  A\n[ok]  B\n[X]  C\n'
                    '[release_check] FAIL: 1/3 未通过\n')
        ROWS_FAIL = [{'seq': 1, 'name': 'A', 'status': 'pass'},
                     {'seq': 2, 'name': 'B', 'status': 'pass'},
                     {'seq': 3, 'name': 'C', 'status': 'fail'}]
        r16 = run_pair(LOG_FAIL, ROWS_FAIL, 'failround')
        ok16, probs16, info16 = verify_run(r16)
        case('16 失败轮: 逐项仍对得上 且 pass_n 记为不可对账（不反推）',
             ok16 and not probs16 and info16.get('pass_n') is None
             and bool(info16.get('pass_n_why')),
             'ok=%s probs=%s info=%s' % (ok16, probs16, info16))

        # 17 ⭐ 负向: 失败轮里两出口**真的打架**时, 判据①②③仍必须报
        #    （证明"红轮判据④不执行"没有顺带让整条对账失效）。
        rows17 = [dict(x) for x in ROWS_FAIL]
        rows17[1]['status'] = 'fail'
        r17 = run_pair(LOG_FAIL, rows17, 'failmix')
        ok17, probs17, _i = verify_run(r17)
        case('17 **负向**: 失败轮里记号打架仍必须报（判据④不执行 ≠ 整条失效）',
             (not ok17) and any('记号不同' in x for x in probs17), str(probs17))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    npass = sum(1 for _n, ok, _d in cases if ok)
    if not quiet:
        for name, ok, det in cases:
            print('  %s %s%s' % ('ok  ' if ok else '[XX]', name,
                                 ('' if ok else '  <- ' + det)))
    nneg = sum(1 for n, _o, _d in cases if n.split(' ', 1)[0] in
               ('3', '4', '5', '6', '7', '8', '9', '10', '11', '17'))
    print('[gate_results-selftest] %s: %d 条（含 %d 条负向）'
          % ('PASS' if npass == len(cases) else 'FAIL', len(cases), nneg))
    return 0 if npass == len(cases) else 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog='gate_results.py', description=__doc__.split('\n')[0])
    ap.add_argument('--dir', default=LOG_DIR, help='日志目录（默认 build/logs）')
    ap.add_argument('--list', action='store_true', help='列出发现的运行')
    ap.add_argument('--verify', metavar='RUN', nargs='?', const='',
                    help='逐项对账（缺省取最近一轮完整的）')
    ap.add_argument('--diff', nargs=2, metavar=('A', 'B'), help='两次运行的差异')
    ap.add_argument('--trend', action='store_true', help='历次运行时间线')
    ap.add_argument('--json', action='store_true', help='结构化输出')
    ap.add_argument('--selftest', action='store_true', help='自检（含负向）')
    ap.add_argument('--quiet', action='store_true', help='静默（只打结论）')
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest(args.quiet)
    if args.diff:
        return cmd_diff(args.diff[0], args.diff[1], args.dir, args.json)
    if args.list:
        return cmd_list(args.dir, args.json)
    if args.trend:
        return cmd_trend(args.dir, args.json)
    if args.verify is not None:
        return cmd_verify(args.dir, args.json, args.verify or None)
    ap.print_help()
    return 2


if __name__ == '__main__':
    sys.exit(main())
