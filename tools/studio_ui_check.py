# -*- coding: utf-8 -*-
"""在**真实浏览器**里点一遍 Studio 外壳，断言它真的渲染出了东西。

## 为什么需要这个工具（它抓到的第一件事）

`tools/studio_server.py --selftest` 的「真实资产自洽」判据读的是**文本**：
`app.js` 里有没有 `vm.continue` 字样、`index.html` 里有没有 `id="vmlisting"`。

`studio/static/app.js` 的 `loadCaps()` 原先写的是

    d.items.forEach(...)

而后端 `capabilities` 命令发的是 **`capabilities{}`（以能力名为键的对象）**，
没有 `items` 这个键。于是「关于」页**从 ST5 起就一直是空的**：

* 静态判据看不见 —— 它只问「页面里有没有提到这些命令」；
* 服务端 e2e 看不见 —— 它验的是「资产被正确读出、命令全通」；
* 唯一的表现是一个 **unhandled rejection**（`TypeError: Cannot read properties
  of undefined (reading 'forEach')`），只有真跑一遍 JS 才会出现。

`docs/STUDIO_PROTOCOL.md:92` 当时写的是 `items[]` —— **前端照着文档写，文档错了**。
这条工具的第二次运行同时修掉了那行文档。

## 三态

* 找不到 Edge：`rc=2`（SKIP）。理由：`linux-portability` 与 CI runner 上都没有
  Edge；把「环境没有浏览器」判成「前端坏了」是假失败。
* 找到 Edge 但断言失败：`rc=1`，逐条打印。
* 全通过：`rc=0`。

**SKIP 不是通过。** 门禁的 `PASS: N 项` 只数 `[ok]`，SKIP 由 `tools/release_check.ps1`
的三态分支显式返回 `'SKIP'`。

## 为什么要有 --selftest

`judge()` 是纯函数（吃一份报告、吐结论），所以可以造坏输入直接喂它。
没有这一层的话，「浏览器里断言失败」与「判据自己坏了」在输出上长得一样。
"""

import argparse
import io
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
if os.path.join(REPO, 'tools') not in sys.path:
    sys.path.insert(0, os.path.join(REPO, 'tools'))

RC_OK = 0
RC_FAIL = 1
RC_SKIP = 2

# 断言: 每个视图在"点开它"之后, 这些元素里必须**至少有一个孩子**。
# 空着是**故意**的容器不在此列（out-solve / graph / out-host / vmlisting /
# vmstack / out-vmdisasm —— 它们要等用户操作才会填）。
REQUIRED_CHILDREN = {
    'gen': ['prof'],           # init() 里 await loadProfiles()
    'mods': ['mods'],          # 点开时 loadModules()
    'about': ['caps'],         # ★ 就是这条抓到了 loadCaps 的 items/capabilities 错位
    'test': ['gate-list'],     # 点 btn-gate-items 之后
}

# 每个视图点开后最小"叶子文本元素"数 —— 太低会漏（空页面也能有 5 个），
# 太高会脆。实测: gen 14 / test 10 / vm 23 / host 6 / mods 159 / about 30。
MIN_TEXT_ELS = {'gen': 8, 'test': 8, 'vm': 15, 'host': 6, 'mods': 20, 'about': 12}

VIEWS = ('gen', 'test', 'vm', 'host', 'mods', 'about')

EDGE_CANDIDATES = (
    r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    r'C:\Program Files\Microsoft\Edge\Application\msedge.exe',
    r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
)

NODE_CANDIDATES = (
    r'D:\environment\nodejs\node.exe',
    r'C:\Program Files\nodejs\node.exe',
)

# ---------------------------------------------------------------- 依赖发现

def find_edge(explicit=None):
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    for c in EDGE_CANDIDATES:
        if os.path.isfile(c):
            return c
    return None


def find_node(explicit=None):
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    for c in NODE_CANDIDATES:
        if os.path.isfile(c):
            return c
    # PATH 上找
    import shutil
    return shutil.which('node')


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ---------------------------------------------------------------- 浏览器驱动

# 驱动脚本: 零依赖（Node 22+ 有全局 WebSocket）。
# 输出一行 `##REPORT##{...}`，其余行是进度（忽略）。
DRIVER_JS = r'''
const http = require('http');
const { spawn } = require('child_process');
const EDGE = process.argv[2];
const URL_ = process.argv[3];
const PORT = parseInt(process.argv[4], 10);
const VIEWS = JSON.parse(process.argv[5]);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function get(path) {
  return new Promise((res, rej) => {
    http.get({ host: '127.0.0.1', port: PORT, path }, (r) => {
      let b = ''; r.on('data', (c) => (b += c)); r.on('end', () => res(b));
    }).on('error', rej);
  });
}

(async () => {
  const tmp = require('os').tmpdir() + '\\studio_ui_' + Date.now();
  const proc = spawn(EDGE, ['--headless=new', '--disable-gpu', '--no-first-run',
    '--no-default-browser-check', '--disable-extensions',
    '--user-data-dir=' + tmp, '--remote-debugging-port=' + PORT, 'about:blank'],
    { stdio: 'ignore' });

  let ver = null;
  for (let i = 0; i < 80; i++) {
    try { ver = JSON.parse(await get('/json/version')); break; } catch (e) { await sleep(250); }
  }
  const fail = (why) => {
    console.log('##REPORT##' + JSON.stringify({ ok: false, why: why, browser: ver && ver.Browser }));
    try { proc.kill(); } catch (e) {}
    process.exit(0);
  };
  if (!ver) return fail('no-cdp');

  let tabs = [];
  for (let i = 0; i < 80; i++) {
    tabs = JSON.parse(await get('/json/list')).filter((t) => t.type === 'page');
    if (tabs.length) break;
    await sleep(250);
  }
  if (!tabs.length) return fail('no-page-target');

  const sock = new WebSocket(tabs[0].webSocketDebuggerUrl);
  let id = 0; const pend = new Map();
  sock.addEventListener('message', (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pend.has(m.id)) { pend.get(m.id)(m); pend.delete(m.id); }
  });
  const send = (method, params) => new Promise((res) => {
    const i = ++id; pend.set(i, res);
    sock.send(JSON.stringify({ id: i, method, params }));
  });
  await new Promise((r) => sock.addEventListener('open', r));

  const ev = async (expr) => {
    const r = await send('Runtime.evaluate',
      { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.result && r.result.exceptionDetails) {
      const d = r.result.exceptionDetails;
      return 'EXC:' + String((d.exception && d.exception.description) || d.text);
    }
    return r.result && r.result.result && r.result.result.value;
  };

  await send('Runtime.enable');
  await send('Page.enable');
  await send('Page.addScriptToEvaluateOnNewDocument', {
    source: 'window.__err=[];'
      + 'window.addEventListener("error",e=>window.__err.push("ERR:"+String(e.message)));'
      + 'window.addEventListener("unhandledrejection",e=>window.__err.push('
      + '"REJ:"+String(e.reason&&e.reason.message?e.reason.message:e.reason)));',
  });
  await send('Page.navigate', { url: URL_ });
  await sleep(2500);

  const rep = { ok: true, browser: ver.Browser, booted: null, errors: [],
                views: {}, gates: {} };

  const appHidden = await ev('document.getElementById("app").hidden');
  rep.booted = (appHidden === false);
  rep.bootErrors = await ev('JSON.stringify(window.__err||[])');

  // 逐个点左侧活动栏
  for (const v of VIEWS) {
    await ev('window.__err=[]');
    const clicked = await ev(
      '(function(){var b=document.querySelector(\'.act[data-view="' + v + '"]\');'
      + 'if(!b)return false;b.click();return true;})()');
    await sleep(1200);
    const raw = await ev(
      'JSON.stringify((function(){'
      + 'var root=document.getElementById("view-' + v + '");'
      + 'if(!root)return {missing:true};'
      + 'var vis=' + JSON.stringify(VIEWS) + '.map(function(x){'
      + 'var e=document.getElementById("view-"+x);return [x,e?!e.hidden:null];});'
      + 'var leaves=[].slice.call(root.querySelectorAll("*")).filter(function(e){'
      + 'return (e.textContent||"").trim() && e.children.length===0;});'
      + 'return {shown:vis.filter(function(p){return p[1];}).map(function(p){return p[0];}),'
      + 'textEls:leaves.length};})())');
    let parsed = null;
    try { parsed = JSON.parse(raw); } catch (e) { parsed = { parseError: String(raw).slice(0, 160) }; }
    parsed.clicked = clicked;
    parsed.errors = await ev('window.__err||[]');
    rep.views[v] = parsed;
  }

  // 有动作才有内容的那些: 点了再看
  await ev('document.querySelector(\'.act[data-view="test"]\').click()');
  await sleep(400);
  await ev('var b=document.getElementById("btn-gate-items"); if(b)b.click();');
  await sleep(1800);
  rep.gates['test'] = await ev(
    '(function(){var e=document.getElementById("gate-list");return e?e.children.length:-1;})()');

  await ev('document.querySelector(\'.act[data-view="vm"]\').click()');
  await sleep(400);
  await ev('var b=document.getElementById("btn-vmimages"); if(b)b.click();');
  await sleep(1800);
  rep.gates['vm'] = await ev(
    '(function(){var e=document.getElementById("vmimg");return e?e.options.length:-1;})()');

  rep.errors = await ev('window.__err||[]');
  console.log('##REPORT##' + JSON.stringify(rep));
  try { sock.close(); } catch (e) {}
  try { proc.kill(); } catch (e) {}
  process.exit(0);
})().catch((e) => {
  console.log('##REPORT##' + JSON.stringify({ ok: false, why: 'driver-exception:' + e.message }));
  process.exit(0);
});
'''

REPORT_RE = re.compile(r'^##REPORT##(.*)$', re.M)


def run_browser(edge, node, url, port, timeout=180.0):
    """跑一次驱动，返回 (report, why)。report 为 None 表示驱动本身没给出报告。"""
    js = os.path.join(tempfile.mkdtemp(prefix='studio_ui_'), 'driver.js')
    io.open(js, 'w', encoding='utf-8', newline='\n').write(DRIVER_JS)
    try:
        r = subprocess.run([node, js, edge, url, str(port), json.dumps(list(VIEWS))],
                           capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, '驱动超时（%.0fs）' % timeout
    out = (r.stdout or b'').decode('utf-8', 'replace')
    err = (r.stderr or b'').decode('utf-8', 'replace').strip()
    m = REPORT_RE.search(out)
    if not m:
        return None, '驱动没有给出报告（rc=%d）%s' % (r.returncode, (' stderr=' + err[:200]) if err else '')
    try:
        return json.loads(m.group(1)), None
    except ValueError as e:
        return None, '报告不是 JSON: %s' % e


# ---------------------------------------------------------------- 判据（纯函数）

def judge(rep, required=None, min_text=None):
    """吃一份驱动报告，返回 `(ok, problems, info)`。

    纯函数 —— `--selftest` 靠这一点造坏输入。
    """
    required = REQUIRED_CHILDREN if required is None else required
    min_text = MIN_TEXT_ELS if min_text is None else min_text
    problems = []

    if not isinstance(rep, dict):
        return False, ['报告不是对象: %r' % (rep,)], {}
    if not rep.get('ok'):
        return False, ['驱动失败: %s' % rep.get('why')], {'browser': rep.get('browser')}

    info = {'browser': rep.get('browser')}

    # ① 启动
    if rep.get('booted') is not True:
        problems.append('外壳没有启动（`#app` 仍然是 hidden）—— 握手失败或 init() 抛了'
                        '（bootErrors=%s）' % (rep.get('bootErrors') or '[]'))
    be = rep.get('bootErrors') or '[]'
    if be not in ('[]', ''):
        problems.append('启动阶段有 JS 错误: %s' % be)

    # ② 每个视图: 点得中、恰好它显示、渲染出了东西
    views = rep.get('views') or {}
    if not views:
        problems.append('报告里没有 views —— 判据失去锚点')
    for v in VIEWS:
        d = views.get(v)
        if not isinstance(d, dict):
            problems.append('视图 %s 没有报告' % v)
            continue
        if not d.get('clicked'):
            problems.append('左侧活动栏里点不到 %s —— 导航按钮不存在或没有绑定' % v)
            continue
        if d.get('missing'):
            problems.append('点开 %s 之后找不到 #view-%s' % (v, v))
            continue
        shown = d.get('shown')
        if shown != [v]:
            problems.append('点 %s 之后可见的是 %s（应当恰好只有它）—— 视图切换坏了'
                            % (v, shown))
        n = d.get('textEls')
        if not isinstance(n, int):
            problems.append('视图 %s 的文本元素数读不到: %r' % (v, d.get('parseError') or n))
        elif n < min_text.get(v, 1):
            problems.append('视图 %s 只渲染出 %d 个文本元素（下限 %d）—— 它可能是空的'
                            % (v, n, min_text.get(v, 1)))
        errs = d.get('errors') or []
        if errs:
            problems.append('视图 %s 里有 JS 错误: %s' % (v, errs))

    # ③ 需要动作才填的容器
    gates = rep.get('gates') or {}
    for v, box in (('test', '#gate-list'), ('vm', '#vmimg')):
        c = gates.get(v)
        if not isinstance(c, int):
            problems.append('%s 的 %s 元素数读不到: %r' % (v, box, c))
        elif c <= 0:
            problems.append('点了按钮之后 %s 的 %s 仍然是空的 —— 命令通了但没渲染出来'
                            % (v, box))
        else:
            info['%s.%s' % (v, box)] = c

    errs = rep.get('errors') or []
    if errs:
        problems.append('整轮结束后仍有 JS 错误: %s' % errs)
    info['booted'] = rep.get('booted')
    info['views'] = {v: (views.get(v) or {}).get('textEls') for v in VIEWS}
    return (not problems), problems, info


# ---------------------------------------------------------------- 自检

def selftest(quiet=False):
    """造坏输入喂 judge() —— 证明判据**会**红，而不只是会绿。"""
    fails = []
    ncase = 0
    nneg = 0

    def mk(**over):
        base = {
            'ok': True, 'browser': 'Edg/test', 'booted': True, 'bootErrors': '[]',
            'errors': [],
            'views': {v: {'clicked': True, 'shown': [v], 'textEls': 99, 'errors': []}
                      for v in VIEWS},
            'gates': {'test': 44, 'vm': 4},
        }
        for k, val in over.items():
            if k.startswith('views.'):
                base['views'][k.split('.', 1)[1]] = val
            elif k.startswith('gates.'):
                base['gates'][k.split('.', 1)[1]] = val
            else:
                base[k] = val
        return base

    def case(name, rep, want_ok, want_sub=None):
        nonlocal ncase, nneg
        ncase += 1
        if not want_ok:
            nneg += 1
        ok, probs, _info = judge(rep)
        good = (ok == want_ok)
        det = 'problems=%s' % (probs[:1] if probs else [])
        if good and want_sub is not None:
            good = any(want_sub in p for p in probs)
            if not good:
                det += ' (缺少子串 %r)' % want_sub
        if not good:
            fails.append('%-52s want_ok=%s %s' % (name, want_ok, det))
        elif not quiet:
            print('  ok  %-52s %s' % (name, det))

    # --- 合规输入必须过（防假红）---
    case('合规报告 -> 通过', mk(), True)

    # --- ★ 本轮真缺陷的形态: 视图渲染为空 + unhandled rejection ---
    case('★ about 渲染为空 (本轮真缺陷) -> 必须报',
         mk(**{'views.about': {'clicked': True, 'shown': ['about'], 'textEls': 0,
                               'errors': ['REJ:Cannot read properties of undefined '
                                          '(reading \'forEach\')']}}),
         False, 'about')
    case('about 空但无 JS 错误 -> 也要报', mk(**{'views.about': {'clicked': True,
         'shown': ['about'], 'textEls': 2, 'errors': []}}), False, 'about')
    case('有 JS 错误 -> 必须报', mk(errors=['REJ:boom']), False, 'JS 错误')
    case('启动阶段有 JS 错误 -> 必须报', mk(bootErrors='["REJ:x"]'), False, '启动阶段')

    # --- 视图切换坏了 ---
    case('点 test 却显示了 gen -> 必须报',
         mk(**{'views.test': {'clicked': True, 'shown': ['gen'], 'textEls': 99,
                              'errors': []}}), False, '视图切换')
    case('点 test 显示了两个视图 -> 必须报',
         mk(**{'views.test': {'clicked': True, 'shown': ['test', 'gen'], 'textEls': 99,
                              'errors': []}}), False, '视图切换')
    case('导航按钮点不到 -> 必须报',
         mk(**{'views.vm': {'clicked': False, 'shown': [], 'textEls': 0,
                            'errors': []}}), False, '点不到')

    # --- 动作型容器 ---
    case('gate-list 点了还是空 -> 必须报', mk(**{'gates.test': 0}), False, '#gate-list')
    case('vmimg 点了还是空 -> 必须报', mk(**{'gates.vm': 0}), False, '#vmimg')

    # --- 外壳没起来 ---
    case('外壳没启动 -> 必须报', mk(booted=False), False, '没有启动')

    # --- 失锚 ---
    case('views 全缺 -> 必须报', mk(views={}), False, '失去锚点')
    case('报告不是对象 -> 必须报', 'not-a-dict', False, '不是对象')

    # --- 驱动自己失败 ---
    case('驱动失败 -> 必须报', {'ok': False, 'why': 'no-cdp'}, False, 'no-cdp')

    total = ncase
    if fails:
        print('[studio_ui_check-selftest] FAIL: %d/%d' % (len(fails), total))
        for f in fails:
            print('  [X] %s' % f)
        return RC_FAIL
    if not quiet:
        print('[studio_ui_check-selftest] PASS: %d 项（含 %d 项负向注入）' % (total, nneg))
    return RC_OK


# ---------------------------------------------------------------- 本体

def main(argv=None):
    ap = argparse.ArgumentParser(prog='studio_ui_check.py')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--edge', help='Edge 可执行文件（缺省自动找）')
    ap.add_argument('--node', help='node 可执行文件（缺省自动找）')
    ap.add_argument('--timeout', type=float, default=180.0)
    ap.add_argument('--keep', action='store_true', help='不关服务器（排障用）')
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest(args.quiet)

    edge = find_edge(args.edge)
    if not edge:
        sys.stdout.write('[studio_ui_check] SKIP: 没有找到 Edge —— '
                         '这条判据需要一个真实浏览器（CI runner 上没有）。\n')
        return RC_SKIP
    node = find_node(args.node)
    if not node:
        sys.stdout.write('[studio_ui_check] SKIP: 没有找到 node —— '
                         'CDP 需要 WebSocket 传输（Python 标准库没有）。\n')
        return RC_SKIP

    import studio_server as S

    port = free_port()
    cdp = free_port()
    while cdp == port:
        cdp = free_port()
    # ⚠️ `make_server` 返回 `(httpd, token, url)` —— 三元组，不是 httpd。
    httpd, tok, url = S.make_server(port=port)
    actual = httpd.server_address[1]
    if actual != port:
        url = 'http://127.0.0.1:%d/#t=%s' % (actual, tok)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        rep, why = run_browser(edge, node, url, cdp, args.timeout)
    finally:
        if not args.keep:
            httpd.shutdown()
            httpd.server_close()

    if rep is None:
        sys.stdout.write('[studio_ui_check] FAIL: %s\n' % why)
        return RC_FAIL

    ok, problems, info = judge(rep)
    if not ok:
        sys.stdout.write('[studio_ui_check] FAIL: %d 条\n' % len(problems))
        for p in problems:
            sys.stdout.write('  [X] %s\n' % p)
        return RC_FAIL
    sys.stdout.write('[studio_ui_check] PASS: %s；六个视图 %s；'
                     'gate.items=%s 项 / vm.images=%s 个；无 JS 错误\n'
                     % (info.get('browser'), info.get('views'),
                        info.get('test.#gate-list'), info.get('vm.#vmimg')))
    return RC_OK


if __name__ == '__main__':
    sys.exit(main())
