/* ShardVase Studio —— 前端。原生 JS，零依赖，零构建步。
 *
 * 三条纪律（都来自 docs/STUDIO_PROTOCOL.md，不是个人偏好）：
 *  1. 令牌从 URL 的 fragment（#t=...）取，放进 X-Studio-Token 请求头。
 *     fragment 不会进 Referer、不进服务端日志；query 会。
 *  2. 失败不吞：后端返回 ok:false 时把 code/message/detail 显示出来，
 *     而不是显示"出错了"。错误码决定了下一步动作（见协议 §6）。
 *  3. "声明"与"结果"不合并：门禁清单（静态 Check）与门禁结果（跑过的）
 *     是两个面板，两个来源。
 */
'use strict';

const $ = (id) => document.getElementById(id);

const state = {
  token: null,
  protocol: null,
  version: null,
  seq: 0,
  buildPlan: null,
};

// ---------------------------------------------------------------- 基础

function boot(msg, isErr) {
  const el = $('boot');
  el.textContent = msg;
  el.className = isErr ? 'boot err' : 'boot';
}

function readToken() {
  // location.hash 形如 "#t=xxxx"；不解析 query，令牌根本不该在 query 里。
  const h = window.location.hash || '';
  const m = /(?:^#|&)t=([^&]+)/.exec(h);
  return m ? decodeURIComponent(m[1]) : null;
}

function setStatus(text, cls) {
  const el = $('status');
  el.textContent = text;
  el.className = 'status ' + (cls || 'dim');
}

function log(line) {
  const out = $('panel-output');
  out.textContent += (out.textContent ? '\n' : '') + line;
  out.scrollTop = out.scrollHeight;
}

function raw(obj) {
  const out = $('panel-raw');
  out.textContent += (out.textContent ? '\n' : '') + JSON.stringify(obj);
  out.scrollTop = out.scrollHeight;
}

function showSide(obj) {
  $('out-side').textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
}

function problem(text) {
  const el = $('panel-problems');
  const d = document.createElement('div');
  d.className = 'item fail';
  d.innerHTML = '<span class="nm"></span>';
  d.firstChild.textContent = text;
  el.appendChild(d);
}

/** 统一的错误渲染。**不编造"出错了"** —— 逐字显示后端给的三段。 */
function renderError(err) {
  const code = (err && err.code) || 'E_UNKNOWN';
  const msg = (err && err.message) || '(无 message)';
  const det = err && err.detail ? JSON.stringify(err.detail, null, 2) : '';
  const text = '[' + code + '] ' + msg + (det ? '\n' + det : '');
  log(text);
  problem(text);
  showSide(err);
  return text;
}

// ---------------------------------------------------------------- 请求

async function call(cmd, args, opts) {
  opts = opts || {};
  const id = ++state.seq;
  const body = JSON.stringify({ id: id, cmd: cmd, args: args || {} });
  const res = await fetch('/api', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Studio-Token': state.token },
    body: body,
  });
  let js;
  try {
    js = await res.json();
  } catch (e) {
    renderError({ code: 'E_TRANSPORT', message: 'HTTP ' + res.status + ' 响应不是 JSON', detail: {} });
    return null;
  }
  raw(js);
  if (!js.ok) {
    renderError(js.error);
    return null;
  }
  if (!opts.quiet) showSide(js.data);
  return js.data;
}

/** 流式调用。每行一个事件；构建输出因此是边跑边到的。 */
async function callStream(cmd, args, onEvent) {
  const id = ++state.seq;
  const res = await fetch('/api/stream', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Studio-Token': state.token },
    body: JSON.stringify({ id: id, cmd: cmd, args: args || {} }),
  });
  if (!res.ok) {
    let js = null;
    try { js = await res.json(); } catch (e) { /* 保持 null */ }
    renderError(js ? js.error
      : { code: 'E_TRANSPORT', message: '流式请求 HTTP ' + res.status, detail: {} });
    return;
  }
  const reader = res.body.getReader();
  const dec = new TextDecoder('utf-8');
  let buf = '';
  for (;;) {
    const r = await reader.read();
    if (r.done) break;
    buf += dec.decode(r.value, { stream: true });
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      let js = null;
      try { js = JSON.parse(line); } catch (e) { continue; }
      raw(js);
      if (js.event) onEvent(js.event);
      else if (js.error) renderError(js.error);
    }
  }
}

// ---------------------------------------------------------------- 视图切换

function show(view) {
  document.querySelectorAll('.act').forEach((b) =>
    b.classList.toggle('on', b.dataset.view === view));
  ['gen', 'test', 'vm', 'host', 'mods', 'about'].forEach((v) => {
    const el = $('view-' + v);
    if (el) el.hidden = (v !== view);
  });
}

// ---------------------------------------------------------------- 生成

async function loadProfiles() {
  const d = await call('plan.list', {}, { quiet: true });
  if (!d) return;
  const sel = $('prof');
  sel.innerHTML = '';
  d.profiles.forEach((p) => {
    const o = document.createElement('option');
    o.value = p.name;
    o.textContent = p.name + ' — ' + (p.description || '');
    sel.appendChild(o);
  });
  log('策略 ' + d.count + ' 个: ' + d.profiles.map((p) => p.name).join(', '));
}

async function doSolve() {
  const prof = $('prof').value;
  const d = await call('plan.solve', { profile: prof });
  if (!d) return;
  $('out-solve').textContent = d._text || JSON.stringify(d, null, 2);
  await doGraph({ profile: prof });
  log('求解 ' + prof + ': 选中 ' + (d.selected || []).length + ' 个模块');
}

async function doGraph(args) {
  const d = await call('plan.graph', args, { quiet: true });
  const g = $('graph');
  g.innerHTML = '';
  if (!d) { g.textContent = '（图不可用）'; return; }

  const h1 = document.createElement('h3');
  h1.textContent = '节点 (' + d.nodes.length + ')';
  const nodes = document.createElement('div');
  nodes.className = 'nodes';
  d.nodes.forEach((n) => {
    const s = document.createElement('span');
    s.className = 'node' + (n.is_primitive ? ' prim' : '');
    s.textContent = n.name + ' [' + n.maturity + ']';
    s.title = 'modifies_text=' + n.modifies_text + ' verifies_text=' + n.verifies_text;
    nodes.appendChild(s);
  });
  g.appendChild(h1);
  g.appendChild(nodes);

  // ⚠️ 顺序图只画 order_edges：dep 边按 topo 排列会方向相反（协议 §5.2）。
  const h2 = document.createElement('h3');
  h2.textContent = '链接顺序（order_edges，topo 真正遵循的关系）';
  const oe = document.createElement('div');
  oe.className = 'edges';
  (d.order_edges || []).forEach((e) => {
    const dv = document.createElement('div');
    const a = document.createElement('span');
    a.className = 'arrow';
    a.textContent = '  ' + e.from + ' → ' + e.to;
    dv.appendChild(a);
    oe.appendChild(dv);
  });
  if (!(d.order_edges || []).length) oe.textContent = '  （无顺序约束）';
  g.appendChild(h2);
  g.appendChild(oe);

  const h3 = document.createElement('h3');
  h3.textContent = '冲突 (' + (d.conflicts || []).length + ')';
  const ce = document.createElement('div');
  ce.className = 'edges';
  (d.conflicts || []).forEach((c) => {
    const dv = document.createElement('div');
    const a = document.createElement('span');
    a.className = 'conf';
    a.textContent = '  ' + (c.a || c.modules || '?') + ' × ' + (c.b || '') +
      '  [' + (c.kind || c.conflict_kind || '?') + '] ' + (c.reason || '');
    dv.appendChild(a);
    ce.appendChild(dv);
  });
  if (!(d.conflicts || []).length) ce.textContent = '  （无冲突）';
  g.appendChild(h3);
  g.appendChild(ce);

  const h4 = document.createElement('h3');
  h4.textContent = '拓扑序';
  const te = document.createElement('div');
  te.className = 'edges';
  te.textContent = '  ' + (d.topo || []).join(' → ') +
    (d.cycle ? '   ⚠ 有环: ' + JSON.stringify(d.cycle) : '');
  g.appendChild(h4);
  g.appendChild(te);

  if ((d.topo_dep_violations || []).length) {
    const note = document.createElement('p');
    note.className = 'hint warn';
    note.textContent = 'dep 边与顺序相反 ' + d.topo_dep_violations.length +
      ' 条 —— 这是语义差异的证据，不是错误（见协议 §5.2）。';
    g.appendChild(note);
  }
  showSide(d);
}

async function doBuildPlan() {
  const prof = $('prof').value;
  $('panel-output').textContent = '';
  state.buildPlan = null;
  log('=== 构建计划（还没有执行） ===');
  await callStream('build.run', { profile: prof, config: $('cfg').value },
                   (ev) => {
    if (ev.event === 'plan') {
      state.buildPlan = ev;
      log('将执行: ' + (ev.argv || []).join(' '));
      if (ev.confirm_required) {
        log('需要确认：' + JSON.stringify(ev.confirm_required));
      }
      $('build-hint').textContent =
        '计划已就绪（' + (ev.argv || []).length + ' 个参数）。点「执行构建」才会真的跑。';
      $('btn-build').disabled = false;
    } else if (ev.event === 'done') {
      log('（未启动：' + (ev.note || '') + '）');
    }
  });
}

async function doBuild() {
  const prof = $('prof').value;
  $('panel-output').textContent = '';
  $('btn-build').disabled = true;
  setStatus('构建中…', '');
  const t0 = Date.now();
  const cfg = $('cfg').value;
  log('=== 执行构建（' + prof + ' / ' + cfg + '）===');
  if (cfg === 'Debug') {
    log('Debug: 产物写入 build/debug/ —— 发布产物 build/ 不受影响。');
  }
  await callStream('build.run',
                   { profile: prof, config: $('cfg').value, confirm: true },
                   (ev) => {
    if (ev.event === 'plan') {
      log('$ ' + (ev.argv || []).join(' '));
    } else if (ev.event === 'start') {
      log('--- 开始（超时预算 ' + ev.timeout_s + 's）---');
    } else if (ev.event === 'line') {
      log(ev.text);
    } else if (ev.event === 'exit') {
      log('--- 退出 rc=' + ev.rc + '，共 ' + ev.lines + ' 行 ---');
      if (ev.first_diag) log('诊断首行: ' + ev.first_diag);
    } else if (ev.event === 'done') {
      const secs = ((Date.now() - t0) / 1000).toFixed(1);
      log('=== 完成 ok=' + ev.ok + '，' + secs + 's ===');
      setStatus(ev.ok ? '构建成功' : '构建失败', ev.ok ? 'ok' : 'bad');
      if (!ev.ok) problem('构建失败: ' + (ev.first_diag || 'rc=' + ev.rc));
    }
  });
  $('btn-build').disabled = false;
}

// ---------------------------------------------------------------- 测试

const PILL = { pass: 'pass', fail: 'fail', error: 'error', skip: 'skip', 'not-run': 'not-run' };

async function gateQuery() {
  const q = $('gq').value;
  const d = await call('test.gate.results', { query: q });
  if (!d) return;
  const box = $('gate-list');
  box.innerHTML = '';

  if (q === 'latest' && d.items) {
    d.items.forEach((it) => {
      const row = document.createElement('div');
      row.className = 'item ' + (PILL[it.status] || '');
      const nm = document.createElement('span');
      nm.className = 'nm';
      nm.textContent = it.seq + '. ' + it.name;
      const why = document.createElement('span');
      why.className = 'why';
      why.textContent = it.why || '';
      const pill = document.createElement('span');
      pill.className = 'pill ' + (PILL[it.status] || '');
      pill.textContent = it.status + (it.seconds != null ? ' ' + it.seconds + 's' : '');
      row.append(nm, why, pill);
      box.appendChild(row);
    });
    const c = d.counts_json || {};
    log('最近一轮 ' + (d.run || '') + ': ' + JSON.stringify(c));
    const fails = d.items.filter((i) => i.status !== 'pass');
    fails.forEach((i) => problem(i.seq + '. ' + i.name + ' [' + i.status + '] ' + (i.why || '')));
    showSide({ run: d.run, counts: c, counts_text: d.counts_text });
  } else {
    box.textContent = JSON.stringify(d, null, 2);
    showSide(d);
  }
}

async function gateItems() {
  const d = await call('gate.items');
  if (!d) return;
  const box = $('gate-list');
  box.innerHTML = '';
  d.items.forEach((it) => {
    const row = document.createElement('div');
    row.className = 'item';
    const nm = document.createElement('span');
    nm.className = 'nm';
    nm.textContent = it.line + ': ' + it.name;
    const pill = document.createElement('span');
    pill.className = 'pill' + (it.gated ? ' gated' : '');
    pill.textContent = it.gated ? '-With* 控制' : '默认跑';
    row.append(nm, pill);
    box.appendChild(row);
  });
  log('门禁声明 ' + d.total + ' 项（默认跑 ' + d.default + '，受开关控制 ' + d.gated + '）');
  showSide({ source: d.source, kind: d.kind, why_no_gated_breakdown: d.why_no_gated_breakdown });
}

// ---------------------------------------------------------------- VM

async function vmImages() {
  const d = await call('vm.images');
  if (!d) return;
  const sel = $('vmimg');
  sel.innerHTML = '';
  d.images.forEach((im) => {
    const o = document.createElement('option');
    o.value = im.name;
    o.textContent = im.name + ' (code_len=' + im.code_len + ')';
    sel.appendChild(o);
  });
  log('镜像 ' + d.count + ' 个: ' + d.images.map((i) => i.name).join(', '));
}

async function vmDisasm() {
  const src = prompt('反汇编来源：输入 .vasm 路径，或留空用 vm.blob 里的镜像名',
    $('vmimg').value ? 'blob' : '');
  if (src === null) return;
  const args = src && src !== 'blob'
    ? { source: 'asm', asm: src }
    : { source: 'blob', name: $('vmimg').value };
  const d = await call('vm.disasm', args);
  if (!d) return;
  const lines = d.insns.map((i) =>
    String(i.off).padStart(5, '0') + '  ' +
    (i.line != null ? ('L' + String(i.line).padStart(4, ' ')) : '     ') + '  ' +
    i.mnem + (i.operand != null ? ' ' + i.operand : '') +
    (i.target != null ? '  -> ' + i.target : ''));
  $('out-vm').textContent = lines.join('\n') +
    '\n\n共 ' + d.count + ' 条；有行号表: ' + d.has_lines;
  log('反汇编 ' + d.count + ' 条（' + args.source + '）');
}

// ---------------------------------------------------------------- 主机调试

function syms() {
  return $('sym').value.split(',').map((s) => s.trim()).filter(Boolean);
}

async function hostCall(cmd, args) {
  const d = await call(cmd, args);
  if (!d) return;
  $('out-host').textContent = JSON.stringify(d, null, 2);
  // 反调试互扰是**一等公民**：它一到就在问题面板留痕，不只在 JSON 里。
  const ad = d.antidebug_interference;
  if (ad && ad.possible) {
    problem(cmd + ': 本次结果可能被工具自身干扰 —— ' +
      (ad.cannot_be_used_as || '不可用于判定防御失效') +
      '（若检测到，目标退出码 ' + ad.exit_code_if_detected + '）');
  }
  if (d.missing && d.missing.length) {
    problem(cmd + ': 查不到的符号: ' + d.missing.join(', ') + '（"没有"与"没说"是两件事）');
  }
  if (d.unknown && d.unknown.length) {
    problem(cmd + ': 未知退出码: ' + d.unknown.join(', ') + '（不猜、不映射成最近的一个）');
  }
}

// ---------------------------------------------------------------- 模块 / 能力

const MATURITY = { core: '核心', verified: '已验证', community: '社区', experimental: '实验' };

async function loadModules() {
  const d = await call('modules.list');
  if (!d) return;
  const box = $('mods');
  box.innerHTML = '';
  d.modules.forEach((m) => {
    const c = document.createElement('div');
    c.className = 'card';
    const h = document.createElement('h4');
    h.textContent = m.name;
    c.appendChild(h);
    const kv = (k, v) => {
      const d2 = document.createElement('div');
      d2.className = 'kv';
      const b = document.createElement('b');
      b.textContent = k + ':';
      const s = document.createElement('span');
      s.textContent = v;
      d2.append(b, s);
      c.appendChild(d2);
    };
    kv('成熟度', (MATURITY[m.maturity] || m.maturity));
    kv('成本', m.cost);
    kv('依赖', (m.deps || []).join(', ') || '—');
    kv('冲突', (m.conflicts_with || []).join(', ') || '—');
    kv('改 .text', m.modifies_text ? '是' : '否');
    const lim = document.createElement('div');
    const limits = (m.known_limits || []).filter((x) => x);
    lim.className = 'limits' + (limits.length ? '' : ' none');
    lim.textContent = limits.length ? '已知局限: ' + limits.join('；') : '已知局限: （未登记）';
    c.appendChild(lim);
    box.appendChild(c);
  });
  log('模块 ' + d.modules.length + ' 个');
  showSide({ maturity_scale: d.maturity_scale, primitives: d.primitives });
}

async function loadCaps() {
  const d = await call('capabilities');
  if (!d) return;
  const box = $('caps');
  box.innerHTML = '';
  d.items.forEach((it) => {
    const row = document.createElement('div');
    row.className = 'item ' + (it.status === 'ready' ? 'pass' : it.status === 'partial' ? 'skip' : '');
    const nm = document.createElement('span');
    nm.className = 'nm';
    nm.textContent = it.name;
    const why = document.createElement('span');
    why.className = 'why';
    why.textContent = (it.evidence || '') + (it.note ? ' · ' + it.note : '');
    const pill = document.createElement('span');
    pill.className = 'pill' + (it.status === 'planned' ? '' : ' pass');
    pill.textContent = it.status + (it.step ? ' @' + it.step : '');
    row.append(nm, why, pill);
    box.appendChild(row);
  });
  log('能力 ' + d.items.length + ' 项: ' +
    d.items.map((i) => i.name + '=' + i.status).join(', '));
}

// ---------------------------------------------------------------- tabs

function tab(name) {
  document.querySelectorAll('.tab').forEach((b) =>
    b.classList.toggle('on', b.dataset.panel === name));
  ['output', 'problems', 'raw'].forEach((p) => {
    $('panel-' + p).hidden = (p !== name);
  });
}

// ---------------------------------------------------------------- 启动

async function init() {
  state.token = readToken();
  if (!state.token) {
    boot('URL 里没有令牌。\n\n请用 studio_server.py 启动时打印的那个地址打开 —— ' +
      '令牌在 # 后面。\n（令牌只在请求头里传递；不放在 query，以免经 Referer 泄漏。）',
      true);
    return;
  }
  boot('正在握手…');
  const d = await call('ping', {}, { quiet: true });
  if (!d) { boot('握手失败，见下方输出。', true); return; }
  state.protocol = d.protocol_version;
  state.version = d.studio_version;
  $('ver').textContent = 'studio ' + d.studio_version + ' · protocol v' + d.protocol_version +
    ' · ' + d.platform;
  setStatus('已连接 ' + d.platform, 'ok');
  $('boot').hidden = true;
  $('app').hidden = false;
  show('gen');

  $('prof') && await loadProfiles();
  log('已连接。协议 v' + d.protocol_version + '，仓库 ' + d.repo);
}

// ---- 事件绑定 ----
document.querySelectorAll('.act').forEach((b) =>
  b.addEventListener('click', () => {
    show(b.dataset.view);
    if (b.dataset.view === 'mods') loadModules();
    if (b.dataset.view === 'about') loadCaps();
    if (b.dataset.view === 'vm') vmImages();
  }));
document.querySelectorAll('.tab').forEach((b) =>
  b.addEventListener('click', () => tab(b.dataset.panel)));

$('btn-solve') && $('btn-solve').addEventListener('click', doSolve);
$('btn-build-plan') && $('btn-build-plan').addEventListener('click', doBuildPlan);
$('btn-build') && $('btn-build').addEventListener('click', doBuild);
$('btn-gate') && $('btn-gate').addEventListener('click', gateQuery);
$('btn-gate-items') && $('btn-gate-items').addEventListener('click', gateItems);
$('btn-vmimages') && $('btn-vmimages').addEventListener('click', vmImages);
$('btn-vmdisasm') && $('btn-vmdisasm').addEventListener('click', vmDisasm);
$('btn-doc') && $('btn-doc').addEventListener('click', () => hostCall('debug.doctor', {}));
$('btn-sym') && $('btn-sym').addEventListener('click', () => hostCall('debug.sym', { symbols: syms() }));
$('btn-mask') && $('btn-mask').addEventListener('click', () => hostCall('debug.mask', { symbols: syms() }));
$('btn-exit') && $('btn-exit').addEventListener('click', () =>
  hostCall('debug.exit', {
    codes: $('exits').value.split(',').map((s) => s.trim()).filter(Boolean),
  }));

init().catch((e) => {
  boot('启动失败: ' + e.message, true);
  problem('启动失败: ' + (e && e.stack ? e.stack : e));
});
