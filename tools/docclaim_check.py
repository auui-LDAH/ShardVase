#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""docclaim_check.py — **文档断言 ↔ 实测** 一致性检查器（R1, 2026-09-29）

## 为什么存在（**换来的教训**）
本项目已出现 **5 次「记录漂移」**：
```
V3 台账注入  -> 防御早已落地（D-D4 同日），矩阵仍标 BREACHED
V1 verify    -> 已优雅报错，仍标 PARTIAL（崩溃）
S4 重放      -> check_nonce_replay 已落地，仍标 PARTIAL（无拦截）
SCDBG 调试日志 -> 已有 #ifdef 开关且产物不含，文档仍称"发条阻断项"
§22/§29/§35  -> 计划已全部完成，标题仍标"📋 待确认"
```
**共同模式**: **修复落地了，但声称它的文档没同步** ->
**持续低估自身能力**，并误导后续工作（本轮我差点重复实现 `V2`）。

## 本工具的做法（**把"文档说的话"变成可执行断言**）
```
CLAIMS 表: 每条 = (id, 断言文本, **来源文档**, 探针函数, 期望)
  -> 探针实测；与期望不符 -> **FAIL**（门禁直接红）
```
> **关键设计**: 断言值**从文档里解析**（而非硬编码）——
> 例如门禁项数，是"从 `publish/` 读到的 N"与"实际 `Check` 块数"比对，
> 所以**改代码不改文档**、或**改文档不改代码**，都会被抓到。

## 用法
```
python tools/docclaim_check.py              # 全部断言
python tools/docclaim_check.py --list       # 列出断言
python tools/docclaim_check.py --only <id>  # 单条
python tools/docclaim_check.py --selftest   # 自检（**含负向**）
```

## 诚实边界
· 只断言**可机械验证**的事实；主观判断（"防护够不够强"）**不在此列**
· 产物的**大小/时间戳**等易变值**不做硬断言**（会变成脆弱测试）
· 每条断言必须写明**来源文档** -> 文档改名/删除会**报错**（防止悬空断言）
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _p(*parts):
    return os.path.join(REPO, *parts)


def _read(path, enc='utf-8'):
    """读文本（绕过 BOM；失败返回 None）。"""
    try:
        with open(path, encoding=enc, errors='replace') as f:
            return f.read()
    except OSError:
        return None


# ============================================================================
# 探针（每个返回 (ok, detail)；**不抛异常**由调用方兜底为 FAIL）
# ============================================================================

def probe_no_scdbg_in(artifact):
    """产物中**不得**含 SCDBG 自解密日志（泄漏 RVA/密钥/CRC）。"""
    p = _p(artifact)
    if not os.path.isfile(p):
        return False, 'missing %s' % artifact
    data = open(p, 'rb').read()
    bad = [m for m in (b'[SCDBG]', b'PRE-VP', b'CRC got', b'VP-OK')
           if m in data]
    if bad:
        return False, ('产物含调试串 %s -> **等于给攻击者解密 oracle**'
                       % [b.decode() for b in bad])
    return True, '%d 字节中无调试串' % len(data)


def probe_scdbg_guarded():
    """SC_DBG 必须**由编译开关控制**（否则 Release 会输出）。"""
    t = _read(_p('src', 'selfcrypt.c'))
    if t is None:
        return False, 'missing src/selfcrypt.c'
    has_guard = '#ifdef PROT_SELFCRYPT_DEBUG' in t
    has_noop = '((void)0)' in t
    if has_guard and has_noop:
        return True, 'SC_DBG 由 PROT_SELFCRYPT_DEBUG 控制'
    return False, ('缺少编译开关（guard=%s noop=%s）'
                   % (has_guard, has_noop))


def _gate_items():
    """从 release_check.ps1 解析门禁项名（**行锚定**）。

    ## ⚠️ 为什么必须行锚定（2026-10-01 实测缺陷）

    原写法 `re.findall(r"Check\\s+'([^']+)'", t)` **非锚定**，会把
    `tools/release_check.ps1:79` 注释里的示例文本

        # 于是 `Check 'X' { & $tool; $LASTEXITCODE -eq 0 }` 得到的是

    也算成一项（多出假项 `'X'`），于是断言得到 **31** 而真实调用点是 **30**。

    **更隐蔽的是它刚好"对"**：`tools/doccheck.py:156-163` 用行锚定正则得 30，
    再**硬编码 `+1`**（"签名提示项"）也得到 31 —— 两个检查器用**两种不同的
    错误方式**各凑出同一个 31，于是 `publish/*.md`(31) / docclaim(31) /
    doccheck(31) 三方一致，**却三方都错**。这是「自洽 != 正确」的第 5 次重演，
    也是「判据必须用**唯一结构形态**，宽松子串已 4 次假阳性」的再次验证。

    修法有两部分，缺一不可：
      ① 本函数改**行锚定**（行首可空白 + `Check` + 引号）；
      ② `tools/release_check.ps1` 的签名块改为**真正的 `Check`** ——
         否则行锚定会得 30 而运行期报 31，漂移只是换了个方向。
    """
    t = _read(_p('tools', 'release_check.ps1'), enc='utf-8-sig')
    if t is None:
        return None
    return re.findall(r"(?m)^\s*Check\s+'([^']+)'", t)


def probe_gate_count_matches_docs():
    """**从 publish 文档解析**声称的门禁项数，与实际 Check 块数比对。

    ## 为什么这样设计
      若硬编码"26"，则**改了代码忘了改文档**不会被发现 —— 而漂移正是
      这种形态。**从文档取值**才能真正抓"文档 vs 实现"的不一致。
    """
    items = _gate_items()
    if items is None:
        return False, 'missing tools/release_check.ps1'
    actual = len(items)

    claimed = {}                     # 文件 -> 声称的 N
    for f in sorted(glob.glob(_p('publish', '*.md'))):
        t = _read(f) or ''
        for m in re.finditer(r'release_check[^\n]{0,24}?(\d+)\s*/\s*(\d+)', t):
            claimed[os.path.basename(f)] = (int(m.group(1)), int(m.group(2)))
    if not claimed:
        return False, ('**没有文档声称门禁项数** -> 断言悬空'
                       '（实际 %d 项；请在 publish/ 写明）' % actual)

    bad = {k: v for k, v in claimed.items() if v[0] != actual}
    if bad:
        return False, ('文档声称 %s，实际 **%d** 项 -> 漂移'
                       % ({k: '%d/%d' % v for k, v in bad.items()}, actual))
    return True, ('文档声称与实际一致: **%d 项**（%d 份文档）'
                  % (actual, len(claimed)))


def probe_ci_runtime_count():
    """ci 运行时项数（`results.append` 去重后的逻辑项）。"""
    t = _read(_p('tools', 'verify_linux_runtime.py'))
    if t is None:
        return False, 'missing verify_linux_runtime.py'
    names = re.findall(r"results\.append\(\('([^']+)'", t)
    uniq = len(set(names))
    if uniq < 5:
        return False, '解析到 %d 项（异常偏少，可能解析失效）' % uniq
    return True, '%d 项（去重后；原始 %d）' % (uniq, len(names))


def probe_matrix_breached():
    """`ATTACK_MATRIX` 的「显式 BREACHED」表里**仍未处置**的条数。

    ## 判据
      表中每条若已标注 `→ BLOCKED` / `→ PARTIAL`（§39/§40 的复核回填），
      则**不再计入** BREACHED 存量。
    """
    p = _p('docs', 'ATTACK_MATRIX.md')
    t = _read(p)
    if t is None:
        return False, 'missing docs/ATTACK_MATRIX.md'
    i = t.find('## 显式 BREACHED')
    if i < 0:
        return False, '未找到「显式 BREACHED」节'
    # ## 只取**第一张表**（到下一个 `## ` 标题为止）
    #   否则 §39/§40 的「D4 复核」表也会被算进去 -> 计数**偏大且无意义**。
    nxt = t.find('\n## ', i + 5)
    seg = t[i:(nxt if nxt > 0 else i + 4000)]
    # 只数**条目行**（形如 `| \`drillN...\` |`）——
    # 否则复核回填的说明行也会被算进去 -> 计数**误导读者**。
    rows = [l for l in seg.split('\n')
            if re.match(r'^\|\s*`', l.strip())]
    unresolved = [l for l in rows
                  if '→ BLOCKED' not in l and '→ PARTIAL' not in l]
    if not rows:
        return False, ('「显式 BREACHED」节存在但**解析不到条目行**'
                       '（格式可能已变 -> 断言需更新）')
    return True, ('显式 BREACHED %d 条（其中仍标 BREACHED 的 %d 条）'
                  % (len(rows), len(unresolved)))


#: 必须携带「最后核实」元数据的关键文档（R1.3）
#:   ## 为什么这些
#:     它们是**决策依据类**文档（成本/可用性/矩阵/交接/平台/威胁模型）——
#:     后续工作最容易引用它们的**结论**，一旦过时危害最大。
#:     元数据必须含**方法**（否则无法复核 -> 形式主义）。
KEY_DOCS = [
    'docs/COST_ASYMMETRY.md',
    'docs/USABILITY_ASSESSMENT.md',
    'docs/ATTACK_MATRIX.md',
    'docs/HANDOVER.md',
    'docs/PLATFORM_ISOLATION_PLAN.md',
    'docs/THREATMODEL.md',
]

#: 元数据格式（docclaim 校验）: `> **最后核实**: YYYY-MM-DD · 方法: ... · 提交 \`hash\``
RE_VERIFIED = re.compile(
    r'^> \*\*最后核实\*\*:\s*(\d{4}-\d{2}-\d{2})\s*·\s*方法:\s*(\S.+)$',
    re.M)

#: 末段的「提交 `hash`」字段。
#:   ## 为什么单独抽出来查（2026-09-30 新增）
#:     本探针的**全部意义**就是"防形式主义"（要求"方法"而非只写日期）。
#:     但实测发现：3 份关键文档把提交字段写成 `提交 \`pending\`` ——
#:     **这恰恰是形式主义本身**，而旧版探针**放行**（它只校验日期与方法）。
#:     => 一处"占位符永久滞留"能骗过为防占位符而写的检查器。
#:   ## 判据的形态
#:     提交字段的值**必须是 7–40 位十六进制 sha**。
#:     用**唯一结构形态**（反引号包裹 + 全 hex）而非宽松子串 —— 后者已 4 次假阳性。
RE_COMMIT = re.compile(r'·\s*提交\s*`([^`]+)`')
RE_SHA = re.compile(r'^[0-9a-f]{7,40}$')


def probe_verified_metadata():
    """关键文档必须含「最后核实」元数据（**日期 + 方法 + 可核对的提交**）。

    ## 为什么要求"方法"
      只写日期是**形式主义** —— 无人知道当时**怎么核实的**、能否复现。
      要求"方法"（工具/命令）-> 复核者可**重跑同一方法**。

    ## 为什么还要求"提交是 sha"
      `提交 \\`pending\\`` / `\\`TBD\\`` / `\\`—\\`` 与"只写日期"同罪：
      它让复核者**无法回到当时那个仓库状态**。实测已有 3 份文档长期滞留
      `pending`（占位符比日期更隐蔽 —— 日期至少会显得"旧"，`pending` 看起来
      像"正在做"）。=> 占位符必须**硬失败**，否则防形式主义的检查器自己会形式化。
    """
    missing, no_method, bad_date, bad_commit = [], [], [], []
    for d in KEY_DOCS:
        t = _read(_p(*d.split('/')))
        if t is None:
            missing.append(d + '(文件缺失)')
            continue
        m = RE_VERIFIED.search(t)
        if not m:
            missing.append(d)
            continue
        if len(m.group(2).strip()) < 6:
            no_method.append(d)
        if not re.match(r'^20\d\d-\d\d-\d\d$', m.group(1)):
            bad_date.append(d)
        c = RE_COMMIT.search(t)
        # 缺字段 与 占位符 分开报 —— 两者的处置不同（补字段 vs 补真实提交）
        if not c:
            bad_commit.append(d + '(缺提交字段)')
        elif not RE_SHA.match(c.group(1).strip()):
            bad_commit.append('%s(%s)' % (d, c.group(1).strip()[:16]))
    if missing or no_method or bad_date or bad_commit:
        return False, ('缺元数据=%s 方法缺失=%s 日期异常=%s 提交非 sha=%s'
                       % (missing, no_method, bad_date, bad_commit))
    return True, '%d 份关键文档均有「最后核实」（日期 + 方法 + sha）' % len(KEY_DOCS)

def probe_flat_clean():
    """`demo/gen/` 根下**无文件**（§34.6 清理后防"复活"）。"""
    d = _p('demo', 'gen')
    if not os.path.isdir(d):
        return False, 'missing demo/gen/'
    flat = sorted(f for f in os.listdir(d)
                  if os.path.isfile(os.path.join(d, f)))
    if flat:
        return False, 'flat 文件复活: %s' % flat
    return True, 'flat clean（仅 %s）' % sorted(os.listdir(d))


# ============================================================================
# 断言表
# ============================================================================
#  字段:
#    id      唯一标识（--only 用）
#    claim   断言文本（人读）
#    source  **来源文档**（必须存在 -> 防止悬空断言）
#    probe   探针
#    expect  期望的探针返回值（通常 True）
#    note    备注（可选）
CLAIMS = [
    {
        'id': 'scdbg-absent-win',
        'claim': 'Release 产物 build/demo.exe **不含** SCDBG 自解密日志',
        'source': 'docs/COST_ASYMMETRY.md',
        'probe': lambda: probe_no_scdbg_in('build/demo.exe'),
        'expect': True,
        'note': '§9 曾称"无编译开关、Release 同样输出"（**已修，此处守护**）',
    },
    {
        'id': 'scdbg-absent-linux',
        'claim': 'Linux 产物 build/demo_linux **不含** SCDBG 自解密日志',
        'source': 'docs/COST_ASYMMETRY.md',
        'probe': lambda: probe_no_scdbg_in('build/demo_linux'),
        'expect': True,
    },
    {
        'id': 'scdbg-guarded',
        'claim': 'SC_DBG **由 `PROT_SELFCRYPT_DEBUG` 编译开关控制**',
        'source': 'docs/COST_ASYMMETRY.md',
        'probe': probe_scdbg_guarded,
        'expect': True,
        'note': '前两条是**结论**，本条是**机制**——机制在则结论可再生成',
    },
    {
        'id': 'gate-count',
        'claim': '`publish/` 文档声称的门禁项数 == 实际 `Check` 块数',
        'source': 'publish/01-关于ShardVase.md',
        'probe': probe_gate_count_matches_docs,
        'expect': True,
        'note': '**值从文档解析**（非硬编码）-> 抓"改了实现忘了改文档"',
    },
    {
        'id': 'ci-runtime-count',
        'claim': '`verify_linux_runtime` 的运行时项数可解析且 >= 5',
        'source': 'docs/PLATFORM_ISOLATION_PLAN.md',
        'probe': probe_ci_runtime_count,
        'expect': True,
    },
    {
        'id': 'matrix-breached',
        'claim': '`ATTACK_MATRIX` 显式 BREACHED 表**存在且可解析**',
        'source': 'docs/ATTACK_MATRIX.md',
        'probe': probe_matrix_breached,
        'expect': True,
        'note': '**不断言具体条数**（会随复核变化）——只保证"表可解析"',
    },
    {
        'id': 'verified-metadata',
        'claim': '6 份**决策依据类**文档均含「最后核实」（日期 + **方法**）',
        'source': 'docs/REFINE_PLAN.md',
        'probe': probe_verified_metadata,
        'expect': True,
        'note': '要求"方法"而非只写日期 —— 否则无法复核（形式主义）',
    },
    {
        'id': 'flat-clean',
        'claim': '`demo/gen/` 根下无 flat 文件（§34.6 清理未复活）',
        'source': 'docs/PLATFORM_ISOLATION_PLAN.md',
        'probe': probe_flat_clean,
        'expect': True,
    },
]


# ============================================================================
# 执行
# ============================================================================

def run_claim(c):
    """执行一条断言 -> (status, detail)。status ∈ ok/fail"""
    # ① 来源文档必须存在（**防悬空断言**）
    src = _p(*c['source'].split('/'))
    if not os.path.exists(src):
        return 'fail', '来源文档不存在: %s（断言悬空）' % c['source']
    # ② 探针（异常兜底为 FAIL，**不崩溃**）
    try:
        ok, detail = c['probe']()
    except Exception as e:                           # noqa: BLE001
        return 'fail', '探针异常: %s: %s' % (type(e).__name__, e)
    holds = (ok == c['expect'])
    return ('ok' if holds else 'fail'), detail


def main():
    ap = argparse.ArgumentParser(prog='docclaim_check.py')
    ap.add_argument('--only', nargs='*', help='只跑指定断言 id')
    ap.add_argument('--list', action='store_true', help='列出断言')
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--quiet', action='store_true', help='只输出汇总')
    ap.add_argument('--selftest', action='store_true',
                    help='自检（**含负向**）')
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    names = args.only or [c['id'] for c in CLAIMS]
    results = []
    for c in CLAIMS:
        if c['id'] not in names:
            continue
        st, det = run_claim(c)
        results.append((c, st, det))
        if not args.json and not args.quiet:
            print('  %-4s %-22s %s'
                  % ('ok' if st == 'ok' else 'FAIL', c['id'], det[:80]))

    if args.list:
        for c in CLAIMS:
            print('  %-22s [%s]' % (c['id'], c['source']))
        return 0

    if args.json:
        print(json.dumps([{'id': c['id'], 'status': st, 'detail': d}
                          for c, st, d in results],
                         ensure_ascii=False, indent=2))
    bad = [c['id'] for c, st, _ in results if st != 'ok']
    n_ok = len(results) - len(bad)
    if not args.json:
        print('[docclaim_check] %s (%d/%d)'
              % ('PASS' if not bad else 'FAIL: ' + ','.join(bad),
                 n_ok, len(results)))
    return 0 if not bad else 1


# ============================================================================
# 自检（**含负向** —— 本项目纪律: 检查器必须自证能抓错）
# ============================================================================

def selftest():
    print('=== docclaim_check 自检 ===')
    fail = 0

    def case(name, ok, detail=''):
        nonlocal fail
        if ok:
            print('  ok  %s' % name)
        else:
            print('  **FAIL** %s  %s' % (name, detail[:90]))
            fail += 1

    # T1 正向: 真实断言应全过（依赖当前仓库状态）
    bad = []
    for c in CLAIMS:
        st, det = run_claim(c)
        if st != 'ok':
            bad.append('%s: %s' % (c['id'], det))
    case('T1 正向: %d 条真实断言全过' % len(CLAIMS), not bad,
         '; '.join(bad))

    # T2 **负向**: 来源文档不存在 -> 必须 FAIL（悬空断言）
    fake = dict(CLAIMS[0])
    fake['source'] = 'docs/__no_such_doc__.md'
    st2, det2 = run_claim(fake)
    case('T2 **负向**: 来源文档缺失 -> 必须 FAIL',
         st2 == 'fail' and '不存在' in det2, det2)

    # T3 **负向**: 探针抛异常 -> 必须 FAIL（且**不崩溃**）
    fake3 = dict(CLAIMS[0])
    fake3['probe'] = lambda: (_ for _ in ()).throw(RuntimeError('boom'))
    st3, det3 = run_claim(fake3)
    case('T3 **负向**: 探针异常 -> 必须 FAIL（不崩溃）',
         st3 == 'fail' and '探针异常' in det3, det3)

    # T4 **负向**: 期望被反转 -> 必须 FAIL（证明判据真的在比对）
    fake4 = dict(CLAIMS[0])
    fake4['expect'] = (not CLAIMS[0]['expect'])
    st4, det4 = run_claim(fake4)
    case('T4 **负向**: expect 反转 -> 必须 FAIL',
         st4 == 'fail', det4)

    # T5 **负向**: 门禁项数断言必须能**真的发现漂移**
    #   构造: 临时篡改一个 publish 文档的声称值 -> 探针必须 FAIL
    import tempfile
    pub = sorted(glob.glob(_p('publish', '*.md')))
    if not pub:
        case('T5 **负向**: 无 publish 文档可测（跳过）', True)
    else:
        target = pub[0]
        # ## ⚠️ 必须**字节级**读写（文本模式会改换行 —— 实测踩过）
        #   `open(p,'w')` 在 Windows 默认把 `\n` 翻译成 `\r\n` ->
        #   受跟踪文件的**换行被静默改写**（内容相同、字节不同 -> git 报修改）。
        #   实测代价: 自检把 `publish/01-*.md` 改成了 CRLF。
        #   => `'rb'` 读、`'wb'` 写，保证**精确恢复**。
        orig_bytes = open(target, 'rb').read()
        orig = orig_bytes.decode('utf-8', errors='replace')
        try:
            tampered = re.sub(r'(release_check[^\n]{0,24}?)(\d+)(\s*/\s*)(\d+)',
                              lambda m: m.group(1) + '999' + m.group(3) + '999',
                              orig)
            if tampered == orig:
                case('T5 **负向**: 文档无 release_check N/N（跳过）', True)
            else:
                open(target, 'wb').write(tampered.encode('utf-8'))
                try:
                    ok5, det5 = probe_gate_count_matches_docs()
                    case('T5 **负向**: 篡改文档声称值 -> 探针必须 FAIL',
                         ok5 is False, str(det5))
                finally:
                    open(target, 'wb').write(orig_bytes)
        finally:
            # 双重保险: 字节级恢复 + **断言恢复后字节一致**
            open(target, 'wb').write(orig_bytes)
            after = open(target, 'rb').read()
            case('T5b **恢复字节一致**（自检不得改坏仓库）',
                 after == orig_bytes,
                 '恢复后 %d vs 原 %d 字节' % (len(after), len(orig_bytes)))

    # T6 **负向**: 「最后核实」的**占位符**必须被拒
    #   ## 为什么必须有这条
    #     实测发现 3 份关键文档长期写着 `提交 \`pending\``，而**旧版探针放行** ——
    #     一个"为防形式主义而写"的检查器，被**形式主义本身**骗过。
    #     这正是自检 T6 存在的理由：**先写"必须失败"的用例**，
    #     否则这个洞会一路进仓库（同 prot_dbg 的空 map 静默 PASS）。
    #   ## 形态
    #     直接调 RE_SHA / RE_COMMIT 的**纯函数**（不碰真实文档 -> 零副作用），
    #     并对**真实 KEY_DOCS 现况**再断言一次（防止将来又写出 pending）。
    for bad_val in ('pending', 'TBD', '—', 'todo', '', 'HEAD'):
        hit = RE_SHA.match(bad_val)
        case('T6 **负向**: 提交字段占位符 %r 必须不被接受' % bad_val,
             hit is None, 'RE_SHA 竟然接受了 %r' % bad_val)
    for good_val in ('ca14477', 'b700574', '1d59ac0'):
        case('T6 正向: 真实 sha %r 必须被接受' % good_val,
             RE_SHA.match(good_val) is not None, 'RE_SHA 拒绝了 %r' % good_val)
    # 对真实文档复现"当时的缺陷形态"：把元数据行的提交段替换成 pending
    #   -> 只在**内存里**替换后调判定逻辑，不写文件
    places = []
    for d in KEY_DOCS:
        t = _read(_p(*d.split('/')))
        if t is None:
            continue
        m = RE_COMMIT.search(t)
        if m and not RE_SHA.match(m.group(1).strip()):
            places.append('%s=%s' % (d, m.group(1).strip()[:12]))
    case('T6 正向对照: 真实 KEY_DOCS 的提交字段全为 sha（现况 %d 份）'
         % len(KEY_DOCS), not places, '仍有占位符: %s' % places)
    # 构造式负向: 把一份真实文档在内存里改成 pending -> 判定必须是 False
    probe_src = None
    for d in KEY_DOCS:
        t = _read(_p(*d.split('/')))
        if t and RE_COMMIT.search(t):
            probe_src = RE_COMMIT.sub('· 提交 `pending`', t, count=1)
            break
    if probe_src is None:
        case('T6 **负向**: 无可构造的样本（跳过）', True)
    else:
        mm = RE_COMMIT.search(probe_src)
        case('T6 **负向**: 内存中改成 `pending` -> 判定必须为"非 sha"',
             mm is not None and RE_SHA.match(mm.group(1).strip()) is None,
             '改后仍被判为合法 sha')

    # T7 **负向**: 注释里的 `Check 'X'` 不得被算作门禁项
    #   ## 为什么必须有这条（2026-10-01 实测缺陷）
    #     旧 `_gate_items()` 用**非锚定**正则 `Check\s+'([^']+)'`，把
    #     `tools/release_check.ps1:79` 的**注释示例**
    #         `# 于是 \`Check 'X' { & $tool; $LASTEXITCODE -eq 0 }\``
    #     也算作一项（假项 `'X'`），于是断言得 31 而真实调用点是 30。
    #   ## 为什么这个洞能活这么久（最值得记的一点）
    #     它**刚好凑对**了: `tools/doccheck.py` 用行锚定正则得 30，
    #     再**硬编码 `+1`**（"签名提示项"）也得到 31 —— 两个检查器用
    #     **两种不同的错误方式**各凑出同一个 31，于是文档 / doccheck /
    #     docclaim 三方一致却**三方都错**（自证循环）。
    #     => 静态判据之间**不能互相印证**，必须与**运行期证据**对齐。
    #   ## 形态
    #     纯函数 + 内存构造（零文件副作用）: 断言"注释形态不计入"，
    #     并断言"真实脚本的行锚定计数 == 运行期证据行数"这一更强的不变量。
    def _count_anchored(text):
        return len(re.findall(r"(?m)^\s*Check\s+'([^']+)'", text))

    def _count_naive(text):
        return len(re.findall(r"Check\s+'([^']+)'", text))

    fake_ps = (
        "Check '真项 A' { $true }\n"
        "# 于是 `Check 'X' { & $tool; $LASTEXITCODE -eq 0 }` 得到的是\n"
        "    Check '真项 B' { $true }\n"
        "  # 注释里的 Check 'Y' 也不算\n"
        "Check '真项 C' { $true }\n"
    )
    case('T7 **负向**: 注释里的 `Check \'X\'` 不得计入（锚定正则）',
         _count_anchored(fake_ps) == 3, '锚定得 %d，期望 3' % _count_anchored(fake_ps))
    case('T7 正向对照: 非锚定正则**确实**会多算（证明本用例有判别力）',
         _count_naive(fake_ps) == 5, '非锚定得 %d，期望 5' % _count_naive(fake_ps))

    # 对**真实脚本**断言: 静态项数 == 运行期 [ok] 证据行数这一不变量。
    #   运行期证据来自门禁日志（gate_log 落盘）；若无日志则跳过并**明确标注**。
    items7 = _gate_items()
    if items7 is None:
        case('T7 **负向**: 无 release_check.ps1（跳过）', True)
    else:
        case('T7 正向对照: 真实脚本无假项 X/Y（现况 %d 项）' % len(items7),
             'X' not in items7 and 'Y' not in items7,
             '仍含注释假项: %s' % [n for n in items7 if n in ('X', 'Y')])
        logs = sorted(glob.glob(_p('build', 'logs', 'release_check_*.log')))
        src = _p('tools', 'release_check.ps1')
        src_mt = os.path.getmtime(src) if os.path.isfile(src) else 0
        # 只看**已完成 PASS 轮**的日志，且拒绝"早于被测脚本"的日志。
        #   ## 为什么必须比时间戳（本项目「归档产物必须自带 prot_sections.json」同型）
        #     一份在脚本**改动之前**跑出的日志，不能作为**当前脚本**的证据 ——
        #     否则本次修复会被上一轮的旧日志判为失败（"用当前 json 校验旧构建"
        #     的镜像错误）。日志与脚本同代才可对账。
        done = []
        for lg in logs:
            lt = _read(lg, enc='utf-8') or ''
            if re.search(r'PASS:\s*(\d+)\s*项检查全通过', lt) and os.path.getmtime(lg) >= src_mt:
                done.append(lg)
        if not done:
            case('T7 不变量: 无"与当前脚本同代"的 PASS 日志可对账（未验证 != 通过）', True)
        else:
            lt = _read(done[-1], enc='utf-8') or ''
            nok = len(re.findall(r'(?m)^\[ok\]', lt))
            npass = re.findall(r'PASS:\s*(\d+)\s*项检查全通过', lt)
            case('T7 不变量: 静态项数(%d) == 运行期报告项数(%s) == 证据行数(%d)'
                 % (len(items7), npass[-1], nok),
                 len(items7) == int(npass[-1]) == nok,
                 '项数 %d / 报告 %s / [ok] 行 %d 三者不等（%s）'
                 % (len(items7), npass[-1], nok, os.path.basename(done[-1])))

    print()
    if fail:
        print('[docclaim-selftest] FAIL: %d 项' % fail)
        return 1
    print('[docclaim-selftest] PASS: 1 正向 + **5 负向** + T6 占位符判据（10 负向/正向对）'
          ' + T7 计数形态判据（注释不计入 + 静态==运行期不变量）均可自证')
    return 0


if __name__ == '__main__':
    sys.exit(main())
