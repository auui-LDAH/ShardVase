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
    t = _read(_p('tools', 'release_check.ps1'), enc='utf-8-sig')
    if t is None:
        return None
    return re.findall(r"Check\s+'([^']+)'", t)


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
    seg = t[i:i + 4000]
    rows = [l for l in seg.split('\n')
            if l.strip().startswith('|') and '---' not in l
            and not re.match(r'^\|\s*id\s*\|', l.strip())]
    unresolved = [l for l in rows
                  if '→ BLOCKED' not in l and '→ PARTIAL' not in l]
    return True, ('显式 BREACHED 表 %d 条，其中**未处置 %d 条**'
                  % (len(rows), len(unresolved)))


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

    print()
    if fail:
        print('[docclaim-selftest] FAIL: %d 项' % fail)
        return 1
    print('[docclaim-selftest] PASS: 1 正向 + **5 负向**均可自证')
    return 0


if __name__ == '__main__':
    sys.exit(main())
