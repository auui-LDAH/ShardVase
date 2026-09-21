#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/drills.py — 攻防演练记录的结构化提取与矩阵生成 (阶段 3)

依据 docs/BLUEPRINT.md §5 阶段 3 与 drills/_schema.json。

功能:
  1. extract — 从 archive/attack-drill*.json 提取记录, 归一化为 schema
               形状差异 (list-of-dict / dict-of-string) 由本工具统一处理
  2. lint    — 校验 drills/*.json 是否符合 schema (字段齐全/取值合法/
               模块名存在于 modules.json)
  3. matrix  — 生成「防御模块 × 攻击类别」对抗矩阵 (markdown)

诚实原则 (对齐项目既有纪律):
  - 无法判定的字段写 null, **不猜**
  - target_module 无法映射时写 "unmapped" 并在报告中列出, 不强行归类
  - 不计入统计的 SKIP 明确标注

用法:
    python tools/drills.py extract [--write]
    python tools/drills.py lint
    python tools/drills.py matrix [--out docs/ATTACK_MATRIX.md]
"""

import argparse
import glob
import json
import os
import re
import sys

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
ARCHIVE = os.path.join(REPO, 'archive')
DRILLS = os.path.join(REPO, 'drills')
REGISTRY = os.path.join(REPO, 'modules.json')

VALID_RESULTS = ('BLOCKED', 'PARTIAL', 'BREACHED', 'SKIP')
VALID_SEV = ('critical', 'high', 'medium', 'low', 'known-boundary')

# 归档文件分两类 (2026-09-20 诊断确认):
#   attack_drill : 攻击方视角 —— 结果为 BLOCKED/PARTIAL/BREACHED/SKIP
#   sdk_matrix   : 回归复验 —— 结果为 PASS/CHECK (断言型), **不是**攻击结论
# 二者混在一起会让矩阵失真 (把"回归通过"算成"防御挡住攻击")。
# 故分别处理: SDK 类只提取断言型记录, result 归一为 'REGRESSION'。
SEMANTIC_ATTACK = 'attack'
SEMANTIC_REGRESSION = 'regression'

# 结果串 -> 归类
RESULT_RE = re.compile(r'^\s*(BLOCKED|PARTIAL|BREACHED|SKIP)\b[:\s(]*(.*)$',
                       re.S | re.I)
REGRESSION_RE = re.compile(r'^\s*(PASS|CHECK|FAIL)\b[:\s(]*(.*)$', re.S | re.I)

# 捕获型条目后缀: '_out' / '_log' 等是执行输出快照, 不是结论条目
CAPTURE_SUFFIX = re.compile(r'_(out|log|stdout|stderr|detail)$', re.I)

# id/描述 -> 推测的目标模块 (关键词表; 不确定则 unmapped, 不猜)
# 依实测数据补充 (2026-09-20): 记录 detail 中出现的高信息量信号,
# 如 "exit=2989 (integrity)" / "static-plaintext=none" / "probe-base=...".
MODULE_HINTS = [
    ('integrity', ['integrity', 'crc', 'watchdog', 'tamper', 'text_patch',
                   'rdata', 'pdata', 'iat', '2989', '0xbad', 'exit=bad']),
    ('selfcrypt', ['selfcrypt', 'self-crypt', 'decrypt', 'plaintext',
                   'protcry', 'dump-ok', 'rva=0x']),
    ('antidebug', ['antidebug', 'debug', 'dbg', 'peb', 'scylla', 'attach',
                   'exit=0xdb', '219']),
    ('license', ['license', 'licence', 'forge', 'pubkey', 'rsa',
                 'serial', 'keygen', 'machine', 'sign', 'tier', 'expires']),
    ('revoke', ['revoke', 'blacklist', 'b1e4']),
    ('blob', ['blob', 'b10b', 'launcher']),
    ('vm', ['vm_', 'bytecode', 'opcode', 'emulat', 'reduce', 'rekey']),
    ('hostid', ['hostid', 'machine_id', 'hwid', 'host_id', 'probe-base']),
    ('dbiguard', ['dbi', 'frida', 'hook', 'inject', 'gum', 'inline_hooks',
                  'dll', 'hijack', 'loadlibrary', 'createremotethread']),    ('vmdetect', ['vmdetect', 'hypervisor', 'sandbox', 'virtual']),
    ('strcrypt', ['strcrypt', 'string', 'const-hits', 'plaintext-hits']),
    ('syscall', ['syscall', 'ssn', 'ntdll']),
    ('indirect', ['indirect', 'direct-call']),
]


def load_registry():
    with open(REGISTRY, 'r', encoding='utf-8') as f:
        return json.load(f)


def guess_module(text):
    """按关键词推测目标模块; 无把握返回 'unmapped'。

    **防过匹配** (2026-09-20 实测教训): 单纯子串匹配会把工具层攻击误归类。
    实例: drill6.V3_ledger_csv_injection 命中 'forge' (来自 "forged ledger
    rows", 指伪造台账行) 与 'inject' (CSV **injection**, 非代码注入),
    被误判为 license 模块。错误归类会让对抗矩阵撒谎, 比 unmapped 更糟。

    对策: 工具层/运维层关键词优先判定为 unmapped —— 它们不属于任何
    运行时防护模块的职责 (见 drills/_schema.json 的 uncovered_attack_surfaces)。
    """
    low = text.lower()

    # 工具层/运维层: 明确不属于运行时模块
    TOOL_LAYER = ['ledger', 'issue-log', 'csv', '台账', 'req_', 'replay',
                  'flood', 'nonce', 'toolchain']
    if any(k in low for k in TOOL_LAYER):
        return 'unmapped'

    # 代码注入类关键词需排除 "csv injection" 这类误命中
    for mod, keys in MODULE_HINTS:
        for k in keys:
            if k == 'inject' and ('csv' in low or 'ledger' in low):
                continue
            if k in low:
                return mod
    return 'unmapped'


def split_result(s):
    """'BLOCKED: xxx' -> ('BLOCKED', 'xxx'); 非攻击语义 -> (None, s)"""
    if not isinstance(s, str):
        return None, str(s)
    m = RESULT_RE.match(s)
    if not m:
        return None, s
    return m.group(1).upper(), m.group(2).strip()


def split_regression(s):
    """'PASS(拒绝)' -> ('PASS', '拒绝'); 用于 SDK 回归记录。"""
    if not isinstance(s, str):
        return None, str(s)
    m = REGRESSION_RE.match(s)
    if not m:
        return None, s
    return m.group(1).upper(), m.group(2).strip()


def guess_severity(result, detail):
    """严重度推断规则 (保守, 可解释)。"""
    d = (detail or '').lower()
    if result == 'BREACHED':
        if 'known boundary' in d or 'known-boundary' in d or 'prerequisite' in d:
            return 'known-boundary'
        return 'high'
    if result == 'PARTIAL':
        return 'medium'
    return 'low'


def classify_file(data):
    """判定归档文件的语义类别 (attack vs regression)。"""
    res = data.get('results')
    if isinstance(res, dict):
        vals = [v for v in res.values() if isinstance(v, str)]
        n_reg = sum(1 for v in vals if REGRESSION_RE.match(v))
        n_atk = sum(1 for v in vals if RESULT_RE.match(v))
        if n_reg > n_atk:
            return SEMANTIC_REGRESSION
    return SEMANTIC_ATTACK


def norm_entry(drill_id, date, key, text):
    """一条原始记录 -> schema 形状。"""
    result, detail = split_result(text)
    blob = '%s %s' % (key, detail)
    mod = guess_module(blob)
    return {
        'id': '%s.%s' % (drill_id, key),
        'attack': None,                 # 需人工细化, 不猜
        'target_module': mod,
        'method': None,                 # 需人工细化
        'prerequisite': None,
        'result': result,
        'result_detail': (detail or '')[:400],
        'severity': guess_severity(result, detail),
        'countermeasure': None,
        'known_limit': 'known boundary' in (detail or '').lower(),
        'evidence': None,               # 由调用方填 (来源文件)
        'date': date,
    }


def extract_all():
    """遍历 archive/attack-drill*.json, 按语义类别归一化。

    返回 (attack_records, regression_records)。
    两类**分开返回** —— 混算会把"回归通过"误当成"防御挡住攻击"。
    """
    attacks, regressions = [], []
    files = sorted(glob.glob(os.path.join(ARCHIVE, 'attack-drill*.json')))
    for f in files:
        try:
            d = json.load(open(f, encoding='utf-8'))
        except (OSError, ValueError) as e:
            print('drills: 跳过 %s (%s)' % (os.path.basename(f), e),
                  file=sys.stderr)
            continue
        if not isinstance(d, dict):
            continue
        name = os.path.basename(f)
        kind = classify_file(d)
        date = d.get('date') or ''
        if not date:
            m = re.search(r'(\d{8})', name)
            date = ('%s-%s-%s' % (m.group(1)[:4], m.group(1)[4:6],
                                  m.group(1)[6:8])) if m else ''
        drill_id = (d.get('drill') or name.replace('.json', '')).replace(
            'attack-drill', 'drill').replace('-', '')

        for key in ('results', 'matrix', 'breach_points'):
            v = d.get(key)
            if isinstance(v, list):
                for i, item in enumerate(v):
                    if not isinstance(item, dict):
                        continue
                    rid = item.get('id') or ('%s.%s%d' % (drill_id, key[:2], i))
                    # 关键: 把 detail 一并交给 norm_entry 做模块推断。
                    # 初版只传 item['result'] (形如 "PARTIAL"), 推断器看不到
                    # "exit=2989 (integrity)" 这类线索 -> 113/122 误判 unmapped。
                    combined = '%s %s' % (item.get('result', ''),
                                          item.get('detail', ''))
                    rec = norm_entry(drill_id, date, rid, combined)
                    if item.get('detail'):
                        rec['result_detail'] = item['detail'][:400]
                    if item.get('severity'):
                        rec['severity'] = item['severity']
                    rec['evidence'] = name
                    if rec['result']:
                        attacks.append(rec)
            elif isinstance(v, dict):
                for k, val in v.items():
                    if not isinstance(val, str):
                        continue
                    if CAPTURE_SUFFIX.search(k):
                        continue          # 执行输出快照, 非结论条目
                    if kind == SEMANTIC_REGRESSION:
                        verdict, detail = split_regression(val)
                        if verdict is None:
                            continue
                        regressions.append({
                            'id': '%s.%s' % (drill_id, k),
                            'kind': 'regression',
                            'verdict': verdict,
                            'detail': detail[:200],
                            'target': d.get('target'),
                            'evidence': name,
                            'date': date,
                        })
                    else:
                        rec = norm_entry(drill_id, date, k, val)
                        rec['evidence'] = name
                        if rec['result']:
                            attacks.append(rec)

    # 去重: 同一归档的 `matrix` 与 `breach_points` 会重叠 (实测
    # attack-drill-real-20260825-final.json 的 23+8 条中有 11 条同 id)。
    # 规则: 同 id 保留信息更全的一条 (有 severity / 更长的 detail)。
    dedup = {}
    for r in attacks:
        cur = dedup.get(r['id'])
        if cur is None:
            dedup[r['id']] = r
            continue
        better = r if (len(r.get('result_detail') or '')
                       > len(cur.get('result_detail') or '')) else cur
        dedup[r['id']] = better
    return list(dedup.values()), regressions


def cmd_extract(args):
    attacks, regressions = extract_all()
    nfiles = len(glob.glob(os.path.join(ARCHIVE, 'attack-drill*.json')))
    print('来源文件: %d 个' % nfiles)
    print()
    print('攻击记录: %d 条 (攻击方视角, 可入对抗矩阵)' % len(attacks))
    from collections import Counter
    print('  result 分布:', dict(Counter(r['result'] for r in attacks)))
    print('  severity 分布:', dict(Counter(r['severity'] for r in attacks)))
    print('  未映射模块: %d 条 (需人工细化, 不强行归类)'
          % sum(1 for r in attacks if r['target_module'] == 'unmapped'))
    print('  未分类 attack: %d 条 (schema 要求细化)'
          % sum(1 for r in attacks if not r['attack']))
    print()
    print('回归记录: %d 条 (SDK 断言型, **不计入**对抗矩阵)' % len(regressions))
    print('  verdict 分布:', dict(Counter(r['verdict'] for r in regressions)))
    if args.write:
        os.makedirs(DRILLS, exist_ok=True)
        outp = os.path.join(DRILLS, 'extracted.json')
        with open(outp, 'w', encoding='utf-8', newline='\n') as f:
            json.dump({
                '_comment': '由 tools/drills.py extract 生成。attack/method/'
                            'target_module 需人工细化为审计级记录; '
                            'regressions 为 SDK 回归断言, 不属于攻击结论。',
                'attacks': attacks,
                'regressions': regressions,
            }, f, ensure_ascii=False, indent=1)
        print()
        print('已写入 %s' % os.path.relpath(outp, REPO))
    return 0


def load_records():
    """读 drills/*.json 中的 attacks (用于矩阵); 兼容 extracted.json 结构。"""
    recs = []
    files = sorted(glob.glob(os.path.join(DRILLS, '*.json')))
    for f in files:
        if os.path.basename(f).startswith('_'):
            continue
        try:
            d = json.load(open(f, encoding='utf-8'))
        except ValueError:
            continue
        recs.extend(d.get('attacks', d.get('drills', [])))
    return recs


def cmd_lint(args):
    reg = load_registry()
    known_mods = set(reg['modules'])
    files = sorted(glob.glob(os.path.join(DRILLS, '*.json')))
    files = [f for f in files if not os.path.basename(f).startswith('_')]
    if not files:
        print('drills: %s 下无记录文件' % os.path.relpath(DRILLS, REPO))
        return 0
    schema = json.load(open(os.path.join(DRILLS, '_schema.json'),
                            encoding='utf-8'))
    required = schema['required_fields']
    taxonomy = set(schema['attack_taxonomy'])
    errors = 0
    total = 0
    for f in files:
        try:
            d = json.load(open(f, encoding='utf-8'))
        except ValueError as e:
            print('  [X] %s: JSON 无效 (%s)' % (os.path.basename(f), e))
            errors += 1
            continue
        for r in d.get('attacks', d.get('drills', [])):
            total += 1
            rid = r.get('id', '?')
            for fld in required:
                if fld not in r:
                    print('  [X] %s: 缺字段 %s' % (rid, fld))
                    errors += 1
            if r.get('result') not in VALID_RESULTS:
                print('  [X] %s: result 非法 %r' % (rid, r.get('result')))
                errors += 1
            if r.get('severity') not in VALID_SEV:
                print('  [X] %s: severity 非法 %r' % (rid, r.get('severity')))
                errors += 1
            tm = r.get('target_module')
            if tm and tm != 'unmapped' and tm not in known_mods:
                print('  [X] %s: target_module %r 不在 modules.json' % (rid, tm))
                errors += 1
            at = r.get('attack')
            if at and at not in taxonomy:
                print('  [X] %s: attack %r 不在 taxonomy' % (rid, at))
                errors += 1
    print('drills lint: %d 条攻击记录, %d 个错误' % (total, errors))
    return 1 if errors else 0


def cmd_matrix(args):
    reg = load_registry()
    mods = sorted(reg['modules'])
    recs = load_records()
    if not recs:
        print('drills: 无攻击记录, 无法生成矩阵')
        print('  先运行: python tools/drills.py extract --write')
        return 0

    print('# 攻防对抗矩阵')
    print()
    print('> 由 `tools/drills.py matrix` 从 `drills/*.json` 生成。')
    print('> 攻击记录数: %d（SDK 回归断言不计入）' % len(recs))
    print()
    print('| 模块 | BLOCKED | PARTIAL | BREACHED | SKIP | 合计 |')
    print('|------|---------|---------|----------|------|------|')
    for m in mods:
        sub = [r for r in recs if r.get('target_module') == m]
        if not sub:
            continue
        c = {k: sum(1 for r in sub if r.get('result') == k) for k in VALID_RESULTS}
        print('| `%s` | %d | %d | %d | %d | %d |'
              % (m, c['BLOCKED'], c['PARTIAL'], c['BREACHED'], c['SKIP'], len(sub)))
    un = [r for r in recs if r.get('target_module') == 'unmapped']
    if un:
        print('| *(未映射)* | %d | %d | %d | %d | %d |'
              % (sum(1 for r in un if r.get('result') == 'BLOCKED'),
                 sum(1 for r in un if r.get('result') == 'PARTIAL'),
                 sum(1 for r in un if r.get('result') == 'BREACHED'),
                 sum(1 for r in un if r.get('result') == 'SKIP'), len(un)))
    print()
    print('## 显式 BREACHED（诚实边界）')
    print()
    br = [r for r in recs if r.get('result') == 'BREACHED']
    if not br:
        print('*(无)*')
    else:
        print('| id | 模块 | 说明 | 来源 |')
        print('|----|------|------|------|')
        for r in br:
            print('| `%s` | `%s` | %s | `%s` |'
                  % (r['id'], r.get('target_module'),
                     (r.get('result_detail') or '')[:90].replace('|', '\\|'),
                     r.get('evidence')))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog='drills.py', description='攻防演练结构化')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p1 = sub.add_parser('extract', help='从 archive/ 提取并归一化')
    p1.add_argument('--write', action='store_true', help='写入 drills/extracted.json')
    sub.add_parser('lint', help='校验 drills/*.json 符合 schema')
    p3 = sub.add_parser('matrix', help='生成对抗矩阵')
    p3.add_argument('--out', help='写入文件 (默认 stdout)')
    args = ap.parse_args(argv)

    if args.cmd == 'extract':
        return cmd_extract(args)
    if args.cmd == 'lint':
        return cmd_lint(args)
    if args.cmd == 'matrix':
        if args.out:
            import io
            buf = io.StringIO()
            old = sys.stdout
            sys.stdout = buf
            try:
                cmd_matrix(args)
            finally:
                sys.stdout = old
            with open(os.path.join(REPO, args.out), 'w', encoding='utf-8',
                      newline='\n') as f:
                f.write(buf.getvalue())
            print('已写入 %s' % args.out)
            return 0
        return cmd_matrix(args)
    return 0


if __name__ == '__main__':
    sys.exit(main())
