#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
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

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


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


def load_doc_tables():
    """从 docs/ATTACK_DRILL*.md 的矩阵表格提取权威 attack/method 字段。

    为什么这样做 (阶段3 剩余项): 归档 JSON 只存 id/result/detail, 不含
    攻击手法描述 —— 111/125 条记录的 attack/method 为 None。

    但演练**文档**里有结构化表格 (ID | 攻击 | 工具/手法 | 预期 | ...),
    这就是权威来源。从文档提取是**证据驱动填充**, 不是猜:
    字段值直接来自演练记录原文。

    返回 {record_id: {'attack_desc':..., 'method_desc':..., 'evidence':...}}
    """
    out = {}
    for f in sorted(glob.glob(os.path.join(REPO, 'docs', 'ATTACK_DRILL*.md'))):
        base = os.path.basename(f)
        try:
            lines = open(f, encoding='utf-8').read().split('\n')
        except OSError:
            continue
        cols = None
        for i, l in enumerate(lines):
            if not l.strip().startswith('|'):
                cols = None
                continue
            cells = [c.strip() for c in l.strip().strip('|').split('|')]
            if any(c in ('ID', '**ID**') for c in cells):
                cols = cells
                continue
            if cols and all(re.fullmatch(r':?-{2,}:?', c) for c in cells if c):
                continue                          # 分隔行
            if cols and len(cells) >= 3:
                # 两种表格形态 (实测):
                #  A) ID 独立成列:  | ID | 攻击 | 工具/手法 | 预期 |
                #  B) ID 内嵌首格:  | **R1-4 VM 模拟器还原** | <攻击> | <工具> | 预期 |
                #     (ATTACK_DRILL4/5 用此形态, 首格 = "**<ID> <描述>**")
                rid = re.sub(r'\*+', '', cells[0]).strip()
                inline_desc = None
                if not re.match(r'^[A-Za-z]{1,3}\d+[a-z]?$', rid):
                    # 形态 B: 从首格提取 "<ID> <描述>"
                    mb = re.match(r'^([A-Za-z]{1,3}\d+[a-z]?(?:-\d+)?)\s+(.+)$', rid)
                    if not mb:
                        continue
                    rid, inline_desc = mb.group(1), mb.group(2).strip()
                    # 形态 B 的列语义右移一位: 攻击/工具 用了表头里的名字
                    cols_b = ['ID', '攻击', '工具/手法', '预期'][:len(cells)]
                    row = dict(zip(cols_b, cells))
                    # 首格自身即"攻击"描述 (含 ID + 手法名)
                    row['攻击'] = inline_desc
                else:
                    row = dict(zip(cols, cells))

                def pick(*names):
                    for n in names:
                        v = row.get(n)
                        if v and v not in ('-', '—'):
                            return re.sub(r'\*+', '', v).strip()
                    return None

                out.setdefault(rid, {
                    'attack_desc': pick('攻击', '攻击手法') or inline_desc,
                    'method_desc': pick('工具/手法', '工具'),
                    'expect_desc': pick('预期', '预期防御', '验收'),
                    'evidence': '%s:%d' % (base, i + 1),
                })
    return out


def load_doc_categories():
    """从 docs/ATTACK_DRILL*.md 的**小节标题**推断每条记录的 attack 类别。

    依据: 文档把记录按前缀分节, 节标题直接写明类别, 例如
      ### R 还原类（VM 保护天敌）      -> vm_reverse
      ### P — 补丁攻击类（改关键判定）  -> patch_data
      ### L 授权文件（license.txt）     -> license_forge

    关键: 前缀**跨文档含义不同** (实测: drill1 的 F=伪造, drill4 的 F=取证),
    故映射必须 (文档, 前缀) 二元组, 不能只用前缀。

    无法确定的一律不填 (None) —— 不猜。
    """
    # (文档正则, 前缀) -> taxonomy 类别
    # 每条依据: 该文档对应小节的标题原文 (见实现下方注释)
    RULES = [
        # --- ATTACK_DRILL.md (第一轮) ---
        (r'ATTACK_DRILL\.md$', 'D', 'memory_dump'),        # dump/还原类（抓引擎）
        (r'ATTACK_DRILL\.md$', 'E', 'patch_data'),         # 环境对抗类（绕过检测）
        (r'ATTACK_DRILL\.md$', 'F', 'license_forge'),      # 伪造攻击类（造合法凭证）
        (r'ATTACK_DRILL\.md$', 'P', 'patch_data'),         # 补丁攻击类（改关键判定）
        (r'ATTACK_DRILL\.md$', 'S', 'symbol_resolution'),  # 静态分析类（找目标）
        # --- ATTACK_DRILL2/3 (深化 + 组合链) ---
        (r'ATTACK_DRILL[23]\.md$', 'D', 'memory_dump'),
        (r'ATTACK_DRILL[23]\.md$', 'P', 'patch_data'),
        (r'ATTACK_DRILL[23]\.md$', 'E', 'patch_data'),
        (r'ATTACK_DRILL3\.md$', 'C', 'injection'),         # 组合攻击链 (注入→hook→patch)
        (r'ATTACK_DRILL3\.md$', 'R', 'toolchain_abuse'),   # G2 可绕过性 (IAT/hook 链)
        # --- ATTACK_DRILL4 (还原/取证/隐蔽/在线) ---
        (r'ATTACK_DRILL4\.md$', 'R', 'vm_reverse'),        # R 还原类（VM 保护天敌）
        (r'ATTACK_DRILL4\.md$', 'F', 'memory_dump'),       # F 取证类（完整转储）
        (r'ATTACK_DRILL4\.md$', 'H', 'watchdog_evasion'),  # H 隐蔽类（绕过检测）
        (r'ATTACK_DRILL4\.md$', 'O', 'collection_channel'),  # O 在线类（补充）
        # --- ATTACK_DRILL5 (DLL 劫持 + VEH) ---
        (r'ATTACK_DRILL5\.md$', 'D', 'toolchain_abuse'),   # DLL 劫持
        (r'ATTACK_DRILL5\.md$', 'V', 'toolchain_abuse'),   # VEH
        # --- ATTACK_DRILL6 (签发链路) ---
        (r'ATTACK_DRILL6\.md$', 'S', 'license_forge'),     # S 签发端
        (r'ATTACK_DRILL6\.md$', 'L', 'license_forge'),     # L 授权文件
        (r'ATTACK_DRILL6\.md$', 'V', 'toolchain_abuse'),   # V 验证/工具链
        (r'ATTACK_DRILL6\.md$', 'T', 'clock_manipulation'),  # T 时序类
        (r'ATTACK_DRILL6\.md$', 'D', 'toolchain_abuse'),   # D 防御候选方向
        # --- ATTACK_DRILL7 (符号表解析) ---
        (r'ATTACK_DRILL7\.md$', 'S', 'symbol_resolution'),
    ]

    out = {}          # rid -> (category, evidence)
    for f in sorted(glob.glob(os.path.join(REPO, 'docs', 'ATTACK_DRILL*.md'))):
        base = os.path.basename(f)
        try:
            lines = open(f, encoding='utf-8').read().split('\n')
        except OSError:
            continue
        cur_cat = None
        cur_pre = None
        for i, l in enumerate(lines, 1):
            # 小节标题: ### R 还原类（...） / ### P — 补丁攻击类（...）
            mh = re.match(r'^###\s+([A-Z]{1,2})\b', l)
            if mh:
                pre = mh.group(1)
                cur_cat = None
                for pat, p, cat in RULES:
                    if p == pre and re.search(pat, base):
                        cur_cat = cat
                        break
                cur_pre = pre
                continue
            # 新的一级/二级标题 -> 离开当前小节
            if re.match(r'^#{1,2}\s', l):
                cur_cat = None
                continue
            if not cur_cat:
                continue
            # 表格数据行的 id
            if l.strip().startswith('|'):
                cells = [c.strip() for c in l.strip().strip('|').split('|')]
                if not cells:
                    continue
                rid = re.sub(r'\*+', '', cells[0]).strip()
                mm = re.match(r'^([A-Za-z]{1,3}\d+[a-z]?(?:-\d+)?)', rid)
                if mm:
                    out.setdefault(mm.group(1),
                                   (cur_cat, '%s:%d' % (base, i)))
    return out


def norm_entry(drill_id, date, key, text, doc_tables=None, doc_cats=None):
    """一条原始记录 -> schema 形状。

    doc_tables: load_doc_tables() 的结果。命中时用文档原文填充
    attack/method (证据驱动); 未命中则保持 None (**不猜**)。
    """
    result, detail = split_result(text)
    blob = '%s %s' % (key, detail)
    mod = guess_module(blob)

    dt = (doc_tables or {}).get(key) or {}
    # 后缀轮次 id (如 P4-2 / E1-2 / D3-2) 在文档里记为基 id (P4/E1/D3) ——
    # "-N" 表示"第 N 轮对该项做的深化"。剥离后缀再查一次可显著提升填充率,
    # 且语义正确 (同一攻击项的深化演练)。
    if not dt:
        base = re.sub(r'-\d+$', '', key)
        if base != key:
            dt = (doc_tables or {}).get(base) or {}
    method = dt.get('method_desc')
    attack_desc = dt.get('attack_desc')
    # method 优先用文档的"工具/手法"; 若同一 id 在多个轮的文档里出现,
    # 取第一个 (load_doc_tables 已 setdefault 保序)。
    evidence = dt.get('evidence')

    # attack 类别: 来自文档**小节标题**的类别归属 (证据驱动)。
    cat = (doc_cats or {}).get(key)
    if not cat:
        base = re.sub(r'-\d+$', '', key)
        if base != key:
            cat = (doc_cats or {}).get(base)
    attack = cat[0] if cat else None
    if cat and not evidence:
        evidence = cat[1]

    return {
        'id': '%s.%s' % (drill_id, key),
        # attack = 11 类 taxonomy 枚举, 由文档小节标题推断 (非猜测)。
        # 推断不出则 None —— 宁可留空也不误分类。
        'attack': attack,
        'attack_desc': attack_desc,      # 文档原文 (自然语言, 供人读)
        'target_module': mod,
        'method': method or attack_desc,  # 文档原文; 无则 None (不猜)
        'prerequisite': None,
        'result': result,
        'result_detail': (detail or '')[:400],
        'severity': guess_severity(result, detail),
        'countermeasure': None,
        'known_limit': 'known boundary' in (detail or '').lower(),
        'evidence': evidence,
        'date': date,
    }


def extract_all():
    """遍历 archive/attack-drill*.json, 按语义类别归一化。

    返回 (attack_records, regression_records)。
    两类**分开返回** —— 混算会把"回归通过"误当成"防御挡住攻击"。
    """
    attacks, regressions = [], []
    doc_tables = load_doc_tables()
    doc_cats = load_doc_categories()
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
                    rec = norm_entry(drill_id, date, rid, combined, doc_tables,
                                     doc_cats)
                    if item.get('detail'):
                        rec['result_detail'] = item['detail'][:400]
                    if item.get('severity'):
                        rec['severity'] = item['severity']
                    # evidence: 文档表格来源优先 (更可追溯); 否则归档文件名
                    if not rec.get('evidence'):
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
