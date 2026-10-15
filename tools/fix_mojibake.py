#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""fix_mojibake.py — 逐行修复源码里的 mojibake（UTF-8 字节被按 CP936 解码的产物）。

## 为什么不是"整文件 GBK 往返"

目标文件里无损行与有损行**混排**，且部分行内又混有**本来正确**的中文
（例如 `docs/迁移核验-2026-09-20.md:309` 的 `... (revoke.blob)\\n"); /* 修复前 */`）。
整文件往返会把正确的中文一起打碎。

## 损坏模型（权威定义在 `tools/mojibake.py`）

`.NET CP936` 解码器遇到无效双字节对时**固定吃 2 字节**并吐 `?`(0x3F)；
**行尾的孤立字节连换行一起吞掉** —— 于是两行、三行甚至更多行会被**并成一行**。
因此单行 `fix_line` 只能修"字节未受损"的行；被吞掉标点/空格/换行的行必须
**三源对证**（该文件全修订 + mirror 全修订 + 全工作区 + 显式候选）。

## 三种独立证明（每条替换都必须来自其中之一）

| 模式 | 证明 |
|------|------|
| `RESTORE` | 无损行自证: 反查后无 U+FFFD，且 `damage(new) == cur`（逆变换唯一） |
| `REF` | 行池对证: 在"全修订 + mirror + 全工作区"里找到 `damage(ref) == cur` |
| `SPLIT` | 换行被吃: 相邻 k 行使 `damage(a+'\\n'+...+b) == cur`，修复即展开为 k 行 |
| `CAND` | 候选表: 从无干净修订的行用显式候选，**逐条硬验证** `damage(c) == cur`，不成立即拒绝 |

用法:
    python tools/fix_mojibake.py --report     # 只报告（默认）
    python tools/fix_mojibake.py --apply      # 写回 + 复扫验证
"""
import argparse
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, 'tools'))
import mojibake as M  # noqa: E402

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

MIRROR = {
    'prot_sdk/skeleton/app_main.c': 'demo/main.c',
    'demo/main.c': 'prot_sdk/skeleton/app_main.c',
}

# 实修目标。**不在其中**的三个文件:
#   docs/迁移核验-2026-09-20.md — 修复前后对照的**证据引用**（故意保留）
#   docs/CONTINUATION_PLAN.md   — 计划文档 §2.3 的**示意**还原文本
#   tools/mojibake.py           — 自检夹具由 `damage()` 现算，已无乱码字面量
TARGETS = [
    'prot_sdk/skeleton/app_main.c',
    'demo/main.c',
    'src/crc32.c',
    'tests/c2vasm_cases/poly.c',
    'tests/c2vasm_cases/cond_agg.c',
    'tests/c2vasm_cases/fnv1a64.c',
]

EXD = {'dist', 'archive', '.git', 'build', 'node_modules', '.vs', '.vscode'}
EXT = {'.c', '.h', '.md', '.py', '.ps1', '.json', '.txt', '.s',
       '.asm', '.yml', '.yaml', '.def'}

MAXLEN = 6      # 最长"被并成一行"的原始行数（实测最多 4，留余量）

# 从无干净修订的行: 候选来自兄弟文件范式与 docs/CONTRACT.md。
# 每条都在 `solve()` 里经 damage() 硬验证，不成立则整个工具报错退出。
CANDIDATES = {
    ('prot_sdk/skeleton/app_main.c', 496): [
        '    const char* g_vmblob_path = NULL; /* A2 phase2: 函数级 blob 路径 (尾部业务装载用) */',
    ],
}


def git(*a):
    return subprocess.run(['git'] + list(a), cwd=REPO, capture_output=True,
                          text=True, encoding='utf-8').stdout


def blob(rev, path):
    r = subprocess.run(['git', 'show', '%s:%s' % (rev, path)], cwd=REPO,
                       capture_output=True, text=True, encoding='utf-8')
    return r.stdout.replace('\r\n', '\n').split('\n') if r.returncode == 0 else []


def build_pools():
    """行池 + 相邻 k 元组池。元组是**真正相邻**的序列切片，不是任意组合。"""
    P, multi, seqs = {}, {}, []

    def add_seq(lines):
        if lines:
            seqs.append(lines)
            for l in lines:
                if not l:
                    continue
                k = M.damage(l)
                if k in P and P[k] != l:
                    multi.setdefault(k, {P[k]}).add(l)
                P.setdefault(k, l)

    for path in list(TARGETS) + list(MIRROR.values()):
        for r in git('rev-list', 'HEAD', '--', path).split():
            add_seq(blob(r, path))
    for root, d, fs in os.walk(REPO):
        d[:] = [x for x in d if x not in EXD]
        for f in fs:
            if os.path.splitext(f)[1].lower() not in EXT:
                continue
            try:
                t = open(os.path.join(root, f), encoding='utf-8').read()
            except (UnicodeDecodeError, OSError):
                continue
            add_seq(t.replace('\r\n', '\n').split('\n'))
    return P, multi, seqs


def solve(path, ln, cur, P, seqs):
    """返回 (证明模式, 替换内容) 或 None。替换内容可含 '\\n'（展开 k 行）。"""
    if (path, ln) in CANDIDATES:
        for c in CANDIDATES[(path, ln)]:
            if M.damage(c) == cur:
                return 'CAND', c
        raise SystemExit('[fix_mojibake] 候选未通过等式验证: %s:%d\n  %s' % (path, ln, cur))

    # 1) 单行自证 / 行池
    raw, lost = M.encode_cp936(cur)
    if not lost:
        new = raw.decode('utf-8', 'replace')
        if M.damage(new) == cur:
            return 'RESTORE', new
    if cur in P:
        return 'REF', P[cur]

    # 2) k 行合并（k = 2..MAXLEN），沿**真正相邻**的滑窗
    for lines in seqs:
        n = len(lines)
        for i in range(n):
            if any(M.is_bad(lines[j]) for j in range(i, min(i + MAXLEN, n))):
                continue
            for k in range(2, min(MAXLEN, n - i) + 1):
                tup = lines[i:i + k]
                if not all(t.strip() for t in tup):
                    continue
                if M.damage('\n'.join(tup)) == cur:
                    return 'SPLIT', '\n'.join(tup)
    return None


def main():
    ap = argparse.ArgumentParser(prog='fix_mojibake.py')
    ap.add_argument('--apply', action='store_true', help='写回文件（默认只报告）')
    ap.add_argument('--report', action='store_true',
                    help='只报告（默认行为；保留此开关以兼容旧调用）')
    a = ap.parse_args()

    P, multi, seqs = build_pools()
    print('[fix_mojibake] 行池 %d 行 / 序列 %d 条' % (len(P), len(seqs)))

    total = unsolved = 0
    plan = {}
    for path in TARGETS:
        full = os.path.join(REPO, path)
        text = open(full, encoding='utf-8').read()
        for ln, cur in enumerate(text.replace('\r\n', '\n').split('\n'), 1):
            if not M.is_bad(cur):
                continue
            total += 1
            r = solve(path, ln, cur, P, seqs)
            if r is None:
                unsolved += 1
                print('  [未决] %s:%d  %s' % (path, ln, cur.strip()[:90]))
                continue
            mode, new = r
            plan.setdefault(path, []).append((ln, mode, cur, new))
            amb = ' (多解 %d)' % len(multi[cur]) if cur in multi else ''
            print('  [%s] %s:%d%s' % (mode, path, ln, amb))
            for i, s in enumerate(new.split('\n')):
                print('        %s %s' % ('->' if i == 0 else '  ', s.strip()[:88]))

    print('-' * 96)
    print('坏行 %d | 已证明 %d | 未决 %d' % (total, total - unsolved, unsolved))
    if unsolved:
        print('有未决行 —— 拒绝写回。')
        return 1
    if not a.apply:
        print('（report 模式；加 --apply 写回）')
        return 0

    for path, items in plan.items():
        full = os.path.join(REPO, path)
        raw = open(full, 'rb').read()
        # BOM **按原样保留**: 本项目有 7 个 tracked .c/.h 自带 BOM（含 src/crc32.c）。
        # 工具的职责是**不改动编码形态** —— 有就留，没有就不加。
        bom = b'\xef\xbb\xbf' if raw.startswith(b'\xef\xbb\xbf') else b''
        parts = raw[len(bom):].decode('utf-8').split('\n')
        # ⚠️ **换行风格也必须按原样保留**: 本仓库 `.gitattributes` 声明
        #   `*.c text eol=lf`，但工作区的行尾风格**不一定**与之一致
        #   （Q1 首轮写回时，3 个 c2vasm 文件在 EOF 处留下了孤立 CRLF，
        #    git 持续告警 "CRLF will be replaced by LF"）。
        #   这里的 `cr` 逐行保留原有 \r —— 不新增、不删除。
        #   规范行尾是**独立的**一步（见 build/_q1_normalize_eol.py），
        #   不能混进修复流程，否则 diff 会同时含有"修字"与"改行尾"两种改动，
        #   无法逐条审阅。
        # **必须倒序**: SPLIT 把 1 行展开为 k 行，正序处理会让后续行号错位。
        for ln, mode, cur, new in sorted(items, key=lambda x: -x[0]):
            el = parts[ln - 1]
            cr = '\r' if el.endswith('\r') else ''
            if el != cur + cr:
                raise SystemExit('[fix_mojibake] %s:%d 行内容不符，拒绝改' % (path, ln))
            parts[ln - 1] = new + cr
        open(full, 'wb').write(bom + '\n'.join(parts).encode('utf-8'))
        print('[written] %s  %d 行%s'
              % (path, len(items), '（保留原有 BOM）' if bom else ''))

    print('-' * 96)
    bad_left = 0
    for path in TARGETS:
        t = open(os.path.join(REPO, path), encoding='utf-8').read().replace('\r\n', '\n')
        n = sum(1 for l in t.split('\n') if M.is_bad(l))
        bad_left += n
        print('  复扫 %-40s 坏行 %d' % (path, n))
    print('复扫合计 = %d %s' % (bad_left, '(期望 0)' if not bad_left else '(!! 仍有残留)'))
    return 0 if bad_left == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
