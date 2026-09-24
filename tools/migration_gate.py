#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""migration_gate.py — 迁移成本门禁（W5.7）

## 目的
  W1.6 把"保护函数特征命中率"（M3）从 **55.9% 降到 5.9%**。
  本工具把该指标固化为**门禁判据**，防止未来改动让它**回退**。

## 为什么需要（历史依据）
  门禁曾因 PowerShell 数组恒真而 **7/13 项失效** —— 一个只会通过的检查器
  比没有更危险。反之，**没有检查器的指标会悄悄退化**：
  W5.6 之前，M3 的 55.9% 无人知晓，直到专门度量才发现。

## 度量方法
  用**固定**的两个种子表 + 固定 salt 构建两次（确定性），
  再跑 `tools/migration_cost.py`。实测 3 轮完全可复现（极差 0.0）。

## 阈值（实测标定）
  | 指标 | 无注入基线 | 当前 | 阈值 |
  |------|-----------|------|------|
  | **M3 保护函数命中** | 55.9% | **5.9%** | **<= 25%** |
  | M1 地址复用率 | — | 1.1% | <= 25% |

  阈值留了余量（25% vs 实测 5.9%），避免抖动误报；
  但若**回退到无注入状态**（55.9%）必被抓。

用法:
  python tools/migration_gate.py            # 跑度量 + 判定
  python tools/migration_gate.py --selftest  # 负向测试
  python tools/migration_gate.py --quiet
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable

# 阈值（实测标定，见文件头）
#
# ⚠️ **阈值收紧过一次**（2026-09-23 反向验证发现）:
#   初版取 25%，只能抓住"完全移除注入"（55.9%），
#   而**禁用 6/16 文件的部分移除**只让 M3 升到 **20.6%** -> 仍在阈值内 -> 漏检。
#
# 实测已知点:
#   · 全部注入   -> **5.9%**（3 轮完全可复现，极差 0.0）
#   · 移除 6/16  -> **20.6%**
#   · 无注入     -> **55.9%**
#
# 故取 **12%**: 高于 5.9%（含 6.1 个百分点余量，实测极差 0.0 故安全），
# 明显低于 20.6% -> **部分移除也会被抓**。
MAX_M3 = 12.0      # 保护函数特征命中率上限（%）
MAX_M1 = 12.0      # 地址复用率上限（%）


def _seed_files(tmp):
    """造两个**内容不同**的种子表（派生不同种子）。"""
    a = os.path.join(tmp, 'seedA.json')
    b = os.path.join(tmp, 'seedB.json')
    json.dump({'tag': 'A'}, open(a, 'w'))
    json.dump({'tag': 'B'}, open(b, 'w'))
    return a, b


def _build(seedfile, salt, out_dir, tag):
    env = dict(os.environ)
    env['PROT_BUILD_SALT'] = salt
    subprocess.run(['powershell', '-ExecutionPolicy', 'Bypass', '-File',
                    'build.ps1', '-Config', 'Release', '-SkipSmoke',
                    '-SkipSign', '-Composition', 'full',
                    '-SeedsFile', seedfile],
                   capture_output=True, cwd=REPO, env=env)
    ok = False
    for src, nm in [('build/demo.exe', tag + '.exe'),
                    ('build/demo.map', tag + '.map')]:
        s = os.path.join(REPO, src)
        if os.path.exists(s):
            shutil.copy2(s, os.path.join(out_dir, nm))
            ok = True
    return ok


def measure(quiet=False):
    """返回 (m3_rate, m1_rate, detail) 或 (None, None, 原因)。"""
    tmp = tempfile.mkdtemp(prefix='miggate_')
    try:
        sa, sb = _seed_files(tmp)
        if not _build(sa, '0x11111111', tmp, 'A'):
            return None, None, '构建 A 失败'
        if not _build(sb, '0xAAAAAAAA', tmp, 'B'):
            return None, None, '构建 B 失败'
        r = subprocess.run([PY, '-X', 'utf8',
                            os.path.join(REPO, 'tools', 'migration_cost.py'),
                            os.path.join(tmp, 'A.exe'),
                            os.path.join(tmp, 'B.exe'),
                            '--map-a', os.path.join(tmp, 'A.map'),
                            '--map-b', os.path.join(tmp, 'B.map')],
                           capture_output=True, cwd=REPO)
        o = (r.stdout + r.stderr).decode('utf-8', 'replace')
        m3 = re.search(r'保护函数命中: (\d+) / (\d+) \(([\d.]+)%\)', o)
        m1 = re.search(r'硬编码地址可复用率: ([\d.]+)%', o)
        if not m3 or not m1:
            return None, None, '度量解析失败'
        if not quiet:
            print('  M3 保护函数特征命中: %s/%s (%s%%)'
                  % (m3.group(1), m3.group(2), m3.group(3)))
            print('  M1 地址复用率:       %s%%' % m1.group(1))
        return float(m3.group(3)), float(m1.group(1)), o
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def selftest():
    """负向测试: 阈值判定必须能抓错。

    纪律（来自门禁失效教训）: **每个检查器必须自证能抓错。**
    """
    fails = []

    def case(name, got, want):
        ok = got == want
        print('  %s %-44s got=%s want=%s'
              % ('ok ' if ok else '**FAIL**', name, got, want))
        if not ok:
            fails.append(name)

    print('=== 阈值判定 ===')
    case('5.9%% <= 12%% -> 通过（全注入）', 5.9 <= MAX_M3, True)
    case('20.6%% <= 12%% -> **失败**（部分移除被抓）', 20.6 <= MAX_M3, False)
    case('55.9%% <= 12%% -> **失败**（完全移除被抓）', 55.9 <= MAX_M3, False)
    case('12.0%% <= 12%% -> 通过（边界）', 12.0 <= MAX_M3, True)
    case('12.1%% <= 12%% -> 失败（边界外）', 12.1 <= MAX_M3, False)
    case('0%% <= 12%% -> 通过', 0.0 <= MAX_M3, True)

    print()
    print('=== 正则解析（度量输出格式）===')
    sample = ('--- M3 特征可匹配性（最关键）---\n'
              '  函数特征在 B 中命中: 491 / 1049 (46.8%)\n'
              '  **保护函数命中: 2 / 34 (5.9%)**\n')
    m = re.search(r'保护函数命中: (\d+) / (\d+) \(([\d.]+)%\)', sample)
    case('能解析 M3', bool(m), True)
    case('M3 命中数 = 2', int(m.group(1)) if m else -1, 2)
    case('M3 总数 = 34', int(m.group(2)) if m else -1, 34)
    case('M3 比率 = 5.9', float(m.group(3)) if m else -1, 5.9)

    sample2 = '  -> 硬编码地址可复用率: 1.1%\n'
    m1 = re.search(r'硬编码地址可复用率: ([\d.]+)%', sample2)
    case('能解析 M1', bool(m1), True)
    case('M1 = 1.1', float(m1.group(1)) if m1 else -1, 1.1)

    print()
    print('=== 畸形输入不崩溃 ===')
    case('空串不匹配', bool(re.search(r'保护函数命中: (\d+)', '')), False)

    print()
    print('=' * 64)
    if fails:
        print('[migration_gate-selftest] FAIL: %d 项 -> %s'
              % (len(fails), '; '.join(fails)))
        return 1
    print('[migration_gate-selftest] PASS: 阈值判定可自证能抓错')
    return 0


def main():
    ap = argparse.ArgumentParser(prog='migration_gate.py')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    if not args.quiet:
        print('=== 迁移成本门禁 ===')
        print('  阈值: M3 <= %.0f%%, M1 <= %.0f%%' % (MAX_M3, MAX_M1))
        print('  方法: 两次构建（异种子+异salt）+ migration_cost 度量')
        print()

    m3, m1, detail = measure(quiet=args.quiet)
    if m3 is None:
        print('[migration_gate] FAIL: %s' % detail, file=sys.stderr)
        return 1

    bad = []
    if m3 > MAX_M3:
        bad.append('M3 %.1f%% > %.0f%%（保护函数可被特征定位 -> 迁移成本低）'
                   % (m3, MAX_M3))
    if m1 > MAX_M1:
        bad.append('M1 %.1f%% > %.0f%%（硬编码地址可复用）' % (m1, MAX_M1))

    if bad:
        for b in bad:
            print('[migration_gate] FAIL: %s' % b)
        return 1
    print('[migration_gate] PASS: M3=%.1f%% M1=%.1f%%（迁移成本可接受）'
          % (m3, m1))
    return 0


if __name__ == '__main__':
    sys.exit(main())
