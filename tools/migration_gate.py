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
  | 指标 | 无注入基线 | 全注入 | 阈值 |
  |------|-----------|--------|------|
  | **M3 保护函数命中** | 55.9% | 5.9% | **<= 12%** |
  | M1 地址复用率 | — | 1.1% | <= 12% |

  阈值 **12%**，不是初版的 25%。2026-09-23 反向验证发现 25% 会漏检：
  「禁用 6/16 文件的部分移除」只让 M3 升到 **20.6%**，仍在 25% 内。
  实测标定点 —— 全部注入 5.9% / 移除 6/16 20.6% / 无注入 55.9% ⇒ 取 12%。
  余量 = 12% vs 5.9%（全注入），而 20.6% / 55.9% 两个已知劣化点都在阈值外。

  ⚠️ **实测抖动（2026-10-06 记）**：同一份代码，本机 MSVC 14.44.35207 实测
  M3 = **15.6%**（FAIL），CI MSVC 14.51.36231 实测 **6.2%**（PASS）。
  机制已查明（见 docs/HANDOVER.md §2.43）：M3 只在函数入口起 32 字节内取特征，
  而 `PROT_PAD_*` 位置抖动落在序言之后 ⇒ 判据窗口与随机化落点相距很近，
  工具链改变序言长度就会把结果推到阈值两侧。**这是阈值附近的抖动敏感，
  不是防护能力差异**；六条判据（`--selftest`）覆盖的是阈值判定逻辑本身。

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

# ---------------------------------------------------------------------------
# 隐藏窗口（2026-09-25）
#
# Windows 上从 Python 启动控制台程序（powershell/cmd/wsl/cl）会**弹出黑窗**。
# 统一用 tools/winproc.py 封装（CREATE_NO_WINDOW + STARTUPINFO/SW_HIDE）。
#
# **为什么统一封装**: 实测本项目约 60 处调用都无隐藏措施；
#   一处修好 = 全部修好，且可自检（见 winproc.py 的 --selftest）。
#
# 路径推导: 从本文件位置向上找含 tools/winproc.py 的目录。
# ---------------------------------------------------------------------------
import os as _os_hw
import sys as _sys_hw


def _hw_tools_dir():
    d = _os_hw.path.dirname(_os_hw.path.abspath(__file__))
    for _ in range(4):
        cand = _os_hw.path.join(d, 'tools')
        if _os_hw.path.isfile(_os_hw.path.join(cand, 'winproc.py')):
            return cand
        d = _os_hw.path.dirname(d)
    return None


_hw_tools = _hw_tools_dir()
if _hw_tools and _hw_tools not in _sys_hw.path:
    _sys_hw.path.insert(0, _hw_tools)
import winproc  # noqa: E402


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
    winproc.run(['powershell', '-ExecutionPolicy', 'Bypass', '-File',
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
    """多次（3 对）测量 M1/M3，取**中位数**（2026-09-25 稳健性修正）。

    ## 为什么从"单对"改为"多对取中位数"
      实测 4 对（8 次构建）: M1 = 47.3% / 0.0% / 7.8% / 0.0%
        · 47.3% 那一对: **两构建的 `vm.c` 同为末位**（概率 ~0.2% 的
          同位巧合）-> `vm.c` 的 55/129 个函数地址全部相同 -> 虚高
      **单对测量对巧合过敏** -> 门禁会**误判**。
      => 与 P5 教训同类（单样本判据 + 巧合 = 不可靠）。
      修法: **3 对取中位数**（对离群稳健），**阈值不变**（12%）。

    ## 诚实边界
      · 构建次数 2 -> 6（门禁变慢，换来可信判定）
      · 若多数对都超阈值 -> 中位数如实反映（不掩盖真实问题）
    """
    import statistics

    pairs = []
    detail_last = ''
    tmp = tempfile.mkdtemp(prefix='miggate_')
    try:
        for k in range(3):
            sa = os.path.join(tmp, 'seedA%d.json' % k)
            sb = os.path.join(tmp, 'seedB%d.json' % k)
            json.dump({'tag': 'A%d' % k}, open(sa, 'w'))
            json.dump({'tag': 'B%d' % k}, open(sb, 'w'))
            salt_a = '0x%08X' % (0x11111111 * (k + 1) & 0xFFFFFFFF)
            salt_b = '0x%08X' % (0xAAAAAAAA * (k + 1) & 0xFFFFFFFF)
            if not _build(sa, salt_a, tmp, 'A%d' % k):
                return None, None, '构建 A%d 失败' % k
            if not _build(sb, salt_b, tmp, 'B%d' % k):
                return None, None, '构建 B%d 失败' % k
            r = winproc.run(
                [PY, '-X', 'utf8',
                 os.path.join(REPO, 'tools', 'migration_cost.py'),
                 os.path.join(tmp, 'A%d.exe' % k),
                 os.path.join(tmp, 'B%d.exe' % k),
                 '--map-a', os.path.join(tmp, 'A%d.map' % k),
                 '--map-b', os.path.join(tmp, 'B%d.map' % k)],
                capture_output=True, cwd=REPO)
            o = (r.stdout + r.stderr).decode('utf-8', 'replace')
            m3 = re.search(r'保护函数命中: (\d+) / (\d+) \(([\d.]+)%\)', o)
            m1 = re.search(
                r'硬编码地址可复用率\(函数, 门禁口径\): ([\d.]+)%', o)
            if not m1:
                m1 = re.search(r'硬编码地址可复用率: ([\d.]+)%', o)
            if not m3 or not m1:
                return None, None, '度量解析失败'
            pairs.append((float(m3.group(3)), float(m1.group(1))))
            detail_last = o
            if not quiet:
                print('  第 %d 对: M3=%5.1f%%  M1=%5.1f%%'
                      % (k + 1, float(m3.group(3)), float(m1.group(1))))
        m1_med = statistics.median([p[1] for p in pairs])
        m3_med = statistics.median([p[0] for p in pairs])
        if not quiet:
            print('  -> 中位数（3 对）: M3=%.1f%%  M1=%.1f%%'
                  % (m3_med, m1_med))
            # ⚠️ M3adv 是**诊断**不是判据（见文件头）：如实报告判据 M3 的
            #    诚实边界 —— 攻击者自选窗口时能定位多少。不参与 PASS/FAIL。
            a = re.search(r'对抗口径（自选窗口）\s*: (\d+) / (\d+) \(([\d.]+)%\)',
                          detail_last)
            if a:
                print('  ⚠️ 诊断 M3adv（自选窗口 + 唯一签名）: %s / %s (%.1f%%)'
                      % (a.group(1), a.group(2), float(a.group(3))))
                print('     这是判据 M3 的**诚实边界**: 攻击者不必从入口取特征。'
                      '把 M3 判据窗口收紧**不改变** M3adv（对抗口径不受判据约束）。')
        # ⚠️ 返回顺序必须与调用方一致: **(m3, m1, detail)**
        #   （初版误写为 (m1, m3) -> 打印时两项互换，已修）
        return m3_med, m1_med, detail_last
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
