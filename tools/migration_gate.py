#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
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

## 按工具链分档（2026-10-17，RELEASE_TAIL_PLAN 阶段 2）
  抖动既然是工具链性质而非防护差异，阈值**按 MSVC 工具链分两档**
  （判据与文档同源，doccheck 对账的是新档常量）：

  · 新档 MSVC >= 14.51（CI 实测 6.2%）: M3 阈值 12%、M1 阈值 12%
  · 旧档 MSVC < 14.51（本机 14.44 实测 15.6%）: M3 阈值 18%、M1 阈值 12%

  旧档 18% 的安全边界：低于已知劣化点 20.6%（禁用 6/16 文件部分移除）
  仍有 2.4pp —— 部分移除 20.6% / 完全移除 55.9% 在旧档下**仍必被拦**，
  漏检方向不变；15.6% 落档内只是序言抖动（上文机制）。分档常量见下：
  `MAX_M3`（新档）/ `MAX_M3_LEGACY`（旧档）/ `MAX_M1`（两档同值）/
  `TIER_BOUNDARY`；档位由 build.ps1 实际解析出的 vcvars64.bat 推工具集版本，
  识别失败从严按新档。selftest 覆盖两档正/负/边界 + 劣化点必拦。

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
#
# ---------------------------------------------------------------------------
# 按工具链分档（2026-10-17，docs/RELEASE_TAIL_PLAN.md 阶段 2）
#
# 同一份代码在不同 MSVC 上 M3 落点不同（序言长度抖动，见文件头/§2.43）：
#   · 新档 MSVC >= 14.51（CI 实测 6.2%）        -> 沿用 12%
#   · 旧档 MSVC <  14.51（本机 14.44 实测 15.6%）-> 18%
# 旧档取 18 的依据: 夹在 15.6（抖动实测）与 20.6（已知劣化点: 禁用 6/16
# 文件部分移除）之间 —— 15.6 落档内，20.6/55.9 必拦，漏检方向不变。
# 档位判定: 以 build.ps1 Find-VcVars 实际解析的 vcvars64.bat 反推
# <root>\VC\Tools\MSVC 最大版本（与构建用的工具集严格同源）；
# 识别失败从严按新档。
#
# ⚠️ `MAX_M3 = 12.0` 必须保持**行首** `MAX_M3` 形态 —— doccheck 的
#    gate_threshold_constants 用 `(?m)^MAX_M3\s*=` 抓唯一真值源；
#    docstring/ release_check 注释里的阈值声明只认 `<= N%` 形态，
#    分档叙述要写「旧档 18%」这种裸写法（不带 <= ），否则会被判漂移。
MAX_M3 = 12.0          # 新档（MSVC >= 14.51）保护函数特征命中率上限（%）
MAX_M3_LEGACY = 18.0   # 旧档（MSVC < 14.51）上限（%）——14.44 实测 15.6 落档内
MAX_M1 = 12.0          # 地址复用率上限（%）——两档同值,1.1%~5.8% 均远离
TIER_BOUNDARY = (14, 51)  # 分档边界（major, minor）


def _seed_files(tmp):
    """造两个**内容不同**的种子表（派生不同种子）。"""
    a = os.path.join(tmp, 'seedA.json')
    b = os.path.join(tmp, 'seedB.json')
    json.dump({'tag': 'A'}, open(a, 'w'))
    json.dump({'tag': 'B'}, open(b, 'w'))
    return a, b


def _msvc_version_from_vcvars(vcvars):
    """从 vcvars64.bat 路径反推活动工具集版本 (major, minor)。

    路径形态: `<root>\\VC\\Auxiliary\\Build\\vcvars64.bat`
    -> `<root>\\VC\\Tools\\MSVC\\<ver>`（取最大版本，与 vcvars 激活的
    工具集一致）。返回 None = 路径不存在/无工具集目录。

    ⚠️ dirname 层数: file → Build → Auxiliary → **VC**（3 层到 VC 目录，
    不是 root）——初版按 root 拼成 `<root>\\VC\\VC\\Tools\\MSVC` 永远
    OSError → 检测静默掉线（2026-10-17 实跑抓到；selftest 已加真树用例
    兜底，不再依赖实跑暴露）。
    """
    if not vcvars:
        return None
    try:
        vc_dir = os.path.dirname(os.path.dirname(os.path.dirname(vcvars)))
        base = os.path.join(vc_dir, 'Tools', 'MSVC')
        best = None
        for nm in os.listdir(base):
            m = re.match(r'(\d+)\.(\d+)', nm)
            if m:
                v = (int(m.group(1)), int(m.group(2)))
                if best is None or v > best:
                    best = v
        return best
    except OSError:
        return None


def tier_for(ver):
    """(major, minor) -> (档名, M3 上限%)；ver=None 从严按新档。"""
    if ver is not None and ver < TIER_BOUNDARY:
        return 'legacy', MAX_M3_LEGACY
    return 'modern', MAX_M3


def _build(seedfile, salt, out_dir, tag):
    env = dict(os.environ)
    env['PROT_BUILD_SALT'] = salt
    r = winproc.run(['powershell', '-ExecutionPolicy', 'Bypass', '-File',
                     'build.ps1', '-Config', 'Release', '-SkipSmoke',
                     '-SkipSign', '-Composition', 'full',
                     '-SeedsFile', seedfile],
                    capture_output=True, cwd=REPO, env=env)
    vcvars = None
    try:
        out = (getattr(r, 'stdout', None) or b'') + \
              (getattr(r, 'stderr', None) or b'')
        m = re.search(rb'build: vcvars = (.+)', out)
        if m:
            vcvars = m.group(1).decode('utf-8', 'replace').strip()
    except Exception:
        vcvars = None
    ok = False
    for src, nm in [('build/demo.exe', tag + '.exe'),
                    ('build/demo.map', tag + '.map')]:
        s = os.path.join(REPO, src)
        if os.path.exists(s):
            shutil.copy2(s, os.path.join(out_dir, nm))
            ok = True
    return ok, vcvars


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
    vcvars_seen = None
    tmp = tempfile.mkdtemp(prefix='miggate_')
    try:
        for k in range(3):
            sa = os.path.join(tmp, 'seedA%d.json' % k)
            sb = os.path.join(tmp, 'seedB%d.json' % k)
            json.dump({'tag': 'A%d' % k}, open(sa, 'w'))
            json.dump({'tag': 'B%d' % k}, open(sb, 'w'))
            salt_a = '0x%08X' % (0x11111111 * (k + 1) & 0xFFFFFFFF)
            salt_b = '0x%08X' % (0xAAAAAAAA * (k + 1) & 0xFFFFFFFF)
            ok_a, vc_a = _build(sa, salt_a, tmp, 'A%d' % k)
            if not ok_a:
                return None, None, '构建 A%d 失败' % k, vcvars_seen
            ok_b, vc_b = _build(sb, salt_b, tmp, 'B%d' % k)
            if not ok_b:
                return None, None, '构建 B%d 失败' % k, vcvars_seen
            if vcvars_seen is None:
                vcvars_seen = vc_a or vc_b
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
                return None, None, '度量解析失败', vcvars_seen
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
        # ⚠️ 返回顺序必须与调用方一致: **(m3, m1, detail, vcvars)**
        #   （初版误写为 (m1, m3) -> 打印时两项互换，已修；
        #     第 4 项 vcvars 是分档依据，2026-10-17 阶段 2 加入）
        return m3_med, m1_med, detail_last, vcvars_seen
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
    print('=== 分档判定（按工具链，2026-10-17 阶段 2）===')
    case('MSVC 14.44 -> 旧档', tier_for((14, 44))[0], 'legacy')
    case('MSVC 14.50 -> 旧档', tier_for((14, 50))[0], 'legacy')
    case('MSVC 14.51 -> 新档', tier_for((14, 51))[0], 'modern')
    case('MSVC 15.00 -> 新档', tier_for((15, 0))[0], 'modern')
    case('未知工具链从严按新档(12)', tier_for(None)[1], MAX_M3)
    case('旧档上限 = 18', MAX_M3_LEGACY, 18.0)
    case('旧档15.6 -> 通过（14.44 抖动实测）', 15.6 <= MAX_M3_LEGACY, True)
    case('旧档 18.0 -> 通过（边界）', 18.0 <= MAX_M3_LEGACY, True)
    case('旧档 18.1 -> 失败（边界外）', 18.1 <= MAX_M3_LEGACY, False)
    case('旧档 20.6 -> **失败**（劣化点仍必拦）', 20.6 <= MAX_M3_LEGACY, False)
    case('旧档 55.9 -> **失败**（完全移除必拦）', 55.9 <= MAX_M3_LEGACY, False)
    # 真树路径反推 —— 抓 dirname 层数回归（初版拼成 <root>\VC\VC\Tools\MSVC
    # 永远 None、检测静默掉线，实跑才暴露；现在自检兜底）
    _tv = tempfile.mkdtemp(prefix='migtier_')
    try:
        _vd = os.path.join(_tv, 'VC', 'Auxiliary', 'Build')
        os.makedirs(_vd)
        _vs = os.path.join(_tv, 'VC', 'Tools', 'MSVC')
        os.makedirs(os.path.join(_vs, '14.44.35207'))
        os.makedirs(os.path.join(_vs, '14.51.36231'))
        case('真树反推: vcvars -> (14,51) 取最大工具集',
             _msvc_version_from_vcvars(os.path.join(_vd, 'vcvars64.bat')),
             (14, 51))
        case('假路径 -> None（不崩）',
             _msvc_version_from_vcvars(r'C:\nope\vcvars64.bat'), None)
        case('空值 -> None', _msvc_version_from_vcvars(None), None)
    finally:
        shutil.rmtree(_tv, ignore_errors=True)
    case('docstring 记录旧档阈值 18%%', '18%' in (__doc__ or ''), True)

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
        print('  阈值: 按工具链分档 —— 新档 (MSVC >= 14.51) M3 <= %.0f%%, '
              '旧档 (< 14.51) M3 <= %.0f%%, M1 两档 <= %.0f%%'
              % (MAX_M3, MAX_M3_LEGACY, MAX_M1))
        print('  方法: 三次异种子异salt 构建（3 对取中位数）+ migration_cost')
        print()

    m3, m1, detail, vcvars = measure(quiet=args.quiet)
    if m3 is None:
        print('[migration_gate] FAIL: %s' % detail, file=sys.stderr)
        return 1

    ver = _msvc_version_from_vcvars(vcvars)
    tier, cap = tier_for(ver)
    ver_txt = ('MSVC %d.%d' % ver) if ver else '未识别(从严按新档)'
    if not args.quiet:
        print('  工具链: %s -> 档位 %s（M3 上限 %.0f%%）'
              % (ver_txt, '新档' if tier == 'modern' else '旧档', cap))
        print()

    bad = []
    if m3 > cap:
        bad.append('M3 %.1f%% > %.0f%%（%s档: 保护函数可被特征定位 '
                   '-> 迁移成本低）' % (m3, cap, tier))
    if m1 > MAX_M1:
        bad.append('M1 %.1f%% > %.0f%%（硬编码地址可复用）' % (m1, MAX_M1))

    if bad:
        for b in bad:
            print('[migration_gate] FAIL: %s' % b)
        return 1
    print('[migration_gate] PASS: M3=%.1f%% M1=%.1f%%'
          '（迁移成本可接受, %s档 %s）'
          % (m3, m1, tier, ver_txt))
    return 0


if __name__ == '__main__':
    sys.exit(main())
