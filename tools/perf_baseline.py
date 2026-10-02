#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""perf_baseline.py — **性能基准**（R2.2, 2026-09-29）

## 为什么存在（填补**诚实标注的空白**）
`docs/USABILITY_ASSESSMENT.md §5` 把三项性能指标标为 **"未测量"**：
```
| 启动总开销（含所有模块）| **未单独测量** |
| 常驻内存增量          | **未测量**     |
| 性能基准（对比无保护版本）| **未做**     |
```
本工具把它们**测出来**（而不是继续标注"未测量"）。

## 方法（**抗抖动设计**）
```
① 跨**组合** measurement: minimal(3 模块) / standard(9) / full(13)
   -> minimal 即"低保护基线"，用于计算**保护带来的增量**
② 每个指标取 **N 次的中位数**（本项目已实测存在 **±40% 抖动** ——
   取自 COST_ASYMMETRY 的看门狗抖动记录 -> 均值会被离群值带偏）
③ 指标:
   · 冷启动  = `--version`（最短路径）耗时
   · 自检    = `--selftest`（完整防护链路）耗时
   · 峰值内存 = 进程 PeakWorkingSet64（PowerShell 侧测，退出后仍可读）
④ 失败**不静默**: 产物缺失 -> 该项标 NA 并写进 JSON（"未验证 != 通过"）

## 用法
```
python tools/perf_baseline.py                    # 用已构建产物
python tools/perf_baseline.py --build            # 先按组合构建（慢）
python tools/perf_baseline.py --runs 15 --json out.json
python tools/perf_baseline.py --selftest         # 自检（含负向）
```

## 诚实边界
· 时间测量受**机器负载**影响 -> 取中位数 + 报告样本数（**不宣称精确**）
· `--version` 只走极短路径 -> 它**不等于**"启动总开销"；
  故同时给 `--selftest`（完整链路）作为上界参考
· 内存为 **PeakWorkingSet64**（含 CRT/系统 DLL 映射），非"净增量"
  -> 用 **minimal 作基线做差**，比绝对值更有意义
"""
import argparse
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMPOSITIONS = ['minimal', 'standard', 'full']


#: 组合产物的**存档目录**
#:   ## 为什么需要存档（**实测教训**）
#:     `build.ps1 -Composition X` **始终输出 `build/demo.exe`**（只改内容，
#:     **不改文件名**）-> 逐组合构建会**互相覆盖** -> 只能测到最后一个。
#:     我最初假设产物名是 `demo_<comp>.exe`（**错的，未验证**）——
#:     这正是"**测量问题 ≠ 缺陷**"：把"产物缺失"误当环境问题。
#:   => 对策: 构建一个 -> **立即复制存档** -> 再测。
ARCHIVE_DIR = os.path.join(REPO, 'build', 'perf')


def _exe_for(comp):
    """组合 -> **存档**产物路径（`build/perf/<comp>.exe`）。"""
    return os.path.join(ARCHIVE_DIR, '%s.exe' % comp)


def _median_time(cmd, runs, timeout=300):
    """跑 N 次取中位数（返回 (median_s, samples, ok, detail)）。"""
    samples = []
    for _ in range(runs):
        t0 = time.perf_counter()
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=timeout,
                               cwd=REPO)
        except subprocess.TimeoutExpired:
            return None, [], False, 'timeout'
        except OSError as e:
            return None, [], False, str(e)
        dt = time.perf_counter() - t0
        # ## 返回码语义（**实测**）
        #   `--version`  -> rc=0
        #   `--selftest` -> **rc=1**（"跑完但结论非 0"是**正常**的 ——
        #                    本机 VM 探测命中，咨询项使结论非 0）
        #   rc=45323 等大值 = **异常退出**（实测: 从仓库根跑找不到 vm.blob
        #                    -> VM 装载失败 code=10）
        #   => 接受 {0,1}；其余视为失败并**如实报出**。
        if r.returncode not in (0, 1):
            return None, samples, False, 'rc=%d（异常退出）' % r.returncode
        samples.append(dt)
    if not samples:
        return None, [], False, 'no samples'
    return statistics.median(samples), samples, True, ''


def _peak_mem_ps(exe):
    """测 `PeakWorkingSet64`（**轮询方案** —— 退出后读不到，实测为 0）。

    ## 为什么必须轮询
```
      Start-Process -PassThru ...; $p.WaitForExit(); $p.PeakWorkingSet64
        -> **0**（进程退出后 Process 对象不再刷新该属性）
```
      `PeakWorkingSet64` 是 OS 维护的**累计峰值** -> 只要在**存活期内**
      读到一次（越晚越准）即可。故: 拉起进程 + 10ms 轮询取最大值。

      ## 诚实标注
        轮询间隔 10ms -> 对瞬时峰值可能有毫秒级漏采；
        本工具的 JSON 会记录 `mem_method` 说明测法（**不宣称精确**）。
    """
    blob = os.path.join(REPO, 'build', 'vm.blob')
    # ## 用 `--wait-ms` 延长存活（**实测: 不延长则三组合都读到 2.60 MB**）
    #   `--wait-ms` 只**加空闲等待**，不改变工作集峰值（"曾达到的最大值"），
    #   但让轮询窗口变宽 -> 能读到峰值后的平台值。
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$p = Start-Process -FilePath '%s' "
        "-ArgumentList '--selftest','--vm-blob','%s','--wait-ms','800' -PassThru "
        "-WindowStyle Hidden;"
        "$peak = 0;"
        "while (-not $p.HasExited) {"
        "  try { $p.Refresh(); "
        "        if ($p.PeakWorkingSet64 -gt $peak) { $peak = $p.PeakWorkingSet64 } } "
        "  catch { break };"
        "  Start-Sleep -Milliseconds 5 }"
        "$peak"
        % (exe.replace("'", "''"), blob.replace("'", "''"))
    )
    try:
        r = subprocess.run(['powershell', '-NoProfile',
                            '-ExecutionPolicy', 'Bypass', '-Command', ps],
                           capture_output=True, timeout=300)
        out = r.stdout.decode('utf-8', 'replace').strip()
        m = re.search(r'(\d+)', out)
        val = int(m.group(1)) if m else None
        if not val:
            return None, '轮询未取到（out=%r）' % out[:40]
        return val, 'poll-5ms + wait-800ms'
    except (subprocess.TimeoutExpired, OSError) as e:
        return None, str(e)[:80]

def measure(comp, runs, with_mem=True):
    """测一个组合 -> dict。"""
    exe = _exe_for(comp)
    rec = {'composition': comp, 'exe': os.path.relpath(exe, REPO)}
    if not os.path.isfile(exe):
        rec['status'] = 'NA'
        rec['detail'] = '产物缺失（需先 `--build` 或 build.ps1 -Composition %s）' % comp
        return rec
    rec['size_bytes'] = os.path.getsize(exe)
    rec['status'] = 'ok'

    # ## 显式传 `--vm-blob`（**消除 cwd 依赖**）
    #   实测: blob 路径**相对当前目录** -> 从仓库根跑会找不到 ->
    #   自检异常退出（rc=45323）。显式传路径才能得到**可复现**的测量。
    # blob 也**按组合存档**（内容随组合变化）-> 用同名存档
    blob = os.path.join(ARCHIVE_DIR, '%s.blob' % comp)
    if not os.path.isfile(blob):
        blob = os.path.join(REPO, 'build', 'vm.blob')
    blob_args = ['--vm-blob', blob] if os.path.isfile(blob) else []

    med, samples, ok, det = _median_time([exe, '--version'], runs)
    rec['cold_ms'] = round(med * 1000, 2) if ok else None
    rec['cold_samples'] = len(samples)
    if not ok:
        rec['cold_detail'] = det

    med2, samples2, ok2, det2 = _median_time(
        [exe, '--selftest'] + blob_args, runs)
    rec['selftest_ms'] = round(med2 * 1000, 2) if ok2 else None
    rec['selftest_samples'] = len(samples2)
    if not ok2:
        rec['selftest_detail'] = det2

    if with_mem:
        mem, mdet = _peak_mem_ps(exe)
        rec['peak_ws_bytes'] = mem
        rec['mem_method'] = 'PeakWorkingSet64 via 5ms poll (+wait-800ms)'
        if mem is None:
            rec['mem_detail'] = mdet
    return rec


def build_all(extra=None):
    """按组合构建，并**立即存档**（否则后一个组合会覆盖前一个）。

    ## 关键
      `build.ps1` 恒输出 `build/demo.exe` -> 必须"构建一个、存档一个"。
      存档 = `build/perf/<comp>.exe`（连 `vm.blob` 一起存，供测量用）。
    """
    cmd = ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass',
           '-File', 'build.ps1', '-Config', 'Release']
    if extra:
        cmd += extra
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    for comp in COMPOSITIONS:
        print('  [build] 组合 %s ...' % comp)
        r = subprocess.run(cmd + ['-Composition', comp],
                           capture_output=True, cwd=REPO, timeout=1800)
        if r.returncode != 0:
            tail = (r.stdout + r.stderr).decode('utf-8', 'replace')[-300:]
            print('    **FAIL** rc=%d\n%s' % (r.returncode, tail))
            return False
        src = os.path.join(REPO, 'build', 'demo.exe')
        dst = _exe_for(comp)
        if not os.path.isfile(src):
            print('    **FAIL**: 构建未产出 build/demo.exe')
            return False
        shutil.copy2(src, dst)
        bl = os.path.join(REPO, 'build', 'vm.blob')
        if os.path.isfile(bl):
            shutil.copy2(bl, os.path.join(ARCHIVE_DIR, '%s.blob' % comp))
        print('    ok -> %s (%d B)' % (os.path.relpath(dst, REPO),
                                       os.path.getsize(dst)))
    return True


def main():
    ap = argparse.ArgumentParser(prog='perf_baseline.py')
    ap.add_argument('--runs', type=int, default=15,
                    help='每个指标采样次数（取中位数；默认 15）')
    ap.add_argument('--build', action='store_true',
                    help='先按组合构建（慢；否则用已有产物）')
    ap.add_argument('--json', dest='json_out', default=None)
    ap.add_argument('--no-mem', action='store_true', help='跳过内存测量')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    if args.build:
        print('=== 按组合构建 ===')
        if not build_all():
            print('[perf_baseline] FAIL: 构建失败')
            return 1

    print('=== 性能基准（每项 %d 次取中位数）===' % args.runs)
    print('  组合        产物大小      冷启动(ms)   自检(ms)    峰值WS(MB)')
    print('  ' + '-' * 66)
    recs = []
    for comp in COMPOSITIONS:
        rec = measure(comp, args.runs, with_mem=not args.no_mem)
        recs.append(rec)
        if rec['status'] != 'ok':
            print('  %-11s **NA**  %s' % (comp, rec.get('detail', '')[:44]))
            continue
        print('  %-11s %9d  %11s  %9s  %10s'
              % (comp, rec['size_bytes'],
                 rec.get('cold_ms', '-'), rec.get('selftest_ms', '-'),
                 ('%.2f' % (rec['peak_ws_bytes'] / 1048576.0))
                 if rec.get('peak_ws_bytes') else '-'))

    # 增量（相对 minimal 基线）
    base = next((r for r in recs
                 if r['composition'] == 'minimal' and r['status'] == 'ok'),
                None)
    if base and base.get('selftest_ms') is not None:
        print()
        print('=== 相对 **minimal（低保护基线）** 的增量 ===')
        for r in recs:
            if r['status'] != 'ok' or r is base:
                continue
            if r.get('selftest_ms') is None:
                continue
            d_ms = r['selftest_ms'] - base['selftest_ms']
            pct = (100.0 * d_ms / base['selftest_ms']) if base['selftest_ms'] else 0
            dm = ''
            if (r.get('peak_ws_bytes') and base.get('peak_ws_bytes')):
                dmb = (r['peak_ws_bytes'] - base['peak_ws_bytes']) / 1048576.0
                dm = '内存 %+.2f MB' % dmb
            print('  %-11s 自检 %+7.2f ms (%+.1f%%)  %s'
                  % (r['composition'], d_ms, pct, dm))
    else:
        print()
        print('  （缺 minimal 基线 -> 无法计算增量；`--build` 可生成）')

    out = {'runs': args.runs, 'results': recs,
           'note': '中位数采样；时间为本机实测，受负载影响'}
    if args.json_out:
        with open(args.json_out, 'w', encoding='utf-8') as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print('\n  已写出: %s' % args.json_out)

    ok_any = any(r['status'] == 'ok' for r in recs)
    print('\n[perf_baseline] %s' % ('PASS（%d/%d 组合有数据）'
                                    % (sum(1 for r in recs if r['status'] == 'ok'),
                                       len(recs)) if ok_any
                                    else 'FAIL: 无可用产物'))
    return 0 if ok_any else 1


def selftest():
    """自检: **含负向**（证明"缺失产物会如实标 NA"而不是编数据）。"""
    print('=== perf_baseline 自检 ===')
    fail = 0

    def case(name, ok, detail=''):
        nonlocal fail
        if ok:
            print('  ok  %s' % name)
        else:
            print('  **FAIL** %s  %s' % (name, detail[:90]))
            fail += 1

    # T1 正向: 真实产物可测（demo.exe 必须存在）
    r = measure('full', runs=3, with_mem=False)
    case('T1 正向: full 组合可测', r['status'] == 'ok'
         and r.get('cold_ms') is not None, str(r)[:90])

    # T2 **负向**: 不存在的产物 -> **必须标 NA**（不编造数据）
    global _exe_for
    orig = _exe_for
    _exe_for = lambda c: os.path.join(REPO, 'build', '__no_such_exe__.exe')
    try:
        r2 = measure('minimal', runs=1, with_mem=False)
    finally:
        _exe_for = orig
    case('T2 **负向**: 产物缺失 -> 必须标 NA（不编数据）',
         r2['status'] == 'NA' and 'cold_ms' not in r2, str(r2)[:90])

    # T3 中位数抗抖动（构造含离群值的样本 -> 中位数不受影响）
    xs = [1.0, 1.01, 0.99, 1.0, 50.0]
    case('T3 中位数抗离群（50.0 不改变结论）',
         abs(statistics.median(xs) - 1.0) < 0.02, str(statistics.median(xs)))

    # T4 组合 -> **存档路径**映射正确（防"改了布局忘了改工具"）
    exp = {'minimal': 'minimal.exe', 'standard': 'standard.exe',
           'full': 'full.exe'}
    ok4 = all(os.path.basename(_exe_for(c)) == exp[c] for c in exp)
    case('T4 组合 -> 存档命名正确（build/perf/<comp>.exe）', ok4,
         str({c: os.path.basename(_exe_for(c)) for c in exp})[:90])

    print()
    if fail:
        print('[perf_baseline-selftest] FAIL: %d 项' % fail)
        return 1
    print('[perf_baseline-selftest] PASS: 1 正向 + **2 负向** + 1 映射校验')
    return 0


if __name__ == '__main__':
    sys.exit(main())
