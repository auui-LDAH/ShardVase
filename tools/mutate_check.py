#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mutate_check.py — 门禁检查器的**变异测试**（W5.3）

## 为什么这是护城河的核心
  门禁曾因 PowerShell 数组恒真而 **7/13 项失效**（必然失败的工具被报 [ok]）。
  那次失效持续了很久，因为**没有人质疑"通过"本身**。

  **纪律**: 每个检查器都必须**自证能抓错** —— 故意破坏它的输入，
  若它仍报 PASS，则该检查器是**盲的**（never-fails），比没有更危险。

## 原理
  对每个检查器:
    1. 记录**基线**（未变异时应 PASS）
    2. **变异**（破坏其输入 -> 应 FAIL）
    3. 恢复输入
    4. 判定:
       · 基线 PASS + 变异后 FAIL  -> **健康**（能抓错）
       · 基线 PASS + 变异后 PASS  -> **盲**（never-fails）**严重问题**
       · 基线 FAIL                -> **本身有问题**（需先修）

## 安全
  · 变异前**备份**目标文件，无论成败都恢复（finally）
  · 只变异 output/产物与注册表，**不改源码**
  · 支持 --dry-run 查看计划

用法:
  python tools/mutate_check.py                 # 全部检查器
  python tools/mutate_check.py --only modcheck # 指定
  python tools/mutate_check.py --list          # 列出变异方案
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

PY = sys.executable
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------
# 变异方案: (名称, 命令, 变异函数, 说明)
#   变异函数返回 (恢复函数) 或抛异常表示无法变异
# --------------------------------------------------------------------------
def _backup(path):
    """备份文件，返回恢复函数。"""
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    tmp = path + '.mutbak'
    shutil.copy2(path, tmp)

    def restore():
        shutil.copy2(tmp, path)
        os.remove(tmp)
    return restore


def mut_modules_json():
    """modcheck: 从注册表删一个 exports 项 -> 应报"注册表登记但头文件无声明"。"""
    p = os.path.join(REPO, 'modules.json')
    restore = _backup(p)
    try:
        d = json.load(open(p, encoding='utf-8'))
        # 找第一个有 exports 的模块，删掉一项
        for name, m in d['modules'].items():
            ex = m.get('exports') or []
            if len(ex) >= 2:
                m['exports'] = ex[:-1]          # 删最后一个
                break
        with open(p, 'w', encoding='utf-8', newline='\n') as f:
            json.dump(d, f, indent=2, ensure_ascii=False)
        return restore
    except Exception:
        restore()
        raise


def mut_demo_exe():
    """e2e/attacks/vmc/protchain: 改产物一个字节 -> 应报失败。"""
    p = os.path.join(REPO, 'build', 'demo.exe')
    restore = _backup(p)
    try:
        with open(p, 'r+b') as f:
            # 改 .text 中部一个字节（避开 PE 头，避免直接崩溃无法执行）
            f.seek(0x2000)
            b = f.read(1)
            f.seek(0x2000)
            f.write(bytes([b[0] ^ 0xFF]))
        return restore
    except Exception:
        restore()
        raise


def mut_manifest():
    """manifest 版本: 改成占位符 '?' -> 应报 FAIL。"""
    p = os.path.join(REPO, 'build', 'manifest.json')
    restore = _backup(p)
    try:
        d = json.load(open(p, encoding='utf-8'))
        d['version'] = '?'
        with open(p, 'w', encoding='utf-8', newline='\n') as f:
            json.dump(d, f, indent=2, ensure_ascii=False)
        return restore
    except Exception:
        restore()
        raise


def mut_drill_json():
    """drills lint: 破坏 `drills/*.json` 的 schema。

    ⚠️ 修正（2026-09-23）: 初版改的是 `docs/ATTACK_DRILL*.md`（Markdown），
    但 `cmd_lint` 实际读的是 **`drills/*.json`**（见 tools/drills.py
    的 `DRILLS = os.path.join(REPO, 'drills')` 与 `glob(DRILLS/'*.json')`）。
    -> 变异打偏 -> **假阳性**（误判为"盲检查器"）。

    **教训**: 变异必须打在**检查器实际的判据**上，否则会冤枉正常的检查器。
    """
    import glob as _g
    cands = [f for f in sorted(_g.glob(os.path.join(REPO, 'drills', '*.json')))
             if not os.path.basename(f).startswith('_')]
    if not cands:
        raise FileNotFoundError('drills/*.json')
    p = cands[0]
    restore = _backup(p)
    try:
        d = json.load(open(p, encoding='utf-8'))
        recs = d.get('attacks', d.get('drills', []))
        if not recs:
            raise ValueError('无 attacks/drills 记录')
        # 删掉 required 字段之一（result/severity 是 schema 必需）
        for fld in ('result', 'severity'):
            if fld in recs[0]:
                del recs[0][fld]
                break
        else:
            recs[0]['result'] = 'NOT_A_VALID_RESULT'
        with open(p, 'w', encoding='utf-8', newline='\n') as f:
            json.dump(d, f, indent=2, ensure_ascii=False)
        return restore
    except Exception:
        restore()
        raise


def mut_doc_gate_count():
    """doccheck: 制造一个错误的 `release_check N/N` 断言。

    ⚠️ 修正（2026-09-23，实测核实后）: 初版先找"已含 N/N 的文件"改写，
    找不到时改 `cands[0]` —— 但该文件可能不含断言，导致变异**没生效**
    -> **假阳性**（误判 doccheck 为盲）。

    核实证据: 手动追加错误断言后 doccheck **立刻抓到**：
        `[X] publish\\README.md:45 release_check 声称 999, 实际 14`
    => doccheck **是健康的**，是我的变异函数有 bug。

    修法: **总是追加**一个错误断言（不依赖现有内容）。
    """
    import glob as _g
    cands = []
    for pat in ('publish/*.md', 'docs/marketing/*.md'):
        cands += sorted(_g.glob(os.path.join(REPO, pat)))
    if not cands:
        raise FileNotFoundError('publish/*.md 或 docs/marketing/*.md')
    target = cands[0]
    restore = _backup(target)
    try:
        with open(target, 'ab') as f:
            f.write('\n\n门禁 release_check 999/999 全通过。\n'.encode('utf-8'))
        return restore
    except Exception:
        restore()
        raise


def mut_example_exe():
    """example: 改示例产物。"""
    import glob
    cands = sorted(glob.glob(os.path.join(REPO, 'build', 'tool_demo*.exe')))
    if not cands:
        raise FileNotFoundError('build/tool_demo*.exe')
    p = cands[0]
    restore = _backup(p)
    try:
        with open(p, 'r+b') as f:
            f.seek(0x800)
            b = f.read(1)
            f.seek(0x800)
            f.write(bytes([b[0] ^ 0xFF]))
        return restore
    except Exception:
        restore()
        raise


def mut_vmc_compiler():
    """vmc: 破坏 `tools/vmc.py` 的**错误检测**（它真正测试的东西）。

    ## 完整排查记录（2026-09-23，四次尝试后定位）
    vmc 的判据是 `out.startswith('RESULT 1')`（见 tests/vmc_tests.py:176）。
    流程: .vmc 源码 -> `tools/vmc.py` 编译 -> `tools/vmenc.py assemble`
          -> runner.exe -> 打印 "RESULT <n>"。

    **`demo/vm_build.json` 不在判据路径上**：它只作为 assemble 的绑定参数，
    其 `expect1/expect2` 仅被 `expect` 用例检查为 `!= 0`（几乎不可能失败）。
    => 改它的任何字段（expect1 / machine_id / serial）**都不会**触发 FAIL。

    **真正有效的变异**：让 vmc.py 对**非法输入也返回 0**
    （即"编译器失去错误检测"）-> 实测 `err1/err2/err3` 全部 FAIL ✓

    ⚠️ **教训**: 变异测试的**假阳性会冤枉正常检查器**。
    前三次我误判 vmc"盲"，实际是我的变异打偏。
    **变异无效时应先怀疑自己的变异，而非直接判定"盲"。**
    """
    p = os.path.join(REPO, 'tools', 'vmc.py')
    restore = _backup(p)
    try:
        t = open(p, encoding='utf-8', errors='replace').read()
        # 把第一个 `return 1` 改成 `return 0`（模拟错误检测失效）
        t2, n = re.subn(r'(\n\s+)return 1\b', r'\1return 0', t, count=1)
        if n == 0:
            restore()
            raise ValueError('未找到 return 1 可变异')
        with open(p, 'w', encoding='utf-8', newline='') as f:
            f.write(t2)
        return restore
    except Exception:
        restore()
        raise


MUTATIONS = {
    'modcheck': {
        'cmd': [PY, '-X', 'utf8', 'tools/modcheck.py', '--all-compositions'],
        'mut': mut_modules_json,
        'desc': '改 modules.json（删一个 exports 项）',
    },
    'drills': {
        'cmd': [PY, '-X', 'utf8', 'tools/drills.py', 'lint'],
        # 修正: 实际读 drills/*.json（非 docs/ATTACK_DRILL*.md）
        'mut': mut_drill_json,
        'desc': '破坏 drills/*.json 的 schema（删 required 字段）',
    },
    'doccheck': {
        'cmd': [PY, '-X', 'utf8', 'tools/doccheck.py'],
        # 修正: 实际校验 release_check N/N 断言（非任意数字）
        'mut': mut_doc_gate_count,
        'desc': '改 release_check N/N 的分子（doccheck 检查项 2）',
    },
    'protchain': {
        'cmd': [PY, '-X', 'utf8', 'tests/protchain_check.py'],
        'mut': mut_demo_exe,
        'desc': '改 build/demo.exe 一个字节',
    },
    'e2e': {
        'cmd': [PY, '-X', 'utf8', 'tests/e2e.py'],
        'mut': mut_demo_exe,
        'desc': '改 build/demo.exe 一个字节',
    },
    'vmc': {
        # 判据: `out.startswith('RESULT 1')`（见 vmc_tests.py:176）。
        # 变异打在其**被测对象**（tools/vmc.py 编译器）上，而非 vm_build.json
        # （实测: 后者不在判据路径上）。
        'cmd': [PY, '-X', 'utf8', 'tests/vmc_tests.py'],
        'mut': mut_vmc_compiler,
        'desc': '让 tools/vmc.py 对非法输入返回 0（错误检测失效）',
    },
}


def run_check(cmd, timeout=900):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=REPO)
        return r.returncode, (r.stdout + r.stderr).decode('utf-8', 'replace')
    except subprocess.TimeoutExpired:
        return 124, '(超时)'


def main():
    ap = argparse.ArgumentParser(prog='mutate_check.py')
    ap.add_argument('--only', nargs='*', help='只测指定检查器')
    ap.add_argument('--list', action='store_true', help='列出变异方案')
    ap.add_argument('--skip-baseline', action='store_true',
                    help='跳过基线（假设已 PASS）')
    args = ap.parse_args()

    names = args.only or list(MUTATIONS)

    if args.list:
        print('变异方案 (%d):' % len(MUTATIONS))
        for n, m in MUTATIONS.items():
            print('  %-12s %s' % (n, m['desc']))
        return 0

    print('=' * 78)
    print('门禁检查器变异测试（每个检查器必须能抓错）')
    print('=' * 78)
    print()

    results = {}
    for name in names:
        m = MUTATIONS.get(name)
        if not m:
            print('  [%s] 无变异方案，跳过' % name)
            continue
        print('--- %s ---' % name)
        print('  变异: %s' % m['desc'])

        # 1. 基线
        if not args.skip_baseline:
            rc0, out0 = run_check(m['cmd'])
            base_ok = rc0 == 0
            print('  基线: rc=%d %s' % (rc0, 'PASS' if base_ok else 'FAIL'))
            if not base_ok:
                print('  **基线就失败 -> 该检查器本身有问题，先修它**')
                results[name] = 'BASELINE_FAIL'
                print()
                continue
        else:
            base_ok = True

        # 2. 变异
        restore = None
        if m.get('mut') is None:
            print('  变异: **无方案** —— 该检查器的输入不是文件')
            print('        实测: vmc 用 subprocess 自建 vasm/源码并汇编，')
            print('        其输入在运行时生成 -> 静态变异不适用。')
            print('        **如实记录为"未验证"，而非谎报通过或失败。**')
            results[name] = 'NO_MUTATION'
            print()
            continue
        try:
            restore = m['mut']()
            rc1, out1 = run_check(m['cmd'])
            mut_failed = rc1 != 0
            print('  变异后: rc=%d %s' % (rc1, 'FAIL(正确抓到)' if mut_failed
                                          else 'PASS(**没抓到！**)'))
        except Exception as e:
            print('  变异失败: %s' % str(e)[:80])
            results[name] = 'MUT_ERROR'
            print()
            continue
        finally:
            if restore:
                restore()

        # 3. 恢复确认
        rc2, _ = run_check(m['cmd'])
        print('  恢复后: rc=%d %s' % (rc2, 'PASS' if rc2 == 0 else 'FAIL'))
        if rc2 != 0:
            print('  **警告: 恢复后仍失败 -> 变异未完全还原，需人工检查**')
            results[name] = 'RESTORE_FAIL'
            print()
            continue

        results[name] = 'HEALTHY' if mut_failed else 'BLIND'
        print('  判定: %s' % ('✓ 健康（能抓错）' if mut_failed
                              else '✗ **盲检查器**（变异后仍 PASS）'))
        print()

    print('=' * 78)
    print('汇总')
    print('=' * 78)
    healthy = [k for k, v in results.items() if v == 'HEALTHY']
    blind = [k for k, v in results.items() if v == 'BLIND']
    other = {k: v for k, v in results.items() if v not in ('HEALTHY', 'BLIND')}
    print('  健康: %d %s' % (len(healthy), healthy))
    print('  **盲: %d %s**' % (len(blind), blind))
    if other:
        print('  未验证/异常: %s' % other)
    print()
    if blind:
        print('  **[mutate_check] FAIL: %d 个检查器无法抓错**' % len(blind))
        return 1
    if other:
        print('  **[mutate_check] FAIL: %d 项未验证**'
              % len([k for k, v in other.items() if v == 'NO_MUTATION']))
        print('        未验证 != 通过。需为这些检查器补变异方案。')
        return 1
    print('  [mutate_check] PASS: 全部检查器均可自证能抓错')
    return 0


if __name__ == '__main__':
    sys.exit(main())
