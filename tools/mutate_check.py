#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
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


def pick_unmasked_text_off(p, exe_rel):
    """在 `p` 的 `.text` 内挑一个**非掩码**字节 -> 返回其文件偏移。

    ## 为什么必须按布局选字节（**缺陷 6**, 2026-10-02 实测）
      win 侧原先**硬编码 `0x2000`**（"避开 PE 头"的经验偏移）。但
      `.text` 里的 selfcrypt **掩码区随每次构建随机化**（节名/填充/盐都随机）,
      一旦 `0x2000` 落进掩码区 -> `protchain` 的 P2（`.text` CRC,
      **掩码字节先清零**）**设计上**看不到这次翻转 -> 判"盲检查器"。
      **这不是 protchain 缺陷, 是变异打偏**（与 linux 侧 D1 同类）。

      实测: 5 次全新随机构建中 `0x2000` **命中掩码区 1/5**
      （`build/_mut_scan_out.txt`）。CI 第六跑（38bc671）正是踩中该分支,
      报 `盲: 1 ['protchain']` -> `[mutate_check] FAIL`。

    ## 判据来源（**复用既有, 不引入新解析**）
      按 `protchain_check.sections_of`（**自动分派 PE/ELF**）定位 `.text`,
      再用 `selfcrypt_meta` 的掩码区排除, 取 CRC 覆盖范围内的非掩码字节。
    """
    sys.path.insert(0, os.path.join(REPO, 'tests'))
    import protchain_check as _pc                # noqa: WPS433

    # ## ⚠️ **必须设 `_CURRENT_EXE`**（实测漏设的代价, 2026-09-29）
    #
    # `selfcrypt_meta` 内部走 `cry_section_names()` ->
    # 读**由 `_CURRENT_EXE` 决定的平台 json**。
    # **不设 -> 默认 Windows json -> Linux 掩码算成 0** ->
    # 选的"非掩码"字节**其实在掩码区内** -> 打进去被 P2 的清零掩盖
    # -> **假报"盲"**（实测正是如此: rel=17157 落在 16160..17231 内）。
    #
    # 教训: 复用某模块的函数时，**连同它的隐式上下文一起设**——
    # 否则"同一个函数在两个调用点算出不同结果"。
    _pc._CURRENT_EXE = exe_rel

    data = open(p, 'rb').read()
    secs = _pc.sections_of(data)
    text = next(s for s in secs if s['name'] == '.text')
    crc_len = min(text['virtual_size'], text['size_raw'])
    masks = [(mrva - text['virtual_addr'], mlen)
             for mrva, mlen, _grp in _pc.selfcrypt_meta(data, secs)]

    rel = None
    for cand in range(crc_len // 2, crc_len):
        if not any(o <= cand < o + ml for o, ml in masks):
            rel = cand
            break
    if rel is None:
        # 理论不可达（掩码不覆盖整节）—— 兜底仍打中部
        rel = crc_len // 2
    return text['ptr_raw'] + rel


def mut_demo_exe():
    """e2e/attacks/vmc/protchain: 改产物一个字节 -> 应报失败。

    ⚠️ 偏移**按布局选取**（缺陷 6）—— 原先是硬编码 `0x2000`，
    落进随机化的掩码区时会让 P2 假报"盲"。
    """
    p = os.path.join(REPO, 'build', 'demo.exe')
    restore = _backup(p)
    try:
        off = pick_unmasked_text_off(p, os.path.join('build', 'demo.exe'))
        with open(p, 'r+b') as f:
            f.seek(off)
            b = f.read(1)
            f.seek(off)
            f.write(bytes([b[0] ^ 0xFF]))
        return restore
    except Exception:
        restore()
        raise


def mut_demo_linux():
    """变异 `build/demo_linux` 的 **.text 非掩码字节**（D1, 2026-09-29）。

    ## 为什么不能照搬 win 的 `0x2000`
      `0x2000` 是**针对 PE 布局**的经验偏移（避开 PE 头）——
      ELF 的文件布局完全不同（`.text` 实测在 `ptr_raw=14848`），
      固定 `0x2000` 可能落进**头部/动态符号区** -> 变异**打偏**
      （"变异打偏 -> 假阳性'盲检查器'"，与 §24 的教训同类）。

      ⚠️ 缺陷 6（2026-10-02）: 该教训**同样适用于 win 侧** —— `.text` 里的
      selfcrypt 掩码区**每次构建随机化**，硬编码偏移会命中掩码区
      （实测 1/5），使 P2 设计上不可见。win 侧已改用同一判据。
      两侧现共用 `pick_unmasked_text_off()`，**单一实现**。
    """
    p = os.path.join(REPO, 'build', 'demo_linux')
    restore = _backup(p)
    try:
        off = pick_unmasked_text_off(p, os.path.join('build', 'demo_linux'))
        with open(p, 'r+b') as f:
            f.seek(off)
            b = f.read(1)
            f.seek(off)
            f.write(bytes([b[0] ^ 0xFF]))
        return restore
    except Exception:                       # noqa: BLE001
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
    vmc 的判据是 `out.startswith('RESULT 1')`（见 tests/vmc_tests.py:250）。
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
        'desc': '改 build/demo.exe 一个字节 (按布局取非掩码偏移)',
    },
    'e2e': {
        'cmd': [PY, '-X', 'utf8', 'tests/e2e.py'],
        'mut': mut_demo_exe,
        'desc': '改 build/demo.exe 一个字节 (按布局取非掩码偏移)',
    },
    'vmc': {
        # 判据: `out.startswith('RESULT 1')`（见 vmc_tests.py:250）。
        # 变异打在其**被测对象**（tools/vmc.py 编译器）上，而非 vm_build.json
        # （实测: 后者不在判据路径上）。
        'cmd': [PY, '-X', 'utf8', 'tests/vmc_tests.py'],
        'mut': mut_vmc_compiler,
        'desc': '让 tools/vmc.py 对非法输入返回 0（错误检测失效）',
    },
}

# ## D1（2026-09-29）: **Linux 侧**变异方案表
#
# ## 为什么需要
#   门禁的 `mutate_check` 只证明**Windows 侧**检查器能抓错；
#   Linux 侧的检查器（ci_linux 里的 protchain/e2e/attacks）**从未自证** ——
#   即"**Linux 侧的判据是否可能已经变盲**"没有守护。
#
# ## 与 win 表的差异（**逐项理由**）
# | 检查器 | Linux 形态 | 说明 |
# |--------|-----------|------|
# | modcheck/drills/doccheck | **同 win** | 平台无关（0 处产物引用）|
# | protchain | `--exe build/demo_linux --blob build/linux/vm.blob` | **镜像** `verify_linux_runtime` 的调用（**单一来源**）|
# | e2e | `--platform linux` | 同上 |
# | attacks | `--platform linux` | **新增**（win 表里没有）—— 补足到 6 个 |
# | vmc | **不含** | `vmc_tests` 依赖 MSVC + Windows 产物；Linux 侧的 vmc 检查器是 `tools/vmc_linux.py`（**被 verify_linux_runtime 调用，但不依赖 demo_linux**，故不纳入）|
#
# ## 变异目标
#   `pick_unmasked_text_off()` —— 按 `sections_of` 定位 `.text`，再排除
#   **selfcrypt 掩码区**，取 CRC 覆盖范围内的非掩码字节。
#   （**不照搬 win 的 0x2000**：ELF 布局不同，固定偏移会打偏 ->
#    "变异打偏 -> 假阳性'盲检查器'"。缺陷 6 证实该规律对 win 侧同样成立。）
MUTATIONS_LINUX = {
    'modcheck': MUTATIONS['modcheck'],
    'drills':   MUTATIONS['drills'],
    'doccheck': MUTATIONS['doccheck'],
    'protchain': {
        'cmd': [PY, '-X', 'utf8', 'tests/protchain_check.py',
                '--exe', os.path.join('build', 'demo_linux'),
                '--blob', os.path.join(REPO, 'build', 'linux', 'vm.blob')],
        'mut': mut_demo_linux,
        'desc': '改 build/demo_linux 一个字节 (按布局取非掩码偏移)',
    },
    'e2e': {
        'cmd': [PY, '-X', 'utf8', 'tests/e2e.py', '--platform', 'linux'],
        'mut': mut_demo_linux,
        'desc': '改 build/demo_linux 一个字节 (按布局取非掩码偏移)',
    },
    'attacks': {
        'cmd': [PY, '-X', 'utf8', 'tests/attacks.py', '--platform', 'linux'],
        'mut': mut_demo_linux,
        'desc': '改 build/demo_linux 一个字节 (按布局取非掩码偏移)',
    },
}



def run_check(cmd, timeout=900):
    try:
        r = winproc.run(cmd, capture_output=True, timeout=timeout, cwd=REPO)
        return r.returncode, (r.stdout + r.stderr).decode('utf-8', 'replace')
    except subprocess.TimeoutExpired:
        return 124, '(超时)'


def main():
    ap = argparse.ArgumentParser(prog='mutate_check.py')
    ap.add_argument('--only', nargs='*', help='只测指定检查器')
    ap.add_argument('--list', action='store_true', help='列出变异方案')
    ap.add_argument('--skip-baseline', action='store_true',
                    help='跳过基线（假设已 PASS）')
    # D1: **平台分派** —— Linux 侧的检查器需自证能抓错（此前只测 win）
    #
    # ⚠️ 判据教训（**同类第 N 次**）: 我先前用 `"'--platform' in t"` 判断
    # "是否已加参数" —— 但 `MUTATIONS_LINUX` 块里**已含该字符串** ->
    # 子串**假阳性** -> 参数没加上、`--list` 却"看起来работает"。
    # => 判据必须是**唯一结构形态**（`add_argument('--platform'`）。
    ap.add_argument('--platform', choices=['win', 'linux'], default='win',
                    help='被测侧：win(门禁) / linux(ci_linux)')
    args = ap.parse_args()

    table = MUTATIONS if args.platform == 'win' else MUTATIONS_LINUX
    names = args.only or list(table)

    if args.list:
        print('变异方案 (%d, platform=%s):' % (len(table), args.platform))
        for n, m in table.items():
            print('  %-12s %s' % (n, m['desc']))
        return 0

    print('=' * 78)
    print('检查器变异测试（platform=%s；每个检查器必须能抓错）' % args.platform)
    print('=' * 78)
    print()

    results = {}
    for name in names:
        m = table.get(name)
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
