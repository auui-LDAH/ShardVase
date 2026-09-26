#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
# vmcalc_flow_test.py — A2 二阶段流程级测试 (vmcalc_build 链路)
# 覆盖: 多函数同文件 / 改名幂等 / 桩槽位静态断言 / 不一致状态自动修复
# 用法: python vmcalc_flow_test.py
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


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
TMP = os.path.join(os.environ.get('TEMP', ROOT), 'vmcalc_flow')
shutil.rmtree(TMP, ignore_errors=True)
os.makedirs(TMP)
PY = sys.executable
VB = os.path.join(ROOT, 'demo', 'vm_build.json')
VMCENC = os.path.join(ROOT, 'tools', 'vmenc.py')
VMC = os.path.join(ROOT, 'tools', 'vmcalc_build.py')

fail = []


def check(name, cond, detail=''):
    print('[%s] %s%s' % ('PASS' if cond else 'FAIL', name,
                         ' :: ' + detail if detail else ''))
    if not cond:
        fail.append(name)


def run_vmcalc(srcs):
    r = winproc.run([PY, VMC, '--src'] + srcs + ['--gen', os.path.join(TMP, 'gen'),
                       '--json', VB, '--vmenc', VMCENC],
                       capture_output=True, text=True)
    return r


# ---- 1. 双函数同文件 ----
dual = os.path.join(TMP, 'biz_dual.c')
open(dual, 'w').write('''// @vmcalc
uint64_t add_mix(uint64_t a, uint64_t b) { return a + b * 3; }
// @vmcalc
uint64_t salter(uint64_t x) {
    uint64_t y = x ^ 0xABCDEF;
    y = y * 31;
    return y;
}
''')
r = run_vmcalc([dual])
check('dual ok', r.returncode == 0, r.stderr[-120:])
src = open(dual, encoding='utf-8').read()
check('rename add_mix_native', 'add_mix_native(' in src)
check('rename salter_native', 'salter_native(' in src)
stubs = open(os.path.join(TMP, 'gen', 'vmcalc_stubs.c'), encoding='utf-8').read()
check('two stubs', stubs.count('uint64_t ') >= 2)
check('stubs count N=2', 'g_vmcalc_imgs[2]' in stubs and 'k_vmcalc_names[2]' in stubs)
check('bin names', 'b_add_mix' in stubs and 'b_salter' in stubs)
# 桩槽位静态断言: 每函数参数 memcpy 偏移为 0,8,... 且完整
for idx in (0, 1):
    ok = ('memcpy(frame + %d, &v%d, 8);' % (8 * idx, idx)) in stubs
    check('stub slot %d' % (idx + 1), ok)

# ---- 2. 幂等: 二次运行不应改名/重复翻译 ----
r2 = run_vmcalc([dual])
check('idempotent rc', r2.returncode == 0)
check('no double rename', '_native_native' not in open(dual, encoding='utf-8').read())
vasms = [f for f in os.listdir(os.path.join(TMP, 'gen')) if f.endswith('.vasm')]
check('no duplicate vasm', len(vasms) == 2, str(vasms))

# ---- 3. 不一致状态修复: 删 stubs 后重跑 -> 自动 unrename 重建 ----
os.unlink(os.path.join(TMP, 'gen', 'vmcalc_stubs.c'))
r3 = run_vmcalc([dual])
check('repair rc', r3.returncode == 0, r3.stderr[-120:])
rep_src = open(dual, encoding='utf-8').read()
check('rebuilt stubs', os.path.isfile(os.path.join(TMP, 'gen', 'vmcalc_stubs.c')))
check('no native_native after repair', '_native_native' not in rep_src)
check('final renamed once', rep_src.count('_native(') == 2)

print('\nRESULT: %d/%d' % (11 - len(fail), 11))
sys.exit(1 if fail else 0)