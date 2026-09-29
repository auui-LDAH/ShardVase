# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
tests/vmc_tests.py ??vmc ???????????? (M2)

???????? vmc ??? -> vmenc assemble -> cl ??? runner -> ??????
result@52??ost ?????????????????? (runner ???)??
???: ???/????????????f/else??hile??em ?????XPECT ???????????????????"""

import json
import os
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


REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
# W5: 用平台目录（flat 已清理）
sys.path.insert(0, os.path.join(REPO, 'tools'))
import genpaths as _gp  # noqa: E402
PY = sys.executable
VMC = os.path.join(REPO, 'tools', 'vmc.py')
VMENC = os.path.join(REPO, 'tools', 'vmenc.py')
JSON = os.path.join(REPO, 'demo', 'vm_build.json')
BUILD = os.path.join(REPO, 'build')
GEN = _gp.paths('win').gen   # W5: **平台目录**（flat 已清理）
#   原为 join(REPO, 'demo', 'gen') = **flat** -> 该目录已被清理；
#   且 blob_c/h 曾写在这里，导致**每次跑测试就复活 2 个 flat 文件**。

CASES = []


def case(name, src, host_hex=''):
    """host_hex: ???????????? hex ?????(64 ???)."""
    CASES.append((name, src, host_hex))


case('arith', """
uint64 a = 6;
uint64 b = 7;
uint64 c = a * b + 8;
uint64 d = c / 5;
uint64 e = d % 3;
uint64 f = (a << 2) | 1;
uint64 g = f ^ 0xFF;
uint64 h = g & 0x0F;
uint64 ok = 0;
if (h == 6 && e == 1 && c == 50) { ok = 1; }
return ok;
""")

case('logic', """
uint64 x = 5;
uint64 ok = 0;
if (x > 3 && x < 10 && !(x == 4)) { ok = 1; }
return ok;
""")

case('ifelse', """
uint64 x = 42;
uint64 r = 0;
if (x >= 100) { r = 7; } else { r = 3; }
return r == 3;
""")

case('loop', """
uint64 i = 0;
uint64 s = 0;
while (i < 10) { s = s + i; i = i + 1; }
return s == 45;
""")

# host[0..3]=0x1234 LE, host[8..15]=0xABCD LE
case('mem', """
uint64 a = mem32(0);
uint64 b = mem64(8);
uint64 ok = 0;
if (a == 0x1234 && b == 0xABCD) { ok = 1; }
return ok;
""", '34120000' + '00' * 4 + 'cdab000000000000')

case('expect', """
uint64 a = EXPECT1;
uint64 b = EXPECT2;
return (a != 0) && (b != 0);
""")

RUNNER_TMPL = r'''
#include "protect/vm.h"
#include "vmc_case_runner_blob.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t host[0x4000];

int main(void)
{
    const char* init = getenv("VMC_HOST_HEX");
    if (init != NULL) {
        size_t n = strlen(init);
        size_t skip = (n >= 2 && init[0] == '0' && (init[1] == 'x' || init[1] == 'X')) ? 2 : 0;
        if (n > skip) {
            size_t len = (n - skip) / 2;
            if (len > sizeof(host)) len = sizeof(host);
            for (size_t i = 0; i < len; i++) {
                unsigned v;
                sscanf_s(init + skip + i * 2, "%2x", &v);
                host[i] = (uint8_t)v;
            }
        }
    }
    prot_status st = prot_vm_run(&g_vmc_case_runner, host, sizeof(host));
    if (st != PROT_OK) {
        printf("RUNFAIL %d\n", (int)st);
        return 1;
    }
    uint32_t r;
    memcpy(&r, host + 52, 4);
    printf("RESULT %u\n", r);
    return 0;
}
'''


def run_case(name, src, host_hex):
    vmc_src = os.path.join(BUILD, 'vmc_case.vmc')
    vmc_vasm = os.path.join(BUILD, 'vmc_case.vasm')
    # W5: blob 写 **BUILD**（与其余 vmc 产物一致，自包含）
    #   原写 GEN（flat）-> **每次跑测试就复活 flat 文件**（清理无效）
    blob_c = os.path.join(BUILD, 'vmc_case_runner_blob.c')
    blob_h = os.path.join(BUILD, 'vmc_case_runner_blob.h')
    runner_c = os.path.join(BUILD, 'vmc_case_runner.c')
    exe = os.path.join(BUILD, 'vmc_case_runner.exe')

    with open(vmc_src, 'w', encoding='utf-8') as f:
        f.write(src)
    r = winproc.run([PY, VMC, vmc_src, vmc_vasm,
                        os.path.join(BUILD, 'vmc_case.layout.json'), '--seed', '0x1234', '--flatten'],
                       capture_output=True, text=True,
                        encoding='utf-8', errors='replace')   # W5: 防 cl 中文输出解码崩溃
    if r.returncode != 0:
        return 'COMPILE FAIL: ' + r.stderr.strip()
    r = winproc.run([PY, VMENC, 'assemble', vmc_vasm, JSON, blob_c, blob_h,
                        '--name', 'g_vmc_case_runner'],
                       capture_output=True, text=True,
                        encoding='utf-8', errors='replace')   # W5: 防 cl 中文输出解码崩溃
    if r.returncode != 0:
        return 'ASSEMBLE FAIL: ' + r.stderr.strip()
    with open(runner_c, 'w', encoding='utf-8') as f:
        f.write(RUNNER_TMPL)
    vcvars = None
    for c in ('D:\\environment\\VS2022BuildTools\\VC\\Auxiliary\\Build\\vcvars64.bat',
              r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'):
        if os.path.isfile(c):
            vcvars = c
            break
    if vcvars is None:
        return 'CL FAIL: vcvars not found'
    # ## L6b（2026-09-25）: 加入平台层源文件
    #
    # **问题**: L6b 把 `vm.c` 的平台相关部分改走平台层
    #   （`prot_plat_monotonic_ns`）后，本处**硬编码的源文件列表**缺平台层
    #   -> `LNK2019: 无法解析的外部符号 prot_plat_monotonic_ns`
    #   -> **门禁 vmc 项失败**（并连带使 mutate_check 报 BASELINE_FAIL）。
    #
    # **这是本项目"硬编码源文件列表"问题的第 6 处**
    #   （L3 修了 build_example.ps1；L6b 修了 build.ps1 的两处；本处是第 6 处）。
    #
    # **为什么不改组合驱动**: 本测试刻意只链接**被测模块**
    #   （vm.c + crc32.c + runner）—— 用完整组合会引入无关模块，
    #   使"VM 编译器测试"变成"整套构建测试"。
    plat_src = os.path.join(REPO, 'src', 'platform', 'prot_platform_win.c')
    clcmd = ('cl /nologo /O2 /W4 /WX /std:c11 /utf-8 '
             '/I "' + os.path.join(REPO, 'include') + '" /I "' + GEN + '" '
             '/I "' + BUILD + '" '   # W5: blob 头在 BUILD
             '/Fe:"' + exe + '" '
             '"' + os.path.join(REPO, 'src', 'vm.c') + '" '
             '"' + os.path.join(REPO, 'src', 'crc32.c') + '" '
             '"' + plat_src + '" '
             '"' + blob_c + '" "' + runner_c + '" '
             '/link /SUBSYSTEM:CONSOLE advapi32.lib winhttp.lib')
    bat = os.path.join(BUILD, 'vmc_cl.bat')
    with open(bat, 'w', encoding='ascii') as f:
        f.write('@echo off\r\ncall "%s" >nul 2>&1\r\n%s\r\n' % (vcvars, clcmd))
    r = winproc.run([bat], capture_output=True, text=True,
                        encoding='utf-8', errors='replace')   # W5: 防 cl 中文输出解码崩溃
    if r.returncode != 0:
        return 'CL FAIL: ' + (r.stderr or r.stdout or '')[-400:]
    env = dict(os.environ)
    env['VMC_HOST_HEX'] = host_hex or '00'
    p = winproc.run([exe], capture_output=True, timeout=20, env=env)
    out = p.stdout.decode('utf-8', 'replace')
    if p.returncode != 0:
        return 'RUN FAIL exit=%d %s' % (p.returncode, out.strip())
    return out.strip()


def main():
    failed = 0
    for name, src, host_hex in CASES:
        out = run_case(name, src, host_hex)
        ok = out.startswith('RESULT 1')
        print('%-12s  %s   (%s)' % (name, 'PASS' if ok else 'FAIL', out))
        if not ok:
            failed += 1

    # ????????????
    err_cases = [
        'uint64 x = y + 1;\n',
        'uint64 x = 1; x = ;\n',
        'unknown_fn(1);\n',
    ]
    for i, src in enumerate(err_cases):
        vmc_src = os.path.join(BUILD, 'vmc_err.vmc')
        with open(vmc_src, 'w', encoding='utf-8') as f:
            f.write(src)
        r = winproc.run([PY, VMC, vmc_src,
                            os.path.join(BUILD, 'vmc_err.vasm'),
                            os.path.join(BUILD, 'vmc_err.layout.json')],
                           capture_output=True, text=True,
                        encoding='utf-8', errors='replace')   # W5: 防 cl 中文输出解码崩溃
        ok = r.returncode != 0
        print('%-12s  %s' % ('err%d' % (i + 1), 'PASS' if ok else 'FAIL'))
        if not ok:
            failed += 1

    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())


