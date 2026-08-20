# -*- coding: utf-8 -*-
"""
tests/vmc_tests.py — vmc 编译器端到端单测 (M2)

对每个案例: vmc 编译 -> vmenc assemble -> cl 链接 runner -> 运行断言
result@52。host 初始化数据经环境变量注入 (runner 读取)。

案例: 算术/位运算、逻辑、if/else、while、mem 内置、EXPECT 符号、
错误输入必须报错。
"""

import json
import os
import subprocess
import sys

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
PY = sys.executable
VMC = os.path.join(REPO, 'tools', 'vmc.py')
VMENC = os.path.join(REPO, 'tools', 'vmenc.py')
JSON = os.path.join(REPO, 'demo', 'vm_build.json')
BUILD = os.path.join(REPO, 'build')
GEN = os.path.join(REPO, 'demo', 'gen')

CASES = []


def case(name, src, host_hex=''):
    """host_hex: 宿主内存初始化的 hex 字符串 (64 字节)."""
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
    blob_c = os.path.join(GEN, 'vmc_case_runner_blob.c')
    blob_h = os.path.join(GEN, 'vmc_case_runner_blob.h')
    runner_c = os.path.join(BUILD, 'vmc_case_runner.c')
    exe = os.path.join(BUILD, 'vmc_case_runner.exe')

    with open(vmc_src, 'w', encoding='utf-8') as f:
        f.write(src)
    r = subprocess.run([PY, VMC, vmc_src, vmc_vasm,
                        os.path.join(BUILD, 'vmc_case.layout.json')],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return 'COMPILE FAIL: ' + r.stderr.strip()
    r = subprocess.run([PY, VMENC, 'assemble', vmc_vasm, JSON, blob_c, blob_h,
                        '--name', 'g_vmc_case_runner'],
                       capture_output=True, text=True)
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
    clcmd = ('cl /nologo /O2 /W4 /WX /std:c11 /utf-8 '
             '/I "' + os.path.join(REPO, 'include') + '" /I "' + GEN + '" '
             '/Fe:"' + exe + '" '
             '"' + os.path.join(REPO, 'src', 'vm.c') + '" '
             '"' + os.path.join(REPO, 'src', 'crc32.c') + '" '
             '"' + blob_c + '" "' + runner_c + '" /link /SUBSYSTEM:CONSOLE')
    bat = os.path.join(BUILD, 'vmc_cl.bat')
    with open(bat, 'w', encoding='ascii') as f:
        f.write('@echo off\r\ncall "%s" >nul 2>&1\r\n%s\r\n' % (vcvars, clcmd))
    r = subprocess.run([bat], capture_output=True, text=True)
    if r.returncode != 0:
        return 'CL FAIL: ' + (r.stderr or r.stdout or '')[-400:]
    env = dict(os.environ)
    env['VMC_HOST_HEX'] = host_hex or '00'
    p = subprocess.run([exe], capture_output=True, timeout=20, env=env)
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

    # 错误输入必须报错
    err_cases = [
        'uint64 x = y + 1;\n',
        'uint64 x = 1; x = ;\n',
        'unknown_fn(1);\n',
    ]
    for i, src in enumerate(err_cases):
        vmc_src = os.path.join(BUILD, 'vmc_err.vmc')
        with open(vmc_src, 'w', encoding='utf-8') as f:
            f.write(src)
        r = subprocess.run([PY, VMC, vmc_src,
                            os.path.join(BUILD, 'vmc_err.vasm'),
                            os.path.join(BUILD, 'vmc_err.layout.json')],
                           capture_output=True, text=True)
        ok = r.returncode != 0
        print('%-12s  %s' % ('err%d' % (i + 1), 'PASS' if ok else 'FAIL'))
        if not ok:
            failed += 1

    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
