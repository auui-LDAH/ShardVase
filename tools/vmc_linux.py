#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""`tools/vmc_linux.py` — **VM 合约测试的 Linux 移植**（固化）。

## 依据（`tests/vmc_tests.py`，权威）
```
① tools/vmc.py <case.vmc> <out.vasm> <layout.json> --seed 0x1234 --flatten
② vmenc assemble <vasm> <json> <blob.c> <blob.h> --name g_vmc_case_runner
③ 编译 runner: src/vm.c + src/crc32.c + 平台层 + runner.c
④ 运行 -> "RESULT 1" = 用例通过
```

## 平台差异（**唯一一处**）
  `RUNNER_TMPL` 用 MSVC 的 **`sscanf_s`**（Linux 无）-> 生成 runner 时
  改为**自包含十六进制解析**。
  **为什么不加 `PROT_SSCANF` 宏**: 只有测试脚手架用 ->
  为测试**污染产品头文件**不值得。

## 数据源复用（**关键纪律**）
  用例**直接 exec `tests/vmc_tests.py` 的定义段**取得 `CASES` ——
  **不重新解析源码**。
  ## 教训: 我先前用正则解析 -> `mem` 的
    `'34120000' + '00' * 4 + 'cdab000000000000'`
    被截断成 `34120000` -> 用例 FAIL（**正则重复了数据源，必然漂移**）。

## 诚实边界
  · 只跑**功能用例**（arith/logic/ifelse/loop/mem/expect）；
    原测试的**错误用例**（语法错误应被拒）**未移植**（记为后续）
  · 需要 `demo/vm_build.json`（用于 assemble 的 EXPECT1/2）
"""
import argparse
import json
import os
import re
import subprocess
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DISTRO = 'Ubuntu-24.04'

# ## 可移植 runner（替换 sscanf_s）
RUNNER_TMPL = r'''/* vmc case runner（**可移植版**，2026-09-25）
 *
 * 与 tests/vmc_tests.py 的 RUNNER_TMPL 等价，唯一差异:
 *   原用 MSVC 的 `sscanf_s`（Linux 无）-> 改为**自包含十六进制解析**。
 *   理由: 测试脚手架（生成物），不为它扩展平台层接口。
 */
#include "protect/vm.h"
#include "vmc_case_runner_blob.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t host[0x4000];

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int main(void)
{
    const char* init = getenv("VMC_HOST_HEX");
    if (init != NULL) {
        size_t n = strlen(init);
        size_t skip = (n >= 2 && init[0] == '0'
                       && (init[1] == 'x' || init[1] == 'X')) ? 2 : 0;
        size_t i;
        size_t len = (n - skip) / 2;
        if (len > sizeof(host)) len = sizeof(host);
        for (i = 0; i < len; i++) {
            int hi = hexval((unsigned char)init[skip + i * 2]);
            int lo = hexval((unsigned char)init[skip + i * 2 + 1]);
            if (hi < 0 || lo < 0) break;
            host[i] = (uint8_t)((hi << 4) | lo);
        }
    }
    {
        prot_status st = prot_vm_run(&g_vmc_case_runner, host, sizeof(host));
        uint32_t r;
        if (st != PROT_OK) {
            printf("RUNFAIL %d\n", (int)st);
            return 1;
        }
        memcpy(&r, host + 52, 4);
        printf("RESULT %u\n", r);
    }
    return 0;
}
'''


def load_err_cases():
    """从 `tests/vmc_tests.py` 提取**错误用例**（应被编译器拒绝）。

    ## 为什么用"正则提取源码"而非 exec
      这些用例是 `main()` 内的**局部变量** `err_cases` ——
      无法通过 exec 模块取值（函数体不执行）。
      => 正则提取**是该数据源的唯一可行方式**。

      ## 防漂移措施（**关键**）
        · **断言数量**（预期 3 个）—— 数量变化 -> 显式失败而非静默漏测
        · 打印提取内容，便于人工核对
    """
    p = os.path.join(REPO, 'tests', 'vmc_tests.py')
    src = open(p, encoding='utf-8', errors='replace').read()
    m = re.search(r'err_cases\s*=\s*\[(.*?)\]', src, re.S)
    if not m:
        return None, '未找到 err_cases 列表'
    body = m.group(1)
    # 提取每个 '...' 字面量（含 \n 转义）
    items = re.findall(r"'((?:[^'\\]|\\.)*)'", body)
    cases = []
    for it in items:
        try:
            cases.append(it.encode('utf-8').decode('unicode_escape'))
        except Exception:                       # noqa: BLE001
            cases.append(it.replace('\\n', '\n'))
    if len(cases) != 3:
        return None, ('err_cases 数量异常: 期望 3，实得 %d '
                      '（数据源可能已变，需人工核对）' % len(cases))
    return cases, None


def run_err_cases(quiet=False):
    """错误用例: **应被 vmc.py 拒绝**（返回码非 0）。"""
    cases, err = load_err_cases()
    if cases is None:
        return None, err
    rp = to_wsl(REPO)
    out_dir = os.path.join(REPO, 'build', 'vmc_linux')
    os.makedirs(out_dir, exist_ok=True)
    n_ok, details = 0, []
    # vmc.py 的错误输出通常走 stderr；捕获以便诊断
    src_path = os.path.join(out_dir, 'err.vmc')
    for i, src in enumerate(cases):
        with open(src_path, 'w', encoding='utf-8', newline='\n') as f:
            f.write(src)
        # **直执**取真实退出码（不套 shell —— 见 wsl_direct 的教训）
        code, o = wsl_direct(['python3', 'tools/vmc.py',
                              'build/vmc_linux/err.vmc',
                              'build/vmc_linux/err.vasm',
                              'build/vmc_linux/err.layout.json'],
                             timeout=300)
        # **负向判据**: 非 0 = 正确拒绝
        if code != 0:
            n_ok += 1
        else:
            details.append('err%d 未被拒绝（RC=0）' % (i + 1))
        if not quiet:
            print('  err%-7d %s   (vmc RC=%d)'
                  % (i + 1, 'PASS' if code != 0 else 'FAIL', code))
    return (n_ok, len(cases)), ('; '.join(details) if details else '全部被拒绝')


def vm_build_json():
    """Linux 的 vm_build.json（A-d）。"""
    sys.path.insert(0, os.path.join(REPO, 'tools'))
    import genpaths
    return genpaths.paths('linux').vm_build_json


def to_wsl(p):
    p = os.path.abspath(p)
    return '/mnt/%s%s' % (p[0].lower(), p[2:].replace('\\', '/'))


def wsl_direct(argv, timeout=1800):
    """**直接执行**（不套 shell）—— 返回 (returncode, 输出)。

    ## ⚠️ 为什么必须直执（2026-09-25 实测教训）
      `bash -c "cmd; echo RC=$?"` 读到的是 **shell 最后一句话**的退出码，
      不是被测进程的 —— 实测把 `vmc.py` 的 `return 1`（**正确报错**）
      读成了 **0**，导致**误判"vmc 不报错"**（差点记录成假缺陷）。

      => **要读被测进程退出码，就用 `wsl.exe -- <cmd>` 直执**。

      ## 与既有教训同类
        `release_check.ps1` 的 `Check` 也曾因"取错值"而**谎报通过**
        （见该文件的"严重教训"注释）。
    """
    env = dict(os.environ)
    env['WSL_UTF8'] = '1'
    r = subprocess.run(['wsl.exe', '-d', DISTRO, '--'] + list(argv),
                       capture_output=True, timeout=timeout, env=env,
                       cwd=REPO)
    return r.returncode, (r.stdout + r.stderr).decode('utf-8', 'replace')


def wsl(cmd, timeout=1800):
    env = dict(os.environ)
    env['WSL_UTF8'] = '1'
    r = subprocess.run(['wsl.exe', '-d', DISTRO, '--', 'bash', '-c', cmd],
                       capture_output=True, timeout=timeout, env=env)
    return r.returncode, (r.stdout + r.stderr).decode('utf-8', 'replace')


def load_cases():
    """**复用权威数据源**: exec `tests/vmc_tests.py` 的定义段取 CASES。

    **不重新解析源码** —— 那会重复数据源并随源码演进而漂移
    （实测: 正则把 `mem` 的拼接表达式截断 -> 用例 FAIL）。
    """
    p = os.path.join(REPO, 'tests', 'vmc_tests.py')
    src = open(p, encoding='utf-8', errors='replace').read()
    cut = src.find('RUNNER_TMPL')
    head = src[:cut] if cut > 0 else src
    ns = {'__name__': 'vmc_head', '__file__': p}
    sys.path.insert(0, os.path.join(REPO, 'tools'))
    sys.path.insert(0, os.path.join(REPO, 'tests'))
    exec(compile(head, 'vmc_head', 'exec'), ns)
    return ns['CASES']


def run_all(quiet=False):
    rp = to_wsl(REPO)
    out_dir = os.path.join(REPO, 'build', 'vmc_linux')
    os.makedirs(out_dir, exist_ok=True)
    runner = os.path.join(out_dir, 'runner.c')
    with open(runner, 'w', encoding='utf-8', newline='\n') as f:
        f.write(RUNNER_TMPL)

    try:
        cases = load_cases()
    except Exception as e:                      # noqa: BLE001
        return None, '无法取得 CASES: %s' % str(e)[:100]

    n_pass, details = 0, []
    for name, body, host_hex in cases:
        with open(os.path.join(out_dir, 'case.vmc'), 'w',
                  encoding='utf-8', newline='\n') as f:
            f.write(body)
        wsl('cd "%s" && python3 tools/vmc.py build/vmc_linux/case.vmc '
            'build/vmc_linux/case.vasm build/vmc_linux/layout.json '
            '--seed 0x1234 --flatten >/dev/null 2>&1' % rp)
        wsl('cd "%s" && python3 tools/vmenc.py assemble '
            'build/vmc_linux/case.vasm "%s" '
            'build/vmc_linux/vmc_case_runner_blob.c '
            'build/vmc_linux/vmc_case_runner_blob.h '
            '--name g_vmc_case_runner >/dev/null 2>&1'
            % (rp, to_wsl(vm_build_json())))
        rc, o = wsl('cd "%s" && gcc -O2 -Wall -Wextra -Werror -std=c11 '
                    '-D_GNU_SOURCE -I include -I build/vmc_linux '
                    '-o build/vmc_linux/runner '
                    'src/vm.c src/crc32.c src/platform/prot_platform_linux.c '
                    'src/platform/prot_crypto_linux.c '
                    'build/vmc_linux/vmc_case_runner_blob.c '
                    'build/vmc_linux/runner.c -lcrypto -lpthread 2>&1 '
                    '| head -4' % rp)
        if rc != 0:
            details.append('%s: 编译失败' % name)
            continue
        rc, o = wsl('cd "%s" && VMC_HOST_HEX=%s ./build/vmc_linux/runner '
                    '2>&1 | tail -1' % (rp, host_hex), timeout=300)
        lines = [l for l in o.split('\n')
                 if l.strip() and 'localhost' not in l]
        res = lines[-1] if lines else ''
        if res.startswith('RESULT 1'):
            n_pass += 1
        else:
            details.append('%s: %s' % (name, res[:40]))
        if not quiet:
            print('  %-9s %s   (%s)'
                  % (name, 'PASS' if res.startswith('RESULT 1') else 'FAIL',
                     res[:48]))

    return (n_pass, len(cases)), ('; '.join(details) if details else '全部通过')


def selftest():
    """负向自检: **必须能报出失败**（否则只是装饰）。

    做法: 跑一个**断言必然为假**的用例（`return 0;`）——
    期望 `RESULT 0`（非 1）-> 该用例应 FAIL。
    """
    rp = to_wsl(REPO)
    out_dir = os.path.join(REPO, 'build', 'vmc_linux')
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, 'runner.c'), 'w',
              encoding='utf-8', newline='\n') as f:
        f.write(RUNNER_TMPL)
    # 断言为假的用例
    with open(os.path.join(out_dir, 'case.vmc'), 'w',
              encoding='utf-8', newline='\n') as f:
        f.write('uint64 x = 1;\nreturn 0;\n')
    wsl('cd "%s" && python3 tools/vmc.py build/vmc_linux/case.vmc '
        'build/vmc_linux/case.vasm build/vmc_linux/layout.json '
        '--seed 0x1234 --flatten >/dev/null 2>&1' % rp)
    wsl('cd "%s" && python3 tools/vmenc.py assemble '
        'build/vmc_linux/case.vasm "%s" '
        'build/vmc_linux/vmc_case_runner_blob.c '
        'build/vmc_linux/vmc_case_runner_blob.h '
        '--name g_vmc_case_runner >/dev/null 2>&1'
        % (rp, to_wsl(vm_build_json())))
    rc, o = wsl('cd "%s" && gcc -O2 -Wall -Wextra -Werror -std=c11 '
                '-D_GNU_SOURCE -I include -I build/vmc_linux '
                '-o build/vmc_linux/runner '
                'src/vm.c src/crc32.c src/platform/prot_platform_linux.c '
                'src/platform/prot_crypto_linux.c '
                'build/vmc_linux/vmc_case_runner_blob.c '
                'build/vmc_linux/runner.c -lcrypto -lpthread 2>&1 | head -4'
                % rp)
    if rc != 0:
        print('  **FAIL** T1 负向用例编译失败: %s' % o.strip()[-70:])
        return 1
    rc, o = wsl('cd "%s" && VMC_HOST_HEX= ./build/vmc_linux/runner 2>&1 '
                '| tail -1' % rp, timeout=300)
    lines = [l for l in o.split('\n')
             if l.strip() and 'localhost' not in l]
    res = lines[-1] if lines else ''
    ok = not res.startswith('RESULT 1')      # **负向**: 不应为 1
    print('  %s T1 假断言用例被正确判为**不通过**（%s）'
          % ('ok ' if ok else '**FAIL**', res[:40]))
    print()
    print('=' * 62)
    print('[vmc_linux-selftest] %s' % ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(prog='vmc_linux.py')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--selftest', action='store_true',
                    help='负向自检（证明能判错）')
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    res, detail = run_all(args.quiet)
    if res is None:
        print('[vmc_linux] FAIL: %s' % detail)
        return 1
    n, total = res

    # **错误用例**（负向契约: 坏输入必须被拒绝）
    if not args.quiet:
        print()
        print('--- 错误用例（应被拒绝）---')
    eres, edetail = run_err_cases(args.quiet)
    if eres is None:
        print()
        print('[vmc_linux] FAIL: 错误用例: %s' % edetail)
        return 1
    en, etotal = eres

    print()
    print('[vmc_linux] %s: 功能 %d/%d, 错误 %d/%d'
          % ('PASS' if (n == total and en == etotal) else 'FAIL',
             n, total, en, etotal))
    if n != total:
        print('  功能详情: %s' % detail)
    if en != etotal:
        print('  错误用例详情: %s' % edetail)
    return 0 if (n == total and en == etotal) else 1


if __name__ == '__main__':
    sys.exit(main())
