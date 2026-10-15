#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
r"""`tests/attacks_linux.py` — **Linux 独有攻击面验证**（C-1）。

## 依据（实测源码）
  `src/platform/prot_platform_linux.c` 的 `prot_plat_extra_debug_flags()`
  实现**三个 Windows 没有**的检测:
```
① LD_PRELOAD    -> 读 /proc/self/environ 找非空 "LD_PRELOAD="
② 可疑 .so      -> 读 /proc/self/maps 找 /tmp//dev/shm//var/tmp 下的 .so
③ ptrace 自附加 -> ptrace(PTRACE_TRACEME) 失败 = 已被跟踪
```
  汇总进 `antidebug` 报告（`src/antidebug.c` L489-496）:
```
PRELOAD | SUSP_SO  -> report.ppid_blacklist = 1
PTRACED            -> report.debug_object  = 1
```
  demo 的 `--selftest` 打印这两个字段 -> **可作验证判据**。

## 本测试做什么
  · **正向 3 项**: 干净环境下两个字段必须为 0（**不误报**）
  · **负向 3 项**: **真的发起攻击** -> 对应字段必须变 1
    （用"真攻击"证明**防护有效**，而非只证明"代码能跑"）

  ## 纪律（本项目既有）
    · 攻击**在临时目录**做 + **必清理**（`safe-ops-backup` 精神）
    · 每项**独立**（一项失败不影响其余）
    · 输出可解析（供 `verify_linux_runtime` 集成）
"""
import os
import re
import subprocess
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DISTRO = 'Ubuntu-24.04'
EXE = 'build/demo_linux'


def to_wsl(p):
    p = os.path.abspath(p)
    return '/mnt/%s%s' % (p[0].lower(), p[2:].replace('\\', '/'))


def wsl(cmd, timeout=600):
    env = dict(os.environ)
    env['WSL_UTF8'] = '1'
    r = subprocess.run(['wsl.exe', '-d', DISTRO, '--', 'bash', '-c', cmd],
                       capture_output=True, timeout=timeout, env=env)
    return r.returncode, (r.stdout + r.stderr).decode('utf-8', 'replace')


def parse_fields(out):
    """从 demo 输出解析反调试字段。"""
    fields = {}
    for m in re.finditer(r'^\s*([a-z_]+):\s*(\d+)\s*$', out, re.M):
        fields[m.group(1)] = int(m.group(2))
    return fields


def run_demo_selftest(extra_env='', pre=''):
    """跑 demo --selftest，返回解析后的字段。

    ## ⚠️ 环境变量的**位置**至关重要（2026-09-25 实测）
      shell 里 `VAR=x cmd1 | cmd2` 的 `VAR` **只作用于 cmd1**（管道左侧）！
      初版写成:
```
LD_PRELOAD=x.so printf "\\n" | ./demo
```
      -> `LD_PRELOAD` 只作用于 `printf`，**demo 拿到的是空环境**
      -> 检测正确地为 0，却被判为"检测失效"（**差点记录成假缺陷**）。
      修法: 把环境变量放在**管道右侧**（demo 命令之前）。
    """
    rp = to_wsl(REPO)
    cmd = ('cd "%s" && printf "\\n" | %s %s ./%s --selftest '
           '--vm-blob build/linux/vm.blob '
           '--license-file build/linux/license.txt 2>&1'
           % (rp, extra_env, pre, EXE))
    rc, o = wsl(cmd, timeout=600)
    return rc, o, parse_fields(o)


def selftest_positive():
    """**正向**: 干净环境三项必须**不误报**。"""
    rc, o, f = run_demo_selftest()
    results = []
    if not f:
        return [('正向: demo 可运行并输出字段', False, '无字段输出')]
    results.append(('正向: demo 输出反调试字段', True,
                    '%d 个字段' % len(f)))
    # LD_PRELOAD / 可疑 .so -> ppid_blacklist
    results.append(('正向①: 干净环境 **无** LD_PRELOAD/.so 注入'
                    '（ppid_blacklist=0）',
                    f.get('ppid_blacklist') == 0,
                    'ppid_blacklist=%s' % f.get('ppid_blacklist')))
    # ptrace -> debug_object
    results.append(('正向②: 干净环境 **无** ptrace 跟踪'
                    '（debug_object=0）',
                    f.get('debug_object') == 0,
                    'debug_object=%s' % f.get('debug_object')))
    # 其余字段也应干净（不误报）
    noisy = {k: v for k, v in f.items()
             if k not in ('vm_hypervisor', 'vm_vendor') and v != 0}
    results.append(('正向③: 其余反调试字段**全为 0**（不误报）',
                    not noisy, '异常: %s' % (noisy or '无')))
    return results


def attack_preload():
    """**负向①**: 真做 LD_PRELOAD 注入 -> ppid_blacklist 必须变 1。"""
    rp = to_wsl(REPO)
    d = '/tmp/sv_atk_preload'
    # 造一个最小 .so
    setup = ('rm -rf %s && mkdir -p %s && '
             'printf "int sv_marker(void){return 42;}" > %s/x.c && '
             'gcc -shared -fPIC -o %s/x.so %s/x.c 2>/dev/null' 
             % (d, d, d, d, d))
    rc, o = wsl('cd "%s" && %s' % (rp, setup), timeout=600)
    if rc != 0 or 'No such' in o:
        return (False, '无法构造注入库: %s' % o.strip()[-80:])
    rc, o, f = run_demo_selftest(extra_env='LD_PRELOAD=%s/x.so' % d)
    wsl('rm -rf %s' % d)          # **必清理**
    got = f.get('ppid_blacklist')
    return (got == 1,
            'LD_PRELOAD 注入 -> ppid_blacklist=%s（期望 1）' % got)


def attack_susp_so():
    """**负向②**: 放可疑 .so 到 /tmp 并加载 -> ppid_blacklist 必须变 1。"""
    rp = to_wsl(REPO)
    d = '/tmp/sv_atk_so'
    setup = ('rm -rf %s && mkdir -p %s && '
             'printf "int sv_marker2(void){return 7;}" > %s/y.c && '
             'gcc -shared -fPIC -o %s/y.so %s/y.c 2>/dev/null'
             % (d, d, d, d, d))
    rc, o = wsl('cd "%s" && %s' % (rp, setup), timeout=600)
    if rc != 0:
        return (False, '无法构造 .so: %s' % o.strip()[-80:])
    # LD_PRELOAD 会使 /tmp 下的 .so 进入 maps -> 两项检测都可能命中
    rc, o, f = run_demo_selftest(extra_env='LD_PRELOAD=%s/y.so' % d)
    wsl('rm -rf %s' % d)
    got = f.get('ppid_blacklist')
    return (got == 1,
            '可疑 .so（/tmp）-> ppid_blacklist=%s（期望 1）' % got)


def attack_ptrace():
    """**负向③**: 真做 ptrace 附加 -> debug_object 必须变 1。"""
    rp = to_wsl(REPO)
    # 父进程 attach 子进程（子进程跑 demo）—— 用一个小 C 程序做 tracer
    d = '/tmp/sv_atk_trace'
    tracer = r'''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/types.h>

int main(int argc, char** argv)
{
    pid_t pid = fork();
    if (pid == 0) {
        freopen("/dev/null", "r", stdin);
        execv(argv[1], &argv[1]);
        perror("execv");
        _exit(127);
    }
    usleep(100000);
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) {
        perror("PTRACE_ATTACH");
        kill(pid, SIGKILL);
        return 3;
    }
    /* ## ⚠️ 必须 waitpid + PTRACE_CONT（C-1 实测修正）
     *   attach 后子进程**停在 SIGSTOP** ——
     *   若不继续它，直到 tracer 退出才恢复 -> **输出不完整**
     *   -> 测试误判"检测失效"（实测: 加了这两步才拿到完整输出）。 */
    waitpid(pid, NULL, 0);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, NULL, 0);
    return 0;
}
'''
    setup = ('rm -rf %s && mkdir -p %s && cat > %s/tr.c <<\'EOF\'\n%s\nEOF\n'
             'gcc -O0 -o %s/tr %s/tr.c 2>&1 | head -3'
             % (d, d, d, tracer, d, d))
    rc, o = wsl('cd "%s" && %s' % (rp, setup), timeout=600)
    if rc != 0 or 'error' in o:
        return (False, '无法构造 tracer: %s' % o.strip()[-80:])
    # 跑: tracer 启动 demo（**不用 --selftest 的 vm/license**，
    #      因为我们要的是"被 trace 时 demo 报什么"）
    cmd = ('cd "%s" && printf "\\n" | %s/tr ./%s --selftest 2>&1'
           % (rp, d, EXE))
    rc2, o2 = wsl(cmd, timeout=600)
    wsl('rm -rf %s' % d)
    f = parse_fields(o2)
    got = f.get('debug_object')
    det = ('ptrace ATTACH -> debug_object=%s（期望 1）'
           % got if f else
           'ptrace ATTACH -> 无字段（输出: %s）' % o2.strip()[-90:])
    return (got == 1, det)


def run_all(quiet=False):
    rp = to_wsl(REPO)
    rc, o = wsl('cd "%s" && test -x %s && echo READY' % (rp, EXE))
    if 'READY' not in o:
        return None, 'build/demo_linux 不存在（先跑 build.sh）'

    results = []
    results.extend(selftest_positive())
    for name, fn in [('负向①: LD_PRELOAD 注入被检出', attack_preload),
                     ('负向②: 可疑 /tmp/.so 被检出', attack_susp_so),
                     ('负向③: ptrace 附加被检出', attack_ptrace)]:
        try:
            ok, det = fn()
        except Exception as e:                      # noqa: BLE001
            ok, det = False, '异常: %s' % str(e)[:80]
        results.append((name, ok, det))

    if not quiet:
        for name, ok, det in results:
            print('  %s %-44s %s'
                  % ('ok  ' if ok else 'FAIL', name, det[:52]))
    n_ok = sum(1 for _, ok, _ in results if ok)
    return (n_ok, len(results)), None


def main():
    import argparse
    ap = argparse.ArgumentParser(prog='attacks_linux.py')
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()
    res, err = run_all(args.quiet)
    if res is None:
        print('[attacks_linux] FAIL: %s' % err)
        return 1
    n, total = res
    print()
    print('[attacks_linux] %s: %d/%d'
          % ('PASS' if n == total else 'FAIL', n, total))
    return 0 if n == total else 1


if __name__ == '__main__':
    sys.exit(main())
