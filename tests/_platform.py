#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
r"""`tests/_platform.py` — 测试的**平台适配公共层**（S5, 2026-09-25）。

## 为什么抽（**复制即漂移**的实证）
  `tests/e2e.py` 与 `tests/attacks.py` 各自实现了**同一批**平台适配:
```
to_wsl / _norm_exit / _norm_expect / _run_demo_wsl / run_demo(/分派)
```
  **实测漂移证据**: `_run_demo_wsl` 在两处分别是 **28 行 vs 55 行** ——
  同一契约（"经 WSL 直执，stdin/退出码直达"）被实现了两遍，
  C-2 修好的细节（不经 bash / 路径转形态 / 自动补 --vm-blob）
  在 C-3 里**又踩了一遍**才补上。
  => 抽取为**单一来源**（与 §24.2 的 P5 修复同一动机）。

## 本模块的**契约**（被抽取的都是"已验证"的实现）
| 函数 | 契约 |
|------|------|
| `parse_platform(argv)` | 解析 `--platform` 并从 argv **移除**（不传给下游）|
| `to_wsl(p)` | Windows 绝对路径 -> `/mnt/<d>/...` |
| `norm_exit(code)` / `norm_expect(e)` | **平台语义归一化**（Linux 只保留低 8 位）|
| `run_demo_via_wsl(...)` | **不经 bash** 直 exec；路径型参数转 WSL 形态；可选自动补 `--vm-blob` |

  ## 关键设计（**保留既有行为，不改良**）
    · 归一化**不是放宽判据**（低 8 位 vs 低 8 位，精确比较）
    · 直 exec（**不经 bash**）是 C-2 三路对照**验证过**的形态:
      `bash -c` 会**吞掉 stdin**（-> license 验签失败）与**退出码**

## 诚实边界
  · 本模块**只放两处都用**的东西；只一处用的（如 e2e 的 `_Results`）留原处
  · `DISTRO` 固定 `Ubuntu-24.04`（本项目 Linux 环境；换发行版需改此处）
"""
import os
import re
import subprocess
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


#: WSL 发行版（本项目 Linux 侧环境；换发行版只改这里）
DISTRO = 'Ubuntu-24.04'

#: 仓库根（本文件在 tests/ 下）
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def parse_platform(argv, default='win'):
    """从 `argv` 解析 `--platform <win|linux>` 并**移除**该参数。

    ## 为什么移除
      下游（argparse / 被测脚本）**不认识** `--platform`
      -> 不移除会导致 argparse 报错退出 2（**实测踩到**）。
    """
    plat = default
    if '--platform' in argv:
        i = argv.index('--platform')
        if i + 1 < len(argv):
            plat = argv[i + 1]
            del argv[i:i + 2]
    return plat


def to_wsl(p):
    """Windows 绝对路径 -> WSL 路径（`D:\\x` -> `/mnt/d/x`）。"""
    p = os.path.abspath(p)
    return '/mnt/%s%s' % (p[0].lower(), p[2:].replace('\\', '/'))


def norm_exit(code, platform):
    """**平台语义归一化**的退出码。

    · Windows: `ExitProcess(0xB10B)` -> **0xB10B**（完整 32 位）
    · Linux  : `exit(0xB10B)` -> **低 8 位** = **0x0B = 11**（POSIX 语义）

    **不是放宽判据** —— 归一化后仍精确比较（低 8 位 vs 低 8 位）。
    """
    if platform == 'win':
        return code & 0xFFFFFFFF
    return code & 0xFF


def norm_expect(expected, platform):
    """把**期望值**按平台归一化（与 `norm_exit` 配对使用）。"""
    if platform == 'win':
        return expected & 0xFFFFFFFF
    return expected & 0xFF


def fix_path_args(args):
    """把**看起来是 Windows 绝对路径**的参数转成 WSL 形态。

    ## 为什么必须做（**实测**）
      `--license-file D:\\...\\license.txt` 传给 **WSL 里的** demo ->
      demo **打不开** -> `license: 0`（验签失败）-> 误判为"验签失效"。
      （与 A 阶段"路径的**来源**与**形态**要同时考虑"同一教训。）
    """
    out = []
    for a in (args or []):
        if (isinstance(a, str) and len(a) > 2 and a[1] == ':'
                and a[2] in ('\\', '/')):
            out.append(to_wsl(a))
        else:
            out.append(a)
    return out


def run_demo_via_wsl(exe, args=None, stdin=None, timeout=60,
                     extra_env='', pre='', auto_vm_blob=True,
                     vm_blob_path=None):
    """经 WSL **直执** demo；返回 `(returncode, stdout, stderr)`。

    ## ⚠️ **不经 bash**（C-2 三路对照验证过）
```
      bash -c "cd ... && exec demo ..." 会**吞掉 stdin**（-> license: 0）
      以及**退出码**
```
      => 用 `wsl.exe --cd <dir> -- <exe> <args>` 直 exec。

    ## 参数
      · `auto_vm_blob=True` 时若未传 `--vm-blob` 则自动补
        （Windows 侧 cwd 恰好在 build/ 能找到 blob；Linux 侧不能 ->
         **平台差异由本适配层吸收**）
      · `extra_env`/`pre`: 预留（当前用于调试；不参与正式路径）
    """
    args = fix_path_args(list(args or []))
    if auto_vm_blob and vm_blob_path and '--vm-blob' not in args:
        args += ['--vm-blob', to_wsl(vm_blob_path)]
    env = dict(os.environ)
    env['WSL_UTF8'] = '1'
    cmd = ['wsl.exe', '-d', DISTRO, '--cd',
           to_wsl(os.path.dirname(exe)), '--', to_wsl(exe)] + args
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env)
    out, err = p.communicate(stdin, timeout=timeout)
    return (p.returncode,
            (out or b'').decode('utf-8', 'replace'),
            (err or b'').decode('utf-8', 'replace'))


# ---------------------------------------------------------------------------
# WSL 内的 mock 服务器（W4, 2026-09-25 —— e2e 的在线用例与 attacks 的 A12 共用）
# ---------------------------------------------------------------------------


class WslMockServer(object):
    """**WSL 内**的 mock 服务器句柄。

    ## 为什么需要
      Linux 侧的 demo **在 WSL 内**，而 mock 若跑在 Windows Python，
      **WSL 的 127.0.0.1 不等于 Windows 的**（实测 curl rc=7）——
      demo 永远连不上。 => 服务器必须**也进 WSL**（同 loopback 才通）。

    ## 接口与 `http.server.HTTPServer` **对齐**（`server_address` / `shutdown`）
      调用方**只用这两个** -> 实现同接口即可**不动调用方**
      （**适配层吸收差异**，与 A 阶段平台层同一做法）。
    """

    def __init__(self, proc, port):
        self._proc = proc
        self.server_address = ('127.0.0.1', port)

    def shutdown(self):
        """杀掉 WSL 内的服务进程（**必做**，否则端口/进程泄漏）。"""
        try:
            self._proc.terminate()
            self._proc.wait(timeout=5)
        except Exception:                     # noqa: BLE001
            try:
                self._proc.kill()
            except Exception:                 # noqa: BLE001
                pass


def start_wsl_mock(extra_args, repo=None, distro=None, timeout=30):
    """在 **WSL 内**起 `tools/mock_http.py`，返回 `WslMockServer`。

    ## 协议（与 `tools/mock_http.py` 对齐）
      启动 -> **stdout 第一行 `PORT=<n>`** -> 本函数读它。

    ## ⚠️ 参数**必须用命令行**（§32.2 实测教训）
      Windows 环境变量**不自动进入 WSL**（需 `WSLENV`）——
      用环境变量传参**会静默丢失**（服务器永不吊销 -> 假通过/假失败）。

    ## 用法
      `start_wsl_mock(['--mode', 'check', '--revoke-serial', serial])`
      `start_wsl_mock(['--mode', 'expect', '--wrong'])`
      `start_wsl_mock(['--mode', 'blob', '--blob-file', to_wsl(path)])`
    """
    import subprocess as _sp
    import time as _time

    repo = repo or REPO
    distro = distro or DISTRO
    cmd = ['wsl.exe', '-d', distro, '--', 'python3',
           'tools/mock_http.py'] + list(extra_args)
    env = dict(os.environ)
    env['WSL_UTF8'] = '1'
    proc = _sp.Popen(cmd, stdout=_sp.PIPE, stderr=_sp.STDOUT,
                     cwd=repo, env=env)
    t0 = _time.time()
    port = None
    while _time.time() - t0 < timeout:
        line = proc.stdout.readline()
        if not line:
            break
        m = re.match(r'PORT=(\d+)', line.decode('utf-8', 'replace').strip())
        if m:
            port = int(m.group(1))
            break
    if port is None:
        try:
            proc.terminate()
        except Exception:                     # noqa: BLE001
            pass
        raise RuntimeError('WSL mock 未返回 PORT（环境问题）')
    return WslMockServer(proc, port)


# ---------------------------------------------------------------------------
# 自检（`python tests/_platform.py --selftest`）
# ---------------------------------------------------------------------------
def _selftest():
    """自检: 归一化边界 + 路径转换 + 参数处理（**含负向**）。"""
    fails = []

    def case(name, ok):
        print('  %s %-52s' % ('ok ' if ok else '**FAIL**', name))
        if not ok:
            fails.append(name)

    print('=== _platform 自检 ===')

    # T1 归一化: Linux 低 8 位
    case('T1 norm_exit(0xB10B, linux) == 0x0B',
         norm_exit(0xB10B, 'linux') == 0x0B)
    # T2 归一化: Windows 全 32 位
    case('T2 norm_exit(0xB10B, win) == 0xB10B',
         norm_exit(0xB10B, 'win') == 0xB10B)
    # T3 **负向**: 两平台**不应**相等（否则归一化无意义）
    case('T3 **负向**: 两平台归一化结果**不同**',
         norm_exit(0xB10B, 'linux') != norm_exit(0xB10B, 'win'))
    # T4 expect 配对
    case('T4 norm_expect 与 norm_exit 配对一致',
         norm_expect(0xBAD, 'linux') == norm_exit(0xBAD, 'linux'))
    # T5 路径转换
    w = to_wsl('D:\\a b\\c.txt')
    case('T5 to_wsl 处理盘符与空格', w == '/mnt/d/a b/c.txt')
    # T6 路径参数转换（含**非路径**参数不受影响）
    fa = fix_path_args(['--license-file', 'D:\\x.txt', '--flag', 'plain'])
    case('T6 fix_path_args 只转路径型',
         fa == ['--license-file', '/mnt/d/x.txt', '--flag', 'plain'])
    # T7 **负向**: 已转换的路径**不重复转换**
    fa2 = fix_path_args(['/mnt/d/x.txt'])
    case('T7 **负向**: WSL 路径不被二次转换',
         fa2 == ['/mnt/d/x.txt'])
    # T8 parse_platform 移除参数
    av = ['prog', '--platform', 'linux', '--other']
    p = parse_platform(av)
    case('T8 parse_platform 解析并移除',
         p == 'linux' and av == ['prog', '--other'])
    # T9 **负向**: 无 --platform 时用默认
    av2 = ['prog']
    case('T9 **负向**: 缺参数时用默认 win',
         parse_platform(av2) == 'win' and av2 == ['prog'])

    print()
    print('=' * 62)
    if fails:
        print('[_platform-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    print('[_platform-selftest] PASS: 9 项（含 3 负向）')
    return 0


if __name__ == '__main__':
    if '--selftest' in sys.argv:
        sys.exit(_selftest())
    print('usage: python tests/_platform.py --selftest')
    sys.exit(0)
