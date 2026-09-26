#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_linux.py — 在 WSL 内验证 Linux 平台层（L5c）

## 为什么需要
  Linux 平台层的**验收判据**是 `tests/platform_conformance.c`（L4-A 设计）。
  本脚本把它跑起来 —— 从 Windows 侧一键调用 WSL。

## 为什么用 Python 而非 PowerShell
  PowerShell 会**抢先解析** `$(...)`、引号、反斜杠 ——
  传给 `wsl.exe` 的 bash 命令会被**改写**（本项目已多次踩坑）。
  Python 的 subprocess 参数**原样传递**，无此问题。

## 前置
  · WSL 已安装（`wsl --version` 可用）
  · 有 Ubuntu 发行版（默认 `Ubuntu-24.04`）
  · 发行版内有 gcc

## 用法
  python tools/verify_linux.py                 # 跑契约测试
  python tools/verify_linux.py --distro Kali   # 指定发行版
  python tools/verify_linux.py --list          # 列出可用发行版
"""
import argparse
import os
import subprocess
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DISTRO = 'Ubuntu-24.04'

# 契约测试需要的编译参数
CFLAGS = '-O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE'


def to_wsl_path(win_path):
    """Windows 路径 -> WSL /mnt 路径。"""
    p = os.path.abspath(win_path)
    drive = p[0].lower()
    rest = p[2:].replace('\\', '/')
    return '/mnt/%s%s' % (drive, rest)


def wsl(args, timeout=1800):
    env = dict(os.environ)
    env['WSL_UTF8'] = '1'
    r = subprocess.run(['wsl.exe'] + args, capture_output=True,
                       timeout=timeout, env=env)
    return (r.returncode,
            r.stdout.decode('utf-8', 'replace')
            + r.stderr.decode('utf-8', 'replace'))


def main():
    ap = argparse.ArgumentParser(prog='verify_linux.py')
    ap.add_argument('--distro', default=DEFAULT_DISTRO)
    ap.add_argument('--list', action='store_true', help='列出发行版')
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    if args.list:
        rc, out = wsl(['--list', '--verbose'], timeout=120)
        print(out)
        return rc

    # ---- 0. WSL 可用性 ----
    rc, out = wsl(['--version'], timeout=120)
    if rc != 0 or 'WSL' not in out:
        print('[verify_linux] SKIP: WSL 不可用（未安装或未启动）',
              file=sys.stderr)
        return 2

    repo_wsl = to_wsl_path(REPO)
    if not args.quiet:
        print('=== Linux 平台层验证（L5c）===')
        print('  仓库（WSL 路径）: %s' % repo_wsl)
        print('  发行版: %s' % args.distro)
        print()

    # ---- 1. Linux 平台层是否存在 ----
    script = '''
set -u
cd "%s" || { echo "REPO_NOT_FOUND"; exit 1; }
if [ ! -f src/platform/prot_platform_linux.c ]; then
    echo "PLATFORM_NOT_IMPLEMENTED"
    exit 1
fi
echo "GCC=$(gcc --version | head -1)"
rm -rf /tmp/l5c_verify && mkdir -p /tmp/l5c_verify
gcc %s -I include tests/platform_conformance.c \\
    src/platform/prot_platform_linux.c \\
    -o /tmp/l5c_verify/platconf || { echo "COMPILE_FAILED"; exit 1; }
echo "COMPILE_OK"
/tmp/l5c_verify/platconf
''' % (repo_wsl, CFLAGS)

    rc, out = wsl(['-d', args.distro, '--', 'bash', '-c', script])

    # ---- 2. 解析结果 ----
    if 'PLATFORM_NOT_IMPLEMENTED' in out:
        print('[verify_linux] FAIL: Linux 平台层尚未实现',
              file=sys.stderr)
        return 1
    if 'REPO_NOT_FOUND' in out:
        print('[verify_linux] FAIL: WSL 内找不到仓库 %s' % repo_wsl,
              file=sys.stderr)
        return 1
    if 'COMPILE_FAILED' in out:
        print('[verify_linux] FAIL: 编译失败', file=sys.stderr)
        for line in out.split('\n'):
            if 'error' in line.lower():
                print('  %s' % line.strip()[:110], file=sys.stderr)
        return 1

    if not args.quiet:
        for line in out.split('\n'):
            s = line.rstrip()
            # 跳过 WSL 的代理提示
            if 'localhost' in s and 'WSL' in s:
                continue
            if s.strip():
                print('  %s' % s)

    ok = (rc == 0) and ('PASS: 契约合规' in out)
    if not args.quiet:
        print()
    print('[verify_linux] %s: Linux 平台层%s'
          % ('PASS' if ok else 'FAIL',
             '契约合规' if ok else '契约违规'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
