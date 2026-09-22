# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""
tools/residency_guard.py — 24h 驻留守护 (缓解 SSH 会话断开/进程崩溃)

用途: 反复启动 demo.exe 驻留进程 (--wait-after 24h), 并守护:
  - 每 ~5s 检查目标 demo 进程存活;
  - 进程崩溃/被杀 -> 自动重启 (保持 3 个驻留);
  - 写到 build/residency_guard.log (供 24h 后核对存活率)。

配合计划任务 (开机/登录自启) 实现注册服务等价效果:
  schtasks /create /tn prot_resguard /tr "python tools\\residency_guard.py" /sc onlogon /f
  (再建一个 /sc onstart 变体 -> 开机自启)

用法:
    python tools/residency_guard.py [--instances 3] [--minutes 1440]
"""

import argparse
import datetime
import os
import subprocess
import sys
import time

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
EXE = os.path.join(REPO, 'build', 'demo.exe')
LICENSE = os.path.join(REPO, 'build', 'license.txt')
BLOB = os.path.join(REPO, 'build', 'vm.blob')
JSON = os.path.join(REPO, 'demo', 'vm_build.json')
LOG = os.path.join(REPO, 'build', 'residency_guard.log')


def log(msg):
    with open(LOG, 'a', encoding='utf-8') as f:
        f.write('[%s] %s\n' % (datetime.datetime.now().isoformat(), msg))
    print('[%s] %s' % (datetime.datetime.now().isoformat(), msg), flush=True)


def get_serial():
    import json
    try:
        with open(JSON, 'r', encoding='utf-8') as f:
            return json.load(f)['serial']
    except Exception:
        return 'DEMO-2026-ABCDEFGH'


def main():
    parser = argparse.ArgumentParser(description='24h residency guard')
    parser.add_argument('--instances', type=int, default=3)
    parser.add_argument('--minutes', type=int, default=1440)
    args = parser.parse_args()

    serial = get_serial()
    procs = []  # 仅追踪本守护启动的进程

    def ensure_instances():
        """保证 self-procs 有 instances 个存活; 崩溃则只重启死掉的 (不重复spawn)."""
        alive = [p for p in procs if p.poll() is None]
        # 清理已退出
        for p in list(procs):
            if p.poll() is not None:
                log('demo pid=%d exited rc=%d' % (p.pid, p.returncode))
                procs.remove(p)
        need = args.instances - len(alive)
        for _ in range(need):
            try:
                p = subprocess.Popen(
                    [EXE, '--license-file', LICENSE, '--vm-blob', BLOB,
                     '--wait-after', str(args.minutes * 60000)],
                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, cwd=os.path.dirname(EXE))
                p.stdin.write((serial + '\n').encode())
                p.stdin.flush()
                procs.append(p)
                log('spawn demo pid=%d (tracked=%d)' % (p.pid, len(procs)))
            except Exception as e:
                log('spawn failed: %r' % e)

    log('residency_guard start: instances=%d minutes=%d exe=%s'
        % (args.instances, args.minutes, EXE))
    start = time.time()
    duration = args.minutes * 60
    while time.time() - start < duration:
        ensure_instances()
        time.sleep(10)
    log('residency_guard: finished %d minutes' % args.minutes)
    return 0


if __name__ == '__main__':
    sys.exit(main())