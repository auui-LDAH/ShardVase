#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_sdk_standalone.py — 验证 SDK 包**独立可用**（缺口 #4）

## 为什么这是 SDK 发布的**必要环节**
  打包"看起来对"没有意义 —— 必须证明把包放到**独立位置**后能构建。
  这是"套件制作器"定义的核心:
    **用户拿一个包 + 一台装了 VS2022/Python 的机器，就能做出受保护的 exe。**

  若不验证，可能发布一个"看似完整但缺文件"的包 —— 用户拿到后构建失败。

## 方法（严格）
  1. 把 `dist/shardvase-sdk-*/` 复制到**临时目录**（脱离仓库）
  2. 在工程目录造 `build-skeleton.json`（字段对齐 prot_wizard）
  3. 从 `prot_sdk/skeleton/` 复制骨架文件 + 业务源
  4. 用**副本内**的 `build_skeleton.ps1` 构建（**绝不复用原仓库**）
  5. 验证: 产物存在 + smoke PASS + **功能测试（license: 1）**

## 用法
  python tools/verify_sdk_standalone.py
  python tools/verify_sdk_standalone.py --pack dist/shardvase-sdk-1.1.0
  python tools/verify_sdk_standalone.py --keep        # 保留临时目录（排障）
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

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

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 与 prot_wizard.py 一致（骨架脚本依赖这些文件）
SKEL_FILES = ['app_main.c', 'prot_shell.h', 'strings.txt', 'version.rc',
              'license_hash.vasm', 'license_mix.vasm', 'license_verify.vasm',
              'license_gate.vasm', 'build_skeleton.ps1']


def find_pack():
    """找 dist/ 下最新的 SDK 目录（非 zip）。"""
    dist = os.path.join(REPO, 'dist')
    if not os.path.isdir(dist):
        return None
    cands = sorted(d for d in os.listdir(dist)
                   if d.startswith('shardvase-sdk-')
                   and os.path.isdir(os.path.join(dist, d)))
    return os.path.join(dist, cands[-1]) if cands else None


def main():
    ap = argparse.ArgumentParser(prog='verify_sdk_standalone.py')
    ap.add_argument('--pack', default=None, help='SDK 包目录（默认 dist/ 最新）')
    ap.add_argument('--keep', action='store_true', help='保留临时目录')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--timeout', type=int, default=1800)
    args = ap.parse_args()

    pack = args.pack or find_pack()
    if not pack or not os.path.isdir(pack):
        print('[verify_sdk_standalone] FAIL: 找不到 SDK 包'
              '（先跑 tools/sdk_pack.py --force）', file=sys.stderr)
        return 1
    pack = os.path.abspath(pack)
    if not args.quiet:
        print('=== SDK 独立可用性验证 ===')
        print('  源包: %s' % pack)

    # 防误用: 包不能就是仓库本身
    if os.path.abspath(pack) == os.path.abspath(REPO):
        print('[verify_sdk_standalone] FAIL: --pack 指向仓库本身'
              '（本验证要求**脱离仓库**）', file=sys.stderr)
        return 1

    W = tempfile.mkdtemp(prefix='sdkstandalone_')
    sdk = os.path.join(W, 'sdk')
    prj = os.path.join(W, 'myproject')
    try:
        shutil.copytree(pack, sdk)
        os.makedirs(prj, exist_ok=True)
        if not args.quiet:
            print('  独立副本: %s' % sdk)

        # ---- 造工程 ----
        cfg = {
            'schema': 'prot-project/1',
            'app_name': 'StandaloneApp',
            'display_name': 'Standalone Test',
            'serial': 'DEMO-2026-ABCDEFGH',
            'key_mode': 'new',
            'key_pub_blob': '',
            'lite': False,
            'composition': 'standard',
            'out_dir': os.path.join(prj, 'build'),
            # **关键**: 指向**副本**，不是原仓库
            'repo_path': sdk,
        }
        with open(os.path.join(prj, 'build-skeleton.json'), 'w',
                  encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        with open(os.path.join(prj, 'vm_build.json'), 'w',
                  encoding='utf-8') as f:
            json.dump({'serial': cfg['serial'], 'machine_id': 0}, f)

        # ---- 复制骨架（含业务源，命名同向导）----
        skel = os.path.join(sdk, 'prot_sdk', 'skeleton')
        missing = []
        for fn in SKEL_FILES:
            src = os.path.join(skel, fn)
            if not os.path.exists(src):
                missing.append(fn)
                continue
            shutil.copy2(src, os.path.join(prj, fn))
        # 业务源: business_stub.c -> business_<app>.c
        stub = os.path.join(skel, 'business_stub.c')
        if os.path.exists(stub):
            shutil.copy2(stub, os.path.join(
                prj, 'business_%s.c' % cfg['app_name']))
        else:
            missing.append('business_stub.c')
        gui = os.path.join(skel, 'business_stub_gui.c')
        if os.path.exists(gui):
            shutil.copy2(gui, os.path.join(prj, 'business_stub_gui.c'))

        if missing:
            print('[verify_sdk_standalone] FAIL: 包内缺骨架文件: %s'
                  % ', '.join(missing), file=sys.stderr)
            return 1

        # ---- 用副本内的脚本构建 ----
        bs = os.path.join(sdk, 'prot_sdk', 'skeleton', 'build_skeleton.ps1')
        r = winproc.run(['powershell', '-ExecutionPolicy', 'Bypass',
                            '-File', bs, '-Project', prj],
                           capture_output=True, timeout=args.timeout)
        out = (r.stdout + r.stderr).decode('utf-8', 'replace')

        exe = os.path.join(prj, 'build', 'StandaloneApp.exe')
        has_exe = os.path.exists(exe)
        smoke = 'smoke PASS' in out
        done = 'DONE' in out

        if not args.quiet:
            print('  构建 rc=%d  产物=%s  smoke=%s  DONE=%s'
                  % (r.returncode, '✓' if has_exe else '✗',
                     '✓' if smoke else '✗', '✓' if done else '✗'))
            if has_exe:
                print('  产物大小: %d 字节' % os.path.getsize(exe))

        if not (has_exe and smoke and done):
            print('[verify_sdk_standalone] FAIL: SDK 包**不独立**'
                  '—— 脱离仓库后构建失败', file=sys.stderr)
            for l in out.split('\n'):
                if re.search(r'FAILED|error:|\[X\]', l):
                    print('  %s' % l.strip()[:110], file=sys.stderr)
            return 1

        # ---- 功能测试 ----
        lic = os.path.join(prj, 'build', 'license.txt')
        blob = os.path.join(prj, 'build', 'vm.blob')
        if os.path.exists(lic) and os.path.exists(blob):
            rr = winproc.run([exe, '--license-file', lic, '--vm-blob', blob],
                                input=b'DEMO-2026-ABCDEFGH\n',
                                capture_output=True, timeout=120)
            oo = rr.stdout.decode('utf-8', 'replace')
            ok = rr.returncode == 0 and 'license: 1' in oo
            if not args.quiet:
                print('  功能测试: rc=%d  license:1=%s'
                      % (rr.returncode, '✓' if ok else '✗'))
            if not ok:
                print('[verify_sdk_standalone] FAIL: 产物功能不正常',
                      file=sys.stderr)
                return 1

        if not args.quiet:
            print('[verify_sdk_standalone] PASS: SDK 包独立可用'
                  '（脱离原仓库即可构建出受保护的 exe）')
        return 0
    except subprocess.TimeoutExpired:
        print('[verify_sdk_standalone] FAIL: 超时（%ds）' % args.timeout,
              file=sys.stderr)
        return 1
    finally:
        if args.keep:
            print('  （临时目录保留: %s）' % W, file=sys.stderr)
        else:
            shutil.rmtree(W, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
