#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""骨架回归工具: `skeleton_check.py`

## 为什么需要（2026-09-23 缺陷的直接教训）
  骨架 strings.txt 缺 19 条 -> **所有 DIY 用户构建失败**，
  而**门禁完全没抓到** —— 因为**门禁从不构建骨架**。

  => 骨架路径（= 用户真正使用的路径）**回归覆盖为零**。

## 本工具做什么
  用**非交互**方式完整走一遍骨架构建（模拟真实用户）:
    1. 造临时工程目录 + build-skeleton.json（字段对齐 prot_wizard）
    2. 复制 skeleton/ 的全部文件
    3. 跑 build_skeleton.ps1
    4. 验证: 产物存在 + smoke PASS

  **不依赖向导**（向导是交互式的，不适合门禁）。

## 用法
  python tools/skeleton_check.py            # 完整回归
  python tools/skeleton_check.py --keep     # 保留临时工程（排障）
  python tools/skeleton_check.py --quiet
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

# 与 prot_wizard.py 写出的字段**保持一致**（否则骨架脚本读不到）
SKEL_FILES = ['app_main.c', 'prot_shell.h', 'strings.txt', 'version.rc',
              'license_hash.vasm', 'license_mix.vasm', 'license_verify.vasm',
              'license_gate.vasm', 'build_skeleton.ps1']

# ⚠️ 业务源文件：向导把 `business_stub.c` **复制为工程专属名**
#    （`business_<app_name>.c`，见 prot_wizard.py L40-52）。
#    初版我只复制 SKEL_FILES（不含业务源）-> cl 找不到 -> 编译失败。
#    （2026-09-23 实测修正。）
BUSINESS_STUB = 'business_stub.c'
BUSINESS_GUI = 'business_stub_gui.c'


def main():
    ap = argparse.ArgumentParser(prog='skeleton_check.py')
    ap.add_argument('--keep', action='store_true', help='保留临时工程')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--composition', default='standard',
                    help='用哪个组合构建骨架（默认 standard）')
    ap.add_argument('--timeout', type=int, default=1800)
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix='skelcheck_')
    try:
        # ---- 1. 造配置（字段对齐 prot_wizard）----
        cfg = {
            'schema': 1,
            'app_name': 'SkelCheck',
            'display_name': 'Skeleton Regression Check',
            'serial': 'DEMO-2026-ABCDEFGH',
            'key_mode': 'new',
            'key_pub_blob': '',
            'lite': False,
            'composition': args.composition,
            'out_dir': os.path.join(tmp, 'build'),
            'repo_path': REPO,
        }
        with open(os.path.join(tmp, 'build-skeleton.json'), 'w',
                  encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        with open(os.path.join(tmp, 'vm_build.json'), 'w',
                  encoding='utf-8') as f:
            json.dump({'serial': cfg['serial'], 'machine_id': 0}, f)

        # ---- 2. 复制 skeleton（照 prot_wizard 的行为）----
        sk = os.path.join(REPO, 'prot_sdk', 'skeleton')
        n = 0
        for fn in SKEL_FILES:
            src = os.path.join(sk, fn)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(tmp, fn))
                n += 1
        # 业务源：`business_stub.c` -> `business_<app_name>.c`
        # （与 prot_wizard.py 的命名规则一致；**否则 cl 找不到业务源**）
        biz_name = 'business_%s.c' % cfg['app_name'].replace('-', '_')
        stub = os.path.join(sk, BUSINESS_STUB)
        if os.path.exists(stub):
            shutil.copy2(stub, os.path.join(tmp, biz_name))
            n += 1
        else:
            print('[skeleton_check] FAIL: 缺业务模板 %s' % BUSINESS_STUB,
                  file=sys.stderr)
            return 1
        # 非 GUI 构建时须排除 GUI stub（build_skeleton.ps1 的逻辑）
        gui_stub = os.path.join(sk, BUSINESS_GUI)
        if os.path.exists(gui_stub):
            shutil.copy2(gui_stub, os.path.join(tmp, BUSINESS_GUI))
            n += 1
        if not args.quiet:
            print('skeleton_check: 复制 %d 个骨架文件（含业务源 %s）'
                  % (n, biz_name))

        # ---- 3. 跑骨架构建 ----
        bs = os.path.join(REPO, 'prot_sdk', 'skeleton', 'build_skeleton.ps1')
        r = winproc.run(['powershell', '-ExecutionPolicy', 'Bypass',
                            '-File', bs, '-Project', tmp],
                           capture_output=True, timeout=args.timeout)
        out = (r.stdout + r.stderr).decode('utf-8', 'replace')

        # ---- 4. 验证 ----
        exe = os.path.join(tmp, 'build', '%s.exe' % cfg['app_name'])
        has_exe = os.path.exists(exe)
        smoke_ok = 'smoke PASS' in out
        done = 'DONE' in out

        if not args.quiet:
            print('  构建 rc=%d  产物=%s  smoke=%s  DONE=%s'
                  % (r.returncode, '✓' if has_exe else '✗',
                     '✓' if smoke_ok else '✗', '✓' if done else '✗'))

        if has_exe and smoke_ok and done:
            if not args.quiet:
                print('[skeleton_check] PASS: 骨架构建成功'
                      '（%d 字节, 组合=%s）'
                      % (os.path.getsize(exe), args.composition))
            return 0

        # 失败 -> 打印**关键诊断**（不刷屏）
        print('[skeleton_check] FAIL: 骨架构建未通过', file=sys.stderr)
        if not has_exe:
            print('  产物未生成: %s' % exe, file=sys.stderr)
        # 提取 FAILED / error 行
        lines = [l.strip() for l in out.split('\n')
                 if re.search(r'FAILED|error:|\[X\]', l)]
        for l in lines[:12]:
            print('  %s' % l[:110], file=sys.stderr)
        if not lines:
            print('  （无明确错误行；末尾 10 行如下）', file=sys.stderr)
            for l in out.strip().split('\n')[-10:]:
                print('  %s' % l[:110], file=sys.stderr)
        return 1
    except subprocess.TimeoutExpired:
        print('[skeleton_check] FAIL: 超时（%ds）' % args.timeout,
              file=sys.stderr)
        return 1
    finally:
        if args.keep:
            print('  （临时工程保留: %s）' % tmp, file=sys.stderr)
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
