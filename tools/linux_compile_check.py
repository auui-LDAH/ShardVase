#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""M1-A0: `tools/linux_compile_check.py` —— Linux 编译覆盖率检查（正式工具）

## 为什么固化（从 L6b 的临时脚本升级）
  L6b 用的是**临时脚本**（在 %TEMP% 里），问题:
    · 不可入库 -> 无法进 CI
    · 无自检 -> 违反"未验证 != 通过"
    · 无结构化输出 -> CI 无法消费

## 本工具的职责
  ① 逐个源文件在 **WSL/Linux** 上 `gcc -c -Werror` 编译
  ② 输出**覆盖率**（N/18）+ **失败原因分类**
  ③ **自检**: 用已知失败的输入验证"能报出失败"
  ④ `--json` 输出（供 CI / 门禁消费）

## 依赖
  WSL + 发行版（默认 Ubuntu-24.04）+ 该发行版内有 gcc

## 用法
  python tools/linux_compile_check.py                 # 人类可读报告
  python tools/linux_compile_check.py --json          # JSON（CI 用）
  python tools/linux_compile_check.py --selftest      # 负向自检
  python tools/linux_compile_check.py --min 13        # 覆盖率下限（门禁用）
"""
import argparse
import json
import os
import re
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


if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DISTRO = 'Ubuntu-24.04'

# 编译参数（与 Windows 的 /W4 /WX 对应）
CFLAGS = '-c -O2 -Wall -Wextra -Werror -std=c11 -D_GNU_SOURCE'

# 扫描哪些目录
SCAN_DIRS = ['src']

# 排除（模板/非构建文件）
EXCLUDE = ('_template.c',)


def to_wsl_path(win_path):
    p = os.path.abspath(win_path)
    drive = p[0].lower()
    rest = p[2:].replace('\\', '/')
    return '/mnt/%s%s' % (drive, rest)


def collect_sources():
    """收集待检查的源文件（相对仓库路径，正斜杠）。"""
    out = []
    for d in SCAN_DIRS:
        base = os.path.join(REPO, d)
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            dirs[:] = [x for x in dirs if x != '__pycache__']
            for f in sorted(files):
                if not f.endswith('.c'):
                    continue
                if f in EXCLUDE:
                    continue
                rel = os.path.relpath(os.path.join(root, f), REPO)
                out.append(rel.replace('\\', '/'))
    return sorted(out)


def classify(errors_text):
    """把编译错误归类（便于统计与定位）。"""
    kinds = []
    if re.search(r'windows\.h|winioctl\.h|bcrypt\.h|tlhelp32\.h|'
                 r'psapi\.h|intrin\.h|winternl\.h', errors_text):
        kinds.append('WINDOWS_HEADER')
    if re.search(r'\b__try\b|\b__except\b|\b__finally\b', errors_text):
        kinds.append('SEH')
    if re.search(r'IMAGE_[A-Z_]', errors_text):
        kinds.append('PE_STRUCT')
    if re.search(r'\bNt(Query|Set)\w+', errors_text):
        kinds.append('NT_NATIVE')
    if re.search(r'\bDWORD\b|\bHANDLE\b|\bBOOL\b|\bHMODULE\b', errors_text):
        kinds.append('WIN_TYPE')
    if re.search(r'fopen_s|__nop|__cpuid|__rdtsc|__declspec|code_seg',
                 errors_text):
        kinds.append('MSVC_ONLY')
    if not kinds:
        kinds.append('OTHER')
    return kinds


def check_one(rel, distro='Ubuntu-24.04'):
    """编译单个文件。返回 (ok, error_text, kinds)。"""
    repo_wsl = to_wsl_path(REPO)
    script = ('cd "%s" && gcc %s -I include "%s" -o /tmp/lcc.o 2>&1'
              % (repo_wsl, CFLAGS, rel))
    env = dict(os.environ)
    env['WSL_UTF8'] = '1'
    try:
        r = winproc.run(
            ['wsl.exe', '-d', distro, '--', 'bash', '-c', script],
            capture_output=True, timeout=300, env=env)
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, 'invoke failed: %s' % e, ['INVOKE_FAILED']
    out = (r.stdout + r.stderr).decode('utf-8', 'replace')
    ok = (r.returncode == 0)
    return ok, ('' if ok else out), ([] if ok else classify(out))


def check_all(distro='Ubuntu-24.04', quiet=False):
    """检查全部源文件。返回 dict 结果。"""
    srcs = collect_sources()
    results = {}
    for rel in srcs:
        ok, err, kinds = check_one(rel, distro)
        results[rel] = {'ok': ok, 'kinds': kinds,
                        'first_error': (err.strip().split('\n')[0][:200]
                                        if err else '')}
        if not quiet:
            mark = 'OK  ' if ok else 'FAIL'
            extra = ('  [%s]' % ','.join(kinds)) if kinds else ''
            print('  %-42s %s%s' % (rel, mark, extra))
    n_ok = sum(1 for v in results.values() if v['ok'])
    return {'total': len(srcs), 'ok': n_ok,
            'rates': '%d/%d' % (n_ok, len(srcs)), 'results': results}


def main():
    ap = argparse.ArgumentParser(prog='linux_compile_check.py')
    ap.add_argument('--distro', default=DEFAULT_DISTRO)
    ap.add_argument('--json', action='store_true', help='JSON 输出')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--min', type=int, default=None,
                    help='覆盖率下限（不足则退出码非 0）')
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    r = check_all(args.distro, quiet=(args.quiet or args.json))

    if args.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    elif not args.quiet:
        print()
        print('=' * 66)
        print('  Linux 编译覆盖率: **%s**' % r['rates'])
        # 失败原因统计
        reasons = {}
        for rel, v in r['results'].items():
            if v['ok']:
                continue
            for k in v['kinds']:
                reasons[k] = reasons.get(k, 0) + 1
        if reasons:
            print()
            print('  失败原因:')
            for k, n in sorted(reasons.items(), key=lambda x: -x[1]):
                print('    %-16s %d' % (k, n))
        print('=' * 66)

    if args.min is not None and r['ok'] < args.min:
        print('[linux_compile_check] FAIL: 覆盖率 %s < 下限 %d'
              % (r['rates'], args.min), file=sys.stderr)
        return 1
    return 0


def selftest():
    """负向自检: 必须能**报出失败**（否则只是装饰）。"""
    import tempfile
    fails = []

    def case(name, ok):
        print('  %s %-56s' % ('ok ' if ok else '**FAIL**', name))
        if not ok:
            fails.append(name)

    print('=== linux_compile_check 自检 ===')
    print()

    # T1: WSL 可用
    env = dict(os.environ)
    env['WSL_UTF8'] = '1'
    try:
        r = winproc.run(['wsl.exe', '--version'], capture_output=True,
                           timeout=120, env=env)
        wsl_ok = (r.returncode == 0)
    except (subprocess.TimeoutExpired, OSError):
        wsl_ok = False
    case('T1 WSL 可用', wsl_ok)
    if not wsl_ok:
        print()
        print('[linux_compile_check-selftest] SKIP: WSL 不可用（无法自检）')
        return 2

    # T2: 源文件收集非空
    srcs = collect_sources()
    case('T2 收集到源文件 (%d 个)' % len(srcs), len(srcs) >= 10)

    # T3: **负向** —— 故意造一个含 windows.h 的文件，必须报失败
    tmpc = os.path.join(REPO, 'src', '__lcc_selftest_bad.c')
    try:
        with open(tmpc, 'w', encoding='utf-8') as f:
            f.write('#include <windows.h>\nint x;\n')
        ok, err, kinds = check_one('src/__lcc_selftest_bad.c')
        case('T3 **能报出失败**（含 windows.h 的文件）', not ok)
        case('T4 失败原因归类正确 (WINDOWS_HEADER)',
             'WINDOWS_HEADER' in kinds)
    finally:
        if os.path.exists(tmpc):
            os.remove(tmpc)

    # T5: **负向** —— 语法错误文件也必须报失败
    tmpc2 = os.path.join(REPO, 'src', '__lcc_selftest_syn.c')
    try:
        with open(tmpc2, 'w', encoding='utf-8') as f:
            f.write('int f(void) { return ; }\n')   # 缺表达式
        ok, err, kinds = check_one('src/__lcc_selftest_syn.c')
        case('T5 **能报出语法错误**', not ok)
    finally:
        if os.path.exists(tmpc2):
            os.remove(tmpc2)

    # T6: **正向** —— 一个合法文件必须编译通过
    tmpc3 = os.path.join(REPO, 'src', '__lcc_selftest_ok.c')
    try:
        with open(tmpc3, 'w', encoding='utf-8') as f:
            f.write('int lcc_selftest_ok(void) { return 0; }\n')
        ok, err, kinds = check_one('src/__lcc_selftest_ok.c')
        case('T6 合法文件**能通过**（不误报）', ok)
    finally:
        if os.path.exists(tmpc3):
            os.remove(tmpc3)

    print()
    print('=' * 66)
    if fails:
        print('[linux_compile_check-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    print('[linux_compile_check-selftest] PASS: 可自证能正确判定')
    return 0


if __name__ == '__main__':
    sys.exit(main())
