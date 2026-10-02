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

# 不含 -D_GNU_SOURCE 的变体 —— 用于复核"源文件自称会自行定义 _GNU_SOURCE"是否为真。
#
# 为什么需要这一遍（CI 实测教训 2026-10-02）：`src/platform/prot_platform_linux.c`
# 曾在**两个自家头之后**才 `#define _GNU_SOURCE`，而 glibc 的 <features.h> 在第一次
# 遇到系统头（自家头里已拉入 <stdio.h>）时就把特性宏读死冻结了 —— 此后再定义完全无效。
# 结果：命令行带 `-D_GNU_SOURCE` 时编译通过（本地门禁一直带着，**永远看不到**），
# 命令行不带时 11+ 个错误（CI 的 gcc 调用没带，**必崩**）。
# 判据：**源文件自己 `#define _GNU_SOURCE` 就要在"命令行不定义"时也能编过** ——
# 这样本地门禁与 CI 就不可能再对同一份源码得出相反结论。
NO_GNU_CFLAGS = '-c -O2 -Wall -Wextra -Werror -std=c11'

RE_SELF_GNU = re.compile(r'^[ \t]*#[ \t]*define[ \t]+_GNU_SOURCE\b', re.M)

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


def self_gnu_sources(srcs=None):
    """返回**自己 `#define _GNU_SOURCE`** 的源文件（相对仓库路径）。

    判据不靠清单：凡是源文件自称会定义该宏，就必须在**命令行不定义**时也能编译 ——
    否则它的"自给自足"是假的，且只在某一条构建路径上暴露。
    """
    out = []
    for rel in (srcs if srcs is not None else collect_sources()):
        p = os.path.join(REPO, rel)
        try:
            with open(p, 'r', encoding='utf-8', errors='replace') as f:
                if RE_SELF_GNU.search(f.read()):
                    out.append(rel)
        except OSError:
            continue
    return out


def check_one(rel, distro='Ubuntu-24.04', cflags=None):
    """编译单个文件。返回 (ok, error_text, kinds)。"""
    repo_wsl = to_wsl_path(REPO)
    script = ('cd "%s" && gcc %s -I include "%s" -o /tmp/lcc.o 2>&1'
              % (repo_wsl, cflags or CFLAGS, rel))
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
    """检查全部源文件。返回 dict 结果。

    第二遍（`no_gnu`）只对**自称 `#define _GNU_SOURCE`** 的源文件跑，且**故意不带
    `-D_GNU_SOURCE`** —— 这类文件若只在"命令行替它定义"时能编过，说明它的
    `#define` 位置太晚（被 `<features.h>` 冻结），本判据就是为抓这种情况而生。
    """
    srcs = collect_sources()
    self_gnu = self_gnu_sources(srcs)
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

    # 第二遍: 自称 _GNU_SOURCE 的必须在**不带 -D_GNU_SOURCE**时也能编过。
    for rel in self_gnu:
        ok2, err2, kinds2 = check_one(rel, distro, cflags=NO_GNU_CFLAGS)
        results[rel]['no_gnu_ok'] = ok2
        results[rel]['no_gnu_error'] = (err2.strip().split('\n')[0][:200]
                                        if err2 else '')
        # 覆盖结果: 自称自给自足却只在带宏时成立 => 该文件判为**不通过**。
        if not ok2:
            results[rel]['ok'] = False
            results[rel]['divergent'] = True
            for k in (kinds2 or ['OTHER']):
                if k not in results[rel]['kinds']:
                    results[rel]['kinds'].append(k)
        if not quiet:
            mark = 'OK  ' if ok2 else 'FAIL'
            extra = '' if ok2 else '  [无 -D_GNU_SOURCE 时失败 —— 自给自足是假的]'
            print('  %-42s %s (no -D_GNU_SOURCE)%s' % (rel, mark, extra))

    n_ok = sum(1 for v in results.values() if v['ok'])
    return {'total': len(srcs), 'ok': n_ok,
            'self_gnu': self_gnu,
            'divergent': sorted(r for r, v in results.items()
                                if v.get('divergent')),
            'rates': '%d/%d' % (n_ok, len(srcs)), 'results': results}


def wsl_distro_ok(distro=DEFAULT_DISTRO):
    """该 WSL **发行版**是否真的可用（而不是仅 `wsl.exe` 二进制存在）。

    ## ⚠️ 为什么必须是这个判据（2026-10-02 CI 实测教训）
      原判据是 `wsl.exe --version` 返回 0 —— 它只证明**二进制存在**，不证明
      **能跑 Linux 编译**。CI 的 Windows runner 上 `wsl.exe` 在 PATH 里
      （检测"通过"）但**没有任何发行版** -> 每个文件的 `check_one` 都
      返回 `INVOKE_FAILED` -> 覆盖率 0/19 -> `--min 18` 失败 -> 门禁永远红。
      实测（本机）:
        `wsl.exe --version`                    rc=0   （二进制在）
        `wsl.exe -l -q`                        -> [Ubuntu-24.04]
        `wsl.exe -d Ubuntu-24.04 -- true`      rc=0   （**真正可用**）
        `wsl.exe -d NoSuchDistro_zzz -- true`  rc=-1 + WSL_E_DISTRO_NOT_FOUND
      => 只有探 `-d <distro>` 才回答"能不能跑 Linux 编译"。
    `WSL_UTF8=1` 必设，否则 wsl.exe 输出 UTF-16 在本控制台成乱码。
    """
    env = dict(os.environ)
    env['WSL_UTF8'] = '1'
    try:
        r = winproc.run(['wsl.exe', '-d', distro, '--', 'true'],
                        capture_output=True, timeout=120, env=env)
        return r.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


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

    # ## 前置: 无该发行版 -> **SKIP（退出 2）**，不是 FAIL（2026-10-02）
    #   "这台机器没有 WSL 发行版"与"源码编不过"是**完全不同的命题**。
    #   前者之下判据从未执行（未验证 != 通过），却会被报成覆盖率 0/19 失败 ——
    #   一个把"环境没装"当成"代码有错"的报告，只会训练人忽略门禁。
    #   退出码 2 = 前置不满足；门禁据此报 `[skip]` 且**不计入 PASS 分子**。
    if not wsl_distro_ok(args.distro):
        msg = ('[linux_compile_check] SKIP: WSL 发行版 %s 不可用 ——'
               ' 本项未验证（未验证 != 通过）；补齐: `wsl --install -d %s`'
               % (args.distro, args.distro))
        if args.json:
            print(json.dumps({'skipped': True, 'reason': msg},
                             ensure_ascii=False, indent=2))
        else:
            print(msg, file=sys.stderr)
        return 2

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

    # T1: WSL **发行版**可用（判据见 `wsl_distro_ok` 的 docstring）
    wsl_ok = wsl_distro_ok(DEFAULT_DISTRO)
    case('T1 WSL 发行版 %s 可用' % DEFAULT_DISTRO, wsl_ok)
    if not wsl_ok:
        print()
        print('[linux_compile_check-selftest] SKIP: WSL 发行版 %s 不可用'
              '（无法自检，未验证 != 通过）' % DEFAULT_DISTRO)
        print('      补齐方式: `wsl --install -d %s`；或本环境本就不跑 Linux'
              ' 编译 -> 由 CI 的 linux-portability job 覆盖。' % DEFAULT_DISTRO)
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

    # T7: **负向** —— 复刻 prot_platform_linux.c 的历史缺陷形态：
    # `#define _GNU_SOURCE` 写在 <stdio.h> **之后**，再使用 CLOCK_MONOTONIC。
    # 它必须"带 -D_GNU_SOURCE 能过、不带则失败" —— 这正是第二遍要抓的分歧。
    tmpc4 = os.path.join(REPO, 'src', '__lcc_selftest_late_gnu.c')
    try:
        with open(tmpc4, 'w', encoding='utf-8') as f:
            f.write('#include <stdio.h>\n'
                    '#ifndef _GNU_SOURCE\n'
                    '#  define _GNU_SOURCE\n'
                    '#endif\n'
                    '#include <time.h>\n'
                    'int lcc_self_late_gnu(void) {\n'
                    '    struct timespec ts;\n'
                    '    return clock_gettime(CLOCK_MONOTONIC, &ts);\n'
                    '}\n')
        rel4 = 'src/__lcc_selftest_late_gnu.c'
        ok_with, _, _ = check_one(rel4)
        ok_without, _, _ = check_one(rel4, cflags=NO_GNU_CFLAGS)
        case('T7 晚定义 _GNU_SOURCE: 带宏能过', ok_with)
        case('T8 晚定义 _GNU_SOURCE: **不带宏必须被抓**', not ok_without)
        case('T9 自给自足检测命中该文件', rel4 in self_gnu_sources([rel4]))
    finally:
        if os.path.exists(tmpc4):
            os.remove(tmpc4)

    print()
    print('=' * 66)
    if fails:
        print('[linux_compile_check-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    print('[linux_compile_check-selftest] PASS: 可自证能正确判定')
    return 0


if __name__ == '__main__':
    sys.exit(main())
