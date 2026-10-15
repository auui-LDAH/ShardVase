#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""`tools/android_compile_check.py` —— Android 交叉编译覆盖率检查

## 为什么建（2026-10-06 实测教训）

2026-10-06 用真实 NDK r28c（`--target=aarch64-linux-android21`）编译
`tools/attacker/android_jniptrace/` 与 `examples/cross_platform/android/`，
暴露出 **5 处从未被任何目标编译过的缺陷**（详见提交
`feat(android)!: 真 NDK 交叉编译暴露并修复 5 处缺陷`）:

  · `patcher_jni.c` / `ptrace_patcher_cli.c` —— `process_vm_writev` 在 API < 23
    的 bionic 上**根本不声明**（`__INTRODUCED_IN(23)`），且 include 路径写成
    `"../elfparse/elfparse.h"`（该目录的上一级没有 elfparse/）。
  · `libprot.c` / `selfcrypt_android.c` —— `-Wall -Wextra -Werror` 下
    unused parameter / ignored qualifiers / unused function。

**根因不是"没写好"，而是"没人编"**：`tools/linux_compile_check.py:88`
`SCAN_DIRS = ['src']` **只扫 `src/`**，`.github/workflows/ci.yml` 搜
`ndk|NDK|android|aarch64` **零命中**。工具作者 `README.md` 里那句
"宿主编译验证" 实测**只编了 `elfparse.c` + `elfdump.c` 两个文件** ——
声称覆盖与实际覆盖是两个集合，而**没有任何机制比对这两个集合**。

⇒ 本工具就是那个比对机制。

## 与 `linux_compile_check.py` 的关系（**互补，不重叠**）

  前者：`src/**` 经 **WSL/gcc(glibc)** 编译 —— 平台是 Linux glibc。
  本项：Android 侧源码经 **NDK/clang(bionic)** 交叉编译 —— 平台是 Android。

两者都保留，因为 **bionic 与 glibc 是两套不同的"声明可见性"规则**：
`linux_compile_check` 抓的是 glibc 的**特性宏冻结**（`<features.h>` 首次
遇到系统头即冻结），本项抓的是 bionic 的 **API 级别门控**
（`__INTRODUCED_IN(N)`）。同型不同因，不可互相替代。

## ⚠️ 本项最关键的判据：**必须在最低 API 上编译**（2026-10-06 实测）

同一份源码，三个 API 级别的实测结果:

  | 形态                              | api21 | api23 | api28 |
  |-----------------------------------|-------|-------|-------|
  | 裸 `process_vm_writev`（未修）     | rc=1  | rc=0  | rc=0  |
  | 仓库实际的 `syscall` 回退（已修）   | rc=0  | rc=0  | rc=0  |
  | 晚定义 `_GNU_SOURCE`（另一类缺陷）  | rc=1  |  -    | rc=1  |

**这个缺陷在 API 23 及以上完全看不见。** 任何"挑一个现代 API 编一遍"的门禁
都会**放它过去** —— 而这正是它潜伏至今的原因。
⇒ 判据锚定**文档声明的最低 API（21）**，见 `DEFAULT_APIS` 与 `--api`。

## 判据清单

  ① **清单完整性**：`SCAN_DIRS` 下每个 `.c` 必须出现在 `TARGETS` 里或被
     `EXCLUDE` 显式豁免（带原因）—— 否则报 `UNLISTED` 并失败。
     **为什么必须查条数**：本项目已记名的教训「表的条数对得上，语义对不上」
     （`hashpatch.py` 的 `TARGET_LOGICAL` 静默 `section absent — skip`）。
     手写清单一定会腐化，除非有人比对**实际集合**与**声明集合**。
  ② **最低 API 编译**（默认 21）：每个目标文件必须编过。
  ③ **现代 API 编译**（默认 28）：同上，用于区分"真的错"与"只是 API 高于下限"。
  ④ **差分归类**：api21 失败但 api28 通过 ⇒ 记 `API_GATED`，即"用到了高于
     声明下限的 API，需要像 patcher 那样写回退"——**这是可行动的诊断**，
     而不是一句笼统的"编译失败"。
  ⑤ **无 `-D_GNU_SOURCE` 命令行注入**：仓库 Android 侧源码**自己**在文件头
     `#define _GNU_SOURCE`。若某文件只在"命令行替它定义"时能编过，说明它的
     `#define` 位置太晚（被 bionic 头冻结）—— 与 `linux_compile_check` 的
     第二遍**同一条判据**，故本工具**不加**该宏。
     ⇒ 本地与 CI 不可能对同一份源码得出相反结论。

## 平台分流（**为什么不直接拓宽 `linux_compile_check.SCAN_DIRS`**）

2026-10-06 实测：把 `src` 换成全部目录会引入 **7 个永久 FAIL** ——
  · 需 `jni.h`（NDK 才有）: `patcher_jni.c` / `libprot.c`
  · 需 `-I elfparse`: `elfdump.c`
  · Windows-only（`windows.h`）: `winpe_sympatcher/{main,mempatch,symparse,test_target}.c`
它们**全是"本平台不适用"，不是"代码有错"**。把"环境不对"报成"代码有错"，
只会训练人忽略门禁（`linux_compile_check.py:266` 同款纪律）。
⇒ 故采用**显式清单 + 每文件自己的 include 目录**，而不是盲目递归。

`tools/attacker/winpe_sympatcher/**` 是 **Windows 原生**（自带 `build.ps1`
用 `cl.exe`），**不属于本项**，已从 `SCAN_DIRS` 排除并在此记名。

## 依赖
  Android NDK（含 `toolchains/llvm/prebuilt/<host>/bin/clang`）。
  查找顺序见 `find_ndk()`；找不到 ⇒ **退出码 2 = SKIP**（未验证 != 通过）。

## 用法
  python tools/android_compile_check.py                  # 人类可读报告
  python tools/android_compile_check.py --json           # JSON（CI 用）
  python tools/android_compile_check.py --quiet          # 只报结论（门禁用）
  python tools/android_compile_check.py --selftest       # 负向自检
  python tools/android_compile_check.py --min 8          # 通过文件数下限
  python tools/android_compile_check.py --ndk <path>     # 显式指定 NDK
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
# 隐藏窗口（2026-09-25 约定）
#
# Windows 上从 Python 启动控制台程序（clang.exe 等）会**弹出黑窗**。
# 统一用 tools/winproc.py 封装（CREATE_NO_WINDOW + STARTUPINFO/SW_HIDE）。
# 实测本项目约 60 处调用曾都无隐藏措施；一处修好 = 全部修好。
# ---------------------------------------------------------------------------
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)
import winproc  # noqa: E402


if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 文档声明的最低 API（`docs/EXTENSION_PLAN.md`: NDK r26+ / Clang 17 / **API 21+**）
# 与一个现代 API 级别。**21 必须在前** —— 它才是有判别力的那一遍（见模块 docstring）。
DEFAULT_APIS = (21, 28)

# 编译参数：与 `linux_compile_check.py:72` 对齐，但**故意不含 `-D_GNU_SOURCE`**
# （仓库 Android 侧源码自己在文件头定义；理由见模块 docstring 判据 ⑤）。
CFLAGS = ['-c', '-O2', '-Wall', '-Wextra', '-Werror', '-std=c11']

# ---------------------------------------------------------------------------
# 目标清单（显式；每个文件带自己的 include 目录）
#
# 字段: (仓库相对路径, [额外 -I 目录（仓库相对）], 说明)
#   说明只用于报告，解释"这个文件为什么在本项里"。
# ---------------------------------------------------------------------------
TARGETS = [
    ('tools/attacker/android_jniptrace/patcher_jni.c',
     ['tools/attacker/android_jniptrace'],
     '攻击侧: JNI 注入 patcher（含 API<23 的 process_vm_writev 回退）'),
    ('tools/attacker/android_jniptrace/ptrace_patcher_cli.c',
     ['tools/attacker/android_jniptrace'],
     '攻击侧: ptrace 改写 CLI（同上回退）'),
    ('tools/attacker/android_jniptrace/elfparse/elfparse.c',
     ['tools/attacker/android_jniptrace/elfparse'],
     '攻击侧: ELF 符号解析器（平台无关，跨编也应过）'),
    ('tools/attacker/android_jniptrace/elfdump.c',
     ['tools/attacker/android_jniptrace/elfparse'],
     '攻击侧: ELF 符号转储 CLI（`#include "elfparse.h"`，需 -I elfparse）'),
    ('examples/cross_platform/android/libprot.c',
     ['examples/cross_platform'],
     '被保护侧示例: JNI 导出 + 运行期自检'),
    ('examples/cross_platform/android/prot_test.c',
     ['examples/cross_platform'],
     '被保护侧示例: 授权链宿主自测'),
    ('examples/cross_platform/android/selfcrypt_android.c',
     [],
     '被保护侧示例: A3 轻量自加密段（平台无关）'),
    ('examples/cross_platform/license_auth_common.c',
     ['examples/cross_platform'],
     '被保护侧示例: 授权链公共逻辑（平台无关）'),
]

# 递归扫描哪些目录来找"漏登记"的 .c（判据 ①）
SCAN_DIRS = [
    'tools/attacker/android_jniptrace',
    'examples/cross_platform',
]

# 显式豁免（相对路径 -> 原因）。**必须带原因**，否则豁免就成了静默通道。
EXCLUDE = {}


def to_rel(p):
    return p.replace('\\', '/')


def collect_sources():
    """`SCAN_DIRS` 下实际存在的所有 `.c`（仓库相对、正斜杠）。"""
    out = []
    for d in SCAN_DIRS:
        base = os.path.join(REPO, d)
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            dirs[:] = [x for x in dirs if x != '__pycache__']
            for f in sorted(files):
                if f.endswith('.c'):
                    out.append(to_rel(os.path.relpath(os.path.join(root, f), REPO)))
    return sorted(set(out))


def unlisted_sources():
    """判据 ①: 实际存在但既不在 `TARGETS` 也不在 `EXCLUDE` 的 `.c`。

    **这是本工具存在的一半理由** —— 没有它，新增一个 Android 源文件会静默
    地不被任何东西编译（正是 2026-10-06 那 5 处缺陷的成因）。
    """
    declared = set(t[0] for t in TARGETS) | set(EXCLUDE)
    return [r for r in collect_sources() if r not in declared]


# ---------------------------------------------------------------------------
# NDK 查找
# ---------------------------------------------------------------------------
RE_VER = re.compile(r'^(\d+)\.(\d+)\.(\d+)$')


def _ver_key(name):
    m = RE_VER.match(name.strip())
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def _prebuilt_triple():
    """本宿主的 NDK prebuilt 目录名。"""
    if os.name == 'nt':
        return 'windows-x86_64'
    if sys.platform == 'darwin':
        return 'darwin-x86_64'
    return 'linux-x86_64'


def _clang_in(ndk_root):
    c = os.path.join(ndk_root, 'toolchains', 'llvm', 'prebuilt',
                     _prebuilt_triple(), 'bin', 'clang.exe'
                     if os.name == 'nt' else 'clang')
    return c if os.path.isfile(c) else None


def _ndk_version(ndk_root):
    """从 `source.properties` 读 `Pkg.Revision`；读不到则退回目录名。"""
    sp = os.path.join(ndk_root, 'source.properties')
    try:
        with open(sp, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if line.strip().startswith('Pkg.Revision'):
                    return line.split('=', 1)[1].strip()
    except OSError:
        pass
    return os.path.basename(os.path.normpath(ndk_root))


def _scan_ndk_dir(base):
    """`<base>/ndk/<ver>` 下按版本号**从高到低**返回可用的 NDK 根。"""
    found = []
    if not (base and os.path.isdir(base)):
        return found
    for name in os.listdir(os.path.join(base, 'ndk')) \
            if os.path.isdir(os.path.join(base, 'ndk')) else []:
        k = _ver_key(name)
        if k:
            found.append((k, os.path.join(base, 'ndk', name)))
    return [p for _, p in sorted(found, reverse=True)]


def find_ndk(explicit=None):
    """定位 NDK 根目录。返回 `(ndk_root, clang, version)`；找不到返回三个 None。

    ## 查找顺序（**可复现优先**）
      0. `--ndk <path>`（显式；用于排除"环境不同导致结论不同"的争议）
      1. `ANDROID_NDK_HOME` / `ANDROID_NDK_ROOT` / `ANDROID_NDK`（环境变量）
      2. `$ANDROID_SDK_ROOT/ndk/*` 与 `$ANDROID_HOME/ndk/*`（**取版本最高者**）
      3. 常见固定路径
    ## ⚠️ 为什么报告里必须打印实际选中的版本
      本机与 CI runner 的 NDK 集合**不同**（CI 同时有 27.3 / 28.2 / 29.0，
      本机只有 28.2），且环境变量指向也可能不同。
      不打印版本，就无法判断"门禁绿了"是因为代码对，还是因为**换了编译器
      恰好看不见**。UD 版本进 JSON 与报告，是这个结论可复核的最低条件。
    """
    cands = []
    if explicit:
        cands.append(os.path.abspath(explicit))
    for ev in ('ANDROID_NDK_HOME', 'ANDROID_NDK_ROOT', 'ANDROID_NDK'):
        v = os.environ.get(ev)
        if v:
            cands.append(v)
    for ev in ('ANDROID_SDK_ROOT', 'ANDROID_HOME'):
        cands.extend(_scan_ndk_dir(os.environ.get(ev)))
    if os.name == 'nt':
        cands.append(r'D:\environment\android-sdk\ndk')
        if os.environ.get('LOCALAPPDATA'):
            cands.append(os.path.join(os.environ['LOCALAPPDATA'],
                                      'Android', 'Sdk'))
    # 上面第 3 类给的是"SDK 根"，再展开一层
    expanded = []
    for c in cands:
        if os.path.isdir(os.path.join(c, 'ndk')):
            expanded.extend(_scan_ndk_dir(c))
        else:
            expanded.append(c)

    for c in expanded:
        clang = _clang_in(c)
        if clang:
            return c, clang, _ndk_version(c)
    return None, None, None


# ---------------------------------------------------------------------------
# 编译与归类
# ---------------------------------------------------------------------------
RE_UNDECLARED = re.compile(
    r"call to undeclared function '([^']+)'|"
    r"implicit declaration of function '([^']+)'")


def classify(errors_text):
    """把交叉编译错误归类（便于统计与定位）。"""
    kinds = []
    if RE_UNDECLARED.search(errors_text):
        kinds.append('API_LEVEL')
    if re.search(r"fatal error: '([^']+)' file not found", errors_text):
        kinds.append('MISSING_HEADER')
    if re.search(r'windows\.h|winioctl\.h|bcrypt\.h|tlhelp32\.h', errors_text):
        kinds.append('WINDOWS_HEADER')
    if re.search(r'\[-Werror,-W(unused|ignored)', errors_text):
        kinds.append('WARNING_AS_ERROR')
    if re.search(r'\berror:', errors_text) and not kinds:
        kinds.append('OTHER')
    return kinds


def check_one(rel, api, clang, inc_dirs):
    """交叉编译单个文件。返回 `(ok, error_text, kinds)`。"""
    cmd = [clang, '--target=aarch64-linux-android%d' % api] + list(CFLAGS)
    for d in inc_dirs:
        cmd.append('-I' + d)
    cmd.append(rel)
    obj = os.path.join(tempfile.gettempdir(), 'acc_%d_%s.o'
                       % (api, os.path.basename(rel)))
    cmd += ['-o', obj]
    try:
        r = winproc.run(cmd, cwd=REPO, capture_output=True, timeout=300)
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, 'invoke failed: %s' % e, ['INVOKE_FAILED']
    out = (r.stdout + r.stderr).decode('utf-8', 'replace')
    try:
        if os.path.exists(obj):
            os.remove(obj)
    except OSError:
        pass
    ok = (r.returncode == 0)
    return ok, ('' if ok else out), ([] if ok else classify(out))


def check_all(clang, apis=DEFAULT_APIS, quiet=False):
    """编译全部目标 × 全部 API 级别。返回 dict 结果。"""
    results = {}
    unlisted = unlisted_sources()
    for rel, inc, why in TARGETS:
        rec = {'why': why, 'inc': inc, 'apis': {}, 'ok': True}
        for api in apis:
            ok, err, kinds = check_one(rel, api, clang, inc)
            rec['apis'][str(api)] = {
                'ok': ok, 'kinds': kinds,
                'first_error': (err.strip().split('\n')[0][:200] if err else ''),
            }
            if not ok:
                rec['ok'] = False
        # 判据 ④: api21 失败但 api28 通过 => API 高于声明下限
        lo, hi = str(min(apis)), str(max(apis))
        if not rec['apis'][lo]['ok'] and rec['apis'][hi]['ok']:
            rec['api_gated'] = True
        results[rel] = rec
        if not quiet:
            marks = '  '.join(
                'api%d=%s' % (api, 'OK  ' if rec['apis'][str(api)]['ok'] else 'FAIL')
                for api in apis)
            tag = '  [API_GATED: 需要回退]' if rec.get('api_gated') else ''
            if not rec['ok']:
                ks = sorted({k for api in apis for k in rec['apis'][str(api)]['kinds']})
                tag += '  [%s]' % ','.join(ks)
            print('  %-54s %s%s' % (rel, marks, tag))

    n_ok = sum(1 for v in results.values() if v['ok'])
    return {
        'total': len(TARGETS), 'ok': n_ok, 'fail': len(TARGETS) - n_ok,
        'rates': '%d/%d' % (n_ok, len(TARGETS)),
        'apis': list(apis),
        'unlisted': unlisted,
        'api_gated': sorted(r for r, v in results.items() if v.get('api_gated')),
        'results': results,
    }


def exit_code_for(r, min_n=None):
    """由结果 dict 判定退出码 —— **抽成独立函数以便自检**。

    ## 为什么必须可自检
      这个函数就是"工具报 FAIL 但退出码是 0"的**唯一把关点**。第一版把它
      写在 `main()` 里且只在 `--min` 时生效，导致编不过也 rc=0
      （2026-10-06 自测抓到）。把关点不可自检 = 假通过会回来。
    """
    if r['unlisted']:
        return 1
    if r['ok'] < r['total']:
        return 1
    if min_n is not None and r['ok'] < min_n:
        return 1
    return 0


def main():
    ap = argparse.ArgumentParser(prog='android_compile_check.py')
    ap.add_argument('--ndk', default=None, help='显式指定 NDK 根目录')
    ap.add_argument('--api', default=None,
                    help='API 级别，逗号分隔（默认 %s；**21 必须有判别力**）'
                         % ','.join(str(a) for a in DEFAULT_APIS))
    ap.add_argument('--json', action='store_true', help='JSON 输出')
    ap.add_argument('--quiet', action='store_true')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--min', type=int, default=None,
                    help='通过文件数下限（不足则退出码非 0）')
    args = ap.parse_args()

    if args.selftest:
        return selftest(args.ndk)

    apis = DEFAULT_APIS
    if args.api:
        try:
            apis = tuple(int(x) for x in args.api.split(',') if x.strip())
        except ValueError:
            print('[android_compile_check] FAIL: --api 解析失败: %r' % args.api,
                  file=sys.stderr)
            return 1
    if not apis:
        print('[android_compile_check] FAIL: --api 为空', file=sys.stderr)
        return 1

    ndk, clang, ver = find_ndk(args.ndk)

    # ## 前置: 无 NDK -> **SKIP（退出 2）**，不是 FAIL
    #   "这台机器没装 NDK"与"源码编不过"是**完全不同的命题**。
    #   前者之下判据从未执行（未验证 != 通过），却会被报成 0/8 失败 ——
    #   一个把"环境没装"当成"代码有错"的报告，只会训练人忽略门禁
    #   （同 `linux_compile_check.py:266` 的纪律）。
    #   退出码 2 = 前置不满足；门禁据此报 `[skip]` 且**不计入 PASS 分子**。
    if not clang:
        msg = ('[android_compile_check] SKIP: 未找到 Android NDK ——'
               ' 本项未验证（未验证 != 通过）；补齐: 设 `ANDROID_NDK_HOME`'
               ' 或用 `--ndk <path>` 指定')
        if args.json:
            print(json.dumps({'skipped': True, 'reason': msg},
                             ensure_ascii=False, indent=2))
        else:
            print(msg, file=sys.stderr)
        return 2

    if not args.json and not args.quiet:
        print('NDK      : %s (%s)' % (ndk, ver))
        print('clang    : %s' % clang)
        print('API 级别 : %s   （最低 API 才是有判别力的那一遍）'
              % ', '.join(str(a) for a in apis))
        print()

    r = check_all(clang, apis, quiet=(args.quiet or args.json))
    r['ndk'] = ndk
    r['ndk_version'] = ver

    if args.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    elif not args.quiet:
        print()
        print('=' * 66)
        print('  Android 交叉编译覆盖率: **%s**   (NDK %s, API %s)'
              % (r['rates'], ver, '/'.join(str(a) for a in apis)))
        if r['api_gated']:
            print()
            print('  ⚠️ 用到高于声明下限 (%d) 的 API，需写回退:' % min(apis))
            for rel in r['api_gated']:
                print('    %s' % rel)
        print('=' * 66)

    # ## ⚠️ 默认即失败（2026-10-06 自查抓到的假通过）
    #   第一版只在传了 `--min` 时才判失败 -> **任何文件编不过是 rc=0**，
    #   门禁那一侧只读退出码 => 会报 `[ok]`。
    #   实测现场（同一次会话内自测发现）:
    #       api21=FAIL  api28=OK  [API_GATED: 需要回退]   <- 工具报得很清楚
    #       rc=0                                           <- 门禁只看这个
    #   这正是本项目反复记名的形态：**工具报 FAIL，门禁说 ok**
    #   （同 `release_check.ps1` 的 `$LASTEXITCODE` 影子变量事件）。
    #   => 判据必须是"**默认**编不过就非 0"；`--min` 只是**额外**的下限要求。
    #   把关点抽到 `exit_code_for()` 以便自检（T10-T13）。
    rc = exit_code_for(r, args.min)
    if rc == 0:
        return 0

    if r['unlisted']:
        print('[android_compile_check] FAIL: %d 个 .c 既未登记也未豁免 ——'
              ' 新增文件不会被任何东西编译，请加入 TARGETS 或 EXCLUDE:'
              % len(r['unlisted']), file=sys.stderr)
        for rel in r['unlisted']:
            print('  %s' % rel, file=sys.stderr)
        return 1

    print('[android_compile_check] FAIL: %s 未通过 —— 见上方逐文件结果'
          % r['rates'], file=sys.stderr)
    if r['api_gated']:
        print('      其中用到高于声明下限 (%d) 的 API，需要写回退:'
              % min(apis), file=sys.stderr)
        for rel in r['api_gated']:
            print('        %s' % rel, file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# 负向自检
# ---------------------------------------------------------------------------
def selftest(explicit_ndk=None):
    """负向自检: 必须能**报出失败**，尤其是能抓 API 级别缺陷。

    ## 为什么 T3/T4 是本自检的核心
      T3 复刻仓库 2026-10-06 修掉的真实缺陷形态（裸 `process_vm_writev`），
      并额外断言 **它在 api28 上能通过** —— 这证明：
        · 判据确实有抓它的能力（api21 报 FAIL）；
        · **只编现代 API 的门禁会放过它**（api28 报 OK），
          即"最低 API"不是随便挑的，是本项存在的理由。
      T4 是仓库实际的修法（`#if __ANDROID_API__ < 23` + `syscall` 回退），
      必须通过 —— 否则门禁会误报正确代码。
    """
    fails = []

    def case(name, ok):
        print('  %s %-58s' % ('ok ' if ok else '**FAIL**', name))
        if not ok:
            fails.append(name)

    print('=== android_compile_check 自检 ===')
    print()

    ndk, clang, ver = find_ndk(explicit_ndk)
    case('T1 找到 Android NDK (%s)' % (ver or '未找到'), bool(clang))
    if not clang:
        print()
        print('[android_compile_check-selftest] SKIP: 未找到 NDK'
              '（无法自检，未验证 != 通过）')
        print('      补齐方式: 设 `ANDROID_NDK_HOME` 或用 `--ndk <path>`。')
        return 2

    lo, hi = DEFAULT_APIS[0], DEFAULT_APIS[-1]

    # T2: 目标清单非空，且扫描目录下无漏登记
    case('T2 登记目标 %d 个' % len(TARGETS), len(TARGETS) >= 6)
    case('T2b 扫描目录下无漏登记 .c', not unlisted_sources())

    tmp = tempfile.mkdtemp(prefix='acc_selftest_')
    try:
        def w(name, body):
            p = os.path.join(tmp, name)
            with open(p, 'w', encoding='utf-8', newline='\n') as f:
                f.write(body)
            return p

        hdr_gnu = '#ifndef _GNU_SOURCE\n#  define _GNU_SOURCE\n#endif\n'
        common = ('#include <stddef.h>\n'
                  '#include <sys/types.h>\n'
                  '#include <sys/uio.h>\n'
                  '#include <unistd.h>\n')

        # T3: **负向** —— 裸 process_vm_writev（仓库 2026-10-06 修掉的真实形态）
        bad = w('t3_bad.c', hdr_gnu + common + (
            'ssize_t probe_write(pid_t pid, const struct iovec* l,\n'
            '                    unsigned long n, const void* r, size_t len)\n'
            '{\n'
            '    struct iovec riov;\n'
            '    riov.iov_base = (void*)r;\n'
            '    riov.iov_len = len;\n'
            '    return process_vm_writev(pid, l, n, &riov, 1, 0);\n'
            '}\n'))
        ok_lo, err_lo, kinds_lo = check_one(bad, lo, clang, [])
        case('T3 **能报出失败**（裸 process_vm_writev @ API %d）' % lo, not ok_lo)
        case('T3b 归因为 API_LEVEL', 'API_LEVEL' in kinds_lo)

        # T3c: 决定性 —— 同一文件在 api28 **必须通过**（证明单遍现代 API 会漏）
        ok_hi, _, _ = check_one(bad, hi, clang, [])
        if ok_hi:
            case('T3c 该缺陷在 API %d **确实看不见**（最低 API 遍不可省）' % hi,
                 True)
        else:
            # API 高于下限时也报错 => T3c 的前提不成立，说明判据变了；
            # 这本身不是缺陷，但要如实标注而非静默跳过。
            print('  %s T3c 该缺陷在 API %d 也报错（前提不成立, 不判失败）'
                  % ('note', hi))

        # T4: **正向** —— 仓库实际的修法必须通过（不误报正确代码）
        good = w('t4_good.c', hdr_gnu + common + (
            '#if defined(__ANDROID__) && defined(__ANDROID_API__) &&'
            ' (__ANDROID_API__ < 23)\n'
            '#  include <sys/syscall.h>\n'
            'static ssize_t prot_process_vm_writev(\n'
            '    pid_t pid, const struct iovec* l, unsigned long ln,\n'
            '    const struct iovec* r, unsigned long rn, unsigned long fl)\n'
            '{\n'
            '    return (ssize_t)syscall(__NR_process_vm_writev,'
            ' pid, l, ln, r, rn, fl);\n'
            '}\n'
            '#else\n'
            '#  define prot_process_vm_writev process_vm_writev\n'
            '#endif\n'
            'ssize_t probe_write(pid_t pid, const struct iovec* l,\n'
            '                    unsigned long n, const void* r, size_t len)\n'
            '{\n'
            '    struct iovec riov;\n'
            '    riov.iov_base = (void*)r;\n'
            '    riov.iov_len = len;\n'
            '    return prot_process_vm_writev(pid, l, n, &riov, 1, 0);\n'
            '}\n'))
        ok4, _, _ = check_one(good, lo, clang, [])
        case('T4 仓库实际修法**能通过**（不误报 @ API %d）' % lo, ok4)

        # T5: **负向** —— 晚定义 _GNU_SOURCE（特性宏冻结）必须被抓
        late = w('t5_late.c', (
            '#include <sys/uio.h>\n'
            '#ifndef _GNU_SOURCE\n'
            '#  define _GNU_SOURCE\n'
            '#endif\n'
            '#include <unistd.h>\n'
            'ssize_t probe_write(pid_t pid, const struct iovec* l,\n'
            '                    unsigned long n, const struct iovec* r,\n'
            '                    unsigned long rn)\n'
            '{\n'
            '    return process_vm_writev(pid, l, n, r, rn, 0);\n'
            '}\n'))
        ok5, _, _ = check_one(late, lo, clang, [])
        case('T5 **能报出**晚定义 _GNU_SOURCE', not ok5)

        # T6: **正向** —— 合法文件必须通过（不误报）
        plain = w('t6_ok.c', '#include <stdint.h>\n'
                             'uint32_t acc_selftest_ok(void) { return 0u; }\n')
        ok6, _, _ = check_one(plain, lo, clang, [])
        case('T6 合法文件**能通过**（不误报）', ok6)

        # T7: **负向** —— 头文件缺失必须归类为 MISSING_HEADER
        miss = w('t7_miss.c', '#include "no_such_header_zzz.h"\nint x;\n')
        ok7, _, kinds7 = check_one(miss, lo, clang, [])
        case('T7 **能报出**头文件缺失', not ok7)
        case('T7b 归因为 MISSING_HEADER', 'MISSING_HEADER' in kinds7)

        # T8: **负向** —— windows.h 在 Android 目标上必须失败
        win = w('t8_win.c', '#include <windows.h>\nint x;\n')
        ok8, _, kinds8 = check_one(win, lo, clang, [])
        case('T8 **能报出** windows.h', not ok8)
        case('T8b 归因为 WINDOWS_HEADER', 'WINDOWS_HEADER' in kinds8)

        # T9: **负向** —— 真实目标的清单完整性判据确实在比对实际集合
        #     （删掉一个登记项就必须被 unlisted_sources() 抓到）
        saved = TARGETS.pop()
        try:
            caught = any(saved[0] == u for u in unlisted_sources())
        finally:
            TARGETS.append(saved)
        case('T9 漏登记判据真的在比对实际集合', caught)

        # T10-T13: **退出码把关点自检** —— 本项目最贵的假通过形态
        #   2026-10-06 自测抓到：文件编不过时工具打印了 FAIL 与 API_GATED，
        #   但 `--quiet` 仍 rc=0（第一版只在 `--min` 时才判失败），
        #   而门禁那一侧只读退出码 => 会报 `[ok]`。
        #   "工具报 FAIL，门禁说 ok" 的**唯一把关点**就是 exit_code_for()，
        #   所以它必须自带回归测试，否则这个假通过会安静地回来。
        def r_of(ok_n, total, unlisted=(), api_gated=()):
            return {'ok': ok_n, 'total': total,
                    'rates': '%d/%d' % (ok_n, total),
                    'unlisted': list(unlisted),
                    'api_gated': list(api_gated)}

        # T10: 正向 —— 全过且无漏登记 => 0
        case('T10 退出码: 全过 => 0',
             exit_code_for(r_of(8, 8)) == 0)

        # T11: **回归测试** —— 不传 `--min` 时，编不过也必须是 1
        #      （这就是本块抓到的假通过；`--min` 的有无不得改变这个判定）
        case('T11 退出码: 不传 --min 时编不过 => 1（假通过回归）',
             exit_code_for(r_of(7, 8)) == 1)

        # T12: 漏登记 => 1（即使每个登记项都编过）
        case('T12 退出码: 有漏登记 => 1',
             exit_code_for(r_of(8, 8, unlisted=['examples/x.c'])) == 1)

        # T13: `--min` 只是**额外**下限，未达 => 1
        case('T13 退出码: --min 未达 => 1',
             exit_code_for(r_of(7, 8), 8) == 1)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print('=' * 66)
    if fails:
        print('[android_compile_check-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    print('[android_compile_check-selftest] PASS: 可自证能正确判定')
    return 0


if __name__ == '__main__':
    sys.exit(main())
