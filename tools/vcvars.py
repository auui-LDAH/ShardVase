# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
"""tools/vcvars.py — vcvars64.bat 探测与 cl 环境就绪的**单一实现**。

## 为什么需要这个模块

此前有 5 处各自硬编码少量 vcvars64.bat 路径，**没有 vswhere 兜底、
也不检查 `cl` 是否已在 PATH 上**。本地能过是因为本机的编译器恰好落在
硬编码表里（`D:\\environment\\VS2022BuildTools`），一旦换到
**未把 MSVC 装在候选表路径**的机器（例如 GitHub windows-latest，
其 MSVC 在 `C:\\Program Files\\Microsoft Visual Studio\\18\\Enterprise`）
就报 `CL FAIL: vcvars not found` —— 而这类失败**本地永远复现不到**。

## 判据（不靠清单）

两条独立的就绪判据，任一成立即视为可用:

1. **`cl` 已在 PATH 上** —— 例如 CI 的 `ilammy/msvc-dev-cmd` 会直接把
   `cl` 放进 PATH，此时**根本不需要 vcvars64.bat**。
2. **找得到 vcvars64.bat** —— 先查常见路径（快路径），再用
   `vswhere.exe` 问安装位置（覆盖任意盘符/版本号/版本版次）。

若两者都不成立，抛 `VcVarsNotFound`（调用方应报错而非静默跳过）。

## 用法

    import vcvars
    vc = vcvars.find_vcvars()          # None = cl 已在 PATH, 无需 call
    bat = vcvars.bat_text(clcmd, vc)   # 生成可直接执行的 .bat 文本

## 自检

    python tools/vcvars.py --selftest

自检用**注入的假探测函数**断言两条判据与"都失败时抛错"，
不依赖本机是否装有 MSVC（否则在没装编译器的机器上无法自证）。
"""
import os
import shutil
import subprocess
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


# 常见安装路径（**快路径**，不是穷举——穷举由 vswhere 负责）
CANDIDATES = (
    r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat',
    r'C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat',
    r'C:\Program Files (x86)\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat',
    r'C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat',
    r'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat',
    r'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat',
    r'D:\environment\VS2022BuildTools\VC\Auxiliary\Build\vcvars64.bat',
)

VSWHERE = r'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
# 要求带 x64 C++ 工具链，否则 vswhere 会返回一个没有 cl 的安装
VSWHERE_REQUIRES = 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64'
REL_VCVARS = os.path.join('VC', 'Auxiliary', 'Build', 'vcvars64.bat')


class VcVarsNotFound(RuntimeError):
    """既没有 cl 在 PATH 上，也找不到 vcvars64.bat。"""


def cl_on_path(which=shutil.which):
    """`cl` 是否已在 PATH 上（CI 的 msvc-dev-cmd 走这条）。"""
    try:
        return bool(which('cl'))
    except Exception:
        return False


def _default_run(args):
    try:
        return subprocess.run(args, capture_output=True, text=True,
                              encoding='utf-8', errors='replace', timeout=60)
    except Exception:
        return None


def _vswhere_install(vswhere, run):
    """问 vswhere 要安装根目录；失败返回 None。"""
    r = run([vswhere, '-latest', '-products', '*',
             '-requires', VSWHERE_REQUIRES,
             '-property', 'installationPath'])
    if r is None:
        return None
    out = (getattr(r, 'stdout', '') or '').strip()
    if not out:
        return None
    # vswhere 可能返回多行；取最后一行非空（-latest 通常只有一行）
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    return lines[-1] if lines else None


def find_vcvars(which=shutil.which, isfile=os.path.isfile, run=None,
                vswhere=VSWHERE):
    """返回 vcvars64.bat 路径；**若 cl 已在 PATH 上则返回 None**（无需 call）。

    找不到则抛 VcVarsNotFound。

    参数可注入，便于自检在不依赖本机 MSVC 的情况下断言判据。
    """
    if cl_on_path(which):
        return None

    for c in CANDIDATES:
        if isfile(c):
            return c

    if isfile(vswhere):
        install = _vswhere_install(vswhere, run or _default_run)
        if install:
            v = os.path.join(install, REL_VCVARS)
            if isfile(v):
                return v

    raise VcVarsNotFound(
        'vcvars64.bat 未找到，且 cl 不在 PATH 上。\n'
        '  需要 Visual Studio 的 "使用 C++ 的桌面开发" 工作负载，\n'
        '  或把 cl 放进 PATH（CI 用 ilammy/msvc-dev-cmd 即属后者）。\n'
        '  常见路径示例: ' + CANDIDATES[0])


def bat_text(clcmd, vcvars=None):
    """生成执行 clcmd 的 .bat 文本。

    vcvars 为 None（cl 已在 PATH）时**不写 `call` 行** —— 写
    `call "" >nul 2>&1` 会静默失败并让后续 cl 找不到。
    """
    head = '@echo off\r\n'
    if vcvars:
        head += 'call "%s" >nul 2>&1\r\n' % vcvars
    return head + clcmd + '\r\n'


# ---------------------------------------------------------------------------
# 自检 (T1-T4): 用注入的假探测函数断言判据, 不依赖本机 MSVC
# ---------------------------------------------------------------------------
def selftest():
    ok = True

    def chk(name, cond, detail=''):
        nonlocal ok
        if not cond:
            ok = False
        print('  %-56s %s%s' % (name, 'ok' if cond else 'FAIL',
                                ('  ' + detail) if detail else ''))

    print('=== vcvars 自检 ===')

    # T1: cl 已在 PATH -> 返回 None, 不查任何路径
    never = lambda p: False  # noqa: E731
    got = find_vcvars(which=lambda n: r'C:\x\cl.exe', isfile=never)
    chk('T1 cl 在 PATH -> None (无需 vcvars)', got is None, 'got=%r' % (got,))

    # T2: cl 不在 PATH, 但候选路径命中 -> 返回该路径
    hit = CANDIDATES[0]
    got = find_vcvars(which=lambda n: None, isfile=lambda p: p == hit)
    chk('T2 候选路径命中', got == hit, 'got=%r' % (got,))

    # T3: 候补全落空, vswhere 给出安装目录 -> 拼出 vcvars64.bat
    #   注意: isfile 必须同时认下 vswhere.exe 本身, 否则兜底分支根本不进入
    #   (这正是本自检首版失败的原因 —— 假探测函数漏了一个文件)
    install = r'C:\Program Files\Microsoft Visual Studio\18\Enterprise'
    want = os.path.join(install, REL_VCVARS)
    fake_vswhere = r'C:\vw\vswhere.exe'

    class _R:
        stdout = install + '\n'

    got = find_vcvars(which=lambda n: None,
                      isfile=lambda p: p in (want, fake_vswhere),
                      vswhere=fake_vswhere,
                      run=lambda a: _R())
    chk('T3 vswhere 兜底 (任意盘符/版本号)', got == want, 'got=%r' % (got,))

    # T3b: vswhere 存在但返回空 (无匹配工作负载) -> 仍须抛错, 不能返回空串
    class _E:
        stdout = ''

    raised_b = False
    try:
        find_vcvars(which=lambda n: None,
                    isfile=lambda p: p == fake_vswhere,
                    vswhere=fake_vswhere, run=lambda a: _E())
    except VcVarsNotFound:
        raised_b = True
    chk('T3b vswhere 返回空 -> 抛错', raised_b)

    # T4: 全部失败 -> 必须抛错 (不能静默返回 None 让调用方误以为 cl ready)
    raised = False
    try:
        find_vcvars(which=lambda n: None, isfile=never,
                    vswhere=r'C:\nope\vswhere.exe', run=lambda a: None)
    except VcVarsNotFound:
        raised = True
    chk('T4 都失败 -> 抛 VcVarsNotFound', raised)

    # T5: bat_text 在 cl 已在 PATH 时**不**写 call 行 (call "" 会静默失败)
    t = bat_text('cl /nologo x.c', None)
    chk('T5 cl 在 PATH -> bat 无 call 行', 'call' not in t and 'cl /nologo x.c' in t)
    t2 = bat_text('cl /nologo x.c', r'C:\vc\vcvars64.bat')
    chk('T5b 有 vcvars -> bat 含 call 行', 'call "C:\\vc\\vcvars64.bat"' in t2)

    print('[vcvars-selftest] %s' % ('PASS: 判据可自证' if ok else 'FAIL'))
    return 0 if ok else 1


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if '--selftest' in argv:
        return selftest()
    if '--print' in argv:
        # 供 PowerShell 门禁使用: 输出单行
        #   - vcvars64.bat 路径, 或
        #   - 'CL_ON_PATH'（cl 已在 PATH, 无需 call; 空行会让调用方无法区分
        #     "没有 vcvars" 与 "调用失败", 故用哨兵字符串）
        try:
            vc = find_vcvars()
        except VcVarsNotFound:
            return 1
        print(vc if vc else 'CL_ON_PATH')
        return 0
    print(__doc__)
    return 0


if __name__ == '__main__':
    sys.exit(main())
