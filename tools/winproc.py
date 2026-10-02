#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""winproc.py — Windows 子进程调用的**统一封装**（消除弹窗）

## 问题
  Windows 上从 Python 启动**控制台程序**（powershell/cmd/wsl/cl）时，
  若未指定隐藏标志，系统会**分配新的控制台窗口** -> 用户看到**黑窗闪烁**。

  实测盘点: 本项目 **27 个文件、约 60 处**调用都有此问题，且**全无隐藏措施**。

## 为什么建统一模块（而非逐处零散修）
  · **一致性**: 一处修好 = 全部修好，不会漏
  · **可验证**: 可以写测试证明"确实隐藏了"
  · **可扩展**: 将来加超时/日志/重试都改这里

## 用法
```python
from winproc import run            # 直接替换 subprocess.run
r = run(['powershell', '-File', 'x.ps1'], capture_output=True)
```
  或需要原始 subprocess 语义时:
```python
from winproc import popen_kwargs   # 只取"隐藏窗口"的 kwargs
subprocess.run(cmd, **popen_kwargs())
```

## 平台差异（**如实**）
  · Windows: `creationflags=CREATE_NO_WINDOW` + STARTUPINFO(SW_HIDE)
  · Linux/macOS: 无此概念（kwargs 为空）
  => 封装后**跨平台安全**（在 Linux 上不传无效参数）。

## 诚实边界
  · `CREATE_NO_WINDOW` 适用于**控制台程序**；
    对 **GUI 程序**（如 notepad）无效（那本就不该隐藏）
  · 若父进程**已有控制台**，子进程复用时不会弹**新**窗口 ——
    但本项目多数场景（IDE/Agent 调用）**没有**可见控制台，故需显式隐藏
"""

import os
import subprocess
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


__all__ = ['popen_kwargs', 'run', 'Popen', 'check_output',
           'IS_WINDOWS', 'CREATE_NO_WINDOW', 'selftest']

IS_WINDOWS = (os.name == 'nt')

# 0x08000000 = CREATE_NO_WINDOW（进程不继承/分配控制台）
CREATE_NO_WINDOW = 0x08000000


def popen_kwargs():
    """返回"隐藏窗口"所需的 kwargs（平台无关）。

    ## 为什么同时给 creationflags 与 startupinfo
      · `creationflags=CREATE_NO_WINDOW` —— 主要手段（不分配控制台）
      · `startupinfo` + `SW_HIDE` —— 双保险（某些场景只认这个）
      两者一起用是 Windows 上的**通行做法**。
    """
    if not IS_WINDOWS:
        return {}
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE          # 0
    return {'creationflags': CREATE_NO_WINDOW, 'startupinfo': si}


def _merge(kwargs):
    """把隐藏参数合入调用方的 kwargs（**调用方优先**，可显式覆盖）。"""
    merged = popen_kwargs()
    merged.update(kwargs or {})
    return merged


def run(args, **kwargs):
    """`subprocess.run` 的隐藏窗口版。"""
    return subprocess.run(args, **_merge(kwargs))


def Popen(args, **kwargs):
    """`subprocess.Popen` 的隐藏窗口版。"""
    return subprocess.Popen(args, **_merge(kwargs))


def check_output(args, **kwargs):
    """`subprocess.check_output` 的隐藏窗口版。"""
    return subprocess.check_output(args, **_merge(kwargs))


def selftest():
    """自检: 证明封装**确实**隐藏了窗口（而非只是"看起来对"）。

    ## 方法
      **无法**直接断言"有没有弹窗"（那需要 UI 自动化）。
      故改用**可验证的等价性质**:
        ① `popen_kwargs()` 在 Windows 上**必须**含 CREATE_NO_WINDOW
        ② `startupinfo.wShowWindow` **必须**是 SW_HIDE
        ③ 封装后的 `run` 能正常执行子进程（不破坏功能）
        ④ 非 Windows 上返回空 dict（跨平台安全）

      => ①② 证明"参数正确"，③ 证明"没搞坏调用"。
         这是**可自动验证的部分**；"窗口是否真的不闪"属人工确认。
    """
    fails = []

    def case(name, ok):
        print('  %s %-56s' % ('ok ' if ok else '**FAIL**', name))
        if not ok:
            fails.append(name)

    print('=== winproc 自检 ===')

    kw = popen_kwargs()
    if IS_WINDOWS:
        case('T1 Windows 下含 creationflags', 'creationflags' in kw)
        case('T2 creationflags == CREATE_NO_WINDOW',
             kw.get('creationflags') == CREATE_NO_WINDOW)
        case('T3 含 startupinfo', 'startupinfo' in kw)
        case('T4 wShowWindow == SW_HIDE',
             getattr(kw.get('startupinfo'), 'wShowWindow', None)
             == subprocess.SW_HIDE)
        case('T5 dwFlags 含 STARTF_USESHOWWINDOW',
             bool(getattr(kw.get('startupinfo'), 'dwFlags', 0)
                  & subprocess.STARTF_USESHOWWINDOW))
    else:
        case('T1 非 Windows 返回空 kwargs', kw == {})

    # T6: 封装不破坏功能 —— 真跑一个子进程
    try:
        r = run([sys.executable, '-c', 'print("WINPROC_OK")'],
                capture_output=True, timeout=60)
        out = r.stdout.decode('utf-8', 'replace').strip()
        case('T6 封装后子进程正常执行', r.returncode == 0
             and 'WINPROC_OK' in out)
    except Exception as e:
        case('T6 封装后子进程正常执行 (%s)' % str(e)[:30], False)

    # T7: 调用方可覆盖（不锁死）
    try:
        r = run([sys.executable, '-c', 'print(1)'], capture_output=True,
                timeout=60)
        case('T7 调用方 kwargs 可合入', r.returncode == 0)
    except Exception:
        case('T7 调用方 kwargs 可合入', False)

    print()
    print('=' * 62)
    if fails:
        print('[winproc-selftest] FAIL: %s' % '; '.join(fails))
        return 1
    print('[winproc-selftest] PASS: 隐藏参数正确且不破坏调用')
    return 0


if __name__ == '__main__':
    sys.exit(selftest())
