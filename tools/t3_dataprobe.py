#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
r"""`tools/t3_dataprobe.py` — **证实**"创建即调试"下 demo 的检出行为（W1）。

## 为什么需要（**先证实，再改 T3**）
  §29.2 已实测: `CreateProcess(DEBUG_ONLY_THIS_PROCESS)` 在本环境**成功**
  （免管理员），且能收到调试事件。
  **但** T3 的判据是:
```
demo 输出 MSG_DBG（"检测到调试环境，程序即将退出。"）+ 退出码 0xDB
```
  会话建立**不等于** demo 会报 —— 必须先**实测**，
  否则改完 T3 仍 SKIP（白改，且会误判为"环境不支持"）。

  ## 这个工具**不是测试**（不被门禁调用）
    它是**诊断/取证工具**，用途:
      · W1 证实（决定 W2 做不做）
      · 将来排障（T3 行为变化的取证入口）

  ## 实现要点（**上版原型挂起的原因与修法**）
    原型用 `GetStdHandle(-10)`（控制台输入）作为子进程 stdin 并把输出重定向到
    文件 —— 结果**挂起**（控制台句柄 + 继承句柄的交互）。
    **修法**: 三个标准句柄**全部用管道**，且:
      · 只让**子进程读端**可继承（父侧写端不继承，否则读端永不 EOF）
      · 输出用**独立线程**读（避免管道缓冲写满 -> 互锁）
      · 用完立刻 `CloseHandle` 写端

  ## 退出码
    0 = 判据**成立**（MSG_DBG + exit 0xDB）-> W2 可做
    1 = 判据**不成立**（如实报告实测值）-> W2 **不做**
    2 = 环境/参数问题（如 demo 未构建）
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import subprocess
import sys
import threading
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------- Win32 结构（ctypes.wintypes 缺 SECURITY_ATTRIBUTES）----------
class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('nLength', wt.DWORD),
                ('lpSecurityDescriptor', ctypes.c_void_p),
                ('bInheritHandle', wt.BOOL)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [('cb', wt.DWORD), ('lpReserved', wt.LPWSTR),
                ('lpDesktop', wt.LPWSTR), ('lpTitle', wt.LPWSTR),
                ('dwX', wt.DWORD), ('dwY', wt.DWORD),
                ('dwXSize', wt.DWORD), ('dwYSize', wt.DWORD),
                ('dwXCountChars', wt.DWORD), ('dwYCountChars', wt.DWORD),
                ('dwFillAttribute', wt.DWORD), ('dwFlags', wt.DWORD),
                ('wShowWindow', wt.WORD), ('cbReserved2', wt.WORD),
                ('lpReserved2', ctypes.POINTER(ctypes.c_byte)),
                ('hStdInput', wt.HANDLE), ('hStdOutput', wt.HANDLE),
                ('hStdError', wt.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [('hProcess', wt.HANDLE), ('hThread', wt.HANDLE),
                ('dwProcessId', wt.DWORD), ('dwThreadId', wt.DWORD)]


#: `CreateProcess` 标志
DEBUG_ONLY_THIS_PROCESS = 0x00000002
CREATE_NO_WINDOW = 0x08000000
#: `StartupInfo.dwFlags`：使用自定义标准句柄
STARTF_USESTDHANDLES = 0x00000100
#: 调试事件
EXIT_PROCESS_DEBUG_EVENT = 5
DBG_CONTINUE = 0x00010002
STILL_ACTIVE = 259
#: `SetHandleInformation` 的"不继承"
HANDLE_FLAG_INHERIT = 0x00000001


def _bind(k):
    """绑定用到的 Win32 函数签名（**显式 argtypes**，避免指针被截断）。"""
    sigs = {
        'CreatePipe': ([ctypes.POINTER(wt.HANDLE), ctypes.POINTER(wt.HANDLE),
                        ctypes.POINTER(SECURITY_ATTRIBUTES), wt.DWORD],
                       wt.BOOL),
        'SetHandleInformation': ([wt.HANDLE, wt.DWORD, wt.DWORD], wt.BOOL),
        'CreateProcessW': ([wt.LPCWSTR, wt.LPWSTR, ctypes.c_void_p,
                            ctypes.c_void_p, wt.BOOL, wt.DWORD,
                            ctypes.c_void_p, wt.LPCWSTR,
                            ctypes.POINTER(STARTUPINFOW),
                            ctypes.POINTER(PROCESS_INFORMATION)], wt.BOOL),
        'WaitForDebugEvent': ([ctypes.c_void_p, wt.DWORD], wt.BOOL),
        'ContinueDebugEvent': ([wt.DWORD, wt.DWORD, wt.DWORD], wt.BOOL),
        'GetExitCodeProcess': ([wt.HANDLE, ctypes.POINTER(wt.DWORD)],
                               wt.BOOL),
        'ReadFile': ([wt.HANDLE, ctypes.c_void_p, wt.DWORD,
                      ctypes.POINTER(wt.DWORD), ctypes.c_void_p], wt.BOOL),
        'WriteFile': ([wt.HANDLE, ctypes.c_void_p, wt.DWORD,
                       ctypes.POINTER(wt.DWORD), ctypes.c_void_p], wt.BOOL),
        'CloseHandle': ([wt.HANDLE], wt.BOOL),
        'TerminateProcess': ([wt.HANDLE, wt.UINT], wt.BOOL),
    }
    for fn, (args, res) in sigs.items():
        f = getattr(k, fn)
        f.argtypes = args
        f.restype = res


def _make_pipe(k, inherit_read):
    """建管道；**只**给需要的一端继承权（否则读端永不 EOF -> 挂起）。"""
    sa = SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(sa)
    sa.bInheritHandle = True
    r, w = wt.HANDLE(), wt.HANDLE()
    if not k.CreatePipe(ctypes.byref(r), ctypes.byref(w),
                        ctypes.byref(sa), 0):
        raise OSError('CreatePipe failed: %d' % ctypes.get_last_error())
    # inherit_read=True -> 读端给子进程（父侧用写端）；False -> 反之
    k.SetHandleInformation(w if inherit_read else r,
                           HANDLE_FLAG_INHERIT, 0)
    return r, w


def _drain(handle, sink, stop):
    """后台线程读管道（**必须**——否则缓冲写满会与子进程互锁）。"""
    buf = ctypes.create_string_buffer(8192)
    got = wt.DWORD()
    while not stop.is_set():
        ok = k32.ReadFile(handle, buf, 8192, ctypes.byref(got), None)
        if not ok or got.value == 0:
            break
        sink.append(buf.raw[:got.value])


k32 = ctypes.WinDLL('kernel32', use_last_error=True)
_bind(k32)


def probe(platform_exe, args, stdin_data, timeout=60, verbose=False):
    """用"创建即调试"跑 demo；返回 (exit_code, stdout_text, notes)。

    ## 与 T3 原实现的**关键差异**
      · T3 原用 `DebugActiveProcess`（附加**已有**进程）-> 需管理员
      · 本工具用 `DEBUG_ONLY_THIS_PROCESS`（调试**自己的子进程**）-> **免管理员**
    """
    sa_in_r, sa_in_w = _make_pipe(k32, inherit_read=True)
    out_r, out_w = _make_pipe(k32, inherit_read=False)
    err_r, err_w = _make_pipe(k32, inherit_read=False)

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    si.dwFlags = STARTF_USESTDHANDLES
    si.hStdInput = sa_in_r
    si.hStdOutput = out_w
    si.hStdError = err_w

    cmd = '"%s" %s' % (platform_exe, ' '.join(args))
    cmdbuf = ctypes.create_unicode_buffer(cmd)
    pi = PROCESS_INFORMATION()

    ctypes.set_last_error(0)
    ok = k32.CreateProcessW(None, cmdbuf, None, None, True,
                            DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW,
                            None, os.path.dirname(platform_exe),
                            ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        err = ctypes.get_last_error()
        for h in (sa_in_r, sa_in_w, out_r, out_w, err_r, err_w):
            k32.CloseHandle(h)
        return None, '', 'CreateProcess failed (win32 err=%d)' % err

    # 父侧只留**该留**的端（其余立刻关，避免 EOF 不到）
    k32.CloseHandle(sa_in_r)
    k32.CloseHandle(out_w)
    k32.CloseHandle(err_w)

    out_buf, err_buf = [], []
    stop = threading.Event()
    th_o = threading.Thread(target=_drain, args=(out_r, out_buf, stop),
                            daemon=True)
    th_e = threading.Thread(target=_drain, args=(err_r, err_buf, stop),
                            daemon=True)
    th_o.start()
    th_e.start()

    # 喂 stdin 然后**关掉写端**（否则 demo 读不到 EOF -> 挂起）
    if stdin_data:
        wrote = wt.DWORD()
        k32.WriteFile(sa_in_w, stdin_data, len(stdin_data),
                      ctypes.byref(wrote), None)
    k32.CloseHandle(sa_in_w)

    # 泵调试事件（**必须在 continue 之间做**，否则 demo 停住）
    ev = ctypes.create_string_buffer(512)
    n_ev = 0
    code = wt.DWORD(STILL_ACTIVE)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if k32.WaitForDebugEvent(ev, 500):
            ec = ctypes.c_ulong.from_buffer(ev, 0).value
            tid = ctypes.c_ulong.from_buffer(ev, 4).value
            n_ev += 1
            k32.ContinueDebugEvent(pi.dwProcessId, tid, DBG_CONTINUE)
            if ec == EXIT_PROCESS_DEBUG_EVENT:
                break
        else:
            k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
            if code.value != STILL_ACTIVE:
                break

    k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
    exit_code = code.value
    if exit_code == STILL_ACTIVE:            # 超时 -> 收尾
        k32.TerminateProcess(pi.hProcess, 0)
        notes_to = 'timeout after %ds (killed)' % timeout
    else:
        notes_to = ''
    time.sleep(0.3)
    stop.set()
    k32.CloseHandle(out_r)
    k32.CloseHandle(err_r)
    k32.CloseHandle(pi.hThread)
    k32.CloseHandle(pi.hProcess)

    out = b''.join(out_buf).decode('utf-8', 'replace')
    err = b''.join(err_buf).decode('utf-8', 'replace')
    if verbose and err.strip():
        notes_to += ' | stderr: %s' % err.strip()[:200]
    return exit_code, out, ('events=%d %s' % (n_ev, notes_to)).strip()


def main():
    ap = argparse.ArgumentParser(prog='t3_dataprobe.py')
    ap.add_argument('--exe', default=os.path.join(REPO, 'build', 'demo.exe'))
    ap.add_argument('--license-file',
                    default=os.path.join(REPO, 'build', 'license.txt'))
    ap.add_argument('--vm-blob', default=os.path.join(REPO, 'build', 'vm.blob'))
    ap.add_argument('--wait-ms', default='3000')
    ap.add_argument('--timeout', type=int, default=60)
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()

    if not os.path.isfile(args.exe):
        print('[t3_dataprobe] demo 未构建: %s（先跑 build.ps1）' % args.exe)
        return 2

    # demo 的序列号（stdin）与判据消息
    serial = ''
    jp = os.path.join(REPO, 'demo', 'vm_build.json')
    if os.path.isfile(jp):
        serial = json.load(open(jp, encoding='ascii'))['serial']
    msg_dbg = ''
    sp = os.path.join(REPO, 'demo', 'strings.txt')
    if os.path.isfile(sp):
        for line in open(sp, encoding='utf-8', errors='replace'):
            if line.startswith('MSG_DBG|'):
                msg_dbg = line.split('|', 1)[1].strip()
                break

    av = ['--license-file', args.license_file, '--vm-blob', args.vm_blob,
          '--wait-ms', args.wait_ms]
    print('=== 用"创建即调试"跑 demo（免管理员）===')
    print('  exe   = %s' % args.exe)
    print('  args  = %s' % ' '.join(av))
    code, out, notes = probe(args.exe, av, (serial + '\n').encode(),
                             timeout=args.timeout, verbose=args.verbose)
    print('  %s' % notes)
    print()
    print('=== demo 输出 ===')
    for l in out.split('\n'):
        if l.strip():
            print('    %s' % l.strip()[:100])

    print()
    print('=== 判据核对（T3 原始期望）===')
    if code is None:
        print('  **环境问题** -> 退出码 2')
        return 2
    ok_code = (code & 0xFF) == 0xDB
    ok_msg = (msg_dbg != '' and msg_dbg in out)
    print('  exit=%d (0x%x)  期望 0xDB  -> %s'
          % (code, code, '命中' if ok_code else '**不符**'))
    print('  MSG_DBG(%r) 出现 -> %s'
          % (msg_dbg, '命中' if ok_msg else '**不符**'))
    print()
    if ok_code and ok_msg:
        print('[t3_dataprobe] PASS: 判据成立 -> **W2 可做**（T3 可用此方式真验证）')
        return 0
    print('[t3_dataprobe] FAIL: 判据不成立 -> **W2 不做**（如实保留 SKIP）')
    return 1


if __name__ == '__main__':
    sys.exit(main())
