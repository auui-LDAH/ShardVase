#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""guard_selftest.py — R3.2-b 判定点快照校验的**行为自检**（含负向）

## 为什么需要（**本项目纪律: 检查器必须自证能抓错**）
快照校验若**退化为恒真**，门禁**不会发现**（所有测试仍绿）:
```
可能的退化原因:
  · 编译器把序言读取**折叠成常量**（故源码用了 `volatile` 读）
  · 比较写错（如漏掉 return / 比较对象搞反）
  · 快照在**被 patch 之后**才建立（时序错）
=> 与"只会通过的检查器"同类 —— 必须**实证它能抓到 patch**。
```

## 判据（两项缺一不可）
```
正向: 不 patch -> 进程**不得**因篡改退出（exit != PROT_EXIT_TAMPERED）
负向: patch 判定函数序言 -> 进程**必须**以 PROT_EXIT_TAMPERED 退出
```

## 方法（**与 ATTACK_DRILL7 步骤 4 同款**）
```
1) 从 build/demo.map 解析 `prot_antidebug_detected` 的**链接时 VA**
2) CreateToolhelp32Snapshot 取 demo.exe 的**运行时模块基址**（ASLR 换算）
3) OpenProcess + WriteProcessMemory 写入 `31 C0 C3`（xor eax,eax; ret）
4) 观察进程是否在窗口内以 PROT_EXIT_TAMPERED 退出
```

## 用法
```
python tools/guard_selftest.py                 # 正 + 负向
python tools/guard_selftest.py --target NAME   # 换判定点（默认该函数）
python tools/guard_selftest.py --json out.json
```

## 诚实边界
· 仅 Windows（OpenProcess/WriteProcessMemory）；非 Windows 上 **SKIP（退出 0）并说明**
· 依赖 demo 的看门狗策略为 **EXIT**（若改策略，负向判据需同步）
· 观察窗口有限（默认 20s）—— 慢机器上可能需调大
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import re
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(REPO, 'build', 'demo.exe')
MAP = os.path.join(REPO, 'build', 'demo.map')
BLOB = os.path.join(REPO, 'build', 'vm.blob')
PREF = 0x140000000                      # 链接时首选基址（见 build.ps1）
PATCH = (0x31, 0xC0, 0xC3)              # xor eax,eax; ret（DRILL7 步骤 4 原样）
WATCH_S = 20.0

PROCESS_ALL = 0x1F0FFF
TH32CS_SNAPMODULE = 0x8


def _exit_code(name, default):
    """从 C 头解析常量值（**不硬编码** —— 改常量时自动跟上）。"""
    for f in ('include/protect/protdef.h', 'include/protect/integrity.h'):
        p = os.path.join(REPO, *f.split('/'))
        if not os.path.isfile(p):
            continue
        t = open(p, encoding='utf-8', errors='replace').read()
        m = re.search(r'#define\s+%s\s+(0x[0-9A-Fa-f]+|\d+)' % name, t)
        if m:
            return int(m.group(1), 0)
    return default


def _sym_va(name):
    """从 map 取符号的链接时 VA。"""
    if not os.path.isfile(MAP):
        return None
    pat = re.compile(r'^\s+[0-9a-f]{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{16})\b',
                     re.I)
    for l in open(MAP, encoding='utf-8', errors='replace'):
        m = pat.match(l)
        if m and m.group(1) == name:
            return int(m.group(2), 16)
    return None


def _module_base(pid, modname):
    """取模块运行时基址（ASLR 换算用）。"""
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)

    class MODULEENTRY32(ctypes.Structure):
        _fields_ = [('dwSize', wt.DWORD), ('th32ModuleID', wt.DWORD),
                    ('th32ProcessID', wt.DWORD), ('GlblcntUsage', wt.DWORD),
                    ('ProccntUsage', wt.DWORD),
                    ('modBaseAddr', ctypes.c_void_p),
                    ('modBaseSize', wt.DWORD), ('hModule', wt.HMODULE),
                    ('szModule', ctypes.c_char * 256),
                    ('szExePath', ctypes.c_char * 260)]

    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    if not snap or snap == -1:
        return None
    try:
        me = MODULEENTRY32()
        me.dwSize = ctypes.sizeof(MODULEENTRY32)
        if not k32.Module32First(snap, ctypes.byref(me)):
            return None
        while True:
            if modname.lower().encode() in me.szModule.lower():
                return me.modBaseAddr
            if not k32.Module32Next(snap, ctypes.byref(me)):
                return None
    finally:
        k32.CloseHandle(snap)


def _spawn():
    return subprocess.Popen([EXE, '--vm-blob', BLOB, '--wait-ms', '9000'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            cwd=REPO)


def _observe(p, want, window=WATCH_S):
    """等 p 退出 -> 返回 (code, lines)；超时 -> (None, [])。"""
    t0 = time.time()
    while time.time() - t0 < window:
        code = p.poll()
        if code is not None:
            out = (p.stdout.read() + p.stderr.read()).decode('utf-8', 'replace')
            return code, out.split('\n')
        time.sleep(0.4)
    return None, []


def run(target, case_positive=True, case_negative=True):
    tamper = _exit_code('PROT_EXIT_TAMPERED', 0xBAD)
    rec = {'target': target, 'tampered_code': tamper, 'cases': []}

    if not os.path.isfile(EXE):
        rec['status'] = 'NA'
        rec['detail'] = 'build/demo.exe 缺失（需先构建）'
        return rec
    va = _sym_va(target)
    if va is None:
        rec['status'] = 'NA'
        rec['detail'] = 'map 中未找到 %s（需 build/demo.map）' % target
        return rec
    rec['link_va'] = hex(va)

    # ---------- 正向: 不 patch -> 不得因篡改退出 ----------
    if case_positive:
        p = _spawn()
        code, lines = _observe(p, tamper)
        if code is None:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
            code = -1
        ok = (code != tamper)
        hit = [l.strip() for l in lines if '篡改' in l or 'TAMPER' in l]
        rec['cases'].append({'case': 'positive', 'exit': code, 'ok': ok,
                             'detail': hit[:1]})
    else:
        code = None

    # ---------- 负向: patch 序言 -> 必须因篡改退出 ----------
    if case_negative:
        p = _spawn()
        time.sleep(3.0)                      # 等看门狗/selfcrypt 就绪
        k32 = ctypes.WinDLL('kernel32', use_last_error=True)
        h = k32.OpenProcess(PROCESS_ALL, False, p.pid)
        base = _module_base(p.pid, 'demo.exe') if h else None
        wrote = 0
        if h and base:
            rt = ctypes.c_void_p(base + (va - PREF))
            patch = (ctypes.c_ubyte * 3)(*PATCH)
            wrote = ctypes.c_size_t(0)
            k32.WriteProcessMemory(h, rt, ctypes.byref(patch), 3,
                                   ctypes.byref(wrote))
            rec['runtime_va'] = hex(rt.value)
        if h:
            k32.CloseHandle(h)
        if wrote.value != 3:
            p.terminate()
            rec['cases'].append({'case': 'negative', 'exit': None, 'ok': False,
                                 'detail': 'WriteProcessMemory 失败（需权限）'})
        else:
            code2, lines2 = _observe(p, tamper)
            if code2 is None:
                p.terminate()
                try:
                    p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    p.kill()
                code2 = -1
            ok2 = (code2 == tamper)
            hit2 = [l.strip() for l in lines2
                    if '篡改' in l or 'TAMPER' in l]
            rec['cases'].append({'case': 'negative', 'exit': code2, 'ok': ok2,
                                 'detail': hit2[:1], 'wrote': wrote.value})

    rec['status'] = ('ok' if all(c['ok'] for c in rec['cases'])
                     else 'fail')
    return rec


def main():
    ap = argparse.ArgumentParser(prog='guard_selftest.py')
    ap.add_argument('--target', default='prot_antidebug_detected')
    ap.add_argument('--json', dest='json_out', default=None)
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    if sys.platform != 'win32':
        print('[guard_selftest] SKIP: 仅 Windows（OpenProcess/WriteProcessMemory）')
        return 0

    tamper = _exit_code('PROT_EXIT_TAMPERED', 0xBAD)
    if not args.quiet:
        print('=== guard_selftest（判定点序言快照校验的行为自检）===')
        print('  目标: %s · PROT_EXIT_TAMPERED=0x%X' % (args.target, tamper))

    rec = run(args.target)
    if rec['status'] == 'NA':
        print('[guard_selftest] SKIP: %s' % rec['detail'])
        return 0

    for c in rec['cases']:
        tag = {'positive': '正向(未patch 不得误报)',
               'negative': '负向(patch 必须被抓)'}[c['case']]
        print('  %s %-26s exit=%-6s %s'
              % ('ok  ' if c['ok'] else '**FAIL**', tag, c['exit'],
                 (c['detail'][0] if c['detail'] else '')[:52]))

    if args.json_out:
        with open(args.json_out, 'w', encoding='utf-8') as f:
            json.dump(rec, f, ensure_ascii=False, indent=2)

    ok = rec['status'] == 'ok'
    print()
    print('[guard_selftest] %s' % ('PASS（正向 + 负向均可自证）' if ok
                                   else 'FAIL: 见上'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
