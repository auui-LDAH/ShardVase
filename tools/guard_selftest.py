#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""guard_selftest.py — R3.2-b 判定点序言快照校验的**行为自检**（含负向）

## 为什么需要（**本项目纪律: 检查器必须自证能抓错**）
快照校验若**退化为恒真**，门禁**不会发现**（所有测试仍绿）:
```
可能的退化原因:
  · 编译器把序言读取**折叠成常量**（故源码用了 `volatile` 读）
  · 比较写错（如漏掉 return / 比较对象搞反）
  · 快照在**被 patch 之后**才建立（时序错）
  · 登记（register_guard）根本没生效（dyn_n 恒 0）
=> 与"只会通过的检查器"同类 —— 必须**实证它能抓到 patch**。
```

## 判据: `g_guard_hits`（**不是退出码**）
```
退出码**无判别力**（2026-09-29 实测）:
  · patch 非掩码区目标 -> `.text` 段 CRC（check_self）**先**终止进程 -> 2989
    => 2989 是 **CRC 的功劳**，守卫根本没机会执行
  · patch 掩码区目标   -> 反调试路径 219 = DEBUG_DETECTED
    => 该 219 由**测试工具自身**的 OpenProcess 触发
=> 退出码无法区分"守卫有效"与"别的检测同向命中"。
判据 = 守卫自己的命中计数 `g_guard_hits`:
  正向: 不 patch   -> hits == 0（无恒报）
  负向: patch 目标 -> hits  > 0（守卫**确实命中**）
```

## ⚠️ 目标必须选 **selfcrypt 掩码区外**的判定点（2026-09-30 实测更正）
```
【旧版结论是**反的**，此处更正】旧版说"必须选掩码区内"，理由
"段 CRC 抓不到则 2989 只可能来自守卫" —— **判据换成 hits 后该理由失效**，
而且掩码区内目标**根本打不到守卫**（实测根因）:

  src/integrity.c:188-198
    if (prot_selfcrypt_enter(PROT_SELFCRYPT_GROUP_EXT) != PROT_OK) {
        switch (g_wd_policy) { … default: increment(&g_wd_tamper); }
        continue;                  /* <== **整轮跳过** */
    }

  掩码区内目标（如 prot_license_verify, rva 0x3E80）
    = 被 patch 的是**密文** -> **selfcrypt 自己的 per-region CRC 先失败**
    -> `continue` -> check_guards(L211) **根本没跑** -> hits 恒 0
  => 旧版选 prot_license_verify 做目标 = **自检永远红**，且原因被误读成"守卫失效"。

  掩码区外目标（prot_antidebug_detected 等）
    = 段 CRC 失败 -> 但 **CONTINUE 分支没有 `continue`** -> 执行流继续
    -> 到达 check_guards -> **可观测** hits
  => 本文件据此**自动选择**目标（读 build/selfcrypt_mask.txt 判掩码归属），
     并在候选表里打印每个候选的掩码归属，便于复核。
```

## ⚠️ 为什么要改运行期策略为 CONTINUE（**观测手段，非攻击**）
```
默认策略是 EXIT: 段 CRC 失败 -> prot_plat_terminate(2989)（L175-178）
=> 进程在**同一个 tick 内**死亡 -> hits 的增量读不到（我实测错过过一次）。
把 `g_wd_policy` 置 0(CONTINUE) 后:
  · 段 CRC 失败只累加计数、**不终止**、且**不 `continue`**
  · => 执行流到达 check_guards -> hits 可稳定观测
语义上这**恰好模拟"攻击者已中和段 CRC"**的场景 ——
而那正是守卫存在的意义（守卫是**纵深**，不是第一道）。
副作用（正向）: 工具自身的 OpenProcess 也不再把进程打成 219。
```

## ⚠️ 写入必须**读回验证**（2026-09-30 补）
```
旧版 run_by_hits() **完全忽略** WriteProcessMemory 的返回值与写入字节数,
且未改页保护 —— `.text` 是只读页, WPM 可能直接失败
=> "负向用例失败"可能是**根本没写进去**，而非守卫无效。
本版: VirtualProtectEx -> WPM -> **rd 读回 3 字节比对** -> 恢复页保护。
```

## 判据（两项缺一不可）
```
正向: 不 patch   -> hits == 0（守卫不得恒报）
负向: patch 目标 -> hits  > 0（守卫必须命中）
```

## 用法
```
python tools/guard_selftest.py                 # 自动选目标（掩码区外的已登记守卫）
python tools/guard_selftest.py --target NAME   # 指定判定点（会打印其掩码归属）
python tools/guard_selftest.py --json out.json
```

## 诚实边界
· 仅 Windows（OpenProcess/WriteProcessMemory）；非 Windows 上 **SKIP（退出 0）并说明**
· **改了运行期策略**（CONTINUE）—— 验证的是"守卫的检测能力"，不是"EXIT 策略下的端到端效果"
· 在 EXIT 策略下，掩码区外目标由段 CRC **先**终止、掩码区内目标由 selfcrypt **先**拦截，
  故**守卫在出厂策略下不是第一发现者**；它的价值在于"段 CRC 被中和后仍有第二道"
· 若**全部**已登记守卫都落在掩码区内 -> 本自检**无判别力** -> 明确 FAIL 并报告（不是静默通过）
· 观察窗口默认 18s；看门狗周期 5s(±40% 抖动)，首轮最晚 ~7s
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

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(REPO, 'build', 'demo.exe')
MAP = os.path.join(REPO, 'build', 'demo.map')
BLOB = os.path.join(REPO, 'build', 'vm.blob')
LICENSE = os.path.join(REPO, 'build', 'license.txt')
MASK_TXT = os.path.join(REPO, 'build', 'selfcrypt_mask.txt')
PREF = 0x140000000                      # 链接时首选基址（见 build.ps1）
PATCH = (0x31, 0xC0, 0xC3)              # xor eax,eax; ret（DRILL7 步骤 4 原样）
OBSERVE_S = 18.0                        # 观察窗口（>= 2 个看门狗周期）
SETTLE_S = 1.2                          # 进程启动后**最短**等待（只为让 PE 加载完成）
READY_TIMEOUT_S = 25.0                  # 等 `start_watchdog` 就绪的上限（见 _wait_ready）
KEEP_MS = 30000                         # 让 demo 活得比观察窗口长

PROCESS_ALL = 0x1F0FFF
TH32CS_SNAPMODULE = 0x8
PAGE_EXECUTE_READWRITE = 0x40

HITS_SYM = 'g_guard_hits'
POLICY_SYM = 'g_wd_policy'
TAMPER_SYM = 'g_wd_tamper'
# 就绪哨兵: `start_watchdog` 校验通过后写它（`src/integrity.c:828`），
# 零初始化 -> **非 0 即已就绪**。选它而非 POLICY_SYM 的原因:
# 本工具会改 `g_wd_policy`（写 CONTINUE = 0），若拿它当信号则**自毁证据**
# （见 `_wait_ready` 注释）。`g_wd_interval` 我们不碰。
READY_SYM = 'g_wd_interval'


# ---------------------------------------------------------------------------
# 只读辅助
# ---------------------------------------------------------------------------
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


def _policy_value(name, default):
    """从 `include/protect/protdef.h` 的枚举解析 PROT_POLICY_* 的值。"""
    p = os.path.join(REPO, 'include', 'protect', 'protdef.h')
    if not os.path.isfile(p):
        return default
    t = open(p, encoding='utf-8', errors='replace').read()
    m = re.search(r'\b%s\s*=\s*(\d+)' % name, t)
    return int(m.group(1)) if m else default


def _sym_va(name):
    """从 map 取符号的**链接时 VA**。

    map 行形态（V1 曾经因为我假设成别的形态而只解析出 948/2989 个符号）:
        0004:00009e98   g_guard_hits   000000014003ce98  integrity.obj
    """
    if not os.path.isfile(MAP):
        return None
    pat = re.compile(r'^\s+([0-9a-f]{4}):([0-9a-f]{8})\s+(\S+)\s+([0-9a-f]{16})\b',
                     re.I)
    for l in open(MAP, encoding='utf-8', errors='replace'):
        m = pat.match(l)
        if m and m.group(3) == name:
            return int(m.group(4), 16)
    return None


def _mask_regions():
    """读 `build/selfcrypt_mask.txt` -> [(rva, len), ...]。

    **为什么不用硬编码的目标名**: 掩码归属取决于每次构建的布局
    （实测同一目标 RVA 从 0x4770 变到 0x3E80；selfcrypt 目标集合也会变）。
    """
    if not os.path.isfile(MASK_TXT):
        return None
    out = []
    for l in open(MASK_TXT, encoding='utf-8', errors='replace'):
        l = l.strip()
        if not l or l.startswith('#'):
            continue
        parts = l.split(',')
        if len(parts) < 2:
            continue
        try:
            out.append((int(parts[0], 0), int(parts[1], 0)))
        except ValueError:
            continue
    return out


def _guard_candidates():
    """从**源码**提取已登记的守卫名（自动跟随实现变化）。

    来源①（静态表）`src/integrity.c`:
        static const prot_guard_entry g_guard_static[] = {
            { "prot_antidebug_detected",   (const void*)&prot_antidebug_detected },
    来源②（运行期登记）`demo/main.c` / `prot_sdk/skeleton/app_main.c`:
        (void)prot_integrity_register_guard(
            "prot_license_verify", (const void*)&prot_license_verify);
    """
    names = []

    p = os.path.join(REPO, 'src', 'integrity.c')
    if os.path.isfile(p):
        t = open(p, encoding='utf-8', errors='replace').read()
        m = re.search(r'g_guard_static\[\]\s*=\s*\{(.*?)\n\};', t, re.S)
        if m:
            for g in re.finditer(r'\{\s*"([A-Za-z0-9_]+)"\s*,\s*'
                                 r'\(const void\*\)\s*&\s*([A-Za-z0-9_]+)', m.group(1)):
                names.append((g.group(2), 'static tbl'))

    for rel, tag in (('demo/main.c', 'main.c 登记'),
                     ('prot_sdk/skeleton/app_main.c', 'app_main.c 登记')):
        p = os.path.join(REPO, *rel.split('/'))
        if not os.path.isfile(p):
            continue
        t = open(p, encoding='utf-8', errors='replace').read()
        for g in re.finditer(r'prot_integrity_register_guard\(\s*"([A-Za-z0-9_]+)"\s*,'
                             r'\s*\(const void\*\)\s*&\s*([A-Za-z0-9_]+)', t):
            names.append((g.group(2), tag))

    seen, out = set(), []
    for n, src in names:
        if n not in seen:
            seen.add(n)
            out.append((n, src))
    return out


def _in_mask(rva, regions):
    if not regions:
        return False
    return any(a <= rva < a + ln for a, ln in regions)


class _MODULEENTRY32(ctypes.Structure):
    _fields_ = [('dwSize', wt.DWORD), ('th32ModuleID', wt.DWORD),
                ('th32ProcessID', wt.DWORD), ('GlblcntUsage', wt.DWORD),
                ('ProccntUsage', wt.DWORD), ('modBaseAddr', ctypes.c_void_p),
                ('modBaseSize', wt.DWORD), ('hModule', wt.HMODULE),
                ('szModule', ctypes.c_char * 256),
                ('szExePath', ctypes.c_char * 260)]


def _module_base(k32, pid, modname):
    """取模块**运行时**基址 —— ASLR 生效时它 != PREF（实测 0x7FF6860A0000）。

    > 曾经的坑: 用 `PREF` 直接读 -> 全部 err=299(ERROR_PARTIAL_COPY)
    > -> 采样为空 -> 差点被读成"变量不存在"。
    """
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    if not snap or snap == -1:
        return None
    try:
        me = _MODULEENTRY32()
        me.dwSize = ctypes.sizeof(_MODULEENTRY32)
        if not k32.Module32First(snap, ctypes.byref(me)):
            return None
        while True:
            if modname.lower().encode() in me.szModule.lower():
                return me.modBaseAddr or None
            if not k32.Module32Next(snap, ctypes.byref(me)):
                return None
    finally:
        k32.CloseHandle(snap)


def _spawn():
    args = [EXE, '--selftest', '--vm-blob', BLOB, '--wait-after', str(KEEP_MS)]
    if os.path.isfile(LICENSE):
        args += ['--license-file', LICENSE]
    return subprocess.Popen(args, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, cwd=REPO)


# ---------------------------------------------------------------------------
# 主用例
# ---------------------------------------------------------------------------
def run_by_hits(target, verbose=True):
    """两个用例：正向（不 patch）/ 负向（patch）。判据 = `g_guard_hits`。"""
    va_fn = _sym_va(target)
    va_hits = _sym_va(HITS_SYM)
    va_pol = _sym_va(POLICY_SYM)
    va_rdy = _sym_va(READY_SYM)
    if va_fn is None or va_hits is None or va_pol is None or va_rdy is None:
        return None

    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    k32.OpenProcess.restype = wt.HANDLE
    k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p,
                                      ctypes.c_void_p, ctypes.c_size_t,
                                      ctypes.POINTER(ctypes.c_size_t)]
    k32.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p,
                                       ctypes.c_void_p, ctypes.c_size_t,
                                       ctypes.POINTER(ctypes.c_size_t)]
    k32.VirtualProtectEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                     wt.DWORD, ctypes.POINTER(wt.DWORD)]
    k32.CloseHandle.argtypes = [wt.HANDLE]
    # ## ⚠️ Toolhelp32 三件套必须**成对**设原型（2026-10-06 补，HANDOVER §2.36.5/§2.37.8）
    #   旧版只设了上面那几个：`_module_base()` 用的
    #   `CreateToolhelp32Snapshot` / `Module32First` / `Module32Next`
    #   三个都**没有** argtypes/restype。默认 restype 是 32 位 `c_int`，
    #   而 `CreateToolhelp32Snapshot` 返回 64 位 `HANDLE` —— 本机句柄值
    #   恰好小，故**侥幸**一直能跑（`tools/prot_dbg.py:283-285` 是第三份
    #   实现且它**设了**原型 ⇒ 三份实现两种纪律）。
    #   `tools/selfcrypt_residency_check.py`（门禁第 39 项）只修正了
    #   `restype` 一处，立刻以
    #   `ctypes.ArgumentError: argument 1: OverflowError: int too long to convert`
    #   炸在 `:268` —— **只补一个反而从"侥幸能跑"变成"必然崩"**，
    #   故这里三个一起补齐。
    k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    k32.Module32First.restype = wt.BOOL
    k32.Module32First.argtypes = [wt.HANDLE, ctypes.POINTER(_MODULEENTRY32)]
    k32.Module32Next.restype = wt.BOOL
    k32.Module32Next.argtypes = [wt.HANDLE, ctypes.POINTER(_MODULEENTRY32)]

    def _rd(h, va, n=4):
        buf = (ctypes.c_ubyte * n)()
        got = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(h, ctypes.c_void_p(va), buf, n,
                                 ctypes.byref(got)) and got.value == n:
            return bytes(buf)
        return None

    def _rd_i32(h, va):
        b = _rd(h, va, 4)
        return int.from_bytes(b, 'little') if b else None

    def _wr(h, va, data):
        """写 + **读回验证**（旧版忽略返回值 = 可能没写进去却报"守卫失效"）。"""
        old = wt.DWORD(0)
        k32.VirtualProtectEx(h, ctypes.c_void_p(va & ~0xFFF), 0x1000,
                             PAGE_EXECUTE_READWRITE, ctypes.byref(old))
        n = ctypes.c_size_t(0)
        buf = (ctypes.c_ubyte * len(data))(*data)
        ok = bool(k32.WriteProcessMemory(h, ctypes.c_void_p(va), buf, len(data),
                                         ctypes.byref(n)))
        k32.VirtualProtectEx(h, ctypes.c_void_p(va & ~0xFFF), 0x1000,
                             old.value or 0x20, ctypes.byref(old))
        back = _rd(h, va, len(data))
        return ok and n.value == len(data) and back == bytes(data), back

    def _wait_ready(h, proc, va_rdy):
        """等 `prot_integrity_start_watchdog` **确实执行过**再动目标。

        ## 为什么必须等（2026-10-05 实测缺陷 —— 本文件曾因此假红）
          旧版只有一句 `time.sleep(SETTLE_S=1.2)`，**赌**宿主已调完
          `prot_integrity_start_watchdog`。而该函数末尾（`src/integrity.c:827`）
          会执行 `g_wd_policy = pol;` —— **把本工具刚写入的 CONTINUE 覆盖回
          demo 传入的 EXIT**。于是:
            段 CRC 失败 -> EXIT 分支 -> `prot_plat_terminate(0xBAD)`
            -> 进程在同一个 tick 内死亡, `g_guard_hits` **从未自增**
            -> 自检报 `negative exit=2989 hits=0` = **假的"守卫失效"**
          慢机器（如 CI runner）上 1.2s 不够 => 间歇性假红。
          本机用 `--wait-ms 5000` 把启动推后即 1/1 稳定复现该签名。

        ## 就绪信号 = `g_wd_interval != 0`（**不是** `g_wd_policy`）
          `start_watchdog` 里 `g_wd_policy = pol; g_wd_interval = interval_ms;`
          是相邻两句（`:827`/`:828`），且两者都零初始化。
          但 `g_wd_policy` **本工具自己要写**（CONTINUE = 0）-> 拿它当信号会
          **自毁证据**: 若宿主已就绪（真实值 EXIT），我们先把 0 写进去，
          信号就与"未就绪"无法区分（第一版修法正是踩了这个坑，12/12 恒报
          "未就绪"）。`g_wd_interval` 我们从不写 => 单调、无歧义。
         顺带得到**加固判据**: `start_watchdog` 里 `g_wd_interval` 仅在
         策略合法性校验（`:817-820`）**之后**才赋值，故 `g_wd_interval != 0`
          还额外证明"宿主已通过参数校验"。

        返回 `(ready, seen, waited_s)`；`seen` 记录观测到的不同值，
        供未就绪时诊断（区分"进程已死"与"只是慢"）。
        """
        t0 = time.time()
        seen = []
        while time.time() - t0 < READY_TIMEOUT_S:
            if proc.poll() is not None:
                return False, seen, time.time() - t0
            v = _rd_i32(h, va_rdy)
            if v is not None and v not in seen:
                seen.append(v)
            if v:
                return True, seen, time.time() - t0
            time.sleep(0.1)
        return False, seen, time.time() - t0

    # 缺省值与 `include/protect/protdef.h:49-51` 的枚举一致
    # （CONTINUE=0, EXIT=1, FAKE=2）；解析存在时以头文件为准。
    cont = _policy_value('PROT_POLICY_CONTINUE', 0)

    def _case(do_patch):
        rec = {}
        p = _spawn()
        time.sleep(SETTLE_S)
        h = k32.OpenProcess(PROCESS_ALL, False, p.pid)
        base = _module_base(k32, p.pid, 'demo.exe') if h else None
        rec['opened'] = bool(h)
        rec['base'] = hex(base) if base else None
        rec['dyn_n'] = None
        rec['policy_set'] = None
        rec['wrote'] = None
        rec['ready'] = None
        peak = 0
        code = None
        if h and base:
            A = lambda va: base + (va - PREF)
            # ## ⚠️ 信号与写入的**顺序无关**（2026-10-05 实测教训）
            #   就绪哨兵用 `g_wd_interval`（本工具从不写它），
            #   故这里**先读哨兵再写 CONTINUE** 只是可读性选择，不再
            #   承担"自毁证据"的风险（用 `g_wd_policy` 当信号的旧版正是
            #   因此恒报"未就绪"）。
            ready, seen, waited = _wait_ready(h, p, A(va_rdy))
            rec['ready'] = ready
            rec['ready_seen'] = [hex(v) for v in seen]
            rec['waited_s'] = round(waited, 3)
            if not ready:
                rec['wrote'] = False
                rec['exit'] = None
                rec['hits'] = 0
                if h:
                    k32.CloseHandle(h)
                if p.poll() is None:      # 别把宿主进程漏在后台
                    p.kill()
                    p.wait()
                return rec
            # 就绪后再写：覆盖 `g_wd_policy = pol;`（见文件头"为什么要改策略"）
            rec['policy_set'], _ = _wr(h, A(va_pol), bytes([cont, 0, 0, 0]))
            rec['dyn_n'] = _rd_i32(h, A(_sym_va('g_guard_dyn_n') or 0))
            if do_patch:
                rec['wrote'], back = _wr(h, A(va_fn), bytes(PATCH))
                rec['prologue'] = back.hex(' ') if back else None
        t0 = time.time()
        while time.time() - t0 < OBSERVE_S:
            if p.poll() is not None:
                rec['early_exit'] = p.returncode
                break
            if h and base:
                v = _rd_i32(h, base + (va_hits - PREF))
                if v is not None and v > peak:
                    peak = v
            time.sleep(0.2)
        code = p.poll()
        if code is None:
            p.kill()
            p.wait()
            code = None
        if h:
            k32.CloseHandle(h)
        rec['exit'] = code
        rec['hits'] = peak
        return rec

    out = {'positive': _case(False), 'negative': _case(True)}
    if verbose:
        for k in ('positive', 'negative'):
            r = out[k]
            print('    [%s] 打开=%s 基址=%s 就绪=%s(等了%.1fs, %s 观测值=%s) '
                  'dyn_n=%s 策略置CONTINUE=%s wrote=%s 序言=%s 退出=%s hits=%d'
                  % (k, r['opened'], r['base'], r.get('ready'),
                     r.get('waited_s') or 0.0, READY_SYM, r.get('ready_seen'),
                     r['dyn_n'], r['policy_set'], r['wrote'],
                     r.get('prologue'), r['exit'], r['hits']))
    return out


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(prog='guard_selftest.py')
    ap.add_argument('--target', default=None,
                    help='指定判定点（默认自动选"掩码区外"的已登记守卫）')
    ap.add_argument('--json', dest='json_out', default=None)
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    if sys.platform != 'win32':
        print('[guard_selftest] SKIP: 仅 Windows（OpenProcess/WriteProcessMemory）')
        return 0

    tamper = _exit_code('PROT_EXIT_TAMPERED', 0xBAD)

    if not os.path.isfile(EXE) or not os.path.isfile(MAP):
        print('[guard_selftest] SKIP: 缺 build/demo.exe 或 build/demo.map（需先构建）')
        return 0

    regions = _mask_regions()
    cands = _guard_candidates()

    # 候选表（打印掩码归属 —— 复核用）
    table = []
    for name, src in cands:
        va = _sym_va(name)
        rva = (va - PREF) if va else None
        table.append({'name': name, 'src': src,
                      'link_va': hex(va) if va else None,
                      'rva': hex(rva) if rva is not None else None,
                      'in_mask': _in_mask(rva, regions) if rva is not None else None,
                      'in_map': va is not None})

    if not args.quiet:
        print('=== guard_selftest（判定点序言快照校验的行为自检）===')
        print('  PROT_EXIT_TAMPERED=0x%X · selfcrypt 掩码区 %s 条 · 观察 %.0fs'
              % (tamper, len(regions) if regions is not None else '?', OBSERVE_S))
        print('  已登记守卫候选:')
        for r in table:
            print('    %-28s %-16s rva=%-10s 掩码区=%s'
                  % (r['name'], r['src'], r['rva'],
                     {True: '是', False: '否', None: '?'}[r['in_mask']]))

    # 选目标
    target = args.target
    if target is None:
        ok_c = [r['name'] for r in table if r['in_map'] and r['in_mask'] is False]
        if not ok_c:
            print()
            print('[guard_selftest] FAIL: **没有"掩码区外"的已登记守卫** -> 本自检无判别力')
            print('  原因: 掩码区内目标被 patch 会先触发 selfcrypt 的 per-region CRC')
            print('        -> src/integrity.c:198 `continue` 整轮跳过 -> 守卫跑不到')
            print('  处置: 或调整 selfcrypt 目标集合，或用 --target 指定并说明')
            return 1
        target = ok_c[0]
        if not args.quiet:
            print('  -> 自动选中掩码区外目标: %s' % target)
    else:
        rec = [r for r in table if r['name'] == target]
        if rec and rec[0]['in_mask']:
            if not args.quiet:
                print('  [!] 警告: 指定的 %s **在掩码区内** -> 预期 hits=0'
                      '（selfcrypt enter 会先失败并 continue）' % target)

    if _sym_va(HITS_SYM) is None or _sym_va(POLICY_SYM) is None \
            or _sym_va(READY_SYM) is None:
        print('[guard_selftest] SKIP: map 缺 %s / %s / %s（无法在检测域内观测）'
              % (HITS_SYM, POLICY_SYM, READY_SYM))
        return 0

    if not args.quiet:
        print()
        print('  用例（判据 = 守卫自己的命中计数）:')
    hitrec = run_by_hits(target, verbose=not args.quiet)

    results = []
    if hitrec:
        for case, label, want in (('positive', '正向(不 patch -> hits 必须 = 0)', 0),
                                  ('negative', '负向(patch -> hits 必须 > 0)', 1)):
            r = hitrec[case]
            okc = (r['hits'] == 0) if want == 0 else (r['hits'] > 0)
            if case == 'negative' and r.get('wrote') is False:
                okc = False
            # 未就绪 => **两个方向都无判别力**。正向尤其危险: 未就绪时
            # `hits` 必然 0, 若不在此拦截就会被读成"正向通过"（假绿）。
            if r.get('ready') is False:
                okc = False
            results.append((label, r, okc))
            print('  %s %-34s exit=%-6s hits=%-4d %s'
                  % ('ok  ' if okc else '**FAIL**', label, r['exit'], r['hits'],
                     '' if okc else '<- 判据未满足'))
            # 未就绪是**环境/时序**问题，不是"守卫失效" —— 必须说清
            # （2026-10-05: 旧版把它误报成"守卫未命中", 误导排查方向）
            if r.get('ready') is False:
                # 注意: 这里**不能**用 `run_by_hits` 里的 `cont`/`exit_pol`
                # —— 它们是那个函数的局部名（2026-10-05 由 `build/_undef.py`
                # 抓到: "UNDEF :557 exit_pol / :559 cont"）。就地解析。
                print('        ^ 原因: 未能等到看门狗启动（等了 %.1fs, %s 观测值=%s）'
                      % (r.get('waited_s') or 0.0, READY_SYM,
                         r.get('ready_seen')))
                print('          宿主稍后执行 `%s = %d`（src/integrity.c:827）会覆盖'
                      % (POLICY_SYM, _policy_value('PROT_POLICY_EXIT', 1)))
                print('          本工具写入的 CONTINUE(%d) -> 段 CRC 失败即 0x%X 终止,'
                      % (_policy_value('PROT_POLICY_CONTINUE', 0), tamper))
                print('          `%s` 从未自增 => 两个方向都**无判别力**, 非守卫失效。'
                      % HITS_SYM)

    ok = bool(results) and all(x[2] for x in results)
    if args.json_out:
        with open(args.json_out, 'w', encoding='utf-8') as f:
            json.dump({'target': target, 'candidates': table,
                       'segments': regions, 'cases': hitrec, 'ok': ok},
                      f, ensure_ascii=False, indent=2)

    print()
    if ok:
        print('[guard_selftest] PASS（守卫命中计数可自证: 正向 0 / 负向 > 0）')
    elif hitrec and any(r.get('ready') is False for r in hitrec.values()):
        print('[guard_selftest] FAIL: 未能等到看门狗就绪（自检无判别力）——'
              ' 见上方原因行；**不要**读成"守卫失效"')
    else:
        print('[guard_selftest] FAIL: 守卫未命中或写入失败'
              '（见 docs/DECISION_REDUNDANCY_PLAN.md §10-§11）')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
