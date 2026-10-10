#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ShardVase contributors
# 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；商业授权见 LICENSE.md。
r"""`tools/prot_dbg.py` — 调试控制台（**第 1 + 2 + 4 步**，2026-09-30/10-01）。

## 为什么需要（不是"想要"，是**实测反复踩到**）
  本项目 100+ 次调试里，同一批动作被反复手写、每次写临时脚本、每次可能踩同一批坑。
  见 `docs/DEBUG_CONSOLE_PLAN.md` §1 的清单（map 符号解析 5+ 次 / 运行时地址换算 4+ 次 /
  退出码解释 8+ 次 / 掩码归属判定 3 次 …）。

## 已实现 / 未实现（**未实现就不假装支持**，P4 诚实边界）
  第 1 步 ✅ `doctor` / `sym` / `mask` / `exit` —— **纯只读，零风险**
  第 2 步 ✅ `patch` / `read` / `watch` —— 进程内读写（Windows）
  第 4 步 ✅ 反调试干扰提示（`patch`/`read`/`watch` 自动打印，`--no-advice` 可关）
  第 3 步 ❌ `run` + `-DPROT_INTEGRITY_DEBUG` 诊断构建包装 —— **用户已降级为可选**（计划 §5）

## 用法
```
python tools/prot_dbg.py doctor                  # 环境体检 + **解析链路正向对照**
python tools/prot_dbg.py sym <名字> [<名字>…]     # 符号 -> 链接时 VA / RVA / .text 偏移 / 掩码归属
python tools/prot_dbg.py mask [<名字>…]           # 掩码区清单（产物 meta 为权威）+ 各区内的符号
python tools/prot_dbg.py exit <码> [<码>…]        # 退出码解释（**从 C 头解析，不硬编码**）
python tools/prot_dbg.py read <符号> [--len N]    # 读运行时内存（**与产物文件字节对照**）
python tools/prot_dbg.py patch <符号> [--observe S] [--policy continue]
                                                  # 运行期 patch（ASLR 自动换算 + **读回验证**）
python tools/prot_dbg.py watch <符号> [<符号>…]   # 轮询计数，打印**变化时间线**
python tools/prot_dbg.py --selftest        [--quiet]   # 第 1 步自检（**纯只读**，可进门禁）
python tools/prot_dbg.py --selftest-live   [--quiet]   # 第 2 步自检（拉目标进程；非 Windows SKIP）
```
  通用选项: `--exe P`（默认 `build/demo.exe`）· `--map P`（默认与 exe 同名 `.map`）·
  `--json F`（结构化证据落盘）· `--quiet`
  第 2 步选项: `--pid P`（附着既有进程；缺省则**本工具自己拉起** demo 并在结束时杀掉）·
  `--len N` · `--seconds S` · `--interval MS` · `--bytes HEX` · `--policy continue|exit|fake` ·
  `--observe S` · `--rva R` · `--no-advice`

## 设计纪律（**每一条都来自实际踩坑**）
  ① **退出码从 `include/protect/*.h` 解析**，不硬编码 —— R1 `docclaim` 的教训: 硬编码会漂移。
  ② **"读不到" ≠ "不存在"**（2026-09-30 我**一小时内连犯三次**）:
     map 正则形态假设错 -> 只解析出 948/2989 个符号 -> 差点判定"符号被优化掉了"。
     => 本工具**任何"空结果"都必须先证明读取链路是通的**:
        `doctor` 做**正向对照** —— map 的符号必须能落进产物节区间内，否则报 ERROR。
  ③ **掩码归属以产物自身的 `.protcry` meta 为权威**，再与 `selfcrypt_mask.txt` **交叉核对**:
     外部 txt 可能与产物不是同一次构建（R3.3 已记名: 归档产物**必须自带** `prot_sections.json`）。
  ④ **复用单一事实源**，不新写解析器:
     `tools/mapfile.py`（map 解析）· `tests/protchain_check.py`（节表 / selfcrypt meta）。
     > ⚠️ **复用函数要连隐式上下文一起设**: `protchain_check` 的
     > `load_section_names` 走模块级 `_CURRENT_EXE` —— 不设就会去解析**另一个平台**的
     > 生成物 JSON，得到**静默错误**的节名（本项目已记名的坑）。
  ⑤ **不向用户暴露未换算的运行时地址**: 打印的是**链接时 VA**，并显式提示 ASLR。
  ⑥ **不改仓库状态**（只读 + 临时目录），自检可在门禁里跑。
  ⑦ **写远程内存必须"读回验证"**（第 2 步）。**2026-10-01 实测更正了这条的理由**:
     本工具曾断言"`.text` 是只读页，所以 `WriteProcessMemory` 会**返回成功但没写进去**"——
     **该断言未复现**。实测（`build/probe_live_page2.py`，同一目标进程）:
       · **映像页**（`MEM_IMAGE`）: RX(`0x20`)、RWX(`0x40`) 不带页保护**直接写就成功**，
         且读回一致（映像是写时复制页，`SEC_IMAGE` 的只读保护**不阻止** WPM）；
         而 R(`0x02`) 失败 `err=998`。
       · **私有页**（`VirtualAllocEx`）: RX/RW 成功；R(`0x02`)/NOACCESS(`0x01`) 失败 `err=998`。
     结论: **WPM 的返回值是可信的**（失败就是 `False`）。读回验证仍然要做，但理由改成
     **① 防"部分写入"（`n.value < len`）② 防调用方从"ok"误推出语义**，
     **不是**"系统会骗你"。
     > 教训: 把没验证过的机制当成结论写进注释，比不写更危险 —— 它会误导后来人
     > 去"修"一个不存在的问题（此处正是一次自检把我自己的错误断言抓了出来）。
  ⑧ **读不到 ≠ 值为 0，也 ≠ 写入失败**（第 2 步）: 无权限 / 进程已退出 / 地址算错
     都是**不同的错误**，必须分别报出，绝不静默退化成 0。
  ⑨ **判据不能用退出码**（第 2 步）: 退出码无判别力（各检测同向命中）——
     `watch` 看的是**被观测符号自己的变化**，`patch` 打印的是**读回字节**。

## 自检（`--selftest`，1 前置 + 4 正向 + 4 负向）—— **纯只读，可进门禁**
```
T0 前置: 产物+map 就绪（缺则 SKIP，不假装通过）
T1 **正向** doctor 通过
T2 **正向** sym 一个**从 map 动态取**的真实符号（不硬编码名字）
T3 **正向** exit 0xBAD -> PROT_EXIT_TAMPERED（从头文件解析）
T4 **正向** exit 11 -> 必须指出 = 0xB10B 的**低 8 位**（Linux exit() 截断）
T5 **负向** sym 不存在的符号 -> **必须失败**（且不崩溃）
T6 **负向** exit 未定义的码 -> **必须明确"未知"**，不得猜测
T7 **负向** map 为**空文件** -> doctor **必须报错**（不是静默通过）
T8 **负向** map **非空但格式不可识别** -> doctor 必须报"读不到 != 不存在"
T9 **负向** 掩码判定不得恒真/恒假（区内点必须在、区外点必须不在）
```

## 活体自检（`--selftest-live`，第 2 步；**会拉起 demo.exe 并在结束时杀掉**）
```
L0 前置: Windows + 产物就绪（非 Windows -> **SKIP 并说明**，不假装通过）
L1 **正向** `read` 一个真实符号 -> 读到的字节必须**与产物文件同址字节一致**
           （把"内存读取链路"钉死在文件这个已知基准上 —— 纪律 ②）
L2 **正向** `patch` -> **读回验证**必须成功，且 patch 前字节与 patch 后字节**必须不同**
L3 **负向** `read` 一个不存在的符号 -> **必须 rc=1**，不得读成 0
L4 **负向对照** **写入链路必须有判别力**: 写一个**私有只读页**（`VirtualAllocEx` +
           `PAGE_READONLY`）-> 必须**明确失败**（`err=998`）。
           ⚠ 2026-10-01 实测更正: 原先写的是"不改页保护写 `.text` -> 必须失败"，
           **该前提是错的** —— 映像 RX 页**可以**直接写成功（写时复制），
           L4 因此一度 FAIL。改用**自建页**做对照，因为它给的是**受控**的保护值，
           不受 `SEC_IMAGE` 语义影响。（见纪律 ⑦）
L5 **负向** `watch` 一个**同址不变量**（只 patch 后应保持的字节）-> 必须报"无变化"
           而不是凭空报变化（采样链路不得恒报）
```
"""
import argparse
import ctypes
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _d in ('tools', 'tests'):
    _p = os.path.join(REPO, _d)
    if _p not in sys.path:
        sys.path.insert(0, _p)

import mapfile                  # noqa: E402  单一 map 解析实现
import protchain_check as pc    # noqa: E402  节表 / selfcrypt meta 的权威解析

DEFAULT_EXE = os.path.join(REPO, 'build', 'demo.exe')
PROT_HDR_DIR = os.path.join(REPO, 'include', 'protect')

# ---- 第 2 步（活体调试）常量 ---------------------------------------------
# 这些值与 `tools/guard_selftest.py` **同源**（共享思路，不共享代码）:
# 该文件已被门禁第 29 项验收，此处是它的**参数化重写**（目标符号/长度可传参），
# 而不是反过来 import 它（它 print 大量输出且不接受参数）。
PREF = 0x140000000              # PE 默认映像基址（map 里的链接时 VA 隐含它）
PATCH = (0x31, 0xC0, 0xC3)      # xor eax,eax; ret —— 函数头 patch 的经典形态
SETTLE_S = 1.2                  # 拉起进程后等它把 watchdog/自检跑起来
POLL_S = 0.2                    # watch 采样间隔
OBSERVE_S = 15.0                # watch 默认观察窗口
KEEP_MS = 30000                 # 自拉目标时留给我们的调试窗口（--wait-after）
PROCESS_ALL = 0x1F0FFF
TH32CS_SNAPMODULE = 0x8
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_GUARD = 0x100
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
MEMORY_BASIC_INFORMATION_SIZE = 48   # x64: 8+8+4+4+2+2+4+8 = 48
EXIT_DEBUG_DETECTED = 219       # PROT_EXIT_DEBUG_DETECTED（第 4 步提示里引用）
SYM_POLICY = 'g_wd_policy'
SYM_HITS = 'g_guard_hits'
SYM_TAMPER = 'g_wd_tamper'


def rel(p):
    """仓库相对路径（显示用；失败则原样返回）。"""
    try:
        r = os.path.relpath(p, REPO)
        return p if r.startswith('..') else r
    except ValueError:
        return p


def default_map_for(exe):
    """产物 -> 同名 `.map`（`build/demo.exe` -> `build/demo.map`）。"""
    return os.path.splitext(exe)[0] + '.map'


def plat_of(path):
    """按**魔数**判平台（不猜扩展名）。读不到返回 None。"""
    try:
        with open(path, 'rb') as f:
            magic = f.read(4)
    except OSError:
        return None
    return 'linux' if magic == b'\x7fELF' else 'win'


def build_dir_of(plat):
    """平台专属 build 目录（**唯一事实源** `tools/genpaths.py`）。"""
    import genpaths
    return genpaths.paths(plat or 'win').build_dir


# ===========================================================================
# 第 2 步：活体调试（读 / 写目标进程内存）
#
# ⚠ 第 4 步的核心结论固化在这段文本里，**所有活体命令都必须打印它**:
#   本工具用 `OpenProcess`/`ReadProcessMemory` 打开目标进程，这**本身就是调试行为**，
#   可能被 demo 自身的反调试检测到，目标可能以 219（PROT_EXIT_DEBUG_DETECTED）退出。
#   **该退出码不能作为"守卫有效/失效"的判据** —— 2026-09-30 实测差点把它误读成"守卫失效"。
# ===========================================================================
ANTIDEBUG_NOTICE = [
    '⚠ 反调试干扰提示（docs/DEBUG_CONSOLE_PLAN.md 第 4 步）:',
    '  本工具用 OpenProcess/ReadProcessMemory 打开目标进程 —— **这本身就是调试行为**，',
    '  可能被 demo 自身的反调试检测到，目标可能以 219 (%d = PROT_EXIT_DEBUG_DETECTED) 退出。' % EXIT_DEBUG_DETECTED,
    '  **219 不能作为"守卫有效/失效"的判据**：它只说明"检测到了"，不说明"检测准不准"。',
    '  判据请用**被观测符号自己的值**（`read` 读回的字节 / `watch` 看到的变化）。',
]

_ERROR_HINTS = {
    5: ('ACCESS_DENIED', '权限不足：需要与目标**相同或更高完整性级别**（本工具不提权）。'
                         '请以同等权限重跑，或改用 --pid 附着由你自己启动的目标。'),
    6: ('INVALID_HANDLE', '句柄无效：目标进程**可能已经退出**（查 --pid 是否还在）。'),
    87: ('INVALID_PARAMETER', '参数无效：多半是**地址算错**（RVA 换算）或长度越界。'),
    299: ('PARTIAL_COPY', '只能读取部分内存 -> **地址很可能不对**。两个最常见原因: '
                          '① 拿**链接时 VA**（0x140000000 附近）去读 ASLR 后的进程 '
                          '（必须先减映像基址、再加**运行时**模块基址）；'
                          '② 该地址不在已提交页内（未初始化 / 已释放 / 只在文件里）。'),
}


class DbError(Exception):
    """带**分类**的调试错误。

    纪律 ⑧: 权限 / 进程 / 地址 / 符号是**不同的**错误，必须分开报出，
    绝不静默退化成"读到 0"或"写入失败但不吭声"。
    """

    def __init__(self, kind, msg, hint=None):
        Exception.__init__(self, msg)
        self.kind = kind          # permission|process|address|symbol|platform|internal
        self.msg = msg
        self.hint = hint


def _why(k32, default_kind='address'):
    """把 Win32 最后一次错误翻成 (kind, 可读文本)。"""
    code = ctypes.get_last_error() if k32 is not None else 0
    name, hint = _ERROR_HINTS.get(code, ('ERROR_%d' % code, None))
    kind = 'permission' if code == 5 else ('process' if code in (6, 87) else default_kind)
    if code == 87:
        kind = 'address'
    txt = 'Win32 %d (%s)' % (code, name)
    return kind, txt, hint


class _MODULEENTRY32(ctypes.Structure):
    """`Module32First/Next` 的结构体。

    ⚠ 用它取**运行时**模块基址，**不要**用 `PREF`(0x140000000) 直接读 ——
    2026-09-30 的实测教训: 那样读会全部失败并报 `err=299 (ERROR_PARTIAL_COPY)`，
    差点被读成"这个变量不存在"（`tools/guard_selftest.py` 同款记录）。
    """

    _fields_ = [
        ('dwSize', ctypes.c_ulong),
        ('th32ModuleID', ctypes.c_ulong),
        ('th32ProcessID', ctypes.c_ulong),
        ('GlblcntUsage', ctypes.c_ulong),
        ('ProccntUsage', ctypes.c_ulong),
        ('modBaseAddr', ctypes.c_void_p),
        ('modBaseSize', ctypes.c_ulong),
        ('hModule', ctypes.c_void_p),
        ('szModule', ctypes.c_char * 256),
        ('szExePath', ctypes.c_char * 260),
    ]


def _kernel32():
    """绑定 kernel32（**只在 Windows 上**；非 Windows 抛 platform 类错误）。"""
    if sys.platform != 'win32':
        raise DbError('platform', '本功能仅 Windows（OpenProcess/ReadProcessMemory/WriteProcessMemory）',
                      '在 Linux 上用 `readelf`/`gdb`，或改跑 CI 的 Linux 门禁。')
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    from ctypes import wintypes as wt
    k32.OpenProcess.restype = wt.HANDLE
    k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    k32.CloseHandle.argtypes = [wt.HANDLE]
    k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k32.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k32.VirtualProtectEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                     wt.DWORD, ctypes.POINTER(wt.DWORD)]
    k32.VirtualQuery.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    # 自检 L4 的**受控**对照页需要自己分配/设保护/释放
    k32.VirtualAllocEx.restype = ctypes.c_void_p
    k32.VirtualAllocEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                   wt.DWORD, wt.DWORD]
    k32.VirtualFreeEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD]
    k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    k32.Module32First.argtypes = [wt.HANDLE, ctypes.POINTER(_MODULEENTRY32)]
    k32.Module32Next.argtypes = [wt.HANDLE, ctypes.POINTER(_MODULEENTRY32)]
    return k32


def _module_base(k32, pid, exe_name):
    """取**运行时**模块基址（ASLR 后的真实基址）。找不到返回 None。"""
    TH32CS_SNAPMODULE32 = 0x10
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if not snap or snap in (ctypes.c_void_p(-1).value, -1):
        return None
    try:
        me = _MODULEENTRY32()
        me.dwSize = ctypes.sizeof(_MODULEENTRY32)
        if not k32.Module32First(snap, ctypes.byref(me)):
            return None
        want = os.path.basename(exe_name).lower().encode()
        while True:
            if want in me.szModule.lower():
                return me.modBaseAddr or None
            if not k32.Module32Next(snap, ctypes.byref(me)):
                return None
    finally:
        k32.CloseHandle(snap)


def file_bytes_at(ctx, rva, n):
    """产物**文件里**同地址的字节（用于 `read` 的正向对照）；不在任何节原始数据内返回 None。

    这是纪律 ② 的落地: 内存读取链路必须钉死在一个**已知基准**（文件）上，
    否则"读到 0x00"到底是真值还是读失败，无法分辨。
    """
    if not ctx or not ctx.data:
        return None
    for s in ctx.secs:
        va, raw, ptr = s['virtual_addr'], s['size_raw'], s['ptr_raw']
        if raw and va <= rva < va + raw:
            off = ptr + (rva - va)
            return ctx.data[off:off + n]
    return None


class Target(object):
    """一个**活着的**调试目标：已换算的运行时地址 + 已打开的进程句柄。"""

    def __init__(self, k32, pid, base, exe_path, proc=None):
        self.k32 = k32
        self.pid = pid
        self.base = base
        self.exe_path = exe_path
        self.proc = proc          # 自己拉起的 Popen；None = 附着到别人的进程
        self.owns = proc is not None
        self.h = None
        self.errors = []

    # ---- 生命周期 ---------------------------------------------------------
    def open(self):
        self.h = self.k32.OpenProcess(PROCESS_ALL, False, self.pid)
        if not self.h:
            kind, txt, hint = _why(self.k32, 'process')
            raise DbError(kind, 'OpenProcess(pid=%d) 失败: %s' % (self.pid, txt), hint)
        return self

    def close(self):
        if self.h:
            self.k32.CloseHandle(self.h)
            self.h = None

    def alive(self):
        return self.proc is None or self.proc.poll() is None

    def exit_code(self):
        return None if self.proc is None else self.proc.poll()

    def kill(self):
        if self.owns and self.proc and self.proc.poll() is None:
            self.proc.kill()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                pass

    # ---- 页查询（L4 的受控对照要用）---------------------------------------
    def prot_of(self, va):
        """返回该地址所在页的 `(Protect, RegionSize, State)`；查不到返回 `(None, 0, 0)`。"""
        from ctypes import wintypes as wt
        mbi = ctypes.create_string_buffer(MEMORY_BASIC_INFORMATION_SIZE)
        n = self.k32.VirtualQuery(self.h, ctypes.c_void_p(va), mbi,
                                  MEMORY_BASIC_INFORMATION_SIZE)
        if not n:
            return None, 0, 0
        # x64 MEMORY_BASIC_INFORMATION: BaseAddress(8) AllocationBase(8)
        #   AllocationProtect(4) PartitionId(2) pad(2) RegionSize(8)
        #   State(4) Protect(4) Type(4) pad(4)
        prot = ctypes.c_uint32.from_buffer(mbi, 32).value
        state = ctypes.c_uint32.from_buffer(mbi, 40).value
        size = ctypes.c_uint64.from_buffer(mbi, 24).value
        return prot, size, state

    def alloc_ro_page(self, size=0x1000):
        """分配一个**私有只读页**并返回地址（L4 的受控对照）。

        为什么不用映像 `.text` 当对照: 映像页是 `SEC_IMAGE` 写时复制，
        其"只读"**不阻止** `WriteProcessMemory` —— 2026-10-01 实测（纪律 ⑦）。
        私有页的保护值由我们**自己设定**，才是干净的对照。
        """
        mem = self.k32.VirtualAllocEx(self.h, None, size,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not mem:
            kind, txt, hint = _why(self.k32, 'internal')
            raise DbError(kind, 'VirtualAllocEx 失败: %s' % txt, hint)
        # 先写点已知字节（RW 时写入），再降为只读
        ok, back, det = self.write(mem, b'\xA5' * 16, protect=False)
        if not ok:
            raise DbError('internal', '对照页初始化写入失败: %s' % det)
        from ctypes import wintypes as wt
        old = wt.DWORD(0)
        if not self.k32.VirtualProtectEx(self.h, ctypes.c_void_p(mem), size,
                                         PAGE_READONLY, ctypes.byref(old)):
            kind, txt, hint = _why(self.k32, 'internal')
            raise DbError(kind, '对照页设为 PAGE_READONLY 失败: %s' % txt, hint)
        return mem

    def free_page(self, mem):
        if mem:
            self.k32.VirtualFreeEx(self.h, ctypes.c_void_p(mem), 0, MEM_RELEASE)

    # ---- 地址换算 ---------------------------------------------------------
    def rt(self, link_va):
        """**链接时 VA -> 运行时地址**（这就是"ASLR 自动换算"）。

        绝不允许把 `link_va` 直接当运行时地址用（`err=299` 的经典来源）。
        """
        return self.base + (link_va - PREF)

    # ---- 读写 -------------------------------------------------------------
    def read(self, va, n):
        """读 n 字节；**失败抛错**（绝不返回 b'\\x00'*n 冒充成功）。"""
        buf = (ctypes.c_ubyte * n)()
        got = ctypes.c_size_t(0)
        ok = self.k32.ReadProcessMemory(self.h, ctypes.c_void_p(va), buf, n, ctypes.byref(got))
        if not ok or got.value != n:
            kind, txt, hint = _why(self.k32)
            raise DbError(kind, 'ReadProcessMemory(0x%X, %d) 失败: %s（读到 %d 字节）'
                          % (va, n, txt, got.value), hint)
        return bytes(buf)

    def write(self, va, data, protect=True):
        """写远程内存 + **读回验证**（纪律 ⑦）。

        返回 `(ok, back, detail)`。`protect=False` 用于自检的**负向对照**：
        不给页解锁就写**私有只读页**，**必须失败**（`err=998`）。

        ⚠ 2026-10-01 实测更正: 曾以为"映像 `.text` 是只读页，WPM 会返回成功却没写进去"——
        **未复现**。映像页（`SEC_IMAGE`）的 RX/RWX **不阻止** WPM（写时复制），
        返回值可信。故这里的 `protect=` **只是省事**（免得每个调用点自己管页保护），
        **不是**为了绕开"系统会骗你"。
        """
        data = bytes(data)
        from ctypes import wintypes as wt
        old = wt.DWORD(0)
        if protect:
            if not self.k32.VirtualProtectEx(self.h, ctypes.c_void_p(va & ~0xFFF), 0x1000,
                                             PAGE_EXECUTE_READWRITE, ctypes.byref(old)):
                kind, txt, hint = _why(self.k32, 'permission')
                return False, None, 'VirtualProtectEx 失败: %s' % txt
        n = ctypes.c_size_t(0)
        buf = (ctypes.c_ubyte * len(data))(*data)
        ok = bool(self.k32.WriteProcessMemory(self.h, ctypes.c_void_p(va), buf, len(data),
                                             ctypes.byref(n)))
        werr = None
        if not ok:
            kind, txt, hint = _why(self.k32, 'address')
            werr = txt + ('；' + hint if hint else '')
        if protect and old.value:
            self.k32.VirtualProtectEx(self.h, ctypes.c_void_p(va & ~0xFFF), 0x1000,
                                      old.value, ctypes.byref(old))
        back = None
        try:
            back = self.read(va, len(data))
        except DbError as e:
            werr = (werr or '') + ' [读回也失败: %s]' % e.msg
        good = bool(ok) and n.value == len(data) and back == data
        detail = werr or ('写入并读回一致' if good else '写入返回成功但**读回不一致**')
        return good, back, detail


def _resolve(ctx, name):
    """符号名 -> 信息 dict；缺失抛 symbol 类错误（**不静默**）。"""
    info = ctx.sym(name)
    if info is None:
        raise DbError('symbol', '符号 `%s` **不在 map 中**' % name,
                      '可能原因:\n    - ' + '\n    - '.join(ctx.why_missing(name)))
    return info


def _default_target(ctx, pid):
    """`--pid` 附着已有进程；否则**自己拉起 demo**（带标准参数）。"""
    k32 = _kernel32()
    exe = ctx.exe
    if pid:
        # 纪律 ⑧: 先确认**能打开**，再谈"模块在不在" —— 否则把 ACCESS_DENIED
        # （如 pid 4 = System，低权限打不开）误报成"模块名不符/进程已退出"。
        h = k32.OpenProcess(PROCESS_ALL, False, pid)
        if not h:
            code = ctypes.get_last_error()
            name, _hint = _ERROR_HINTS.get(code, ('ERROR_%d' % code, None))
            # OpenProcess 的错误**只能**是"权限 / 进程"两类，**不是**地址问题 ——
            # 这里必须盖掉默认的 address 归类，否则提示会把人引向 RVA 换算（错方向）。
            if code == 5:
                raise DbError('permission', 'OpenProcess(pid=%d) 失败: Win32 %d (%s)'
                              % (pid, code, name),
                              '权限不足：需要与目标**相同或更高完整性级别**'
                              '（本工具不提权）。请以同等权限重跑。')
            raise DbError('process', 'OpenProcess(pid=%d) 失败: Win32 %d (%s)'
                          % (pid, code, name),
                          '该 pid **不存在或已退出**（ERR 87 = 参数无效通常就是"没有这个进程"）。'
                          '用任务管理器/`Get-Process` 确认 pid 后再附着。')
        k32.CloseHandle(h)
        base = _module_base(k32, pid, exe)
        if base is None:
            raise DbError('process',
                          '在 pid=%d 里找不到模块 `%s`（进程可能已退出，或模块名不符）'
                          % (pid, os.path.basename(exe)),
                          '用 `--exe` 指明正确的产物，或确认 --pid 仍在运行。')
        return Target(k32, pid, base, exe, proc=None)
    # ---- 自己拉起 ---------------------------------------------------------
    bd = os.path.dirname(os.path.abspath(exe))
    argv = [exe, '--selftest', '--wait-after', str(int(KEEP_MS))]
    blob = os.path.join(bd, 'vm.blob')
    if os.path.exists(blob):
        argv += ['--vm-blob', blob]
    lic = os.path.join(bd, 'license.txt')
    if os.path.exists(lic):
        argv += ['--license-file', lic]
    print('[prot_dbg] 拉起目标: %s' % ' '.join('"%s"' % a for a in argv))
    proc = subprocess.Popen(argv, cwd=REPO, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    time.sleep(SETTLE_S)
    if proc.poll() is not None:
        raise DbError('process',
                      '目标在 %.1fs 内就以 %s 退出 —— 无法调试（先跑 `prot_dbg doctor` 看产物/依赖）'
                      % (SETTLE_S, proc.returncode))
    base = _module_base(k32, proc.pid, exe)
    if base is None:
        proc.kill()
        raise DbError('process', '拿不到 pid=%d 的运行时模块基址' % proc.pid)
    return Target(k32, proc.pid, base, exe, proc=proc)


def _adwarn(quiet, no_adwarn, where, js=None):
    """第 4 步验收: 提示文本必须出现在 `patch`/`watch` 的输出里；`--quiet` 可关。

    ⚠ 2026-10-10 (ST3.4) 更正: **`--quiet` 只关人读文本, 不关事实**。
    原实现在 `quiet or no_adwarn` 时直接 `return` —— 于是自动化调用方
    (取数据一律走 `--quiet`, 免得混进人读文本) **恰好永远看不到这条提示**,
    而它正是"不要把 219 读成守卫失效"的唯一防线（2026-09-30 差点误读）。
    ⇒ 现在无论是否打印, 都往 `js` 写入机读记录; `shown` 如实区分印没印。
    """
    rec = {
        'possible': True,
        'why': '本工具用 OpenProcess/ReadProcessMemory 打开目标进程, '
               '**这本身就是调试行为**, 可能被目标的自身反调试检测到',
        'exit_code_if_detected': EXIT_DEBUG_DETECTED,
        'cannot_be_used_as': '守卫有效/失效的判据',
        'why_not': '该退出码只说明"检测到了", 不说明"检测准不准"',
        'how_to_judge': '用**被观测符号自己的值**'
                        '（read 读回的字节 / watch 看到的变化）',
        'command': where,
        'shown': not (quiet or no_adwarn),
    }
    if js is not None:
        js['antidebug_interference'] = rec
    if quiet or no_adwarn:
        return
    print('')
    for ln in ANTIDEBUG_NOTICE:
        print('[%s] %s' % (where, ln))



# ===========================================================================
# 上下文：一次加载，多命令复用
# ===========================================================================
class Ctx(object):
    """产物 + map + 掩码的**只读**上下文。

    `errors` 里的每一条都是**判据失败**（含"读取链路可疑"），
    调用方**不得**把 `errors` 非空当成"目标不存在"（纪律 ②）。
    """

    def __init__(self, exe=None, map_path=None):
        self.exe = os.path.abspath(exe or DEFAULT_EXE)
        self.map_path = os.path.abspath(map_path or default_map_for(self.exe))
        self.plat = plat_of(self.exe)
        self.errors = []
        self.warns = []
        self.data = None
        self.image_base = mapfile.DEFAULT_IMAGE_BASE
        self.secs = []
        self.text = None
        self.cry_sec = None
        self.meta = []          # [(rva, len, group)]
        self.mask_txt = None    # [(rva, len)] 或 None（文件不存在）
        self.syms = {}          # {名字: RVA}
        self.map_lines = 0
        self.map_fmt = None
        self._load()

    # ---- 加载 -------------------------------------------------------------
    def _load(self):
        self._load_exe()
        self._load_map()
        self._load_mask()

    def _load_exe(self):
        if not os.path.isfile(self.exe):
            self.errors.append('产物不存在: %s'
                               '（先构建: powershell -File build.ps1）' % rel(self.exe))
            return
        try:
            with open(self.exe, 'rb') as f:
                self.data = f.read()
        except OSError as e:
            self.errors.append('产物读取失败: %s' % e)
            return
        try:
            self.secs = pc.sections_of(self.data)
        except Exception as e:                       # noqa: BLE001
            self.errors.append('节表解析失败: %s: %s' % (type(e).__name__, e))
            return
        self.text = next((s for s in self.secs if s['name'] == '.text'), None)
        if self.text is None:
            self.errors.append('产物中找不到 .text 节（节名: %s）'
                               % ', '.join(s['name'] for s in self.secs))
        self.image_base = mapfile.read_image_base(self.exe)

        # ## 纪律 ④: 复用 protchain_check 前**必须**先设隐式上下文
        #   否则 `load_section_names` 会去解析**另一个平台**的 prot_sections.json，
        #   得到静默错误的节名 -> protcry 找不到 -> 掩码恒空（正是纪律 ② 的形态）。
        pc._CURRENT_EXE = self.exe

        try:
            cry_names = pc.cry_section_names()
        except Exception as e:                       # noqa: BLE001
            cry_names = set()
            self.errors.append('protcry 节名解析失败: %s' % e)
        found = [s for s in self.secs if s['name'] in cry_names]
        if not found:
            self.errors.append(
                '产物中找不到 protcry 节（候选名 %s）—— 生成物 JSON 缺失/平台错配？'
                '（**不等于**"没有 selfcrypt"）' % sorted(cry_names))
        else:
            self.cry_sec = found[0]
            try:
                self.meta = pc.selfcrypt_meta(self.data, self.secs)
            except Exception as e:                   # noqa: BLE001
                self.errors.append('selfcrypt meta 解析失败: %s' % e)

    def _load_map(self):
        if not os.path.isfile(self.map_path):
            self.errors.append('map 不存在: %s（先构建；或 --map 指定）'
                               % rel(self.map_path))
            return
        try:
            with open(self.map_path, encoding='utf-8', errors='replace') as f:
                self.map_lines = sum(1 for _ in f)
        except OSError as e:
            self.errors.append('map 读取失败: %s' % e)
            return
        self.map_fmt = mapfile.detect_format(self.map_path)
        self.syms = mapfile.parse(self.map_path)

        # ## 纪律 ②: "读不到" ≠ "不存在" —— 三种"空"必须**分别**判定
        #   ⚠️ 本分支是自检 T7 逼出来的: 最初的写法只覆盖 `map_lines > 0`，
        #      于是**空 map 会静默 PASS**（0 个符号却报 doctor PASS）——
        #      正是"读不到当成不存在"的形态，只是发生在工具自己身上。
        #      => 判据: **符号表为空就不许 PASS**，且原因要区分得开。
        if self.map_lines == 0:
            self.errors.append(
                'map 文件为**空**（0 行）-> 一个符号都取不到，'
                '任何据此得出的"某某符号不存在"结论都无效（**读不到 != 不存在**）')
        elif self.map_fmt is None:
            self.errors.append(
                'map 非空（%d 行）但**格式未识别**（既非 MSVC 亦非 gcc 形态）'
                '-> 这是**读取链路异常**，不是"符号不存在"' % self.map_lines)
        elif not self.syms:
            self.errors.append(
                'map 非空（%d 行）但**解析出 0 个符号** -> 解析链路异常'
                '（**读不到 != 不存在**）' % self.map_lines)
        self._positive_control()

    def _positive_control(self):
        """**正向对照**: 已知非空的靶子必须能被读到。

        今日实测教训: 用链接偏好基址去读 ASLR 后的进程 -> 全部 `err=299`
        -> 差点判定"变量不存在"。**任何"为 0/读不到"的结论都必须先证明链路是通的。**
        这里用**结构性**对照（不硬编码符号名）:
          map 的符号 RVA 必须能落进产物自身节表的区间内。
        落不进去 => 基址算错 / map 与产物不是同一次构建 / 平台错配。
        """
        if not self.syms or not self.secs:
            return
        end = max(s['virtual_addr'] + max(s['virtual_size'], s['size_raw'])
                  for s in self.secs)
        inside = [n for n, r in self.syms.items() if 0 <= r < end]
        if not inside:
            self.errors.append(
                'map 的 %d 个符号**无一**落在产物节区间 [0, 0x%X) 内'
                '-> 基址/平台不匹配（**读不到 != 不存在**；也说明 map 与产物不同源）'
                % (len(self.syms), end))
        else:
            self._n_inside = len(inside)

    def _load_mask(self):
        p = os.path.join(build_dir_of(self.plat), 'selfcrypt_mask.txt')
        if not os.path.isfile(p):
            self.warns.append('掩码提示文件不存在: %s（不影响 meta 权威判定）' % rel(p))
            return
        out = []
        try:
            with open(p, encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split(',')
                    if len(parts) < 2:
                        continue
                    out.append((int(parts[0], 0), int(parts[1], 0)))
        except (OSError, ValueError) as e:
            self.warns.append('掩码提示文件解析失败: %s' % e)
            return
        self.mask_txt = out
        got = sorted((r, l) for r, l, _g in self.meta)
        if got != sorted(out):
            self.warns.append(
                '掩码**交叉核对不一致**: 产物 meta %d 区 %s vs `selfcrypt_mask.txt` '
                '%d 区 %s -> 该 txt 与产物**不是同一次构建**（已有检查 P2 会抓；'
                '以产物 meta 为准）' % (len(got), got, len(out), sorted(out)))

    # ---- 查询 -------------------------------------------------------------
    def mask_hit(self, rva):
        """RVA -> 掩码区 `(rva, len, group)` 或 None。"""
        for r, l, g in self.meta:
            if r <= rva < r + l:
                return (r, l, g)
        return None

    def text_off(self, rva):
        """RVA -> `.text` 内偏移（不在 .text 内返回 None）。"""
        if not self.text:
            return None
        t0 = self.text['virtual_addr']
        t1 = t0 + max(self.text['virtual_size'], self.text['size_raw'])
        return (rva - t0) if t0 <= rva < t1 else None

    def sym(self, name):
        """名字 -> 信息 dict；不在 map 中返回 None。"""
        rva = self.syms.get(name)
        if rva is None:
            return None
        return {
            'name': name,
            'rva': rva,
            'va': rva + self.image_base,
            'image_base': self.image_base,
            'text_off': self.text_off(rva),
            'mask': self.mask_hit(rva),
        }

    def why_missing(self, name):
        """符号找不到时，给出**可能原因清单**（而不是只说"没找到"）。"""
        out = []
        if not self.syms:
            out.append('map 未成功解析（见 doctor 的解析链路自检）')
        if name.startswith('_') or name.startswith('?'):
            out.append('MSVC 会修饰名字（`_` 前缀 / `?` 开头的 C++ 修饰名）—— '
                       '请用 map 里的**原始拼写**')
        out.append('名字拼写（区分大小写；`static` 函数会带 `_`/修饰前缀）')
        out.append('该符号被编译器内联/合并（`/O2` 下 static 函数可能消失）')
        out.append('map 与产物不同源（跑一次 build 再试）')
        return out


# ===========================================================================
# exit 子命令：退出码解释（**从 C 头解析**）
# ===========================================================================
def parse_code_table():
    """-> [(值, 名字, 来源, 备注), ...]。**解析**而非硬编码（纪律 ①）。"""
    out = []
    if os.path.isdir(PROT_HDR_DIR):
        for fn in sorted(os.listdir(PROT_HDR_DIR)):
            if not fn.endswith('.h'):
                continue
            p = os.path.join(PROT_HDR_DIR, fn)
            try:
                t = open(p, encoding='utf-8', errors='replace').read()
            except OSError:
                continue
            for m in re.finditer(
                    r'#define\s+(PROT_EXIT_\w+)\s+(0x[0-9A-Fa-f]+|\d+)([^\n]*)', t):
                note = re.sub(r'/\*|\*/', '', m.group(3)).strip()
                out.append((int(m.group(2), 0), m.group(1), fn, note))
    # prot_status 枚举: 顺序隐含取值（PROT_OK = 0），显式 `= N` 覆盖
    p = os.path.join(PROT_HDR_DIR, 'protdef.h')
    if os.path.isfile(p):
        t = open(p, encoding='utf-8', errors='replace').read()
        m = re.search(r'typedef\s+enum\s+prot_status\s*\{(.*?)\}\s*prot_status\s*;',
                      t, re.S)
        if m:
            body = re.sub(r'/\*.*?\*/', '', m.group(1), flags=re.S)
            idx = 0
            for line in body.splitlines():
                line = line.strip().rstrip(',').strip()
                if not line:
                    continue
                mm = re.match(r'(PROT_\w+)\s*(?:=\s*(\d+))?$', line)
                if not mm:
                    continue
                if mm.group(2) is not None:
                    idx = int(mm.group(2))
                out.append((idx, mm.group(1), 'protdef.h (prot_status)',
                            '(状态码，非进程退出码)'))
                idx += 1
    return out


def explain_code(code, table):
    """-> (是否已知, 文本行 list)。"""
    lines = []
    direct = [e for e in table if e[0] == code]
    low = [e for e in table if e[0] > 0xFF and (e[0] & 0xFF) == code]
    if direct:
        for v, n, src, note in direct:
            lines.append('  = 0x%X (%d)  %s   [%s] %s' % (v, v, n, src, note))
    if low:
        if not direct:
            lines.append('  直接匹配: 无')
        lines.append('  ⚠ 但它是以下**大码的低 8 位**（Linux `exit()` 只保留低 8 位，'
                     'Windows `ExitProcess` 保留全 32 位）:')
        for v, n, src, note in low:
            lines.append('      0x%X (%d) & 0xFF = %d  ->  %s   [%s]'
                         % (v, v, code, n, src))
    if not direct and not low:
        lines.append('  未知: 该码**不在** `include/protect/` 的任何 `PROT_EXIT_*` '
                     '定义或 `prot_status` 枚举中。')
        lines.append('  （本工具**不猜测** —— 若确属业务层自定返回码，'
                     '请在源码中加 `#define`/注释后再查。）')
    # ## 同值歧义只在**真的同值**时报（"判据必须唯一"）
    #   最初写法对任何命中 prot_status 的码都报，导致 `11` 也附带一句
    #   与它无关的 0/1/2 说明 —— 噪声会稀释告警，等于没有告警。
    if code in (0, 1, 2) and any(
            e[2] == 'protdef.h (prot_status)' for e in direct):
        lines.append('  ⚠ 同值歧义: %d 在 `demo/main.c` 里**也被用作业务层返回码**'
                     '（`return 1` = 授权无效、`return 2` = 用法错误），'
                     '与 `prot_status` 的数值**不是同一语义** —— 判定时必须结合上下文。'
                     % code)
    # 状态码与退出码数值空间**重叠**（两套枚举各自从 0 起）:
    #   仅当「本码命中 prot_status」且「本码同时是某个 PROT_EXIT_* 的低 8 位」时
    #   才是真正的不可区分（实测例: 11 = PROT_ERR_BLOB_CORRUPT = 0xB10B & 0xFF）。
    if low and any(e[2] == 'protdef.h (prot_status)' for e in direct):
        lines.append('  ⚠ 另一处重叠: `prot_status` 状态码 %d 与 `PROT_EXIT_*` 的'
                     '低 8 位折算值**数值相同**，单看码无法区分 —— '
                     '须结合「谁在什么时机退出」判断（见 `docs/HANDOVER.md`）。' % code)
    return (bool(direct or low), lines)


# ===========================================================================
# 子命令
# ===========================================================================
def cmd_doctor(ctx, quiet, js):
    print('[prot_dbg doctor] 仓库: %s' % REPO)
    print('平台: %s   产物: %s   基址 0x%X (%s)'
          % (ctx.plat or '?', rel(ctx.exe), ctx.image_base,
             '从 PE 头读' if ctx.plat == 'win' else 'ELF 侧'))
    print()
    print('输入文件:')
    for label, p in (('产物', ctx.exe), ('map', ctx.map_path),
                     ('vm.blob', os.path.join(build_dir_of(ctx.plat), 'vm.blob')),
                     ('license.txt',
                      os.path.join(build_dir_of(ctx.plat), 'license.txt')),
                     ('selfcrypt_mask.txt',
                      os.path.join(build_dir_of(ctx.plat), 'selfcrypt_mask.txt'))):
        if os.path.isfile(p):
            print('  ok   %-20s %10d B  %s' % (label, os.path.getsize(p), rel(p)))
        else:
            print('  --   %-20s %10s    %s' % (label, '(缺失)', rel(p)))
    print()
    print('解析链路自检（**"读不到" != "不存在"**）:')
    print('  map 格式识别   %s' % (ctx.map_fmt or '**未识别**'))
    print('  map 原始行数   %d' % ctx.map_lines)
    print('  解析出符号数   %d' % len(ctx.syms))
    n_in = getattr(ctx, '_n_inside', None)
    print('  正向对照       落进产物节区间的符号数: %s'
          % ('%d（链路通）' % n_in if n_in else '**0 -> 链路异常/不同源**'))
    print('  节表           %d 节%s' % (len(ctx.secs),
          '' if not ctx.text else '（.text rva=0x%X vsize=0x%X raw=0x%X）'
          % (ctx.text['virtual_addr'], ctx.text['virtual_size'],
             ctx.text['size_raw'])))
    print()
    print('掩码区（权威来源: 产物 `%s` meta）:'
          % (ctx.cry_sec['name'] if ctx.cry_sec else '?'))
    print('  产物 meta      %d 区' % len(ctx.meta))
    print('  提示文件       %s'
          % ('%d 区（交叉核对一致 ✓）' % len(ctx.mask_txt)
             if ctx.mask_txt is not None
             and sorted((r, l) for r, l, _g in ctx.meta) == sorted(ctx.mask_txt)
             else ('%d 区（**不一致**）' % len(ctx.mask_txt)
                   if ctx.mask_txt is not None else '缺失')))
    print()
    print('提示:')
    print('  · 本工具打印的是**链接时 VA**；运行时地址 = 模块基址 + RVA —— '
          '本机**实测 ASLR 生效**（同一次实验两次基址不同），不要直接拿 VA 去读进程。')
    print('  · 启动 demo 时 `--vm-blob` **必须显式传**，否则 rc=45323 '
          '（PROT_EXIT_BLOB_MISSING）—— 本项目已踩 6+ 次。')
    print('  · 活体命令（`read`/`patch`/`watch`，第 2 步）会**打开目标进程** —— 与只读命令'
          '不同，它们**需要权限**，且**可能触发目标自身的反调试**（见第 4 步提示）。')
    print('  · 第 3 步（`run` + `-DPROT_INTEGRITY_DEBUG` 诊断构建包装）**尚未实现**'
          '（**用户已降级为可选**，计划 §5）。')
    for w in ctx.warns:
        print('  [warn] %s' % w)
    print()
    if ctx.errors:
        print('判据失败 %d 条:' % len(ctx.errors))
        for e in ctx.errors:
            print('  [X] %s' % e)
        print()
        print('[prot_dbg doctor] FAIL')
        js['doctor'] = {'ok': False, 'errors': ctx.errors, 'warns': ctx.warns}
        return 1
    print('[prot_dbg doctor] PASS')
    js['doctor'] = {'ok': True, 'errors': [], 'warns': ctx.warns,
                    'syms': len(ctx.syms), 'mask_regions': len(ctx.meta)}
    return 0


def cmd_sym(ctx, names, quiet, js):
    rc = 0
    out = {}
    for name in names:
        info = ctx.sym(name)
        if info is None:
            rc = 1
            print('%s: **不在 map 中**' % name)
            for r in ctx.why_missing(name):
                print('    · %s' % r)
            out[name] = None
            continue
        m = info['mask']
        in_text = info['text_off'] is not None
        print('%s' % name)
        print('  链接时 VA     0x%016X   （映像基址 0x%X）'
              % (info['va'], info['image_base']))
        print('  RVA           0x%X (%d)' % (info['rva'], info['rva']))
        print('  .text 内偏移  %s'
              % ('+0x%X' % info['text_off'] if info['text_off'] is not None
                 else '（不在 .text 内）'))
        if m:
            print('  掩码区        **在区内** [0x%X, 0x%X)  len=%d  group=%d'
                  % (m[0], m[0] + m[1], m[1], m[2]))
            print('                => 改这段字节 = 改**密文**；'
                  '段 CRC 因掩码清零而**看不到**（但同时 selfcrypt 自己的 '
                  'per-region CRC 会先失败 -> 看门狗 `continue`）')
        elif in_text:
            print('  掩码区        不在任何区内（.text 段 CRC **会**看到改动）')
        else:
            # ## 诚实边界: 段 CRC 只覆盖特定节；对**非 .text** 符号
            #   （数据/只读数据/导入表…）不能顺手套用同一结论。
            print('  掩码区        不在任何区内；且该符号**不在 `.text` 内** '
                  '—— 段 CRC 的结论对它**不直接适用**（需另判该节是否被校验）')
        out[name] = {'rva': info['rva'], 'va': info['va'],
                     'text_off': info['text_off'],
                     'mask': list(m) if m else None}
        print()
    js['sym'] = out
    return rc


def cmd_mask(ctx, names, quiet, js):
    if names:
        return cmd_sym(ctx, names, quiet, js)
    rc = 0 if not ctx.errors else 1
    print('掩码区（权威来源: 产物 `%s` meta，%d 区）'
          % (ctx.cry_sec['name'] if ctx.cry_sec else '?', len(ctx.meta)))
    if not ctx.meta:
        print('  **无掩码区** —— 但先看 doctor 的解析链路自检:'
              '这可能是"读不到"而不是"没有"')
    inside = []
    for i, (r, l, g) in enumerate(ctx.meta):
        hits = sorted(n for n, rv in ctx.syms.items() if r <= rv < r + l)
        prot = [n for n in hits if 'prot_' in n]
        inside.extend(prot)
        print('  #%-2d [0x%06X, 0x%06X)  len=%-5d grp=%d   区内符号 %d（prot_* %d）'
              % (i, r, r + l, l, g, len(hits), len(prot)))
        for n in prot[:6]:
            print('        · %s' % n)
        if len(prot) > 6:
            print('        · …（另 %d 个）' % (len(prot) - 6))
    print()
    n_in = getattr(ctx, '_n_inside', 0) or 0
    print('小计: 掩码区内 prot_* 符号 %d 个 / map 符号 %d 个' % (len(inside), len(ctx.syms)))
    print('提示: 区外目标改动**会**被 .text 段 CRC 抓到；区内目标不会（掩码清零），'
          '但会被 selfcrypt 自己的 per-region CRC 抓到。')
    for w in ctx.warns:
        print('  [warn] %s' % w)
    js['mask'] = {'regions': [[r, l, g] for r, l, g in ctx.meta],
                  'inside_syms': inside,
                  'warns': ctx.warns}
    return rc


def cmd_exit(ctx, codes, quiet, js):
    table = parse_code_table()
    rc = 0
    out = {}
    print('退出码解释（表来源: `include/protect/*.h`，%d 条）' % len(table))
    print()
    for raw in codes:
        try:
            code = int(raw, 0)
        except ValueError:
            print('%s: **不是合法整数**（支持 10 进制与 0x 前缀）' % raw)
            rc = 1
            out[raw] = None
            continue
        known, lines = explain_code(code, table)
        print('%d (0x%X): %s' % (code, code, '已知' if known else '**未知**'))
        for l in lines:
            print(l)
        out[raw] = {'known': known}
        if not known:
            rc = 1
        print()
    js['exit'] = out
    return rc


# ===========================================================================
# 第 2 步子命令：read / patch / watch（活体，需权限）
# ===========================================================================
def _hexdump(data, base=0, width=16):
    out = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hs = ' '.join('%02X' % b for b in chunk)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        out.append('  %08X  %-*s  %s' % (base + i, width * 3 - 1, hs, asc))
    return out


def _parse_hex_bytes(s):
    """`"31 C0 C3"` / `"31C0C3"` / `"0x31,0xC0"` -> bytes。非法抛 ValueError。"""
    toks = [t for t in re.split(r'[\s,:]+', (s or '').strip()) if t]
    out = []
    for t in toks:
        if t.lower().startswith('0x'):
            t = t[2:]
        if len(t) > 2:
            if len(t) % 2:
                raise ValueError('十六进制串长度必须是偶数: `%s`' % t)
            for i in range(0, len(t), 2):
                out.append(int(t[i:i + 2], 16))
        else:
            out.append(int(t, 16))
    return bytes(out)


def _policy_continue():
    """从 C 头**解析** `PROT_POLICY_CONTINUE`（纪律 ①: 解析而非硬编码）。"""
    val = 0
    if os.path.isdir(PROT_HDR_DIR):
        for fn in sorted(os.listdir(PROT_HDR_DIR)):
            if not fn.endswith('.h'):
                continue
            try:
                t = open(os.path.join(PROT_HDR_DIR, fn),
                         encoding='utf-8', errors='replace').read()
            except OSError:
                continue
            m = re.search(r'\bPROT_POLICY_CONTINUE\s*=\s*(\d+)', t)
            if m:
                val = int(m.group(1))
    return val


def _live_setup(ctx, a):
    """建目标 + 打开句柄。调用方负责 `close()` 与 `kill()`。"""
    if ctx.errors:
        raise DbError('symbol',
                      '产物/map 链路异常 -> **先修 `doctor` 再调试**（读不到 != 不存在）',
                      '跑 `prot_dbg doctor` 看是哪一环断了。')
    if not os.path.exists(ctx.exe):
        raise DbError('process', '产物不存在: %s' % rel(ctx.exe), '先构建再调试。')
    t = _default_target(ctx, a.pid)
    t.open()
    return t


def _keep_alive(t, ctx, quiet, js):
    """把看门狗策略预置成 CONTINUE，免得 patch 之后被 watchdog **立刻 EXIT** 掉
    （`demo/main.c:679` 是 `prot_integrity_start_watchdog(PROT_POLICY_EXIT, 5000)`）。

    ⚠ 这**本身也是一次写入** —— 必须如实报告，不能当成"没做事"（纪律 ⑦/⑨）。
    做法与 `tools/guard_selftest.py` 一致（共享思路）。
    """
    rec = {'sym': SYM_POLICY, 'applied': False}
    info = ctx.sym(SYM_POLICY)
    if not info:
        rec['why'] = '符号 `%s` 不在 map 中（无法预置策略；patch 后可能被 watchdog 退出）' % SYM_POLICY
        js['keep_alive'] = rec
        return rec
    cont = _policy_continue()
    rt = t.rt(info['va'])
    ok, back, detail = t.write(rt, bytes([cont & 0xFF, 0, 0, 0]))
    rec.update({'applied': bool(ok), 'value': cont, 'rt': rt,
                'back': None if back is None else list(back), 'detail': detail})
    if not quiet:
        print('  预置看门狗策略: %s = %d (PROT_POLICY_CONTINUE) -> %s'
              % (SYM_POLICY, cont, '已写入并读回一致' if ok else '**写入失败**: %s' % detail))
    js['keep_alive'] = rec
    return rec


def _fail(js, cmd, kind, msg, hint, quiet):
    js['ok'] = False
    js['error'] = {'kind': kind, 'msg': msg, 'hint': hint}
    if not quiet:
        print()
        print('[prot_dbg %s] **失败**（%s）: %s' % (cmd, kind, msg))
        if hint:
            print('  提示: %s' % hint)
    else:
        sys.stderr.write('[prot_dbg] %s 失败 (%s): %s\n' % (cmd, kind, msg))
    return 1


def _rtline(t, info):
    slide = t.base - PREF
    return ('  链接时 VA 0x%X  ->  运行时地址 0x%X  '
            '(映像基址 0x%X；ASLR 滑动 +0x%X)'
            % (info['va'], t.rt(info['va']), t.base, slide))


def cmd_read(ctx, operands, quiet, js, a):
    """读目标进程内存（**读不到就报错，绝不返回 0**）。"""
    _adwarn(quiet, a.no_adwarn, 'read', js)
    if not operands:
        print('用法: prot_dbg read <符号> [--len N] [--pid P]')
        return 2
    name = operands[0]
    n = a.len or 16
    t = None
    try:
        info = _resolve(ctx, name)
        t = _live_setup(ctx, a)
        va = t.rt(info['va'])
        mem = t.read(va, n)
        rel_va = info['va']
    except DbError as e:
        if t:
            t.close()
            t.kill()
        return _fail(js, 'read', e.kind, e.msg, e.hint, quiet)
    try:
        js['read'] = {'sym': name, 'len': n, 'pid': t.pid, 'rt': va,
                      'bytes': list(mem), 'base': t.base, 'rva': info['rva']}
        if quiet:
            return 0
        print('读内存: %s' % name)
        print('  RVA 0x%X  (map 符号)' % info['rva'])
        print(_rtline(t, info))
        print('  pid %d  长度 %d 字节' % (t.pid, n))
        print()
        for l in _hexdump(mem, va):
            print(l)
        # ---- 纪律 ②: 把内存读取链路钉死在**文件**这个已知基准上 ----
        f = file_bytes_at(ctx, info['rva'], n)
        print()
        if f is None:
            print('  正向对照: 该 RVA **不在任何节的原始数据内**（可能是未初始化数据 / '
                  '运行期才填的内存）—— 无法用文件做基准。')
        elif f == mem:
            print('  正向对照: 与产物**文件内同址字节完全一致**（%s） -> 读取链路可信。'
                  % f.hex(' '))
        else:
            print('  正向对照: **与文件不一致**')
            print('    文件: %s' % f.hex(' '))
            print('    内存: %s' % mem.hex(' '))
            print('  -> 两种可能，**不要混为一谈**: ① 该地址在运行期被写过（正常）；'
                  '② 读取链路有偏（地址算错）。')
            print('    判别: 换一个**只读且运行期不改**的符号（如 .rdata 里的字符串）重读。')
        m = info['mask'] or ctx.mask_hit(info['rva'])
        if m:
            print('  掩码区: 0x%06X..0x%06X (len=%d group=%d)' % (m[0], m[0] + m[1], m[1], m[2]))
        print()
    finally:
        t.close()
        t.kill()
    return 0


def cmd_patch(ctx, operands, quiet, js, a):
    """写目标进程内存 + **读回验证**（纪律 ⑦）。"""
    _adwarn(quiet, a.no_adwarn, 'patch', js)
    if not operands:
        print('用法: prot_dbg patch <符号> [--bytes "31 C0 C3" | --nop N | --restore] '
              '[--pid P] [--no-keep-alive]')
        return 2
    name = operands[0]
    try:
        info = _resolve(ctx, name)
    except DbError as e:
        return _fail(js, 'patch', e.kind, e.msg, e.hint, quiet)
    # ---- 决定要写入的字节 -------------------------------------------------
    src = 'default(PATCH=31 C0 C3)'
    try:
        if a.restore:
            data = file_bytes_at(ctx, info['rva'], a.len or len(PATCH))
            src = 'restore(产物文件原字节)'
            if data is None:
                return _fail(js, 'patch', 'symbol',
                             '`--restore` 失败: RVA 0x%X **不在任何节的原始数据内**，'
                             '拿不到"原字节"做基准' % info['rva'],
                             '这类地址（未初始化数据）只能靠你自己记住原值。', quiet)
        elif a.nop:
            data = b'\x90' * a.nop
            src = '--nop %d' % a.nop
        elif a.bytes:
            data = _parse_hex_bytes(a.bytes)
            src = '--bytes "%s"' % a.bytes
        else:
            data = bytes(PATCH)
    except ValueError as e:
        return _fail(js, 'patch', 'address', '十六进制解析失败: %s' % e, None, quiet)
    if not data:
        return _fail(js, 'patch', 'address', '要写入的字节为空', None, quiet)
    t = None
    try:
        t = _live_setup(ctx, a)
        va = t.rt(info['va'])
        try:
            before = t.read(va, len(data))
        except DbError as e:
            return _fail(js, 'patch', e.kind,
                         'patch **前**读取失败（所以"改了什么"无从谈起）: %s' % e.msg,
                         e.hint, quiet)
        ka = None if a.no_keep_alive else _keep_alive(t, ctx, quiet, js)
        ok, back, detail = t.write(va, data)
    except DbError as e:
        if t:
            t.close()
            t.kill()
        return _fail(js, 'patch', e.kind, e.msg, e.hint, quiet)
    try:
        rec = {'sym': name, 'rva': info['rva'], 'rt': va, 'pid': t.pid, 'src': src,
               'want': list(data), 'before': list(before),
               'back': None if back is None else list(back), 'ok': bool(ok),
               'detail': detail, 'verify': 'readback'}
        js['patch'] = rec
        rc = 0 if ok else 1
        if not quiet:
            print('patch: %s  (%s)' % (name, src))
            print('  RVA 0x%X' % info['rva'])
            print(_rtline(t, info))
            print('  pid %d  %d 字节' % (t.pid, len(data)))
            print()
            print('  写入前: %s' % before.hex(' '))
            print('  期望:   %s' % data.hex(' '))
            print('  读回:   %s' % (back.hex(' ') if back is not None else '<读回失败>'))
            print()
            # ---- 纪律 ⑦: 只有"读回一致"才算写进去 ----
            if ok:
                print('  ✓ **读回验证通过** —— 写入确实生效（这不是推测，是读回来的）。')
            else:
                print('  [X] **读回验证失败**: %s' % detail)
                print('  -> 不要把它读成"守卫失效"（那正是纪律 ⑦ 挡的误判）。'
                      '先查权限/页保护/地址换算。')
            # ---- 完整性检测的**诚实边界** ----
            m = info['mask'] or ctx.mask_hit(info['rva'])
            in_text = info['text_off'] is not None
            if m:
                print('  掩码区: 0x%06X..0x%06X -> 改的是**密文**；.text 段 CRC 看不到，'
                      '但 selfcrypt 自己的 per-region CRC 会先失败。'
                      % (m[0], m[0] + m[1]))
            elif in_text:
                print('  掩码区: 不在区内（在 .text 内）-> .text 段 CRC **会**看到这次改动。')
            elif not in_text:
                print('  掩码区: 不在 .text 内 -> 段 CRC 的结论对它**不直接适用**（需另判该节）。')
            print()
            print('  ⚠ 判据提醒: 本命令能证明的是"**我写进去了**"（读回）。'
                  '它**不能**证明"守卫有效/失效" ——')
            print('    那要看**被观测符号自己的值**（用 `prot_dbg watch <计数器>` 看变化）。')
            ec = t.exit_code()
            if ec is not None:
                print('  ⚠ 目标已退出，退出码 %d%s' % (ec, _ec_note(ec)))
            print()
        return rc
    finally:
        t.close()
        t.kill()


def _ec_note(ec):
    """退出码注解 —— 第 4 步: 219 必须**当场**被标注为"不能当判据"。"""
    if ec == EXIT_DEBUG_DETECTED:
        return (' = PROT_EXIT_DEBUG_DETECTED。**这不是"守卫有效/失效"的判据** —— '
                '本工具自己就是探测源（OpenProcess/ReadProcessMemory）。')
    return ''


def cmd_watch(ctx, operands, quiet, js, a):
    """轮询被观测符号的字节变化 —— **判据是它自己的值，不是进程死没死**（纪律 ⑨）。"""
    _adwarn(quiet, a.no_adwarn, 'watch', js)
    if not operands:
        print('用法: prot_dbg watch <符号> [--len N] [--interval S] [--seconds S] '
              '[--patch <符号>]… [--pid P]')
        return 2
    name = operands[0]
    n = a.len or 4
    interval = a.interval or POLL_S
    seconds = a.seconds or OBSERVE_S
    try:
        info = _resolve(ctx, name)
    except DbError as e:
        return _fail(js, 'watch', e.kind, e.msg, e.hint, quiet)
    t = None
    try:
        t = _live_setup(ctx, a)
        va = t.rt(info['va'])
        if not a.no_keep_alive:
            _keep_alive(t, ctx, quiet, js)
        # ---- 可选的"先 patch 别的符号"：把多轮实验压成一条命令 ----
        patched = []
        for pn in (a.patch or []):
            try:
                pinfo = _resolve(ctx, pn)
                pva = t.rt(pinfo['va'])
                ok, back, detail = t.write(pva, bytes(PATCH))
                patched.append({'sym': pn, 'ok': bool(ok), 'want': list(PATCH),
                                'back': None if back is None else list(back), 'detail': detail})
                if not quiet:
                    print('  先 patch: %s @0x%X <- %s -> %s'
                          % (pn, pva, bytes(PATCH).hex(' '),
                             '读回一致' if ok else '**读回失败**: %s' % detail))
            except DbError as e:
                return _fail(js, 'watch', e.kind, '预置 patch `%s` 失败: %s' % (pn, e.msg),
                             e.hint, quiet)
        js['watch'] = {'sym': name, 'len': n, 'pid': t.pid, 'rt': va,
                       'interval': interval, 'seconds': seconds, 'prepatched': patched}
        if not quiet:
            print('watch: %s  (len=%d, 每 %.2fs 采样, 观察 %.1fs)'
                  % (name, n, interval, seconds))
            print('  RVA 0x%X' % info['rva'])
            print(_rtline(t, info))
            print('  pid %d' % t.pid)
            print()
        first = t.read(va, n)
        cur = first
        changes = []
        t0 = time.time()
        while time.time() - t0 < seconds:
            time.sleep(interval)
            try:
                now = t.read(va, n)
            except DbError as e:
                if not quiet:
                    print('  [%6.2fs] 读取失败: %s' % (time.time() - t0, e.msg))
                changes.append({'t': round(time.time() - t0, 3), 'error': e.kind})
                break
            if now != cur:
                changes.append({'t': round(time.time() - t0, 3),
                                'from': list(cur), 'to': list(now)})
                if not quiet:
                    print('  [%6.2fs] %s -> %s' % (time.time() - t0, cur.hex(' '), now.hex(' ')))
                cur = now
            if t.exit_code() is not None:
                if not quiet:
                    print('  [%6.2fs] 目标退出，退出码 %d%s'
                          % (time.time() - t0, t.exit_code(), _ec_note(t.exit_code())))
                break
        js['watch'].update({'first': list(first), 'last': list(cur),
                            'changes': changes, 'n_changes': len(changes)})
        if not quiet:
            print()
            if not changes:
                # ---- 纪律 ⑨: "无变化"是一个**结论**，不是"读不到" ----
                print('  结果: **观察窗口内无变化**（%d 次采样，值恒为 %s）'
                      % (int(seconds / interval) + 1, first.hex(' ')))
                print('  -> 这是一个**有效结论**（读取链路已被正向对照验证过）：'
                      '该符号在此期间没被改写。')
            else:
                print('  结果: **变化 %d 次**，首值 %s -> 末值 %s'
                      % (len(changes), first.hex(' '), cur.hex(' ')))
                print('  -> 判据看的是**这个符号自己的值**，与进程是否退出**无关**'
                      '（退出码无判别力）。')
            print()
        return 0
    except DbError as e:
        return _fail(js, 'watch', e.kind, e.msg, e.hint, quiet)
    finally:
        if t:
            t.close()
            t.kill()


# ===========================================================================
# 自检
# ===========================================================================
def selftest(quiet):
    def case(name, ok, detail=None):
        fails.append(name) if not ok else None
        if not quiet:
            print('  %s  %s' % ('ok  ' if ok else 'FAIL', name))
            if detail and not ok:
                print('        detail: %s' % detail)
        return ok

    fails = []
    print('=== prot_dbg 自检 ===')
    ctx = Ctx()
    ready = (os.path.isfile(ctx.exe) and os.path.isfile(ctx.map_path)
             and not ctx.errors)
    case('T0 前置: 产物+map 就绪且解析链路自检通过', ready,
         '; '.join(ctx.errors)[:160])
    if not ready:
        print()
        print('[prot_dbg-selftest] SKIP: 产物未就绪或链路异常'
              '（**未验证 != 通过**）')
        return 2

    # T1 正向: doctor
    js = {}
    jsn = {}
    case('T1 **正向**: doctor -> PASS', cmd_doctor(ctx, quiet, jsn) == 0)

    # T2 正向: sym 动态取一个真实符号（不硬编码名字）
    name = next((n for n in ctx.syms if ctx.text_off(ctx.syms[n]) is not None),
                None)
    if case('T2a **正向**: map 中存在落在 .text 内的符号', name is not None):
        case('T2b **正向**: sym 能查到它 -> rc=0',
             cmd_sym(ctx, [name], True, jsn) == 0)
        info = ctx.sym(name)
        case('T2c **正向**: 它的 .text 偏移算得出来',
             info is not None and info['text_off'] is not None)

    # T3 正向: exit 0xBAD
    tbl = parse_code_table()
    ok3, l3 = explain_code(0xBAD, tbl)
    case('T3 **正向**: exit 0xBAD -> PROT_EXIT_TAMPERED',
         ok3 and any('PROT_EXIT_TAMPERED' in x for x in l3))

    # T4 正向: Linux 低 8 位折算
    ok4, l4 = explain_code(0xB10B & 0xFF, tbl)
    case('T4 **正向**: exit 11 -> 指出 = 0xB10B 的低 8 位（Linux exit() 截断）',
         ok4 and any('PROT_EXIT_BLOB_MISSING' in x for x in l4))

    # T5 负向: 不存在的符号 -> 必须失败
    case('T5 **负向**: sym 不存在的符号 -> **必须 rc=1**',
         cmd_sym(ctx, ['__no_such_symbol_prot_dbg__'], True, jsn) == 1)

    # T6 负向: 未定义的码 -> 必须明确未知（不得猜测）
    ok6, l6 = explain_code(0x1234, tbl)
    case('T6 **负向**: exit 0x1234 -> **必须判未知**',
         (not ok6) and any('未知' in x for x in l6))

    # T7/T8 负向: 空 map / 非空但格式不识别 -> doctor 必须报错
    tmp = tempfile.mkdtemp(prefix='protdbg_')
    try:
        for tag, content, want in (
                ('T7 **负向**: map 为**空文件** -> doctor 必须 FAIL',
                 '', 'map 文件为**空**'),
                ('T8 **负向**: map **非空但格式不识别** -> 必须报"读不到 != 不存在"',
                 '这不是 map 文件\n' * 20, '格式未识别')):
            mp = os.path.join(tmp, tag[:2].strip() + '.map')
            with open(mp, 'w', encoding='utf-8', newline='\n') as f:
                f.write(content)
            c2 = Ctx(exe=ctx.exe, map_path=mp)
            joined = ' '.join(c2.errors)
            # doctor 必须返回 1（不是 0），且**原因必须正确**
            rcd = cmd_doctor(c2, True, {})
            case(tag, rcd == 1 and (want in joined),
                 'rc=%d errors=%s' % (rcd, joined[:120]))

        # T9 负向: 掩码判定不得恒真/恒假
        if ctx.meta:
            r, l, _g = ctx.meta[0]
            case('T9a **负向**: 掩码区内一个点必须判"在区内"',
                 ctx.mask_hit(r) is not None)
            # 找第一个**不在**任何区内的符号 RVA
            outside = next((rv for rv in ctx.syms.values()
                            if ctx.mask_hit(rv) is None), None)
            case('T9b **负向**: 掩码区外一个点必须判"不在区内"',
                 outside is not None and ctx.mask_hit(outside) is None)
        else:
            case('T9 掩码判定: 无区可测 -> **不假装通过**', False,
                 'ctx.meta 为空（先看 doctor 的链路自检）')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    print('=' * 66)
    if fails:
        # ## 静默模式也必须保留**失败信号**（否则门禁里只看到一个 rc，
        #    "诊断信息不可丢失" 是同一条纪律）。
        msg = '[prot_dbg-selftest] FAIL: %s' % '; '.join(fails)
        if quiet:
            sys.stderr.write(msg + '\n')
        else:
            print(msg)
        return 1
    print('[prot_dbg-selftest] PASS: 1 前置 + 4 正向 + 4 负向均可自证')
    return 0


# ===========================================================================
# 活体自检（第 2 步）—— **会拉起并杀掉 demo.exe**，故不进只读门禁
#
# 与只读自检同一条纪律: **"只会通过的检查器没有价值"**。
# 因此既有正向对照（L1 内存==文件、L2 读回一致），也有负向对照
# （L3 不存在的符号必须失败、L4 写私有只读页必须失败、
#   L5 采样链路不得恒报"有变化"）。
# ===========================================================================
class _FakeArgs(object):
    """给活体命令凑一个 argparse 命名空间（自检不走命令行）。"""

    def __init__(self, **kw):
        self.pid = 0
        self.len = 0
        self.bytes = None
        self.nop = 0
        self.restore = False
        self.interval = 0.0
        self.seconds = 0.0
        self.patch = None
        self.no_keep_alive = True
        self.no_adwarn = True
        for k, v in kw.items():
            setattr(self, k, v)


def selftest_live(quiet):
    def case(name, ok, detail=None):
        if not ok:
            fails.append(name)
        if not quiet:
            print('  %s  %s' % ('ok  ' if ok else 'FAIL', name))
            if detail and not ok:
                print('        detail: %s' % detail)
        return ok

    fails = []
    if not quiet:
        print('=== prot_dbg 活体自检（第 2 步；**会拉起并杀掉 demo.exe**）===')
    if sys.platform != 'win32':
        print('[prot_dbg-selftest-live] SKIP: 仅 Windows（OpenProcess/ReadProcessMemory）'
              '（**未验证 != 通过**）')
        return 2

    ctx = Ctx()
    ready = (os.path.isfile(ctx.exe) and os.path.isfile(ctx.map_path) and not ctx.errors)
    if not case('L0 前置: Windows + 产物/map 就绪且链路通过', ready,
                '; '.join(ctx.errors)[:160]):
        print('[prot_dbg-selftest-live] SKIP: 前置不满足（**未验证 != 通过**）')
        return 2

    # 选一个**落在 .text 内、且在产物的原始数据里**的符号（才能做文件对照）
    pick = next((n for n, rv in sorted(ctx.syms.items())
                 if ctx.text_off(rv) is not None
                 and file_bytes_at(ctx, rv, 3) is not None), None)
    if not case('L1a **前置**: 存在可做文件对照的 .text 符号', pick is not None):
        print('[prot_dbg-selftest-live] SKIP: 无可对照符号（**未验证 != 通过**）')
        return 2

    t = None
    try:
        t = _live_setup(ctx, _FakeArgs())
        info = ctx.sym(pick)
        va = t.rt(info['va'])

        # ---- L1 正向: 内存 == 文件（把读取链路钉在已知基准上）----
        mem = t.read(va, 8)
        f = file_bytes_at(ctx, info['rva'], 8)
        case('L1 **正向**: read 的字节与产物**文件内同址字节一致**',
             f is not None and mem == f,
             'mem=%s file=%s' % (mem.hex(' '), None if f is None else f.hex(' ')))

        # ---- L2 正向: patch 必须"读回一致"且确实变了 ----
        before = t.read(va, 3)
        ok2, back2, det2 = t.write(va, bytes(PATCH))
        case('L2 **正向**: patch 写入后**读回验证**必须成功', ok2, det2)
        case('L2b **正向**: patch 后字节必须**确实变了**', back2 == bytes(PATCH),
             'back=%s' % (None if back2 is None else back2.hex(' ')))
        # 还原本地（进程随即被杀，但这步保证"撤销"路径也被走到）
        ok2c, back2c, _ = t.write(va, before)
        case('L2c **正向**: 写回原字节也必须读回一致', ok2c and back2c == before,
             'back=%s' % (None if back2c is None else back2c.hex(' ')))

        # ---- L3 负向: 不存在的符号必须**失败**，不得读成 0 ----
        jsn = {}
        rc3 = cmd_read(ctx, ['__no_such_symbol_prot_dbg__'], True, jsn,
                       _FakeArgs(pid=t.pid, len=4))
        case('L3 **负向**: read 不存在的符号 -> **必须 rc=1**（不得读成 0）',
             rc3 == 1, 'rc=%d' % rc3)

        # ---- L4 负向对照: **私有**只读页必须拒绝写入 ----
        #   2026-10-01 更正: 原先拿映像 `.text` 当对照，前提就是错的 ——
        #   映像页是 SEC_IMAGE 写时复制，RX 页**可以**直接写成功（实测）。
        #   私有页的保护值由我们设定，才是"写入链路有判别力"的干净对照。
        ctrl = None
        try:
            ctrl = t.alloc_ro_page()
            ok4, back4, det4 = t.write(ctrl, bytes(PATCH), protect=False)
            case('L4 **负向对照**: 写**私有 PAGE_READONLY 页**（不改保护）-> 必须**明确失败**',
                 not ok4, 'ok=%s detail=%s back=%s'
                 % (ok4, det4, None if back4 is None else back4.hex(' ')))
            # L4b **正向对照**: 同一个私有页，**改**页保护后必须写得进去 ——
            #   证明 L4 的失败是"保护"造成的，而不是"地址无效/长度非法"造成的。
            ok4b, back4b, det4b = t.write(ctrl, bytes(PATCH), protect=True)
            case('L4b **正向对照**: 同一私有页**改**页保护后 -> 必须写成功'
                 '（证明 L4 的失败确实是"保护"造成的，而非地址非法）',
                 ok4b and back4b == bytes(PATCH),
                 'ok=%s back=%s detail=%s'
                 % (ok4b, None if back4b is None else back4b.hex(' '), det4b))
            ro_va = ctrl
        finally:
            if ctrl:
                t.free_page(ctrl)

        # ---- L5 负向: 采样链路不得**恒报变化** ----
        a1 = t.read(va, 4)
        time.sleep(0.3)
        a2 = t.read(va, 4)
        case('L5 **负向**: 同址两次采样（期间无人写）-> 必须**相等**（采样链路不得恒报变化）',
             a1 == a2, 'a1=%s a2=%s' % (a1.hex(' '), a2.hex(' ')))
    except DbError as e:
        case('L* 活体链路异常', False, '%s: %s' % (e.kind, e.msg))
    finally:
        if t:
            t.close()
            t.kill()

    print()
    print('=' * 66)
    if fails:
        msg = '[prot_dbg-selftest-live] FAIL: %s' % '; '.join(fails)
        if quiet:
            sys.stderr.write(msg + '\n')
        else:
            print(msg)
        return 1
    print('[prot_dbg-selftest-live] PASS: 3 前置/正向 + 3 负向均可自证 '
          '（读回验证、页保护对照、采样链路均已自证）')
    return 0


# ===========================================================================
def main(argv=None):
    p = argparse.ArgumentParser(
        prog='prot_dbg.py',
        description='ShardVase 调试控制台（第 1 步只读 + 第 2 步活体调试）',
        epilog='只读: doctor | sym <名字…> | mask [名字…] | exit <码…>\n'
               '活体: read <符号> | patch <符号> | watch <符号>   '
               '（需权限；会打开目标进程，可能触发反调试 -> 见第 4 步提示）')
    p.add_argument('args', nargs='*', help='子命令与操作数')
    p.add_argument('--exe', default=None, help='产物路径（默认 build/demo.exe）')
    p.add_argument('--map', dest='map_path', default=None,
                   help='map 路径（默认与 --exe 同名 .map）')
    p.add_argument('--json', dest='json_out', default=None,
                   help='结构化结果落盘（JSON）')
    p.add_argument('--quiet', action='store_true')
    p.add_argument('--selftest', action='store_true',
                   help='纯只读自检（可进门禁）')
    p.add_argument('--selftest-live', dest='selftest_live', action='store_true',
                   help='活体自检（**会拉起并杀掉 demo.exe**，不进只读门禁）')
    # ---- 第 2 步: 活体调试参数 ----
    p.add_argument('--pid', type=int, default=0,
                   help='附着到已有进程（不给则自己拉起一个 demo）')
    p.add_argument('--len', type=int, default=0, help='读/写/观测的字节数')
    p.add_argument('--bytes', default=None, help='patch 写入的字节，如 "31 C0 C3"')
    p.add_argument('--nop', type=int, default=0, help='patch 写入 N 个 0x90')
    p.add_argument('--restore', action='store_true',
                   help='patch 用产物文件里的原字节写回（撤销）')
    p.add_argument('--interval', type=float, default=0.0, help='watch 采样间隔秒')
    p.add_argument('--seconds', type=float, default=0.0, help='watch 观察窗口秒')
    p.add_argument('--patch', action='append', default=None, metavar='符号',
                   help='watch 前先 patch 该符号（可重复）')
    p.add_argument('--no-keep-alive', dest='no_keep_alive', action='store_true',
                   help='不预置看门狗策略（默认预置 CONTINUE，免得刚 patch 就被 EXIT）')
    p.add_argument('--no-adwarn', dest='no_adwarn', action='store_true',
                   help='关闭反调试干扰提示（第 4 步；--quiet 也会关掉它）')
    a = p.parse_args(argv)

    # ## `--quiet` 的真实语义（2026-09-30 补: 原先只写在参数表里、**没有任何效果**）
    #   人类看的是 stdout 的讲解；静默模式的消费者是**门禁/脚本**，
    #   它们只需要 `rc` + `--json`。=> 静默时把 stdout 整体沉掉，但
    #   **失败信息走 stderr 保留**（rc 之外还要留证据）。
    saved, sink = sys.stdout, None
    if a.quiet:
        sink = open(os.devnull, 'w', encoding='utf-8')
        sys.stdout = sink
    try:
        rc = _dispatch(p, a)
    finally:
        sys.stdout = saved
        if sink is not None:
            sink.close()
    if a.quiet and rc != 0:
        sys.stderr.write('[prot_dbg] rc=%d（静默模式；细节见 stdout 或 --json）\n' % rc)
    return rc


def _dispatch(p, a):
    if a.selftest:
        return selftest(a.quiet)
    if a.selftest_live:
        return selftest_live(a.quiet)

    if not a.args:
        p.print_help()
        return 2
    cmd, operands = a.args[0], a.args[1:]
    READONLY = ('doctor', 'sym', 'mask', 'exit')
    LIVE = ('read', 'patch', 'watch')
    if cmd not in READONLY + LIVE:
        print('未知子命令: %s（只读: %s；活体: %s）'
              % (cmd, ' | '.join(READONLY), ' | '.join(LIVE)))
        return 2

    js = {'tool': 'prot_dbg', 'cmd': cmd, 'exe': a.exe or DEFAULT_EXE,
          'step': 1 if cmd in READONLY else 2}
    if cmd == 'exit':
        # exit 不依赖产物 -> 无产物也能用（例如读别人的退出码）
        rc = cmd_exit(None, operands, a.quiet, js)
    else:
        ctx = Ctx(exe=a.exe, map_path=a.map_path)
        if cmd == 'doctor':
            rc = cmd_doctor(ctx, a.quiet, js)
        elif cmd == 'sym':
            if not operands:
                print('sym 需要一个或多个符号名')
                return 2
            rc = cmd_sym(ctx, operands, a.quiet, js)
        elif cmd == 'mask':
            rc = cmd_mask(ctx, operands, a.quiet, js)
        elif cmd == 'read':
            rc = cmd_read(ctx, operands, a.quiet, js, a)
        elif cmd == 'patch':
            rc = cmd_patch(ctx, operands, a.quiet, js, a)
        else:
            rc = cmd_watch(ctx, operands, a.quiet, js, a)

    if a.json_out:
        try:
            with open(a.json_out, 'w', encoding='utf-8', newline='\n') as f:
                json.dump(js, f, ensure_ascii=False, indent=2)
            if not a.quiet:
                print('[prot_dbg] JSON 证据已落盘: %s' % a.json_out)
        except OSError as e:
            print('[prot_dbg] JSON 落盘失败: %s' % e)
            return 1
    return rc


if __name__ == '__main__':
    sys.exit(main())
