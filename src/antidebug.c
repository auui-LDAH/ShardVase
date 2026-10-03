/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * antidebug.c — 反调试: 检测调试器 / 分析环境
 *
 * 对应契约 docs/CONTRACT.md §6 (x64)。
 * 检测项: PEB.BeingDebugged / PEB.NtGlobalFlag / ProcessDebugPort /
 *         ProcessDebugFlags / ProcessDebugObjectHandle / 硬件断点 /
 *         QPC+Sleep 计时 / 内核调试器标志。
 * 任何 WinAPI/ntdll 调用失败均将该检测项记为 0 (不误报)。
 *
 * ## 平台分支（M5，2026-09-25）—— **重新设计**，不是移植
 *
 * **Windows 路径逐字保留**（下方 `#if` 内）——
 *   `PEB 直读`是模块的**核心特征**（项目要求"绕过用户态 hook"）。
 *
 * **Linux 路径是重新设计**（`#else` 分支）:
 *   Windows 的 12 个维度依赖 **PEB / NT 原生查询 / SEH** ——
 *   Linux 上**无等价物**（详见 docs/LINUX_PORT_PLAN.md §2.2）。
 *
 *   | 类 | 项数 | 说明 |
 *   |----|------|------|
 *   | **可等价实现** | 5 | 计时 / 父进程 / int3 / 时钟漂移 / 内核调试器 |
 *   | **归一化**     | 5 | PEB 与 NT 查询 -> **统一归约为 TracerPid** |
 *   | **明确不支持** | 1 | **硬件断点**（需 ptrace 附加，自相矛盾）|
 *   | **Linux 独有** | **+3** | LD_PRELOAD / 可疑 .so / ptrace 试探 |
 *
 *   => **净增 2 个维度**（+3 −1）。**不是降级。**
 */

#include "protect/antidebug.h"
#include "protect/prot_noise.h"   /* W1.6 序言噪声 */
#include "protect/syscall.h"      /* A6: direct syscall 直调 */
#include "protect/prot_platform.h"/* M5: 反调试探测原语（跨平台）*/
#include "protect/prot_compiler.h"/* M5: PROT_CODE_SEG */

/* ================================================================== *
 * Windows 实现（**逐字保留**）
 * ================================================================== */
#if PROT_PLATFORM == PROT_PLATFORM_WINDOWS

#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <string.h>

/* S1 专项 (2026-08-30): 辅助函数移入 .protxec 独立页 (与加密段分页,
 * 消除"页内未加密邻居被 VP 禁执行"自伤). scan 自身在下方恢复 .text. */
/* 阶段1(第二支柱): 节名每构建随机, 消除自解释线索 (见 tools/gen_sections.py) */
#include "protect/prot_sections.h"
PROT_CODE_SEG(PROT_SEC_XEC)

/* Phase 3b: 多轮计时采样配置. 5 轮 × 20ms, 任一轮 < 5ms 判可疑. */
#define PROT_AD_TIMING_ROUNDS 5u
#define PROT_AD_TIMING_SLEEP_MS 20u
#define PROT_AD_TIMING_MIN_MS 5u

/* --- ntdll 信息类常量 (契约 §6.1) --- */
#define PROT_PID_DEBUG_PORT            7    /* ProcessDebugPort */
#define PROT_PID_DEBUG_OBJECT_HANDLE   30   /* ProcessDebugObjectHandle */
#define PROT_PID_DEBUG_FLAGS           31   /* ProcessDebugFlags */
#define PROT_THREAD_HIDE_FROM_DEBUGGER 17   /* ThreadHideFromDebugger */
#define PROT_SYS_KERNEL_DEBUGGER_INFO  0x23 /* SystemKernelDebuggerInformation */

/* int3 蜜罐 (Phase 3a): 自投 int3, 若 VEH 未被接管则说明有外部断点处理者 */
static volatile LONG g_int3_caught;
static LONG CALLBACK vh_int3(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    InterlockedExchange(&g_int3_caught, 1);
    ep->ContextRecord->Rip += 1; /* 跳过 1 字节 int3, 继续执行 */
    return EXCEPTION_CONTINUE_EXECUTION;
}

/* 返回: 0=未完成探测, 1=VEH 正常接管, 2=未接管(可疑) */
static uint32_t ad_int3_probe(void) {
    BYTE* stub;
    PVOID hveh;
    uint32_t r = 0u;

    stub = (BYTE*)VirtualAlloc(NULL, 2, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (stub == NULL) {
        return 0u; /* 无法分配, 不设防 */
    }
    stub[0] = 0xCCu; /* int3 */
    stub[1] = 0xC3u; /* ret */
    FlushInstructionCache(GetCurrentProcess(), stub, 2);

    InterlockedExchange(&g_int3_caught, 0);
    hveh = AddVectoredExceptionHandler(1, vh_int3);
    if (hveh != NULL) {
        ((void(WINAPI*)(void))stub)(); /* 执行 int3;ret 存根 */
        RemoveVectoredExceptionHandler(hveh);
        r = (InterlockedCompareExchange(&g_int3_caught, 0, 0) == 0) ? 2u : 1u;
    }
    VirtualFree(stub, 0, MEM_RELEASE);
    return r;
}

/* NTSTATUS 不随 windows.h 提供 (winternl.h 可选), 自行定义 */
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

typedef NTSTATUS(NTAPI* nt_query_info_process_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* nt_query_system_info_t)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* nt_set_info_thread_t)(HANDLE, ULONG, PVOID, ULONG);

/* ntdll 函数指针: 一次性解析, static 缓存 (契约 §6.1) */
static nt_query_info_process_t s_pNtQueryInformationProcess;
static nt_query_system_info_t  s_pNtQuerySystemInformation;
static nt_set_info_thread_t    s_pNtSetInformationThread;
static volatile LONG           s_ntdll_resolved;

static void ad_resolve_ntdll(void) {
    HMODULE h;

    if (InterlockedCompareExchange(&s_ntdll_resolved, 1, 0) != 0) {
        return; /* 已解析 */
    }
    h = GetModuleHandleW(L"ntdll.dll");
    if (h == NULL) {
        return; /* ntdll 必然已加载; 即便失败, 各指针保持 NULL, 检测项记 0 */
    }
    s_pNtQueryInformationProcess =
        (nt_query_info_process_t)GetProcAddress(h, "NtQueryInformationProcess");
    s_pNtQuerySystemInformation =
        (nt_query_system_info_t)GetProcAddress(h, "NtQuerySystemInformation");
    s_pNtSetInformationThread =
        (nt_set_info_thread_t)GetProcAddress(h, "NtSetInformationThread");
}

/* SystemKernelDebuggerInformation (0x23) 返回结构, 共 2 字节 */
typedef struct prot_sys_kdbg_info {
    BOOLEAN DebuggerEnabled;
    BOOLEAN DebuggerNotPresent;
} prot_sys_kdbg_info;

/* scan 及以下回 .text (scan 为加密目标, 需留在 .text) */
PROT_CODE_SEG_END()
prot_status prot_antidebug_scan(prot_antidebug_report* out) {
    PROT_NOISE();   /* W1.6: 每构建序言噪声（破坏特征匹配）*/
    uintptr_t peb;
    LARGE_INTEGER freq;
    LARGE_INTEGER t0;
    LARGE_INTEGER t1;
    prot_sys_kdbg_info kdbg;

    if (out == NULL) {
        return PROT_OK; /* 契约: 永不失败, 返回 PROT_OK */
    }
    memset(out, 0, sizeof(*out));

    ad_resolve_ntdll();

    /* PEB 直读: GS:0x60 为 TEB->ProcessEnvironmentBlock */
    peb = (uintptr_t)__readgsqword(0x60);
    out->peb_being_debugged = (*(const uint8_t*)(peb + 0x02) != 0) ? 1u : 0u; /* BeingDebugged */
    out->peb_nt_global_flag = ((*(const uint32_t*)(peb + 0xBC) & 0x70u) != 0) ? 1u : 0u; /* 咨询项 */

    /* PEB.ProcessHeap 调试堆泄漏 (Phase 3a): 被调试时堆 Flags/ForceFlags 被置调试位 */
    {
        const uintptr_t heap = *(const uintptr_t*)(peb + 0x30); /* ProcessHeap */
        if (heap != 0) {
            const uint32_t fflags = *(const uint32_t*)(heap + 0x74);
            /* 正常 Heap->ForceFlags=0; 调试时被置调试位 */
            out->debug_heap_flags = (fflags != 0) ? 1u : 0u;
        }
    }

    /* int3 VEH 蜜罐 (Phase 3a, 咨询项) */
    out->int3_honey = (ad_int3_probe() == 2u) ? 1u : 0u;

    /* 硬件断点: Dr0-3 != 0 或 Dr7 低 8 位 (局部/全局使能位) 非 0 */
    {
        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, GetCurrentThreadId());
        if (hThread != NULL) {
            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(hThread, &ctx)) {
                out->hardware_breakpoints =
                    (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 ||
                     (ctx.Dr7 & 0xFF) != 0) ? 1u : 0u;
            }
            CloseHandle(hThread);
        }
    }

    /* 计时检测 (Phase 3b): 多轮 QPC+Sleep 采样, 取最快一轮, 可抗调度抖动误报 */
    freq.QuadPart = 0;
    t0.QuadPart = 0;
    t1.QuadPart = 0;
    if (QueryPerformanceFrequency(&freq) && freq.QuadPart != 0) {
        uint32_t round;
        out->timing_suspicious = 0u;
        for (round = 0u; round < PROT_AD_TIMING_ROUNDS; round++) {
            QueryPerformanceCounter(&t0);
            Sleep(PROT_AD_TIMING_SLEEP_MS);
            QueryPerformanceCounter(&t1);
            /* 任一轮耗时显著低于 Sleep 名义值即可疑 */
            if ((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart <
                PROT_AD_TIMING_MIN_MS) {
                out->timing_suspicious = 1u;
                break;
            }
        }
    }

    /* NtQueryInformationProcess 三项 (A6: 优先 syscall 直调绕 hook,
     * 直调不可用 (STATUS_UNSUCCESSFUL) 时回退 GetProcAddress 路径) */
    if (s_pNtQueryInformationProcess != NULL || prot_sys_available() != 0u) {
        ULONG_PTR port = 0;
        ULONG flags = 0;
        HANDLE hDbg = NULL;
        NTSTATUS st;

        st = prot_sys_nt_query_information_process(GetCurrentProcess(),
                                                   PROT_PID_DEBUG_PORT,
                                                   &port, sizeof(port), NULL);
        if (st < 0 && s_pNtQueryInformationProcess != NULL)
            st = s_pNtQueryInformationProcess(GetCurrentProcess(),
                                              PROT_PID_DEBUG_PORT,
                                              &port, sizeof(port), NULL);
        if (st >= 0) {
            out->debug_port = (port != 0) ? 1u : 0u;
        }

        st = prot_sys_nt_query_information_process(GetCurrentProcess(),
                                                   PROT_PID_DEBUG_FLAGS,
                                                   &flags, sizeof(flags), NULL);
        if (st < 0 && s_pNtQueryInformationProcess != NULL)
            st = s_pNtQueryInformationProcess(GetCurrentProcess(),
                                              PROT_PID_DEBUG_FLAGS,
                                              &flags, sizeof(flags), NULL);
        if (st >= 0) {
            out->debug_flags = (flags != 1) ? 1u : 0u;
        }

        st = prot_sys_nt_query_information_process(GetCurrentProcess(),
                                                   PROT_PID_DEBUG_OBJECT_HANDLE,
                                                   &hDbg, sizeof(hDbg), NULL);
        if (st < 0 && s_pNtQueryInformationProcess != NULL)
            st = s_pNtQueryInformationProcess(GetCurrentProcess(),
                                              PROT_PID_DEBUG_OBJECT_HANDLE,
                                              &hDbg, sizeof(hDbg), NULL);
        if (st >= 0 && hDbg != NULL) {
            out->debug_object = 1u;
            CloseHandle(hDbg); /* 成功后关闭返回的句柄 (契约 §6.1) */
        }
    }

    /* 内核调试器标志 (咨询项; A6: 优先 syscall 直调) */
    if (s_pNtQuerySystemInformation != NULL || prot_sys_available() != 0u) {
        NTSTATUS st;
        memset(&kdbg, 0, sizeof(kdbg));
        st = prot_sys_nt_query_system_information(PROT_SYS_KERNEL_DEBUGGER_INFO,
                                                  &kdbg, sizeof(kdbg), NULL);
        if (st < 0 && s_pNtQuerySystemInformation != NULL)
            st = s_pNtQuerySystemInformation(PROT_SYS_KERNEL_DEBUGGER_INFO,
                                             &kdbg, sizeof(kdbg), NULL);
        if (st >= 0) {
            out->kernel_debugger = (kdbg.DebuggerEnabled != 0) ? 1u : 0u;
        }
    }

    /* S5 (2026-08-29): 父进程调试器黑名单 (关键项) */
    out->ppid_blacklist = 0u;
    {
        static const wchar_t* const dbg_parents[] = {
            L"x64dbg.exe", L"x32dbg.exe", L"ollydbg.exe", L"windbg.exe",
            L"cdb.exe", L"ida.exe", L"ida64.exe", L"gdb.exe", L"x96dbg.exe",
            NULL };
        unsigned char pbi[48];
        ULONG ppid = 0;
        NTSTATUS st = (s_pNtQueryInformationProcess != NULL)
                          ? s_pNtQueryInformationProcess(
                                GetCurrentProcess(), 0 /*ProcessBasicInformation*/,
                                pbi, sizeof(pbi), NULL)
                          : 1;
        /* PROCESS_BASIC_INFORMATION: [0]UniqueProcessId, [8]InheritedFromUniqueProcessId */
        if (st >= 0) {
            memcpy(&ppid, pbi + 8, sizeof(ppid));
        }
        if (st >= 0 && ppid != 0 && ppid != 0xFFFFFFFFu) {
            HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                    ppid);
            if (hp != NULL) {
                wchar_t name[MAX_PATH];
                DWORD nlen = MAX_PATH;
                int k;
                if (QueryFullProcessImageNameW(hp, 0, name, &nlen)) {
                    for (k = 0; dbg_parents[k] != NULL; k++) {
                        size_t plen = wcslen(dbg_parents[k]);
                        if (nlen >= plen &&
                            _wcsicmp(name + nlen - plen, dbg_parents[k]) == 0) {
                            out->ppid_blacklist = 1u;
                            break;
                        }
                    }
                }
                CloseHandle(hp);
            }
        }
    }

    /* S5: 墙钟 vs tick 源交叉漂移 (150ms Sleep 窗口, >250ms 偏差可疑, 咨询项) */
    out->clock_drift_sec = 0u;
    {
        ULONGLONG t0t = GetTickCount64();
        ULONGLONG t0w, t1w, t1t;
        SYSTEMTIME st_sys;
        FILETIME ft;
        ULARGE_INTEGER ul;
        GetSystemTime(&st_sys);
        if (SystemTimeToFileTime(&st_sys, &ft)) {
            ul.LowPart = ft.dwLowDateTime;
            ul.HighPart = ft.dwHighDateTime;
            t0w = (ul.QuadPart / 10000ull) - 11644473600000ull;
        } else {
            t0w = 0;
        }
        Sleep(150);
        t1t = GetTickCount64();
        GetSystemTime(&st_sys);
        if (SystemTimeToFileTime(&st_sys, &ft)) {
            ul.LowPart = ft.dwLowDateTime;
            ul.HighPart = ft.dwHighDateTime;
            t1w = (ul.QuadPart / 10000ull) - 11644473600000ull;
        } else {
            t1w = 0;
        }
        if (t0w != 0 && t1w >= t0w) {
            ULONGLONG dt_tick = t1t - t0t;
            ULONGLONG dt_wall = t1w - t0w;
            if (dt_tick > dt_wall + 250ull || dt_wall > dt_tick + 250ull)
                out->clock_drift_sec = 1u;
        }
    }

    return PROT_OK;
}

/* ================================================================== *
 * 非 Windows（Linux 等）—— **重新设计**（M5，2026-09-25）
 * ================================================================== */
#else

#include <stdio.h>
#include <string.h>
#include <time.h>

/* 计时配置（与 Windows 侧同名同值，保持语义一致） */
#define PROT_AD_TIMING_ROUNDS 5u
#define PROT_AD_TIMING_SLEEP_MS 20u
#define PROT_AD_TIMING_MIN_MS 5u

/* 父进程调试器/分析工具黑名单（**Linux 语境**）
 *
 * ## 与 Windows 名单的差异（如实标注）
 *   Windows 名单是**GUI 调试器**为主（x64dbg/windbg/IDA）；
 *   Linux 侧应列**Linux 的常用工具**:
 *     gdb / lldb / strace / ltrace / radare2 / r2 / ghidra / frida 等。
 *   **保留 gdb 是两平台共有的**。
 */
static const char* const k_ad_dbg_parents[] = {
    "gdb", "lldb", "strace", "ltrace", "radare2", "r2",
    "ghidra", "frida", "frida-server", "perf", "valgrind", "rr",
    NULL
};

prot_status prot_antidebug_scan(prot_antidebug_report* out)
{
    PROT_NOISE();   /* W1.6: 每构建序言噪声（破坏特征匹配）*/
    prot_debug_state dbg;
    uint32_t extra;
    uint32_t round;

    if (out == NULL)
        return PROT_OK;   /* 契约: 永不失败, 返回 PROT_OK */
    memset(out, 0, sizeof(*out));

    /* ---- 归一化调试状态（TracerPid 等）----
     *
     * ## 为什么 5 个 Windows 维度在此**归一化为一个**
     *   Windows 的 `peb_being_debugged` / `debug_port` / `debug_flags` /
     *   `debug_object` / `peb_nt_global_flag` 本质都是查**同一件事**
     *   （EPROCESS 的不同字段）。
     *   Linux 内核**只暴露 `TracerPid`** -> 全部由它派生。
     *
     *   => **不是降级，是归一化**。
     */
    memset(&dbg, 0, sizeof(dbg));
    if (prot_plat_debug_probe(&dbg) == PROT_OK) {
        out->peb_being_debugged = dbg.tracer_pid;   /* 归一化 */
        out->debug_port         = dbg.tracer_pid;   /* 归一化 */
        out->debug_flags        = dbg.tracer_pid;   /* 归一化 */
        out->debug_object       = dbg.tracer_pid;   /* 归一化 */
        out->peb_nt_global_flag = dbg.tracer_pid;   /* 归一化 */
        out->kernel_debugger    = dbg.kernel_debugger;
        out->hardware_breakpoints = dbg.hardware_bp; /* **恒 0**（不支持）*/
    }

    /* ---- 调试堆标志 ----
     *   glibc **无** "调试堆" 概念（Windows 的 PEB.ProcessHeap Flags 是
     *   ntdll 堆管理器的实现细节）。故本项**归一化到 TracerPid**。
     */
    out->debug_heap_flags = out->peb_being_debugged;

    /* ---- int3 蜜罐（`sigaction(SIGTRAP)`，**机制不同语义相同**）---- */
    out->int3_honey = (prot_plat_int3_probe() == 2u) ? 1u : 0u;

    /* ---- 计时检测（`clock_gettime` + `nanosleep`，**等价**）---- */
    out->timing_suspicious = 0u;
    for (round = 0u; round < PROT_AD_TIMING_ROUNDS; round++) {
        struct timespec a, b;
        int64_t dt_ms;
        if (clock_gettime(CLOCK_MONOTONIC, &a) != 0)
            break;
        prot_plat_sleep_ms(PROT_AD_TIMING_SLEEP_MS);
        if (clock_gettime(CLOCK_MONOTONIC, &b) != 0)
            break;
        dt_ms = (int64_t)(b.tv_sec - a.tv_sec) * 1000
                + (int64_t)((b.tv_nsec - a.tv_nsec) / 1000000);
        /* 任一轮耗时显著低于名义值即可疑（同 Windows 判据） */
        if (dt_ms < (int64_t)PROT_AD_TIMING_MIN_MS) {
            out->timing_suspicious = 1u;
            break;
        }
    }

    /* ---- 父进程黑名单（`/proc/<ppid>/comm`，**等价且更简单**）---- */
    out->ppid_blacklist = 0u;
    {
        static char pname[256];
        if (prot_plat_parent_name(pname, sizeof(pname))) {
            int k;
            for (k = 0; k_ad_dbg_parents[k] != NULL; k++) {
                if (strstr(pname, k_ad_dbg_parents[k]) != NULL) {
                    out->ppid_blacklist = 1u;
                    break;
                }
            }
        }
    }

    /* ---- 时钟漂移（单调钟 vs 墙钟，**等价**）---- */
    out->clock_drift_sec = 0u;
    {
        uint64_t t0t = 0, t0w = 0, t1t = 0, t1w = 0;
        if (prot_plat_clock_pair(&t0t, &t0w)) {
            prot_plat_sleep_ms(150);
            if (prot_plat_clock_pair(&t1t, &t1w)) {
                uint64_t dt_tick, dt_wall;
                dt_tick = (t1t >= t0t) ? (t1t - t0t) : 0u;
                dt_wall = (t1w >= t0w) ? (t1w - t0w) : 0u;
                if (dt_tick > dt_wall + 250ull ||
                    dt_wall > dt_tick + 250ull)
                    out->clock_drift_sec = 1u;
            }
        }
    }

    /* ---- **Linux 独有的 3 个维度** ----
     *
     * ## 为什么这些是"独有"
     *   Linux 的注入/HOOK 生态与 Windows **不同**:
     *     · Windows: DLL 注入、IAT hook、inline hook
     *     · Linux:   **LD_PRELOAD**、PLT/GOT hook、ptrace
     *   => Linux 需要检查**自己的**主流注入方式。
     *
     * ## 字段映射（**如实说明**）
     *   报表结构体**无**这三个字段（它是对外 ABI 契约）——
     *   故映射到**语义最近的既有字段**，并在此**明确记录**:
     *     · LD_PRELOAD     -> `ppid_blacklist`（**注入类检测**）
     *     · 可疑 .so       -> `ppid_blacklist`（同上）
     *     · 已被 ptrace    -> `debug_object`（**已确认被跟踪**）
     *
     *   **为什么不加新字段**: `prot_antidebug_report` 是对外契约
     *   （`include/protect/antidebug.h`），加字段会**破坏 ABI**;
     *   且宿主（demo）按固定字段名读取。
     *   => 用既有字段 + **本注释记录语义扩展**（最小侵入）。
     */
    extra = prot_plat_extra_debug_flags();
    if (extra != 0u) {
        if ((extra & (PROT_PLAT_EXTRA_PRELOAD | PROT_PLAT_EXTRA_SUSP_SO))
            != 0u)
            out->ppid_blacklist = 1u;
        if ((extra & PROT_PLAT_EXTRA_PTRACED) != 0u)
            out->debug_object = 1u;
    }

    return PROT_OK;
}

#endif /* PROT_PLATFORM */

/* ================================================================== *
 * 平台无关的公共接口
 * ================================================================== */

uint32_t prot_antidebug_detected(const prot_antidebug_report* rep) {
    PROT_NOISE();   /* W1.6 序言噪声 */
    /* S3 试点 (2026-08-30): 受限控制流平坦化 —— 关键位聚合改为等价
     * switch-dispatch 状态机 (语义不变, 静态分支不可直读). */
    uint32_t mask[7];
    uint32_t st = 0u;
    uint32_t acc = 0u;
    if (rep == NULL) {
        return 0;
    }
    mask[0] = rep->peb_being_debugged;
    mask[1] = rep->debug_port;
    mask[2] = rep->debug_flags;
    mask[3] = rep->debug_object;
    mask[4] = rep->hardware_breakpoints;
    mask[5] = rep->timing_suspicious;
    mask[6] = rep->ppid_blacklist;
    for (;;) {
        switch (st) {
        case 0: acc |= mask[0]; st = 1; continue;
        case 1: acc |= mask[1]; st = 2; continue;
        case 2: acc |= mask[2]; st = 3; continue;
        case 3: acc |= mask[3]; st = 4; continue;
        case 4: acc |= mask[4]; st = 5; continue;
        case 5: acc |= mask[5]; st = 6; continue;
        case 6: acc |= mask[6]; st = 7; continue;
        default: break;
        }
        break;
    }
    return acc ? 1u : 0u;
}

/* FAKE 策略伪结果标志 (契约 §6.2) */
static volatile uint32_t g_fake;
prot_status prot_antidebug_apply_policy(prot_policy pol) {
    PROT_NOISE();   /* W1.6 序言噪声 */
    /* S3 扩展 (2026-08-30): 策略分发 switch-dispatch 化 (等价语义) */
    prot_antidebug_report rep;
    uint32_t st;

    prot_antidebug_scan(&rep);
    if (prot_antidebug_detected_multi(&rep) == 0u) {
        return PROT_OK;
    }
    st = (uint32_t)pol;
    for (;;) {
        switch (st) {
        case PROT_POLICY_EXIT:
            prot_plat_terminate(PROT_EXIT_DEBUG_DETECTED);   /* M5: 平台层 */
            st = 0xFFFFFFFFu;
            continue;
        case PROT_POLICY_FAKE:
            g_fake = 1u;
            st = 0xFFFFFFFFu;
            continue;
        case 0xFFFFFFFFu:
            break;
        default:
            st = 0xFFFFFFFFu; /* CONTINUE/其他: 无操作 */
            continue;
        }
        break;
    }
    return PROT_OK;
}

uint32_t prot_antidebug_fake_active(void) {
    return g_fake;
}

prot_status prot_antidebug_hide_thread(void) {
    PROT_NOISE();   /* W1.6 序言噪声 */
    /* M5: 平台层（Windows: NtSetInformationThread；Linux: 如实不支持）*/
    return prot_plat_hide_thread();
}

/* ================================================================== *
 * R3.2-c: 判定多副本 + 交叉聚合
 *
 * 缘起 (docs/DECISION_REDUNDANCY_PLAN.md §3 R3.2-c):
 *   DRILL7 步骤 4 实证 —— patch prot_antidebug_detected 的函数头
 *   (3 字节 31 C0 C3) 即让「盾」的判定被永久关闭。单点判定 = 单点失效。
 *
 * 修法:
 *   同一语义的 3 个独立副本 (不同名 / 不同机器码 / 不同位置) + 一个
 *   「非短路多路 OR」聚合器 —— 任一副本报 1 即视为检测到。
 *
 * P1 (语义等价必须可验证, MODULE_GUIDE P1):
 *   副本与本体在「7 个关键位 × 5 个咨询位 + NULL」的全组合域上逐位同输出;
 *   由 tools/replica_check.py 机械判据守护:
 *     (a) 差分等价 —— 同输入同输出, 全域穷举 + 定向 fuzz;
 *     (b) 地址互异   —— map 中各副本 VA 两两不同 (抗 /OPT:ICF 折叠);
 *     (c) 负向对照   —— 改动任一副本语义必须被 (a) 抓到。
 *
 * 抗 ICF 为什么需要每副本各自的立即数:
 *   释放构建带 /OPT:ICF (build.ps1 $linkHard), 等价函数会被折叠成同一
 *   地址 —— 那样副本就白做了。故每个副本注入各自不同的立即数使机器码
 *   不同。注意 PROT_NOISE 的 PROT_BUILD_SALT 是全局同一值, 做不到这点。
 * ================================================================== */

#define PROT_AD_R2_SALT 0x5A17C3E9u
#define PROT_AD_R3_SALT 0x1B873593u
#define PROT_AD_R4_SALT 0x9E3779B9u

/* 副本 r2: 展开式顺序 OR (无状态机) */
PROT_NOINLINE
uint32_t prot_antidebug_detected_r2(const prot_antidebug_report* rep) {
    volatile uint32_t k = PROT_AD_R2_SALT;
    uint32_t acc = 0u;

    if (k == 0xDEADBEEFu) { PROT_NOP(); }   /* 抗 ICF: 本副本专属立即数 */
    if (rep == NULL) {
        return 0u;
    }
    acc |= rep->peb_being_debugged;
    acc |= rep->debug_port;
    acc |= rep->debug_flags;
    acc |= rep->debug_object;
    acc |= rep->hardware_breakpoints;
    acc |= rep->timing_suspicious;
    acc |= rep->ppid_blacklist;
    return acc ? 1u : 0u;
}

/* 副本 r3: 状态机, 但**逆序**遍历且状态编号不同 (与本体同构不同码) */
PROT_NOINLINE
uint32_t prot_antidebug_detected_r3(const prot_antidebug_report* rep) {
    volatile uint32_t k = PROT_AD_R3_SALT;
    uint32_t v[7];
    uint32_t st;
    uint32_t acc = 0u;

    if (k == 0xDEADBEEFu) { PROT_NOP(); }   /* 抗 ICF: 本副本专属立即数 */
    if (rep == NULL) {
        return 0u;
    }
    v[0] = rep->ppid_blacklist;
    v[1] = rep->timing_suspicious;
    v[2] = rep->hardware_breakpoints;
    v[3] = rep->debug_object;
    v[4] = rep->debug_flags;
    v[5] = rep->debug_port;
    v[6] = rep->peb_being_debugged;
    st = 6u;
    for (;;) {
        switch (st) {
        case 6: acc |= v[6]; st = 5u; continue;
        case 5: acc |= v[5]; st = 4u; continue;
        case 4: acc |= v[4]; st = 3u; continue;
        case 3: acc |= v[3]; st = 2u; continue;
        case 2: acc |= v[2]; st = 1u; continue;
        case 1: acc |= v[1]; st = 0u; continue;
        case 0: acc |= v[0]; st = 0xFFFFFFFFu; continue;
        default: break;
        }
        break;
    }
    return acc ? 1u : 0u;
}

/* 副本 r4: 归约式 —— (acc | -acc) >> 31 等价于 acc != 0
 * 证明: acc == 0 -> 0; acc != 0 时, 若 acc 最高位为 1 则已完成,
 *       否则 acc < 2^31 故 -acc = 2^32 - acc > 2^31, 最高位必为 1。 */
PROT_NOINLINE
uint32_t prot_antidebug_detected_r4(const prot_antidebug_report* rep) {
    volatile uint32_t k = PROT_AD_R4_SALT;
    uint32_t acc;

    if (k == 0xDEADBEEFu) { PROT_NOP(); }   /* 抗 ICF: 本副本专属立即数 */
    if (rep == NULL) {
        return 0u;
    }
    acc  = rep->peb_being_debugged | rep->debug_port | rep->debug_flags;
    acc |= rep->debug_object | rep->hardware_breakpoints;
    acc |= rep->timing_suspicious | rep->ppid_blacklist;
    return (acc | (0u - acc)) >> 31;
}

/* 非短路多路 OR 聚合器 (契约入口: 宿主应调用本函数, 而非任一副本)
 *
 * 为什么**非短路**: 用 || 会让后续副本永不执行 —— 攻击者只需让先执行的
 * 那个副本返回 0 即跳过其余副本, 冗余归零。此处四个调用**全部发生**,
 * 再由 | 位或合并 (| 对 uint32_t 无短路语义)。
 *
 * 为什么四个调用不会被优化掉: 每个副本首条语句是局部 volatile 的写入
 * (PROT_NOISE / 副本专属立即数), volatile 访问是副作用, 编译器不得
 * 消除、合并或跨副本复用。 */
PROT_NOINLINE
uint32_t prot_antidebug_detected_multi(const prot_antidebug_report* rep) {
    uint32_t hit = 0u;

    PROT_NOISE();   /* W1.6 序言噪声 */
    hit |= prot_antidebug_detected(rep);
    hit |= prot_antidebug_detected_r2(rep);
    hit |= prot_antidebug_detected_r3(rep);
    hit |= prot_antidebug_detected_r4(rep);
    return hit ? 1u : 0u;
}
