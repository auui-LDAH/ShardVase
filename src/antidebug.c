/*
 * antidebug.c — 反调试: 检测调试器 / 分析环境
 *
 * 对应契约 docs/CONTRACT.md §6 (x64)。
 * 检测项: PEB.BeingDebugged / PEB.NtGlobalFlag / ProcessDebugPort /
 *         ProcessDebugFlags / ProcessDebugObjectHandle / 硬件断点 /
 *         QPC+Sleep 计时 / 内核调试器标志。
 * 任何 WinAPI/ntdll 调用失败均将该检测项记为 0 (不误报)。
 */

#include <windows.h>
#include <intrin.h>
#include <string.h>

#include "protect/antidebug.h"

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

prot_status prot_antidebug_scan(prot_antidebug_report* out) {
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

    /* NtQueryInformationProcess 三项 */
    if (s_pNtQueryInformationProcess != NULL) {
        ULONG_PTR port = 0;
        ULONG flags = 0;
        HANDLE hDbg = NULL;
        NTSTATUS st;

        st = s_pNtQueryInformationProcess(GetCurrentProcess(), PROT_PID_DEBUG_PORT,
                                          &port, sizeof(port), NULL);
        if (st >= 0) {
            out->debug_port = (port != 0) ? 1u : 0u;
        }

        st = s_pNtQueryInformationProcess(GetCurrentProcess(), PROT_PID_DEBUG_FLAGS,
                                          &flags, sizeof(flags), NULL);
        if (st >= 0) {
            out->debug_flags = (flags != 1) ? 1u : 0u;
        }

        st = s_pNtQueryInformationProcess(GetCurrentProcess(), PROT_PID_DEBUG_OBJECT_HANDLE,
                                          &hDbg, sizeof(hDbg), NULL);
        if (st >= 0 && hDbg != NULL) {
            out->debug_object = 1u;
            CloseHandle(hDbg); /* 成功后关闭返回的句柄 (契约 §6.1) */
        }
    }

    /* 内核调试器标志 (咨询项) */
    if (s_pNtQuerySystemInformation != NULL) {
        NTSTATUS st;
        memset(&kdbg, 0, sizeof(kdbg));
        st = s_pNtQuerySystemInformation(PROT_SYS_KERNEL_DEBUGGER_INFO,
                                         &kdbg, sizeof(kdbg), NULL);
        if (st >= 0) {
            out->kernel_debugger = (kdbg.DebuggerEnabled != 0) ? 1u : 0u;
        }
    }

    return PROT_OK;
}

uint32_t prot_antidebug_detected(const prot_antidebug_report* rep) {
    if (rep == NULL) {
        return 0;
    }
    /* 关键项 = {being_debugged, debug_port, debug_flags, debug_object,
     *           hardware_breakpoints, timing_suspicious}; 咨询项
     *  (peb_nt_global_flag, kernel_debugger, debug_heap_flags, int3_honey) 不计入 */
    return (rep->peb_being_debugged || rep->debug_port || rep->debug_flags ||
            rep->debug_object || rep->hardware_breakpoints ||
            rep->timing_suspicious) ? 1u : 0u;
}

/* FAKE 策略伪结果标志 (契约 §6.2) */
static volatile uint32_t g_fake;

prot_status prot_antidebug_apply_policy(prot_policy pol) {
    prot_antidebug_report rep;

    prot_antidebug_scan(&rep);
    if (prot_antidebug_detected(&rep) != 0) {
        switch (pol) {
            case PROT_POLICY_EXIT:
                TerminateProcess(GetCurrentProcess(), PROT_EXIT_DEBUG_DETECTED);
                break;
            case PROT_POLICY_FAKE:
                g_fake = 1u;
                break;
            case PROT_POLICY_CONTINUE:
            default:
                break; /* 无操作 */
        }
    }
    return PROT_OK;
}

uint32_t prot_antidebug_fake_active(void) {
    return g_fake;
}

prot_status prot_antidebug_hide_thread(void) {
    ad_resolve_ntdll();
    if (s_pNtSetInformationThread != NULL) {
        /* ThreadHideFromDebugger; 若正在被调试, 可能导致进程被调试器终止 */
        s_pNtSetInformationThread(GetCurrentThread(), PROT_THREAD_HIDE_FROM_DEBUGGER,
                                  NULL, 0);
    }
    return PROT_OK;
}
