/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * syscall.c — direct syscall 直调 (A6)
 *
 * 对应契约 docs/CONTRACT.md §6.3。
 * 在 ntdll 导出 stub 可能被 inline hook 的场景下, 从 stub 字节码中提取
 * syscall 号 (SSN) 并绕开 stub 入口直接 syscall 进入内核。
 *
 * ## 平台分支（C1，2026-09-25）
 *
 * **Windows（原实现，逐字保留）** —— 4 步手工绕 hook:
 *   1. 定位 ntdll 导出函数 (GetProcAddress, 只读地址, 与 hook 无关)
 *   2. 在字节码窗口内扫描 `0F 05`, 向前找 `B8 <imm32>` (mov eax, SSN)
 *   3. 运行时生成 12 字节 stub: `mov r10,rcx; mov eax,SSN; syscall; ret`
 *   4. 调用 stub; 任何失败 -> STATUS_UNSUCCESSFUL, 调用方回退
 *
 * **Linux（C1 新增）** —— **不需要上述任何一步**:
 *   `syscall(SYS_xxx, ...)` 本身就是**直接陷入内核**,
 *   **不经过任何用户态 stub** -> **天然免疫** LD_PRELOAD / PLT hook。
 *
 *   > **Windows 需要"绕"的东西，在 Linux 上根本不存在。**
 *   > 这不是"降级"，而是**该平台的原生做法本就更直接**。
 *
 *   实现: 直接转调平台层 `prot_plat_nt_query_*`
 *   （Linux 实现读 `/proc/self/status` 的 TracerPid —— 内核提供，
 *     **用户态无法 hook**，与 Windows 直调的**目的一致**）。
 */

#include "protect/syscall.h"
#include "protect/prot_platform.h"   /* C1: 跨平台 NT 查询等价物 */
#include "protect/prot_noise.h"
#include <stdint.h>   /* C1: uint32_t（非 Windows 分支）*/      /* W1.6 序言噪声 */

/* ================================================================== *
 * Windows 实现（**原实现，逐字保留**）
 * ================================================================== */
#if PROT_PLATFORM == PROT_PLATFORM_WINDOWS

#include <windows.h>
#include <string.h>

#define PROT_SYS_SSN_INVALID 0xFFFFFFFFu

typedef NTSTATUS(NTAPI* sys_ntqip_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* sys_ntqsi_t)(ULONG, PVOID, ULONG, PULONG);

static void* s_stub_qip;              /* NtQueryInformationProcess 直调 stub */
static void* s_stub_qsi;              /* NtQuerySystemInformation 直调 stub */
static volatile LONG s_sys_init;      /* 一次性初始化标志 */

/*
 * 在导出函数字节码窗口内提取 SSN:
 * 找 `0F 05` (syscall), 再向前 (最多 24 字节) 找 `B8/B9 <imm32>`。
 * 返回 SSN; 未找到返回 PROT_SYS_SSN_INVALID。
 */
static uint32_t sys_find_ssn(const uint8_t* fn)
{
    int32_t i, j;

    for (i = -32; i <= 48; i++) {
        if (fn[i] == 0x0Fu && fn[i + 1] == 0x05u) {
            for (j = i - 1; j >= i - 24 && j >= 0; j--) {
                if (fn[j] == 0xB8u || fn[j] == 0xB9u) {
                    uint32_t ssn;
                    memcpy(&ssn, fn + j + 1, 4);
                    if (ssn < 0x1000u)
                        return ssn;
                }
            }
        }
    }
    return PROT_SYS_SSN_INVALID;
}

/* 运行时生成 12 字节直调 stub 并设为只读可执行; 失败返回 NULL */
static void* sys_make_stub(uint32_t ssn)
{
    static const uint8_t code[12] = {
        0x4Cu, 0x8Bu, 0xD1u,          /* mov r10, rcx          */
        0xB8u, 0x00u, 0x00u, 0x00u, 0x00u, /* mov eax, imm32 (SSN) */
        0x0Fu, 0x05u,                 /* syscall               */
        0xC3u                         /* ret                   */
    };
    uint8_t* p;
    DWORD old;

    p = (uint8_t*)VirtualAlloc(NULL, sizeof(code), MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (p == NULL)
        return NULL;
    memcpy(p, code, sizeof(code));
    memcpy(p + 4, &ssn, 4);
    FlushInstructionCache(GetCurrentProcess(), p, sizeof(code));
    VirtualProtect(p, sizeof(code), PAGE_EXECUTE_READ, &old);
    return p;
}

static void sys_init(void)
{
    HMODULE h;
    uint32_t ssn;
    const uint8_t* qip;
    const uint8_t* qsi;

    if (InterlockedCompareExchange(&s_sys_init, 1, 0) != 0)
        return; /* 已初始化 */

    h = GetModuleHandleW(L"ntdll.dll");
    if (h == NULL)
        return; /* ntdll 必然已加载; 失败则保持 NULL, 调用方回退 */

    qip = (const uint8_t*)GetProcAddress(h, "NtQueryInformationProcess");
    qsi = (const uint8_t*)GetProcAddress(h, "NtQuerySystemInformation");

    if (qip != NULL) {
        ssn = sys_find_ssn(qip);
        if (ssn != PROT_SYS_SSN_INVALID)
            s_stub_qip = sys_make_stub(ssn);
    }
    if (qsi != NULL) {
        ssn = sys_find_ssn(qsi);
        if (ssn != PROT_SYS_SSN_INVALID)
            s_stub_qsi = sys_make_stub(ssn);
    }
}

NTSTATUS prot_sys_nt_query_information_process(void* h, uint32_t cls,
                                               void* buf, uint32_t len,
                                               uint32_t* ret)
{
    PROT_NOISE();   /* W1.6 序言噪声 */
    sys_init();
    if (s_stub_qip != NULL) {
        /* ## 类型转换（2026-09-25 实测修正）
         *   接口已平台无关化（`void*`/`uint32_t`），而 Windows 原生 stub
         *   需要 `HANDLE`/`ULONG`/`PVOID`/`PULONG`。
         *   本次**显式转换**（而非依赖隐式）—— 否则 MSVC 报
         *   **C4057**（"PULONG 在间接程度上与 uint32_t* 的基类型存在细微差异"）
         *   -> `/WX` 下失败。
         *
         *   **为什么** `PULONG` 与 `uint32_t*` 不同:
         *     `ULONG` = `unsigned long`，而 `uint32_t` = `unsigned int`；
         *     虽然都是 32 位，但 MSVC 视为**不同基类型**。
         */
        return ((sys_ntqip_t)s_stub_qip)((HANDLE)h, (ULONG)cls,
                                         (PVOID)buf, (ULONG)len,
                                         (PULONG)ret);
    }
    return (NTSTATUS)0xC0000001; /* STATUS_UNSUCCESSFUL: 调用方回退 */
}

NTSTATUS prot_sys_nt_query_system_information(uint32_t cls, void* buf,
                                              uint32_t len, uint32_t* ret)
{
    PROT_NOISE();   /* W1.6 序言噪声 */
    sys_init();
    if (s_stub_qsi != NULL) {
        /* 同上的显式转换（避免 C4057） */
        return ((sys_ntqsi_t)s_stub_qsi)((ULONG)cls, (PVOID)buf, (ULONG)len,
                                         (PULONG)ret);
    }
    return (NTSTATUS)0xC0000001; /* STATUS_UNSUCCESSFUL: 调用方回退 */
}

uint32_t prot_sys_available(void)
{
    PROT_NOISE();   /* W1.6 序言噪声 */
    sys_init();
    return (s_stub_qip != NULL && s_stub_qsi != NULL) ? 1u : 0u;
}

/* ================================================================== *
 * 非 Windows 实现（C1 新增）
 * ================================================================== */
#else

/* ## 为什么不需要 stub
 *   Windows 的 SSN 提取 + 直调 stub 是为了**绕开可被 hook 的 ntdll stub**。
 *   Linux 上:
 *     · `syscall()` 本身即直调 —— **没有 stub 可供 hook**
 *     · 本模块转调平台层，而平台层读 `/proc/self/status`（**内核提供**）
 *   => 两者**目的一致**（拿到未被用户态篡改的事实），
 *      但 Linux 的实现**更直接**（无需自建 stub）。
 *
 * ## 语义保持
 *   返回值约定与 Windows 完全一致:
 *     · 成功 -> 0
 *     · 失败 -> 0xC0000001 (STATUS_UNSUCCESSFUL)，**调用方回退**
 *   => `antidebug.c` 的回退逻辑**无需改动**。
 */

NTSTATUS prot_sys_nt_query_information_process(void* h, uint32_t cls,
                                               void* buf, uint32_t len,
                                               uint32_t* ret)
{
    size_t rl = 0;
    uint32_t pcls;
    int r;
    (void)h;   /* 本平台只查**自身进程**（与调用方语义一致）*/

    PROT_NOISE();   /* W1.6 序言噪声 */

    /* NT class -> 平台无关 cls */
    switch (cls) {
    case 7u:  pcls = PROT_PIQ_DEBUG_PORT; break;
    case 31u: pcls = PROT_PIQ_DEBUG_FLAGS; break;
    case 30u: pcls = PROT_PIQ_DEBUG_OBJECT_HANDLE; break;
    default:  return (NTSTATUS)0xC0000001;
    }

    r = prot_plat_nt_query_process(pcls, buf, (size_t)len, &rl);
    if (r != PROT_NT_OK)
        return (NTSTATUS)0xC0000001;
    if (ret != NULL)
        *ret = (uint32_t)rl;
    return (NTSTATUS)0;
}

NTSTATUS prot_sys_nt_query_system_information(uint32_t cls, void* buf,
                                              uint32_t len, uint32_t* ret)
{
    size_t rl = 0;
    int r;

    PROT_NOISE();   /* W1.6 序言噪声 */

    if (cls != 0x23u)   /* 只支持 SystemKernelDebuggerInformation */
        return (NTSTATUS)0xC0000001;

    r = prot_plat_nt_query_system(PROT_SIQ_KERNEL_DEBUGGER, buf,
                                  (size_t)len, &rl);
    if (r != PROT_NT_OK)
        return (NTSTATUS)0xC0000001;
    if (ret != NULL)
        *ret = (uint32_t)rl;
    return (NTSTATUS)0;
}

uint32_t prot_sys_available(void)
{
    PROT_NOISE();   /* W1.6 序言噪声 */
    return prot_plat_nt_query_available();
}

#endif /* PROT_PLATFORM */
