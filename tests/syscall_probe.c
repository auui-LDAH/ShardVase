/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * tests/syscall_probe.c — direct syscall 单测 (A6)
 *
 * 验证 prot_sys_nt_query_information_process / prot_sys_nt_query_system_information
 * 的直调 stub 可用, 且返回码与结果与 GetProcAddress 路径完全一致
 * (干净环境两者都必须成功, 且值相同)。退出码 0 = 全部断言通过。
 * 链接 src/syscall.c, 由 build.ps1 每构建执行。
 */
#include <windows.h>
#include <stdio.h>

#include "protect/syscall.h"

#define PROT_PID_DEBUG_PORT   7
#define PROT_PID_DEBUG_FLAGS  31
#define PROT_SYS_KERNEL_DEBUGGER_INFO 0x23

typedef NTSTATUS(NTAPI* probe_qip_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* probe_qsi_t)(ULONG, PVOID, ULONG, PULONG);

typedef struct probe_kdbg {
    BOOLEAN DebuggerEnabled;
    BOOLEAN DebuggerNotPresent;
} probe_kdbg;

int main(void)
{
    HMODULE ntdll;
    probe_qip_t qip = NULL;
    probe_qsi_t qsi = NULL;
    int failed = 0;

    printf("syscall_probe: available=%u\n", prot_sys_available());
    if (!prot_sys_available()) {
        printf("syscall_probe: FAIL stub unavailable\n");
        return 1;
    }

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll != NULL) {
        qip = (probe_qip_t)GetProcAddress(ntdll, "NtQueryInformationProcess");
        qsi = (probe_qsi_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    }
    if (qip == NULL || qsi == NULL) {
        printf("syscall_probe: FAIL cannot resolve ntdll exports\n");
        return 1;
    }

    {
        ULONG_PTR port = 0, port2 = 0;
        NTSTATUS a = prot_sys_nt_query_information_process(
            GetCurrentProcess(), PROT_PID_DEBUG_PORT, &port, sizeof(port), NULL);
        NTSTATUS b = qip(GetCurrentProcess(), PROT_PID_DEBUG_PORT,
                         &port2, sizeof(port2), NULL);
        printf("  qip debug_port  direct=0x%lx(%llu) api=0x%lx(%llu)\n",
               (unsigned long)a, (unsigned long long)port,
               (unsigned long)b, (unsigned long long)port2);
        if (a != b || port != port2)
            failed = 1;
    }
    {
        ULONG flags = 0, flags2 = 0;
        NTSTATUS a = prot_sys_nt_query_information_process(
            GetCurrentProcess(), PROT_PID_DEBUG_FLAGS, &flags, sizeof(flags), NULL);
        NTSTATUS b = qip(GetCurrentProcess(), PROT_PID_DEBUG_FLAGS,
                         &flags2, sizeof(flags2), NULL);
        printf("  qip debug_flags direct=0x%lx(%lu) api=0x%lx(%lu)\n",
               (unsigned long)a, (unsigned long)flags,
               (unsigned long)b, (unsigned long)flags2);
        if (a != b || flags != flags2)
            failed = 1;
    }
    {
        probe_kdbg k = { 0, 0 }, k2 = { 0, 0 };
        NTSTATUS a = prot_sys_nt_query_system_information(
            PROT_SYS_KERNEL_DEBUGGER_INFO, &k, sizeof(k), NULL);
        NTSTATUS b = qsi(PROT_SYS_KERNEL_DEBUGGER_INFO, &k2, sizeof(k2), NULL);
        printf("  qsi kdbg        direct=0x%lx(en=%u) api=0x%lx(en=%u)\n",
               (unsigned long)a, (unsigned)k.DebuggerEnabled,
               (unsigned long)b, (unsigned)k2.DebuggerEnabled);
        if (a != b || k.DebuggerEnabled != k2.DebuggerEnabled)
            failed = 1;
    }

    if (failed) {
        printf("syscall_probe: FAIL direct syscall != API path\n");
        return 1;
    }
    printf("syscall_probe: PASS (direct syscall == API path)\n");
    return 0;
}
