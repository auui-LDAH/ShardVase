/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * dbiguard.c — 反动态插桩/反 hook 检测 (N2, 咨询项)
 *
 * 对应契约 docs/ADVANCED2.md §3。
 *   - inline_hooks: 检查 GetProcAddress/NtQueryInformationProcess 等敏感
 *     API 入口前 8 字节是否被改写为跳转 (Detours 典型 5-12 字节 inline hook);
 *   - frida_agent: 遍历已加载模块, 匹配 frida-agent/gum-js 特征;
 *   - rx_rw_regions: 进程可执行+可写页数量超过阈值 (插桩引擎特征);
 *   - thread_count: 线程数超过阈值 (注入/插桩副作用)。
 * 全部为咨询项 (只报告, 不触发策略; 正常杀软也可能注入)。
 */

#include <windows.h>
#include <tlhelp32.h>
#include <string.h>

#include "protect/dbiguard.h"
#include "protect/prot_noise.h"   /* W1.6 序言噪声 */

#define DBIGUARD_RX_RW_MAX 8u
#define DBIGUARD_THREADS_MAX 200u

/* 敏感 API: (模块, 函数名) —— 只读 ntdll/kernel32 导出入口 */
static const struct api_probe {
    const char* mod;
    const char* fn;
} k_probes[] = {
    { "ntdll.dll", "NtQueryInformationProcess" },
    { "ntdll.dll", "NtQuerySystemInformation" },
    { "kernel32.dll", "GetProcAddress" },
    { "kernel32.dll", "CreateFileW" },
};

/* 前 8 字节是否"被改写为跳转" (jmp rel32=E9 / jmp [mem]=FF 25) */
static int entry_hooked(const uint8_t* p)
{
    /* E9 xx xx xx xx: jmp rel32 (Detours 常用) */
    if (p[0] == 0xE9u)
        return 1;
    /* FF 25 xx xx xx xx: jmp qword ptr [rip+disp] */
    if (p[0] == 0xFFu && p[1] == 0x25u)
        return 1;
    /* 68 xx xx xx xx C3: push imm32; ret (x86 风格, x64 少见) */
    if (p[0] == 0x68u && p[5] == 0xC3u)
        return 1;
    return 0;
}

static uint32_t scan_inline_hooks(void)
{
    size_t i;
    uint32_t hits = 0u;

    for (i = 0u; i < sizeof(k_probes) / sizeof(k_probes[0]); i++) {
        HMODULE h = GetModuleHandleA(k_probes[i].mod);
        if (h != NULL) {
            const uint8_t* p = (const uint8_t*)GetProcAddress(h, k_probes[i].fn);
            if (p != NULL && entry_hooked(p))
                hits++;
        }
    }
    return hits;
}

static uint32_t scan_frida_agent(void)
{
    HANDLE snap;
    MODULEENTRY32 me;
    uint32_t hits = 0u;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                    GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE)
        return 0u;
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            /* szModule 是 TCHAR; 本项目编译 ANSI (未定义 UNICODE) */
            const char* n = me.szModule;
            if (strstr(n, "frida") != NULL || strstr(n, "gum-js") != NULL ||
                strstr(n, "gadget") != NULL)
                hits++;
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return hits;
}

static uint32_t scan_rx_rw_regions(void)
{
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = 0u;
    uint32_t count = 0u;

    while (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) != 0) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & 0xFFu) == PAGE_EXECUTE_READWRITE)
            count++;
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (addr == 0u)
            break;
    }
    return (count > DBIGUARD_RX_RW_MAX) ? 1u : 0u;
}

static uint32_t scan_thread_count(void)
{
    HANDLE snap;
    THREADENTRY32 te;
    uint32_t n = 0u;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0u;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == GetCurrentProcessId())
                n++;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return (n > DBIGUARD_THREADS_MAX) ? 1u : 0u;
}

prot_status prot_dbiguard_scan(prot_dbiguard_report* out)
{
    PROT_NOISE();   /* W1.6 序言噪声 */
    if (out == NULL)
        return PROT_OK;
    memset(out, 0, sizeof(*out));
    out->inline_hooks = scan_inline_hooks();
    out->frida_agent = scan_frida_agent();
    out->rx_rw_regions = scan_rx_rw_regions();
    out->thread_count = scan_thread_count();
    return PROT_OK;
}

uint32_t prot_dbiguard_suspicious(const prot_dbiguard_report* rep)
{
    PROT_NOISE();   /* W1.6 序言噪声 */
    if (rep == NULL)
        return 0u;
    return (rep->inline_hooks || rep->frida_agent ||
            rep->rx_rw_regions || rep->thread_count) ? 1u : 0u;
}
