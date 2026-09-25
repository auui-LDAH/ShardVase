/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * prot_platform_win.c — 平台抽象层（Windows 实现）
 *
 * ## 这个文件是什么（L1：跨平台缺口 #3 的接入步骤）
 *   `include/protect/prot_platform.h` 定义了平台原语的**薄接口**。
 *   本文件提供 **Windows 实现**，委托到既有 Windows API。
 *
 * ## 为什么先做 Windows 实现
 *   L1 的目标不是"移植 Linux"，而是**证明接口可用** ——
 *   把 Windows 实现接上，并让 **1-2 个模块实际改用它**。
 *   这样接口才算被验证过，而非纸面设计。
 *
 * ## 注册位置
 *   本文件在 `modules.json` 的 `primitives` 中登记为 `platform_win`
 *   （与 `crc32` / `vm_rekey` 同类 —— **基础设施，总是编译**）。
 *
 * ## 诚实边界
 *   · 仅**部分**接口有实现（见各函数注释）
 *   · 未实现的接口返回明确的失败值，**不静默**
 *   · 本文件**不改变任何现有行为** —— 它只是把既有 API 调用集中封装
 */

#include "protect/prot_platform.h"

#if PROT_PLATFORM == PROT_PLATFORM_WINDOWS

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string.h>
#include <stdio.h>

#pragma comment(lib, "psapi.lib")

/* ------------------------------------------------------------------ *
 * 分组 1: 内存页管理
 * ------------------------------------------------------------------ */

static DWORD win_prot_of(prot_page_prot p)
{
    switch (p) {
    case PROT_PAGE_READ:             return PAGE_READONLY;
    case PROT_PAGE_READWRITE:        return PAGE_READWRITE;
    case PROT_PAGE_EXECUTE:          return PAGE_EXECUTE;
    case PROT_PAGE_EXECUTE_READ:     return PAGE_EXECUTE_READ;
    case PROT_PAGE_EXECUTE_READWRITE:return PAGE_EXECUTE_READWRITE;
    default:                         return PAGE_READWRITE;
    }
}

void* prot_plat_alloc(size_t size, prot_page_prot prot)
{
    if (size == 0)
        return NULL;
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE,
                        win_prot_of(prot));
}

prot_status prot_plat_protect(void* addr, size_t size, prot_page_prot prot)
{
    DWORD old = 0;
    if (addr == NULL || size == 0)
        return PROT_ERR_INVALID_ARG;
    if (!VirtualProtect(addr, size, win_prot_of(prot), &old))
        return PROT_ERR_UNSUPPORTED;
    return PROT_OK;
}

prot_status prot_plat_free(void* addr, size_t size)
{
    (void)size;     /* VirtualFree(MEM_RELEASE) 需要 size=0 */
    if (addr == NULL)
        return PROT_ERR_INVALID_ARG;
    if (!VirtualFree(addr, 0, MEM_RELEASE))
        return PROT_ERR_UNSUPPORTED;
    return PROT_OK;
}

uint32_t prot_plat_capabilities(void)
{
    /* Windows 全部支持（实测: 这些 API 在 Win7+ 均可用） */
    return PROT_PCAP_PAGE_PROTECT
         | PROT_PCAP_PAGE_ALLOC_RWX
         | PROT_PCAP_DEBUG_DETECT
         | PROT_PCAP_PROC_ENUM
         | PROT_PCAP_MODULE_ENUM
         | PROT_PCAP_TIME_HIRES
         | PROT_PCAP_FILE_SELF;
}

/* ------------------------------------------------------------------ *
 * 分组 2: 调试检测原语
 *
 * **注意**: 本函数只采集**事实** —— "检测到怎么办"由模块决定
 *          （与 host_hooks 的职责分离一致）。
 * ------------------------------------------------------------------ */

prot_status prot_plat_debug_primitives(prot_debug_primitives* out)
{
    if (out == NULL)
        return PROT_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    out->being_debugged = IsDebuggerPresent() ? 1 : 0;

    {
        BOOL remote = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote))
            out->remote_debugger = remote ? 1 : 0;
    }

    /* 硬件断点: 读 Dr0-Dr3（仅 x64）。失败则标记"不支持"。 */
#if defined(_M_X64)
    {
        CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            out->hardware_supported = 1;
            out->hardware_breakpoints =
                (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) ? 1 : 0;
        }
    }
#else
    out->hardware_supported = 0;
#endif
    return PROT_OK;
}

/* ------------------------------------------------------------------ *
 * 分组 3: 进程/模块枚举
 * ------------------------------------------------------------------ */

/* 窄字符拷贝（**不用 strncpy** —— /WX 下触发 C4996 不安全警告）。
 *
 * 与项目其它处的做法一致: 显式循环 + 强制终止符。 */
static void copy_narrow(char* dst, size_t capacity, const char* src)
{
    size_t i;
    if (dst == NULL || capacity == 0)
        return;
    for (i = 0; i + 1 < capacity && src[i] != '\0'; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

/* 宽字符 -> 窄字符（ASCII 安全；非 ASCII 用 '?' 占位）。 */
static void narrow_ascii(const wchar_t* src, char* dst, size_t capacity)
{
    size_t i;
    if (dst == NULL || capacity == 0)
        return;
    for (i = 0; i + 1 < capacity && src[i] != L'\0'; i++) {
        wchar_t c = src[i];
        dst[i] = (c > 0 && c < 128) ? (char)c : '?';
    }
    dst[i] = '\0';
}

size_t prot_plat_enum_processes(prot_proc_info* out, size_t capacity)
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    size_t n = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (out != NULL && n < capacity) {
                out[n].pid = (uint32_t)pe.th32ProcessID;
                narrow_ascii(pe.szExeFile, out[n].name,
                             sizeof(out[n].name));
            }
            n++;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return n;
}

size_t prot_plat_enum_modules(prot_module_info* out, size_t capacity)
{
    HMODULE mods[256];
    DWORD needed = 0;
    size_t n = 0;
    DWORD i;

    if (!EnumProcessModules(GetCurrentProcess(), mods,
                            (DWORD)sizeof(mods), &needed))
        return 0;

    for (i = 0; i < needed / sizeof(HMODULE); i++) {
        MODULEINFO mi;
        char name[MAX_PATH] = { 0 };
        if (out != NULL && n < capacity) {
            memset(&mi, 0, sizeof(mi));
            if (GetModuleInformation(GetCurrentProcess(), mods[i],
                                     &mi, (DWORD)sizeof(mi))) {
                out[n].base = mi.lpBaseOfDll;
                out[n].size = (size_t)mi.SizeOfImage;
            }
            GetModuleFileNameA(mods[i], name, (DWORD)sizeof(name));
            copy_narrow(out[n].name, sizeof(out[n].name), name);
        }
        n++;
    }
    return n;
}

/* ------------------------------------------------------------------ *
 * 分组 4: 计时与自身映像
 * ------------------------------------------------------------------ */

uint64_t prot_plat_monotonic_ns(void)
{
    LARGE_INTEGER freq, now;
    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0)
        return 0;
    if (!QueryPerformanceCounter(&now))
        return 0;
    /* 避免溢出: 先算秒再算纳秒余数 */
    return (uint64_t)(now.QuadPart / freq.QuadPart) * 1000000000ull
         + (uint64_t)((now.QuadPart % freq.QuadPart) * 1000000000ull
                      / freq.QuadPart);
}

size_t prot_plat_self_path(char* out, size_t capacity)
{
    DWORD n;
    if (out == NULL || capacity == 0)
        return 0;
    n = GetModuleFileNameA(NULL, out, (DWORD)capacity);
    if (n == 0 || (size_t)n >= capacity)
        return 0;
    out[n] = '\0';
    return (size_t)n;
}

#endif /* PROT_PLATFORM_WINDOWS */
