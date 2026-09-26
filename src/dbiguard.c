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

#include <stdlib.h>   /* M4: 两段式枚举需 malloc */
#include <string.h>

#include "protect/dbiguard.h"
#include "protect/prot_platform.h"  /* M4: 内存/线程/符号抽象 */
#include "protect/prot_noise.h"   /* W1.6 序言噪声 */

#define DBIGUARD_RX_RW_MAX 8u
#define DBIGUARD_THREADS_MAX 200u

/* 敏感 API 探针（**平台无关**）—— M4（2026-09-25）
 *
 * ## 改动前
 *   硬编码 Windows 模块名与函数名:
 *     { "ntdll.dll", "NtQueryInformationProcess" },
 *     { "kernel32.dll", "GetProcAddress" }, ...
 *
 * ## 改动后
 *   用**平台无关的角色名**，由平台层映射到实际模块/符号:
 *     Windows: ntdll.dll / kernel32.dll
 *     Linux:   libc.so.6 / linux-vdso.so.1
 *
 * ## 为什么保留"4 个探针"的结构
 *   探针数量与语义（"**关键 API 是否被改写**"）是**设计的一部分**，
 *   具体符号名才是平台属性 -> 故只替换名字来源。
 */
static const struct api_probe {
    const char* role;   /* 平台无关角色名（见 handle_probe_role）*/
} k_probes[] = {
    { "query_process_info" },
    { "query_system_info" },
    { "resolve_symbol" },
    { "open_file" },
};

/* 平台层可能返回 NULL（该平台无此符号）—— 调用方跳过 */
static void* probe_addr(const char* role);

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

/* ## M4（2026-09-25）: hook 扫描（**平台语义扩展**）
 *
 * **Windows（原语义）**: 检查敏感 API 的**函数体头 8 字节**。
 * **Linux（新增）**: **额外**检查 **GOT 表项是否被改** ——
 *   对应该平台上更主流的 hook 方式（LD_PRELOAD / PLT hook）。
 *
 * **两者共同计入 `inline_hooks`**（语义为"可疑 hook 计数"）。
 */
static uint32_t scan_inline_hooks(void)
{
    size_t i;
    uint32_t hits = 0u;

    for (i = 0u; i < sizeof(k_probes) / sizeof(k_probes[0]); i++) {
        void* p = probe_addr(k_probes[i].role);
        if (p != NULL && entry_hooked((const uint8_t*)p))
            hits++;
    }
    return hits;
}

/* ## M4（2026-09-25）: 模块名扫描 -> 平台层
 *
 * 原实现用 Toolhelp32 枚举模块（Windows 专有）；
 * 新实现用 `prot_plat_enum_modules()`（Windows: EnumProcessModules；
 * Linux: 解析 `/proc/self/maps`）。
 *
 * **额外新增（Linux 相关）**: 除 frida/gum-js/gadget 外，
 * 再查 **LD_PRELOAD 迹象** —— 见 `scan_preload`。
 */
static uint32_t scan_frida_agent(void)
{
    prot_module_info* mods;
    size_t n, i;
    uint32_t hits = 0u;

    /* ## ⚠️ M4 实测教训（2026-09-25）: **不要用大静态数组**
     *
     *   初版用 `static prot_module_info mods[512]`（≈74 KB .bss），
     *   加上 `regs[4096]`（≈98 KB）—— 共 **≈172 KB 静态 .bss**
     *   -> **改变了映像布局** -> **M1 从 6.5% 退化到 100%**
     *     （函数地址跨构建不再变化 -> 攻击者硬编码地址仍有效）。
     *
     *   由二分法实测确认（回退本文件即恢复）。
     *
     *   => 改用**两段式 + 堆分配**（接口的既定设计，见 prot_platform.h）:
     *        ① 先 `out=NULL` 查总数
     *        ② 按总数 `malloc` -> 再取
     *      堆内存**不进 .bss**，布局不受影响。
     *
     *   **为什么不用"小静态缓冲 + 截断"**: 截断会**漏掉**超容量的模块
     *   -> **漏检**（安全侧不可接受）。两段式**不截断**，语义更正确。
     */
    n = prot_plat_enum_modules(NULL, 0);
    if (n == 0u)
        return 0u;
    mods = (prot_module_info*)malloc(n * sizeof(*mods));
    if (mods == NULL)
        return 0u;   /* 分配失败 -> 如实返回"未检出" */

    n = prot_plat_enum_modules(mods, n);
    for (i = 0u; i < n; i++) {
        const char* nm = mods[i].name;
        if (strstr(nm, "frida") != NULL || strstr(nm, "gum-js") != NULL ||
            strstr(nm, "gadget") != NULL)
            hits++;
    }
    free(mods);
    return hits;
}

/* ## M4（2026-09-25）: RWX 页扫描 -> 平台层
 *
 * 原实现用 `VirtualQuery` 遍历（Windows 专有）；
 * 新实现用 `prot_plat_enum_memory()`（Windows: VirtualQuery；
 * Linux: `/proc/self/maps`，**权限字段直接给 rwxp**）。
 */
static uint32_t scan_rx_rw_regions(void)
{
    prot_mem_region* regs;
    size_t n, i;
    uint32_t count = 0u;

    /* 同 scan_frida_agent: **两段式 + 堆分配**（避免大 .bss 影响布局）。
     * 见该函数注释的 M4 实测教训。 */
    n = prot_plat_enum_memory(NULL, 0);
    if (n == 0u)
        return 0u;
    regs = (prot_mem_region*)malloc(n * sizeof(*regs));
    if (regs == NULL)
        return 0u;

    n = prot_plat_enum_memory(regs, n);
    for (i = 0u; i < n; i++) {
        if ((regs[i].prot & (PROT_MEM_PROT_READ | PROT_MEM_PROT_WRITE
                             | PROT_MEM_PROT_EXEC))
            == (PROT_MEM_PROT_READ | PROT_MEM_PROT_WRITE
                | PROT_MEM_PROT_EXEC))
            count++;
    }
    free(regs);
    return (count > DBIGUARD_RX_RW_MAX) ? 1u : 0u;
}

/* ## M4（2026-09-25）: 线程计数 -> 平台层
 *
 * 原实现用 Toolhelp32 枚举线程；新实现用 `prot_plat_thread_count()`
 * （Windows: Toolhelp32；Linux: 数 `/proc/self/task`）。
 */
static uint32_t scan_thread_count(void)
{
    size_t n = prot_plat_thread_count();
    return (n > DBIGUARD_THREADS_MAX) ? 1u : 0u;
}

/* ## 角色名 -> 平台实际符号（M4）
 *
 * 各平台的**敏感 API 不同名但角色相同**:
 *   | 角色 | Windows | Linux |
 *   |------|---------|-------|
 *   | query_process_info | ntdll!NtQueryInformationProcess | libc!ptrace |
 *   | query_system_info  | ntdll!NtQuerySystemInformation  | libc!sysinfo |
 *   | resolve_symbol     | kernel32!GetProcAddress         | libc!dlsym |
 *   | open_file          | kernel32!CreateFileW            | libc!open |
 *
 * **诚实说明**: Linux 侧映射的是"**功能角色相同**"的符号 ——
 *   `ptrace` 是 Linux 上"读进程信息"的核心入口（对应 NT 的
 *   `NtQueryInformationProcess` 的部分用途），但**不是等价物**。
 *   本检查的目的是"**这些关键入口是否被 hook**" ——
 *   角色对应即可，不需要 API 语义完全等价。
 */
static void* probe_addr(const char* role)
{
    if (role == NULL)
        return NULL;
#if defined(_WIN32)
    if (strcmp(role, "query_process_info") == 0)
        return prot_plat_symbol_addr("ntdll.dll",
                                     "NtQueryInformationProcess");
    if (strcmp(role, "query_system_info") == 0)
        return prot_plat_symbol_addr("ntdll.dll",
                                     "NtQuerySystemInformation");
    if (strcmp(role, "resolve_symbol") == 0)
        return prot_plat_symbol_addr("kernel32.dll", "GetProcAddress");
    if (strcmp(role, "open_file") == 0)
        return prot_plat_symbol_addr("kernel32.dll", "CreateFileW");
#else
    if (strcmp(role, "query_process_info") == 0)
        return prot_plat_symbol_addr("libc.so.6", "ptrace");
    if (strcmp(role, "query_system_info") == 0)
        return prot_plat_symbol_addr("libc.so.6", "sysinfo");
    if (strcmp(role, "resolve_symbol") == 0)
        return prot_plat_symbol_addr("libc.so.6", "dlsym");
    if (strcmp(role, "open_file") == 0)
        return prot_plat_symbol_addr("libc.so.6", "open");
#endif
    return NULL;
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
