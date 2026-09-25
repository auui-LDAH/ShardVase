/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * prot_platform.h — 平台抽象接口（跨平台缺口 #3 的第一步）
 *
 * ## 这个文件是什么
 *   把现有代码里**平台相关的原语**抽成一组**薄接口**，使:
 *     · 纯逻辑模块（VM/crc32/strcrypt/授权链）**不直接调用**平台 API
 *     · 平台相关模块通过本接口访问平台能力
 *     · 新增平台 = **实现本接口**，而非改所有模块
 *
 * ## 为什么这样设计（而非直接做 Linux 移植）
 *   实测（2026-09-23）: **38% 的 C 文件**含 Windows API 依赖，
 *   且反调试/完整性/页管理在 Linux 上**机制完全不同**
 *   （ptrace/ELF/procfs/mprotect vs PEB/PE/VirtualProtect）。
 *   直接移植 = 重写这 38%。
 *
 *   故第一步是**接口抽象** —— 它的价值是:
 *     证明"模块协议可跨平台"，而非"完成 Linux 支持"。
 *
 * ## 诚实边界
 *   · 本文件目前是**接口定义 + Windows 实现委托**，**未改变任何现有行为**
 *   · Linux 部分仅提供**明确的未实现标记**（返回 PROT_ERR_UNSUPPORTED）
 *   · **未接入构建**（独立头文件，不影响现有 Windows 构建）
 *   · 不是"运行期 ABI"（仍是编译期选择平台实现）
 */

#ifndef PROT_PLATFORM_H
#define PROT_PLATFORM_H

#include "protect/protdef.h"

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ *
 * 平台标识
 * ------------------------------------------------------------------ */

#define PROT_PLATFORM_WINDOWS 1
#define PROT_PLATFORM_LINUX   2
#define PROT_PLATFORM_MACOS   3

#if defined(_WIN32)
#  define PROT_PLATFORM PROT_PLATFORM_WINDOWS
#elif defined(__linux__)
#  define PROT_PLATFORM PROT_PLATFORM_LINUX
#elif defined(__APPLE__)
#  define PROT_PLATFORM PROT_PLATFORM_MACOS
#else
#  error "prot_platform.h: 未知平台（需先定义该平台的实现）"
#endif

/*
 * 平台能力位掩码 —— 模块可据此**声明自己需要什么**。
 *
 * 为什么需要: 某些模块（如页对齐的 selfcrypt）在缺少对应能力的平台上
 * 应**优雅降级**或**明确拒绝**，而非静默失效（P4 诚实边界）。
 */
#define PROT_PCAP_PAGE_PROTECT   (1u << 0)  /* 可改内存页保护属性 */
#define PROT_PCAP_PAGE_ALLOC_RWX (1u << 1)  /* 可分配 RWX 页 */
#define PROT_PCAP_DEBUG_DETECT   (1u << 2)  /* 可检测调试器 */
#define PROT_PCAP_PROC_ENUM      (1u << 3)  /* 可枚举进程 */
#define PROT_PCAP_MODULE_ENUM    (1u << 4)  /* 可枚举已加载模块 */
#define PROT_PCAP_TIME_HIRES     (1u << 5)  /* 高精度计时 */
#define PROT_PCAP_FILE_SELF      (1u << 6)  /* 可读自身映像 */

/* ------------------------------------------------------------------ *
 * 分组 1: 内存页管理
 *
 * 对应 Windows: VirtualAlloc / VirtualProtect / VirtualFree
 * 对应 Linux  : mmap / mprotect / munmap
 * ------------------------------------------------------------------ */

typedef enum prot_page_prot {
    PROT_PAGE_READ = 0,
    PROT_PAGE_READWRITE,
    PROT_PAGE_EXECUTE,
    PROT_PAGE_EXECUTE_READ,
    PROT_PAGE_EXECUTE_READWRITE
} prot_page_prot;

/* 分配内存页（返回 NULL 表示失败）。flags 见 PROT_PAGE_ALLOC_*。 */
void* prot_plat_alloc(size_t size, prot_page_prot prot);

/* 改变已有页的保护属性。 */
prot_status prot_plat_protect(void* addr, size_t size, prot_page_prot prot);

/* 释放 prot_plat_alloc 分配的内存。 */
prot_status prot_plat_free(void* addr, size_t size);

/* 查询本平台是否支持某能力（返回 PROT_PCAP_* 的位或）。 */
uint32_t prot_plat_capabilities(void);

/* ------------------------------------------------------------------ *
 * 分组 2: 调试检测原语
 *
 * 对应 Windows: IsDebuggerPresent / PEB 读 / CheckRemoteDebuggerPresent
 * 对应 Linux  : /proc/self/status (TracerPid) / ptrace(PTRACE_TRACEME)
 *
 * **注意**: 本接口只提供**原语**；"检测到什么"的**语义**由模块定义
 *          （与 host_hooks 的职责分离一致 —— 平台给原语，模块给判断）。
 * ------------------------------------------------------------------ */

typedef struct prot_debug_primitives {
    int being_debugged;      /* 有调试器附加 */
    int remote_debugger;     /* 远程调试 */
    int hardware_breakpoints;/* 硬件断点（平台支持时） */
    int hardware_supported;  /* 本平台是否支持硬件断点检测 */
} prot_debug_primitives;

/* 采集调试检测原语。永不失败（失败时字段置 0 并返回 PROT_OK）。 */
prot_status prot_plat_debug_primitives(prot_debug_primitives* out);

/* ------------------------------------------------------------------ *
 * 分组 3: 进程/模块信息
 *
 * 对应 Windows: Toolhelp32 / NtQuerySystemInformation
 * 对应 Linux  : /proc 遍历
 * ------------------------------------------------------------------ */

typedef struct prot_proc_info {
    uint32_t pid;
    char     name[64];
} prot_proc_info;

/* 枚举进程。返回写入的条目数；capacity 不足时截断并报告真实数量。 */
size_t prot_plat_enum_processes(prot_proc_info* out, size_t capacity);

typedef struct prot_module_info {
    void*    base;
    size_t   size;
    char     name[128];
} prot_module_info;

/* 枚举已加载模块（含自身映像）。 */
size_t prot_plat_enum_modules(prot_module_info* out, size_t capacity);

/* ------------------------------------------------------------------ *
 * 分组 4: 计时与自身映像
 * ------------------------------------------------------------------ */

/* 高精度单调时钟（纳秒）。失败返回 0。 */
uint64_t prot_plat_monotonic_ns(void);

/* 定位自身映像在文件系统中的路径；返回写入长度，0 表示失败。 */
size_t prot_plat_self_path(char* out, size_t capacity);

/* ------------------------------------------------------------------ *
 * 平台实现约定
 *
 * Windows: src/platform/prot_platform_win.c（委托到现有 Windows API 调用）
 * Linux  : src/platform/prot_platform_linux.c（**未实现**，见该文件说明）
 *
 * **当前状态**（2026-09-23）:
 *   本头文件为**接口原型**，尚未接入构建（不影响现有 Windows 构建）。
 *   接入步骤见 docs/PORTABILITY_ASSESSMENT.md §5。
 * ------------------------------------------------------------------ */

#ifdef __cplusplus
}
#endif

#endif /* PROT_PLATFORM_H */
