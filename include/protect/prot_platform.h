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

/* 枚举进程。
 *
 * ## 返回值语义（**契约** —— 平台实现必须遵守，见
 *    `tests/platform_conformance.c` C4.4/C4.5）
 *   返回**真实总数**（不论容量是否足够）:
 *     · `capacity` 不足      -> 截断写入，**仍返回真实总数**
 *     · `out == NULL`        -> **只计数**，不写入
 *     · `capacity == 0`      -> 同 `out == NULL`（只计数）
 *
 * ## 为什么这样约定
 *   调用方需要**两段式用法**: 先查总数 -> 分配缓冲 -> 再取。
 *   若返回值受容量影响，两段式就不可行。
 *
 * ## 失败语义
 *   枚举失败（如平台不支持）-> 返回 0。
 *   （0 也意味着"系统里没有进程"，实际不可能 —— 调用方只需判 `> 0`。）
 */
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
 * 分组 5: 机器指纹**因子来源**（L5b）
 *
 * ## 为什么需要
 *   `src/hostid.c` 此前**直接调用** Windows API 取 4 个因子:
 *     卷序列号 / 计算机名 / MachineGuid(注册表) / 物理盘序列号
 *   -> 机器绑定**不可移植**。
 *
 * ## 关键约束（**改动必须保指纹不变**）
 *   `prot_hostid_get()` 的返回值参与**授权签名**。
 *   若折叠算法或**因子顺序**变化 -> 机器指纹变化 ->
 *   **所有已签发授权失效**（用户机器"认不出自己"）。
 *
 *   故: **折叠算法留在模块里**（协议的一部分，逐字节不变）；
 *       本接口只提供**因子来源**（平台属性）。
 *
 * ## Linux 的现实
 *   这些因子在 Linux **没有 1:1 等价物**，只有**替代方案**:
 *     MachineGuid  -> /etc/machine-id
 *     卷序列号     -> statvfs().f_fsid
 *     计算机名     -> gethostname()
 *     磁盘序列号   -> /sys/block/[dev]/device/serial（**注意**: 勿写成
 *                     `斜杠星号` 形式 —— 会提前闭合本注释块，2026-09-23 实测踩过）
 *   => **指纹值必然不同**（这是预期，不是缺陷）——
 *      Linux 构建的产物与 Windows 的不共享授权。
 * ------------------------------------------------------------------ */

/* 因子类型: 明确区分"通用字符串"与"平台原生整数"。
 *
 * **为什么保留整数类型**: Windows 的卷序列号是 `DWORD`，
 * 原实现按 `(uint32_t)` 折叠。若统一转字符串 -> **指纹会变**。
 * 故必须保留原始类型与值。 */
typedef enum prot_host_factor_kind {
    PROT_HOST_FACTOR_STR = 0,   /* UTF-8/ASCII 字符串 */
    PROT_HOST_FACTOR_U32 = 1    /* 平台原生 32 位整数 */
} prot_host_factor_kind;

typedef struct prot_host_factor {
    prot_host_factor_kind kind;
    uint32_t u32;               /* kind == U32 时有效 */
    const char* str;            /* kind == STR 时有效（NUL 结尾） */
    size_t str_len;             /* 不含 NUL；0 表示用 strlen */
} prot_host_factor;

/* 因子数量上限。
 *
 * ## ⚠️ 容量计算（2026-09-23 实测教训）
 *   初版设为 **8** -> **指纹变了**（`b4281468e21a4033` -> `1706bdf43d5c194c`）！
 *
 *   原因: 因子构成是
 *     卷序列号 3 个 U32 + **计算机名逐码元（最多 16 个）**
 *     + MachineGuid 1 + 磁盘序列号 1
 *     = **最坏 21 个**
 *
 *   本机计算机名 `DEV-MACHINE` 是 **15 字符** -> 需 **20 个槽**
 *   -> 容量 8 **必然截断** -> 折叠的码元数少于原实现 -> 指纹不同。
 *
 *   **这印证了"未验证 != 通过"**: 若不设基线比对，
 *   这个缺陷会**静默破坏所有已签发授权**。
 *
 *   故上限设为 **32**（21 + 余量），并在平台实现中**拒绝超容**而非静默截断。
 */
#define PROT_HOST_MAX_FACTORS 32

/* 采集机器指纹因子。
 *
 * ## 返回
 *   写入 `out` 的因子个数（<= PROT_HOST_MAX_FACTORS）；0 表示失败。
 *
 * ## 顺序契约（**重要**）
 *   返回顺序**必须稳定**（同一机器上多次调用同序），
 *   因为调用方按该顺序折叠 -> 顺序变化 = 指纹变化。
 *
 * ## 平台差异（**如实**）
 *   Windows: [卷序列号(U32)] [计算机名(STR)] [MachineGuid(STR)]
 *            [物理盘序列号(STR)]  —— 缺失的项**跳过**，不占位
 *   Linux:   [machine-id] [hostname] [DMI product_uuid]
 *            [磁盘序列号] —— **值不同**，指纹必然不同
 *
 * ## 缺失因子的处理
 *   某项取不到 -> **跳过该项**（不写入）。
 *   这与原 `hostid.c` 的行为一致（`if (GetVolumeInformationW(...))`）。
 */
size_t prot_plat_host_factors(prot_host_factor* out, size_t capacity);

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
