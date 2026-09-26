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
 * 分组 6: NT 原生查询的**跨平台等价物**（C0/C1）
 *
 * ## 为什么需要
 *   `src/syscall.c`（A6 direct syscall）与 `src/antidebug.c` 用 NT 专有查询:
 *     · `NtQueryInformationProcess(ProcessDebugPort/DebugFlags/
 *        DebugObjectHandle)` —— 查调试器附加状态
 *     · `NtQuerySystemInformation(SystemKernelDebuggerInformation)`
 *
 *   这些 API 在 Linux 上**没有直接等价物**，但**用途可以映射**。
 *
 * ## 语义映射（**实测** `antidebug.c` 的实际用法）
 *   | NT 查询 | 判断条件 | Linux 对应 |
 *   |---------|---------|-----------|
 *   | `ProcessDebugPort` | `port != 0` | `/proc/self/status` **TracerPid != 0** |
 *   | `ProcessDebugFlags` | `flags != 1` | 同 TracerPid 派生 |
 *   | `ProcessDebugObjectHandle` | `hDbg != NULL` | 同 TracerPid |
 *   | `SystemKernelDebuggerInformation` | flags | `/proc/cmdline` 含 kgdb/kdb |
 *
 *   **关键**: Windows 上三个 PID 查询本质是查**同一个状态**的不同字段；
 *   Linux 用 **TracerPid 一个字段**表达同一件事。
 *   => **不是"降级"，是"归一化"** —— 且 Linux **另有** Windows 没有的
 *      维度（LD_PRELOAD / 可疑 .so / ptrace 试探）。
 *
 * ## 返回值契约
 *   统一用 `PROT_NT_*`，**不暴露 NTSTATUS**（那是 Windows 专有类型）:
 *     · `PROT_NT_OK`          = 0   —— 查询成功，buf 已填
 *     · `PROT_NT_UNSUPPORTED` = 1   —— **该平台不支持此查询**（调用方回退）
 *     · `PROT_NT_ERROR`       = 2   —— 查询出错
 *
 *   **为什么用 1 表示不支持**（而非负值）:
 *     原 `syscall.c` 用 `STATUS_UNSUCCESSFUL`（负值）触发回退；
 *     本接口显式区分"不支持"，调用方**更精确**。
 * ------------------------------------------------------------------ */

#define PROT_NT_OK          0
#define PROT_NT_UNSUPPORTED 1
#define PROT_NT_ERROR       2

/* 进程级查询（对应 NtQueryInformationProcess）。
 *
 * ## 参数
 *   cls    —— **平台无关的信息类**（见 `PROT_PIQ_*`）
 *   buf/len—— 输出缓冲
 *   ret    —— 可选，接收实际长度（可 NULL）
 *
 * ## 已支持的 cls（平台无关编号）
 *   `PROT_PIQ_DEBUG_PORT`          -> 输出 `uintptr_t`（0 = 无调试端口）
 *   `PROT_PIQ_DEBUG_FLAGS`         -> 输出 `uint32_t`（1 = 无调试）
 *   `PROT_PIQ_DEBUG_OBJECT_HANDLE` -> 输出 `void*`（NULL = 无）
 */
#define PROT_PIQ_DEBUG_PORT          1u
#define PROT_PIQ_DEBUG_FLAGS         2u
#define PROT_PIQ_DEBUG_OBJECT_HANDLE 3u

int prot_plat_nt_query_process(uint32_t cls, void* buf, size_t len,
                               size_t* ret);

/* 系统级查询（对应 NtQuerySystemInformation）。
 *   `PROT_SIQ_KERNEL_DEBUGGER` -> 输出 `uint32_t`（1 = 内核调试器已启用）
 */
#define PROT_SIQ_KERNEL_DEBUGGER 1u

int prot_plat_nt_query_system(uint32_t cls, void* buf, size_t len,
                              size_t* ret);

/* 1 = 至少一个 NT 等价查询可用（对应原 `prot_sys_available()`）。 */
uint32_t prot_plat_nt_query_available(void);

/* ------------------------------------------------------------------ *
 * 分组 7: 自身映像与安全读取（C2，`selfcrypt` 用）
 *
 * ## 为什么需要
 *   `src/selfcrypt.c` 用 4 类 Windows 专有依赖:
 *     · `GetModuleHandleW(NULL)`  —— 自身映像基址
 *     · `VirtualProtect`          —— 改页保护（**平台层已有**）
 *     · `FlushInstructionCache`   —— 指令缓存刷新
 *     · `__try/__except`          —— 安全读（CRC 遍历可能越界）
 * ------------------------------------------------------------------ */

/* 自身映像的**加载基址**。
 *
 * Windows: `GetModuleHandleW(NULL)`（HMODULE 即基址）
 * Linux  : 第一个 `PT_LOAD` 段的对齐基址（`dl_iterate_phdr` 或 auxv）
 *
 * 返回 NULL 表示失败。
 */
void* prot_plat_self_base(void);

/* 刷新指令缓存。
 *
 * Windows: `FlushInstructionCache`
 * Linux  : **x86 上无需操作**（指令/数据缓存一致），
 *          但 ARM 等需要 —— 故保留接口，Linux/x86 实现为空操作。
 *
 * **为什么要保留**: selfcrypt 解密**代码段**后必须让 CPU 看到新指令；
 *   x86 恰好自动一致，但**接口语义必须表达这个需求**（跨架构正确）。
 */
void prot_plat_flush_icache(void* addr, size_t len);

/* **安全读取**: 把 src 的 len 字节复制到 dst。
 *
 * ## 为什么需要（替代 SEH）
 *   `selfcrypt.c` 原用 `__try/__except` 包住 CRC 遍历 ——
 *   因为 dst 是"解密后的代码段"，理论上可能未映射。
 *
 * ## 跨平台实现
 *   **Windows**: `__try/__except`（SEH）—— 与原实现**语义等价**
 *   **Linux**:   `mincore()` 探测映射 -> 通过才读
 *                （**不改全局信号状态**，比 sigsetjmp 轻量）
 *
 * ## 返回
 *   `PROT_OK` —— 读取成功
 *   `PROT_ERR_INTEGRITY` —— 读取失败（未映射/不可读）
 */
prot_status prot_plat_safe_read(void* dst, const void* src, size_t len);

/* ------------------------------------------------------------------ *
 * 分组 8: 互斥锁（C2，`selfcrypt` 用）
 *
 * ## 为什么需要
 *   `selfcrypt.c` 用 Windows 的 `SRWLOCK` 串行化 enter/leave
 *   （多线程同时解密同一段会**数据竞争**）。
 *
 * ## 设计（**不透明类型**）
 *   用 `prot_plat_mutex` 不透明句柄，避免暴露平台类型:
 *     Windows: `SRWLOCK`（独占模式）
 *     Linux  : `pthread_mutex_t`
 *
 * ## API
 *   `prot_plat_mutex_init(m)`  —— 初始化（返回 PROT_OK）
 *   `plat_mutex_lock/unlock`   —— 加锁/解锁（**可重入? 否**）
 *
 * ## 诚实说明
 *   · Windows 的 `SRWLOCK` 是**读写锁**，本用途只用独占 -> `pthread_mutex` 等价
 *   · `prot_plat_mutex` 在头文件里是**不透明字节数组**（够大即可），
 *     避免 include 平台头
 * ------------------------------------------------------------------ */

#define PROT_PLAT_MUTEX_SIZE 64     /* 足够容纳 SRWLOCK(8) / pthread_mutex_t(40) */

typedef struct prot_plat_mutex {
    /* 对齐到指针宽度，保证可用作平台类型的容器 */
    unsigned long long _opaque[PROT_PLAT_MUTEX_SIZE / 8];
} prot_plat_mutex;

prot_status prot_plat_mutex_init(prot_plat_mutex* m);
void prot_plat_mutex_lock(prot_plat_mutex* m);
void prot_plat_mutex_unlock(prot_plat_mutex* m);

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
