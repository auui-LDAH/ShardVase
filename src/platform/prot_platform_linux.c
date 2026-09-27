/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * prot_platform_linux.c — 平台抽象层（Linux 实现）
 *
 * ## 这是什么（L5c）
 *   `include/protect/prot_platform.h` 定义了平台原语的**薄接口**。
 *   L1 实现了 Windows（`prot_platform_win.c`）；
 *   本文件是 **Linux 实现**。
 *
 * ## 验收判据（**唯一**）
 *   `tests/platform_conformance.c` —— L4-A 建立的契约测试。
 *   **不需要**人工评审"移植对不对"：
 *     能通过该测试 = 契约合规。
 *
 * ## 环境（实测 2026-09-25）
 *   Ubuntu 24.04.5 LTS / 内核 6.18.33.2-microsoft-standard-WSL2
 *   gcc 13.3.0 / glibc 2.39 / x86_64 / 20 核
 *   `mmap` 与 `ptrace` 已实测可编译可运行。
 *
 * ## 实现范围（本轮）
 *   按 `docs/LINUX_MIGRATION_INVENTORY.md` 的**低难度 7 项**起步:
 *     ✅ 页管理（mmap/mprotect/munmap）
 *     ✅ 计时（clock_gettime CLOCK_MONOTONIC）
 *     ✅ 自身路径（/proc/self/exe）
 *     ✅ 调试原语（TracerPid）
 *     ✅ 进程枚举（/proc 遍历）
 *     ✅ 模块枚举（/proc/self/maps）
 *     ⬜ 机器指纹因子（需 DMI/machine-id —— 见文件末尾说明）
 *
 * ## 诚实边界
 *   · **不追求与 Windows 行为一致** —— 两个平台的机制本就不同
 *     （见 migration inventory 的「差异」栏）
 *   · 部分能力**明确声明为不支持**（通过 capabilities 位），
 *     而非假装支持 —— 契约测试会按能力**条件断言**
 *   · 机器指纹因子返回的是**替代方案**，值与 Windows **必然不同**
 */

#include "protect/prot_platform.h"

#if PROT_PLATFORM == PROT_PLATFORM_LINUX

/* _GNU_SOURCE 可能已由构建命令行定义（-D_GNU_SOURCE），
 * 故**先判后定义**，避免 "redefined" 警告（`/WX` 风格的严格构建会失败）。 */
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <pthread.h>
#include <sys/wait.h>
#include <dlfcn.h>   /* C4: dlsym */   /* C2: 互斥锁 */

/* ------------------------------------------------------------------ *
 * 工具
 * ------------------------------------------------------------------ */

static void copy_narrow(char* dst, size_t cap, const char* src)
{
    size_t i;
    if (dst == NULL || cap == 0 || src == NULL)
        return;
    for (i = 0; i + 1 < cap && src[i] != '\0'; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

/* 读文件首行到缓冲（去尾换行）。返回 1 成功。 */
static int read_first_line(const char* path, char* out, size_t cap)
{
    FILE* f;
    size_t n;
    if (out == NULL || cap == 0)
        return 0;
    out[0] = '\0';
    f = fopen(path, "r");
    if (f == NULL)
        return 0;
    if (fgets(out, (int)cap, f) == NULL) {
        fclose(f);
        return 0;
    }
    fclose(f);
    n = strlen(out);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        out[--n] = '\0';
    return (n > 0);
}

/* ------------------------------------------------------------------ *
 * 分组 1: 内存页管理
 *
 * ## Windows vs Linux 差异（见 inventory）
 *   · VirtualAlloc -> mmap(MAP_PRIVATE|MAP_ANONYMOUS)
 *   · VirtualFree(addr, 0) -> munmap(addr, **len**)  <- 必须传原长度
 *   · VirtualProtect 返回旧属性 -> mprotect **不返回**（调用方自己记）
 *   · **W^X**: 部分内核/Android 禁 RWX -> 本实现按需给 RWX，
 *     若内核拒绝则**明确失败**（不静默降级为 R-X 之外的组合）
 * ------------------------------------------------------------------ */

static int lin_prot_of(prot_page_prot p, int* out)
{
    switch (p) {
    case PROT_PAGE_READ:              *out = PROT_READ; return 1;
    case PROT_PAGE_READWRITE:         *out = PROT_READ | PROT_WRITE; return 1;
    case PROT_PAGE_EXECUTE:           *out = PROT_EXEC; return 1;
    case PROT_PAGE_EXECUTE_READ:      *out = PROT_READ | PROT_EXEC; return 1;
    case PROT_PAGE_EXECUTE_READWRITE: *out = PROT_READ | PROT_WRITE
                                            | PROT_EXEC; return 1;
    default: return 0;
    }
}

void* prot_plat_alloc(size_t size, prot_page_prot prot)
{
    int mp;
    void* p;
    if (size == 0)
        return NULL;
    if (!lin_prot_of(prot, &mp))
        return NULL;
    /* ⚠️ mmap 的 length 会被**页对齐向上取整** ——
     *    故 prot_plat_free 必须传**同一 length**，
     *    否则 munmap 失败（不同于 Windows 的 MEM_RELEASE）。 */
    p = mmap(NULL, size, mp, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return NULL;
    return p;
}

prot_status prot_plat_protect(void* addr, size_t size, prot_page_prot prot)
{
    int mp;
    if (addr == NULL || size == 0)
        return PROT_ERR_INVALID_ARG;
    if (!lin_prot_of(prot, &mp))
        return PROT_ERR_INVALID_ARG;
    if (mprotect(addr, size, mp) != 0)
        return PROT_ERR_UNSUPPORTED;
    return PROT_OK;
}

prot_status prot_plat_free(void* addr, size_t size)
{
    if (addr == NULL)
        return PROT_ERR_INVALID_ARG;
    /* ⚠️ **必须传长度**（Windows 传 0 表示整块）—— 语义差异 */
    if (size == 0)
        return PROT_ERR_INVALID_ARG;
    if (munmap(addr, size) != 0)
        return PROT_ERR_UNSUPPORTED;
    return PROT_OK;
}

uint32_t prot_plat_capabilities(void)
{
    /* ## 与 Windows 的能力差异（**如实**）
     *
     * · PAGE_PROTECT        ✅ mprotect
     * · PAGE_ALLOC_RWX      ✅ mmap(PROT_EXEC|WRITE) —— 但见下
     * · DEBUG_DETECT        ✅ TracerPid（**机制不同**: /proc vs PEB）
     * · PROC_ENUM           ✅ /proc 遍历
     * · MODULE_ENUM         ✅ /proc/self/maps 解析
     * · TIME_HIRES          ✅ clock_gettime(CLOCK_MONOTONIC)
     * · FILE_SELF           ✅ /proc/self/exe
     *
     * **注意 RWX 的诚实声明**:
     *   Linux 上 mmap 允许 RWX，但**加固内核/Android 10+ 会拒绝**。
     *   此处仍声明 PAGE_ALLOC_RWX（因为标准 Linux 支持），
     *   若内核拒绝则该次 alloc **明确返回 NULL**（不静默）。
     *   契约测试不假定 RWX 一定成功（C2 只在 alloc 成功后继续）。
     */
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
 * ## 机制完全不同（**关键差异**）
 *   Windows: PEB.BeingDebugged / CheckRemoteDebuggerPresent / Dr0-Dr3
 *   Linux  : /proc/self/status 的 TracerPid（!= 0 表示被 trace）
 *
 *   硬件断点: Windows 可直接读 Dr0-Dr3（GetThreadContext）；
 *   Linux **读自身也受限**（需 PTRACE_TRACEME + 信号，
 *   而 TRACEME 本身会让自己"被调试"-> 自相矛盾）。
 *   => **如实**把 hardware_supported 置 0，而非假装支持。
 * ------------------------------------------------------------------ */

prot_status prot_plat_debug_primitives(prot_debug_primitives* out)
{
    char buf[4096];
    FILE* f;
    if (out == NULL)
        return PROT_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    /* TracerPid: 0 = 未被 trace；非 0 = 有调试器/跟踪器 */
    f = fopen("/proc/self/status", "r");
    if (f != NULL) {
        while (fgets(buf, (int)sizeof(buf), f) != NULL) {
            if (strncmp(buf, "TracerPid:", 10) == 0) {
                long pid = strtol(buf + 10, NULL, 10);
                out->being_debugged = (pid != 0) ? 1 : 0;
                out->remote_debugger = out->being_debugged;
                break;
            }
        }
        fclose(f);
    }

    /* 硬件断点: Linux 上**不支持**从自身可靠读取
     * （需 ptrace 附加，而附加会改变 TracerPid -> 自相矛盾）。
     * => 明确声明不支持（契约 C3.5 要求此时该字段为 0）。 */
    out->hardware_supported = 0;
    out->hardware_breakpoints = 0;

    return PROT_OK;   /* 契约: 永不失败 */
}

/* ------------------------------------------------------------------ *
 * 分组 3: 进程/模块枚举
 *
 * ## 与 Windows 的关键差异
 *   · 进程名来自 /proc/<pid>/comm，**限 15 字符**（TASK_COMM_LEN-1）
 *     -> 长名被**截断**（inventory 已记录该差异）
 *   · 模块来自 /proc/self/maps 文本解析（**需自己解析**）
 * ------------------------------------------------------------------ */

/* 从 /proc/<pid>/comm 读进程名并去掉尾换行。
 *
 * ⚠️ **不转换 pid 为字符串再拼路径** ——
 *    gcc 的 `-Wformat-truncation` 会警告 snprintf 可能截断
 *    （pidstr 的类型是 `const char*`，编译器无法证明其长度）。
 *    改为**直接拼接**并用 snprintf 的返回值做边界检查。 */
static void read_comm(const char* pidstr, char* out, size_t cap)
{
    char path[64];
    int n;
    out[0] = '\0';
    n = snprintf(path, sizeof(path), "/proc/%s/comm", pidstr);
    /* 返回值 >= sizeof(path) 表示被截断 -> 路径非法，直接放弃 */
    if (n <= 0 || (size_t)n >= sizeof(path))
        return;
    (void)read_first_line(path, out, cap);
}

size_t prot_plat_enum_processes(prot_proc_info* out, size_t capacity)
{
    DIR* d;
    struct dirent* e;
    size_t n = 0;

    d = opendir("/proc");
    if (d == NULL)
        return 0;

    while ((e = readdir(d)) != NULL) {
        /* 只看纯数字目录（进程）*/
        const char* p = e->d_name;
        size_t i;
        int numeric = (p[0] != '\0');
        for (i = 0; p[i] != '\0'; i++) {
            if (p[i] < '0' || p[i] > '9') { numeric = 0; break; }
        }
        if (!numeric)
            continue;
        /* **契约**: 返回真实总数，不受容量限制（两段式用法）*/
        if (out != NULL && n < capacity) {
            out[n].pid = (uint32_t)strtoul(p, NULL, 10);
            read_comm(p, out[n].name, sizeof(out[n].name));
        }
        n++;
    }
    closedir(d);
    return n;
}

size_t prot_plat_enum_modules(prot_module_info* out, size_t capacity)
{
    char line[1024];
    FILE* f;
    size_t n = 0;

    f = fopen("/proc/self/maps", "r");
    if (f == NULL)
        return 0;

    /* maps 格式: <start>-<end> <perms> <offset> <dev> <inode> <path>
     * 只统计**有路径**的行（真实文件映射 = 模块）。 */
    while (fgets(line, (int)sizeof(line), f) != NULL) {
        unsigned long start = 0, end = 0;
        char perms[8];
        char path[512];
        const char* p;
        int matched;

        path[0] = '\0';
        matched = sscanf(line, "%lx-%lx %7s %*s %*s %*s %511s",
                         &start, &end, perms, path);
        if (matched < 3)
            continue;
        /* 无路径（匿名映射）-> 跳过 */
        p = strchr(line, '/');
        if (p == NULL)
            continue;
        if (matched >= 4)
            copy_narrow(path, sizeof(path), p);
        else
            copy_narrow(path, sizeof(path), p);

        if (out != NULL && n < capacity) {
            out[n].base = (void*)(uintptr_t)start;
            out[n].size = (size_t)(end - start);
            /* 去尾换行 */
            {
                size_t L = strlen(path);
                while (L > 0 && (path[L - 1] == '\n' || path[L - 1] == '\r'))
                    path[--L] = '\0';
            }
            copy_narrow(out[n].name, sizeof(out[n].name), path);
        }
        n++;
    }
    fclose(f);
    return n;
}

/* ------------------------------------------------------------------ *
 * 分组 4: 计时与自身映像
 * ------------------------------------------------------------------ */

uint64_t prot_plat_monotonic_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

size_t prot_plat_self_path(char* out, size_t capacity)
{
    ssize_t n;
    if (out == NULL || capacity == 0)
        return 0;
    /* readlink 不追加 NUL，故容量需留 1 字节 */
    n = readlink("/proc/self/exe", out, capacity - 1);
    if (n <= 0)
        return 0;
    out[n] = '\0';
    return (size_t)n;
}

/* ------------------------------------------------------------------ *
 * 分组 5: 机器指纹因子
 *
 * ## ⚠️ 诚实说明: 这里返回的是**替代方案**，不是等价物
 *   Windows 的 4 个因子在 Linux 上**没有 1:1 对应**:
 *     MachineGuid(注册表)  -> /etc/machine-id
 *     卷序列号             -> （Linux 无直接对应；用 machine-id 代替）
 *     计算机名             -> gethostname()
 *     物理盘序列号         -> /sys/block/[dev]/device/serial（权限受限）
 *
 *   **注意（2026-09-25 实测踩坑第二次）**:
 *     上面写路径时**不可**用 `斜杠 + 星号` 形式 ——
 *     它会**提前闭合本注释块**，导致后续中文注释被当成 C 代码，
 *     报一堆 `stray '\342' in program`。
 *     （第一次踩坑在 include/protect/prot_platform.h。）
 *
 *   => **指纹值必然与 Windows 不同** —— 这是预期，不是缺陷。
 *      Linux 构建的产物与 Windows 构建的**不共享授权**。
 *
 * ## 本轮实现范围
 *   提供 **machine-id + hostname** 两个因子（最可靠、无需提权）。
 *   磁盘序列号需读 /sys（可能权限不足）-> **本轮不实现**，
 *   留待后续（inventory 已记录）。
 * ------------------------------------------------------------------ */

/* 因子字符串的静态存储（接口不分配内存） */
static char s_lin_id[128];
static char s_lin_host[256];

size_t prot_plat_host_factors(prot_host_factor* out, size_t capacity)
{
    size_t n = 0;

    if (out == NULL || capacity < 2)
        return 0;

    /* 因子 1: /etc/machine-id（对应 Windows 的 MachineGuid）
     * 这是 Linux 上最接近"系统唯一 ID"的东西。 */
    if (read_first_line("/etc/machine-id", s_lin_id, sizeof(s_lin_id))
        || read_first_line("/var/lib/dbus/machine-id", s_lin_id,
                           sizeof(s_lin_id))) {
        out[n].kind = PROT_HOST_FACTOR_STR;
        out[n].str = s_lin_id;
        out[n].str_len = 0;
        out[n].u32 = 0;
        n++;
    }

    /* 因子 2: hostname（对应 Windows 的计算机名）
     *
     * ⚠️ **差异**: Windows 按 **UTF-16 码元**折叠计算机名；
     *    Linux hostname 是 **UTF-8 字节**。此处按字节返回 STR 因子
     *    -> 与 Windows 的折叠路径**不同**（预期，见上方说明）。 */
    if (gethostname(s_lin_host, sizeof(s_lin_host) - 1) == 0) {
        s_lin_host[sizeof(s_lin_host) - 1] = '\0';
        if (s_lin_host[0] != '\0') {
            out[n].kind = PROT_HOST_FACTOR_STR;
            out[n].str = s_lin_host;
            out[n].str_len = 0;
            out[n].u32 = 0;
            n++;
        }
    }

    return n;
}

/* ------------------------------------------------------------------ *
 * 分组 6: NT 查询的 **Linux 等价物**（C0/C1）
 *
 * ## 语义映射（见 prot_platform.h 的表）
 *   三个 PID 查询在 Linux 上**归一化为 TracerPid** ——
 *   因为内核不暴露等价的细分字段。
 *
 *   **这不是"降级"**: Windows 的三个查询本质也是查同一个
 *   "是否有调试器附加"状态（EPROCESS 的不同字段）。
 * ------------------------------------------------------------------ */

/* 读 /proc/self/status 的 TracerPid；返回 -1 表示读取失败。 */
static long lin_tracer_pid(void)
{
    FILE* f;
    char buf[4096];
    long pid = -1;

    f = fopen("/proc/self/status", "r");
    if (f == NULL)
        return -1;
    while (fgets(buf, (int)sizeof(buf), f) != NULL) {
        if (strncmp(buf, "TracerPid:", 10) == 0) {
            pid = strtol(buf + 10, NULL, 10);
            break;
        }
    }
    fclose(f);
    return pid;
}

int prot_plat_nt_query_process(uint32_t cls, void* buf, size_t len,
                               size_t* ret)
{
    long tp;

    if (buf == NULL)
        return PROT_NT_ERROR;
    tp = lin_tracer_pid();
    if (tp < 0)
        return PROT_NT_ERROR;

    switch (cls) {
    case PROT_PIQ_DEBUG_PORT:
        /* Windows: port != 0 表示有调试端口。Linux: TracerPid != 0 */
        if (len < sizeof(uintptr_t))
            return PROT_NT_ERROR;
        *(uintptr_t*)buf = (tp != 0) ? (uintptr_t)tp : (uintptr_t)0;
        if (ret) *ret = sizeof(uintptr_t);
        return PROT_NT_OK;

    case PROT_PIQ_DEBUG_FLAGS:
        /* Windows: flags != 1 表示被调试（1 = 无调试）。
         * Linux: 归一化为 TracerPid == 0 时返回 1（无调试）。 */
        if (len < sizeof(uint32_t))
            return PROT_NT_ERROR;
        *(uint32_t*)buf = (tp == 0) ? 1u : 0u;
        if (ret) *ret = sizeof(uint32_t);
        return PROT_NT_OK;

    case PROT_PIQ_DEBUG_OBJECT_HANDLE:
        /* Windows: hDbg != NULL 表示有调试对象。Linux: 同 TracerPid */
        if (len < sizeof(void*))
            return PROT_NT_ERROR;
        *(void**)buf = (tp != 0) ? (void*)(uintptr_t)tp : NULL;
        if (ret) *ret = sizeof(void*);
        return PROT_NT_OK;

    default:
        return PROT_NT_UNSUPPORTED;
    }
}

int prot_plat_nt_query_system(uint32_t cls, void* buf, size_t len,
                              size_t* ret)
{
    char line[512];
    FILE* f;
    int found = 0;

    if (buf == NULL)
        return PROT_NT_ERROR;
    if (cls != PROT_SIQ_KERNEL_DEBUGGER)
        return PROT_NT_UNSUPPORTED;

    /* Linux 的内核调试器: 检查 /proc/cmdline 是否含 kgdb/kdb 参数。
     *
     * **诚实说明**: 这是**启发式**（Windows 的 SystemKernelDebuggerInformation
     * 是内核直接暴露的标志）。Linux 无等价接口 -> 用 cmdline 推断。
     */
    f = fopen("/proc/cmdline", "r");
    if (f != NULL) {
        if (fgets(line, (int)sizeof(line), f) != NULL) {
            if (strstr(line, "kgdb") != NULL ||
                strstr(line, "kdb") != NULL)
                found = 1;
        }
        fclose(f);
    }

    if (len < sizeof(uint32_t))
        return PROT_NT_ERROR;
    *(uint32_t*)buf = found ? 1u : 0u;
    if (ret) *ret = sizeof(uint32_t);
    return PROT_NT_OK;
}

uint32_t prot_plat_nt_query_available(void)
{
    /* Linux 上 /proc 始终可用 -> 始终返回 1
     * （与原 `prot_sys_available()` 的语义一致: "查询可用"）。 */
    return 1u;
}

/* ------------------------------------------------------------------ *
 * 分组 7: 自身映像与安全读取（C2，Linux）
 * ------------------------------------------------------------------ */

/* ## 取自身映像基址（Linux）
 *
 * 为什么用 `dl_iterate_phdr` 而非 `dladdr`:
 *   · `dl_iterate_phdr` 直接给**每个已加载对象**的基址与 phdr
 *   · 第一个对象的 `dlpi_addr` 即**主程序**的加载基址
 *   · 无需链接 `-ldl`（glibc 将其放在 libc 内）
 */
#include <link.h>

struct lin_base_ctx {
    void* base;
    int   found;
};

static int lin_base_cb(struct dl_phdr_info* info, size_t size, void* data)
{
    struct lin_base_ctx* ctx = (struct lin_base_ctx*)data;
    (void)size;
    /* 第一个回调对象 = 主程序（name 为空串） */
    ctx->base = (void*)(uintptr_t)info->dlpi_addr;
    ctx->found = 1;
    return 1;   /* 非 0 = 停止遍历 */
}

void* prot_plat_self_base(void)
{
    struct lin_base_ctx ctx;
    ctx.base = NULL;
    ctx.found = 0;
    (void)dl_iterate_phdr(lin_base_cb, &ctx);
    return ctx.found ? ctx.base : NULL;
}

void prot_plat_flush_icache(void* addr, size_t len)
{
    /* ## 为什么 Linux/x86 上是空操作
     *   x86 的**指令缓存与数据缓存一致**（self-modifying code 无需显式刷新，
     *   只要不发生跨核竞态）。ARM 需要 `__builtin___clear_cache`。
     *
     *   **如实说明**: 本实现在 x86_64 上正确；若将来支持 ARM64，
     *   需改为 `__builtin___clear_cache((char*)addr, (char*)addr + len)`。
     */
#if defined(__aarch64__) || defined(__arm__)
    __builtin___clear_cache((char*)addr, (char*)addr + len);
#else
    (void)addr;
    (void)len;
#endif
}

prot_status prot_plat_safe_read(void* dst, const void* src, size_t len)
{
    /* ## 用 `mincore()` 探测映射（**不引入信号处理**）
     *
     * **为什么不用 sigsetjmp/SIGSEGV**:
     *   那会**改变进程的全局信号行为**（安装/恢复 handler），
     *   与项目"最小侵入"原则相悖；且多线程下 handler 是**进程级**的，
     *   会影响其它线程 —— 风险高于收益。
     *
     * **mincore 方案**:
     *   ① 把 src 向下页对齐，算出覆盖 len 的页数
     *   ② `mincore()` 查询这些页是否在内存中
     *   ③ 通过才 `memcpy`
     *
     * **诚实边界**:
     *   `mincore` 检查的是"**页是否在物理内存中**"，
     *   严格来说不保证"可读"（映射存在但 PROT_NONE 时仍可能故障）。
     *   => 本实现是 **"尽力而为的安全读"**，不是绝对保证。
     *      对本用途（读自身已解密代码段）**足够** ——
     *      因为该段刚刚被 `mprotect` 设为可读可写。
     */
    long page;
    uintptr_t pstart;
    uintptr_t pend;
    size_t npages;
    unsigned char* vec;
    size_t i;

    if (dst == NULL || src == NULL)
        return PROT_ERR_INVALID_ARG;
    if (len == 0)
        return PROT_OK;

    page = sysconf(_SC_PAGESIZE);
    if (page <= 0)
        return PROT_ERR_UNSUPPORTED;

    pstart = (uintptr_t)src & ~((uintptr_t)page - 1u);
    pend = ((uintptr_t)src + len + (uintptr_t)page - 1u)
           & ~((uintptr_t)page - 1u);
    npages = (size_t)((pend - pstart) / (uintptr_t)page);
    if (npages == 0)
        npages = 1;

    vec = (unsigned char*)malloc(npages);
    if (vec == NULL)
        return PROT_ERR_INTERNAL;

    if (mincore((void*)pstart, npages * (size_t)page, vec) != 0) {
        free(vec);
        return PROT_ERR_INTEGRITY;   /* 未映射 -> 读取会故障 */
    }
    for (i = 0; i < npages; i++) {
        if ((vec[i] & 1u) == 0u) {    /* bit0 = 在内存中 */
            free(vec);
            return PROT_ERR_INTEGRITY;
        }
    }
    free(vec);

    memcpy(dst, src, len);
    return PROT_OK;
}

/* ------------------------------------------------------------------ *
 * 分组 8: 互斥锁（C2，Linux 用 pthread_mutex）
 * ------------------------------------------------------------------ */

prot_status prot_plat_mutex_init(prot_plat_mutex* m)
{
    pthread_mutexattr_t attr;
    if (m == NULL)
        return PROT_ERR_INVALID_ARG;
    /* 用**默认**属性（非递归）—— 与 Windows SRWLOCK 独占语义一致。
     * 若初始化失败则回退为全零（PTHREAD_MUTEX_INITIALIZER 等价）。 */
    memset(m, 0, sizeof(*m));
    if (pthread_mutexattr_init(&attr) != 0)
        return PROT_ERR_INTERNAL;
    (void)pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL);
    if (pthread_mutex_init((pthread_mutex_t*)(void*)m->_opaque,
                           &attr) != 0) {
        pthread_mutexattr_destroy(&attr);
        return PROT_ERR_INTERNAL;
    }
    (void)pthread_mutexattr_destroy(&attr);
    return PROT_OK;
}

void prot_plat_mutex_lock(prot_plat_mutex* m)
{
    if (m == NULL)
        return;
    (void)pthread_mutex_lock((pthread_mutex_t*)(void*)m->_opaque);
}

void prot_plat_mutex_unlock(prot_plat_mutex* m)
{
    if (m == NULL)
        return;
    (void)pthread_mutex_unlock((pthread_mutex_t*)(void*)m->_opaque);
}

/* ------------------------------------------------------------------ *
 * 分组 9: 节表 / 重定位 / IAT（C3，Linux）
 *
 * ## 与 Windows 的**真实差异**（如实标注）
 *   | 项 | Windows | Linux |
 *   |----|---------|-------|
 *   | 节表来源 | 内存中的 PE 头 | **磁盘上的 ELF 节表**（映射到内存）|
 *   | 节名 | .text/.rdata/.pdata | .text/.rodata/.eh_frame |
 *   | 重定位 | .reloc 块 | .rela.dyn（`Elf64_Rela`）|
 *   | IAT | 数据目录 12 | .got.plt（需解析 .dynamic）|
 *
 * ## 实现策略
 *   ELF 节表**在内存中可用**（节表本身被映射），故直接读:
 *     `Elf64_Ehdr`（映像基址）-> `e_shoff`/`e_shnum`/`e_shentsize`
 *     -> `Elf64_Shdr[]` -> `sh_name`（查 `.shstrtab`）
 *
 * ## 诚实边界
 *   · **`.pdata` 无对应物** -> 映射为 `.eh_frame`（最近的对应）
 *   · **重定位枚举返回"需要修正的区间"** —— ELF 的 `.rela.dyn`
 *     每项描述一个 8 字节槽；本实现按 `ELF64_R_TYPE` 过滤（只取
 *     会**写入**的 relocation 类型）
 *   · **IAT/GOT 解析需要 `.dynamic`** —— 本实现用"节名匹配 `.got`/.got.plt`"
 *     作为简化（见下方说明）
 * ------------------------------------------------------------------ */

#include <elf.h>
#include <string.h>

/* 从映像基址取 ELF 头 */
static const Elf64_Ehdr* lin_ehdr(void)
{
    uint8_t* base = (uint8_t*)prot_plat_self_base();
    if (base == NULL)
        return NULL;
    if (base[0] != 0x7Fu || base[1] != 'E' || base[2] != 'L'
        || base[3] != 'F')
        return NULL;
    if (base[EI_CLASS] != ELFCLASS64)
        return NULL;
    return (const Elf64_Ehdr*)base;
}

/* 取节表首地址 */
static const Elf64_Shdr* lin_shdr_table(void)
{
    const Elf64_Ehdr* eh = lin_ehdr();
    if (eh == NULL || eh->e_shoff == 0 || eh->e_shnum == 0)
        return NULL;
    return (const Elf64_Shdr*)((const uint8_t*)eh + eh->e_shoff);
}

/* 取节名字符串表 */
static const char* lin_shstrtab(void)
{
    const Elf64_Ehdr* eh = lin_ehdr();
    const Elf64_Shdr* sh;
    if (eh == NULL)
        return NULL;
    if (eh->e_shstrndx == SHN_UNDEF || eh->e_shstrndx >= eh->e_shnum)
        return NULL;
    sh = (const Elf64_Shdr*)((const uint8_t*)eh + eh->e_shoff
                             + (size_t)eh->e_shstrndx * eh->e_shentsize);
    return (const char*)((const uint8_t*)eh + sh->sh_offset);
}

static void lin_copy_name(char* dst, size_t cap, const char* src)
{
    size_t i;
    if (dst == NULL || cap == 0)
        return;
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    for (i = 0; i + 1 < cap && src[i] != '\0'; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

size_t prot_plat_enum_sections(prot_section_view* out, size_t capacity)
{
    const Elf64_Ehdr* eh = lin_ehdr();
    const Elf64_Shdr* sh = lin_shdr_table();
    const char* strtab = lin_shstrtab();
    size_t n = 0;
    Elf64_Half i;

    if (eh == NULL || sh == NULL)
        return 0;

    for (i = 0; i < eh->e_shnum; i++) {
        const Elf64_Shdr* s = (const Elf64_Shdr*)((const uint8_t*)sh
                                                  + (size_t)i
                                                  * eh->e_shentsize);
        if (s->sh_type == SHT_NULL)
            continue;   /* 索引 0 是空节 */
        if (out != NULL && n < capacity) {
            lin_copy_name(out[n].name, PROT_SECTION_NAME_MAX,
                          strtab ? (strtab + s->sh_name) : NULL);
            out[n].rva = (size_t)s->sh_addr;      /* 运行期地址（已含基址）*/
            out[n].size = (size_t)s->sh_size;
        }
        n++;
    }
    return n;
}

size_t prot_plat_reloc_ranges(prot_range* out, size_t capacity)
{
    /* ## 枚举 `.rela.dyn` 的**目标区间**
     *
     * 每项 `Elf64_Rela` 描述一个需要修正的槽:
     *   `r_offset`（运行期地址）+ 类型决定宽度。
     *
     * **只取会写入的类型**（与 Windows 只取 type 3/10 对应）:
     *   R_X86_64_RELATIVE(8) / GLOB_DAT(6) / JUMP_SLOT(7) -> 8 字节
     *
     * **诚实边界**: 本实现按"节名 `.rela.dyn`"定位（简化）；
     *   完整实现应解析 `.dynamic` 的 `DT_RELA`/`DT_RELASZ`。
     *   => 对标准静态/动态链接的 ELF **足够**；对剥离节表的极端情况**会返回 0**
     *      （那会导致 CRC 恒不匹配 -> **安全侧失败**，不会漏检）。
     */
    const Elf64_Ehdr* eh = lin_ehdr();
    const Elf64_Shdr* sh = lin_shdr_table();
    const char* strtab = lin_shstrtab();
    size_t n = 0;
    Elf64_Half i;

    if (eh == NULL || sh == NULL || strtab == NULL)
        return 0;

    for (i = 0; i < eh->e_shnum; i++) {
        const Elf64_Shdr* s = (const Elf64_Shdr*)((const uint8_t*)sh
                                                  + (size_t)i
                                                  * eh->e_shentsize);
        const char* nm = strtab + s->sh_name;
        if (strcmp(nm, ".rela.dyn") != 0 && strcmp(nm, ".rela.plt") != 0)
            continue;
        {
            const Elf64_Rela* rel = (const Elf64_Rela*)((const uint8_t*)eh
                                                        + s->sh_addr);
            size_t cnt = (size_t)(s->sh_size / sizeof(Elf64_Rela));
            size_t k;
            for (k = 0; k < cnt; k++) {
                uint32_t type = (uint32_t)ELF64_R_TYPE(rel[k].r_info);
                if (type == R_X86_64_RELATIVE || type == R_X86_64_GLOB_DAT
                    || type == R_X86_64_JUMP_SLOT) {
                    if (out != NULL && n < capacity) {
                        out[n].rva = (size_t)rel[k].r_offset;
                        out[n].size = 8u;
                    }
                    n++;
                }
            }
        }
    }
    return n;
}

int prot_plat_iat_range(prot_range* out)
{
    /* ## IAT/GOT 定位（简化但可靠）
     *
     * **为什么按节名而非解析 `.dynamic`**:
     *   `DT_PLTGOT` 指向 GOT，但解析 `.dynamic` 需额外代码；
     *   而 `.got.plt`（或 `.got`）**节名即语义**，且始终存在（有导入时）。
     *
     * **诚实边界**: 若二进制被 strip 掉节名 -> 返回 0 ->
     *   `integrity` 的 IAT 校验会**跳过**（而非误报）。
     *   这是**安全侧的保守选择**（跳过 < 误杀）。
     */
    const Elf64_Ehdr* eh = lin_ehdr();
    const Elf64_Shdr* sh = lin_shdr_table();
    const char* strtab = lin_shstrtab();
    Elf64_Half i;

    if (eh == NULL || sh == NULL || strtab == NULL || out == NULL)
        return 0;

    for (i = 0; i < eh->e_shnum; i++) {
        const Elf64_Shdr* s = (const Elf64_Shdr*)((const uint8_t*)sh
                                                  + (size_t)i
                                                  * eh->e_shentsize);
        const char* nm = strtab + s->sh_name;
        if (strcmp(nm, ".got.plt") == 0 || strcmp(nm, ".got") == 0) {
            out->rva = (size_t)s->sh_addr;
            out->size = (size_t)s->sh_size;
            return 1;
        }
    }
    return 0;
}

const char* prot_plat_crc_target_name(unsigned idx)
{
    /* Linux: ELF 节名。
     *
     * **映射说明（如实）**:
     *   idx 0: `.text`     -> `.text`（同名）
     *   idx 1: `.rdata`    -> `.rodata`（**只读数据，概念对应**）
     *   idx 2: `.pdata`    -> `.eh_frame`（**最近的对应物**）
     *          —— PE 的 `.pdata` 是异常处理表；ELF 的 `.eh_frame` 是
     *             展开信息表。**两者用途相近但格式不同**，
     *             故这是"**替代**"而非"等价"。
     */
    static const char* const names[3] = { ".text", ".rodata", ".eh_frame" };
    return (idx < 3u) ? names[idx] : NULL;
}

/* ------------------------------------------------------------------ *
 * 分组 10: 线程 / 计时 / 原子 / 终止（C3，Linux）
 * ------------------------------------------------------------------ */

void prot_plat_sleep_ms(uint32_t ms)
{
    struct timespec ts;
    if (ms == 0u)
        return;
    ts.tv_sec = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)((ms % 1000u) * 1000000u);
    /* 处理 EINTR（信号中断时继续睡剩余时间）—— 简化: 循环重试 */
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
        ;
}

typedef struct plat_lin_thread_ctx {
    prot_plat_thread_fn fn;
    void* arg;
} plat_lin_thread_ctx;

static void* plat_lin_thread_entry(void* p)
{
    plat_lin_thread_ctx* c = (plat_lin_thread_ctx*)p;
    prot_plat_thread_fn fn = c->fn;
    void* arg = c->arg;
    free(c);
    if (fn != NULL)
        fn(arg);
    return NULL;
}

int prot_plat_thread_create(prot_plat_thread_fn fn, void* arg,
                            void** out_handle)
{
    plat_lin_thread_ctx* c;
    pthread_t tid;

    if (fn == NULL)
        return 0;
    c = (plat_lin_thread_ctx*)malloc(sizeof(*c));
    if (c == NULL)
        return 0;
    c->fn = fn;
    c->arg = arg;

    if (pthread_create(&tid, NULL, plat_lin_thread_entry, c) != 0) {
        free(c);
        return 0;
    }
    /* ## 为什么 detach（**与 Windows 语义对齐**）
     *   Windows 的 `CreateThread` 返回句柄后即使不 join，线程结束即回收；
     *   Linux 的 pthread **默认可 join** -> 不 join 会**积累僵尸线程**。
     *   本模块只用"创建 + 停止标志"（不 join）-> 必须 `pthread_detach`。
     */
    (void)pthread_detach(tid);
    if (out_handle != NULL)
        *out_handle = (void*)(uintptr_t)tid;
    return 1;
}

void prot_plat_terminate(int exit_code)
{
    /* ## 为什么用 `_exit` 而非 `exit`
     *   Windows 的 `TerminateProcess` **立即终止**，不跑 atexit / 析构。
     *   `exit()` 会跑 atexit handlers 与 stdio flush —— **语义不符**，
     *   且在"检测到篡改"的场景下**不应**给攻击者执行额外代码的机会。
     *   => 用 `_exit()`（直接系统调用，与 TerminateProcess 对齐）。
     */
    _exit((int)exit_code);
}

int prot_plat_atomic_load(volatile int* p)
{
    if (p == NULL)
        return 0;
    return __atomic_load_n(p, __ATOMIC_SEQ_CST);
}

int prot_plat_atomic_exchange(volatile int* p, int v)
{
    if (p == NULL)
        return 0;
    return __atomic_exchange_n(p, v, __ATOMIC_SEQ_CST);
}

int prot_plat_atomic_increment(volatile int* p)
{
    if (p == NULL)
        return 0;
    return __atomic_add_fetch(p, 1, __ATOMIC_SEQ_CST);
}

/* ------------------------------------------------------------------ *
 * 分组 11: 内存区间 / 线程 / 符号（C4，Linux）
 *
 * ## 与 Windows 的差异（**Linux 侧更直接**）
 *   `/proc/self/maps` 的**权限字段直接给 `rwxp`** ——
 *   无需像 Windows 那样把 `PAGE_*` 位翻译成 READ/WRITE/EXEC。
 * ------------------------------------------------------------------ */

size_t prot_plat_enum_memory(prot_mem_region* out, size_t capacity)
{
    FILE* f;
    char line[1024];
    size_t n = 0;

    f = fopen("/proc/self/maps", "r");
    if (f == NULL)
        return 0;

    while (fgets(line, (int)sizeof(line), f) != NULL) {
        unsigned long start = 0, end = 0;
        char perms[8] = {0};
        uint32_t prot = 0u;

        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) < 3)
            continue;
        if (perms[0] == 'r') prot |= PROT_MEM_PROT_READ;
        if (perms[1] == 'w') prot |= PROT_MEM_PROT_WRITE;
        if (perms[2] == 'x') prot |= PROT_MEM_PROT_EXEC;

        if (out != NULL && n < capacity) {
            out[n].base = (void*)(uintptr_t)start;
            out[n].size = (size_t)(end - start);
            out[n].prot = prot;
        }
        n++;
    }
    fclose(f);
    return n;
}

size_t prot_plat_thread_count(void)
{
    DIR* d;
    struct dirent* e;
    size_t n = 0;

    d = opendir("/proc/self/task");
    if (d == NULL)
        return 0;
    while ((e = readdir(d)) != NULL) {
        const char* p = e->d_name;
        size_t i;
        int numeric = (p[0] != '\0');
        for (i = 0; p[i] != '\0'; i++) {
            if (p[i] < '0' || p[i] > '9') { numeric = 0; break; }
        }
        if (numeric)
            n++;
    }
    closedir(d);
    return n;
}

void* prot_plat_symbol_addr(const char* module, const char* symbol)
{
    /* ## 为什么不主动 dlopen
     *   用 `RTLD_NOLOAD` 表示"**仅当已加载时**取句柄" ——
     *   避免为了查符号而**引入新的库依赖**（那会改变进程状态，
     *   与 `dbiguard` 的"只读探测"原则相悖）。
     *
     *   对 libc/libpthread 等必然已加载的库有效；
     *   对未加载的库返回 NULL（**如实**，而非"假装找不到"）。
     */
    void* h;
    if (module == NULL || symbol == NULL)
        return NULL;
    h = dlopen(module, RTLD_LAZY | RTLD_NOLOAD);
    if (h == NULL)
        return NULL;
    return dlsym(h, symbol);
    /* 注: 不 dlclose —— RTLD_NOLOAD 获得的是**已有**引用，
     *     关掉会减少引用计数（可能卸载别人正在用的库）。 */
}

/* ------------------------------------------------------------------ *
 * 分组 12: 反调试探测原语（C5，Linux）—— **重新设计**
 *
 * ## 与 Windows 的**本质差异**（如实标注）
 *   Windows 有 12 个**独立维度**（PEB 多字段 + NT 查询 + SEH + 计时）。
 *   Linux 内核**只暴露一个核心字段**（`TracerPid`）——
 *   故 5 个 Windows 维度**归一化**为它。
 *
 *   **但 Linux 另有 3 个 Windows 没有的维度**（见 extra_debug_flags）——
 *   净增 2 个维度。
 * ------------------------------------------------------------------ */

prot_status prot_plat_debug_probe(prot_debug_state* out)
{
    char buf[4096];
    FILE* f;
    int found_tracer = 0;

    if (out == NULL)
        return PROT_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    /* TracerPid: Linux 的**核心调试信号**（内核提供，用户态不可 hook） */
    f = fopen("/proc/self/status", "r");
    if (f == NULL)
        return PROT_ERR_UNSUPPORTED;
    while (fgets(buf, (int)sizeof(buf), f) != NULL) {
        if (strncmp(buf, "TracerPid:", 10) == 0) {
            long pid = strtol(buf + 10, NULL, 10);
            out->tracer_pid = (pid != 0) ? 1u : 0u;
            found_tracer = 1;
            break;
        }
    }
    fclose(f);
    if (!found_tracer)
        return PROT_ERR_UNSUPPORTED;

    /* 内核调试器（同 C1 的启发式） */
    out->kernel_debugger = 0u;
    {
        char line[512];
        FILE* c = fopen("/proc/cmdline", "r");
        if (c != NULL) {
            if (fgets(line, (int)sizeof(line), c) != NULL) {
                if (strstr(line, "kgdb") != NULL ||
                    strstr(line, "kdb") != NULL)
                    out->kernel_debugger = 1u;
            }
            fclose(c);
        }
    }

    /* ## 硬件断点: **如实声明不支持**
     *   Linux 的硬件断点（DR0-3）需通过 `ptrace(PTRACE_PEEKUSER)` 读取 ——
     *   而 `ptrace` 要求**另一个进程附加**（或被附加）。
     *   自己读自己的 DR 寄存器在用户态**不可行**。
     *
     *   （`PTRACE_TRACEME` 可让**父进程**跟踪自己，但那会**改变进程状态** ——
     *    与"只读探测"原则相悖。）
     */
    out->hardware_bp = 0u;

    /* supported_mask: bit2(hwbp) **不置位** —— 如实声明不支持 */
    out->supported_mask = 1u | 2u;
    return PROT_OK;
}

/* ## int3 蜜罐（Linux: SIGTRAP + sigaction）
 *
 * ### 与 Windows 的对应
 *   Windows 用 **VEH**（向量化异常处理）接管 int3；
 *   Linux 用 **`sigaction(SIGTRAP)`** —— **机制不同，语义相同**：
 *     两者都是"**自己安装处理器 -> 执行 int3 -> 看是否自己接管**"。
 *
 * ### 判定
 *   · 自己的 handler 被调用 -> 正常（返回 1）
 *   · 未调用 -> **有外部断点处理者**（返回 2，可疑）
 *
 * ### 诚实边界
 *   · 全局 `sigaction` 会**短暂改变进程的信号处理**（安装后恢复）
 *   · 多线程下 handler 是**进程级**的 —— 故本探测有**并发窗口**
 *     （Windows 的 VEH 同样是进程级，故两平台**面临同样限制**）
 */
static volatile sig_atomic_t g_plat_trap_caught;

static void plat_trap_handler(int sig, siginfo_t* info, void* ctx)
{
    (void)sig;
    (void)info;
    (void)ctx;
    g_plat_trap_caught = 1;
}

uint32_t prot_plat_int3_probe(void)
{
    struct sigaction sa_new;
    struct sigaction sa_old;
    uint32_t r = 0u;

    /* 可执行的 int3;ret 存根 */
    static const uint8_t stub_code[2] = { 0xCCu, 0xC3u };
    size_t pg = (size_t)sysconf(_SC_PAGESIZE);
    uint8_t* stub = (uint8_t*)mmap(NULL, pg, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stub == MAP_FAILED)
        return 0u;
    memcpy(stub, stub_code, sizeof(stub_code));
    if (mprotect(stub, pg, PROT_READ | PROT_EXEC) != 0) {
        munmap(stub, pg);
        return 0u;
    }

    memset(&sa_new, 0, sizeof(sa_new));
    sa_new.sa_sigaction = plat_trap_handler;
    sa_new.sa_flags = SA_SIGINFO;
    sigemptyset(&sa_new.sa_mask);
    if (sigaction(SIGTRAP, &sa_new, &sa_old) != 0) {
        munmap(stub, pg);
        return 0u;
    }

    g_plat_trap_caught = 0;
    ((void(*)(void))stub)();   /* 执行 int3;ret */

    /* 恢复原 handler（**必须** —— 不改变进程的长期信号行为） */
    (void)sigaction(SIGTRAP, &sa_old, NULL);
    munmap(stub, pg);

    r = (g_plat_trap_caught == 0) ? 2u : 1u;
    return r;
}

int prot_plat_parent_name(char* name, size_t cap)
{
    /* ## Linux 侧的父进程名**极简单**
     *   读 `/proc/<ppid>/comm` 即可 —— 无需 NT 查询 + 打开进程句柄。
     */
    char path[64];
    FILE* f;
    long ppid;

    if (name == NULL || cap == 0)
        return 0;

    ppid = (long)getppid();
    if (ppid <= 0)
        return 0;

    snprintf(path, sizeof(path), "/proc/%ld/comm", ppid);
    f = fopen(path, "r");
    if (f == NULL)
        return 0;
    if (fgets(name, (int)cap, f) == NULL) {
        fclose(f);
        return 0;
    }
    fclose(f);

    /* 去掉尾部换行 */
    {
        size_t n = strlen(name);
        while (n > 0 && (name[n - 1] == '\n' || name[n - 1] == '\r'))
            name[--n] = '\0';
    }
    return (name[0] != '\0') ? 1 : 0;
}

int prot_plat_clock_pair(uint64_t* tick_ms, uint64_t* wall_ms)
{
    struct timespec mono;
    struct timespec real;

    if (tick_ms == NULL || wall_ms == NULL)
        return 0;
    if (clock_gettime(CLOCK_MONOTONIC, &mono) != 0)
        return 0;
    if (clock_gettime(CLOCK_REALTIME, &real) != 0)
        return 0;

    *tick_ms = (uint64_t)mono.tv_sec * 1000ull
               + (uint64_t)(mono.tv_nsec / 1000000);
    *wall_ms = (uint64_t)real.tv_sec * 1000ull
               + (uint64_t)(real.tv_nsec / 1000000);
    return 1;
}

/* ## Linux **独有**的 3 个反调试维度
 *
 * ### 为什么这些是"独有"
 *   Windows 的注入/HOOK 生态与 Linux **不同**:
 *     · Windows: DLL 注入、IAT hook、inline hook
 *     · Linux:   **LD_PRELOAD**、PLT/GOT hook、ptrace
 *   => Linux 需要检查**自己的**主流注入方式。
 */
uint32_t prot_plat_extra_debug_flags(void)
{
    uint32_t flags = 0u;

    /* ---- ① LD_PRELOAD 检测 ----
     *   LD_PRELOAD 是 Linux **最主要的用户态注入手段**
     *   （等价于 Windows 的 DLL 注入，但更简单）。
     *   检查 `/proc/self/environ`（**内核提供，不可被用户态伪造**）。
     */
    {
        static const char needle[] = "LD_PRELOAD=";
        FILE* f = fopen("/proc/self/environ", "r");
        if (f != NULL) {
            /* environ 用 NUL 分隔，需按块读 */
            char buf[8192];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf) - 1, f)) > 0) {
                size_t i;
                buf[n] = '\0';
                for (i = 0; i + sizeof(needle) <= n; i++) {
                    if (memcmp(buf + i, needle, sizeof(needle) - 1) == 0) {
                        /* 值非空才算（LD_PRELOAD= 空值无害）*/
                        const char* v = buf + i + sizeof(needle) - 1;
                        if (*v != '\0')
                            flags |= PROT_PLAT_EXTRA_PRELOAD;
                        break;
                    }
                }
                if (flags & PROT_PLAT_EXTRA_PRELOAD)
                    break;
            }
            fclose(f);
        }
    }

    /* ---- ② 可疑 .so 检测 ----
     *   正常进程的库来自**系统目录**（/usr/lib、/lib）
     *   或**自身目录**。若映射里有来自 `/tmp`、`/dev/shm`、
     *   当前目录**相对路径**的 .so -> 可疑（frida-gadget 等的常见位置）。
     */
    {
        FILE* f = fopen("/proc/self/maps", "r");
        if (f != NULL) {
            char line[1024];
            while (fgets(line, (int)sizeof(line), f) != NULL) {
                const char* p = strchr(line, '/');
                if (p == NULL)
                    continue;
                if (strstr(p, ".so") == NULL)
                    continue;
                if (strncmp(p, "/tmp/", 5) == 0 ||
                    strncmp(p, "/dev/shm/", 9) == 0 ||
                    strncmp(p, "/var/tmp/", 9) == 0) {
                    flags |= PROT_PLAT_EXTRA_SUSP_SO;
                    break;
                }
            }
            fclose(f);
        }
    }

    /* ---- ③ ptrace 自附加试探 ----
     *   `PTRACE_TRACEME` 的语义: "**让父进程跟踪我**"。
     *   若**已被跟踪**（有 tracer）-> 内核拒绝再次 TRACEME -> 返回失败。
     *
     *   ⚠️ **副作用**: TRACEME 成功后，本进程**会被父进程跟踪**到退出。
     *      为**避免副作用**，本实现**只在已有 TracerPid 时才试探**
     *      （那时 TRACEME 必然失败 -> 无副作用）。
     */
    {
        char buf[4096];
        FILE* f = fopen("/proc/self/status", "r");
        long tp = 0;
        if (f != NULL) {
            while (fgets(buf, (int)sizeof(buf), f) != NULL) {
                if (strncmp(buf, "TracerPid:", 10) == 0) {
                    tp = strtol(buf + 10, NULL, 10);
                    break;
                }
            }
            fclose(f);
        }
        if (tp != 0) {
            /* 已被跟踪 -> TRACEME 必然失败，**调用它无副作用** */
            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0)
                flags |= PROT_PLAT_EXTRA_PTRACED;
        }
    }

    return flags;
}

prot_status prot_plat_hide_thread(void)
{
    /* ## Linux **无等价物**（如实声明）
     *   Windows 的 `NtSetInformationThread(ThreadHideFromDebugger)` 让
     *   **调试器看不到该线程的调试事件**。
     *   Linux 内核**不提供**这类"对 tracer 隐藏"的接口 ——
     *   tracer 通过 ptrace 拥有**完全可见性**。
     *
     *   => 如实返回 `PROT_ERR_UNSUPPORTED`（不假装成功）。
     */
    return PROT_ERR_UNSUPPORTED;
}

/* ------------------------------------------------------------------ *
 * 分组 13: HTTP 下载（B4，Linux: **如实降级**）
 *
 * ## 为什么返回 UNSUPPORTED 而不是"假装失败"
 *   `demo/main.c` 的 `--blob-url` 在下载失败时**静默回退本地路径**。
 *   若本函数返回 `PROT_ERR_INTERNAL`（"网络失败"），调用方会回退 ——
 *   **行为上等价**，但**语义上误导**（让人以为"网络不通"，
 *   实际是"该平台未实现"）。
 *
 *   => 返回 **`PROT_ERR_UNSUPPORTED`** —— 调用方**同样回退**，
 *      但**语义准确**（可据此区分"未实现"与"网络故障"）。
 *
 * ## 为什么不用 libcurl（**决策记录**）
 *   见 `prot_platform.h` 分组 13 的注释:
 *   ① 不引入新依赖 ② 诚实 ③ 可扩展（将来可填 libcurl 实现）
 * ------------------------------------------------------------------ */

prot_status prot_plat_http_get(const char* url, const char* out_path,
                               size_t max_size)
{
    (void)url;
    (void)out_path;
    (void)max_size;
    /* 如实声明: Linux 侧未实现网络下载 -> 调用方回退本地路径 */
    return PROT_ERR_UNSUPPORTED;
}

/* 下载到内存（Linux: **同样如实降级**，理由见 prot_plat_http_get）。 */
prot_status prot_plat_http_get_mem(const char* url, char* buf, size_t cap,
                                   size_t* out_len)
{
    (void)url;
    (void)buf;
    (void)cap;
    (void)out_len;
    return PROT_ERR_UNSUPPORTED;
}

/* 平台层: 页大小（C2 后续，2026-09-25）。 */
size_t prot_plat_page_size(void)
{
    long p = sysconf(_SC_PAGESIZE);
    return (p > 0) ? (size_t)p : (size_t)4096u;
}

/* 控制台设为 UTF-8（Linux: **no-op**，语义等价 —— 见头文件说明）。
 *
 * POSIX 终端没有"代码页"概念，输出编码由 **locale** 决定；
 * 本项目的输出以 UTF-8 字节写出，终端按 UTF-8 解释即可。
 */
prot_status prot_plat_console_utf8(void)
{
    return PROT_OK;
}

#endif /* PROT_PLATFORM_LINUX */
