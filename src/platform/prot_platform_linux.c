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

/* ## ⚠️ `_GNU_SOURCE` 必须**先于任何 `<...>` 包含**（CI 实测教训 2026-10-02）
 *
 * 本文件曾把这段"先判后定义"放在 `prot_platform.h` / `prot_compiler.h` **之后**。
 * 那两个头会间接拉入 `<stdio.h>` —— 而 glibc 的 `<features.h>` 在**第一次**
 * 遇到系统头时就把特性宏**读死并冻结**，之后再定义 `_GNU_SOURCE` **完全无效**。
 *
 * 后果（**只在 CI 上暴露，本地门禁永远看不到**）：
 *   · `tools/linux_compile_check.py` 与 `build.ps1` 都传 `-D_GNU_SOURCE`
 *     -> 定义在命令行，早于一切包含 -> 编译通过；
 *   · `.github/workflows/ci.yml` 原先**没传**该宏 -> 11+ 个错误：
 *       CLOCK_MONOTONIC undeclared / struct dl_phdr_info /
 *       PTHREAD_MUTEX_NORMAL / siginfo_t / SA_SIGINFO / struct addrinfo ...
 *   => 典型的"**本地才生效的门禁**"：两条编译命令不一致时，
 *      本地那条带着宏，于是缺陷只在 CI 上现形。
 *
 * 修法（两处都做，缺一不可）：
 *   ① **本文件自给自足** —— 宏定义提到所有 `#include` 之前（就是下面这段）；
 *   ② `ci.yml` 的两条 `gcc` 补 `-D_GNU_SOURCE`，与 `linux_compile_check.py`
 *      的 `CFLAGS` 逐字一致（命令行定义与这里的 `#ifndef` 不冲突）。
 *
 * 为什么保留 `#ifndef` 守卫：命令行已定义时**不能重复 define**，
 * 否则严格构建（`-Werror`）会因 "redefined" 失败。 */
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include "protect/prot_platform.h"
#include "protect/prot_compiler.h"   /* W3: PROT_FOPEN_S / PROT_SNPRINTF / PROT_STRCPY_S
                                      *（与 `prot_platform_win.c` 结构对等 —— 该侧早已包含）*/

#if PROT_PLATFORM == PROT_PLATFORM_LINUX

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

prot_status prot_plat_protect(void* addr, size_t size,
                              prot_page_prot prot)
{
    /* ## ⚠️ 页对齐必须**自己做**（2026-09-25 实测根因）
     *
     * **根因**: POSIX 的 `mprotect` 要求 `addr` **页对齐** ——
     *   否则返回 **EINVAL**。而调用方传的是**函数内的任意地址**
     *   （如 `selfcrypt` 传 `base + 0xc2f2`，1164 字节）——
     *   实测 `VP-FAIL` -> selfcrypt 解密失败 -> 报"完整性校验失败"。
     *
     * **Windows 侧为什么没有这个问题**:
     *   `VirtualProtect` **自动向下对齐**到页边界
     *   （MSDN: "the address is rounded down to the next page boundary"）
     *   —— 故 PE 侧从不暴露该差异。
     *
     * **=> 平台层必须吸收这个差异**（调用方不该关心页对齐）:
     *   把 [addr, addr+size) **向外扩展到整页**再 mprotect，
     *   语义与 Windows **一致**（Windows 也是整页生效）。
     *
     * **诚实边界**: 扩展后**相邻数据也被改保护** —— 这是页粒度保护的
     *   固有性质（Windows 同样如此），两侧行为**等价**。
     */
    int prot_native;
    long pg;
    uintptr_t a, lo, hi;
    size_t span;

    if (addr == NULL || size == 0u)
        return PROT_ERR_INVALID_ARG;

    switch (prot) {
    case PROT_PAGE_READ:              prot_native = PROT_READ; break;
    case PROT_PAGE_READWRITE:         prot_native = PROT_READ | PROT_WRITE;
                                      break;
    case PROT_PAGE_EXECUTE:           prot_native = PROT_EXEC; break;
    case PROT_PAGE_EXECUTE_READ:      prot_native = PROT_READ | PROT_EXEC;
                                      break;
    case PROT_PAGE_EXECUTE_READWRITE: prot_native = PROT_READ | PROT_WRITE
                                                  | PROT_EXEC;
                                      break;
    default: return PROT_ERR_INVALID_ARG;
    }

    pg = sysconf(_SC_PAGESIZE);
    if (pg <= 0)
        return PROT_ERR_INTERNAL;

    /* 向外扩展到整页（与 Windows 的"向下对齐"等价且更完整）*/
    a = (uintptr_t)addr;
    lo = a & ~((uintptr_t)pg - 1u);
    hi = (a + size + (uintptr_t)pg - 1u) & ~((uintptr_t)pg - 1u);
    span = (size_t)(hi - lo);
    if (span == 0u)
        span = (size_t)pg;

    if (mprotect((void*)lo, span, prot_native) != 0)
        return PROT_ERR_INTERNAL;
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

/* ## W3（2026-09-25）: HTTP 实现所需的 **POSIX socket** 头
 *   不是"新依赖": 见分组 13 决策说明 —— `sys/socket.h` 等是
 *   **glibc 标准件**（与 Windows 的 WinHTTP 同为系统组件），
 *   **不引入第三方库**。 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>

/* 从映像基址取 ELF 头 */
/* ================================================================== *
 * ELF 元数据的读取（C 阶段修正，2026-09-25）
 *
 * ## ⚠️ 关键事实: **ELF 节表不在内存里**
 *   实测: 原实现假设"映像基址处是 ELF 头、节表紧随其后" ->
 *   `nsec = 0`（节枚举失败）-> integrity 报"完整性校验失败"。
 *
 *   **两个原因**:
 *     ① `dl_iterate_phdr` 给的 `dlpi_addr` 对 **PIE** 是**加载偏移**，
 *        基址处**未必**是 ELF 头
 *     ② **`e_shoff` 是文件偏移** —— 内核只映射 **PT_LOAD 段**，
 *        **节表不加载**（这与 PE 不同: PE 的节表在映像内）
 *
 * ## 修正后的数据来源（**各取其正确者**）
 *   | 数据 | 来源 |
 *   |------|------|
 *   | 节表（名/偏移/大小/`sh_addr`）| **文件** `/proc/self/exe` |
 *   | 运行期地址 | `sh_addr + load_bias`（`dlpi_addr`）|
 *
 * ## 为什么 `/proc/self/exe`
 *   · 指向**本进程实际的可执行文件**（即使被重命名也指向打开时的 inode）
 *   · 始终存在（Linux 提供）-> 无额外依赖
 *   · **只读**打开 -> 与"最小侵入"一致
 *
 * ## 诚实边界
 *   · `/proc` 未挂载（极简容器）-> 返回 NULL -> 枚举返回 0
 *     （调用方按"枚举失败"处理，**不误报**）
 *   · 每次调用重新读文件（简单优先；如需可加缓存）
 * ================================================================== */

/* 加载偏移（PIE 的 dlpi_addr）。失败返回 0。 */
static uintptr_t lin_load_bias(void)
{
    struct lin_base_ctx ctx;
    ctx.base = NULL;
    ctx.found = 0;
    (void)dl_iterate_phdr(lin_base_cb, &ctx);
    return ctx.found ? (uintptr_t)ctx.base : (uintptr_t)0;
}

/* 打开自身可执行文件；失败返回 NULL。 */
static FILE* lin_open_self(void)
{
    FILE* f = fopen("/proc/self/exe", "rb");
    if (f != NULL)
        return f;
    /* 回退: dl_iterate_phdr 的 dlpi_name（主程序通常是空串 ->
     * 再试 /proc/self/exe 已失败，故此处基本不会成功；
     * 保留为**显式失败**而非静默返回错误数据）。 */
    return NULL;
}

/* 从文件读整个节表（调用方 free）。
 *
 * ⚠️ **注释里绝不能出现"斜杠+星号"两字符组合**（连举例都不行）——
 *    那会被编译器当作**嵌套注释起始**（GCC `-Wcomment` -> `-Werror`
 *    直接失败）。本项目第 5 次同类陷阱: 前 4 次分别出现在
 *    `prot_platform.h`、`prot_platform_linux.c`（两处）、
 *    `prot_sections.h`；**第 5 次是我在写"解释该陷阱"的注释时又踩了**。
 *    由 `tools/comment_lint.py` 的 C1 规则抓到（这正是它存在的意义）。
 *    描述该序列时请用中文表述，不要写出实际字符。
 *
 * 输出: 节表指针、条目数（out_num）、条目大小（out_entsize）、
 *       名字表索引（out_strndx）。
 * 失败: 返回 NULL 并置 out_num = 0。
 */
static Elf64_Shdr* lin_read_shdrs_from_file(size_t* out_num,
                                            size_t* out_entsize,
                                            size_t* out_strndx)
{
    FILE* f;
    Elf64_Ehdr eh;
    Elf64_Shdr* shdrs;
    uint64_t shoff;
    uint16_t shnum, shentsize, shstrndx;

    *out_num = 0u;
    *out_entsize = 0u;
    *out_strndx = 0u;

    f = lin_open_self();
    if (f == NULL)
        return NULL;

    if (fread(&eh, 1, sizeof(eh), f) != sizeof(eh)) {
        fclose(f);
        return NULL;
    }
    if (eh.e_ident[0] != 0x7Fu || eh.e_ident[1] != 'E'
        || eh.e_ident[2] != 'L' || eh.e_ident[3] != 'F'
        || eh.e_ident[EI_CLASS] != ELFCLASS64) {
        fclose(f);
        return NULL;
    }

    shoff = eh.e_shoff;
    shnum = eh.e_shnum;
    shentsize = eh.e_shentsize;
    shstrndx = eh.e_shstrndx;
    if (shoff == 0u || shnum == 0u || shentsize < sizeof(Elf64_Shdr)
        || (size_t)shnum > 4096u) {
        fclose(f);
        return NULL;
    }

    shdrs = (Elf64_Shdr*)malloc((size_t)shnum * sizeof(Elf64_Shdr));
    if (shdrs == NULL) {
        fclose(f);
        return NULL;
    }
    if (fseek(f, (long)shoff, SEEK_SET) != 0
        || fread(shdrs, sizeof(Elf64_Shdr), (size_t)shnum, f)
           != (size_t)shnum) {
        free(shdrs);
        fclose(f);
        return NULL;
    }
    fclose(f);

    *out_num = (size_t)shnum;
    *out_entsize = (size_t)shentsize;
    *out_strndx = (size_t)shstrndx;
    /* ⚠️ 文件里的 shdr 用的 `sh_offset` 是文件偏移（**正是我们需要的**），
     * 而 `sh_addr` 是**链接期虚拟地址** -> 加 load_bias 得运行期地址。 */
    return shdrs;
}

/* 读节名字符串表到缓冲（调用方 free）；成功写 *out_len。 */
static char* lin_read_shstrtab(const Elf64_Shdr* shdrs, size_t shnum,
                               size_t strndx, size_t* out_len)
{
    FILE* f;
    Elf64_Shdr s;
    char* buf;

    *out_len = 0u;
    if (shdrs == NULL || strndx >= shnum)
        return NULL;
    s = shdrs[strndx];
    if (s.sh_offset == 0u || s.sh_size == 0u || s.sh_size > (1u << 20))
        return NULL;

    f = lin_open_self();
    if (f == NULL)
        return NULL;
    buf = (char*)malloc((size_t)s.sh_size + 1u);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }
    if (fseek(f, (long)s.sh_offset, SEEK_SET) != 0
        || fread(buf, 1, (size_t)s.sh_size, f) != (size_t)s.sh_size) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    buf[s.sh_size] = '\0';
    *out_len = (size_t)s.sh_size;
    return buf;
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


/* 统一的"取节表 + 名字表"（各函数共用；返回 0 表示失败）。
 * 成功后 shdrs/strtab 需由调用方释放。
 */
static int lin_get_sections(Elf64_Shdr** shdrs, size_t* shnum,
                            size_t* entsize, char** strtab, uintptr_t* bias)
{
    size_t strndx = 0u, slen = 0u;
    *shdrs = NULL;
    *strtab = NULL;
    *shnum = 0u;
    *entsize = 0u;
    *bias = lin_load_bias();
    *shdrs = lin_read_shdrs_from_file(shnum, entsize, &strndx);
    if (*shdrs == NULL)
        return 0;
    *strtab = lin_read_shstrtab(*shdrs, *shnum, strndx, &slen);
    if (*strtab == NULL) {
        free(*shdrs);
        *shdrs = NULL;
        *shnum = 0u;
        return 0;
    }
    return 1;
}

size_t prot_plat_enum_sections(prot_section_view* out, size_t capacity)
{
    /* ## C 阶段修正（2026-09-25）: 节表**从文件读**
     *
     * 原实现假设"内存里有 ELF 头 + 节表" —— 实测 **nsec=0**
     * （ELF 节表**不加载到内存**，且 PIE 的基址处未必是 ELF 头）。
     * 见 lin_read_shdrs_from_file 的注释。
     *
     * `rva` 语义: `sh_addr + load_bias` = **运行期地址**
     * （与 Windows 的 `VirtualAddress` 语义不同 —— 那边是 RVA，
     *  此处调用方 `integrity.c` 用 `base + rva`... 而 base 即 load_bias，
     *  故若此处返回"运行期地址"会**双重加**）。
     *
     * ### ⚠️ 因此这里返回 **RVA**（= `sh_addr`，不加 bias）
     *   保持与 Windows **完全一致的语义**（调用方统一 `base + rva`）。
     *   PIE 下 `sh_addr` 数值即 RVA（链接期地址，基址为 0）。
     */
    Elf64_Shdr* shdrs = NULL;
    char* strtab = NULL;
    size_t shnum = 0u, entsize = 0u, n = 0u, k;
    uintptr_t bias = 0u;

    (void)bias;
    if (!lin_get_sections(&shdrs, &shnum, &entsize, &strtab, &bias))
        return 0u;

    for (k = 0u; k < shnum; k++) {
        const Elf64_Shdr* s = &shdrs[k];
        if (s->sh_type == SHT_NULL)
            continue;
        if (s->sh_name < (1u << 20)
            && strtab[s->sh_name] != '\0') {
            /* 有名节 —— 计入 */
        }
        if (out != NULL && n < capacity) {
            lin_copy_name(out[n].name, PROT_SECTION_NAME_MAX,
                          strtab + s->sh_name);
            out[n].rva = (size_t)s->sh_addr;   /* RVA（与 Windows 同语义）*/
            out[n].size = (size_t)s->sh_size;
        }
        n++;
    }

    free(strtab);
    free(shdrs);
    return n;
}

size_t prot_plat_reloc_ranges(prot_range* out, size_t capacity)
{
    /* C 阶段修正: 节表**从文件读**（见 lin_read_shdrs_from_file）。 */
    Elf64_Shdr* shdrs = NULL;
    char* strtab = NULL;
    size_t shnum = 0u, entsize = 0u, n = 0u, k, i;
    uintptr_t bias = 0u;

    if (!lin_get_sections(&shdrs, &shnum, &entsize, &strtab, &bias))
        return 0u;

    for (i = 0u; i < shnum; i++) {
        const Elf64_Shdr* s = &shdrs[i];
        const char* nm = strtab + s->sh_name;
        size_t cnt, q;
        if (strcmp(nm, ".rela.dyn") != 0 && strcmp(nm, ".rela.plt") != 0)
            continue;
        /* ⚠️ 重定位表**在内存里**（PT_LOAD 会映射它）——
         *   故从 `sh_addr + bias` 读，而非文件偏移。 */
        if (s->sh_addr == 0u || s->sh_entsize == 0u)
            continue;
        cnt = (size_t)(s->sh_size / s->sh_entsize);
        for (q = 0u; q < cnt; q++) {
            const Elf64_Rela* rel =
                (const Elf64_Rela*)(bias + s->sh_addr
                                    + q * s->sh_entsize);
            uint32_t type = (uint32_t)ELF64_R_TYPE(rel->r_info);
            if (type == R_X86_64_RELATIVE || type == R_X86_64_GLOB_DAT
                || type == R_X86_64_JUMP_SLOT) {
                /* r_offset 是**运行期地址** -> 转 RVA（减 bias）*/
                if (out != NULL && n < capacity) {
                    out[n].rva = (size_t)(rel->r_offset - bias);
                    out[n].size = 8u;
                }
                n++;
            }
        }
    }
    free(strtab);
    free(shdrs);
    (void)k;
    return n;
}

int prot_plat_iat_range(prot_range* out)
{
    /* 等价于"取 iat_ranges 的第一个"（保持向后兼容）。 */
    prot_range all[8];
    size_t n = prot_plat_iat_ranges(all, sizeof(all) / sizeof(all[0]));
    if (n == 0u || out == NULL)
        return 0;
    out->rva = all[0].rva;
    out->size = all[0].size;
    return 1;
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
 * 分组 13: HTTP 下载（W3, 2026-09-25: **POSIX socket 实现**）
 *
 * ## 决策变更（**与 §22.5 的原判断的关系**）
 *   原决策: "不用 libcurl（①不引入新依赖 ②诚实 ③可扩展）"。
 *   **该判断针对 libcurl 是对的**（第三方库）—— 本实现**仍然遵守**。
 *
 *   **但**: Windows 侧用的是 **WinHTTP**（**系统组件**，非第三方）。
 *   对等的做法是 Linux 用 **POSIX socket**（`<sys/socket.h>`，
 *   **glibc 自带**）—— **同为系统提供的网络能力**。
 *   => **不引入第三方依赖**（与原决策一致），且**与 Windows 对等**。
 *
 * ## 语义对齐（逐项对照 `prot_platform_win.c`）
 *   · 参数预检 NULL -> `INVALID_ARG`；大小上限 = `max_size` 或 **16 MiB**
 *   · 超限 -> **删文件** + `INTERNAL`（与 Windows 同）
 *   · `get_mem`: 仅当 `avail < cap` 才读 -> `OK`（与 Windows 同）
 *   · 超时 3s（对应 Windows 的 `WinHttpSendRequest(..., 3000)`）
 *
 * ## 范围（**最小化，如实降级**）
 *   支持: `http://host[:port]/path` 的 GET
 *   **不支持（返回 `UNSUPPORTED`，不假装成功）**:
 *     https（需 TLS 栈）/ 重定向 / 分块传输 / 代理
 *
 * ## 为什么 HERE（而不是新文件）
 *   本文件即"Linux 平台层"，HTTP 属分组 13 的平台实现 ——
 *   放这里与 Windows 侧**结构对等**（便于对照维护）。
 * ------------------------------------------------------------------ */

/*: HTTP 默认端口（只支持 http://） */
#define PROT_HTTP_PORT_DEFAULT 80
/*: 与 Windows 的 `cap` 默认值一致（16 MiB） */
#define PROT_HTTP_MAX_DEFAULT (16u * 1024u * 1024u)
/*: 超时（秒）—— 对应 WinHTTP 的 3000ms */
#define PROT_HTTP_TIMEOUT_SEC 3

/* 解析 `http://host[:port]/path`。
 *
 * 返回 1 成功（host/path/port 填好）；0 = 不支持或格式错。
 * **不支持 https**（scheme 不是 http -> 返回 0，调用方报 UNSUPPORTED）。
 */
static int http_parse_url(const char* url, char* host, size_t host_cap,
                          char* path, size_t path_cap, int* port,
                          int* scheme_unsupported)
{
    const char* p;
    const char* slash;
    size_t host_len;
    *scheme_unsupported = 0;
    if (url == NULL || host == NULL || path == NULL || port == NULL)
        return 0;
    if (strncmp(url, "http://", 7u) == 0) {
        p = url + 7u;
        *port = PROT_HTTP_PORT_DEFAULT;
    } else if (strncmp(url, "https://", 8u) == 0) {
        /* **如实降级**: https 需 TLS 栈，本实现不支持 */
        *scheme_unsupported = 1;
        return 0;
    } else {
        return 0;
    }
    slash = strchr(p, '/');
    host_len = (slash != NULL) ? (size_t)(slash - p) : strlen(p);
    if (host_len == 0u || host_len >= host_cap)
        return 0;
    memcpy(host, p, host_len);
    host[host_len] = '\0';
    /* 可选 `:port` */
    {
        char* colon = strchr(host, ':');
        if (colon != NULL) {
            long v = 0;
            const char* q = colon + 1;
            if (*q == '\0')
                return 0;
            while (*q != '\0') {
                if (*q < '0' || *q > '9')
                    return 0;
                v = v * 10 + (*q - '0');
                if (v > 65535)
                    return 0;
                q++;
            }
            *port = (int)v;
            *colon = '\0';
        }
    }
    if (slash != NULL) {
        size_t plen = strlen(slash);
        if (plen >= path_cap)
            return 0;
        memcpy(path, slash, plen + 1u);
    } else {
        PROT_STRCPY_S(path, path_cap, "/");
    }
    return 1;
}

/* 建立到 host:port 的 TCP 连接；失败返回 -1。
 *
 * ## 实现说明（W3）
 *   先按**字面 IPv4** 解析（demo 的用途几乎都是 `127.0.0.1`）——
 *   快且无 DNS 依赖；失败才走 `getaddrinfo`（支持主机名）。
 *   两者都设 **超时**（对应 Windows 的 3000ms）。
 */
static int http_connect(const char* host, int port)
{
    struct sockaddr_in sa;
    struct timeval tv;
    int fd;

    tv.tv_sec = PROT_HTTP_TIMEOUT_SEC;
    tv.tv_usec = 0;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);

    if (inet_pton(AF_INET, host, &sa.sin_addr) == 1) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
            return -1;
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
            close(fd);
            return -1;
        }
        return fd;
    }

    /* 非字面 IPv4 -> 主机名解析（demo 用途少见，但保持可用） */
    {
        struct addrinfo hints;
        struct addrinfo* res = NULL;
        char portstr[8];
        int rc;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        PROT_SNPRINTF(portstr, sizeof(portstr), "%d", port);
        rc = getaddrinfo(host, portstr, &hints, &res);
        if (rc != 0 || res == NULL)
            return -1;
        fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd < 0) {
            freeaddrinfo(res);
            return -1;
        }
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, res->ai_addr, (socklen_t)res->ai_addrlen) != 0) {
            close(fd);
            freeaddrinfo(res);
            return -1;
        }
        freeaddrinfo(res);
        return fd;
    }
}

/* 发送 GET 请求；失败返回 0。 */
static int http_send_get(int fd, const char* host, int port,
                         const char* path)
{
    char req[1024];
    int n;
    n = PROT_SNPRINTF(req, sizeof(req),
                      "GET %s HTTP/1.0\r\nHost: %s:%d\r\n"
                      "User-Agent: PROT-Demo/1.0\r\n"
                      "Connection: close\r\n\r\n",
                      path, host, port);
    if (n <= 0 || (size_t)n >= sizeof(req))
        return 0;
    return (send(fd, req, (size_t)n, 0) == n) ? 1 : 0;
}

/* 跳过 HTTP 响应头，返回剩余缓冲里的**体起始偏移**；-1 = 头未结束。
 *
 * ## 为什么缓冲区跨调用保留
 *   `recv` 可能把头与体一次返回 -> 必须把"头之后"的数据**交给调用方**，
 *   否则会丢字节（实测常见的实现错误）。
 *   => 本函数把已读缓冲、长度、已用偏移都作为**出入参**。
 */
static long http_skip_headers(char* buf, size_t* used, size_t cap)
{
    size_t i;
    for (i = 0u; i + 3u < *used; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' &&
            buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return (long)(i + 4u);
        }
    }
    (void)cap;
    return -1;
}

prot_status prot_plat_http_get(const char* url, const char* out_path,
                               size_t max_size)
{
    char host[256];
    char path[512];
    int port = 0;
    int unsup = 0;
    int fd;
    FILE* f = NULL;
    size_t total = 0u;
    size_t cap;
    char buf[4096];
    long body_off = -1;
    size_t used = 0u;
    prot_status st = PROT_ERR_INTERNAL;
    ssize_t n;

    if (url == NULL || out_path == NULL)
        return PROT_ERR_INVALID_ARG;
    if (!http_parse_url(url, host, sizeof(host), path, sizeof(path),
                        &port, &unsup))
        return unsup ? PROT_ERR_UNSUPPORTED : PROT_ERR_INVALID_ARG;

    fd = http_connect(host, port);
    if (fd < 0)
        return PROT_ERR_INTERNAL;
    if (!http_send_get(fd, host, port, path)) {
        close(fd);
        return PROT_ERR_INTERNAL;
    }

    if (PROT_FOPEN_S(&f, out_path, "wb") != 0) {
        close(fd);
        return PROT_ERR_INTERNAL;
    }
    cap = (max_size != 0u) ? max_size : (size_t)PROT_HTTP_MAX_DEFAULT;

    /* 先收一块（含响应头），再跳过头部 */
    while ((n = recv(fd, buf + used, sizeof(buf) - used, 0)) > 0) {
        size_t chunk = (size_t)n;
        size_t off = 0u;
        used += chunk;
        if (body_off < 0) {
            body_off = http_skip_headers(buf, &used, sizeof(buf));
            if (body_off < 0) {
                if (used >= sizeof(buf)) {   /* 头过大 -> 失败 */
                    st = PROT_ERR_INTERNAL;
                    goto done;
                }
                continue;                     /* 继续收，直到头完整 */
            }
            off = (size_t)body_off;
        }
        {
            size_t body_len = used - off;
            if (total + body_len > cap) {
                st = PROT_ERR_INTERNAL;       /* 超限 */
                goto done;
            }
            if (body_len > 0u) {
                (void)fwrite(buf + off, 1u, body_len, f);
                total += body_len;
            }
        }
        used = 0u;
        off = 0u;
        (void)off;
    }
    st = (body_off >= 0) ? PROT_OK : PROT_ERR_INTERNAL;

done:
    if (f != NULL)
        fclose(f);
    close(fd);
    if (st != PROT_OK) {
        /* 与 Windows 一致: 失败/超限 -> **删掉半成品文件** */
        remove(out_path);
    }
    return st;
}

/* 下载到内存（语义与 Windows 的 `get_mem` 对齐: 仅当 `avail < cap` 才读）。 */
prot_status prot_plat_http_get_mem(const char* url, char* buf, size_t cap,
                                   size_t* out_len)
{
    char host[256];
    char path[512];
    int port = 0;
    int unsup = 0;
    int fd;
    char raw[8192];
    size_t used = 0u;
    size_t body_total = 0u;
    long body_off = -1;
    prot_status st = PROT_ERR_INTERNAL;
    ssize_t n;

    if (url == NULL || buf == NULL || cap == 0u)
        return PROT_ERR_INVALID_ARG;
    if (!http_parse_url(url, host, sizeof(host), path, sizeof(path),
                        &port, &unsup))
        return unsup ? PROT_ERR_UNSUPPORTED : PROT_ERR_INVALID_ARG;
    if (out_len != NULL)
        *out_len = 0u;

    fd = http_connect(host, port);
    if (fd < 0)
        return PROT_ERR_INTERNAL;
    if (!http_send_get(fd, host, port, path)) {
        close(fd);
        return PROT_ERR_INTERNAL;
    }

    /* ## ⚠️ 循环直到**真的拿到体**（W3 缺陷修复, 2026-09-25）
     *
     * **原实现的缺陷**: "头已完整但体还没到"的那次 recv 会算出
     * `body_len == 0`，而 `0 < cap` 成立 -> **报 OK 且内容为空**
     * （**误报成功**，最危险）。本地大体量/分开到达时暴露。
     *
     * **修法（对齐 Windows 的 `avail < cap` 语义）**:
     *   · `body_len == 0` -> **不算成功**，继续 recv
     *   · 连接结束仍无体 -> INTERNAL
     *   · 体合计 >= cap -> INTERNAL（与 Windows 一致）
     */
    while ((n = recv(fd, raw + used, sizeof(raw) - used, 0)) > 0) {
        size_t off = 0u;
        size_t body_len;
        used += (size_t)n;
        if (body_off < 0) {
            body_off = http_skip_headers(raw, &used, sizeof(raw));
            if (body_off < 0) {
                if (used >= sizeof(raw)) {      /* 头过大 */
                    st = PROT_ERR_INTERNAL;
                    goto done;
                }
                continue;                        /* 继续收，直到头完整 */
            }
        }
        off = (size_t)body_off;
        body_len = used - off;
        if (body_len == 0u) {
            used = 0u;                           /* 头之后无体 -> 继续收 */
            body_off = 0;                        /* 头已消费 */
            continue;
        }
        if (body_len >= cap) {
            st = PROT_ERR_INTERNAL;              /* 体 >= cap（与 Windows 同） */
            goto done;
        }
        memcpy(buf, raw + off, body_len);
        buf[body_len] = '\0';
        if (out_len != NULL)
            *out_len = body_len;
        st = PROT_OK;
        goto done;      /* demo 的用途（小 JSON）一次足够 */
    }
    /* 连接结束: 有头无体 -> INTERNAL（**不报成功**） */
    st = PROT_ERR_INTERNAL;

done:
    (void)body_total;
    close(fd);
    return st;
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

/* 全部 GOT 类区间（C 阶段，2026-09-25）。
 *
 * ## 为什么必须两个都掩
 *   `.got` 与 `.got.plt` **都会被 loader 填充**（前者全局偏移、
 *   后者 PLT 延迟绑定）-> 两者都必须排除在 CRC 之外。
 *   构建侧（hashpatch）已掩两者；本函数修正运行侧口径以**对齐**。
 */
size_t prot_plat_iat_ranges(prot_range* out, size_t capacity)
{
    /* C 阶段修正: 节表**从文件读**。返回 **RVA**（与 Windows 同语义）。 */
    Elf64_Shdr* shdrs = NULL;
    char* strtab = NULL;
    size_t shnum = 0u, entsize = 0u, n = 0u, i;
    uintptr_t bias = 0u;

    if (!lin_get_sections(&shdrs, &shnum, &entsize, &strtab, &bias))
        return 0u;

    for (i = 0u; i < shnum; i++) {
        const Elf64_Shdr* s = &shdrs[i];
        const char* nm = strtab + s->sh_name;
        if (strcmp(nm, ".got") == 0 || strcmp(nm, ".got.plt") == 0) {
            if (out != NULL && n < capacity) {
                out[n].rva = (size_t)s->sh_addr;   /* RVA */
                out[n].size = (size_t)s->sh_size;
            }
            n++;
        }
    }
    free(strtab);
    free(shdrs);
    return n;
}

#endif /* PROT_PLATFORM_LINUX */
