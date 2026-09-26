/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * platform_conformance.c — 平台层**契约测试**（L4-A）
 *
 * ## 为什么需要（这是 L4 的关键设计）
 *   L4 的目标是"实现 Linux 平台层"。但**新平台实现是否正确**，
 *   若靠人工判断，就会变成"看起来对" —— 正是本项目反复批判的。
 *
 *   本测试把"平台层是否正确"变成**可执行的验收条件**:
 *     **任何平台实现，只要能通过本测试，就视为契约合规。**
 *
 *   => 把"实现 Linux"从**写代码**变成**通过测试**。
 *
 * ## 设计原则
 *   · **只测契约，不测实现细节**（不假设 Windows/Linux 的具体行为）
 *   · 每个断言都对应 `prot_platform.h` 里的**明确承诺**
 *   · 平台差异（如 Linux 无硬件断点）通过 `capabilities()` **声明**
 *     而非硬性要求 —— 测试按能力**条件断言**
 *
 * ## 用法
 *   与平台层一起编译:
 *     cl /I include platform_conformance.c prot_platform_win.c
 *   退出码 0 = 契约合规；非 0 = 违规项数。
 *
 * ## 诚实边界
 *   · 本测试**不验证**平台层能否检测真实调试器（那需真实环境）
 *   · 只验证**接口语义**（返回值、边界、能力自洽、前后置条件）
 */

#include "protect/prot_platform.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0;
static int g_pass = 0;

static void ck(int cond, const char* what)
{
    if (cond) {
        g_pass++;
        printf("  [ok]   %s\n", what);
    } else {
        g_fail++;
        printf("  [FAIL] %s\n", what);
    }
}

int main(void)
{
    uint32_t caps;

    printf("=== 平台层契约测试 (platform conformance) ===\n");
    printf("platform = %d\n\n", (int)PROT_PLATFORM);

    /* ---- C1: capabilities 必须自洽 ---- */
    printf("--- C1: capabilities ---\n");
    caps = prot_plat_capabilities();
    ck(caps != 0, "C1.1 capabilities 非零（至少声明一项能力）");
    /* 只允许已定义的位 */
    {
        uint32_t known = PROT_PCAP_PAGE_PROTECT | PROT_PCAP_PAGE_ALLOC_RWX
                       | PROT_PCAP_DEBUG_DETECT | PROT_PCAP_PROC_ENUM
                       | PROT_PCAP_MODULE_ENUM | PROT_PCAP_TIME_HIRES
                       | PROT_PCAP_FILE_SELF;
        ck((caps & ~known) == 0, "C1.2 capabilities 不含未定义的位");
    }

    /* ---- C2: 页管理（仅当声明了 PAGE_PROTECT）---- */
    printf("\n--- C2: 页管理 ---\n");
    if (caps & PROT_PCAP_PAGE_PROTECT) {
        void* p = prot_plat_alloc(4096, PROT_PAGE_READWRITE);
        ck(p != NULL, "C2.1 alloc(4096, RW) 返回非 NULL");
        if (p != NULL) {
            /* 可写 */
            memset(p, 0xA5, 4096);
            ck(((unsigned char*)p)[0] == 0xA5
               && ((unsigned char*)p)[4095] == 0xA5,
               "C2.2 分配的内存可读写（首尾字节）");
            /* 改保护为只读 */
            ck(prot_plat_protect(p, 4096, PROT_PAGE_READ) == PROT_OK,
               "C2.3 protect(RW -> R) 返回 PROT_OK");
            /* 改回可写（否则 free 后可能出问题） */
            ck(prot_plat_protect(p, 4096, PROT_PAGE_READWRITE) == PROT_OK,
               "C2.4 protect(R -> RW) 返回 PROT_OK");
            ck(prot_plat_free(p, 4096) == PROT_OK,
               "C2.5 free 返回 PROT_OK");
        }
        /* 边界: 非法参数必须**明确失败**，不崩溃 */
        ck(prot_plat_protect(NULL, 0, PROT_PAGE_READ)
           != PROT_OK, "C2.6 protect(NULL,0) 明确失败（不崩溃）");
        ck(prot_plat_free(NULL, 0) != PROT_OK,
           "C2.7 free(NULL) 明确失败（不崩溃）");
        ck(prot_plat_alloc(0, PROT_PAGE_READWRITE) == NULL,
           "C2.8 alloc(0) 返回 NULL");
    } else {
        printf("  [skip] 未声明 PAGE_PROTECT，跳过 C2\n");
    }

    /* ---- C3: 调试原语（契约: 永不失败，字段置 0）---- */
    printf("\n--- C3: 调试原语 ---\n");
    {
        prot_debug_primitives dp;
        prot_status st;
        memset(&dp, 0xFF, sizeof(dp));   /* 先填垃圾，验证会被覆写 */
        st = prot_plat_debug_primitives(&dp);
        ck(st == PROT_OK, "C3.1 返回 PROT_OK（契约: 永不失败）");
        ck(dp.being_debugged == 0 || dp.being_debugged == 1,
           "C3.2 being_debugged 是 0/1（非垃圾值）");
        ck(dp.remote_debugger == 0 || dp.remote_debugger == 1,
           "C3.3 remote_debugger 是 0/1");
        ck(dp.hardware_supported == 0 || dp.hardware_supported == 1,
           "C3.4 hardware_supported 是 0/1");
        if (!dp.hardware_supported) {
            ck(dp.hardware_breakpoints == 0,
               "C3.5 不支持硬件断点时该字段为 0（不留垃圾）");
        }
        /* NULL 必须明确失败 */
        ck(prot_plat_debug_primitives(NULL) != PROT_OK,
           "C3.6 NULL 参数明确失败");
    }

    /* ---- C4: 进程枚举（容量语义）---- */
    printf("\n--- C4: 进程枚举 ---\n");
    if (caps & PROT_PCAP_PROC_ENUM) {
        prot_proc_info one[1];
        size_t total, got;
        memset(one, 0, sizeof(one));
        total = prot_plat_enum_processes(one, 1);
        ck(total >= 1, "C4.1 至少枚举到 1 个进程（自身）");
        ck(one[0].name[0] != '\0',
           "C4.2 容量为 1 时仍写入名称");
        ck(strlen(one[0].name) < sizeof(one[0].name),
           "C4.3 名称已终止（不溢出）");
        /* **契约**: 返回真实总数，不受容量影响（两段式用法的基础）。
         *
         * ⚠️ **不能用 `==` 断言**（2026-09-23 实测教训）:
         *   真实系统上**进程随时创建/退出** -> 两次调用的总数**可能不同**。
         *   实测: `capacity=1 -> 296, NULL/0 -> 298`（差 2）。
         *   **这是测试的问题，不是实现的问题** ——
         *   断言不应假设"枚举瞬间稳定"（那测的是**系统状态**，
         *   而非**平台层契约**）。
         *
         *   故改为**容差断言** + **关键区分**:
         *     若返回值真受容量限制 -> NULL/0 会返回 0 或 1（容量）
         *     实测返回 ~296 -> **证明不受容量限制**（这才是契约要点）
         */
        total = prot_plat_enum_processes(one, 1);
        got = prot_plat_enum_processes(NULL, 0);
        {
            size_t d = (total > got) ? (total - got) : (got - total);
            size_t tol = total / 20 + 8;    /* 5% + 8 的容差 */
            ck(d <= tol,
               "C4.4 out=NULL/capacity=0 返回真实总数（不受容量限制）");
            if (d > tol) {
                printf("         (capacity=1 -> %u, NULL/0 -> %u,"
                       " 差 %u > 容差 %u)\n",
                       (unsigned)total, (unsigned)got, (unsigned)d,
                       (unsigned)tol);
            }
            /* **关键**: 若真受容量限制，NULL/0 应返回 0 —— 实际远大于 0 */
            ck(got > 10,
               "C4.5 out=NULL/0 返回**真实总数**（远大于容量 0）");
        }
        /* 大容量枚举不应少于小容量（容差内）*/
        {
            static prot_proc_info big[4096];
            size_t nbig = prot_plat_enum_processes(
                big, sizeof(big) / sizeof(big[0]));
            ck(nbig + 8 >= total, "C4.6 大容量枚举结果 >= 小容量（容差内）");
            if (total < sizeof(big) / sizeof(big[0])) {
                /* 系统进程数未超容量 -> 应能取到全部 */
                ck(nbig + 8 >= total,
                   "C4.7 容量充足时取到全部进程");
            }
        }
    } else {
        printf("  [skip] 未声明 PROC_ENUM，跳过 C4\n");
    }

    /* ---- C5: 模块枚举 ---- */
    printf("\n--- C5: 模块枚举 ---\n");
    if (caps & PROT_PCAP_MODULE_ENUM) {
        static prot_module_info mods[512];
        size_t n = prot_plat_enum_modules(mods, 512);
        ck(n >= 1, "C5.1 至少枚举到 1 个模块（自身映像）");
        if (n >= 1) {
            ck(mods[0].base != NULL, "C5.2 首个模块有 base 地址");
            ck(mods[0].size > 0, "C5.3 首个模块 size > 0");
        }
    } else {
        printf("  [skip] 未声明 MODULE_ENUM，跳过 C5\n");
    }

    /* ---- C6: 单调时钟 ---- */
    printf("\n--- C6: 单调时钟 ---\n");
    if (caps & PROT_PCAP_TIME_HIRES) {
        uint64_t a = prot_plat_monotonic_ns();
        uint64_t b;
        volatile int i;
        ck(a != 0, "C6.1 返回非零");
        for (i = 0; i < 100000; i++) { /* 制造一点时间流逝 */ }
        b = prot_plat_monotonic_ns();
        ck(b >= a, "C6.2 **单调不减**（b >= a）");
    } else {
        printf("  [skip] 未声明 TIME_HIRES，跳过 C6\n");
    }

    /* ---- C7: 自身映像路径 ---- */
    printf("\n--- C7: 自身映像路径 ---\n");
    if (caps & PROT_PCAP_FILE_SELF) {
        char buf[1024];
        size_t n;
        memset(buf, 0, sizeof(buf));
        n = prot_plat_self_path(buf, sizeof(buf));
        ck(n > 0, "C7.1 返回正长度");
        ck(n < sizeof(buf), "C7.2 长度在容量内");
        ck(buf[0] != '\0', "C7.3 已写入非空路径");
        ck(strlen(buf) == n, "C7.4 返回长度与字符串长度一致");
        /* 容量为 0 / NULL 必须明确失败 */
        ck(prot_plat_self_path(NULL, 0) == 0, "C7.5 NULL/0 返回 0");
    } else {
        printf("  [skip] 未声明 FILE_SELF，跳过 C7\n");
    }

    printf("\n=== 平台层契约测试结果 ===\n");
    printf("通过 %d 项，失败 %d 项\n", g_pass, g_fail);
    if (g_fail == 0) {
        printf("[platform_conformance] PASS: 契约合规\n");
    } else {
        printf("[platform_conformance] FAIL: %d 项违规\n", g_fail);
    }
    return g_fail;
}
