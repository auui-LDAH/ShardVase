/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * integrity.c — 完整性校验 + 看门狗
 *
 * 对应契约 docs/CONTRACT.md §7。
 * check_self: 遍历 PE 节表, 对 .text/.rdata/.pdata 各取
 *             min(SizeOfRawData, VirtualSize) 字节做 CRC32, 与构建期烧录值
 *             比对 (A3: 覆盖"只校验 .text"的缺口 —— 改文件就死)。
 *             基址重定位 (ASLR) 会改写 .rdata 中的绝对指针字段 —— 文件侧
 *             (tools/hashpatch.py) 与运行侧 (本文件) 用同一掩码把这些字段
 *             归零后再算 CRC, 保证两遍一致。
 * 看门狗: 后台线程按 (±40% 抖动后的) 间隔循环 check_self, 失败按策略处理;
 *         (A5) 同线程周期重跑 prot_antidebug_scan, 命中关键项推同一策略。
 */

#include <stdlib.h>      /* malloc */
#include <string.h>

#include "protect/antidebug.h"
#include "protect/prot_noise.h"   /* W1.6 序言噪声 */
#include "protect/selfcrypt.h"
#include "protect/integrity.h"
#include "protect/prot_platform.h"   /* M3: 节表/重定位/IAT 统一抽象 */
#include "protect/prot_compiler.h"    /* M3: 节/分配宏 */

/* ## 诊断输出（2026-09-25，**opt-in**）
 *
 * **为什么 opt-in**: 打印"算出的 CRC / 烧录值 / 节范围"等于把
 * 完整性校验的**期望值与定位信息**免费交给攻击者 ——
 * 故默认关闭，仅排障时 `-DPROT_INTEGRITY_DEBUG` 启用。
 * （与 `selfcrypt.c` 的 `SC_DBG` 同一纪律。）
 */
#ifdef PROT_INTEGRITY_DEBUG
#include <stdio.h>
#define IDBG(...) fprintf(stderr, __VA_ARGS__)
#else
#define IDBG(...) ((void)0)
#endif

/* 烧录结构 (契约 §7.1; hashpatch.py 依赖其名字与布局) */
typedef struct prot_baked_crc {
    uint8_t magic[8];    /* 标记: PROTCRCP(.text)/PROTCRCD(.rdata)/PROTCRDP(.pdata) */
    uint32_t crc;        /* 段 CRC32, 构建期由 hashpatch.py 写入 */
    uint32_t reserved;   /* 保留 */
} prot_baked_crc;

/* A3: 专用只读段 .protcrc —— 烧录表自身不被任何段 CRC 覆盖 (避免自引用)。
 * 下标顺序必须与 tools/hashpatch.py 的 MAGICS 完全一致。 */
/* 阶段1(第二支柱): 节名每构建随机, 消除自解释线索 (见 tools/gen_sections.py) */
#include "protect/prot_sections.h"
PROT_SECTION_BEGIN(PROT_SEC_CRC, read)
PROT_ALLOCATE(PROT_SEC_CRC)
const prot_baked_crc g_prot_baked_crc[3] = {
    /* 阶段3(第二支柱): magic 每构建随机，消除 'PROTCRCP' 这类自解释标记。
     * 值来自 include/protect/prot_sections.h（默认）+ 生成头（随机覆盖）；
     * 写入侧 tools/hashpatch.py 从同一 JSON 读同样的值，两侧保持一致。
     * 注意: magic 仅作**写入侧定位标记**，运行期校验用的是本数组的符号
     *       顺序（下标 0/1/2 = .text/.rdata/.pdata），故随机化是安全的。 */
    { PROT_MAGIC_TEXT_BYTES,  0, 0 }, /* 0: .text  */
    { PROT_MAGIC_RDATA_BYTES, 0, 0 }, /* 1: .rdata */
    { PROT_MAGIC_PDATA_BYTES, 0, 0 }, /* 2: .pdata */
};
/*
 * 读取烧录 CRC。必须用 volatile 指针: 否则 /O2 会把 const 全局的
 * crc 字段常量折叠成 0, 运行期永远比对失败 (hashpatch.py 改的是文件字节,
 * 编译器根本不知道)。
 */
static uint32_t read_baked_crc(uint32_t idx) {
    const volatile prot_baked_crc* p =
        (const volatile prot_baked_crc*)&g_prot_baked_crc[0];
    return p[idx].crc;
}

/* --- 看门狗 --- */
static volatile int   g_wd_stop;    /* 停止标志 */
static void*          g_wd_thread;  /* 线程句柄 (NULL = 未运行) */
static prot_policy    g_wd_policy;  /* 校验失败时的策略 */
static uint32_t       g_wd_interval;/* 检查间隔 (ms) */
static volatile int   g_wd_fake;    /* FAKE 策略伪结果标志 */
static volatile int   g_wd_tamper;  /* CONTINUE 策略失败计数 */

/* W2 (WIN_ENHANCE): 周期回调 (demo 注册 N3 数据自校验等) */
static prot_wd_callback g_wd_cb = NULL;
static prot_plat_mutex g_wd_cb_lock;   /* C3: 平台无关锁 */

void prot_integrity_set_watchdog_callback(prot_wd_callback cb)
{
    PROT_NOISE();   /* W1.6 序言噪声 */
    /* C3: 锁需先初始化（幂等；pthread_mutex 重复 init 未定义，
     * 故用一个静态标志保证只 init 一次）*/
    static volatile int _lock_init = 0;
    if (!_lock_init) {
        (void)prot_plat_mutex_init(&g_wd_cb_lock);
        _lock_init = 1;
    }
    prot_plat_mutex_lock(&g_wd_cb_lock);
    g_wd_cb = cb;
    prot_plat_mutex_unlock(&g_wd_cb_lock);
}

/* A5: 间隔抖动用的 xorshift64 (种子派生自 QPC) */
static uint64_t wd_jitter_next(uint64_t rng)
{
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return rng;
}

/* ## M3（2026-09-25）: 加密函数的**间接调用**（修复 P5 回归）
 *
 * ### 问题
 *   `prot_antidebug_scan` **是 selfcrypt 加密目标**
 *   （`tools/selfcrypt_proto.py` 的 `EXT_TARGETS`）。
 *   而 watchdog 里**直接调用**它（下方 L162 附近）——
 *   这违反 P5 的规则（**加密函数不得被直接 call**）。
 *
 *   **M3 前 P5 侥幸 PASS**（编译器恰好把调用优化成了非 E8 形式）；
 *   M3 改变代码布局后**暴露了该既存问题**。
 *
 * ### 修法
 *   用 **volatile 函数指针**调用 —— 编译器**无法内联**、
 *   且生成 `call qword ptr [...]`（**不是直接 E8**），
 *   符合 P5 的设计意图（加密函数走间接途径）。
 *
 * ### 为什么不用 `PROT_INDIRECT_CALL`
 *   间接表由 `tools/indirect.py` 生成，条目来自 `modules.json` 的
 *   `indirect_slots`（L4-C 已改为可声明）。给表加项需同时改
 *   `indirect.h` 枚举 + `modules.json` —— **影响面更大**，
 *   且间接表是**宿主相关**的（见 L3 的发现）。
 *   => 本轮用**局部函数指针**（最小侵入）。
 *
 * ### 诚实边界
 *   这不是"真正的间接化"（不走随机化表）。
 *   真正的做法是把 `prot_antidebug_scan` 加入 `indirect_slots`。
 *   **本轮的修法只保证"不产生直接 E8 调用"**（满足 P5 的判据）。
 */
typedef prot_status (*prot_ad_scan_fn)(prot_antidebug_report*);
static prot_ad_scan_fn volatile g_ad_scan_fn = prot_antidebug_scan;

static void watchdog_thread(void* param) {
    uint64_t rng;
    prot_antidebug_report ad;

    (void)param;
    /* C3: QueryPerformanceCounter -> 平台层单调时钟 */
    rng = prot_plat_monotonic_ns() | 0x9E3779B97F4A7C15u;

    for (;;) {
        if (prot_plat_atomic_load(&g_wd_stop) != 0) {
            break; /* 停止标志已置位 */
        }
        /* A5: 检查间隔 ±40% 抖动: [interval*0.6, interval*1.4] */
        {
            uint64_t base_ms = (uint64_t)g_wd_interval * 60u / 100u;
            uint64_t span_ms = (uint64_t)g_wd_interval * 80u / 100u;
            rng = wd_jitter_next(rng);
            prot_plat_sleep_ms((uint32_t)(base_ms + rng % (span_ms + 1u)));
        }
        if (prot_selfcrypt_enter(PROT_SELFCRYPT_GROUP_EXT) != PROT_OK) {
            /* 解密失败: 按 tamper 策略处理 */
            switch (g_wd_policy) {
                case PROT_POLICY_EXIT:
                    prot_plat_terminate(PROT_EXIT_TAMPERED);
                    break;
                default:
                    (void)prot_plat_atomic_increment(&g_wd_tamper);
                    break;
            }
            continue;
        }
        if (prot_integrity_check_self() != PROT_OK) {
            switch (g_wd_policy) {
                case PROT_POLICY_EXIT:
                    prot_plat_terminate(PROT_EXIT_TAMPERED);
                    break; /* 失败则进程已终止 */
                case PROT_POLICY_FAKE:
                    (void)prot_plat_atomic_exchange(&g_wd_fake, 1);
                    break;
                case PROT_POLICY_CONTINUE:
                default:
                    (void)prot_plat_atomic_increment(&g_wd_tamper);
                    break;
            }
        }
        /* A5: 反附加周期复查 —— 驻留期调试器/探测不再只有启动一次检测
         *
         * ## T11 修复（2026-10-03）: 必须留在 `enter(EXT)` 窗口**之内**
         *
         *   缺陷: 本块原先放在 `prot_selfcrypt_leave(PROT_SELFCRYPT_GROUP_EXT)`
         *   **之后**。而 `g_ad_scan_fn` 指向 `prot_antidebug_scan` ——
         *   它**本身是 selfcrypt 加密目标**（`EXT_TARGETS`，组 1）。
         *   leave 已把组 1 全部重新加密, 于是这次调用执行的是**磁盘密文**。
         *
         *   为什么本机长期没暴露: 8 个条目共用同一个硬编码 key0
         *   (`tools/selfcrypt_proto.py` 的 seed), 密钥流与构建无关 ->
         *   密文首字节恒 = `明文首字节 ^ 0x8f`。本机 MSVC 14.44 下
         *   `prot_antidebug_scan` 明文首字节 = 0x4C(C4 帧序言) ->
         *   密文首字节 = 0xC3 = `ret` -> 调用**静默空转**(A5 复查失效, 但不崩)。
         *   CI 的 MSVC 14.51 下序言字节不同 -> 密文首字节非 `ret` ->
         *   执行垃圾指令 -> `0xC0000005`, 表现为 e2e `T11 watchdog-stable`
         *   以 `exit=3221225477` 失败。
         *
         *   修法: 把本块移到 `leave(EXT)` **之前**（即与 `check_self` 同窗口）。
         *   注: `check_iat` / `check_guards` **不是**加密目标, 留在窗口外无妨;
         *   而所有加密目标（`prot_vm_blob_load` / `prot_license_verify` /
         *   `prot_integrity_check_self` / `prot_antidebug_scan`）都必须在
         *   各自的 enter/leave 窗口内被调用。
         *
         *   遗留风险（**诚实边界**）: 该约束目前**无静态门禁覆盖** ——
         *   P5 只判"加密函数不得被直接 E8 调用", 不判"调用点是否在窗口内"。
         *   间接调用绕过了 P5 的字面判据。 */
        if (g_ad_scan_fn != NULL && g_ad_scan_fn(&ad) == PROT_OK &&
            prot_antidebug_detected_multi(&ad) != 0u) {
            switch (g_wd_policy) {
                case PROT_POLICY_EXIT:
                    prot_plat_terminate(PROT_EXIT_DEBUG_DETECTED);
                    break;
                case PROT_POLICY_FAKE:
                    (void)prot_plat_atomic_exchange(&g_wd_fake, 1);
                    break;
                case PROT_POLICY_CONTINUE:
                default:
                    (void)prot_plat_atomic_increment(&g_wd_tamper);
                    break;
            }
        }
        prot_selfcrypt_leave(PROT_SELFCRYPT_GROUP_EXT);
        /* G2 补洞: 运行期 IAT 改写 (hook 导入表) 周期复查 ——
         * 文件级 CRC 不覆盖 loader 写入的 IAT, 这里快照比对 detect。 */
        if (prot_integrity_check_iat() != PROT_OK) {
            switch (g_wd_policy) {
                case PROT_POLICY_EXIT:
                    prot_plat_terminate(PROT_EXIT_TAMPERED);
                    break;
                case PROT_POLICY_FAKE:
                    (void)prot_plat_atomic_exchange(&g_wd_fake, 1);
                    break;
                case PROT_POLICY_CONTINUE:
                default:
                    (void)prot_plat_atomic_increment(&g_wd_tamper);
                    break;
            }
        }
        /* R3.2-b: **判定点序言快照**周期复查 ——
         *   段 CRC 先清零 selfcrypt 区 -> 落在该区的判定点改它**不影响 CRC**
         *   （R3.2-a 实测: ③ check_self / ④ license_verify 均在区内）。
         *   本校验不依赖 CRC -> 对"落掩码区"与"重算 CRC"**均有效**。
         *   （策略处理沿用既有三分支；刻意重复以**最小侵入**，重构另议。） */
        if (prot_integrity_check_guards() != PROT_OK) {
            switch (g_wd_policy) {
                case PROT_POLICY_EXIT:
                    prot_plat_terminate(PROT_EXIT_TAMPERED);
                    break;
                case PROT_POLICY_FAKE:
                    (void)prot_plat_atomic_exchange(&g_wd_fake, 1);
                    break;
                case PROT_POLICY_CONTINUE:
                default:
                    (void)prot_plat_atomic_increment(&g_wd_tamper);
                    break;
            }
        }
        /* A5 反附加周期复查**已上移**到 leave(EXT) 之前 —— 见上方 T11 修复注释。
         * （`prot_antidebug_scan` 是组 1 加密目标, 必须在解密窗口内调用。） */
        /* W2 (WIN_ENHANCE): 周期回调 (demo N3 数据自校验等) */
        {
            prot_wd_callback cb;
            prot_plat_mutex_lock(&g_wd_cb_lock);   /* 平台层无读写锁；本用途只用独占 */
            cb = g_wd_cb;
            prot_plat_mutex_unlock(&g_wd_cb_lock);
            if (cb != NULL && cb() != PROT_OK) {
                switch (g_wd_policy) {
                    case PROT_POLICY_EXIT:
                        prot_plat_terminate(PROT_EXIT_TAMPERED);
                        break;
                    case PROT_POLICY_FAKE:
                        (void)prot_plat_atomic_exchange(&g_wd_fake, 1);
                        break;
                    case PROT_POLICY_CONTINUE:
                    default:
                        (void)prot_plat_atomic_increment(&g_wd_tamper);
                        break;
                }
            }
        }
    }
    return;
}

/* --- 完整性校验 (A3) --- */
/* M3（2026-09-25）: **删除** `g_crc_targets` 硬编码表
 *
 * 原表是 PE 节名: `{ ".text", 0 }, { ".rdata", 1 }, { ".pdata", 2 }`。
 * M3 改为 `prot_plat_crc_target_name(j)` 由**平台层**提供:
 *   Windows: .text / .rdata  / .pdata
 *   Linux:   .text / .rodata / .eh_frame   <- **名字不同**
 *
 * => 该表成为**死代码**（GCC 的 `-Wunused-const-variable` 抓到），
 *    故删除 —— 保留会让读者误以为节名是跨平台固定的。
 */

/* M3（2026-09-25）: 改为比较**平台无关的节名**
 *
 * 原实现比较 `IMAGE_SECTION_HEADER->Name`（固定 8 字节，PE 专有）。
 * 新实现比较 `prot_section_view.name`（NUL 结尾字符串）——
 * 由平台层给出（PE: 8 字节节名；ELF: 节名字符串表）。
 */
static int sec_name_eq(const prot_section_view* sec, const char* name)
{
    if (sec == NULL || name == NULL)
        return 0;
    return (strcmp(sec->name, name) == 0);
}

/* 把 [rva, rva+len) 内会被加载器/重定位改写的字节在 mask 中置 0xFF (A3):
 *   1. 基址重定位字段: type 10 (DIR64) 8 字节 / type 3 (HIGHLOW) 4 字节
 *   2. IAT (目录项 12): loader 启动时写入已解析的导入函数地址
 * 规则与 tools/hashpatch.py 完全一致, 保证文件侧与运行侧两遍 CRC 相同。 */
/* M3（2026-09-25）: 改为**平台无关**的掩码构建
 *
 * ## 原实现（PE 专有）
 *   遍历 `.reloc`（`IMAGE_BASE_RELOCATION`）+ 查 IAT 数据目录 ——
 *   61 个 `IMAGE_*` 符号中的绝大部分。
 *
 * ## 新实现
 *   调平台层:
 *     · `prot_plat_reloc_ranges()` —— 会被 loader 改写的区间
 *     · `prot_plat_iat_range()`    —— IAT / GOT 区间
 *   本函数只负责"把区间折进掩码"。
 *
 * ## 行为等价性
 *   区间来源变了（PE 解析 -> 平台层），但**折进掩码的规则不变**。
 *   Windows 平台层的实现是**原 PE 解析逻辑的搬迁**（逐字保留）——
 *   故 Windows 行为**完全一致**。
 */
static void build_reloc_mask(uint8_t* base, uint8_t* mask,
                             uint32_t rva, uint32_t len)
{
    prot_range rng[4096];
    prot_range iat;
    size_t n, i;
    (void)base;

    /* IAT / GOT: loader 会写入导入地址
     *
     * ## C 阶段修正（2026-09-25）: 改用**多区间**
     *   ELF 有 `.got` **与** `.got.plt` 两个 GOT 类节，**两者都被 loader
     *   填充**。原用单区间接口 -> 只掩一个 -> **与构建侧口径不一致** ->
     *   运行时报"完整性校验失败"（实测）。
     *   => 用 `prot_plat_iat_ranges` 掩**全部**。
     */
    {
        prot_range iats[8];
        size_t ni = prot_plat_iat_ranges(iats,
                                         sizeof(iats) / sizeof(iats[0]));
        size_t k;
        (void)iat;
        for (k = 0u; k < ni && k < sizeof(iats) / sizeof(iats[0]); k++) {
            if (iats[k].rva >= rva &&
                iats[k].rva + iats[k].size <= (size_t)rva + len)
                memset(mask + (iats[k].rva - rva), 0xFF, iats[k].size);
        }
    }

    /* 重定位 / .rela.dyn */
    n = prot_plat_reloc_ranges(rng, sizeof(rng) / sizeof(rng[0]));
    for (i = 0u; i < n && i < sizeof(rng) / sizeof(rng[0]); i++) {
        if (rng[i].rva >= rva && rng[i].rva + rng[i].size <= (size_t)rva + len)
            memset(mask + (rng[i].rva - rva), 0xFF, rng[i].size);
    }
}

/* N1 (D1b): 把 selfcrypt 加密段 (从 .protcry meta 读 rva/len) 在 mask 中
 * 置 0xFF —— 加密态(文件)与解密态(运行)该段不参与 .text CRC, 两侧一致。
 * 规则与 tools/selfcrypt_proto.py 的 MASK 输出一致。
 * meta entry 24B (S1 组字段): rva u32 | len u32 | key0 u64 | crc u32 | group u32 */
static void build_selfcrypt_mask(uint8_t* mask, uint32_t rva, uint32_t len)
{
    extern uint8_t g_prot_selfcrypt_blob[];
    const uint8_t* blob = g_prot_selfcrypt_blob;
    uint32_t n;
    uint32_t i;

    memcpy(&n, blob, 4u);
        if (n == 0u || n > 16u)
        return;
    for (i = 0u; i < n; i++) {
        uint32_t s_rva, s_len;
        memcpy(&s_rva, blob + 4u + i * 24u, 4u);
        memcpy(&s_len, blob + 4u + i * 24u + 4u, 4u);
                if (s_rva >= rva && s_rva + s_len <= rva + len)
            memset(mask + (s_rva - rva), 0xFF, s_len);
    }
}

/* 流式 CRC: 掩码归零的字节按 0 参与计算 (与整段明文 CRC 等价时跳过掩码字节) */
static uint32_t section_crc_masked(uint8_t* base, const uint8_t* mask,
                                   uint32_t off, uint32_t len)
{
    uint32_t crc = prot_crc32_init();
    uint32_t i;
    for (i = 0u; i < len; i++)
        crc = prot_crc32_step(crc, (uint8_t)(base[off + i] & ~mask[i]));
    return prot_crc32_done(crc);
}

prot_status prot_integrity_check_self(void) {
    PROT_NOISE();   /* W1.6 序言噪声 */
    /* M3（2026-09-25）: 原实现解析 PE 头（`IMAGE_DOS_HEADER` ->
     * `IMAGE_NT_HEADERS` -> `IMAGE_FIRST_SECTION`）——
     * 新实现调 `prot_plat_enum_sections()`（PE 节表 / ELF 节表）。
     *
     * **目标节名也按平台给**（`prot_plat_crc_target_name`）:
     *   Windows: .text / .rdata / .pdata
     *   Linux:   .text / .rodata / .eh_frame   <- **名字不同！**
     */
    static prot_section_view secs[64];
    /* ## ⚠️ M3 实测回归（2026-09-25）: **必须保持栈上分配**
     *
     *   我在 M3 一度改成 `static uint8_t mask[0x40000];`（怕 256KB 栈溢出）
     *   -> **门禁立即抓到回归**:
     *     · `P5 indirect-no-direct-call` FAIL（间接化失效）
     *     · `T11 watchdog-stable` FAIL（exit=219）
     *
     *   **根因**: 256KB 的 static 缓冲进入 `.bss`
     *   -> **内存布局变化** -> 间接化表/页关系受影响。
     *
     *   => **恢复栈上分配**（与原实现一致）。
     *      原实现能工作，说明 256KB 栈**在本项目实际栈大小下是安全的**
     *      （Windows 默认 1MB 栈；watchdog 线程与主线程各自独立）。
     */
    uint8_t mask[0x40000];  /* 段 CRC 上限 256KB（**栈上**，与原实现一致）*/
    uint8_t* base;
    size_t nsec, i;
    uint32_t j;
    uint32_t found = 0u;

    base = (uint8_t*)prot_plat_self_base();
    IDBG("[IDBG] check_self: base=%p\n", (void*)base);
    if (base == NULL)
        return PROT_ERR_INTEGRITY;

    nsec = prot_plat_enum_sections(secs, sizeof(secs) / sizeof(secs[0]));
    IDBG("[IDBG] check_self: nsec=%u (capacity=%u)\n",
         (unsigned)nsec, (unsigned)(sizeof(secs) / sizeof(secs[0])));
    if (nsec == 0u)
        return PROT_ERR_INTEGRITY;
    {
        size_t _k;
        for (_k = 0u; _k < nsec && _k < 6u; _k++)
            IDBG("[IDBG]   sec[%u] name=%s rva=0x%x size=%u\n",
                 (unsigned)_k, secs[_k].name,
                 (unsigned)secs[_k].rva, (unsigned)secs[_k].size);
    }

    for (j = 0u; j < 3u; j++)
        IDBG("[IDBG]   target[%u] = %s\n", (unsigned)j,
             prot_plat_crc_target_name(j) ? prot_plat_crc_target_name(j)
                                          : "(null)");
    for (i = 0u; i < nsec && i < sizeof(secs) / sizeof(secs[0]); i++) {
        for (j = 0u; j < 3u; j++) {
            uint32_t crc;
            const char* tname = prot_plat_crc_target_name(j);
            uint32_t len;
            if (tname == NULL)
                continue;
            if (!sec_name_eq(&secs[i], tname))
                continue;
            len = (uint32_t)secs[i].size;
            if (len == 0u) {
                found |= (1u << j);   /* 空段视为通过 */
                break;
            }
            if (len > sizeof(mask))
                return PROT_ERR_INTEGRITY;
            memset(mask, 0, len);
            build_reloc_mask(base, mask, (uint32_t)secs[i].rva, len);
            build_selfcrypt_mask(mask, (uint32_t)secs[i].rva, len); /* N1 D1b */
            crc = section_crc_masked(base, mask, (uint32_t)secs[i].rva, len);
            IDBG("[IDBG] sec=%s rva=0x%x len=%u got=0x%08x want=0x%08x %s\n",
                 tname, (unsigned)secs[i].rva, (unsigned)len,
                 (unsigned)crc, (unsigned)read_baked_crc(j),
                 (crc == read_baked_crc(j)) ? "OK" : "**MISMATCH**");
            if (crc != read_baked_crc(j)) {
                return PROT_ERR_INTEGRITY;
            }
            found |= (1u << j);
            break;
        }
    }

    if ((found & 1u) == 0u) {
        return PROT_ERR_INTEGRITY; /* 至少 .text 必须存在且被校验 */
    }
    return PROT_OK;
}

PROT_CODE_SEG(PROT_SEC_XEC)  /* 辅助函数与加密段分页 (S1 技术债, 2026-08-30) */
/* --- 运行期 IAT 完整性 (G2 补洞, ATTACK_DRILL2) ---
 * loader 启动时写入 IAT 导入地址 (合法); 攻击者运行期改写 IAT (hook 导入
 * 表) 不在文件级 CRC 覆盖内。这里快照 IAT 初始值, 周期比对 detect 改写。
 * 首次调用建立快照; 之后逐项比对。使用 InitOnce 保证线程安全单次初始化。 */
/* M3（2026-09-25）: IAT 快照/校验改为**平台层驱动**
 *
 * ## 原实现（PE 专有）
 *   用 `InitOnce` + `IMAGE_DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_IAT]`
 *   取 IAT 区间 -> 快照 -> 逐字节比对。
 *
 * ## 新实现
 *   `prot_plat_iat_range()` 给出 IAT/GOT 区间（PE: 数据目录 12；
 *   ELF: `.got.plt`/`.got`），其余逻辑不变。
 *
 *   **线程安全**: 用平台层 mutex（原用 `InitOnce` —— 那是 Windows 专有）。
 */
static prot_plat_mutex g_iat_lock;
static volatile int    g_iat_lock_ready = 0;
static volatile int    g_iat_ready = 0;
static uint8_t*        g_iat_snap = NULL;   /* IAT 快照 */
static uint32_t        g_iat_snap_len = 0u;

static void iat_snapshot_init(void)
{
    prot_range iat;
    uint8_t* base;

    if (g_iat_ready)
        return;

    /* 一次性初始化锁（幂等，可重复调用）*/
    if (!g_iat_lock_ready) {
        (void)prot_plat_mutex_init(&g_iat_lock);
        g_iat_lock_ready = 1;
    }

    prot_plat_mutex_lock(&g_iat_lock);
    if (g_iat_ready) {          /* 双重检查 */
        prot_plat_mutex_unlock(&g_iat_lock);
        return;
    }

    base = (uint8_t*)prot_plat_self_base();
    if (base == NULL || !prot_plat_iat_range(&iat)) {
        g_iat_ready = 1;        /* 无 IAT -> 视为完成（check 会跳过）*/
        prot_plat_mutex_unlock(&g_iat_lock);
        return;
    }
    g_iat_snap_len = (uint32_t)iat.size;
    g_iat_snap = (uint8_t*)malloc(g_iat_snap_len);
    if (g_iat_snap == NULL) {
        g_iat_snap_len = 0u;
        g_iat_ready = 1;
        prot_plat_mutex_unlock(&g_iat_lock);
        return;
    }
    memcpy(g_iat_snap, base + iat.rva, g_iat_snap_len);
    g_iat_ready = 1;
    prot_plat_mutex_unlock(&g_iat_lock);
}

prot_status prot_integrity_check_iat(void)
{
    PROT_NOISE();   /* W1.6 序言噪声 */
    prot_range iat;
    uint8_t* base;
    uint32_t i;

    iat_snapshot_init();
    if (!g_iat_ready || g_iat_snap_len == 0u) {
        /*
         * 快照未建立: 无 IAT（纯静态）或 malloc 失败 -> 视为 OK。
         * —— watchdog 不因资源问题误杀（与 MDL 完整性语义一致）。
         */
        return PROT_OK;
    }

    base = (uint8_t*)prot_plat_self_base();
    if (base == NULL)
        return PROT_ERR_INTEGRITY;
    if (!prot_plat_iat_range(&iat))
        return PROT_ERR_INTEGRITY;   /* 快照有时无 -> 异常 */
    if ((uint32_t)iat.size != g_iat_snap_len)
        return PROT_ERR_INTEGRITY;   /* IAT 目录异常 */

    /* 逐项比对: 运行期改写 (hook) 会与快照不一致 */
    for (i = 0u; i < g_iat_snap_len; i++) {
        if (((volatile uint8_t*)base)[iat.rva + i] != g_iat_snap[i]) {
            return PROT_ERR_INTEGRITY;
        }
    }
    return PROT_OK;
}

/* --- R3.2-b (2026-09-29): **判定点序言快照校验** ---
 *
 * ## 与 IAT 快照（G2）的关系
 *   同一模式: "启动快照 + 运行期逐字节比对"。
 *   IAT 版防**导入表改写**；本版防**判定函数头 patch**（DRILL7 步骤 4）。
 *
 * ## 为什么必须做（R3.2-a 实测, 见 docs/DECISION_REDUNDANCY_PLAN.md §9）
 *   `prot_integrity_check_self` 与 `prot_license_verify` **落在 selfcrypt
 *   掩码区内** -> 段 CRC 先清零该区 -> **改它们不影响 CRC**。其中
 *   `check_self` 更是"**校验器不在自己覆盖范围内**"的自我指涉缺口。
 *   本校验**不依赖 CRC** -> 两种规避（落掩码区 / 重算 CRC）**均无效**。
 *
 * ## 覆盖范围（第 1 组）
 *   ① `prot_antidebug_detected`（DRILL7 步骤 4 实证的要害）
 *   ①b R3.2-c 的 3 个等价副本（patch 单个副本不再足够 -> 每个副本各自被守护）
 *   ①c R3.2-c 的聚合器 `prot_antidebug_detected_multi`（宿主实际调用的入口）
 *   ③ `prot_integrity_check_self`（自我指涉缺口）
 *   本模块 deps = [antidebug, selfcrypt] -> **无新增跨模块依赖**。
 *   ② dbiguard / ④ license / ⑤ vmdetect 需注册式扩展（后续组）。
 */
#define PROT_GUARD_SNAP_LEN 16u

typedef struct prot_guard_entry {
    const char*  name;      /* 仅用于诊断 */
    const void*  fn;
} prot_guard_entry;

/* 判定点表（**函数地址编译期已知**） */
/* 编译期已知的判定点（integrity 自身 + antidebug，deps 内） */
static const prot_guard_entry g_guard_static[] = {
    { "prot_antidebug_detected",       (const void*)&prot_antidebug_detected },
    { "prot_antidebug_detected_r2",    (const void*)&prot_antidebug_detected_r2 },
    { "prot_antidebug_detected_r3",    (const void*)&prot_antidebug_detected_r3 },
    { "prot_antidebug_detected_r4",    (const void*)&prot_antidebug_detected_r4 },
    { "prot_antidebug_detected_multi", (const void*)&prot_antidebug_detected_multi },
    { "prot_integrity_check_self",     (const void*)&prot_integrity_check_self },
};
#define PROT_GUARD_N \
    (sizeof(g_guard_static) / sizeof(g_guard_static[0]))

/* R3.2-b 第2组: **运行期注册**的判定点（宿主在 #ifdef PROT_MOD_<X> 下登记）
 *
 * 为什么需要: license / dbiguard / vmdetect 的 deps 均为 []，
 * `integrity.c` 直接引用会**破坏组合裁剪**（minimal 不含它们）。
 * 注册式让 integrity 不引用任何外部模块符号（见 integrity.h 的说明）。
 */
static prot_guard_entry g_guard_dyn[PROT_GUARD_CAPACITY];
static volatile int    g_guard_dyn_n = 0;

static uint8_t      g_guard_snap[PROT_GUARD_N + PROT_GUARD_CAPACITY]
                                [PROT_GUARD_SNAP_LEN];
static volatile int g_guard_ready = 0;
static prot_plat_mutex g_guard_lock;
static volatile int g_guard_lock_ready = 0;
/* 累计命中（诊断/自检用）—— 类型必须与 `prot_plat_atomic_*` 的
 * `volatile int*` 一致（否则 MSVC **C4057** -> /WX 致命；实测踩）。*/
static volatile int g_guard_hits = 0;

/* R3.2-b 第2组: **运行期登记**判定点（在首次 check_guards 之前调用）。
 *
 * 失败语义（**明确失败，不静默丢弃**）:
 *   · fn == NULL            -> PROT_ERR_INVALID_ARG
 *   · 容量已满              -> PROT_ERR_INVALID_ARG（**不覆盖已有项**）
 *   · 已建立快照后登记      -> PROT_ERR_INVALID_ARG
 *     （快照已固定，后登记的项**永远比对自己** = 恒真 -> 必须拒绝）
 *   · 重复登记同一 fn       -> PROT_OK（幂等）
 */
prot_status prot_integrity_register_guard(const char* name, const void* fn)
{
    int i;

    if (fn == NULL)
        return PROT_ERR_INVALID_ARG;
    /* 快照已建立 -> 拒绝（否则新项形同虚设） */
    if (g_guard_ready)
        return PROT_ERR_INVALID_ARG;

    /* 幂等: 已登记过同一函数指针则直接成功 */
    for (i = 0; i < g_guard_dyn_n; i++) {
        if (g_guard_dyn[i].fn == fn)
            return PROT_OK;
    }
    if (g_guard_dyn_n >= (int)PROT_GUARD_CAPACITY)
        return PROT_ERR_INVALID_ARG;   /* **明确失败**，不静默丢弃 */

    g_guard_dyn[g_guard_dyn_n].name = name;
    g_guard_dyn[g_guard_dyn_n].fn = fn;
    g_guard_dyn_n++;
    return PROT_OK;
}

static void guard_snapshot_init(void)
{
    uint32_t i, j;

    if (g_guard_ready)
        return;
    if (!g_guard_lock_ready) {
        (void)prot_plat_mutex_init(&g_guard_lock);
        g_guard_lock_ready = 1;
    }
    prot_plat_mutex_lock(&g_guard_lock);
    if (g_guard_ready) {                    /* 双重检查 */
        prot_plat_mutex_unlock(&g_guard_lock);
        return;
    }
    /* 编译期静态项 */
    for (i = 0u; i < (uint32_t)PROT_GUARD_N; i++) {
        /* ## 为什么两步转换（实测 C4057 -> /WX 致命）
         *   `(const volatile uint8_t*)<函数指针>` 会触发
         *   MSVC **C4057**（基类型间接程度差异）-> 构建失败。
         *   故: 先转 `const uint8_t*`（去 volatile），
         *       再用 `*(volatile const uint8_t*)` **逐字节易变读** ——
         *       **保留"防编译器优化成常量"的语义**（那才是校验不恒真的关键）。*/
        const uint8_t* p = (const uint8_t*)(const void*)g_guard_static[i].fn;
        if (p == NULL)
            continue;
        for (j = 0u; j < PROT_GUARD_SNAP_LEN; j++)
            g_guard_snap[i][j] = *(const volatile uint8_t*)(p + j);
    }
    /* R3.2-b 第2组: **运行期注册项**（紧接静态项之后） */
    for (i = 0u; i < (uint32_t)g_guard_dyn_n; i++) {
        const uint8_t* p = (const uint8_t*)(const void*)g_guard_dyn[i].fn;
        if (p == NULL)
            continue;
        for (j = 0u; j < PROT_GUARD_SNAP_LEN; j++)
            g_guard_snap[PROT_GUARD_N + i][j] =
                *(const volatile uint8_t*)(p + j);
    }
    g_guard_ready = 1;
    prot_plat_mutex_unlock(&g_guard_lock);
}

prot_status prot_integrity_check_guards(void)
{
    uint32_t i, j;

    PROT_NOISE();   /* W1.6 序言噪声 */

    guard_snapshot_init();

    uint32_t ntot = (uint32_t)PROT_GUARD_N + (uint32_t)g_guard_dyn_n;

    for (i = 0u; i < ntot; i++) {
        /* 同快照侧: 两步转换避免 C4057；`volatile const` 读**防优化成常量**
         * （否则编译器可把序言读折叠 -> 校验恒真 = 假防护）。 */
        const prot_guard_entry* e = (i < (uint32_t)PROT_GUARD_N)
                                    ? &g_guard_static[i]
                                    : &g_guard_dyn[i - (uint32_t)PROT_GUARD_N];
        const uint8_t* p = (const uint8_t*)(const void*)e->fn;
        if (p == NULL)
            continue;
        for (j = 0u; j < PROT_GUARD_SNAP_LEN; j++) {
            uint8_t cur = *(const volatile uint8_t*)(p + j);
            if (cur != g_guard_snap[i][j]) {
                (void)prot_plat_atomic_increment(&g_guard_hits);
                IDBG("[IDBG] guard MISMATCH %s off=%u got=%02x want=%02x\n",
                     e->name, (unsigned)j,
                     (unsigned)cur, (unsigned)g_guard_snap[i][j]);
                return PROT_ERR_INTEGRITY;
            }
        }
    }
    return PROT_OK;
}

/* R3.2-b 第2组修复 (2026-09-29): **主动预热判定点快照**
 *
 * ## 为什么必须在这里预热（实测缺陷）
 *   原实现惰性建立快照（首次 `prot_integrity_check_guards()` 时），
 *   而该调用发生在**看门狗线程首轮**（~3-5s，±40% 抖动）。
 *   => 攻击者在首轮之前 patch，快照就会**拍到已 patch 的字节**
 *      -> 比对恒真 -> **假防护**。
 *
 *   实测证据（5 判定点逐一负向验证）:
 *     `prot_integrity_check_self` / `prot_license_verify`（**均在 selfcrypt
 *     掩码区内，段 CRC 抓不到**）patch 后**未被守卫抓到**。
 *
 * ## 为什么选这个时机
 *   调用者约定"登记必须在 start_watchdog 之前完成" ->
 *   此处快照必然**已包含全部登记项**，且看门狗尚未运行 -> 窗口最小。
 *
 * ## 残余窗口（**诚实边界**）
 *   "进程启动 -> start_watchdog" 之间仍可被 patch（该窗口通常 <1s，
 *   且此时进程尚未进入受保护逻辑）。记入 known_limits。
 */
static void guard_prime_snapshot(void);

prot_status prot_integrity_start_watchdog(prot_policy pol, uint32_t interval_ms) {
    /* R3.2-b 修复: **预热快照** —— 必须在看门狗首轮之前建立，
     * 否则"首轮前 patch"会被快照吸收（实测缺陷，见上方注释）。 */
    guard_prime_snapshot();
    PROT_NOISE();   /* W1.6 序言噪声 */
    if (interval_ms == 0) {
        return PROT_ERR_INVALID_ARG;
    }
    if (pol != PROT_POLICY_CONTINUE && pol != PROT_POLICY_EXIT &&
        pol != PROT_POLICY_FAKE) {
        return PROT_ERR_INVALID_ARG;
    }
    if (g_wd_thread != NULL) {
        return PROT_OK; /* 已在运行, 保持现状 */
    }

    (void)prot_plat_atomic_exchange(&g_wd_stop, 0);
    g_wd_policy = pol;
    g_wd_interval = interval_ms;

    /* G2: watchdog 启动时立即建立 IAT 快照 (早于攻击者可改写窗口)。
     * 若延迟到首轮循环 (3-7s 抖动后) 才快照, 攻击者可在启动早期改写
     * IAT 使快照记录被改值 -> 后续比对恒一致 -> 绕过。 */
    (void)prot_integrity_check_iat();

    /* M3（2026-09-25）: CreateThread -> 平台层 */
    if (!prot_plat_thread_create(watchdog_thread, NULL, &g_wd_thread)) {
        g_wd_thread = NULL;
        return PROT_ERR_INTERNAL;
    }
    return PROT_OK;
}

prot_status prot_integrity_stop_watchdog(void) {
    PROT_NOISE();   /* W1.6 序言噪声 */

    if (g_wd_thread == NULL) {
        return PROT_OK; /* 幂等 */
    }
    (void)prot_plat_atomic_exchange(&g_wd_stop, 1);

    /* ## ⚠️ 平台差异（**如实标注**，2026-09-25）
     *
     *   **Windows**: 原实现 `WaitForSingleObject(h, INFINITE)` ——
     *     置停止标志后**等待线程真正退出**再返回。
     *   **Linux**: 线程是 **detached** 的（无 join 句柄）——
     *     置标志后**立即返回**；线程会在下次循环检查时自行退出。
     *
     *   **影响评估**:
     *     · `g_iat_lock` 保护快照/校验 -> **无数据竞争**
     *     · 调用方（demo）在 stop 后立即退出 -> 差异**不可观测**
     *
     *   => 接口语义保持 `PROT_OK`，但**该差异必须被记录**，
     *      否则读者会误以为两个平台完全一致。
     */
    g_wd_thread = NULL;
    return PROT_OK;
}

/* 预热: 建立快照（幂等；已建立则无操作）。定义在 start_watchdog 之后，
 * 但上方有前向声明 —— 保持"预热点"紧邻看门狗启动，便于阅读。 */
static void guard_prime_snapshot(void)
{
    (void)prot_integrity_check_guards();   /* 首次调用即建立快照 */
}
