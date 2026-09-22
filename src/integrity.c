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

#include <windows.h>
#include <stdlib.h>      /* malloc */
#include <string.h>

#include "protect/antidebug.h"
#include "protect/selfcrypt.h"
#include "protect/integrity.h"

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
#pragma section(PROT_SEC_CRC, read)
__declspec(allocate(PROT_SEC_CRC))
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
static volatile LONG  g_wd_stop;    /* 停止标志 */
static HANDLE         g_wd_thread;  /* 线程句柄 (NULL = 未运行) */
static prot_policy    g_wd_policy;  /* 校验失败时的策略 */
static uint32_t       g_wd_interval;/* 检查间隔 (ms) */
static volatile LONG  g_wd_fake;    /* FAKE 策略伪结果标志 */
static volatile LONG  g_wd_tamper;  /* CONTINUE 策略失败计数 */

/* W2 (WIN_ENHANCE): 周期回调 (demo 注册 N3 数据自校验等) */
static prot_wd_callback g_wd_cb = NULL;
static SRWLOCK          g_wd_cb_lock = SRWLOCK_INIT;

void prot_integrity_set_watchdog_callback(prot_wd_callback cb)
{
    AcquireSRWLockExclusive(&g_wd_cb_lock);
    g_wd_cb = cb;
    ReleaseSRWLockExclusive(&g_wd_cb_lock);
}

/* A5: 间隔抖动用的 xorshift64 (种子派生自 QPC) */
static uint64_t wd_jitter_next(uint64_t rng)
{
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return rng;
}

static DWORD WINAPI watchdog_thread(LPVOID param) {
    LARGE_INTEGER qpc;
    uint64_t rng;
    prot_antidebug_report ad;

    (void)param;
    QueryPerformanceCounter(&qpc);
    rng = (uint64_t)qpc.QuadPart | 0x9E3779B97F4A7C15u;

    for (;;) {
        if (InterlockedCompareExchange(&g_wd_stop, 0, 0) != 0) {
            break; /* 停止标志已置位 */
        }
        /* A5: 检查间隔 ±40% 抖动: [interval*0.6, interval*1.4] */
        {
            uint64_t base_ms = (uint64_t)g_wd_interval * 60u / 100u;
            uint64_t span_ms = (uint64_t)g_wd_interval * 80u / 100u;
            rng = wd_jitter_next(rng);
            Sleep((DWORD)(base_ms + rng % (span_ms + 1u)));
        }
        if (prot_selfcrypt_enter(PROT_SELFCRYPT_GROUP_EXT) != PROT_OK) {
            /* 解密失败: 按 tamper 策略处理 */
            switch (g_wd_policy) {
                case PROT_POLICY_EXIT:
                    TerminateProcess(GetCurrentProcess(), PROT_EXIT_TAMPERED);
                    break;
                default:
                    InterlockedIncrement(&g_wd_tamper);
                    break;
            }
            continue;
        }
        if (prot_integrity_check_self() != PROT_OK) {
            switch (g_wd_policy) {
                case PROT_POLICY_EXIT:
                    TerminateProcess(GetCurrentProcess(), PROT_EXIT_TAMPERED);
                    break; /* 失败则进程已终止 */
                case PROT_POLICY_FAKE:
                    InterlockedExchange(&g_wd_fake, 1);
                    break;
                case PROT_POLICY_CONTINUE:
                default:
                    InterlockedIncrement(&g_wd_tamper);
                    break;
            }
        }
        prot_selfcrypt_leave(PROT_SELFCRYPT_GROUP_EXT);
        /* G2 补洞: 运行期 IAT 改写 (hook 导入表) 周期复查 ——
         * 文件级 CRC 不覆盖 loader 写入的 IAT, 这里快照比对 detect。 */
        if (prot_integrity_check_iat() != PROT_OK) {
            switch (g_wd_policy) {
                case PROT_POLICY_EXIT:
                    TerminateProcess(GetCurrentProcess(), PROT_EXIT_TAMPERED);
                    break;
                case PROT_POLICY_FAKE:
                    InterlockedExchange(&g_wd_fake, 1);
                    break;
                case PROT_POLICY_CONTINUE:
                default:
                    InterlockedIncrement(&g_wd_tamper);
                    break;
            }
        }
        /* A5: 反附加周期复查 —— 驻留期调试器/探测不再只有启动一次检测 */
        if (prot_antidebug_scan(&ad) == PROT_OK &&
            prot_antidebug_detected(&ad) != 0u) {
            switch (g_wd_policy) {
                case PROT_POLICY_EXIT:
                    TerminateProcess(GetCurrentProcess(), PROT_EXIT_DEBUG_DETECTED);
                    break;
                case PROT_POLICY_FAKE:
                    InterlockedExchange(&g_wd_fake, 1);
                    break;
                case PROT_POLICY_CONTINUE:
                default:
                    InterlockedIncrement(&g_wd_tamper);
                    break;
            }
        }
        /* W2 (WIN_ENHANCE): 周期回调 (demo N3 数据自校验等) */
        {
            prot_wd_callback cb;
            AcquireSRWLockShared(&g_wd_cb_lock);
            cb = g_wd_cb;
            ReleaseSRWLockShared(&g_wd_cb_lock);
            if (cb != NULL && cb() != PROT_OK) {
                switch (g_wd_policy) {
                    case PROT_POLICY_EXIT:
                        TerminateProcess(GetCurrentProcess(), PROT_EXIT_TAMPERED);
                        break;
                    case PROT_POLICY_FAKE:
                        InterlockedExchange(&g_wd_fake, 1);
                        break;
                    case PROT_POLICY_CONTINUE:
                    default:
                        InterlockedIncrement(&g_wd_tamper);
                        break;
                }
            }
        }
    }
    return 0;
}

/* --- 完整性校验 (A3) --- */
static const struct prot_crc_target {
    const char* name; /* 节名 (前 8 字节) */
    uint32_t    idx;  /* g_prot_baked_crc 下标 */
} g_crc_targets[3] = {
    { ".text", 0u }, { ".rdata", 1u }, { ".pdata", 2u },
};

static int sec_name_eq(const IMAGE_SECTION_HEADER* sec, const char* name)
{
    size_t n = strlen(name);
    size_t i;
    if (n > sizeof(sec->Name))
        return 0;
    for (i = 0u; i < n; i++)
        if (sec->Name[i] != (uint8_t)name[i])
            return 0;
    for (; i < sizeof(sec->Name); i++)
        if (sec->Name[i] != 0u)
            return 0;
    return 1;
}

/* 把 [rva, rva+len) 内会被加载器/重定位改写的字节在 mask 中置 0xFF (A3):
 *   1. 基址重定位字段: type 10 (DIR64) 8 字节 / type 3 (HIGHLOW) 4 字节
 *   2. IAT (目录项 12): loader 启动时写入已解析的导入函数地址
 * 规则与 tools/hashpatch.py 完全一致, 保证文件侧与运行侧两遍 CRC 相同。 */
static void build_reloc_mask(uint8_t* base, const IMAGE_NT_HEADERS* nt,
                             uint8_t* mask, uint32_t rva, uint32_t len)
{
    const IMAGE_DATA_DIRECTORY* iat =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    const IMAGE_DATA_DIRECTORY* dd =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    const uint8_t* reloc_end;
    const IMAGE_BASE_RELOCATION* br;
    uint32_t w;

    /* IAT: loader 会写入导入地址 */
    if (iat->VirtualAddress >= rva && iat->VirtualAddress + iat->Size <= rva + len)
        memset(mask + (iat->VirtualAddress - rva), 0xFF, iat->Size);

    /* 基址重定位字段 (ASLR 偏移修正) */
    if (dd->VirtualAddress == 0u || dd->Size == 0u)
        return;
    br = (const IMAGE_BASE_RELOCATION*)(base + dd->VirtualAddress);
    reloc_end = (const uint8_t*)br + dd->Size;
    while ((const uint8_t*)br + sizeof(IMAGE_BASE_RELOCATION) <= reloc_end &&
           br->VirtualAddress != 0u &&
           br->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION) &&
           (const uint8_t*)br + br->SizeOfBlock <= reloc_end) {
        uint32_t cnt = (br->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2u;
        const uint16_t* ent = (const uint16_t*)(br + 1);
        uint32_t i;
        for (i = 0u; i < cnt; i++) {
            uint32_t type = (uint32_t)(ent[i] >> 12);
            w = (type == 10u) ? 8u : ((type == 3u) ? 4u : 0u);
            if (w != 0u) {
                uint32_t tgt = br->VirtualAddress + (ent[i] & 0xFFFu);
                if (tgt >= rva && tgt + w <= rva + len)
                    memset(mask + (tgt - rva), 0xFF, w);
            }
        }
        br = (const IMAGE_BASE_RELOCATION*)((const uint8_t*)br + br->SizeOfBlock);
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
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS* nt;
    const IMAGE_SECTION_HEADER* sec;
    uint8_t* base;
    uint32_t i, j, len;
    uint32_t found = 0u;

    base = (uint8_t*)GetModuleHandleW(NULL); /* 自身映像基址 */
    if (base == NULL) {
        return PROT_ERR_INTEGRITY;
    }

    dos = (const IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return PROT_ERR_INTEGRITY;
    }

    nt = (const IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return PROT_ERR_INTEGRITY;
    }

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0u; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        for (j = 0u; j < 3u; j++) {
            uint32_t crc;
            uint8_t mask[0x40000]; /* 段 CRC 上限 256KB (栈上; .text 已 >128KB) */
            if (!sec_name_eq(sec, g_crc_targets[j].name))
                continue;
            len = (sec->Misc.VirtualSize < sec->SizeOfRawData)
                      ? sec->Misc.VirtualSize : sec->SizeOfRawData;
            if (len == 0u) {
                found |= (1u << j); /* 空段视为通过 */
                break;
            }
            if (len > sizeof(mask))
                return PROT_ERR_INTEGRITY;
            memset(mask, 0, len);
            build_reloc_mask(base, nt, mask, sec->VirtualAddress, len);
            build_selfcrypt_mask(mask, sec->VirtualAddress, len); /* N1 D1b */
            crc = section_crc_masked(base, mask, sec->VirtualAddress, len);
            if (crc != read_baked_crc(g_crc_targets[j].idx)) {
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

#pragma code_seg(PROT_SEC_XEC)  /* 辅助函数与加密段分页 (S1 技术债, 2026-08-30) */
/* --- 运行期 IAT 完整性 (G2 补洞, ATTACK_DRILL2) ---
 * loader 启动时写入 IAT 导入地址 (合法); 攻击者运行期改写 IAT (hook 导入
 * 表) 不在文件级 CRC 覆盖内。这里快照 IAT 初始值, 周期比对 detect 改写。
 * 首次调用建立快照; 之后逐项比对。使用 InitOnce 保证线程安全单次初始化。 */
static INIT_ONCE g_iat_once = INIT_ONCE_STATIC_INIT;
static volatile LONG g_iat_ready = 0;
static uint8_t* g_iat_snap = NULL;      /* IAT 快照 */
static uint32_t g_iat_snap_len = 0u;

static BOOL CALLBACK iat_snapshot_init(PINIT_ONCE once, PVOID p, PVOID* ctx)
{
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS* nt;
    const IMAGE_DATA_DIRECTORY* iat;
    uint8_t* base;
    (void)once;
    (void)p;
    (void)ctx;

    base = (uint8_t*)GetModuleHandleW(NULL);
    if (base == NULL) {
        return TRUE; /* 失败也视为完成 (后续 check 直接失败) */
    }
    dos = (const IMAGE_DOS_HEADER*)base;
    nt = (const IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    iat = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    if (iat->VirtualAddress == 0u || iat->Size == 0u) {
        return TRUE; /* 无 IAT (静态链接/无导入) */
    }
    g_iat_snap_len = iat->Size;
    g_iat_snap = (uint8_t*)malloc(g_iat_snap_len);
    if (g_iat_snap == NULL) {
        g_iat_snap_len = 0u;
        return TRUE;
    }
    memcpy(g_iat_snap, base + iat->VirtualAddress, g_iat_snap_len);
    InterlockedExchange(&g_iat_ready, 1);
    return TRUE;
}

prot_status prot_integrity_check_iat(void)
{
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS* nt;
    const IMAGE_DATA_DIRECTORY* iat;
    uint8_t* base;
    uint32_t i;

    InitOnceExecuteOnce(&g_iat_once, iat_snapshot_init, NULL, NULL);
    if (!g_iat_ready) {
        /*
         * 快照未建立: 无 IAT (纯静态) 视为 OK; 其他情况 (malloc 失败) 忽略
         * —— watchdog 不因资源问题误杀 (与 MDL 完整性语义一致)。
         */
        return PROT_OK;
    }

    base = (uint8_t*)GetModuleHandleW(NULL);
    if (base == NULL) {
        return PROT_ERR_INTEGRITY;
    }
    dos = (const IMAGE_DOS_HEADER*)base;
    nt = (const IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    iat = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    if (iat->VirtualAddress == 0u || iat->Size != g_iat_snap_len) {
        return PROT_ERR_INTEGRITY; /* IAT 目录异常 */
    }

    /* 逐项比对: 运行期改写 (hook) 会与快照不一致 */
    for (i = 0u; i < g_iat_snap_len; i++) {
        if (((volatile uint8_t*)base)[iat->VirtualAddress + i] !=
            g_iat_snap[i]) {
            return PROT_ERR_INTEGRITY;
        }
    }
    return PROT_OK;
}

prot_status prot_integrity_start_watchdog(prot_policy pol, uint32_t interval_ms) {
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

    InterlockedExchange(&g_wd_stop, 0);
    g_wd_policy = pol;
    g_wd_interval = interval_ms;

    /* G2: watchdog 启动时立即建立 IAT 快照 (早于攻击者可改写窗口)。
     * 若延迟到首轮循环 (3-7s 抖动后) 才快照, 攻击者可在启动早期改写
     * IAT 使快照记录被改值 -> 后续比对恒一致 -> 绕过。 */
    (void)prot_integrity_check_iat();

    g_wd_thread = CreateThread(NULL, 0, watchdog_thread, NULL, 0, NULL);
    if (g_wd_thread == NULL) {
        return PROT_ERR_INTERNAL;
    }
    return PROT_OK;
}

prot_status prot_integrity_stop_watchdog(void) {
    HANDLE h;

    h = g_wd_thread;
    if (h == NULL) {
        return PROT_OK; /* 幂等 */
    }
    InterlockedExchange(&g_wd_stop, 1);
    WaitForSingleObject(h, INFINITE); /* 等待线程退出 */
    CloseHandle(h);
    g_wd_thread = NULL;
    return PROT_OK;
}
