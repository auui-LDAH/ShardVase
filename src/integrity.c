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
#include <string.h>

#include "protect/antidebug.h"
#include "protect/integrity.h"

/* 烧录结构 (契约 §7.1; hashpatch.py 依赖其名字与布局) */
typedef struct prot_baked_crc {
    uint8_t magic[8];    /* 标记: PROTCRCP(.text)/PROTCRCD(.rdata)/PROTCRDP(.pdata) */
    uint32_t crc;        /* 段 CRC32, 构建期由 hashpatch.py 写入 */
    uint32_t reserved;   /* 保留 */
} prot_baked_crc;

/* A3: 专用只读段 .protcrc —— 烧录表自身不被任何段 CRC 覆盖 (避免自引用)。
 * 下标顺序必须与 tools/hashpatch.py 的 MAGICS 完全一致。 */
#pragma section(".protcrc", read)
__declspec(allocate(".protcrc"))
const prot_baked_crc g_prot_baked_crc[3] = {
    { { 'P', 'R', 'O', 'T', 'C', 'R', 'C', 'P' }, 0, 0 }, /* 0: .text  */
    { { 'P', 'R', 'O', 'T', 'C', 'R', 'C', 'D' }, 0, 0 }, /* 1: .rdata */
    { { 'P', 'R', 'O', 'T', 'C', 'R', 'D', 'P' }, 0, 0 }, /* 2: .pdata */
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
            uint8_t mask[0x20000]; /* 段 CRC 上限 128KB (栈上) */
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
