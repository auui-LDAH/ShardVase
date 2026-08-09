/*
 * integrity.c — 完整性校验 + 看门狗
 *
 * 对应契约 docs/CONTRACT.md §7。
 * check_self: 遍历 PE 节表找 .text, 对其 min(SizeOfRawData, VirtualSize) 字节
 *             做 prot_crc32, 与构建期烧录值 g_prot_baked_crc.crc 比对。
 * 看门狗: 后台线程按 interval 循环 check_self, 失败按策略处理。
 */

#include <windows.h>
#include <string.h>

#include "protect/integrity.h"

/* 烧录结构 (契约 §7.1; hashpatch.py 依赖其名字与布局) */
typedef struct prot_baked_crc {
    uint8_t magic[8];    /* 标记 "PROTCRCP" */
    uint32_t crc;        /* .text CRC32, 构建期由 hashpatch.py 写入 */
    uint32_t reserved;   /* 保留 */
} prot_baked_crc;

const prot_baked_crc g_prot_baked_crc = {
    { 'P', 'R', 'O', 'T', 'C', 'R', 'C', 'P' },
    0,
    0
};

/*
 * 读取烧录 CRC。必须用 volatile 指针: 否则 /O2 会把 const 全局的
 * crc 字段常量折叠成 0, 运行期永远比对失败 (hashpatch.py 改的是文件字节,
 * 编译器根本不知道)。
 */
static uint32_t read_baked_crc(void) {
    const volatile prot_baked_crc* p =
        (const volatile prot_baked_crc*)&g_prot_baked_crc;
    return p->crc;
}

/* --- 看门狗 --- */
static volatile LONG  g_wd_stop;    /* 停止标志 */
static HANDLE         g_wd_thread;  /* 线程句柄 (NULL = 未运行) */
static prot_policy    g_wd_policy;  /* 校验失败时的策略 */
static uint32_t       g_wd_interval;/* 检查间隔 (ms) */
static volatile LONG  g_wd_fake;    /* FAKE 策略伪结果标志 */
static volatile LONG  g_wd_tamper;  /* CONTINUE 策略失败计数 */

static DWORD WINAPI watchdog_thread(LPVOID param) {
    (void)param;
    for (;;) {
        if (InterlockedCompareExchange(&g_wd_stop, 0, 0) != 0) {
            break; /* 停止标志已置位 */
        }
        Sleep(g_wd_interval);
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
    }
    return 0;
}

prot_status prot_integrity_check_self(void) {
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS* nt;
    const IMAGE_SECTION_HEADER* sec;
    uint32_t i;
    uint32_t len;
    uint32_t crc;
    HMODULE base;

    base = GetModuleHandleW(NULL); /* 自身映像基址 */
    if (base == NULL) {
        return PROT_ERR_INTEGRITY;
    }

    dos = (const IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return PROT_ERR_INTEGRITY;
    }

    nt = (const IMAGE_NT_HEADERS*)((const uint8_t*)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return PROT_ERR_INTEGRITY;
    }

    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            len = (sec->Misc.VirtualSize < sec->SizeOfRawData)
                      ? sec->Misc.VirtualSize : sec->SizeOfRawData;
            crc = prot_crc32((const uint8_t*)base + sec->VirtualAddress, len);
            return (crc == read_baked_crc()) ? PROT_OK : PROT_ERR_INTEGRITY;
        }
    }

    return PROT_ERR_INTEGRITY; /* 未找到 .text */
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
