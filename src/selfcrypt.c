/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * selfcrypt.c — 运行时自变形 (N1 二期: II-1 解密态 CRC + II-2 D2b 调用级 + II-3 多函数)
 *
 * 方案 B (原位加密, 一期结论):
 *   - .text 原位: 目标函数体构建期 XOR 加密 (不搬移, 无跳板) ——
 *     函数内相对 call/jmp (E8/E9 rel32) 不受影响;
 *   - .protcrypt 专用节 (.protcry): 存 meta [count][rva,len,key,crc...];
 *
 * II-1: 解密后对每个函数体算 CRC32 与 meta 明文 CRC 比对, 失败 ->
 *   PROT_ERR_INTEGRITY (防"替换密文段构造假明文" / 解密桩被 patch)。
 * II-2 (D2b, 编译开关 PROT_SELFCRYPT_D2B): prot_selfcrypt_enter/leave
 *   按函数组解密/重加密 (对称 XOR 往返), 调用点包裹; 默认 D2a。
 * II-3: 多目标函数 (meta 多条 entry)。
 *
 * 完整性 (D1b): .text CRC 对加密段掩码, 加密态/解密态该段不参与 CRC。
 * 降级开关 PROT_SELFCRYPT_DISABLE: 全部空转 (构建期不加密)。
 *
 * 注意: 本函数自身不得被加密 (它是解密桩的目标)。
 */
#include "protect/selfcrypt.h"
#include "protect/prot_noise.h"   /* W1.6 序言噪声 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

/* .protcrypt 专用节容器 (N1): 构建期 selfcrypt_proto.py 写入 meta
 * [count u32][entry*20] (rva/len/key/crc)。
 * 定义在本实现文件: 链接 selfcrypt.c 的模块 (demo/example) 共用,
 * 避免"容器在 main.c 导致 example 链接缺符号"。 */
/* S1 专项 (2026-08-30): .protpad 填充节 — 把 .protxec 推后一页,
 * 使其与 .text 尾部加密段 (revoke) 分页, 消除
 * 页粒度 VP 禁执行自伤。 */
/* 阶段1(第二支柱): 节名每构建随机, 消除自解释线索 (见 tools/gen_sections.py) */
#include "protect/prot_sections.h"
#pragma section(PROT_SEC_PAD, read)
__declspec(allocate(PROT_SEC_PAD))
const char g_prot_pad[4096] = {0};

#pragma section(PROT_SEC_CRY, read, write)
__declspec(allocate(PROT_SEC_CRY))
uint8_t g_prot_selfcrypt_blob[16384];

const uint32_t g_prot_selfcrypt_blob_size = sizeof(g_prot_selfcrypt_blob);

#ifdef PROT_SELFCRYPT_DISABLE

prot_status prot_selfcrypt_init(void)
{
    PROT_NOISE();   /* W1.6 序言噪声 */
    return PROT_OK;
}
prot_status prot_selfcrypt_enter(uint32_t group) { (void)group; return PROT_OK; }
prot_status prot_selfcrypt_leave(uint32_t group) { (void)group; return PROT_OK; }

#else

/* meta entry 布局 (与 selfcrypt_proto.py 一致, 24B, S1 组字段):
 *   rva u32 | len u32 | key0 u64 | crc32 u32 | group u32 (明文 CRC, II-1) */
#define SC_ENTRY_SIZE 24u
#define SC_ENTRY_GROUP_OFF 20u

/* 每个函数的当前状态: 0=密文(加密态) 1=明文(解密态)。
 * 组状态 = 组内全部函数同态 (enter/leave 按组整体切换)。 */
static volatile uint8_t g_sc_state[PROT_SELFCRYPT_MAX_FN];
static volatile uint8_t g_sc_d2b_enabled = 0u;

/* 解密期诊断日志开关 (2026-09-20 收尾).
 *
 * 背景: 这些 fprintf 原本**无条件编译**进产物, 泄漏每个加密函数的
 * RVA / 长度 / 密钥流种子 k / 明文 CRC 期望值 / 解密后地址 ——
 * 等于免费给出"定位 + 验证"两个最关键的破解环节。
 * PROT_RELEASE_CONCEAL 只收敛了 prot_status 码, 未覆盖此处。
 *
 * 策略: **显式 opt-in**。默认关闭 (含 Dev 与 Release);
 * 仅当定义 PROT_SELFCRYPT_DEBUG 时编译进日志。
 * 排障用法: build.ps1 -ScDebug   (或手工 /DPROT_SELFCRYPT_DEBUG)
 *
 * 注意: 关闭后 Release/Dev 产物的 .text 与 .rdata 布局均会变化,
 * 需重新生成 selfcrypt mask 与三段 CRC (构建管线已自动处理)。 */
#ifdef PROT_SELFCRYPT_DEBUG
#define SC_DBG(...) fprintf(stderr, __VA_ARGS__)
#else
#define SC_DBG(...) ((void)0)
#endif

/* 互斥: D2b 下多线程并发 enter/leave 保护 (SRWLock 无锁读优化) */
static SRWLOCK g_sc_lock = SRWLOCK_INIT;

/* 独立节 .protxec (2026-08-29): 解密器与加密目标分页,
 * 避免 VirtualProtect 切换目标页权限时把自身执行页
 * 关了 (0x5000 同页自伤崩溃的根源). */
#pragma code_seg(PROT_SEC_XEC)
static void sc_xor_range(uint8_t* dst, uint32_t len, uint64_t key)
{
    uint64_t k = key;
    uint32_t j;
    for (j = 0u; j < len; j++) {
        k = k * PROT_KS_MUL + PROT_KS_ADD;
        dst[j] = (uint8_t)(dst[j] ^ (uint8_t)(k >> 56));
    }
}


static prot_status sc_do_range(uint32_t idx, int decrypt)
{
    const uint8_t* e = g_prot_selfcrypt_blob + 4u + idx * SC_ENTRY_SIZE;
    HMODULE hmod = GetModuleHandleW(NULL);
    uint8_t* base = (uint8_t*)hmod;
    uint8_t* dst;
    uint32_t rva, len;
    uint64_t k;
    uint32_t crc;
    DWORD oldp = 0u;

    if (hmod == NULL)
        return PROT_ERR_INTERNAL;
    SC_DBG("[SCDBG] idx=%u decrypt=%d\n", idx, decrypt);

    memcpy(&rva, e, 4u);
    memcpy(&len, e + 4u, 4u);
    memcpy(&k, e + 8u, 8u);
    memcpy(&crc, e + 16u, 4u);
    dst = base + rva;
    SC_DBG("[SCDBG]   rva=0x%x len=%u k=0x%llx crc=0x%x dst=%p\n",
           rva, len, (unsigned long long)k, crc, (void*)dst);
    SC_DBG("[SCDBG]   PRE-VP\n");
    if (!VirtualProtect((LPVOID)dst, len, PAGE_READWRITE, &oldp)) {
        SC_DBG("[SCDBG]   VP-FAIL err=%lu\n", GetLastError());
        return PROT_ERR_INTERNAL;
    }
    SC_DBG("[SCDBG]   VP-OK\n");
    sc_xor_range(dst, len, k);
    SC_DBG("[SCDBG]   XOR-OK\n");
    if (decrypt) {
        /* II-1: 解密态 CRC 校验 (内联逐字节, 标准 0xEDB88320) */
        __try {
            uint32_t got = 0xFFFFFFFFu;
            uint32_t j;
            for (j = 0u; j < len; j++) {
                uint32_t b;
                got ^= dst[j];
                for (b = 0u; b < 8u; b++)
                    got = (got >> 1) ^ (0xEDB88320u & (uint32_t)-(int)(got & 1u));
            }
            got ^= 0xFFFFFFFFu;
            SC_DBG("[SCDBG]   CRC got=0x%x want=0x%x\n", got, crc);
            if (got != crc) {
                VirtualProtect((LPVOID)dst, len, oldp, &oldp);
                return PROT_ERR_INTEGRITY;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            SC_DBG("[SCDBG]   CRC-EXCEPTION code=0x%x\n",
                   (unsigned)GetExceptionCode());
            return PROT_ERR_INTEGRITY;
        }
    }
    FlushInstructionCache(GetCurrentProcess(), (LPCVOID)dst, len);
    SC_DBG("[SCDBG]   FLUSH-OK\n");
    VirtualProtect((LPVOID)dst, len, PAGE_EXECUTE_READ, &oldp);
    SC_DBG("[SCDBG]   RX-OK\n");
    return PROT_OK;
}

/* 组 -> 函数索引范围 (组 0 = VM 引擎组, 组 1 = EXT 扩展组) */
static void sc_group_range(uint32_t group, uint32_t* lo, uint32_t* hi)
{
    uint32_t n;
    memcpy(&n, g_prot_selfcrypt_blob, 4u);
    if (n > PROT_SELFCRYPT_MAX_FN)
        n = PROT_SELFCRYPT_MAX_FN;
    for (*lo = 0u; *lo < n; (*lo)++) {
        uint32_t g;
        memcpy(&g, g_prot_selfcrypt_blob + 4u + (*lo) * SC_ENTRY_SIZE
               + SC_ENTRY_GROUP_OFF, 4u);
        if (g == group)
            break;
    }
    for (*hi = *lo; *hi < n; (*hi)++) {
        uint32_t g;
        memcpy(&g, g_prot_selfcrypt_blob + 4u + (*hi) * SC_ENTRY_SIZE
               + SC_ENTRY_GROUP_OFF, 4u);
        if (g != group)
            break;
    }
}

prot_status prot_selfcrypt_init(void)
{
    PROT_NOISE();   /* W1.6 序言噪声 */
    uint8_t* blob = g_prot_selfcrypt_blob;
    uint32_t n;
    uint32_t i;

    if (g_prot_selfcrypt_blob_size < 4u)
        return PROT_OK;
    memcpy(&n, blob, 4u);
    if (n == 0u || n > PROT_SELFCRYPT_MAX_FN)
        return PROT_OK;

    /* D2a: 全部解密并校验; D2b: 只解密组 0 一次 (enter/leave 接管后续) */
    for (i = 0u; i < n; i++) {
        prot_status st = sc_do_range(i, 1);
        if (st != PROT_OK)
            return st;
        g_sc_state[i] = 1u;
    }
#ifdef PROT_SELFCRYPT_D2B
    g_sc_d2b_enabled = 1u;
#endif
    return PROT_OK;
}

prot_status prot_selfcrypt_enter(uint32_t group)
{
    PROT_NOISE();   /* W1.6 序言噪声 */
    uint32_t lo, hi, i;
    prot_status st = PROT_OK;
    if (!g_sc_d2b_enabled)
        return PROT_OK; /* D2a: 函数已常驻明文 */
    sc_group_range(group, &lo, &hi);
    AcquireSRWLockExclusive(&g_sc_lock);
    for (i = lo; i < hi; i++) {
        if (!g_sc_state[i]) {
            st = sc_do_range(i, 1);
            if (st != PROT_OK)
                break;
            g_sc_state[i] = 1u;
        }
    }
    ReleaseSRWLockExclusive(&g_sc_lock);
    return st;
}

prot_status prot_selfcrypt_leave(uint32_t group)
{
    PROT_NOISE();   /* W1.6 序言噪声 */
    uint32_t lo, hi, i;
    if (!g_sc_d2b_enabled)
        return PROT_OK;
    sc_group_range(group, &lo, &hi);
    AcquireSRWLockExclusive(&g_sc_lock);
    for (i = lo; i < hi; i++) {
        if (g_sc_state[i]) {
            sc_do_range(i, 0); /* 重加密 (对称 XOR), 不校验 */
            g_sc_state[i] = 0u;
        }
    }
    ReleaseSRWLockExclusive(&g_sc_lock);
    return PROT_OK;
}

#endif /* PROT_SELFCRYPT_DISABLE */
