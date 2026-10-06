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
#include "protect/prot_platform.h"  /* C2: 平台抽象层 */
#include "protect/prot_compiler.h"  /* C2: PROT_SECTION_* / PROT_ALLOCATE */
#include "protect/prot_noise.h"   /* W1.6 序言噪声 */

#include <stdio.h>
#include <stdlib.h>   /* C2: malloc（安全读缓冲）*/
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
/* ## C2（2026-09-25）: 自定义节改为**跨平台宏**
 *
 * ⚠️ **MSVC 的属性参数不能加引号**（实测踩坑）:
 *   `__pragma(section(".foo", "read, write"))` -> MSVC 报
 *     `C4081: 应输入"标识符"；找到"字符串"`
 *   **正确**: `__pragma(section(".foo", read, write))`（标识符，无反引号）
 *
 * 故宏签名为 `PROT_SECTION_BEGIN(sec, attrs...)` —— **可变参数**，
 * 让 MSVC 与 GCC 各自展开（GCC 侧的属性随变量走，忽略此宏）。
 */
PROT_SECTION_BEGIN(PROT_SEC_PAD, read)
PROT_ALLOCATE(PROT_SEC_PAD)
const char g_prot_pad[4096] = {0};

PROT_SECTION_BEGIN(PROT_SEC_CRY, read, write)
PROT_ALLOCATE(PROT_SEC_CRY)
uint8_t g_prot_selfcrypt_blob[16384];

const uint32_t g_prot_selfcrypt_blob_size = sizeof(g_prot_selfcrypt_blob);

#ifdef PROT_SELFCRYPT_DISABLE

prot_status prot_selfcrypt_init(void)
{
    /* C2: 初始化平台无关互斥锁（幂等，可重复调用）*/
    (void)prot_plat_mutex_init(&g_sc_lock);
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
static prot_plat_mutex g_sc_lock;   /* C2: 平台无关互斥锁 */

/* 独立节 .protxec (2026-08-29): 解密器与加密目标分页,
 * 避免 VirtualProtect 切换目标页权限时把自身执行页
 * 关了 (0x5000 同页自伤崩溃的根源). */
PROT_CODE_SEG(PROT_SEC_XEC)
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
    uint8_t* base = (uint8_t*)prot_plat_self_base();
    uint8_t* dst;
    uint32_t rva, len;
    uint64_t k;
    uint32_t crc;
    prot_status st;

    /* C2（2026-09-25）: 原 `HMODULE hmod = GetModuleHandleW(NULL)` 改为
     * 平台层 `prot_plat_self_base()`（Linux 用 dl_iterate_phdr）。 */
    if (base == NULL)
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
    /* ## ② 同页兜底（2026-09-25）: 若**我们自己**与目标页同页 -> 用 RWX
     *
     * **为什么必须兜底**: 即使顺序修正后，`sc_xor_range`/CRC 循环
     *   是**函数调用** —— 若它们的代码与 `dst` **落在同一 4KB 页**，
     *   页被设为 RW（禁执行）期间执行它们 -> **仍然崩**。
     *
     * 判定: 目标页范围 = [dst 页起始, (dst+len-1) 页起始]；
     *   若**本函数地址**在其中 -> 同页。
     *
     * 处置: 该次操作使用 `PROT_PAGE_EXECUTE_READWRITE`（保证可执行），
     *   结束后**立即**恢复 RX（见函数末尾）。
     *
     * **诚实边界**: 短暂存在 RWX 页（该布局下）。彻底方案见文件头注释
     *   的"后续工作"（逐页判断 / 解密桩独立分页）。
     */
    {
        /* ## 恒用 RWX（2026-09-25 第二次修正 —— **布局无关**）
         *
         * ### 第一版为什么不够（实测）
         *   初版只比较 `&sc_do_range` 是否与目标同页。但 RW 窗口内
         *   还会执行: `sc_xor_range`、CRC 循环、`malloc/free`、
         *   `prot_plat_safe_read` —— **任一与目标同页即崩**。
         *   实测: 原崩溃盐修好，但 3/4 盐仍崩（崩溃点转移）。
         *
         * ### 本版: 窗口内**页保持可执行**
         *   `EXECUTE_READWRITE` -> 无论谁与目标同页都不会取指失败；
         *   窗口结束**立即**恢复 `EXECUTE_READ`（再 flush icache）。
         *
         * ### 诚实边界
         *   · 窗口内存在**短暂 RWX 页**（理论上可被扫描检测）
         *   · 窗口极小: 一次 XOR + CRC 遍历，随即恢复
         *   · **原设计避免了 RWX，但依赖布局（S1 页分离）**——
         *     而布局依赖已被证明不可靠。**两害相权**取其不崩。
         *   · **彻底方案（后续）**: 逐页判定（整页纯加密段才用 RW），
         *     或把解密桩固定在独立节并强制分页。
         */
        if (prot_plat_protect(dst, len, PROT_PAGE_EXECUTE_READWRITE)
            != PROT_OK) {
            SC_DBG("[SCDBG]   VP-FAIL\n");
            return PROT_ERR_INTERNAL;
        }
    }
    SC_DBG("[SCDBG]   VP-OK\n");
    sc_xor_range(dst, len, k);
    SC_DBG("[SCDBG]   XOR-OK\n");
    if (decrypt) {
        /* II-1: 解密态 CRC 校验 (内联逐字节, 标准 0xEDB88320)
         *
         * ## C2（2026-09-25）: `__try/__except` -> 平台层安全读
         *
         * **改动前**: 内联 SEH 包住整个 CRC 循环 ——
         *   因为 dst 是"刚解密的代码段"，理论上可能不可读。
         *
         * **改动后**: 先 `prot_plat_safe_read` 把该段读进**临时缓冲**，
         *   再对缓冲算 CRC。
         *   · Windows: 平台层内部仍用 `__try/__except`（**语义等价**）
         *   · Linux:   `mincore()` 探测映射（**不引入信号处理**）
         *
         * **为什么改成"先读进缓冲"**:
         *   原设计是"边遍历边读"，靠 SEH 兜住故障；
         *   平台层接口是"一次读 len 字节"，故需缓冲。
         *   **行为等价**: CRC 的输入字节完全一致。
         *
         * **额外收益**: 读进缓冲后，CRC 循环**不再触碰可能失效的地址** ——
         *   遍历过程本身绝对安全。
         */
        uint8_t* tmp = (uint8_t*)malloc(len);
        if (tmp == NULL) {
            (void)prot_plat_protect(dst, len, PROT_PAGE_EXECUTE_READ);
            return PROT_ERR_INTERNAL;
        }
        st = prot_plat_safe_read(tmp, dst, len);
        if (st != PROT_OK) {
            free(tmp);
            SC_DBG("[SCDBG]   SAFE-READ-FAIL\n");
            (void)prot_plat_protect(dst, len, PROT_PAGE_EXECUTE_READ);
            return PROT_ERR_INTEGRITY;
        }
        {
            uint32_t got = 0xFFFFFFFFu;
            uint32_t j;
            for (j = 0u; j < len; j++) {
                uint32_t b;
                got ^= tmp[j];
                for (b = 0u; b < 8u; b++)
                    got = (got >> 1)
                        ^ (0xEDB88320u & (uint32_t)-(int)(got & 1u));
            }
            got ^= 0xFFFFFFFFu;
            free(tmp);
            SC_DBG("[SCDBG]   CRC got=0x%x want=0x%x\n", got, crc);
            if (got != crc) {
                (void)prot_plat_protect(dst, len, PROT_PAGE_EXECUTE_READ);
                return PROT_ERR_INTEGRITY;
            }
        }
    }
    /* ## ⚠️ 顺序修正（2026-09-25，S1 同类自伤）
     *
     * **原顺序**: `protect(RW) -> XOR -> CRC -> flush_icache -> protect(RX)`
     *   -> `flush_icache` 在**页仍为 RW（禁执行）**时执行 ->
     *      **取指失败 -> AV 0xC0000005**（调试器实测: 崩溃符号
     *      = `prot_plat_flush_icache`，访问类型 = 执行）。
     *
     * **新顺序**: 先把页恢复为 RX，**再** flush：
     *   -> "在 RW 页上执行代码"的窗口**消失**。
     *
     * 注: x86 上 `flush_icache` 本身是 no-op；但**调用它**这件事
     *     需要该页可执行 —— 故顺序至关重要。
     */
    if (prot_plat_protect(dst, len, PROT_PAGE_EXECUTE_READ) == PROT_OK) {
        SC_DBG("[SCDBG]   RX-OK\n");
        prot_plat_flush_icache(dst, len);
        SC_DBG("[SCDBG]   FLUSH-OK\n");
    }
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

    /* D2c (2026-10-06): 启动逐条校验 + **校验后立即回密**。
     *
     * ## 改前 (旧注释宣称 "D2b 只解密组 0", 实现却是 D2a 全量明文)
     *   `for (i = 0; i < n; i++) sc_do_range(i, 1);` 把**全部** n 条解密后
     *   **留在明文态**, 各自直到 `leave(组)` 才重新加密。
     *   => 从本函数返回, 到**首次** `leave(组)` 之间, 存在一段
     *      **全量明文驻留窗口**。demo 实测: 自然路径 ~0.66s;
     *      带 `--wait-ms 6000` 时 ~6.67s (期间 dump 可抓到全部明文引擎)。
     *   这**违反** N1 的运行期承诺「非调用时刻内存中函数为密文」
     *   (`docs/N1_PHASE2_PLAN.md` 的威胁边界), 且与旧注释自相矛盾。
     *
     * ## 改后 (D2c)
     *   ① 仍逐条解密 + 逐条 CRC 校验: 篡改 -> 立即返回非 OK,
     *      调用方 (`demo/main.c` / `app_main.c`) 退 `PROT_EXIT_TAMPERED`。
     *      启动即拒止的语义**不变** (T29 meta-CRC / T30 密文体-CRC 均走此路径)。
     *   ② 校验完**立即把全部条目重新加密** (对称 XOR, 不校验), `g_sc_state[]` 归 0;
     *   ③ 之后的按需解密全部交给 `prot_selfcrypt_enter` / `prot_selfcrypt_leave`。
     *   => 明文只存在于 enter/leave 窗口内。
     *
     * ## 为什么回密必须限定在 `PROT_SELFCRYPT_D2B` 下
     *   D2a 构建的 `enter` / `leave` 是**空操作** (开头 `!g_sc_d2b_enabled` 早退)。
     *   若 D2a 下也回密, 函数体会**永久停在密文** -> 调用即执行垃圾指令
     *   (即 T11 的 `0xC0000005` 形状)。故回密仅 D2B 编译期生效。
     *
     * ## 为什么回密后不会踩空 (修法安全性依据)
     *   · 全部加密目标的**跨模块**调用点都在配对 enter/leave 窗口内 ——
     *     `tools/window_check.py` (门禁第 11 项) 静态覆盖 24 文件 / 308 函数
     *     / 9 个目标, 当前 PASS;
     *   · 组内私有函数 `vm_build_keymaps` / `vm_wb` / `vm_var` 只在
     *     `prot_vm_run` 体内被调用, 随 VM 组窗口一并解密;
     *   · 本函数返回后到首次开窗之间**没有**任何加密目标调用点
     *     (`demo/main.c`: init -> 反调试扫描窗口; `app_main.c` 同形)。
     *
     * ## 诚实边界
     *   · `examples/tool_demo/main.c` 有 5 处**未开窗**调用, 但该示例的
     *     构建管线不接 selfcrypt (`.protcry` 条目数 n=0 -> 本函数早退),
     *     故当前无害; 一旦给它接上 selfcrypt 就会全部踩空,
     *     而 `tools/window_check.py` 的扫描面**不含 `examples/`**。
     */
    for (i = 0u; i < n; i++) {
        prot_status st = sc_do_range(i, 1);
        if (st != PROT_OK)
            return st;
        g_sc_state[i] = 1u;
    }
#ifdef PROT_SELFCRYPT_D2B
    g_sc_d2b_enabled = 1u;
    for (i = 0u; i < n; i++) {
        (void)sc_do_range(i, 0);
        g_sc_state[i] = 0u;
    }
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
    prot_plat_mutex_lock(&g_sc_lock);
    for (i = lo; i < hi; i++) {
        if (!g_sc_state[i]) {
            st = sc_do_range(i, 1);
            if (st != PROT_OK)
                break;
            g_sc_state[i] = 1u;
        }
    }
    prot_plat_mutex_unlock(&g_sc_lock);
    return st;
}

prot_status prot_selfcrypt_leave(uint32_t group)
{
    PROT_NOISE();   /* W1.6 序言噪声 */
    uint32_t lo, hi, i;
    if (!g_sc_d2b_enabled)
        return PROT_OK;
    sc_group_range(group, &lo, &hi);
    prot_plat_mutex_lock(&g_sc_lock);
    for (i = lo; i < hi; i++) {
        if (g_sc_state[i]) {
            sc_do_range(i, 0); /* 重加密 (对称 XOR), 不校验 */
            g_sc_state[i] = 0u;
        }
    }
    prot_plat_mutex_unlock(&g_sc_lock);
    return PROT_OK;
}

#endif /* PROT_SELFCRYPT_DISABLE */
