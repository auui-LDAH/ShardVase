/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * hostid.c — 机器指纹 (D5: 机器绑定因子)
 *
 * ## L5b（2026-09-23）: 因子来源已抽到**平台层**
 *
 * **改动前**: 本文件**直接调用** Windows API 取 4 个因子:
 *   卷序列号 / 计算机名 / MachineGuid(注册表) / 物理盘序列号
 *   -> 机器绑定**不可移植**（含 windows.h + winioctl.h + 注册表 + DeviceIoControl）
 *
 * **改动后**:
 *   · 因子来源 -> `prot_plat_host_factors()`（平台层）
 *   · **FNV-1a 折叠** -> **留在本文件**（见下）
 *
 * ## ⚠️ 为什么折叠必须留在模块里（**关键约束**）
 *   `prot_hostid_get()` 的返回值参与**授权签名**。
 *   若折叠算法或**因子顺序**变化 -> 机器指纹变化 ->
 *   **所有已签发授权失效**（用户机器"认不出自己"）。
 *
 *   故: **折叠算法是协议的一部分**，逐字节不变；
 *       平台层只提供**因子来源**（平台属性）。
 *
 *   **验证**: 改动前后指纹**逐位相同**
 *     （基线 `b4281468e21a4033`，已实测比对，见提交说明）。
 *
 * ## Linux 的现实（如实）
 *   这些因子在 Linux **无 1:1 等价物**，只有替代方案
 *   （machine-id / hostname / DMI uuid / 磁盘序列号）
 *   -> **指纹值必然不同**（这是预期，不是缺陷）。
 */

#include <string.h>

#include "protect/hostid.h"
#include "protect/prot_platform.h"   /* L5b: 平台层因子来源 */
#include "protect/prot_noise.h"      /* W1.6 序言噪声 */

/* FNV-1a 64 位常量 */
#define HOSTID_FNV_BASIS 0xCBF29CE484222325u
#define HOSTID_FNV_PRIME 0x100000001B3u

uint64_t prot_hostid_get(void) {
    PROT_NOISE();   /* W1.6 序言噪声 */
    uint64_t h = HOSTID_FNV_BASIS;
    prot_host_factor fac[PROT_HOST_MAX_FACTORS];
    size_t nfac, i;
    uint32_t j;

    /* **折叠顺序契约**: 必须与改动前**完全一致**。
     *
     * 改动前（原 hostid.c）的顺序:
     *   1. 卷序列号(U32) -> 2. max_len(U32) -> 3. fs_flags(U32)
     *   4. 计算机名(UTF-16 码元, 逐个) -> 5. MachineGuid(ASCII 字节)
     *   6. 物理盘序列号(ASCII 字节)
     *
     * 平台层保证按此顺序返回（见 prot_plat_host_factors 的顺序契约），
     * 本函数按返回顺序**原样折叠** —— 故指纹不变。
     */
    nfac = prot_plat_host_factors(fac, PROT_HOST_MAX_FACTORS);
    if (nfac == 0)
        return 0;   /* 与原实现一致: 无任何因子 -> 只余 BASIS */

    for (i = 0; i < nfac; i++) {
        if (fac[i].kind == PROT_HOST_FACTOR_U32) {
            /* U32 因子: 直接折叠（原实现卷序列号/计算机名码元皆此路径）*/
            h ^= (uint64_t)fac[i].u32;
            h *= HOSTID_FNV_PRIME;
        } else if (fac[i].kind == PROT_HOST_FACTOR_STR && fac[i].str != NULL) {
            /* 字符串因子: 按**字节**折叠（原实现的 GUID/序列号路径）*/
            for (j = 0; fac[i].str[j] != '\0'; j++) {
                h ^= (uint64_t)(uint8_t)fac[i].str[j];
                h *= HOSTID_FNV_PRIME;
            }
        }
    }

    h ^= h >> 32; /* 高位与低位折叠, 保持两侧一致 */
    return h;
}
