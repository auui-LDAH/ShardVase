/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * revoke.c — 授权吊销 (I1, 离线黑名单)
 *
 * 对应契约 docs/CONTRACT.md §9.6。读取 revoke.blob:
 *   - 文件缺失 -> PROT_REVOKE_NO_FILE (不阻断);
 *   - magic/CRC/长度不符 -> PROT_REVOKE_CORRUPT (不阻断 + 调用方告警);
 *   - serial 精确匹配 + tier 匹配 (条目 tier==0xFF 或相等) -> PROT_REVOKE_HIT。
 * 黑名单版本号单调递增, 旧客户端接受新黑名单 (VER 只读不回写)。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protect/license.h"
#include "protect/revoke.h"

#define PROT_REVOKE_MAGIC_LEN 8u
#define PROT_REVOKE_HEADER    (PROT_REVOKE_MAGIC_LEN + 4u + 4u)
#define PROT_REVOKE_ENTRY     60u /* SERIAL[48] + TIER u32 + REVOKED_AT u64 */
#define PROT_REVOKE_MAX_ENTRIES 4096u

/* BLOB_SIGN_PLAN: v1 签名 revoke (MAGIC "PROTREV1"):
 * 布局: MAGIC8 | VER4 | COUNT4 | entries | SIG_LEN4 | SIG(256B) | CRC4 */
#define PROT_REVOKE_SIG_LEN 384u

/* N 加固: "PROTREVK" 不以连续字符串出现 —— 拆成两个 u32 (LE) 比较.
 * v1 判定: 第 8 字节 '1' (v0 是 'K'). */
static int revoke_magic_ok(const uint8_t* p, uint32_t* is_v1)
{
    static const uint8_t m1[8] = { 'P', 'R', 'O', 'T', 'R', 'E', 'V', '1' };
    static const uint8_t m0[8] = { 'P', 'R', 'O', 'T', 'R', 'E', 'V', 'K' };
    if (memcmp(p, m1, 8) == 0) {
        *is_v1 = 1u;
        return 1;
    }
    if (memcmp(p, m0, 8) == 0) {
        *is_v1 = 0u;
        return 1;
    }
    return 0;
}

static uint32_t rk_u32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

prot_revoke_status prot_revoke_check(const char* path,
                                     const char* serial, uint32_t tier,
                                     uint32_t* out_ver)
{
    FILE* f;
    long fsz;
    uint8_t* buf;
    size_t size;
    uint32_t ver = 0u, count = 0u, i;
    size_t pos;
    uint32_t crc;
    int hit = 0;

    if (out_ver != NULL)
        *out_ver = 0u;
    if (path == NULL || serial == NULL)
        return PROT_REVOKE_INVALID_ARG;

    if (fopen_s(&f, path, "rb") != 0 || f == NULL)
        return PROT_REVOKE_NO_FILE;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return PROT_REVOKE_CORRUPT;
    }
    fsz = ftell(f);
    if (fsz <= 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return PROT_REVOKE_CORRUPT;
    }
    size = (size_t)fsz;

    buf = (uint8_t*)malloc(size);
    if (buf == NULL) {
        fclose(f);
        return PROT_REVOKE_CORRUPT;
    }
    if (fread(buf, 1, size, f) != size) {
        fclose(f);
        free(buf);
        return PROT_REVOKE_CORRUPT;
    }
    fclose(f);

    if (size < PROT_REVOKE_HEADER + 4u) {
        free(buf);
        return PROT_REVOKE_CORRUPT;
    }
    {
        uint32_t is_v1 = 0u;
        if (!revoke_magic_ok(buf, &is_v1)) {
            free(buf);
            return PROT_REVOKE_CORRUPT;
        }
        /* BLOB_SIGN_PLAN (D1a 扩展): 强制 v1 —— v0 (未签名) 视为损坏 */
        if (!is_v1) {
            free(buf);
            return PROT_REVOKE_CORRUPT;
        }
    }
    crc = prot_crc32(buf, size - 4u);
    if (crc != rk_u32(buf + size - 4u)) {
        free(buf);
        return PROT_REVOKE_CORRUPT;
    }

    /* BLOB_SIGN_PLAN: v1 RSA 验签 —— 消息 = [0, sig_len_field) */
    {
        uint32_t sig_len;
        size_t sig_off = PROT_REVOKE_HEADER +
                         (size_t)rk_u32(buf + PROT_REVOKE_MAGIC_LEN + 4u) *
                             PROT_REVOKE_ENTRY;
        if (sig_off + 4u + PROT_REVOKE_SIG_LEN > size - 4u) {
            free(buf);
            return PROT_REVOKE_CORRUPT;
        }
        sig_len = rk_u32(buf + sig_off);
        if (sig_len != PROT_REVOKE_SIG_LEN ||
            !prot_license_verify(buf, sig_off, buf + sig_off + 4u,
                                 PROT_REVOKE_SIG_LEN)) {
            free(buf);
            return PROT_REVOKE_CORRUPT;
        }
    }

    ver = rk_u32(buf + PROT_REVOKE_MAGIC_LEN);
    count = rk_u32(buf + PROT_REVOKE_MAGIC_LEN + 4u);
    if (count > PROT_REVOKE_MAX_ENTRIES) {
        free(buf);
        return PROT_REVOKE_CORRUPT;
    }

    pos = PROT_REVOKE_HEADER;
    for (i = 0u; i < count; i++) {
        uint32_t t;
        if (pos + PROT_REVOKE_ENTRY > size - 4u) {
            free(buf);
            return PROT_REVOKE_CORRUPT;
        }
        if (memcmp(buf + pos, serial, PROT_REVOKE_ENTRY - 12u) == 0) {
            t = rk_u32(buf + pos + 48u);
            if (t == PROT_REVOKE_TIER_ALL || t == tier) {
                hit = 1;
                break;
            }
        }
        pos += PROT_REVOKE_ENTRY;
    }

    if (out_ver != NULL)
        *out_ver = ver;
    free(buf);
    return hit ? PROT_REVOKE_HIT : PROT_REVOKE_OK;
}
