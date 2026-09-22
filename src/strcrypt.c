/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * strcrypt.c — 字符串解密助手
 *
 * 对应契约 docs/CONTRACT.md §8。
 * prot_str_decrypt: 用 §3 滚动密钥流解密 enc[0..len) 到 out, 并写 out[len] = 0。
 *   k = k * PROT_KS_MUL + PROT_KS_ADD (uint64 回绕); 每字节输出 (k >> 56) & 0xFF。
 *   (prot_str_get 由 tools/strgen.py 生成的 demo/gen/strings.c 提供。)
 */

#include <stdint.h>

#include "protect/strcrypt.h"

void prot_str_decrypt(const uint8_t* enc, uint32_t len, uint64_t key, char* out) {
    uint64_t k;
    uint32_t i;

    if (enc == NULL || out == NULL) {
        return;
    }
    k = key;
    for (i = 0; i < len; i++) {
        k = k * PROT_KS_MUL + PROT_KS_ADD; /* §3: 先更新 k, 每字节输出 (k >> 56) */
        out[i] = (char)(enc[i] ^ (uint8_t)(k >> 56));
    }
    out[len] = 0; /* 契约 §8: out[len] = 0 */
}
