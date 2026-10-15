/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * license_auth_common.c — 跨平台授权公共 (纯 C, 字节级与 vmenc/Windows 一致)
 *
 * EXTENSION_PLAN C1: share the same message format across Windows/Android/iOS。
 * 本文件不含平台加密调用 (验签在各自 impl), 只做字节构建/解析。
 */
#include "license_auth.h"

#include <string.h>

size_t prot_auth_build_message(const char* serial,
                               uint64_t machine_id,
                               uint32_t tier,
                               uint32_t expires,
                               uint8_t* out_buf, size_t out_cap)
{
    size_t plen = strlen(serial) + 8u + sizeof(PROT_PRODUCT) - 1u + 1u + 4u;
    size_t i;
    size_t o = 0;

    if (out_buf == NULL || out_cap < plen)
        return 0u;

    memcpy(out_buf + o, serial, strlen(serial));
    o += strlen(serial);
    for (i = 0u; i < 8u; i++)
        out_buf[o + i] = (uint8_t)(machine_id >> (8u * i)); /* LE64 */
    o += 8u;
    memcpy(out_buf + o, PROT_PRODUCT, sizeof(PROT_PRODUCT) - 1u);
    o += sizeof(PROT_PRODUCT) - 1u;
    out_buf[o++] = (uint8_t)(tier & 0xFFu);
    for (i = 0u; i < 4u; i++)
        out_buf[o + i] = (uint8_t)(expires >> (8u * i)); /* LE32 */
    o += 4u;
    return o;
}

void prot_auth_strip_crlf(char* s)
{
    size_t L = strlen(s);
    while (L > 0u && (s[L - 1] == '\r' || s[L - 1] == '\n' || s[L - 1] == ' '))
        s[--L] = '\0';
}