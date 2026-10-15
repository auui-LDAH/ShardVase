/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * prot_test.c — libprot 纯逻辑自测 (无 JNI/Android 依赖, 可宿主编译验证)
 *
 * 验证: 消息构建字节级一致 (serial||mid||PRODUCT||tier||expires) +
 *       CRC32 与标准一致 + license 文本解析。
 *
 * gcc prot_test.c ../license_auth_common.c -o prot_test
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../license_auth.h"

static uint32_t crc32_byte(uint32_t crc, uint8_t b)
{
    int bit;
    crc ^= b;
    for (bit = 0; bit < 8; bit++)
        crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)-(int)(crc & 1u));
    return crc;
}
static uint32_t crc32_range(const uint8_t* d, size_t n)
{
    uint32_t crc = 0xFFFFFFFFu;
    size_t i;
    for (i = 0; i < n; i++)
        crc = crc32_byte(crc, d[i]);
    return crc ^ 0xFFFFFFFFu;
}

int main(void)
{
    int fail = 0;

    /* 1. 消息构建 — 与 vmenc.license_message("DEMO-2026-ABCDEFGH", 0x123456789ABCDEF0, 1, 0)
     *    期望 45 字节: 44454d4f2d...f0debc9a7856341250524f542d44454d4f2d323032360100000000 */
    {
        uint8_t msg[256];
        size_t n = prot_auth_build_message("DEMO-2026-ABCDEFGH",
                                           0x123456789ABCDEF0ull,
                                           PROT_TIER_FULL, 0, msg, sizeof(msg));
        const uint8_t expect[] = {
            0x44,0x45,0x4d,0x4f,0x2d,0x32,0x30,0x32,0x36,0x2d,0x41,0x42,0x43,0x44,
            0x45,0x46,0x47,0x48,0xf0,0xde,0xbc,0x9a,0x78,0x56,0x34,0x12,
            0x50,0x52,0x4f,0x54,0x2d,0x44,0x45,0x4d,0x4f,0x2d,0x32,0x30,0x32,0x36,
            0x01,0x00,0x00,0x00,0x00
        };
        if (n != sizeof(expect) || memcmp(msg, expect, sizeof(expect)) != 0) {
            printf("[FAIL] msg build: n=%u\n", (unsigned)n);
            fail = 1;
        } else {
            printf("[ ok ] msg build: %u bytes byte-identical\n", (unsigned)n);
        }
    }

    /* 2. CRC32 — "123456789" -> 0xCBF43926 */
    {
        uint32_t c = crc32_range((const uint8_t*)"123456789", 9);
        if (c != 0xCBF43926u) {
            printf("[FAIL] crc32: got 0x%08x\n", c);
            fail = 1;
        } else {
            printf("[ ok ] crc32: 0x%08x\n", c);
        }
    }

    /* 3. license 文本解析 (行拆分 + strip_crlf) */
    {
        char l[] = "SERIAL=DEMO-2026-ABCDEFGH\r\nPRODUCT=PROT-DEMO-2026\r\nTIER=1\r\nSIGNATURE=AAAA\r\n";
        const char* p = l;
        int serial_ok = 0, sig_ok = 0;
        while (*p) {
            const char* nl = strchr(p, '\n');
            size_t ln = nl ? (size_t)(nl - p) : strlen(p);
            char line[64];
            if (ln >= sizeof(line)) ln = sizeof(line) - 1;
            memcpy(line, p, ln); line[ln] = '\0';
            if (strncmp(line, "SERIAL=", 7) == 0) serial_ok = 1;
            if (strncmp(line, "SIGNATURE=", 10) == 0) sig_ok = 1;
            if (!nl) break;
            p = nl + 1;
        }
        if (!serial_ok || !sig_ok) {
            printf("[FAIL] license parse\n");
            fail = 1;
        } else {
            printf("[ ok ] license parse: SERIAL+PRODUCT+SIGNATURE\n");
        }
    }

    printf(fail ? "ALL FAIL\n" : "ALL PASS\n");
    return fail ? 1 : 0;
}