/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/* bitmix.c — golden 样例 3: 位移/异或混合 (雪崩式) */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t bitmix(uint64_t x)
{
    uint64_t y = x;
    y ^= y >> 33;
    y *= 0xff51afd7ed558ccdull;
    y ^= y >> 33;
    y = (y << 17) | (y >> 47);
    y &= 0x7fffffffffffffffull;
    return y ^ 0x9e3779b97f4a7c15ull;
}

int main(int argc, char** argv)
{
    uint64_t v = 0;
    if (argc > 1) { v = strtoull(argv[1], NULL, 0); }
    printf("%llu", (unsigned long long)bitmix(v));
    return 0;
}

