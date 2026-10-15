/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/* poly.c — golden 样例 4: 多项式求值 (Horner) 父循环 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t poly(uint64_t x)
{
    uint64_t r = 0;
    uint64_t i;
    for (i = 0; i < 8; i++) {
        uint64_t c = (i * 2654435761ull) % 1000003ull;
        r = r * x + c;
    }
    return r;
}

int main(int argc, char** argv)
{
    uint64_t v = 0;
    if (argc > 1) { v = strtoull(argv[1], NULL, 0); }
    printf("%llu", (unsigned long long)poly(v));
    return 0;
}

