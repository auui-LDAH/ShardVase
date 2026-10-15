/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/* cond_agg.c — golden 样例 5: if/else 条件聚合 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t cond_agg(uint64_t x)
{
    uint64_t r = 0;
    if (x < 10) {
        r = x * 3;
    } else if (x < 50) {
        r = x + 1000;
    } else {
        r = x ^ x;
        r = r + x;
    }
    if (x != 42) {
        r = r + 1;
    }
    return r;
}

int main(int argc, char** argv)
{
    uint64_t v = 0;
    if (argc > 1) { v = strtoull(argv[1], NULL, 0); }
    printf("%llu", (unsigned long long)cond_agg(v));
    return 0;
}

