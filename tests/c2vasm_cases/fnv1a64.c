/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/* fnv1a64.c — golden 样例 1: FNV-1a 64 位 (与 license_hash.vasm 同算法) */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t fnv1a64(uint64_t n)
{
    uint64_t h = 14695981039346656037ull;
    uint64_t i;
    for (i = 0; i < n; i++) {
        h ^= (i + 1);
        h *= 1099511628211ull;
    }
    return h;
}

int main(int argc, char** argv)
{
    uint64_t v = 0;
    if (argc > 1) { v = strtoull(argv[1], NULL, 0); }
    printf("%llu", (unsigned long long)fnv1a64(v));
    return 0;
}
