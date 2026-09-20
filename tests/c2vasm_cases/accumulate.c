/* accumulate.c — golden 样例 2: 0..n-1 求和 (循环累积) */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t accumulate(uint64_t n)
{
    uint64_t s = 0;
    uint64_t i = 0;
    while (i < n) {
        s = s + i;
        i = i + 1;
    }
    return s;
}

int main(int argc, char** argv)
{
    uint64_t v = 0;
    if (argc > 1) { v = strtoull(argv[1], NULL, 0); }
    printf("%llu", (unsigned long long)accumulate(v));
    return 0;
}

