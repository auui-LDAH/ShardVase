/* modsum.c 鈥?golden 鏍蜂緥 6: 闄ゆ硶/鍙栨ā/澶嶅悎璧嬪€?鑷 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t modsum(uint64_t n)
{
    uint64_t s = 0;
    uint64_t i = 0;
    while (i < n) {
        uint64_t q = i / 7;
        uint64_t m = i % 7;
        s += q + m * 11;
        i++;
    }
    return s;
}

int main(int argc, char** argv)
{
    uint64_t v = 0;
    if (argc > 1) { v = strtoull(argv[1], NULL, 0); }
    printf("%llu", (unsigned long long)modsum(v));
    return 0;
}

