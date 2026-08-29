/* poly.c 鈥?golden 鏍蜂緥 4: 澶氶」寮忔眰鍊?(Horner) 鐖跺惊鐜?*/
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

