/*
 * tests/vm_unit.c — VM 指令集单测 runner (ROADMAP Phase 1d)
 *
 * 链接 demo/gen/vm_unit_blob.c (生成) 与 src/{vm,crc32}.c, 运行
 * g_vm_unit_image 并断言宿主内存结果与 tests/unit_vm.vasm 的注释一致。
 * 退出码 0 = 全部断言通过。
 */
#include "protect/vm.h"
#include "vm_unit_blob.h" /* g_vm_unit_image */

#include <stdio.h>
#include <string.h>

static uint8_t g_host[0x4000];

static uint32_t rd32(size_t off)
{
    return (uint32_t)g_host[off]
         | ((uint32_t)g_host[off + 1] << 8)
         | ((uint32_t)g_host[off + 2] << 16)
         | ((uint32_t)g_host[off + 3] << 24);
}

int main(void)
{
    memset(g_host, 0, sizeof(g_host));

    prot_status st = prot_vm_run(&g_vm_unit_image, g_host, sizeof(g_host));
    if (st != PROT_OK) {
        printf("vm_unit: FAIL run status=%d\n", (int)st);
        return 1;
    }

    int failed = 0;
    struct check {
        size_t off;
        uint32_t want;
        const char* what;
    } checks[] = {
        { 0x0000u, 0x2A2Au,    "success marker host[0]" },
        { 0x1000u, 0x1BAD2F5Eu, "nop/pushr/popr host[0x1000]" },
        { 0x1004u, 0x101u,    "setcon/pushcon host[0x1004]" },
        { 0x2000u, 0xC0F0u,   "lea/callind host[0x2000]" },
    };
    for (size_t i = 0u; i < sizeof(checks) / sizeof(checks[0]); i++) {
        uint32_t got = rd32(checks[i].off);
        if (got != checks[i].want) {
            printf("vm_unit: FAIL %s (got 0x%08x, want 0x%08x)\n",
                   checks[i].what, got, checks[i].want);
            failed = 1;
        }
    }

    if (!failed)
        printf("vm_unit: PASS (Phase 1D ops verified)\n");
    return failed ? 1 : 0;
}