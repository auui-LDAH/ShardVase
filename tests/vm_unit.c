/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * tests/vm_unit.c — VM 指令集单测 runner (ROADMAP Phase 1d / A4)
 *
 * 链接 demo/gen/vm_unit_blob.c + vm_unit_brk_blob.c (生成) 与 src/{vm,crc32}.c,
 * 运行 g_vm_unit_image / g_vm_unit_brk_image 并断言宿主内存结果与
 * tests/unit_vm.vasm / tests/unit_vm_brk.vasm 的注释一致。
 * 退出码 0 = 全部断言通过。
 */
#include "protect/vm.h"
#include "vm_unit_blob.h"     /* g_vm_unit_image */
#include "vm_unit_brk_blob.h" /* g_vm_unit_brk_image (A4) */

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

static int run_unit(void)
{
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
        { 0x302Cu, 0xCAFEBABEu, "move/storr32 host[0x302C] (A4)" },
        { 0x3030u, 0xCAFEBABEu, "loadr32 host[0x3030] (A4)" },
    };
    for (size_t i = 0u; i < sizeof(checks) / sizeof(checks[0]); i++) {
        uint32_t got = rd32(checks[i].off);
        if (got != checks[i].want) {
            printf("vm_unit: FAIL %s (got 0x%08x, want 0x%08x)\n",
                   checks[i].what, got, checks[i].want);
            failed = 1;
        }
    }
    return failed;
}

static int run_brk_trap(void)
{
    memset(g_host, 0, sizeof(g_host));
    prot_status st = prot_vm_run(&g_vm_unit_brk_image, g_host, sizeof(g_host));
    if (st != PROT_ERR_VM_BREAKPOINT) {
        printf("vm_unit: FAIL brk-trap (status=%d, want %d)\n",
               (int)st, (int)PROT_ERR_VM_BREAKPOINT);
        return 1;
    }
    if (rd32(0x0000u) != 0u) { /* 陷阱后指令不得执行 */
        printf("vm_unit: FAIL brk-trap (host[0]=0x%08x, want 0)\n", rd32(0x0000u));
        return 1;
    }
    return 0;
}

int main(void)
{
    memset(g_host, 0, sizeof(g_host));

    int failed = run_unit();
    if (run_brk_trap() != 0)
        failed = 1;

    if (!failed)
        printf("vm_unit: PASS (Phase 1D + A4 ops verified)\n");
    return failed ? 1 : 0;
}