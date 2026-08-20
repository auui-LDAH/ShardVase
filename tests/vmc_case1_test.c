/*
 * tests/vmc_case1_test.c — vmc 编译产物端到端验证
 *
 * 运行 g_vmc_case1 (由 tests/vmc_case1.vmc 编译), 用正确/错误 serial
 * 断言 result@52。宿主内存布局与 vmc_case1.layout.json 一致:
 *   serial[48] @ 0, serial_len @ 48, result @ 52, machine_id @ 56,
 *   i @ 64, h @ 72, x @ 80, total @ 88, ok @ 96
 */
#include "protect/vm.h"
#include "vmc_case1_blob.h"

#include <stdio.h>
#include <string.h>

static uint8_t host[0x4000];

static void setup(const char* serial, uint64_t mid)
{
    memset(host, 0, sizeof(host));
    strcpy_s((char*)host, 48, serial);
    memcpy(host + 48, &(uint32_t){ (uint32_t)strlen(serial) }, 4);
    memcpy(host + 56, &mid, 8);
}

static uint32_t result(void)
{
    uint32_t v;
    memcpy(&v, host + 52, 4);
    return v;
}

int main(void)
{
    /* 正确 serial + 当前构建的 machine_id (demo/vm_build.json) */
    setup("DEMO-2026-ABCDEFGH", 0xb4281468e21a4033ull);
    if (prot_vm_run(&g_vmc_case1, host, sizeof(host)) != PROT_OK) {
        printf("vmc_case1: FAIL run status\n");
        return 1;
    }
    if (result() != 1u) {
        printf("vmc_case1: FAIL correct serial result=%u\n", result());
        return 1;
    }
    printf("vmc_case1: correct serial -> result=1 OK\n");

    /* 错误 serial */
    setup("WRONG-SERIAL", 0xb4281468e21a4033ull);
    if (prot_vm_run(&g_vmc_case1, host, sizeof(host)) != PROT_OK) {
        printf("vmc_case1: FAIL run status (wrong)\n");
        return 1;
    }
    if (result() != 0u) {
        printf("vmc_case1: FAIL wrong serial result=%u\n", result());
        return 1;
    }
    printf("vmc_case1: wrong serial -> result=0 OK\n");

    printf("vmc_case1: PASS\n");
    return 0;
}
