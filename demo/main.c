/*
 * demo/main.c — 反逆向保护套件演示入口 (Lane D)
 *
 * 对应契约 docs/CONTRACT.md §9。流程:
 *   控制台 UTF-8 -> 参数解析(--selftest / --wait-ms N) -> BANNER
 *   -> 反调试扫描/摘要/策略 -> 完整性自检 -> 看门狗 -> HWID
 *   -> 输入序列号 -> VM 校验 -> FAKE 伪结果翻转 -> 结果与退出码。
 *
 * 退出码 (契约 §9.3): 0 成功 / 1 序列号无效 / 0xDB 调试环境 / 0xBAD 被篡改。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

#include "protect/antidebug.h"
#include "protect/hostid.h"
#include "protect/integrity.h"
#include "protect/strcrypt.h"
#include "protect/vm.h"

#include "vm_hash_blob.h"
#include "vm_mix_blob.h"
#include "vm_verify_blob.h"
/* demo/gen: g_vm_hash_image / g_vm_mix_image / g_vm_verify_image (Phase 2a) */

/* demo_mem 布局 (契约 §9.2, 与 demo/license_*.vasm 偏移注释一致, 勿改) */
typedef struct demo_mem {
    char     serial[48];   /* +0  */
    uint32_t serial_len;   /* +48 */
    uint32_t result;       /* +52 */
    uint64_t machine_id;   /* +56 */
    uint64_t vm_h;         /* +64 (VM#1 输出: FNV-1a 结果 h) */
    uint64_t vm_total;     /* +72 (VM#2 输出: GOLDEN 混合 total) */
    uint64_t vm_scratch;   /* +80 (VM#1 内部循环计数器, 宿主无需初始化) */
} demo_mem;                /* 总 88 字节 */

/*
 * 解析 CLI 参数 (契约 §9.1-2):
 *   --selftest   逐项打印检测结果
 *   --wait-ms N  扫描前 Sleep N 毫秒
 * 返回 1 成功, 0 用法错误。
 */
static int parse_args(int argc, char** argv, int* selftest, uint32_t* wait_ms)
{
    int i;

    *selftest = 0;
    *wait_ms = 0;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--selftest") == 0) {
            *selftest = 1;
        } else if (strcmp(argv[i], "--wait-ms") == 0) {
            char* end = NULL;
            unsigned long v;
            if (i + 1 >= argc) {
                fprintf(stderr, "usage: demo.exe [--selftest] [--wait-ms N]\n");
                return 0;
            }
            v = strtoul(argv[i + 1], &end, 10);
            if (end == argv[i + 1] || *end != '\0') {
                fprintf(stderr, "usage: demo.exe [--selftest] [--wait-ms N]\n");
                return 0;
            }
            *wait_ms = (uint32_t)v;
            i++;
        } else {
            fprintf(stderr, "usage: demo.exe [--selftest] [--wait-ms N]\n");
            return 0;
        }
    }
    return 1;
}

/* --selftest: 逐项打印检测结果 (契约 §9.1-4) */
static void print_selftest(const prot_antidebug_report* rep)
{
    printf("  peb_being_debugged: %u\n", rep->peb_being_debugged);
    printf("  peb_nt_global_flag: %u\n", rep->peb_nt_global_flag);
    printf("  debug_port: %u\n", rep->debug_port);
    printf("  debug_flags: %u\n", rep->debug_flags);
    printf("  debug_object: %u\n", rep->debug_object);
    printf("  hardware_breakpoints: %u\n", rep->hardware_breakpoints);
    printf("  timing_suspicious: %u\n", rep->timing_suspicious);
    printf("  kernel_debugger: %u\n", rep->kernel_debugger);
    printf("  debug_heap_flags: %u\n", rep->debug_heap_flags);
    printf("  int3_honey: %u\n", rep->int3_honey);
}

int main(int argc, char** argv)
{
    prot_antidebug_report rep;
    demo_mem mem;
    int selftest;
    uint32_t wait_ms;
    size_t n;
    prot_status st;

    /* §9.1-1: 控制台 UTF-8 输出/输入 */
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    /* §9.1-2: 解析参数 */
    if (!parse_args(argc, argv, &selftest, &wait_ms)) {
        return 2; /* 用法错误 */
    }

    /* §9.1-3: BANNER */
    printf("%s\n", prot_str_get(PROT_STR_BANNER));

    /* §9.1-2: --wait-ms N 在扫描前延时 (为调试附加留出窗口) */
    if (wait_ms > 0) {
        Sleep(wait_ms);
    }

    /* §9.1-4: 反调试扫描 -> 摘要 -> (--selftest 逐项) -> EXIT 策略 */
    prot_antidebug_scan(&rep);
    printf("反调试扫描: %s\n",
           prot_antidebug_detected(&rep) ? "发现可疑" : "通过");
    if (selftest) {
        print_selftest(&rep);
    }

    /*
     * 注意: src/antidebug.c 的 EXIT 策略实现是 TerminateProcess(0xDB),
     * 该调用不冲刷 stdout (stdout 重定向到管道时为全缓冲, 数据会丢失)。
     * 因此先把 MSG_DBG 打印并冲刷, 再触发策略, 保证 §9.1 要求的提示可见。
     */
    if (prot_antidebug_detected(&rep)) {
        printf("%s\n", prot_str_get(PROT_STR_MSG_DBG));
        fflush(stdout);
    }
    prot_antidebug_apply_policy(PROT_POLICY_EXIT); /* 检测到 -> TerminateProcess(0xDB) */
    if (prot_antidebug_detected(&rep)) {
        exit(PROT_EXIT_DEBUG_DETECTED); /* 兜底: 若策略未终止进程则显式退出 */
    }

    /* §9.1-5: 完整性自检 */
    if (prot_integrity_check_self() != PROT_OK) {
        printf("%s\n", prot_str_get(PROT_STR_MSG_TAMPER));
        exit(PROT_EXIT_TAMPERED);
    }

    /* §9.1-6: 看门狗 (每 5 秒复查完整性) */
    prot_integrity_start_watchdog(PROT_POLICY_EXIT, 5000);

    /* §9.1-7: 机器标识 (Phase 4: 真实硬件绑定); 读到序列号前先清零全部区 */
    memset(&mem, 0, sizeof(mem));
    {
        uint64_t hwid = prot_hostid_get();
        printf("%s0x%016llx\n", prot_str_get(PROT_STR_MSG_HWID),
               (unsigned long long)hwid);
        mem.machine_id = hwid;
    }

    /* §9.1-8: 提示并读入序列号 (去掉换行, 长度上限 47) */
    printf("%s", prot_str_get(PROT_STR_PROMPT_SERIAL));
    fflush(stdout);
    if (fgets(mem.serial, sizeof(mem.serial), stdin) == NULL) {
        mem.serial_len = 0;
    } else {
        n = strlen(mem.serial);
        while (n > 0 && (mem.serial[n - 1] == '\n' || mem.serial[n - 1] == '\r')) {
            mem.serial[--n] = '\0';
        }
        mem.serial_len = (uint32_t)n; /* fgets 一次至多 47 字符, 符合上限 */
    }

    /* §9.1-9: VM 校验 —— Phase 2a: 拆成 3 个独立小 VM, 各自密钥/置换/窗口。
     * 依次执行 FNV 哈希 -> GOLDEN 混合 -> 期望值校验, 共享 demo_mem 中间区。 */
    st = prot_vm_run(&g_vm_hash_image, &mem, sizeof(mem));
    if (st != PROT_OK) {
        printf("%s (vm error %d)\n", prot_str_get(PROT_STR_MSG_FAIL), (int)st);
        exit(1);
    }
    st = prot_vm_run(&g_vm_mix_image, &mem, sizeof(mem));
    if (st != PROT_OK) {
        printf("%s (vm error %d)\n", prot_str_get(PROT_STR_MSG_FAIL), (int)st);
        exit(1);
    }
    st = prot_vm_run(&g_vm_verify_image, &mem, sizeof(mem));
    if (st != PROT_OK) {
        printf("%s (vm error %d)\n", prot_str_get(PROT_STR_MSG_FAIL), (int)st);
        exit(1);
    }

    /* §9.1-10: FAKE 策略伪结果翻转 */
    if (prot_antidebug_fake_active()) {
        mem.result ^= 1u;
    }

    /* §9.1-11: 结果与退出码 */
    if (mem.result != 0) {
        printf("%s\n", prot_str_get(PROT_STR_MSG_OK));
        exit(0);
    }
    printf("%s\n", prot_str_get(PROT_STR_MSG_FAIL));
    exit(1);
}
