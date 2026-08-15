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
#include "protect/license.h"
#include "protect/strcrypt.h"
#include "protect/vm.h"

#include "vm_hash_blob.h"
#include "vm_mix_blob.h"
#include "vm_verify_blob.h"
#include "vm_gate_blob.h"
/* demo/gen: g_vm_hash_image / g_vm_mix_image / g_vm_verify_image / g_vm_gate_image */

/* demo_mem 布局 (契约 §9.2, 与 demo/license_*.vasm 偏移注释一致, 勿改) */
typedef struct demo_mem {
    char     serial[48];   /* +0  */
    uint32_t serial_len;   /* +48 */
    uint32_t result;       /* +52 */
    uint64_t machine_id;   /* +56 */
    uint64_t vm_h;         /* +64 (VM#1 输出: FNV-1a 结果 h) */
    uint64_t vm_total;     /* +72 (VM#2 输出: GOLDEN 混合 total) */
    uint64_t vm_scratch;   /* +80 (VM#1 内部循环计数器, 宿主无需初始化) */
    uint32_t license_ok;   /* +88 (A1: 宿主 RSA 验签结果 0/1, VM#4 并入) */
    uint32_t license_tier; /* +92 (Phase 4: 授权等级 0/1/2, 参与签名不可篡改) */
} demo_mem;                /* 总 96 字节 */

/*
 * 解析 CLI 参数 (契约 §9.1-2):
 *   --selftest       逐项打印检测结果
 *   --wait-ms N      扫描前 Sleep N 毫秒
 *   --wait-after N   看门狗启动后驻留 N 毫秒 (A5 长驻留回归钩子)
 *   --license-file F 读入 RSA 授权文件 (A1) 并验签
 * 返回 1 成功, 0 用法错误。
 */
static int parse_args(int argc, char** argv, int* selftest, uint32_t* wait_ms,
                      uint32_t* wait_after_ms, const char** license_path)
{
    int i;

    *selftest = 0;
    *wait_ms = 0;
    *wait_after_ms = 0;
    *license_path = NULL;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--selftest") == 0) {
            *selftest = 1;
        } else if (strcmp(argv[i], "--wait-ms") == 0 ||
                   strcmp(argv[i], "--wait-after") == 0) {
            int after = (strcmp(argv[i], "--wait-after") == 0);
            char* end = NULL;
            unsigned long v;
            if (i + 1 >= argc) {
                fprintf(stderr, "usage: demo.exe [--selftest] [--wait-ms N] [--wait-after N] [--license-file F]\n");
                return 0;
            }
            v = strtoul(argv[i + 1], &end, 10);
            if (end == argv[i + 1] || *end != '\0') {
                fprintf(stderr, "usage: demo.exe [--selftest] [--wait-ms N] [--wait-after N] [--license-file F]\n");
                return 0;
            }
            if (after)
                *wait_after_ms = (uint32_t)v;
            else
                *wait_ms = (uint32_t)v;
            i++;
        } else if (strcmp(argv[i], "--license-file") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "usage: demo.exe --license-file F\n");
                return 0;
            }
            *license_path = argv[i + 1];
            i++;
        } else {
            fprintf(stderr, "usage: demo.exe [--selftest] [--wait-ms N] [--wait-after N] [--license-file F]\n");
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

/* base64 解码 (标准 64 字符字母表)。返回解码后字节数; 非法输入返回 (size_t)-1。 */
static size_t b64_decode(const char* in, uint8_t* out, size_t cap)
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint8_t vals[256];
    size_t n = 0, i;
    size_t acc = 0;
    int bits = 0;

    memset(vals, 0xFF, sizeof(vals));
    for (i = 0; i < 64; i++)
        vals[(unsigned char)tbl[i]] = (uint8_t)i;

    for (i = 0; in[i] != '\0'; i++) {
        int c = (unsigned char)in[i];
        uint8_t d;
        if (c == '=' || c == '\r' || c == '\n' || c == ' ')
            continue;
        if (c == '\0')
            break;
        d = vals[c];
        if (d == 0xFF)
            return (size_t)-1;
        acc = (acc << 6) | d;
        bits += 6;
        if (bits >= 8) {
            if (n >= cap)
                return (size_t)-1;
            bits -= 8;
            out[n++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    return n;
}

/*
 * 读 license.txt (A1 + Phase 4 tier, 格式见 tools/vmenc.py sign 输出):
 *   SERIAL=... / MACHINE_ID=0x.. / PRODUCT=... / TIER=<0|1|2> /
 *   SIGNATURE=<base64 256B>
 * 验签通过 -> 返回 1 并写出 tier; 文件缺失/字段错/签名无效/机器不匹配
 * -> 返回 0 (tier 保持 0)。TIER 行缺省视为 1 (正式, 向后兼容)。
 */
static int load_and_verify_license(const char* path, demo_mem* mem)
{
    FILE* f;
    char line[512];
    uint8_t sig[256];
    uint8_t msg[256];
    size_t msg_len;
    int have_serial = 0, have_prod = 0, have_sig = 0;
    uint32_t tier = PROT_LICENSE_TIER_FULL;
    char f_serial[48] = {0};
    char f_prod[64] = {0};
    errno_t err;

    err = fopen_s(&f, path, "rb");
    if (err != 0 || f == NULL)
        return 0;
    memset(sig, 0, sizeof(sig));
    while (fgets(line, (int)sizeof(line), f) != NULL) {
        char* eq = strchr(line, '=');
        if (eq == NULL)
            continue;
        *eq = '\0';
        eq++;
        /* strip \r\n */
        {
            size_t L = strlen(eq);
            while (L > 0 && (eq[L - 1] == '\r' || eq[L - 1] == '\n'))
                eq[--L] = '\0';
        }
        if (strcmp(line, "SERIAL") == 0) {
            if (strlen(eq) < sizeof(f_serial)) {
                strcpy_s(f_serial, sizeof(f_serial), eq);
                have_serial = 1;
            }
        } else if (strcmp(line, "PRODUCT") == 0) {
            if (strlen(eq) < sizeof(f_prod)) {
                strcpy_s(f_prod, sizeof(f_prod), eq);
                have_prod = 1;
            }
        } else if (strcmp(line, "TIER") == 0) {
            char* end = NULL;
            unsigned long v = strtoul(eq, &end, 10);
            if (end != eq && *end == '\0' && v <= PROT_LICENSE_TIER_PREMIUM)
                tier = (uint32_t)v;
        } else if (strcmp(line, "SIGNATURE") == 0) {
            have_sig = 1;
            {
                size_t d = b64_decode(eq, sig, sizeof(sig));
                if (d != 256)
                    have_sig = 0;
            }
        }
    }
    fclose(f);

    if (!have_serial || !have_prod || !have_sig)
        return 0;
    if (strcmp(f_prod, PROT_LICENSE_PRODUCT) != 0)
        return 0;
    if (strcmp(f_serial, mem->serial) != 0)
        return 0;
    msg_len = prot_license_build_message(mem->serial, mem->serial_len,
                                         mem->machine_id, tier, msg,
                                         sizeof(msg));
    if (msg_len == 0u)
        return 0;
    if (!prot_license_verify(msg, msg_len, sig, sizeof(sig)))
        return 0;
    mem->license_tier = tier;
    return 1;
}

int main(int argc, char** argv)
{
    prot_antidebug_report rep;
    demo_mem mem;
    int selftest;
    uint32_t wait_ms;
    uint32_t wait_after_ms;
    const char* license_path = NULL;
    size_t n;
    prot_status st;

    /* §9.1-1: 控制台 UTF-8 输出/输入 */
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    /* §9.1-2: 解析参数 */
    if (!parse_args(argc, argv, &selftest, &wait_ms, &wait_after_ms,
                    &license_path)) {
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

    /* §9.1-6: 看门狗 (每 5 秒 ±40% 抖动复查完整性 + A5 反调试) */
    prot_integrity_start_watchdog(PROT_POLICY_EXIT, 5000);

    /* A5 长驻留回归钩子: 看门狗启动后驻留 N 毫秒, 让周期复查多次触发
     * (e2e T11 用 --wait-after 验证干净环境零误报) */
    if (wait_after_ms > 0) {
        Sleep(wait_after_ms);
    }

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

    /* §9.1-9b: RSA 授权 (A1 + Phase 4 tier) —— 宿主验签, 结果由 VM#4 并入
     * 最终判定位。提供 --license-file 时: 验签失败 = license_ok=0, VM#4
     * 使 result 归零; 未提供时与旧行为一致 (license_ok=1, tier=正式)。 */
    mem.license_ok = 1u;
    mem.license_tier = PROT_LICENSE_TIER_FULL;
    if (license_path != NULL) {
        mem.license_ok = (uint32_t)load_and_verify_license(license_path, &mem);
        {
            char eye[48];
            snprintf(eye, sizeof(eye), "%u (tier=%u)",
                     mem.license_ok, mem.license_tier);
            printf("license: %s\n", eye);
        }
    }

    st = prot_vm_run(&g_vm_gate_image, &mem, sizeof(mem));
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
