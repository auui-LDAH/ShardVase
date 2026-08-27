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
#include <time.h>

#include <windows.h>
#include <winhttp.h>

#include "protect/antidebug.h"
#include "protect/blob.h"
#include "protect/dbiguard.h"
#include "protect/hostid.h"
#include "protect/indirect.h"
#include "protect/integrity.h"
#include "protect/license.h"
#include "protect/revoke.h"
#include "protect/selfcrypt.h"
#include "protect/strcrypt.h"
#include "protect/version.h"
#include "protect/vm.h"
#include "protect/vmdetect.h"

/* DBI launcher (技术债 #3): VM 镜像由 build\vm.blob 装载, 不再静态嵌入。
 * 顺序与 build.ps1 3c 的 pack 入参一致; 名称须与 assemble --bin-name 相同。 */
static const char* const k_vm_names[4] = {
    "hash", "mix", "verify", "gate",
};
static prot_vm_image g_vm_imgs[4];
static void* g_vm_blob_buf = NULL;

#ifdef PROT_DRILL_HOOK
/* 演练钩子 (ATTACK_DRILL2): --loop-vm N 循环校验次数 */
uint32_t g_loop_vm = 0u;
#endif /* PROT_DRILL_HOOK */

/* N2 策略 (ATTACK_DRILL2 E2-2): --dbiguard-policy EXIT 时 hook 检测即终止 */
int dbiguard_exit_policy = 0;

/* N5: VM#3 构建期默认期望值 (demo/gen/expect_default.c 生成, 离线兜底) */
extern const uint64_t g_prot_expect_default[2];

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
    uint32_t license_expires; /* +96 (Phase 4: 到期 unix, 0=永久, 参与签名) */
    uint32_t result2;      /* +100 (N3: result 副本2, VM#4 写) */
    uint32_t result3;      /* +104 (N3: result 副本3, VM#4 写) */
    uint32_t result_sum;   /* +108 (N3: result ^ 0xA5A5A5A5, VM#4 写) */
    uint64_t vm_expect1;   /* +112 (N5: VM#3 期望值 h, 会话级; 离线=构建期默认) */
    uint64_t vm_expect2;   /* +120 (N5: VM#3 期望值 total, 会话级) */
} demo_mem;                /* 总 128 字节 (VM 使用的 +0..+108 偏移不变) */

/* W4 (WIN_ENHANCE): Release 隐藏内部 prot_status 码 (仅显示统一失败提示).
 * Dev 保留错误码便于调试. */
#ifdef PROT_RELEASE_CONCEAL
#define PROT_LOG_VM_ERR(st) \
    printf("%s\n", prot_str_get(PROT_STR_MSG_FAIL))
#else
#define PROT_LOG_VM_ERR(st) \
    printf("%s (vm error %d)\n", prot_str_get(PROT_STR_MSG_FAIL), (int)(st))
#endif

/* ---------------------------------------------------------------------------
 * N1 运行时自变形: .protcrypt 容器 (g_prot_selfcrypt_blob) 定义在
 * src/selfcrypt.c (实现文件), 供所有链接 selfcrypt.c 的模块使用。
 * ------------------------------------------------------------------------- */

/* N4 函数级间接化: 经间接表解析函数指针后调用 (静态无直接 call)。
 * 泛型函数指针转具体签名 (函数指针互转, MSVC 允许)。 */
#define PROT_INDIRECT_CALL(fn_id, sig, ...) \
    ((sig)prot_indirect_resolve(fn_id))(__VA_ARGS__)

/* N1 II-2 (D2b): VM 引擎调用包裹 —— enter 解密函数组 -> 调用 -> leave 重加密。
 * D2a (默认) 下 enter/leave 空转, 行为与一期一致。
 * 返回 prot_status: 调用结果; enter 失败 (CRC) 也返回错误。 */
static prot_status vm_run_wrapped(const prot_vm_image* img, void* mem)
{
    prot_status e = prot_selfcrypt_enter(PROT_SELFCRYPT_GROUP_VM);
    if (e != PROT_OK)
        return e;
    e = PROT_INDIRECT_CALL(PROT_INDIRECT_VM_RUN,
                           prot_status (*)(const prot_vm_image*, void*, size_t),
                           img, mem, sizeof(*(demo_mem*)mem));
    prot_selfcrypt_leave(PROT_SELFCRYPT_GROUP_VM);
    return e;
}

/* W2 (WIN_ENHANCE): 看门狗周期回调 —— N3 数据冗余 + dbiguard 复查。
 * demo_mem 在 main() 栈上, 这里用全局指针引用 (VM 链完成后设置).
 * 返回 PROT_OK 一致 / PROT_ERR_INTEGRITY 不一致 (看门狗按 policy 处理). */
static volatile int g_demo_mem_ready = 0;
static demo_mem* g_demo_mem_ptr = NULL;
static prot_status wd_n3_recheck(void)
{
    demo_mem* m;
    uint32_t r1, r2, r3, r;
    if (!g_demo_mem_ready)
        return PROT_OK;
    m = g_demo_mem_ptr;
    if (m == NULL)
        return PROT_OK;
    /* N3: result 三副本多数一致 + 校验和 */
    r1 = m->result;
    r2 = m->result2;
    r3 = m->result3;
    r = (r1 == r2) ? r1 : ((r1 == r3) ? r1 : r2);
    if ((r ^ 0xA5A5A5A5u) != m->result_sum)
        return PROT_ERR_INTEGRITY;
    if (r1 != r && r2 != r && r3 != r)
        return PROT_ERR_INTEGRITY;
    /* W2b: dbiguard 周期复查 (N2 从启动一次升级为周期) */
    {
        prot_dbiguard_report drep;
        prot_dbiguard_scan(&drep);
        if (prot_dbiguard_suspicious(&drep))
            return PROT_ERR_INTEGRITY; /* hook 检测到 -> 按 policy (EXIT) */
    }
    return PROT_OK;
}

/*
 * 解析 CLI 参数 (契约 §9.1-2):
 *   --selftest       逐项打印检测结果
 *   --wait-ms N      扫描前 Sleep N 毫秒
 *   --wait-after N   看门狗启动后驻留 N 毫秒 (A5 长驻留回归钩子)
 *   --license-file F 读入 RSA 授权文件 (A1) 并验签
 *   --vm-blob F      VM 镜像 blob 路径 (默认 "vm.blob", DBI launcher)
 *   --blob-url URL   在线下发 vm.blob 端点 (BLOB_SIGN_PLAN; 不可达回退本地)
 *   --revoke-file F  吊销黑名单路径 (默认 "revoke.blob", I1)
 *   --revoke-policy  吊销命中策略: strict(默认, 拒绝) / warn(告警继续)
 *   --check-url URL  在线验证端点 (M3.1, 缺省不启用在线; 不可达时降级本地)
 * 返回 1 成功, 0 用法错误。
 */
static int parse_args(int argc, char** argv, int* selftest, uint32_t* wait_ms,
                      uint32_t* wait_after_ms, const char** license_path,
                      const char** vm_blob_path, const char** blob_url,
                      const char** revoke_path,
                      int* revoke_strict, const char** check_url)
{
    int i;

    *selftest = 0;
    *wait_ms = 0;
    *wait_after_ms = 0;
    *license_path = NULL;
    *vm_blob_path = NULL;
    *blob_url = NULL;
    *revoke_path = NULL;
    *revoke_strict = 1; /* 默认 strict: 命中即拒绝 */
    *check_url = NULL;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--selftest") == 0) {
            *selftest = 1;
        } else if (strcmp(argv[i], "--wait-ms") == 0 ||
                   strcmp(argv[i], "--wait-after") == 0) {
            int after = (strcmp(argv[i], "--wait-after") == 0);
            char* end = NULL;
            unsigned long v;
            if (i + 1 >= argc) {
                fprintf(stderr, "usage: demo.exe [--selftest] [--wait-ms N] [--wait-after N] [--license-file F] [--vm-blob F] [--blob-url URL] [--revoke-file F] [--revoke-policy strict|warn]\n");
                return 0;
            }
            v = strtoul(argv[i + 1], &end, 10);
            if (end == argv[i + 1] || *end != '\0') {
                fprintf(stderr, "usage: demo.exe [--selftest] [--wait-ms N] [--wait-after N] [--license-file F] [--vm-blob F] [--revoke-file F] [--revoke-policy strict|warn]\n");
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
        } else if (strcmp(argv[i], "--vm-blob") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "usage: demo.exe --vm-blob F\n");
                return 0;
            }
            *vm_blob_path = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "--blob-url") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "usage: demo.exe --blob-url URL\n");
                return 0;
            }
            *blob_url = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "--revoke-file") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "usage: demo.exe --revoke-file F\n");
                return 0;
            }
            *revoke_path = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "--revoke-policy") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "usage: demo.exe --revoke-policy strict|warn\n");
                return 0;
            }
            if (strcmp(argv[i + 1], "strict") == 0) {
                *revoke_strict = 1;
            } else if (strcmp(argv[i + 1], "warn") == 0) {
                *revoke_strict = 0;
            } else {
                fprintf(stderr, "usage: demo.exe --revoke-policy strict|warn\n");
                return 0;
            }
            i++;
        } else if (strcmp(argv[i], "--check-url") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "usage: demo.exe --check-url URL\n");
                return 0;
            }
            *check_url = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "--dbiguard-policy") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "usage: demo.exe --dbiguard-policy EXIT\n");
                return 0;
            }
            if (strcmp(argv[i + 1], "EXIT") == 0) {
                dbiguard_exit_policy = 1;
            } else {
                fprintf(stderr, "usage: demo.exe --dbiguard-policy EXIT\n");
                return 0;
            }
            i++;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("prot-demo %s\n", PROT_VERSION_STR); /* RELEASE §1.2 */
            exit(0);
#ifdef PROT_DRILL_HOOK
        } else if (strcmp(argv[i], "--loop-vm") == 0) {
            /* 演练钩子 (ATTACK_DRILL2): 循环 VM 校验 N 次, 供外部 dump/写验证 */
            if (i + 1 >= argc) {
                fprintf(stderr, "usage: demo.exe --loop-vm N\n");
                return 0;
            }
            g_loop_vm = (uint32_t)strtoul(argv[i + 1], NULL, 10);
            i++;
#endif /* PROT_DRILL_HOOK */
        } else {
            fprintf(stderr, "usage: demo.exe [--selftest] [--wait-ms N] [--wait-after N] [--license-file F] [--vm-blob F] [--revoke-file F] [--revoke-policy strict|warn]\n");
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
 * 读 license.txt (A1 + Phase 4 tier/expires, 格式见 tools/vmenc.py sign 输出):
 *   SERIAL=... / MACHINE_ID=0x.. / PRODUCT=... / TIER=<0|1|2> /
 *   EXPIRES=<unix> / SIGNATURE=<base64 256B>
 * 验签通过 -> 返回 1 并写出 tier/expires; 文件缺失/字段错/签名无效/机器
 * 不匹配/已过期 -> 返回 0。TIER 缺省 1, EXPIRES 缺省 0 (永久)。
 * 非 static: N4 间接表 (demo/gen/indirect_table.c) 引用。 */
int load_and_verify_license(const char* path, demo_mem* mem)
{
    FILE* f;
    char line[512];
    uint8_t sig[256];
    uint8_t msg[256];
    size_t msg_len;
    int have_serial = 0, have_prod = 0, have_sig = 0;
    uint32_t tier = PROT_LICENSE_TIER_FULL;
    uint32_t expires = 0u;
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
        } else if (strcmp(line, "EXPIRES") == 0) {
            char* end = NULL;
            unsigned long long v = strtoull(eq, &end, 10);
            if (end != eq && *end == '\0' && v <= 0xFFFFFFFFull)
                expires = (uint32_t)v;
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
                                         mem->machine_id, tier, expires,
                                         msg, sizeof(msg));
    if (msg_len == 0u)
        return 0;
    if (!prot_license_verify(msg, msg_len, sig, sizeof(sig)))
        return 0;
    /* 试用期控制: expires != 0 且已过期 -> 拒绝 */
    if (expires != 0u) {
        time_t now = time(NULL);
        if (now < 0 || (uint64_t)now > (uint64_t)expires)
            return 0;
    }
    mem->license_tier = tier;
    mem->license_expires = expires;
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
    const char* vm_blob_path = NULL;
    const char* blob_url = NULL;
    const char* revoke_path = NULL;
    const char* check_url = NULL;
    int revoke_strict = 1;
    size_t n;
    prot_status st;

    /* §9.1-1: 控制台 UTF-8 输出/输入 */
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    /* §9.1-2: 解析参数 */
    if (!parse_args(argc, argv, &selftest, &wait_ms, &wait_after_ms,
                    &license_path, &vm_blob_path, &blob_url, &revoke_path,
                    &revoke_strict, &check_url)) {
        return 2; /* 用法错误 */
    }

    /* §9.1-3: BANNER */
    printf("%s\n", prot_str_get(PROT_STR_BANNER));

    /* N1 (二期 II-1): 解密引擎函数 + 解密态 CRC 校验; 失败 = 完整性被破坏 */
    {
        prot_status sc = prot_selfcrypt_init();
        if (sc != PROT_OK) {
            printf("%s\n", prot_str_get(PROT_STR_MSG_TAMPER));
            fflush(stdout);
            exit(PROT_EXIT_TAMPERED);
        }
    }

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

    /* §9.1-4b (N2): 反 DBI/反 hook 检测 —— 咨询项, 只报告不触发策略 */
    {
        prot_dbiguard_report drep;
        prot_dbiguard_scan(&drep);
        if (selftest) {
            printf("  dbi_inline_hooks: %u\n", drep.inline_hooks);
            printf("  dbi_frida_agent: %u\n", drep.frida_agent);
            printf("  dbi_rxrw_regions: %u\n", drep.rx_rw_regions);
            printf("  dbi_thread_count: %u\n", drep.thread_count);
        }
        if (prot_dbiguard_suspicious(&drep)) {
            printf("疑似动态插桩/hook 环境 (咨询项, 不影响运行)\n");
            /* N2 策略 (ATTACK_DRILL2 E2-2): --dbiguard-policy EXIT
             * 时 hook 检测到 -> 终止 (0xDB), 防注入 hook 被忽略 */
            if (dbiguard_exit_policy) {
                printf("%s\n", prot_str_get(PROT_STR_MSG_DBG));
                fflush(stdout);
                exit(PROT_EXIT_DEBUG_DETECTED);
            }
        }
    }

    /* §9.1-4c (M1): 虚拟机/沙箱检测 —— 咨询项, 只报告不触发策略 */
    {
        prot_vmdetect_report vmrep;
        prot_vmdetect_scan(&vmrep);
        if (selftest) {
            printf("  vm_hypervisor: %u\n", vmrep.cpu_hypervisor);
            printf("  vm_vendor: %u\n", vmrep.hv_vendor);
            printf("  vm_processes: %u\n", vmrep.vm_processes);
        }
        if (prot_vmdetect_suspicious(&vmrep)) {
            printf("疑似虚拟机环境 (咨询项, 不影响运行)\n");
        }
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

    /* §9.1-6b: 装载 VM blob (DBI launcher, 技术债 #3) —— 镜像密文不静态
     * 嵌入 exe; 缺失/损坏 -> 拒绝运行 (0xB10B)。默认相对 cwd 找 vm.blob。
     * BLOB_SIGN_PLAN: --blob-url 时先从网络下载到临时文件 (验签兜底,
     * 中间人替换也过不了 RSA 签名); 下载失败/不可达 -> 回退本地路径。 */
    {
        const char* bp = (vm_blob_path != NULL) ? vm_blob_path : "vm.blob";
        size_t blob_size = 0u;
        if (blob_url != NULL) {
            static char tmp[64] = "vm_blob_dl.tmp";
            HINTERNET hin = NULL, hconn = NULL, hreq = NULL;
            BOOL ok = FALSE;
            hin = WinHttpOpen(L"PROT-Demo/1.0",
                              WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if (hin != NULL) {
                wchar_t whost[256];
                wchar_t wpath[512];
                URL_COMPONENTS uc;
                INTERNET_PORT port;
                memset(&uc, 0, sizeof(uc));
                uc.dwStructSize = sizeof(uc);
                uc.lpszHostName = whost;
                uc.dwHostNameLength = 256;
                uc.lpszUrlPath = wpath;
                uc.dwUrlPathLength = 512;
                {
                    wchar_t wurl[1024];
                    MultiByteToWideChar(CP_UTF8, 0, blob_url, -1, wurl, 1024);
                    if (WinHttpCrackUrl(wurl, 0, 0, &uc)) {
                        port = uc.nPort;
                        hconn = WinHttpConnect(hin, whost, port, 0);
                        if (hconn != NULL) {
                            hreq = WinHttpOpenRequest(hconn, L"GET", wpath, NULL,
                                                     WINHTTP_NO_REFERER,
                                                     WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
                            if (hreq != NULL &&
                                WinHttpSendRequest(hreq,
                                                   WINHTTP_NO_ADDITIONAL_HEADERS,
                                                   0, WINHTTP_NO_REQUEST_DATA,
                                                   0, 0, 3000) &&
                                WinHttpReceiveResponse(hreq, NULL)) {
                                FILE* f = NULL;
                                DWORD avail = 0u;
                                unsigned long long total = 0ull;
                                /* blob 上限防 DoS: 恶意服务端无法写盘填满 */
                                const unsigned long long MAX_BLOB_DL_SIZE =
                                    2ull * 1024ull * 1024ull;
                                int overflow = 0;
                                if (fopen_s(&f, tmp, "wb") == 0 && f != NULL) {
                                    while (WinHttpQueryDataAvailable(hreq, &avail) &&
                                           avail > 0u && !overflow) {
                                        uint8_t chunk[4096];
                                        DWORD got2 = 0u;
                                        DWORD want = (avail < (DWORD)sizeof(chunk))
                                                         ? avail : (DWORD)sizeof(chunk);
                                        if (!WinHttpReadData(hreq, chunk, want, &got2) ||
                                            got2 == 0u)
                                            break;
                                        if (total + got2 > MAX_BLOB_DL_SIZE) {
                                            overflow = 1; /* 超限: 中止, 不落盘 */
                                            break;
                                        }
                                        total += got2;
                                        fwrite(chunk, 1, got2, f);
                                    }
                                    fclose(f);
                                    if (overflow) {
                                        /* 删掉截断的临时文件, 回退本地 */
                                        remove(tmp);
                                        tmp[0] = '\0';
                                    } else {
                                        ok = TRUE;
                                    }
                                }
                            }
                        }
                    }
                }
                if (hreq != NULL)
                    WinHttpCloseHandle(hreq);
                if (hconn != NULL)
                    WinHttpCloseHandle(hconn);
                WinHttpCloseHandle(hin);
            }
            if (ok) {
                bp = tmp; /* 用下载的 blob (装载时验签, 失败仍 0xB10B) */
            }
            /* !ok = 网络不可达/超时 -> 静默回退本地 (离线优先, 不锁死) */
        }
        st = prot_vm_blob_load(bp, k_vm_names, 4u, g_vm_imgs,
                               &g_vm_blob_buf, &blob_size);
        if (st != PROT_OK) {
            printf("%s (code=%d)\n", prot_str_get(PROT_STR_MSG_BLOB), (int)st);
            exit(PROT_EXIT_BLOB_MISSING);
        }
    }

    /* A5 长驻留回归钩子: 看门狗启动后驻留 N 毫秒, 让周期复查多次触发
     * (e2e T11 用 --wait-after 验证干净环境零误报) */
    if (wait_after_ms > 0) {
        Sleep(wait_after_ms);
    }

    /* §9.1-7: 机器标识 (Phase 4: 真实硬件绑定); 读到序列号前先清零全部区 */
    memset(&mem, 0, sizeof(mem));
    {
        /* N4: 机器标识经间接表调用 (静态无直接 call) */
        uint64_t hwid = PROT_INDIRECT_CALL(PROT_INDIRECT_HOSTID,
                                           uint64_t (*)(void));
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
     * 依次执行 FNV 哈希 -> GOLDEN 混合 -> 期望值校验, 共享 demo_mem 中间区。
     * 镜像来自 §9.1-6b 装载的 vm.blob (DBI launcher)。 */
    st = vm_run_wrapped(&g_vm_imgs[0], &mem);
    if (st != PROT_OK) {
        PROT_LOG_VM_ERR(st);
        exit(1);
    }
    st = vm_run_wrapped(&g_vm_imgs[1], &mem);
    if (st != PROT_OK) {
        PROT_LOG_VM_ERR(st);
        exit(1);
    }

    /* §9.1-9b: RSA 授权 (A1 + Phase 4 tier/expires) —— 宿主验签, 结果由
     * VM#4 并入最终判定位。提供 --license-file 时: 验签失败/过期 =
     * license_ok=0, VM#4 使 result 归零; 未提供时与旧行为一致
     * (license_ok=1, tier=正式, 不过期)。 */
    mem.license_ok = 1u;
    mem.license_tier = PROT_LICENSE_TIER_FULL;
    mem.license_expires = 0u;
    if (license_path != NULL) {
        mem.license_ok = (uint32_t)PROT_INDIRECT_CALL(
            PROT_INDIRECT_LICENSE, int (*)(const char*, void*),
            license_path, &mem);
        {
            char eye[64];
            /* 模板串经 strcrypt 加密 (N 加固: 消除明文特征) */
            _snprintf_s(eye, sizeof(eye), _TRUNCATE,
                        prot_str_get(PROT_STR_LICENSE_FMT),
                        mem.license_ok, mem.license_tier, mem.license_expires);
            printf("%s\n", eye);
        }
    }

    /* N5: VM#3 期望值 —— 会话级。先设构建期默认 (g_prot_expect_default,
     * 与旧行为逐位一致); revoke/online 块若解析到服务端下发的会话
     * expect1/expect2 会覆盖 (每次启动不同, 破解者 patch "期望值比较"
     * 只对当次会话有效)。 */
    mem.vm_expect1 = g_prot_expect_default[0];
    mem.vm_expect2 = g_prot_expect_default[1];

    /* §9.1-9c: 吊销检查 (I1) —— 黑名单随 vm.blob 渠道分发, 启动校验。
     * strict(默认): 命中即拒 (0xB1E4); warn: 告警继续。
     * 文件缺失/损坏: 不阻断 (离线优先, 不因分发疏漏锁死客户)。
     * M3.1: --check-url 启用在线查询 (不可达/超时 -> 静默降级本地)。 */
    {
        const char* rp = (revoke_path != NULL) ? revoke_path : "revoke.blob";
        uint32_t rver = 0u;
        prot_revoke_status rs = PROT_INDIRECT_CALL(
            PROT_INDIRECT_REVOKE,
            prot_revoke_status (*)(const char*, const char*, uint32_t, uint32_t*),
            rp, mem.serial, mem.license_tier, &rver);
        int online_revoked = 0;
        if (rs == PROT_REVOKE_HIT) {
            online_revoked = 1;
        } else if (rs == PROT_REVOKE_CORRUPT) {
            printf("吊销列表损坏，已忽略 (revoke.blob)\n");
        }

        /* M3.1: 在线查询 (仅本地 mock / 生产 TLS 端点) */
        if (check_url != NULL && !online_revoked) {
            char url[1024];
            char buf[512];
            DWORD got = 0u;
            HINTERNET hin = NULL, hconn = NULL, hreq = NULL;
            BOOL ok = FALSE;

            _snprintf_s(url, sizeof(url), _TRUNCATE,
                        "%s?serial=%s&mid=%llx&tier=%u&build=%s",
                        check_url, mem.serial,
                        (unsigned long long)mem.machine_id,
                        mem.license_tier, PROT_VERSION_STR);
            /* 尝试 winhttp; 失败/超时 -> 静默降级 (离线优先) */
            hin = WinHttpOpen(L"PROT-Demo/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if (hin != NULL) {
                wchar_t whost[256];
                wchar_t wpath[512];
                URL_COMPONENTS uc;
                INTERNET_PORT port;
                memset(&uc, 0, sizeof(uc));
                uc.dwStructSize = sizeof(uc);
                uc.lpszHostName = whost;
                uc.dwHostNameLength = 256;
                uc.lpszUrlPath = wpath;
                uc.dwUrlPathLength = 512;
                {
                    wchar_t wurl[1024];
                    MultiByteToWideChar(CP_UTF8, 0, url, -1, wurl, 1024);
                    if (WinHttpCrackUrl(wurl, 0, 0, &uc)) {
                        port = uc.nPort;
                        hconn = WinHttpConnect(hin, whost, port, 0);
                        if (hconn != NULL) {
                            hreq = WinHttpOpenRequest(hconn, L"GET", wpath, NULL,
                                                     WINHTTP_NO_REFERER,
                                                     WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
                            if (hreq != NULL &&
                                WinHttpSendRequest(hreq,
                                                   WINHTTP_NO_ADDITIONAL_HEADERS,
                                                   0, WINHTTP_NO_REQUEST_DATA,
                                                   0, 0, 3000) &&
                                WinHttpReceiveResponse(hreq, NULL)) {
                                DWORD avail = 0u;
                                if (WinHttpQueryDataAvailable(hreq, &avail) &&
                                    avail > 0u && avail < sizeof(buf)) {
                                    if (WinHttpReadData(hreq, buf, avail, &got)) {
                                        buf[got] = '\0';
                                        if (strstr(buf, "\"revoked\"") != NULL)
                                            online_revoked = 1;
                                        ok = TRUE;
                                    }
                                }
                            }
                        }
                    }
                }
                if (hreq != NULL)
                    WinHttpCloseHandle(hreq);
                if (hconn != NULL)
                    WinHttpCloseHandle(hconn);
                WinHttpCloseHandle(hin);
            }
            if (ok) {
                char ob[32];
                /* N5: 解析会话级期望值 (服务端下发, 每次启动不同)。
                 * 格式: {"status":"ok","tier":1,"expect1":"0x..","expect2":"0x.."}
                 * 解析失败/缺失 -> 保持构建期默认 (不锁死)。 */
                if (!online_revoked) {
                    /* 解析会话级期望值, 格式:
                     * {"status":"ok","tier":1,"expect1":"0x..","expect2":"0x.."}
                     * (mock/生产 JSON 可能有空格, 用 strchr 定位值, 健壮解析) */
                    const char* e1 = strstr(buf, "\"expect1\"");
                    const char* e2 = strstr(buf, "\"expect2\"");
                    if (e1 != NULL && e2 != NULL) {
                        const char* v1 = strchr(e1, ':');
                        const char* v2 = strchr(e2, ':');
                        if (v1 != NULL && v2 != NULL) {
                            v1 = strchr(v1 + 1, '"');
                            v2 = strchr(v2 + 1, '"');
                            if (v1 != NULL && v2 != NULL) {
                                v1++;
                                v2++;
                                if (*v1 != '\0' && *v2 != '\0') {
                                    unsigned long long a1 = strtoull(v1, NULL, 0);
                                    unsigned long long a2 = strtoull(v2, NULL, 0);
                                    if (a1 != 0ull || a2 != 0ull) {
                                        mem.vm_expect1 = a1;
                                        mem.vm_expect2 = a2;
                                    }
                                }
                            }
                        }
                    }
                }
                _snprintf_s(ob, sizeof(ob), _TRUNCATE,
                            prot_str_get(PROT_STR_ONLINE_FMT),
                            online_revoked ? "revoked" : "ok");
                printf("%s\n", ob);
            }
            /* !ok = 网络不可达/超时 -> 静默降级本地 (离线优先, 不锁死) */
        }

        if (online_revoked) {
            printf("%s\n", prot_str_get(PROT_STR_MSG_REVOKED));
            fflush(stdout);
            if (revoke_strict) {
                exit(PROT_EXIT_REVOKED);
            }
        }
    }

    /* N5: VM#3 期望值校验 —— 期望值已在 revoke/online 块前设默认、
     * 在线会话被服务端下发值覆盖。 */
    st = vm_run_wrapped(&g_vm_imgs[2], &mem);
    if (st != PROT_OK) {
        PROT_LOG_VM_ERR(st);
        exit(1);
    }

    st = vm_run_wrapped(&g_vm_imgs[3], &mem);
    if (st != PROT_OK) {
        PROT_LOG_VM_ERR(st);
        exit(1);
    }

#ifdef PROT_DRILL_HOOK
    /* 演练钩子 (ATTACK_DRILL2): --loop-vm N 循环校验, 间隙 Sleep 给外部
     * dump/内存写留窗口. 仅测试构建启用, 发布构建无此代码. */
    {
        extern uint32_t g_loop_vm;
        uint32_t li;
        for (li = 0u; li < g_loop_vm && g_loop_vm > 0u; li++) {
            st = vm_run_wrapped(&g_vm_imgs[1], &mem); /* 循环 mix+verify */
            if (st != PROT_OK) {
                PROT_LOG_VM_ERR(st);
                exit(1);
            }
            st = vm_run_wrapped(&g_vm_imgs[2], &mem);
            if (st != PROT_OK) {
                PROT_LOG_VM_ERR(st);
                exit(1);
            }
            Sleep(500); /* 留出观测窗口 (D2b 下间隙为密文) */
        }
    }
#endif /* PROT_DRILL_HOOK */

    /* §9.1-10: N3 数据完整性 —— 三份冗余多数一致 + 校验和 (单点 patch 识破) */
    {
        uint32_t r1 = mem.result;
        uint32_t r2 = mem.result2;
        uint32_t r3 = mem.result3;
        uint32_t r;
        /* 多数一致 */
        if (r1 == r2)
            r = r1;
        else if (r1 == r3)
            r = r1;
        else
            r = r2;
        /* 校验和 */
        if ((r ^ 0xA5A5A5A5u) != mem.result_sum) {
            printf("%s\n", prot_str_get(PROT_STR_MSG_TAMPER));
            exit(PROT_EXIT_TAMPERED);
        }
        mem.result = r; /* 用多数一致值 */
    }

    /* §9.1-10b: FAKE 策略伪结果翻转 (全部副本, 保持一致性但结果反转) */
    if (prot_antidebug_fake_active()) {
        mem.result ^= 1u;
        mem.result2 ^= 1u;
        mem.result3 ^= 1u;
        mem.result_sum ^= 1u; /* W2: 翻转同步校验和, 保持一致 */
    }

    /* W2 (WIN_ENHANCE): 注册看门狗周期回调 (N3 冗余 + dbiguard 复查).
     * demo_mem 在 exit 前一直有效; FAKE 翻转后置就绪, 一致则复查生效.
     * 驻留场景 (loop/long-run) 下 watchdog 每轮复查关键字段. */
    g_demo_mem_ptr = &mem;
    g_demo_mem_ready = 1;
    prot_integrity_set_watchdog_callback(wd_n3_recheck);

    /* §9.1-11: 结果与退出码 */
    if (mem.result != 0) {
        printf("%s\n", prot_str_get(PROT_STR_MSG_OK));
        exit(0);
    }
    printf("%s\n", prot_str_get(PROT_STR_MSG_FAIL));
    exit(1);
}
