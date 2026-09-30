/*
 * demo/main.c 鈥?鍙嶉€嗗悜淇濇姢濂椾欢婕旂ず鍏ュ彛 (Lane D)
 *
 * 瀵瑰簲濂戠害 docs/CONTRACT.md 搂9銆傛祦绋?
 *   鎺у埗鍙?UTF-8 -> 鍙傛暟瑙ｆ瀽(--selftest / --wait-ms N) -> BANNER
 *   -> 鍙嶈皟璇曟壂鎻?鎽樿/绛栫暐 -> 瀹屾暣鎬ц嚜妫€ -> 鐪嬮棬鐙?-> HWID
 *   -> 杈撳叆搴忓垪鍙?-> VM 鏍￠獙 -> FAKE 浼粨鏋滅炕杞?-> 缁撴灉涓庨€€鍑虹爜銆? *
 * 閫€鍑虹爜 (濂戠害 搂9.3): 0 鎴愬姛 / 1 搴忓垪鍙锋棤鏁?/ 0xDB 璋冭瘯鐜 / 0xBAD 琚鏀广€? */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ## ⚠️ 顺序至关重要（2026-09-25 实测教训）
 *
 * `PROT_PLATFORM` / `PROT_PLATFORM_WINDOWS` **由 prot_platform.h 定义** ——
 * 故该头**必须先于任何 `#if PROT_PLATFORM`**。
 *
 * **踩过的坑**: 初版把平台头放在下方、`#if` 放在上方 ->
 *   两个宏都未定义 -> `0 == 0` 为 **真** -> `windows.h` **仍被包含** ->
 *   Linux 构建照旧失败（表面看"已条件化"，实际没生效）。
 */
#include "protect/prot_platform.h"

#if PROT_PLATFORM == PROT_PLATFORM_WINDOWS
#include <windows.h>
/* ⚠️ `winhttp.h` 也是 **Windows SDK 专有头**（与 windows.h 同属 SDK）——
 * 必须一起条件化。HTTP 已改走平台层（`prot_plat_http_get*`），
 * 本文件不再直接调用 WinHTTP。 */
#endif

#include "protect/antidebug.h"
#include "protect/prot_compiler.h"   /* B4: PROT_SNPRINTF */   /* B4: 平台抽象（HTTP/Sleep/时钟）*/

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

/* 组合配置 (阶段 2): 由 tools/compose.py 依据 compositions/<name>.json 生成。
 * 定义 PROT_MOD_<NAME>=1 表示该模块参与本次构建。
 * 未定义的模块: 其调用段被 #ifdef 排除, 且源文件不参与编译/链接
 * (不用空桩 —— 桩会被链进产物且本身是可被 patch 的攻击面)。 */
#include "prot_modconfig.h"

/* 未提供组合配置时 (直接手工 cl 编译) 退化为"全模块", 保持旧行为。 */
#ifndef PROT_COMPOSITION_NAME
#define PROT_MOD_ANTIDEBUG   1
#define PROT_MOD_BLOB        1
#define PROT_MOD_DBIGUARD    1
#define PROT_MOD_HOSTID      1
#define PROT_MOD_INDIRECT    1
#define PROT_MOD_INTEGRITY   1
#define PROT_MOD_LICENSE     1
#define PROT_MOD_REVOKE      1
#define PROT_MOD_SELFCRYPT   1
#define PROT_MOD_STRCRYPT    1
#define PROT_MOD_SYSCALL     1
#define PROT_MOD_VM          1
#define PROT_MOD_VMDETECT    1
#endif

/* S1 (2026-08-29): 深级密码已落地, 调试插桩清理 */

/* DBI launcher (鎶€鏈€?#3): VM 闀滃儚鐢?build\vm.blob 瑁呰浇, 涓嶅啀闈欐€佸祵鍏ャ€? * 椤哄簭涓?build.ps1 3c 鐨?pack 鍏ュ弬涓€鑷? 鍚嶇О椤讳笌 assemble --bin-name 鐩稿悓銆?*/
static const char* const k_vm_names[4] = {
    "hash", "mix", "verify", "gate",
};
static prot_vm_image g_vm_imgs[4];
static void* g_vm_blob_buf = NULL;

#ifdef PROT_DRILL_HOOK
/* 婕旂粌閽╁瓙 (ATTACK_DRILL2): --loop-vm N 寰幆鏍￠獙娆℃暟 */
uint32_t g_loop_vm = 0u;
#endif /* PROT_DRILL_HOOK */

/* S1 绾垫繁 (2026-08-29): EXT 缁勮皟鐢ㄥ寘瑁?鈥斺€?blob 瑁呰浇/楠岀/瀹屾暣鎬?鍙嶈皟璇?
 * 鍚婇攢 5 绫诲嚱鏁板凡鍔犲瘑, 瀹夸富璋冪敤鐐?enter/leave 鍚岀粍 (D2b 绐楀彛璇箟;
 * D2a 涓?enter/leave 绌鸿浆, 闆跺紑閿€)銆?*/
static prot_status sc_ext_enter(void)
{
    return prot_selfcrypt_enter(PROT_SELFCRYPT_GROUP_EXT);
}

static void sc_ext_leave(void)
{
    prot_selfcrypt_leave(PROT_SELFCRYPT_GROUP_EXT);
}

/* N2 绛栫暐 (ATTACK_DRILL2 E2-2): --dbiguard-policy EXIT 鏃?hook 妫€娴嬪嵆缁堟 */
int dbiguard_exit_policy = 0;

/* N5: VM#3 鏋勫缓鏈熼粯璁ゆ湡鏈涘€?(demo/gen/expect_default.c 鐢熸垚, 绂荤嚎鍏滃簳) */
extern const uint64_t g_prot_expect_default[2];

/* demo_mem 甯冨眬 (濂戠害 搂9.2, 涓?demo/license_*.vasm 鍋忕Щ娉ㄩ噴涓€鑷? 鍕挎敼) */
typedef struct demo_mem {
    char     serial[48];   /* +0  */
    uint32_t serial_len;   /* +48 */
    uint32_t result;       /* +52 */
    uint64_t machine_id;   /* +56 */
    uint64_t vm_h;         /* +64 (VM#1 杈撳嚭: FNV-1a 缁撴灉 h) */
    uint64_t vm_total;     /* +72 (VM#2 杈撳嚭: GOLDEN 娣峰悎 total) */
    uint64_t vm_scratch;   /* +80 (VM#1 鍐呴儴寰幆璁℃暟鍣? 瀹夸富鏃犻渶鍒濆鍖? */
    uint32_t license_ok;   /* +88 (A1: 瀹夸富 RSA 楠岀缁撴灉 0/1, VM#4 骞跺叆) */
    uint32_t license_tier; /* +92 (Phase 4: 鎺堟潈绛夌骇 0/1/2, 鍙備笌绛惧悕涓嶅彲绡℃敼) */
    uint32_t license_expires; /* +96 (Phase 4: 鍒版湡 unix, 0=姘镐箙, 鍙備笌绛惧悕) */
    uint32_t result2;      /* +100 (N3: result 鍓湰2, VM#4 鍐? */
    uint32_t result3;      /* +104 (N3: result 鍓湰3, VM#4 鍐? */
    uint32_t result_sum;   /* +108 (N3: result ^ 0xA5A5A5A5, VM#4 鍐? */
    uint64_t vm_expect1;   /* +112 (N5: VM#3 鏈熸湜鍊?h, 浼氳瘽绾? 绂荤嚎=鏋勫缓鏈熼粯璁? */
    uint64_t vm_expect2;   /* +120 (N5: VM#3 鏈熸湜鍊?total, 浼氳瘽绾? */
} demo_mem;                /* 鎬?128 瀛楄妭 (VM 浣跨敤鐨?+0..+108 鍋忕Щ涓嶅彉) */

/* W4 (WIN_ENHANCE): Release 闅愯棌鍐呴儴 prot_status 鐮?(浠呮樉绀虹粺涓€澶辫触鎻愮ず).
 * Dev 淇濈暀閿欒鐮佷究浜庤皟璇? */
#ifdef PROT_RELEASE_CONCEAL
#define PROT_LOG_VM_ERR(st) \
    printf("%s\n", prot_str_get(PROT_STR_MSG_FAIL))
#else
#define PROT_LOG_VM_ERR(st) \
    printf("%s (vm error %d)\n", prot_str_get(PROT_STR_MSG_FAIL), (int)(st))
#endif

/* ---------------------------------------------------------------------------
 * N1 杩愯鏃惰嚜鍙樺舰: .protcrypt 瀹瑰櫒 (g_prot_selfcrypt_blob) 瀹氫箟鍦? * src/selfcrypt.c (瀹炵幇鏂囦欢), 渚涙墍鏈夐摼鎺?selfcrypt.c 鐨勬ā鍧椾娇鐢ㄣ€? * ------------------------------------------------------------------------- */

/* N4 鍑芥暟绾ч棿鎺ュ寲: 缁忛棿鎺ヨ〃瑙ｆ瀽鍑芥暟鎸囬拡鍚庤皟鐢?(闈欐€佹棤鐩存帴 call)銆? * 娉涘瀷鍑芥暟鎸囬拡杞叿浣撶鍚?(鍑芥暟鎸囬拡浜掕浆, MSVC 鍏佽)銆?*/
#define PROT_INDIRECT_CALL(fn_id, sig, ...) \
    ((sig)prot_indirect_resolve(fn_id))(__VA_ARGS__)

/* N1 II-2 (D2b): VM 寮曟搸璋冪敤鍖呰９ 鈥斺€?enter 瑙ｅ瘑鍑芥暟缁?-> 璋冪敤 -> leave 閲嶅姞瀵嗐€? * D2a (榛樿) 涓?enter/leave 绌鸿浆, 琛屼负涓庝竴鏈熶竴鑷淬€? * 杩斿洖 prot_status: 璋冪敤缁撴灉; enter 澶辫触 (CRC) 涔熻繑鍥為敊璇€?*/
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

/* W2 (WIN_ENHANCE): 鐪嬮棬鐙楀懆鏈熷洖璋?鈥斺€?N3 鏁版嵁鍐椾綑 + dbiguard 澶嶆煡銆? * demo_mem 鍦?main() 鏍堜笂, 杩欓噷鐢ㄥ叏灞€鎸囬拡寮曠敤 (VM 閾惧畬鎴愬悗璁剧疆).
 * 杩斿洖 PROT_OK 涓€鑷?/ PROT_ERR_INTEGRITY 涓嶄竴鑷?(鐪嬮棬鐙楁寜 policy 澶勭悊). */
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
    /* N3: result 涓夊壇鏈鏁颁竴鑷?+ 鏍￠獙鍜?*/
    r1 = m->result;
    r2 = m->result2;
    r3 = m->result3;
    r = (r1 == r2) ? r1 : ((r1 == r3) ? r1 : r2);
    if ((r ^ 0xA5A5A5A5u) != m->result_sum)
        return PROT_ERR_INTEGRITY;
    if (r1 != r && r2 != r && r3 != r)
        return PROT_ERR_INTEGRITY;
    /* W2b: dbiguard 鍛ㄦ湡澶嶆煡 (N2 浠庡惎鍔ㄤ竴娆″崌绾т负鍛ㄦ湡) */
#ifdef PROT_MOD_DBIGUARD
    {
        prot_dbiguard_report drep;
        prot_dbiguard_scan(&drep);
        if (prot_dbiguard_suspicious(&drep))
            return PROT_ERR_INTEGRITY; /* hook 妫€娴嬪埌 -> 鎸?policy (EXIT) */
    }
#endif /* PROT_MOD_DBIGUARD */
    return PROT_OK;
}

/*
 * 瑙ｆ瀽 CLI 鍙傛暟 (濂戠害 搂9.1-2):
 *   --selftest       閫愰」鎵撳嵃妫€娴嬬粨鏋? *   --wait-ms N      鎵弿鍓?Sleep N 姣
 *   --wait-after N   鐪嬮棬鐙楀惎鍔ㄥ悗椹荤暀 N 姣 (A5 闀块┗鐣欏洖褰掗挬瀛?
 *   --license-file F 璇诲叆 RSA 鎺堟潈鏂囦欢 (A1) 骞堕獙绛? *   --vm-blob F      VM 闀滃儚 blob 璺緞 (榛樿 "vm.blob", DBI launcher)
 *   --blob-url URL   鍦ㄧ嚎涓嬪彂 vm.blob 绔偣 (BLOB_SIGN_PLAN; 涓嶅彲杈惧洖閫€鏈湴)
 *   --revoke-file F  鍚婇攢榛戝悕鍗曡矾寰?(榛樿 "revoke.blob", I1)
 *   --revoke-policy  鍚婇攢鍛戒腑绛栫暐: strict(榛樿, 鎷掔粷) / warn(鍛婅缁х画)
 *   --check-url URL  鍦ㄧ嚎楠岃瘉绔偣 (M3.1, 缂虹渷涓嶅惎鐢ㄥ湪绾? 涓嶅彲杈炬椂闄嶇骇鏈湴)
 * 杩斿洖 1 鎴愬姛, 0 鐢ㄦ硶閿欒銆? */
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
    *revoke_strict = 1; /* 榛樿 strict: 鍛戒腑鍗虫嫆缁?*/
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
            printf("prot-demo %s\n", PROT_VERSION_STR); /* RELEASE 搂1.2 */
            exit(0);
#ifdef PROT_DRILL_HOOK
        } else if (strcmp(argv[i], "--loop-vm") == 0) {
            /* 婕旂粌閽╁瓙 (ATTACK_DRILL2): 寰幆 VM 鏍￠獙 N 娆? 渚涘閮?dump/鍐欓獙璇?*/
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

/* --selftest: 閫愰」鎵撳嵃妫€娴嬬粨鏋?(濂戠害 搂9.1-4) */
#ifdef PROT_MOD_ANTIDEBUG
static void print_selftest(const prot_antidebug_report* rep)
{
    printf(prot_str_get(PROT_STR_SELFTEST_PEB), rep->peb_being_debugged);
  printf("\n");
    printf(prot_str_get(PROT_STR_SELFTEST_NTGFLAG), rep->peb_nt_global_flag);
  printf("\n");
    printf(prot_str_get(PROT_STR_SELFTEST_DEBUGPORT), rep->debug_port);
  printf("\n");
    printf(prot_str_get(PROT_STR_SELFTEST_DEBUGFLAGS), rep->debug_flags);
  printf("\n");
    printf(prot_str_get(PROT_STR_SELFTEST_DEBUGOBJ), rep->debug_object);
  printf("\n");
    printf(prot_str_get(PROT_STR_SELFTEST_HWBP), rep->hardware_breakpoints);
  printf("\n");
    printf(prot_str_get(PROT_STR_SELFTEST_TIMING), rep->timing_suspicious);
  printf("\n");
    printf(prot_str_get(PROT_STR_SELFTEST_KDBG), rep->kernel_debugger);
  printf("\n");
    printf(prot_str_get(PROT_STR_SELFTEST_HEAPFLAGS), rep->debug_heap_flags);
  printf("\n");
    printf(prot_str_get(PROT_STR_SELFTEST_INT3), rep->int3_honey);
  printf("\n");
    printf(prot_str_get(PROT_STR_SELFTEST_PPID), rep->ppid_blacklist);
  printf("\n");
    printf(prot_str_get(PROT_STR_SELFTEST_CLOCK), rep->clock_drift_sec);
  printf("\n");
}
#endif /* PROT_MOD_ANTIDEBUG */   /* print_selftest 函数 */

/* base64 瑙ｇ爜 (鏍囧噯 64 瀛楃瀛楁瘝琛?銆傝繑鍥炶В鐮佸悗瀛楄妭鏁? 闈炴硶杈撳叆杩斿洖 (size_t)-1銆?*/
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
 * 璇?license.txt (A1 + Phase 4 tier/expires, 鏍煎紡瑙?tools/vmenc.py sign 杈撳嚭):
 *   SERIAL=... / MACHINE_ID=0x.. / PRODUCT=... / TIER=<0|1|2> /
 *   EXPIRES=<unix> / SIGNATURE=<base64 384B>
 * 楠岀閫氳繃 -> 杩斿洖 1 骞跺啓鍑?tier/expires; 鏂囦欢缂哄け/瀛楁閿?绛惧悕鏃犳晥/鏈哄櫒
 * 涓嶅尮閰?宸茶繃鏈?-> 杩斿洖 0銆俆IER 缂虹渷 1, EXPIRES 缂虹渷 0 (姘镐箙)銆? * 闈?static: N4 闂存帴琛?(demo/gen/indirect_table.c) 寮曠敤銆?*/
int load_and_verify_license(const char* path, demo_mem* mem)
{
    FILE* f;
    char line[1024];
    uint8_t sig[384];
    uint8_t msg[256];
    size_t msg_len;
    int have_serial = 0, have_prod = 0, have_sig = 0;
    uint32_t tier = PROT_LICENSE_TIER_FULL;
    uint32_t expires = 0u;
    char f_serial[48] = {0};
    char f_prod[64] = {0};
    int err;

    err = PROT_FOPEN_S(&f, path, "rb");
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
                PROT_STRCPY_S(f_serial, sizeof(f_serial), eq);
                have_serial = 1;
            }
        } else if (strcmp(line, "PRODUCT") == 0) {
            if (strlen(eq) < sizeof(f_prod)) {
                PROT_STRCPY_S(f_prod, sizeof(f_prod), eq);
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
                if (d != 384)
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
    /* 璇曠敤鏈熸帶鍒? expires != 0 涓斿凡杩囨湡 -> 鎷掔粷 */
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
#ifdef PROT_MOD_ANTIDEBUG
    prot_antidebug_report rep;
#endif /* PROT_MOD_ANTIDEBUG */   /* rep 声明 */
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

    /* 搂9.1-1: 鎺у埗鍙?UTF-8 杈撳嚭/杈撳叆 */
    (void)prot_plat_console_utf8();
     /* 宕╂簝鐜板満鏃犵紦鍐?(S1 鎺掗殰绛? */
    
     /* S1 鎺掗殰: 宕╂簝鍦板潃钀界洏 */

    /* 搂9.1-2: 瑙ｆ瀽鍙傛暟 */
    if (!parse_args(argc, argv, &selftest, &wait_ms, &wait_after_ms,
                    &license_path, &vm_blob_path, &blob_url, &revoke_path,
                    &revoke_strict, &check_url)) {
        return 2; /* 鐢ㄦ硶閿欒 */
    }

    /* 搂9.1-3: BANNER */
    printf("%s\n", prot_str_get(PROT_STR_BANNER));

    /* N1 (浜屾湡 II-1): 瑙ｅ瘑寮曟搸鍑芥暟 + 瑙ｅ瘑鎬?CRC 鏍￠獙; 澶辫触 = 瀹屾暣鎬ц鐮村潖 */
    {
        prot_status sc = prot_selfcrypt_init();
        if (sc != PROT_OK) {
            printf("%s\n", prot_str_get(PROT_STR_MSG_TAMPER));
            fflush(stdout);
            exit(PROT_EXIT_TAMPERED);
        }
    }

    /* 搂9.1-2: --wait-ms N 鍦ㄦ壂鎻忓墠寤舵椂 (涓鸿皟璇曢檮鍔犵暀鍑虹獥鍙? */
    if (wait_ms > 0) {
        prot_plat_sleep_ms(wait_ms);
    }

#ifdef PROT_MOD_ANTIDEBUG
    /* 搂9.1-4: 鍙嶈皟璇曟壂鎻?-> 鎽樿 -> (--selftest 閫愰」) -> EXIT 绛栫暐 */
    if (sc_ext_enter() != PROT_OK) {
        printf("%s\n", prot_str_get(PROT_STR_MSG_FAIL));
        exit(1);
    }
    prot_antidebug_scan(&rep);
    sc_ext_leave();
    printf("反调试扫描: %s\n",
           prot_antidebug_detected(&rep) ? "发现可疑" : "通过");
    if (selftest) {
        print_selftest(&rep);
    }
#endif /* PROT_MOD_ANTIDEBUG */   /* 反调试 scan 段 */

    /* 搂9.1-4b (N2): 鍙?DBI/鍙?hook 妫€娴?鈥斺€?鍜ㄨ椤? 鍙姤鍛婁笉瑙﹀彂绛栫暐 */
#ifdef PROT_MOD_DBIGUARD
    {
        prot_dbiguard_report drep;
        prot_dbiguard_scan(&drep);
        if (selftest) {
            printf(prot_str_get(PROT_STR_SELFTEST_DBI_HOOK), drep.inline_hooks);
  printf("\n");
            printf(prot_str_get(PROT_STR_SELFTEST_DBI_FRIDA), drep.frida_agent);
  printf("\n");
            printf(prot_str_get(PROT_STR_SELFTEST_DBI_RXRW), drep.rx_rw_regions);
  printf("\n");
            printf(prot_str_get(PROT_STR_SELFTEST_DBI_THREADS), drep.thread_count);
  printf("\n");
        }
        if (prot_dbiguard_suspicious(&drep)) {
            printf("疑似动态插桩/hook 环境 (咨询项, 不影响运行)\n");
            /* N2 绛栫暐 (ATTACK_DRILL2 E2-2): --dbiguard-policy EXIT
             * 鏃?hook 妫€娴嬪埌 -> 缁堟 (0xDB), 闃叉敞鍏?hook 琚拷鐣?*/
            if (dbiguard_exit_policy) {
                printf("%s\n", prot_str_get(PROT_STR_MSG_DBG));
                fflush(stdout);
                exit(PROT_EXIT_DEBUG_DETECTED);
            }
        }
    }
#endif /* PROT_MOD_DBIGUARD */

    /* 搂9.1-4c (M1): 铏氭嫙鏈?娌欑妫€娴?鈥斺€?鍜ㄨ椤? 鍙姤鍛婁笉瑙﹀彂绛栫暐 */
#ifdef PROT_MOD_VMDETECT
    {
        prot_vmdetect_report vmrep;
        prot_vmdetect_scan(&vmrep);
        if (selftest) {
            printf(prot_str_get(PROT_STR_SELFTEST_VM_HV), vmrep.cpu_hypervisor);
  printf("\n");
            printf(prot_str_get(PROT_STR_SELFTEST_VM_VENDOR), vmrep.hv_vendor);
  printf("\n");
            printf(prot_str_get(PROT_STR_SELFTEST_VM_PROCS), vmrep.vm_processes);
  printf("\n");
        }
        if (prot_vmdetect_suspicious(&vmrep)) {
            printf("疑似虚拟机环境 (咨询项, 不影响运行)\n");
        }
    }
#endif /* PROT_MOD_VMDETECT */

#ifdef PROT_MOD_ANTIDEBUG
    /*
     * 娉ㄦ剰: src/antidebug.c 鐨?EXIT 绛栫暐瀹炵幇鏄?TerminateProcess(0xDB),
     * 璇ヨ皟鐢ㄤ笉鍐插埛 stdout (stdout 閲嶅畾鍚戝埌绠￠亾鏃朵负鍏ㄧ紦鍐? 鏁版嵁浼氫涪澶?銆?     * 鍥犳鍏堟妸 MSG_DBG 鎵撳嵃骞跺啿鍒? 鍐嶈Е鍙戠瓥鐣? 淇濊瘉 搂9.1 瑕佹眰鐨勬彁绀哄彲瑙併€?     */
    if (prot_antidebug_detected(&rep)) {
        printf("%s\n", prot_str_get(PROT_STR_MSG_DBG));
        fflush(stdout);
    }
    if (sc_ext_enter() == PROT_OK) {
        prot_antidebug_apply_policy(PROT_POLICY_EXIT);
        sc_ext_leave();
    } else {
        prot_antidebug_apply_policy(PROT_POLICY_EXIT);
    }
    if (prot_antidebug_detected(&rep)) {
        exit(PROT_EXIT_DEBUG_DETECTED); /* 鍏滃簳: 鑻ョ瓥鐣ユ湭缁堟杩涚▼鍒欐樉寮忛€€鍑?*/
    }
#endif /* PROT_MOD_ANTIDEBUG */   /* 反调试策略段 */

#ifdef PROT_MOD_INTEGRITY
    /* 搂9.1-5: 瀹屾暣鎬ц嚜妫€ */
    if (sc_ext_enter() != PROT_OK
        || prot_integrity_check_self() != PROT_OK) {
        printf("%s\n", prot_str_get(PROT_STR_MSG_TAMPER));
        exit(PROT_EXIT_TAMPERED);
    }
    sc_ext_leave();
#endif /* PROT_MOD_INTEGRITY */   /* 完整性自检段 */

#ifdef PROT_MOD_INTEGRITY
    /* R3.2-b 第2组 (2026-09-29): **登记关键判定点**（跨模块，注册式）
     *
     * ## 为什么必须登记
     *   `checks_guards` 的编译期静态表只含 integrity/antidebug（deps 内）。
     *   license / dbiguard / vmdetect 的 deps 均为 [] -> integrity.c
     *   **不能**直接引用（破坏组合裁剪）-> 由宿主在此登记。
     *
     * ## 判定点清单来源
     *   `modules.json` 的 `host_hooks[].predicate`（官方声明）:
     *     dbiguard.pre_license.predicate = prot_dbiguard_suspicious
     *     vmdetect.post_license.predicate = prot_vmdetect_suspicious
     *   `prot_license_verify` 不在 host_hooks（是**宿主自己的授权门**）,
     *   但它恰是 R3.2-a 实测的**高危缺口**（在 selfcrypt 掩码区内 -> 段 CRC
     *   抓不到），故一并登记。
     *
     * ## 为什么用 `#if defined(A) && defined(B)`
     *   按模块裁剪时（如 'standard' 不含 vmdetect）若只判 INTEGRITY,
     *   会引用**未定义符号** -> 链接失败。双重条件保证只在两者都在时才登记。
     *
     * ## 时机
     *   必须在**首次** `prot_integrity_check_guards()` 之前
     *   （即 watchdog 启动前）—— 快照建立后再登记会被**拒绝**
     *   （`PROT_ERR_INVALID_ARG`，避免"登记了却永不比对"的假防护）。
     */
#if defined(PROT_MOD_LICENSE)
    (void)prot_integrity_register_guard(
        "prot_license_verify", (const void*)&prot_license_verify);
#endif
#if defined(PROT_MOD_DBIGUARD)
    (void)prot_integrity_register_guard(
        "prot_dbiguard_suspicious", (const void*)&prot_dbiguard_suspicious);
#endif
#if defined(PROT_MOD_VMDETECT)
    (void)prot_integrity_register_guard(
        "prot_vmdetect_suspicious", (const void*)&prot_vmdetect_suspicious);
#endif
#endif /* PROT_MOD_INTEGRITY */   /* R3.2-b 判定点登记 */

#ifdef PROT_MOD_INTEGRITY
    /* 搂9.1-6: 鐪嬮棬鐙?(姣?5 绉?卤40% 鎶栧姩澶嶆煡瀹屾暣鎬?+ A5 鍙嶈皟璇? */
    prot_integrity_start_watchdog(PROT_POLICY_EXIT, 5000);
#endif /* PROT_MOD_INTEGRITY */   /* 看门狗启动 */

    /* 搂9.1-6b: 瑁呰浇 VM blob (DBI launcher, 鎶€鏈€?#3) 鈥斺€?闀滃儚瀵嗘枃涓嶉潤鎬?     * 宓屽叆 exe; 缂哄け/鎹熷潖 -> 鎷掔粷杩愯 (0xB10B)銆傞粯璁ょ浉瀵?cwd 鎵?vm.blob銆?     * BLOB_SIGN_PLAN: --blob-url 鏃跺厛浠庣綉缁滀笅杞藉埌涓存椂鏂囦欢 (楠岀鍏滃簳,
     * 涓棿浜烘浛鎹篃杩囦笉浜?RSA 绛惧悕); 涓嬭浇澶辫触/涓嶅彲杈?-> 鍥為€€鏈湴璺緞銆?*/
    {
        const char* bp = (vm_blob_path != NULL) ? vm_blob_path : "vm.blob";
        size_t blob_size = 0u;
        if (blob_url != NULL) {
            /* ## B4（2026-09-25）: WinHTTP -> **平台层**（跨平台）
             *
             * **改动前**: 82 行 WinHTTP 调用（`WinHttpOpen`/`Connect`/
             *   `OpenRequest`/`SendRequest`/`ReceiveResponse`/
             *   `QueryDataAvailable`/`ReadData`/`CloseHandle`）——
             *   Windows 专有，Linux 无法编译。
             *
             * **改动后**: 一次 `prot_plat_http_get()` 调用。
             *   平台实现:
             *     · Windows —— **原 WinHTTP 逻辑搬迁**（行为不变）
             *     · Linux   —— **如实返回 UNSUPPORTED**
             *       （不引入 libcurl；见 prot_platform.h 分组 13 的决策）
             *
             * **语义等价性**: 原代码在下载失败时**静默回退本地**
             *   （下方 `!ok` 分支）。Linux 返回 UNSUPPORTED -> 同样回退
             *   -> **行为与 Windows 网络失败时完全一致**。
             */
            static char tmp[64] = "vm_blob_dl.tmp";
            prot_status dl_st = prot_plat_http_get(blob_url, tmp, 0u);
            if (dl_st == PROT_OK) {
                bp = tmp;   /* 用下载的 blob（装载时验签，失败仍 0xB10B）*/
            } else {
                /* 未实现 / 网络不可达 -> **回退本地路径**（离线优先，不锁死）。
                 * Linux 侧走此分支（`PROT_ERR_UNSUPPORTED`）——
                 * **与 Windows 网络故障时的行为一致**。 */
                tmp[0] = '\0';
            }
        }
        if (sc_ext_enter() != PROT_OK) {
            printf("%s\n", prot_str_get(PROT_STR_MSG_FAIL));
            exit(1);
        }
        st = prot_vm_blob_load(bp, k_vm_names, 4u, g_vm_imgs,
                               &g_vm_blob_buf, &blob_size);
        /* S2: 装载后内存重编码 (每运行密钥域不同, 双 dump 失效) */
        if (st == PROT_OK) {
            uint64_t ent = (uint64_t)prot_plat_monotonic_ns() / 1000000ull
                           ^ ((uint64_t)0ull << 32u)
                           ^ (uint64_t)(uintptr_t)bp;
            uint32_t vi;
            for (vi = 0u; vi < 4u; vi++)
                prot_vm_rekey(&g_vm_imgs[vi], (ent ^ (uint64_t)vi) | 1u);
        }
        sc_ext_leave();
        if (st != PROT_OK) {
            printf("%s (code=%d)\n", prot_str_get(PROT_STR_MSG_BLOB), (int)st);
            exit(PROT_EXIT_BLOB_MISSING);
        }
    }

    /* A5 闀块┗鐣欏洖褰掗挬瀛? 鐪嬮棬鐙楀惎鍔ㄥ悗椹荤暀 N 姣, 璁╁懆鏈熷鏌ュ娆¤Е鍙?     * (e2e T11 鐢?--wait-after 楠岃瘉骞插噣鐜闆惰鎶? */
    if (wait_after_ms > 0) {
        prot_plat_sleep_ms(wait_after_ms);
    }

    /* 搂9.1-7: 鏈哄櫒鏍囪瘑 (Phase 4: 鐪熷疄纭欢缁戝畾); 璇诲埌搴忓垪鍙峰墠鍏堟竻闆跺叏閮ㄥ尯 */
    memset(&mem, 0, sizeof(mem));
    {
        /* N4: 鏈哄櫒鏍囪瘑缁忛棿鎺ヨ〃璋冪敤 (闈欐€佹棤鐩存帴 call) */
        uint64_t hwid = PROT_INDIRECT_CALL(PROT_INDIRECT_HOSTID,
                                           uint64_t (*)(void));
        printf("%s", prot_str_get(PROT_STR_MSG_HWID));
        {
            const char* _hf = prot_str_get(PROT_STR_MSG_HWID_FMT);
            printf(_hf, (unsigned long long)hwid);
            printf("\n");
        }
        mem.machine_id = hwid;
    }

    /* 搂9.1-8: 鎻愮ず骞惰鍏ュ簭鍒楀彿 (鍘绘帀鎹㈣, 闀垮害涓婇檺 47) */
    printf("%s", prot_str_get(PROT_STR_PROMPT_SERIAL));
    fflush(stdout);
    if (fgets(mem.serial, sizeof(mem.serial), stdin) == NULL) {
        mem.serial_len = 0;
    } else {
        n = strlen(mem.serial);
        while (n > 0 && (mem.serial[n - 1] == '\n' || mem.serial[n - 1] == '\r')) {
            mem.serial[--n] = '\0';
        }
        mem.serial_len = (uint32_t)n; /* fgets 涓€娆¤嚦澶?47 瀛楃, 绗﹀悎涓婇檺 */
    }

    /* 搂9.1-9: VM 鏍￠獙 鈥斺€?Phase 2a: 鎷嗘垚 3 涓嫭绔嬪皬 VM, 鍚勮嚜瀵嗛挜/缃崲/绐楀彛銆?     * 渚濇鎵ц FNV 鍝堝笇 -> GOLDEN 娣峰悎 -> 鏈熸湜鍊兼牎楠? 鍏变韩 demo_mem 涓棿鍖恒€?     * 闀滃儚鏉ヨ嚜 搂9.1-6b 瑁呰浇鐨?vm.blob (DBI launcher)銆?*/
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

    /* 搂9.1-9b: RSA 鎺堟潈 (A1 + Phase 4 tier/expires) 鈥斺€?瀹夸富楠岀, 缁撴灉鐢?     * VM#4 骞跺叆鏈€缁堝垽瀹氫綅銆傛彁渚?--license-file 鏃? 楠岀澶辫触/杩囨湡 =
     * license_ok=0, VM#4 浣?result 褰掗浂; 鏈彁渚涙椂涓庢棫琛屼负涓€鑷?     * (license_ok=1, tier=姝ｅ紡, 涓嶈繃鏈?銆?*/
    mem.license_ok = 1u;
    mem.license_tier = PROT_LICENSE_TIER_FULL;
    mem.license_expires = 0u;
    if (license_path != NULL) {
        if (sc_ext_enter() != PROT_OK) {
            printf("%s\n", prot_str_get(PROT_STR_MSG_FAIL));
            exit(1);
        }
        mem.license_ok = (uint32_t)PROT_INDIRECT_CALL(
            PROT_INDIRECT_LICENSE, int (*)(const char*, void*),
            license_path, &mem);
        sc_ext_leave();
        {
            char eye[64];
            /* 妯℃澘涓茬粡 strcrypt 鍔犲瘑 (N 鍔犲浐: 娑堥櫎鏄庢枃鐗瑰緛) */
            PROT_SNPRINTF(eye, sizeof(eye),
                        prot_str_get(PROT_STR_LICENSE_FMT),
                        mem.license_ok, mem.license_tier, mem.license_expires);
            printf("%s\n", eye);
        }
    }

    /* N5: VM#3 鏈熸湜鍊?鈥斺€?浼氳瘽绾с€傚厛璁炬瀯寤烘湡榛樿 (g_prot_expect_default,
     * 涓庢棫琛屼负閫愪綅涓€鑷?; revoke/online 鍧楄嫢瑙ｆ瀽鍒版湇鍔＄涓嬪彂鐨勪細璇?     * expect1/expect2 浼氳鐩?(姣忔鍚姩涓嶅悓, 鐮磋В鑰?patch "鏈熸湜鍊兼瘮杈?
     * 鍙褰撴浼氳瘽鏈夋晥)銆?*/
    mem.vm_expect1 = g_prot_expect_default[0];
    mem.vm_expect2 = g_prot_expect_default[1];

    /* 搂9.1-9c: 鍚婇攢妫€鏌?(I1) 鈥斺€?榛戝悕鍗曢殢 vm.blob 娓犻亾鍒嗗彂, 鍚姩鏍￠獙銆?     * strict(榛樿): 鍛戒腑鍗虫嫆 (0xB1E4); warn: 鍛婅缁х画銆?     * 鏂囦欢缂哄け/鎹熷潖: 涓嶉樆鏂?(绂荤嚎浼樺厛, 涓嶅洜鍒嗗彂鐤忔紡閿佹瀹㈡埛)銆?     * M3.1: --check-url 鍚敤鍦ㄧ嚎鏌ヨ (涓嶅彲杈?瓒呮椂 -> 闈欓粯闄嶇骇鏈湴)銆?*/
    {
        const char* rp = (revoke_path != NULL) ? revoke_path : "revoke.blob";
        uint32_t rver = 0u;
        prot_revoke_status rs;
        if (sc_ext_enter() != PROT_OK) {
            printf("%s\n", prot_str_get(PROT_STR_MSG_FAIL));
            exit(1);
        }
        rs = PROT_INDIRECT_CALL(
            PROT_INDIRECT_REVOKE,
            prot_revoke_status (*)(const char*, const char*, uint32_t, uint32_t*),
            rp, mem.serial, mem.license_tier, &rver);
        sc_ext_leave();
        int online_revoked = 0;
        if (rs == PROT_REVOKE_HIT) {
            online_revoked = 1;
        } else if (rs == PROT_REVOKE_CORRUPT) {
            printf("%s\n", prot_str_get(PROT_STR_MSG_REVOKE_CORRUPT));
        }

        /* M3.1: 鍦ㄧ嚎鏌ヨ (浠呮湰鍦?mock / 鐢熶骇 TLS 绔偣) */
        if (check_url != NULL && !online_revoked) {
            char url[1024];
            char buf[512];
            /* ## B4（2026-09-25）: 第二处 WinHTTP -> 平台层
             *
             * **改动前**: 约 62 行 WinHTTP 调用（下载吊销 JSON 到内存）。
             * **改动后**: 一次 `prot_plat_http_get_mem()` 调用。
             *
             * **语义等价性**: 原代码在网络失败时**静默降级**
             *   （`ok` 保持 FALSE -> 不解析）。Linux 返回 UNSUPPORTED
             *   -> `ok` 同样保持 0 -> **行为一致**。
             */
            size_t got = 0u;
            int ok = 0;

            PROT_SNPRINTF(url, sizeof(url),
                        prot_str_get(PROT_STR_URL_CHECK_FMT),
                        check_url, mem.serial,
                        (unsigned long long)mem.machine_id,
                        mem.license_tier, PROT_VERSION_STR);
            if (prot_plat_http_get_mem(url, buf, sizeof(buf), &got) == PROT_OK) {
                if (strstr(buf, "\"revoked\"") != NULL)
                    online_revoked = 1;
                ok = 1;
            }
            if (ok) {
                char ob[32];
                /* N5: 瑙ｆ瀽浼氳瘽绾ф湡鏈涘€?(鏈嶅姟绔笅鍙? 姣忔鍚姩涓嶅悓)銆?                 * 鏍煎紡: {"status":"ok","tier":1,"expect1":"0x..","expect2":"0x.."}
                 * 瑙ｆ瀽澶辫触/缂哄け -> 淇濇寔鏋勫缓鏈熼粯璁?(涓嶉攣姝?銆?*/
                if (!online_revoked) {
                    /* 瑙ｆ瀽浼氳瘽绾ф湡鏈涘€? 鏍煎紡:
                     * {"status":"ok","tier":1,"expect1":"0x..","expect2":"0x.."}
                     * (mock/鐢熶骇 JSON 鍙兘鏈夌┖鏍? 鐢?strchr 瀹氫綅鍊? 鍋ュ．瑙ｆ瀽) */
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
                PROT_SNPRINTF(ob, sizeof(ob),
                            prot_str_get(PROT_STR_ONLINE_FMT),
                            online_revoked ? "revoked" : "ok");
                printf("%s\n", ob);
            }
            /* !ok = 缃戠粶涓嶅彲杈?瓒呮椂 -> 闈欓粯闄嶇骇鏈湴 (绂荤嚎浼樺厛, 涓嶉攣姝? */
        }

        if (online_revoked) {
            printf("%s\n", prot_str_get(PROT_STR_MSG_REVOKED));
            fflush(stdout);
            if (revoke_strict) {
                exit(PROT_EXIT_REVOKED);
            }
        }
    }

    /* N5: VM#3 鏈熸湜鍊兼牎楠?鈥斺€?鏈熸湜鍊煎凡鍦?revoke/online 鍧楀墠璁鹃粯璁ゃ€?     * 鍦ㄧ嚎浼氳瘽琚湇鍔＄涓嬪彂鍊艰鐩栥€?*/
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
    /* 婕旂粌閽╁瓙 (ATTACK_DRILL2): --loop-vm N 寰幆鏍￠獙, 闂撮殭 Sleep 缁欏閮?     * dump/鍐呭瓨鍐欑暀绐楀彛. 浠呮祴璇曟瀯寤哄惎鐢? 鍙戝竷鏋勫缓鏃犳浠ｇ爜. */
    {
        extern uint32_t g_loop_vm;
        uint32_t li;
        for (li = 0u; li < g_loop_vm && g_loop_vm > 0u; li++) {
            st = vm_run_wrapped(&g_vm_imgs[1], &mem); /* 寰幆 mix+verify */
            if (st != PROT_OK) {
                PROT_LOG_VM_ERR(st);
                exit(1);
            }
            st = vm_run_wrapped(&g_vm_imgs[2], &mem);
            if (st != PROT_OK) {
                PROT_LOG_VM_ERR(st);
                exit(1);
            }
            prot_plat_sleep_ms(500); /* 鐣欏嚭瑙傛祴绐楀彛 (D2b 涓嬮棿闅欎负瀵嗘枃) */
        }
    }
#endif /* PROT_DRILL_HOOK */

    /* 搂9.1-10: N3 鏁版嵁瀹屾暣鎬?鈥斺€?涓変唤鍐椾綑澶氭暟涓€鑷?+ 鏍￠獙鍜?(鍗曠偣 patch 璇嗙牬) */
    {
        uint32_t r1 = mem.result;
        uint32_t r2 = mem.result2;
        uint32_t r3 = mem.result3;
        uint32_t r;
        /* 澶氭暟涓€鑷?*/
        if (r1 == r2)
            r = r1;
        else if (r1 == r3)
            r = r1;
        else
            r = r2;
        /* 鏍￠獙鍜?*/
        if ((r ^ 0xA5A5A5A5u) != mem.result_sum) {
            printf("%s\n", prot_str_get(PROT_STR_MSG_TAMPER));
            exit(PROT_EXIT_TAMPERED);
        }
        mem.result = r; /* 鐢ㄥ鏁颁竴鑷村€?*/
    }

    /* 搂9.1-10b: FAKE 绛栫暐浼粨鏋滅炕杞?(鍏ㄩ儴鍓湰, 淇濇寔涓€鑷存€т絾缁撴灉鍙嶈浆) */
#ifdef PROT_MOD_ANTIDEBUG
    if (prot_antidebug_fake_active()) {
        mem.result ^= 1u;
        mem.result2 ^= 1u;
        mem.result3 ^= 1u;
        mem.result_sum ^= 1u; /* W2: 缈昏浆鍚屾鏍￠獙鍜? 淇濇寔涓€鑷?*/
    }
#endif /* PROT_MOD_ANTIDEBUG */   /* fake_active 段 */

    /* W2 (WIN_ENHANCE): 娉ㄥ唽鐪嬮棬鐙楀懆鏈熷洖璋?(N3 鍐椾綑 + dbiguard 澶嶆煡).
     * demo_mem 鍦?exit 鍓嶄竴鐩存湁鏁? FAKE 缈昏浆鍚庣疆灏辩华, 涓€鑷村垯澶嶆煡鐢熸晥.
     * 椹荤暀鍦烘櫙 (loop/long-run) 涓?watchdog 姣忚疆澶嶆煡鍏抽敭瀛楁. */
    g_demo_mem_ptr = &mem;
    g_demo_mem_ready = 1;
#ifdef PROT_MOD_INTEGRITY
    prot_integrity_set_watchdog_callback(wd_n3_recheck);
#endif /* PROT_MOD_INTEGRITY */   /* 看门狗回调注册 */

    /* 搂9.1-11: 缁撴灉涓庨€€鍑虹爜 */
    if (mem.result != 0) {
        printf("%s\n", prot_str_get(PROT_STR_MSG_OK));
        exit(0);
    }
    printf("%s\n", prot_str_get(PROT_STR_MSG_FAIL));
    exit(1);
}

