/*
 * examples/tool_demo/main.c — 小工具接入示例 (保护 SDK 实证)
 *
 * 一个"文件加密小工具"展示如何把保护套件用于你自己的工具:
 *   1. 授权门: RSA license + 机器绑定 + 试用期 + 黑名单吊销
 *   2. 校验逻辑进 VM: check.vasm (FNV+xorshift+比对), 静态不可读
 *   3. 防篡改: .text/.rdata/.pdata CRC + 看门狗
 *   4. 反调试: 完整 antidebug 扫描
 *   5. 断源: VM 镜像由 vm.blob 装载, exe 内无 VM 逻辑
 *
 * 用法:
 *   tool_demo.exe --serial <sn> [--license-file <f>] [--vm-blob <f>]
 *                 [--encrypt <file>] [--decrypt <file>]
 *   授权通过后执行加/解密 (XOR 简单演示算法)。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <windows.h>
#include <winhttp.h>

#include "protect/antidebug.h"
#include "protect/blob.h"
#include "protect/hostid.h"
#include "protect/integrity.h"
#include "protect/license.h"
#include "protect/revoke.h"
#include "protect/vm.h"

/* VM 镜像: 由 build_example.ps1 打包的 vm.blob 装载 */
static prot_vm_image g_check_img;
static void* g_blob_buf = NULL;

/* 宿主内存 (与 check.vmc 编译后的布局一致: 变量区 0x40 起由 vmc 分配) */
typedef struct tool_mem {
    char     serial[48];      /* +0   */
    uint32_t serial_len;      /* +48  */
    uint32_t result;          /* +52  */
    uint64_t machine_id;      /* +56  */
    uint64_t vm_vars[8];      /* +64  (vmc 变量区: i/h/x/total/ok 等) */
    uint32_t license_ok;      /* +128 */
    uint32_t license_tier;    /* +132 */
    uint32_t license_expires; /* +136 */
} tool_mem;

static void usage(void)
{
    fprintf(stderr,
            "usage: tool_demo.exe --serial <sn> --license-file F [--vm-blob F]\n"
            "                     [--revoke-file F] [--check-url URL]\n"
            "                     [--encrypt FILE] [--decrypt FILE]\n");
}

/* XOR 加密/解密 (演示算法; 生产可换成任意工具业务逻辑) */
static int xor_file(const char* path, int encrypt, uint8_t key)
{
    FILE* f;
    errno_t err;
    long sz;
    uint8_t* buf;
    long i;

    err = fopen_s(&f, path, "r+b");
    if (err != 0 || f == NULL) {
        fprintf(stderr, "tool: cannot open %s\n", path);
        return 0;
    }
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    if (sz <= 0) {
        fclose(f);
        fprintf(stderr, "tool: empty file %s\n", path);
        return 0;
    }
    fseek(f, 0, SEEK_SET);
    buf = (uint8_t*)malloc((size_t)sz);
    if (buf == NULL) {
        fclose(f);
        return 0;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return 0;
    }
    for (i = 0; i < sz; i++)
        buf[i] ^= key;
    fseek(f, 0, SEEK_SET);
    fwrite(buf, 1, (size_t)sz, f);
    fclose(f);
    free(buf);
    printf("tool: %s %s (%ld bytes, key=0x%02x)\n",
           encrypt ? "encrypted" : "decrypted", path, sz, key);
    return 1;
}

/* base64 解码 (与 demo/main.c 相同) */
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

/* 完整 license 验签 (RSA + tier + expires + 机器绑定) */
static int verify_license_file(const char* path, tool_mem* mem)
{
    FILE* f;
    char line[512];
    uint8_t sig[256];
    uint8_t msg[256];
    size_t msg_len;
    int have_serial = 0, have_prod = 0, have_sig = 0;
    uint32_t tier = PROT_LICENSE_TIER_FULL;
    uint32_t expires = 0u;
    char f_serial[48] = { 0 };
    char f_prod[64] = { 0 };
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
    if (expires != 0u) {
        time_t now = time(NULL);
        if (now < 0 || (uint64_t)now > (uint64_t)expires)
            return 0; /* 已过期 */
    }
    mem->license_tier = tier;
    mem->license_expires = expires;
    return 1;
}

int main(int argc, char** argv)
{
    const char* serial_in = NULL;
    const char* lic_path = NULL;
    const char* blob_path = NULL;
    const char* revoke_path = NULL;
    const char* check_url = NULL;
    const char* enc_path = NULL;
    const char* dec_path = NULL;
    int i;
    tool_mem mem;
    prot_antidebug_report rep;
    uint8_t key;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--serial") == 0 && i + 1 < argc)
            serial_in = argv[++i];
        else if (strcmp(argv[i], "--license-file") == 0 && i + 1 < argc)
            lic_path = argv[++i];
        else if (strcmp(argv[i], "--vm-blob") == 0 && i + 1 < argc)
            blob_path = argv[++i];
        else if (strcmp(argv[i], "--revoke-file") == 0 && i + 1 < argc)
            revoke_path = argv[++i];
        else if (strcmp(argv[i], "--check-url") == 0 && i + 1 < argc)
            check_url = argv[++i];
        else if (strcmp(argv[i], "--encrypt") == 0 && i + 1 < argc)
            enc_path = argv[++i];
        else if (strcmp(argv[i], "--decrypt") == 0 && i + 1 < argc)
            dec_path = argv[++i];
        else {
            usage();
            return 2;
        }
    }
    if (serial_in == NULL || (enc_path == NULL && dec_path == NULL)) {
        usage();
        return 2;
    }

    SetConsoleOutputCP(65001);

    /* 1. 反调试 + 策略 */
    prot_antidebug_scan(&rep);
    if (prot_antidebug_detected(&rep)) {
        printf("tool: debugger detected - exiting\n");
        return PROT_EXIT_DEBUG_DETECTED;
    }

    /* 2. 完整性自检 */
    if (prot_integrity_check_self() != PROT_OK) {
        printf("tool: integrity check failed (tampered?)\n");
        return PROT_EXIT_TAMPERED;
    }
    prot_integrity_start_watchdog(PROT_POLICY_EXIT, 5000);

    /* 3. 装载 VM 镜像 (断源) */
    {
        static const char* const names[1] = { "check" };
        size_t bsz = 0u;
        const char* bp = blob_path ? blob_path : "vm.blob";
        if (prot_vm_blob_load(bp, names, 1u, &g_check_img, &g_blob_buf, &bsz)
            != PROT_OK) {
            printf("tool: VM blob load failed (%s)\n", bp);
            return PROT_EXIT_BLOB_MISSING;
        }
    }

    /* 4. 组装宿主内存: serial + machine_id */
    memset(&mem, 0, sizeof(mem));
    strcpy_s(mem.serial, sizeof(mem.serial), serial_in);
    mem.serial_len = (uint32_t)strlen(mem.serial);
    mem.machine_id = prot_hostid_get();
    printf("tool: machine_id=0x%016llx\n", (unsigned long long)mem.machine_id);

    /* 5. RSA license (授权门): 无 license -> 拒绝 (防未授权使用) */
    if (lic_path == NULL) {
        printf("tool: no license provided - access denied\n");
        return 1;
    }
    mem.license_ok = 1u;
    mem.license_tier = PROT_LICENSE_TIER_FULL;
    mem.license_expires = 0u;
    {
        mem.license_ok = (uint32_t)verify_license_file(lic_path, &mem);
        printf("tool: license_ok=%u (tier=%u expires=%u)\n",
               mem.license_ok, mem.license_tier, mem.license_expires);
        if (mem.license_ok == 0u) {
            printf("tool: license invalid/expired - access denied\n");
            return 1;
        }
    }

    /* 6. VM 校验: 序列号合法性 (核心校验在 VM 内, 静态不可读) */
    {
        prot_status st = prot_vm_run(&g_check_img, &mem, sizeof(mem));
        if (st != PROT_OK) {
            printf("tool: vm error %d\n", (int)st);
            return 1;
        }
    }

    /* 7. 门控: VM 结果 AND license */
    mem.result &= mem.license_ok;

    /* 8. 吊销检查 (本地黑名单 + M3.1 可选在线查询) */
    {
        int revoked = 0;
        if (revoke_path != NULL) {
            uint32_t rver = 0u;
            if (prot_revoke_check(revoke_path, mem.serial, mem.license_tier,
                                  &rver) == PROT_REVOKE_HIT)
                revoked = 1;
        }
        if (check_url != NULL && !revoked) {
            char url[1024];
            char buf[512];
            DWORD got = 0u;
            HINTERNET hin = NULL, hconn = NULL, hreq = NULL;
            _snprintf_s(url, sizeof(url), _TRUNCATE,
                        "%s?serial=%s&mid=%llx&tier=%u&build=%s",
                        check_url, mem.serial,
                        (unsigned long long)mem.machine_id,
                        mem.license_tier, "1.0.0");
            hin = WinHttpOpen(L"PROT-ToolDemo/1.0",
                              WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if (hin != NULL) {
                wchar_t whost[256], wpath[512], wurl[1024];
                URL_COMPONENTS uc;
                memset(&uc, 0, sizeof(uc));
                uc.dwStructSize = sizeof(uc);
                uc.lpszHostName = whost;
                uc.dwHostNameLength = 256;
                uc.lpszUrlPath = wpath;
                uc.dwUrlPathLength = 512;
                MultiByteToWideChar(CP_UTF8, 0, url, -1, wurl, 1024);
                if (WinHttpCrackUrl(wurl, 0, 0, &uc)) {
                    hconn = WinHttpConnect(hin, whost, uc.nPort, 0);
                    if (hconn != NULL) {
                        hreq = WinHttpOpenRequest(hconn, L"GET", wpath, NULL,
                                                  WINHTTP_NO_REFERER,
                                                  WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
                        if (hreq != NULL &&
                            WinHttpSendRequest(hreq,
                                               WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                               WINHTTP_NO_REQUEST_DATA, 0, 0, 3000) &&
                            WinHttpReceiveResponse(hreq, NULL)) {
                            DWORD avail = 0u;
                            if (WinHttpQueryDataAvailable(hreq, &avail) &&
                                avail > 0u && avail < sizeof(buf) &&
                                WinHttpReadData(hreq, buf, avail, &got)) {
                                buf[got] = '\0';
                                if (strstr(buf, "\"revoked\"") != NULL)
                                    revoked = 1;
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
        }
        if (revoked) {
            printf("tool: license revoked\n");
            return PROT_EXIT_REVOKED;
        }
    }

    if (mem.result == 0u) {
        printf("tool: invalid serial / no license - access denied\n");
        return 1;
    }
    printf("tool: authorized (serial=%s)\n", mem.serial);

    /* 9. 业务功能: 文件加/解密 */
    key = (uint8_t)(mem.serial[0] ^ mem.serial[3]); /* 简单业务密钥派生 */
    if (enc_path != NULL)
        return xor_file(enc_path, 1, key) ? 0 : 1;
    if (dec_path != NULL)
        return xor_file(dec_path, 0, key) ? 0 : 1;
    return 0;
}
