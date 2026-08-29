/*
 * business_hash.c — showcase 业务: 批量文件哈希校验工具 (prot_sdk 演示)
 *
 * 分级展示:
 *   tier 1 (正式):   单文件/多文件 SHA-256 计算
 *   tier 2 (高级):   额外支持 --scan <dir> 递归目录扫描 + 汇总报告
 *   到期控制:        评估 license (expires) 到期后由壳拒绝进入业务
 *
 * 用法: hashcalc <file>... | hashcalc --scan <dir> | hashcalc --selftest
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <bcrypt.h>

#include "../prot_shell.h"

/* A2 phase2 演示: 标注 @vmcalc 的纯计算函数将被自动翻译进 VM.
 * 构建后本函数体运行在 VM 内 (原名保留给调用点, 原生实现改名 _native). */
// @vmcalc
uint64_t biz_seed(uint64_t a, uint64_t b)
{
    uint64_t x = a;
    uint64_t i;
    for (i = 0; i < 4; i++) {
        x = x * 31;
        x = x ^ b;
    }
    x += 7;
    return x;
}

/* ---------- SHA-256 (Windows BCrypt, 与壳同依赖) ---------- */
static int sha256_file(const char* path, unsigned char out[32])
{
    FILE* f = fopen(path, "rb");
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE h = NULL;
    NTSTATUS st;
    unsigned char buf[65536];
    size_t got;
    if (f == NULL)
        return -1;
    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (st != 0) { fclose(f); return -1; }
    st = BCryptCreateHash(alg, &h, NULL, 0, NULL, 0, 0);
    if (st != 0) { BCryptCloseAlgorithmProvider(alg, 0); fclose(f); return -1; }
    while ((got = fread(buf, 1, sizeof(buf), f)) > 0)
        BCryptHashData(h, buf, (ULONG)got, 0);
    fclose(f);
    BCryptFinishHash(h, out, 32, 0);
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    return 0;
}

static int hash_one(const char* path)
{
    unsigned char d[32];
    int i;
    if (sha256_file(path, d) != 0) {
        printf("  [FAIL] %s (无法读取)\n", path);
        return 1;
    }
    printf("  %s:", path);
    for (i = 0; i < 32; i++)
        printf("%02x", d[i]);
    printf("\n");
    return 0;
}

/* ---------- tier 2: 递归目录扫描 + 汇总 ---------- */
static int g_total = 0;
static int g_failed = 0;

static void scan_dir(const char* dir)
{
    char pat[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    _snprintf_s(pat, sizeof(pat), _TRUNCATE, "%s\\*", dir);
    h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;
    do {
        char full[MAX_PATH];
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        _snprintf_s(full, sizeof(full), _TRUNCATE, "%s\\%s", dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_dir(full);
        } else {
            g_total++;
            if (hash_one(full) != 0)
                g_failed++;
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

/* ---------- 业务入口 (壳授权门通过后调用) ---------- */
int prot_business_main(const prot_business_ctx* ctx)
{
    printf("== 批量哈希校验工具 (正式版) ==\n");
    printf("   机器绑定: 0x%016llx     授权: Tier%d  expires=%u\n",
           (unsigned long long)ctx->machine_id,
           ctx->license_tier, ctx->license_expires);
    printf("   业务VM演示种子: 0x%016llx (biz_seed @vmcalc)\n",
           (unsigned long long)biz_seed(ctx->machine_id, 0x1234));

    if (ctx->license_tier < 2) {
        printf("\nTier 1 功能: 单文件哈希 (高级版支持 --scan 目录扫描)\n");
        /* 演示: 计算自身文件哈希 */
        return hash_one("hashcalc.exe");
    }

    /* tier 2 (premium): 递归扫描当前目录 */
    printf("\nTier 2 (高级): 递归目录扫描汇总\n");
    scan_dir(".");
    printf("  总计 %d 个文件, %d 个失败\n", g_total, g_failed);
    return (g_failed == 0) ? 0 : 2;
}