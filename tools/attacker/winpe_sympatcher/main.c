/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * main.c — WinPE-SymPatcher 命令行入口
 *
 * 用法:
 *   winpe_sympatcher.exe --file <pe> --sym <name>          # 符号 -> VA (离线解析)
 *   winpe_sympatcher.exe --pid <pid> --mod <demo.exe> --sym <name> [--show]
 *                                                          # 附加 + 解析 (进程内)
 *   winpe_sympatcher.exe --pid <pid> --mod <demo.exe> --addr <va> --byte <hex> [--byte ...]
 *                                                          # 写内存
 *   winpe_sympatcher.exe --list <pe>                        # 列出 COFF 符号
 *
 * 仅用于自有产物攻防演练。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "symparse.h"
#include "mempatch.h"

static void usage(void)
{
    printf("WinPE-SymPatcher — PE 符号表解析 + 内存补丁 (攻防演练用)\n"
           "用法:\n"
           "  --file <pe> --sym <name>                 离线解析符号->VA\n"
           "  --map <map> --sym <name>                 MAP 文件解析 (MSVC /MAP)\n"
           "  --pid <pid> --mod <mod.exe> --sym <name>  附加+解析\n"
           "  --pid <pid> --addr <va> --byte <hh> [--byte ...]  写内存\n"
           "  --list <pe>                             列出 COFF 符号\n");
}

static int cmd_list(const char* pe)
{
    int rc = sp_load_file(pe);
    if (rc != SP_OK) {
        fprintf(stderr, "load failed: %s (%s)\n", sp_err_str(rc), pe);
        return 1;
    }
    rc = sp_list_all(NULL, NULL);
    if (rc != SP_OK) {
        printf("(no COFF symbols; exports present: %d)\n",
               sp_ctx_get()->have_exports ? 1 : 0);
        return 1;
    }
    return 0;
}

static int cmd_resolve_file(const char* pe, const char* map, const char* sym)
{
    sp_result r;
    int rc;
    if (map != NULL) {
        rc = sp_load_map(map);
        if (rc != SP_OK) {
            fprintf(stderr, "map load failed: %s (%s)\n", sp_err_str(rc), map);
            return 1;
        }
        rc = sp_lookup(sym, &r);
        if (rc != SP_OK) {
            fprintf(stderr, "symbol '%s' not found in map\n", sym);
            return 1;
        }
        printf("symbol '%s': va=0x%llx via=map\n",
               r.name, (unsigned long long)r.va);
        return 0;
    }
    rc = sp_load_file(pe);
    if (rc != SP_OK) {
        fprintf(stderr, "load failed: %s (%s)\n", sp_err_str(rc), pe);
        return 1;
    }
    rc = sp_lookup(sym, &r);
    if (rc != SP_OK) {
        fprintf(stderr, "symbol '%s' not found: %s (exports=%d coff=%d)\n",
                sym, sp_err_str(rc),
                sp_ctx_get()->have_exports ? 1 : 0,
                sp_ctx_get()->have_coff ? 1 : 0);
        return 1;
    }
    printf("symbol '%s': rva=0x%llx va=0x%llx via=%s\n",
           r.name, (unsigned long long)r.rva, (unsigned long long)r.va,
           r.from_export ? "export" : "coff");
    return 0;
}

static int cmd_attach_resolve(DWORD pid, const char* mod, const char* sym)
{
    mp_handle h;
    sp_result r;
    int rc;

    rc = mp_attach(&h, pid, mod);
    if (rc != 0) {
        fprintf(stderr, "attach failed (pid %lu): rc=%d (权限不足?)\n", pid, rc);
        return 1;
    }
    printf("attached pid=%lu base=0x%llx\n", pid,
           (unsigned long long)h.image_base);

    /* 从目标进程内存映射 PE 头部 + 符号表 (简化: 读头部解析) */
    {
        IMAGE_DOS_HEADER dos;
        if (mp_read(&h, h.image_base, &dos, sizeof(dos)) != 0 ||
            dos.e_magic != IMAGE_DOS_SIGNATURE) {
            fprintf(stderr, "cannot read PE header\n");
            mp_close(&h);
            return 1;
        }
        /* 简化: 离线解析同文件更可靠; 附加模式仅演示基址对齐 */
    }
    mp_close(&h);
    fprintf(stderr, "note: attach-mode 符号解析依赖离线文件 (--file) + 基址对齐; "
            "完整方案见 docs/MEMPATCH_PLAN.md\n");
    return 1;
}

int main(int argc, char** argv)
{
    const char* pe = NULL;
    const char* sym = NULL;
    const char* mod = NULL;
    const char* map = NULL;
    const char* pref = NULL;
    DWORD pid = 0;
    uint64_t addr = 0;
    uint8_t bytes[64];
    int nbytes = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--file") == 0 && i + 1 < argc) pe = argv[++i];
        else if (strcmp(argv[i], "--map") == 0 && i + 1 < argc) map = argv[++i];
        else if (strcmp(argv[i], "--pref") == 0 && i + 1 < argc) pref = argv[++i];
        else if (strcmp(argv[i], "--sym") == 0 && i + 1 < argc) sym = argv[++i];
        else if (strcmp(argv[i], "--mod") == 0 && i + 1 < argc) mod = argv[++i];
        else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc)
            pid = (DWORD)strtoul(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "--addr") == 0 && i + 1 < argc)
            addr = _strtoui64(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "--byte") == 0 && i + 1 < argc) {
            if (nbytes < 64) bytes[nbytes++] = (uint8_t)strtoul(argv[++i], NULL, 16);
        }
        else if (strcmp(argv[i], "--list") == 0 && i + 1 < argc) {
            return cmd_list(argv[++i]);
        }
        else { usage(); return 2; }
    }

    if (sym != NULL && (pe != NULL || map != NULL))
        return cmd_resolve_file(pe, map, sym);

    if (pid != 0 && nbytes > 0) {
        mp_handle h;
        int rc = mp_attach(&h, pid, mod);
        if (rc != 0) { fprintf(stderr, "attach failed rc=%d\n", rc); return 1; }
        /* ASLR 换算: --pref <首选基址> 给出时, addr 视为编译时 VA */
        if (pref != NULL && h.image_base != 0) {
            uint64_t pbase = _strtoui64(pref, NULL, 0);
            addr = mp_aslr_adjust(pbase, h.image_base, addr);
        }
        rc = mp_write(&h, addr, bytes, (size_t)nbytes);
        if (rc != 0) {
            fprintf(stderr, "write failed rc=%d (addr 0x%llx 可能未按 ASLR 换算)\n",
                    rc, (unsigned long long)addr);
            mp_close(&h);
            return 1;
        }
        printf("wrote %d byte(s) @0x%llx pid=%lu\n", nbytes,
               (unsigned long long)addr, pid);
        mp_close(&h);
        return 0;
    }

    usage();
    return 2;
}
