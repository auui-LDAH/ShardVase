/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * elfdump.c — ELF 符号解析命令行工具 (宿主编译测试用)
 *
 * 用法: elfdump.exe <elf> [symbol]
 *   symbol 缺省 = 列出全部符号
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elfparse.h"

static void print_sym(const ep_symbol* s, void* ud)
{
    (void)ud;
    printf("  %c %-48s st_value=0x%llx size=0x%x\n",
           s->from_dynsym ? 'D' : 'S',
           s->name,
           (unsigned long long)s->st_value,
           s->st_size);
}

int main(int argc, char** argv)
{
    int rc;
    if (argc < 2) {
        fprintf(stderr, "usage: %s <elf> [symbol]\n", argv[0]);
        return 2;
    }
    rc = ep_load_file(argv[1]);
    if (rc != EP_OK) {
        fprintf(stderr, "load failed: rc=%d (symtab=%d dynsym=%d)\n", rc,
                ep_ctx_get()->have_symtab, ep_ctx_get()->have_dynsym);
        return 1;
    }
    if (argc >= 3) {
        ep_symbol s;
        rc = ep_lookup(argv[2], &s);
        if (rc != EP_OK) {
            fprintf(stderr, "symbol '%s' not found\n", argv[2]);
            return 1;
        }
        print_sym(&s, NULL);
        return 0;
    }
    printf("total symbols: %u (symtab=%d dynsym=%d)\n",
           ep_ctx_get()->symbol_count,
           ep_ctx_get()->have_symtab,
           ep_ctx_get()->have_dynsym);
    ep_list_all(print_sym, NULL);
    return 0;
}
