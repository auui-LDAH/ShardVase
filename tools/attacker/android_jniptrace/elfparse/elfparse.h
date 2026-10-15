/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * elfparse.h — ELF64 符号表解析器（攻防工具，仅用于自有产物演练）
 *
 * 解析 ELF64:
 *   1) .symtab  — 静态符号表 (SECTION SYMTAB, 通常被 strip 移除)
 *   2) .dynsym  — 动态符号表 (DYNSYM, 导出的 JNI 函数在这里)
 *
 * 目标: 给定符号名 -> 返回其在目标进程中的虚拟地址 (st_value)。
 * 注意: JNI 导出函数 (Java_com_...) 在 .dynsym 中必有 (导出)。
 */
#ifndef MEMPATCH_ELFPARSE_H
#define MEMPATCH_ELFPARSE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ep_symbol {
    char     name[256];
    uint64_t st_value;    /* 虚拟地址 (链接时) */
    uint32_t st_size;
    int      from_dynsym; /* 1=.dynsym, 0=.symtab */
} ep_symbol;

typedef struct ep_ctx {
    int      is_elf64;
    int      have_symtab;
    int      have_dynsym;
    uint32_t symtab_count;
    uint32_t dynsym_count;
    /* 最多 65536 条 */
    ep_symbol symbols[65536];
    uint32_t symbol_count;
} ep_ctx;

/* 加载 ELF 文件 -> 0 成功 */
int ep_load_file(const char* path);
/* 查找符号 -> 0 找到 */
int ep_lookup(const char* name, ep_symbol* out);
/* 列出所有符号 (调试用) */
int ep_list_all(void (*cb)(const ep_symbol* s, void* ud), void* ud);
const ep_ctx* ep_ctx_get(void);

#define EP_OK          0
#define EP_ERR_OPEN    -1
#define EP_ERR_SIZE    -2
#define EP_ERR_NOT_ELF -3
#define EP_ERR_NOSYM   -4
#define EP_ERR_NOTFOUND -5

#ifdef __cplusplus
}
#endif

#endif /* MEMPATCH_ELFPARSE_H */
