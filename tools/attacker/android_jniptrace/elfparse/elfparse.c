/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * elfparse.c — ELF64 符号表解析器实现
 *
 * 依赖: <elf.h> (Linux/Android NDK 自带; Windows 宿主编译时提供精简头)。
 * 纯解析, 不修改文件。
 */
#include "elfparse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Windows 宿主无 <elf.h>, 提供精简定义 */
#ifdef _WIN32
typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef struct {
    unsigned char e_ident[16];
    Elf64_Half    e_type;
    Elf64_Half    e_machine;
    Elf64_Word    e_version;
    Elf64_Addr    e_entry;
    Elf64_Off     e_phoff;
    Elf64_Off     e_shoff;
    Elf64_Word    e_flags;
    Elf64_Half    e_ehsize;
    Elf64_Half    e_phentsize;
    Elf64_Half    e_phnum;
    Elf64_Half    e_shentsize;
    Elf64_Half    e_shnum;
    Elf64_Half    e_shstrndx;
} Elf64_Ehdr;
typedef struct {
    Elf64_Word  sh_name;
    Elf64_Word  sh_type;
    Elf64_Word  sh_flags;
    Elf64_Addr  sh_addr;
    Elf64_Off   sh_offset;
    Elf64_Off   sh_size;
    Elf64_Word  sh_link;
    Elf64_Word  sh_info;
    Elf64_Off   sh_addralign;
    Elf64_Off   sh_entsize;
} Elf64_Shdr;
typedef struct {
    Elf64_Word      st_name;
    unsigned char   st_info;
    unsigned char   st_other;
    Elf64_Half      st_shndx;
    Elf64_Addr      st_value;
    Elf64_Word      st_size;
} Elf64_Sym;
#define SHT_SYMTAB     2
#define SHT_DYNSYM     11
#define ELFCLASS64     2
#define ELFMAG0        0x7f
#define ELFMAG1       'E'
#define ELFMAG2       'L'
#define ELFMAG3       'F'
#else
#include <elf.h>
#endif

static ep_ctx g_ctx;
static uint8_t* g_file;
static int g_loaded;

static int load_from_memory(const uint8_t* base, size_t size)
{
    const Elf64_Ehdr* eh;
    const Elf64_Shdr* sh;
    const char* shstr;
    uint16_t i;

    if (size < 64) return EP_ERR_SIZE;
    eh = (const Elf64_Ehdr*)base;
    if (eh->e_ident[0] != ELFMAG0 || eh->e_ident[1] != ELFMAG1 ||
        eh->e_ident[2] != ELFMAG2 || eh->e_ident[3] != ELFMAG3) {
        return EP_ERR_NOT_ELF;
    }
    if (eh->e_ident[4] != ELFCLASS64) return EP_ERR_NOT_ELF;

    memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.is_elf64 = 1;

    if (eh->e_shoff == 0 || eh->e_shnum == 0) return EP_ERR_NOSYM;
    sh = (const Elf64_Shdr*)(base + eh->e_shoff);
    if (eh->e_shstrndx >= eh->e_shnum) return EP_ERR_NOSYM;
    shstr = (const char*)(base + sh[eh->e_shstrndx].sh_offset);

    for (i = 0; i < eh->e_shnum; i++) {
        const char* secname;
        uint32_t n, j;
        const Elf64_Sym* sym;
        const char* strtab;
        if (sh[i].sh_offset + sh[i].sh_size > size) continue;
        secname = shstr + sh[i].sh_name;
        if (sh[i].sh_type == SHT_SYMTAB) {
            g_ctx.have_symtab = 1;
            g_ctx.symtab_count = sh[i].sh_size / sizeof(Elf64_Sym);
            sym = (const Elf64_Sym*)(base + sh[i].sh_offset);
            /* 字符串表在 sh_link 索引 */
            if (sh[i].sh_link < eh->e_shnum) {
                strtab = (const char*)(base + sh[sh[i].sh_link].sh_offset);
                n = sh[i].sh_size / sizeof(Elf64_Sym);
                for (j = 0; j < n && g_ctx.symbol_count < 65536; j++) {
                    const char* nm = strtab + sym[j].st_name;
                    if (sym[j].st_name != 0 && sym[j].st_value != 0) {
                        ep_symbol* e = &g_ctx.symbols[g_ctx.symbol_count++];
                        strncpy(e->name, nm, sizeof(e->name) - 1);
                        e->name[sizeof(e->name) - 1] = '\0';
                        e->st_value = sym[j].st_value;
                        e->st_size = sym[j].st_size;
                        e->from_dynsym = 0;
                    }
                }
            }
        } else if (sh[i].sh_type == SHT_DYNSYM) {
            g_ctx.have_dynsym = 1;
            g_ctx.dynsym_count = sh[i].sh_size / sizeof(Elf64_Sym);
            sym = (const Elf64_Sym*)(base + sh[i].sh_offset);
            if (sh[i].sh_link < eh->e_shnum) {
                strtab = (const char*)(base + sh[sh[i].sh_link].sh_offset);
                n = sh[i].sh_size / sizeof(Elf64_Sym);
                for (j = 0; j < n && g_ctx.symbol_count < 65536; j++) {
                    const char* nm = strtab + sym[j].st_name;
                    if (sym[j].st_name != 0 && sym[j].st_value != 0) {
                        ep_symbol* e = &g_ctx.symbols[g_ctx.symbol_count++];
                        strncpy(e->name, nm, sizeof(e->name) - 1);
                        e->name[sizeof(e->name) - 1] = '\0';
                        e->st_value = sym[j].st_value;
                        e->st_size = sym[j].st_size;
                        e->from_dynsym = 1;
                    }
                }
            }
        }
        (void)secname;
    }

    if (g_file != NULL) free(g_file);
    g_file = (uint8_t*)malloc(size);
    if (g_file == NULL) return EP_ERR_SIZE;
    memcpy(g_file, base, size);
    g_loaded = 1;
    return (g_ctx.symbol_count > 0) ? EP_OK : EP_ERR_NOSYM;
}

int ep_load_file(const char* path)
{
    FILE* f;
    long sz;
    uint8_t* buf;
    int rc;
    f = fopen(path, "rb");
    if (f == NULL) return EP_ERR_OPEN;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return EP_ERR_SIZE; }
    buf = (uint8_t*)malloc((size_t)sz);
    if (buf == NULL) { fclose(f); return EP_ERR_SIZE; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return EP_ERR_SIZE;
    }
    fclose(f);
    rc = load_from_memory(buf, (size_t)sz);
    free(buf);
    return rc;
}

int ep_lookup(const char* name, ep_symbol* out)
{
    uint32_t i;
    if (!g_loaded) return EP_ERR_NOSYM;
    if (out == NULL || name == NULL) return EP_ERR_NOTFOUND;
    memset(out, 0, sizeof(*out));
    for (i = 0; i < g_ctx.symbol_count; i++) {
        if (strcmp(g_ctx.symbols[i].name, name) == 0) {
            *out = g_ctx.symbols[i];
            return EP_OK;
        }
    }
    return EP_ERR_NOTFOUND;
}

int ep_list_all(void (*cb)(const ep_symbol* s, void* ud), void* ud)
{
    uint32_t i;
    if (!g_loaded) return EP_ERR_NOSYM;
    for (i = 0; i < g_ctx.symbol_count; i++) {
        if (cb) cb(&g_ctx.symbols[i], ud);
    }
    return EP_OK;
}

const ep_ctx* ep_ctx_get(void) { return &g_ctx; }
