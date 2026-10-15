/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * symparse.c — PE 符号表解析器实现
 *
 * 只读解析, 不修改文件。线程安全: 本实现为单线程设计 (工具用途)。
 */
#include "symparse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static sp_ctx g_ctx;
static uint8_t* g_file;   /* 文件完整副本 */
static int g_loaded;

/* 节表查找: 按 COFF 节索引找 VA */
static const void* section_va_by_index(const IMAGE_SECTION_HEADER* sh,
                                       uint16_t nsec, uint16_t idx)
{
    uint16_t i;
    if (idx == 0 || idx > nsec) return NULL;
    for (i = 0; i < nsec; i++) {
        if (i + 1 == idx) return sh + i;
    }
    return NULL;
}

/* COFF 符号 RVA 换算: section_number -> 节 VA + value */
static uint64_t coff_symbol_rva(const IMAGE_SECTION_HEADER* sh, uint16_t nsec,
                                int16_t section_number, uint32_t value)
{
    const IMAGE_SECTION_HEADER* sec;
    if (section_number <= 0) return 0; /* 绝对符号/未定义: 无 RVA */
    sec = section_va_by_index(sh, nsec, (uint16_t)section_number);
    if (sec == NULL) return 0;
    return (uint64_t)sec->VirtualAddress + value;
}

static int load_from_memory(const uint8_t* base, size_t size)
{
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS* nt;
    const IMAGE_FILE_HEADER* fh;
    const IMAGE_OPTIONAL_HEADER* oh;
    const IMAGE_SECTION_HEADER* sh;
    const IMAGE_EXPORT_DIRECTORY* ed;
    const uint8_t* symtab;
    const uint8_t* strtab;
    uint32_t i;

    if (size < sizeof(IMAGE_DOS_HEADER)) return SP_ERR_SIZE;
    dos = (const IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return SP_ERR_NOT_PE;
    if (dos->e_lfanew <= 0 || (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > size)
        return SP_ERR_SIZE;
    nt = (const IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return SP_ERR_NOT_PE;
    fh = &nt->FileHeader;
    oh = &nt->OptionalHeader;

    memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.image_base = oh->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
                           ? (uint64_t)oh->ImageBase : (uint64_t)oh->ImageBase;
    g_ctx.file_size = size;
    g_ctx.section_count = fh->NumberOfSections > 64 ? 64 : fh->NumberOfSections;
    sh = (const IMAGE_SECTION_HEADER*)((const uint8_t*)&nt->OptionalHeader +
                                       fh->SizeOfOptionalHeader);
    for (i = 0; i < g_ctx.section_count; i++) {
        g_ctx.sections[i].va = sh[i].VirtualAddress;
        g_ctx.sections[i].size = sh[i].Misc.VirtualSize;
        g_ctx.sections[i].idx = (uint16_t)(i + 1);
    }

    /* 导出表 */
    if (oh->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const IMAGE_OPTIONAL_HEADER64* oh64 = (const IMAGE_OPTIONAL_HEADER64*)oh;
        ed = (oh64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0)
                 ? (const IMAGE_EXPORT_DIRECTORY*)(
                       base + oh64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
                 : NULL;
    } else {
        const IMAGE_OPTIONAL_HEADER32* oh32 = (const IMAGE_OPTIONAL_HEADER32*)oh;
        ed = (oh32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0)
                 ? (const IMAGE_EXPORT_DIRECTORY*)(
                       base + oh32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
                 : NULL;
    }
    /* 注意: 导出目录 RVA 可能指向文件偏移不同的位置; 简化为"RVA==fileoff"
     * (常见于未对齐小文件)。生产级需 RVA2Offset 换算。这里记录有导出表即可。 */
    g_ctx.have_exports = (ed != NULL);

    /* COFF 符号表 */
    if (fh->PointerToSymbolTable != 0 && fh->NumberOfSymbols != 0) {
        size_t symtab_size = (size_t)fh->NumberOfSymbols * 18; /* IMAGE_SYMBOL=18B */
        if (fh->PointerToSymbolTable + symtab_size <= size) {
            g_ctx.have_coff = 1;
            g_ctx.coff_symbol_count = fh->NumberOfSymbols;
            g_ctx.coff_symbol_offset = fh->PointerToSymbolTable;
            /* 字符串表在符号表之后, 首 4 字节为长度 */
            g_ctx.coff_string_offset = fh->PointerToSymbolTable + symtab_size;
            if (g_ctx.coff_string_offset + 4 > size) g_ctx.have_coff = 0;
        }
    }

    /* 保存文件副本 (解析需要随机访问) */
    if (g_file != NULL) {
        free(g_file);
        g_file = NULL;
    }
    g_file = (uint8_t*)malloc(size);
    if (g_file == NULL) return SP_ERR_MAPPED;
    memcpy(g_file, base, size);
    g_loaded = 1;
    (void)symtab;
    (void)strtab;
    return SP_OK;
}

int sp_load_file(const char* path)
{
    FILE* f;
    long sz;
    uint8_t* buf;
    int rc;

    f = fopen(path, "rb");
    if (f == NULL) return SP_ERR_OPEN;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return SP_ERR_SIZE; }
    buf = (uint8_t*)malloc((size_t)sz);
    if (buf == NULL) { fclose(f); return SP_ERR_MAPPED; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return SP_ERR_SIZE;
    }
    fclose(f);
    rc = load_from_memory(buf, (size_t)sz);
    free(buf); /* load_from_memory 内部已复制 */
    return rc;
}

int sp_load_memory(const uint8_t* base, size_t size)
{
    return load_from_memory(base, size);
}

/* MAP 文件解析: MSVC /MAP 产物
 * 格式: " 0001:00002460       prot_antidebug_scan        0000000140003460 f   antidebug.obj"
 *       (段:偏移)  (符号名)  (VA 16 进制)  (类型)  (对象)
 * VA 列直接给出, 无需换算。
 */
int sp_load_map(const char* path)
{
    FILE* f;
    char line[1024];
    uint32_t count = 0;

    if (g_file != NULL) { free(g_file); g_file = NULL; }
    memset(&g_ctx, 0, sizeof(g_ctx));
    g_loaded = 0;

    f = fopen(path, "r");
    if (f == NULL) return SP_ERR_OPEN;
    while (fgets(line, sizeof(line), f)) {
        /* 行格式: 空格+段:偏移+空格+名字+空格+VA(+ 可选类型/对象) */
        char segoff[32];
        char name[256];
        char va_str[32];
        uint64_t va;
        int n = sscanf(line, " %31[^:]:%31s %255s %31s",
                       segoff, segoff, name, va_str);
        if (n >= 3 && name[0] != '$' && name[0] != '?' && name[0] != '.') {
            /* va_str 可能缺省 (段起始行), 用 "0000000" 占位; 有 VA 才收 */
            va = strtoull(va_str, NULL, 16);
            if (va != 0 && count < 65536) {
                strncpy(g_ctx.map_entries[count].name, name,
                        sizeof(g_ctx.map_entries[count].name) - 1);
                g_ctx.map_entries[count].name[
                    sizeof(g_ctx.map_entries[count].name) - 1] = '\0';
                g_ctx.map_entries[count].va = va;
                count++;
            }
        }
    }
    fclose(f);
    g_ctx.have_map = (count > 0) ? 1 : 0;
    g_ctx.map_count = count;
    g_loaded = 1;
    return (count > 0) ? SP_OK : SP_ERR_NOSYM;
}

/* RVA -> 文件偏移 (节表换算) */
static uint32_t rva_to_offset(uint32_t rva)
{
    const sp_ctx* ctx = &g_ctx;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)g_file;
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(g_file + dos->e_lfanew);
    const IMAGE_SECTION_HEADER* sh = (const IMAGE_SECTION_HEADER*)(
        (const uint8_t*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    uint32_t i;
    for (i = 0; i < ctx->section_count; i++) {
        if (rva >= sh[i].VirtualAddress &&
            rva < sh[i].VirtualAddress + sh[i].SizeOfRawData) {
            return rva - sh[i].VirtualAddress + sh[i].PointerToRawData;
        }
    }
    return rva; /* 回退: RVA==offset */
}

/* 导出表按名查找 */
static int lookup_export(const char* name, sp_result* out)
{
    const sp_ctx* ctx = &g_ctx;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)g_file;
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(g_file + dos->e_lfanew);
    const IMAGE_OPTIONAL_HEADER* oh = &nt->OptionalHeader;
    uint32_t ed_rva, ed_off;
    const IMAGE_EXPORT_DIRECTORY* ed;
    const uint32_t* name_rvas;
    const uint16_t* ordinals;
    const uint32_t* func_rvas;
    uint32_t i, n;

    if (oh->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        ed_rva = ((const IMAGE_OPTIONAL_HEADER64*)oh)
                     ->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    } else {
        ed_rva = ((const IMAGE_OPTIONAL_HEADER32*)oh)
                     ->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    }
    if (ed_rva == 0) return SP_ERR_NOTFOUND;
    ed_off = rva_to_offset(ed_rva);
    if (ed_off + sizeof(IMAGE_EXPORT_DIRECTORY) > ctx->file_size) return SP_ERR_NOTFOUND;
    ed = (const IMAGE_EXPORT_DIRECTORY*)(g_file + ed_off);

    n = ed->NumberOfNames;
    name_rvas = (const uint32_t*)(g_file + rva_to_offset(ed->AddressOfNames));
    ordinals  = (const uint16_t*)(g_file + rva_to_offset(ed->AddressOfNameOrdinals));
    func_rvas = (const uint32_t*)(g_file + rva_to_offset(ed->AddressOfFunctions));
    for (i = 0; i < n; i++) {
        const char* nm = (const char*)(g_file + rva_to_offset(name_rvas[i]));
        if (strcmp(nm, name) == 0) {
            uint32_t ord = ordinals[i];
            out->rva = func_rvas[ord];
            out->va = ctx->image_base + out->rva;
            out->from_export = 1;
            strncpy(out->name, nm, sizeof(out->name) - 1);
            out->name[sizeof(out->name) - 1] = '\0';
            return SP_OK;
        }
    }
    return SP_ERR_NOTFOUND;
}

/* COFF 符号表按名查找 */
static int lookup_coff(const char* name, sp_result* out)
{
    const sp_ctx* ctx = &g_ctx;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)g_file;
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(g_file + dos->e_lfanew);
    const IMAGE_SECTION_HEADER* sh = (const IMAGE_SECTION_HEADER*)(
        (const uint8_t*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    const uint8_t* sym = g_file + ctx->coff_symbol_offset;
    uint32_t i;

    if (!ctx->have_coff) return SP_ERR_NOTFOUND;
    for (i = 0; i < ctx->coff_symbol_count; i++) {
        const IMAGE_SYMBOL* s = (const IMAGE_SYMBOL*)(sym + (size_t)i * 18);
        char nm[256];
        const char* strtab = (const char*)(g_file + ctx->coff_string_offset);
        uint64_t rva;

        if (s->N.Name.Short != 0) {
            memcpy(nm, s->N.ShortName, 8);
            nm[8] = '\0';
        } else {
            uint32_t off = s->N.Name.Long;
            if (off + 1 > ctx->file_size) continue;
            strncpy(nm, strtab + off, sizeof(nm) - 1);
            nm[sizeof(nm) - 1] = '\0';
        }
        if (strcmp(nm, name) != 0) continue;
        rva = coff_symbol_rva(sh, ctx->section_count, s->SectionNumber, s->Value);
        if (rva == 0) return SP_ERR_NOTFOUND; /* 无地址符号 */
        out->rva = rva;
        out->va = ctx->image_base + rva;
        out->from_export = 0;
        strncpy(out->name, nm, sizeof(out->name) - 1);
        out->name[sizeof(out->name) - 1] = '\0';
        return SP_OK;
    }
    return SP_ERR_NOTFOUND;
}

int sp_lookup(const char* name, sp_result* out)
{
    int rc;
    uint32_t i;
    if (!g_loaded) return SP_ERR_MAPPED;
    if (out == NULL || name == NULL) return SP_ERR_MAPPED;
    memset(out, 0, sizeof(*out));
    if (g_ctx.have_map) {
        for (i = 0; i < g_ctx.map_count; i++) {
            if (strcmp(g_ctx.map_entries[i].name, name) == 0) {
                out->rva = g_ctx.map_entries[i].va - g_ctx.image_base;
                out->va = g_ctx.map_entries[i].va;
                out->from_export = 0;
                strncpy(out->name, name, sizeof(out->name) - 1);
                out->name[sizeof(out->name) - 1] = '\0';
                return SP_OK;
            }
        }
    }
    rc = lookup_export(name, out);
    if (rc == SP_OK) return SP_OK;
    rc = lookup_coff(name, out);
    if (rc == SP_OK) return SP_OK;
    return SP_ERR_NOTFOUND;
}

int sp_list_all(void (*cb)(const char*, uint64_t, int, void*), void* ud)
{
    const sp_ctx* ctx = &g_ctx;
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS* nt;
    const IMAGE_SECTION_HEADER* sh;
    const uint8_t* sym;
    uint32_t i;

    if (!g_loaded) return SP_ERR_MAPPED;
    dos = (const IMAGE_DOS_HEADER*)g_file;
    nt = (const IMAGE_NT_HEADERS*)(g_file + dos->e_lfanew);
    sh = (const IMAGE_SECTION_HEADER*)((const uint8_t*)&nt->OptionalHeader +
                                       nt->FileHeader.SizeOfOptionalHeader);
    sym = g_file + ctx->coff_symbol_offset;
    for (i = 0; i < ctx->coff_symbol_count; i++) {
        const IMAGE_SYMBOL* s = (const IMAGE_SYMBOL*)(sym + (size_t)i * 18);
        char nm[256];
        const char* strtab = (const char*)(g_file + ctx->coff_string_offset);
        uint64_t rva;
        if (s->N.Name.Short != 0) {
            memcpy(nm, s->N.ShortName, 8); nm[8] = '\0';
        } else {
            uint32_t off = s->N.Name.Long;
            if (off + 1 > ctx->file_size) continue;
            strncpy(nm, strtab + off, sizeof(nm) - 1); nm[sizeof(nm) - 1] = '\0';
        }
        rva = coff_symbol_rva(sh, ctx->section_count, s->SectionNumber, s->Value);
        if (cb) cb(nm, rva, 0, ud);
    }
    return SP_OK;
}

const char* sp_err_str(int err)
{
    switch (err) {
    case SP_OK:           return "ok";
    case SP_ERR_OPEN:     return "cannot open file";
    case SP_ERR_SIZE:     return "file too small / read error";
    case SP_ERR_MAPPED:   return "memory error";
    case SP_ERR_NOT_PE:   return "not a PE file";
    case SP_ERR_NOSYM:    return "no symbol table / export table (stripped?)";
    case SP_ERR_NOTFOUND: return "symbol not found";
    default:              return "unknown error";
    }
}

const sp_ctx* sp_ctx_get(void) { return &g_ctx; }
