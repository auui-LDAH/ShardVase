/*
 * symparse.h — PE 符号表解析器（攻防工具，仅用于自有产物演练）
 *
 * 解析 PE 文件内的:
 *   1) 导出表 (.edata)  — 映像导出目录 (按名称 -> RVA)
 *   2) COFF 符号表      — 文件头部 PointerToSymbolTable (符号名 -> VA)
 *
 * 设计目标: 给定符号名, 返回其在目标进程中的虚拟地址 (VA)。
 * 局限 (如实记录): RELEASE 构建 (/DEBUG:NONE /OPT:REF,ICF) 会剥离 COFF
 * 符号表且无导出表, 此时解析失败——这是真实破解者也会遇到的 strip 场景。
 */
#ifndef MEMPATCH_SYMPARSE_H
#define MEMPATCH_SYMPARSE_H

#include <stddef.h>
#include <stdint.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 解析结果 */
typedef struct sp_result {
    uint64_t rva;        /* 相对虚拟地址 (0 = 未找到) */
    uint64_t va;         /* 虚拟地址 = imageBase + rva */
    int      from_export;/* 1=导出表命中, 0=COFF 符号表命中 */
    char     name[256];  /* 命中的符号名 */
} sp_result;

/* 解析 PE 文件 (从磁盘读) */
int sp_load_file(const char* path);
/* 解析 PE 内存映像 (已映射到进程地址空间) */
int sp_load_memory(const uint8_t* base, size_t size);
/* 解析 MAP 文件 (MSVC /MAP 产物, 符号名 -> VA 直接给出) */
int sp_load_map(const char* path);

/* 按符号名查找 -> 0 成功, <0 失败 (错误码见 sp_err_str) */
int sp_lookup(const char* name, sp_result* out);
/* 列出所有符号 (调试用) -> 0 成功 */
int sp_list_all(void (*cb)(const char* name, uint64_t rva, int from_export, void* ud),
                void* ud);

const char* sp_err_str(int err);

/* 错误码 */
#define SP_OK           0
#define SP_ERR_OPEN      -1
#define SP_ERR_SIZE      -2
#define SP_ERR_MAPPED    -3
#define SP_ERR_NOT_PE    -4
#define SP_ERR_NOSYM     -5  /* 无符号表也无导出表 (可能被 strip) */
#define SP_ERR_NOTFOUND  -6  /* 符号未找到 */

/* 内部状态 (暴露给测试) */
typedef struct sp_ctx {
    uint64_t image_base;      /* PE 镜像基址 */
    size_t   file_size;
    int      have_exports;    /* 有导出表 */
    int      have_coff;       /* 有 COFF 符号表 */
    int      have_map;        /* 有 MAP 文件 (sp_load_map) */
    uint32_t coff_symbol_count;
    uint32_t coff_symbol_offset;
    uint32_t coff_string_offset;
    uint32_t section_count;
    /* 节表快照 (COFF 符号 RVA 换算需要) */
    struct { uint32_t va; uint32_t size; uint16_t idx; } sections[64];
    /* MAP 符号表 (简单数组, 最多 65536 条) */
    struct sp_map_entry {
        char     name[256];
        uint64_t va;
    } map_entries[65536];
    uint32_t map_count;
} sp_ctx;

const sp_ctx* sp_ctx_get(void);

#ifdef __cplusplus
}
#endif

#endif /* MEMPATCH_SYMPARSE_H */
