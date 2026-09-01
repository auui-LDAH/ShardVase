/*
 * mempatch.h — 附加进程 + 内存读写（攻防工具，仅用于自有产物演练）
 */
#ifndef MEMPATCH_MEMPATCH_H
#define MEMPATCH_MEMPATCH_H

#include <windows.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mp_handle {
    DWORD   pid;
    HANDLE  h;
    int     attached;      /* 1 = OpenProcess 成功 */
    uint64_t image_base;   /* 目标进程内镜像基址 (按模块名查) */
} mp_handle;

/* 附加: pid 目标进程; modname 模块名 (如 "demo.exe") 用于算基址, 可为 NULL */
int mp_attach(mp_handle* h, DWORD pid, const char* modname);
/* 读内存: 0 成功 */
int mp_read(mp_handle* h, uint64_t addr, void* buf, size_t len);
/* 写内存: 0 成功 */
int mp_write(mp_handle* h, uint64_t addr, const void* buf, size_t len);
/* 读字节 (便捷) */
int mp_read_byte(mp_handle* h, uint64_t addr, uint8_t* out);
/* 写字节 (便捷) */
int mp_write_byte(mp_handle* h, uint64_t addr, uint8_t val);
/* ASLR 换算: 编译时 VA + 运行时基址 - 首选基址 -> 运行时 VA */
uint64_t mp_aslr_adjust(uint64_t preferred_base, uint64_t runtime_base,
                        uint64_t compile_time_va);
void mp_close(mp_handle* h);

#ifdef __cplusplus
}
#endif

#endif /* MEMPATCH_MEMPATCH_H */
