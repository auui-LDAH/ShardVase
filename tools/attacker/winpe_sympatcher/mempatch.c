/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * mempatch.c — 附加进程 + 内存读写实现
 *
 * 权限: OpenProcess 需要 PROCESS_VM_READ|WRITE|QUERY_INFORMATION (目标进程
 * 同用户/管理员)。受限时返回失败——与既有攻防结论一致 (受限则 SKIP)。
 */
#include "mempatch.h"

#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>

static uint64_t find_module_base(DWORD pid, const char* modname)
{
    HANDLE snap;
    MODULEENTRY32 me;
    uint64_t base = 0;

    if (modname == NULL) return 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            if (_stricmp(me.szModule, modname) == 0) {
                base = (uint64_t)(uintptr_t)me.modBaseAddr;
                break;
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

int mp_attach(mp_handle* h, DWORD pid, const char* modname)
{
    if (h == NULL) return -1;
    memset(h, 0, sizeof(*h));
    h->pid = pid;
    h->h = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE |
                           PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                       FALSE, pid);
    if (h->h == NULL) {
        return -2; /* 权限不足 */
    }
    h->attached = 1;
    h->image_base = find_module_base(pid, modname);
    return 0;
}

int mp_read(mp_handle* h, uint64_t addr, void* buf, size_t len)
{
    SIZE_T rd = 0;
    if (h == NULL || !h->attached || buf == NULL) return -1;
    if (!ReadProcessMemory(h->h, (LPCVOID)(uintptr_t)addr, buf, len, &rd)) {
        return -2;
    }
    return (rd == len) ? 0 : -3;
}

int mp_write(mp_handle* h, uint64_t addr, const void* buf, size_t len)
{
    SIZE_T wr = 0;
    DWORD old;
    int rc = 0;
    if (h == NULL || !h->attached || buf == NULL) return -1;
    /* 目标页面可能只读 (.text) — 先改保护再写, 写完恢复 (真实破解者行为) */
    if (!VirtualProtectEx(h->h, (LPVOID)(uintptr_t)addr, len,
                          PAGE_EXECUTE_READWRITE, &old)) {
        return -2;
    }
    if (!WriteProcessMemory(h->h, (LPVOID)(uintptr_t)addr, buf, len, &wr)) {
        rc = -3;
    } else if (wr != len) {
        rc = -4;
    }
    VirtualProtectEx(h->h, (LPVOID)(uintptr_t)addr, len, old, &old);
    return rc;
}

int mp_read_byte(mp_handle* h, uint64_t addr, uint8_t* out)
{
    return mp_read(h, addr, out, 1);
}

int mp_write_byte(mp_handle* h, uint64_t addr, uint8_t val)
{
    return mp_write(h, addr, &val, 1);
}

uint64_t mp_aslr_adjust(uint64_t preferred_base, uint64_t runtime_base,
                        uint64_t compile_time_va)
{
    if (compile_time_va >= preferred_base && preferred_base != 0) {
        return runtime_base + (compile_time_va - preferred_base);
    }
    return compile_time_va;
}

void mp_close(mp_handle* h)
{
    if (h != NULL && h->attached) {
        CloseHandle(h->h);
        h->attached = 0;
    }
}
