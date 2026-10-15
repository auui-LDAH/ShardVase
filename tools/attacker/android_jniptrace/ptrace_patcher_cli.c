/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * ptrace_patcher_cli.c — 命令行版 Android ptrace 内存补丁器 (真机/宿主编译)
 *
 * 用法: ptrace_patcher_cli <pid> <libmod> <symbol> [arch]
 *   arch: 0=arm64 (默认), 1=x86_64
 * 需 root (ptrace 附加)。
 */

/* `_GNU_SOURCE` 必须先于**任何**系统头: `process_vm_writev` 在 glibc 下
 * 仅于 `_GNU_SOURCE` 时由 <sys/uio.h> 声明。
 * 2026-10-06 用真实 Android NDK r28 (aarch64-linux-android21) 交叉编译时暴露 ——
 * 此前本文件从未在任何 Linux/Android 目标上编过。 */
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>

#include "elfparse/elfparse.h"

/* ---- process_vm_writev 的 API 23 门槛 (2026-10-06 真实 NDK r28 交叉编译暴露) ----
 * bionic 的 <sys/uio.h> 标其为 `__INTRODUCED_IN(23)`; 本项目 Android 侧下限是
 * API 21 (docs/EXTENSION_PLAN.md), 故低级别走 `syscall(__NR_...)` 直呼。
 * 系统调用本身在 arm64 内核早已存在 (Linux 3.2+), 缺的只是 libc 声明。 */
#if defined(__ANDROID__) && defined(__ANDROID_API__) && (__ANDROID_API__ < 23)
#  include <sys/syscall.h>
static ssize_t prot_process_vm_writev(pid_t pid,
                                      const struct iovec* liov, unsigned long licnt,
                                      const struct iovec* riov, unsigned long ricnt,
                                      unsigned long flags)
{
    return (ssize_t)syscall(__NR_process_vm_writev, pid, liov, licnt, riov, ricnt, flags);
}
#else
#  define prot_process_vm_writev process_vm_writev
#endif

/* 与 patcher_jni.c 相同的补丁字节 */
#define AARCH64_MOVZ_X0_0 0xD2800000u
#define AARCH64_RET       0xD65F03C0u

static uint64_t find_module_base(pid_t pid, const char* modname)
{
    char path[64];
    FILE* f;
    char line[512];
    uint64_t base = 0;
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    f = fopen(path, "r");
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        if (modname && strstr(line, modname)) {
            sscanf(line, "%lx", &base);
            break;
        }
    }
    fclose(f);
    return base;
}

static int write_mem(pid_t pid, uint64_t addr, const uint8_t* buf, size_t len)
{
    struct iovec local = { .iov_base = (void*)buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void*)(uintptr_t)addr, .iov_len = len };
    return (prot_process_vm_writev(pid, &local, 1, &remote, 1, 0) == (ssize_t)len) ? 0 : -1;
}

int main(int argc, char** argv)
{
    pid_t pid;
    const char* mod;
    const char* sym;
    int arch;
    uint64_t base;
    ep_symbol s;
    uint8_t patch[16];
    size_t patch_len;

    if (argc < 4) {
        fprintf(stderr, "usage: %s <pid> <libmod> <symbol> [arch 0=arm64/1=x86_64]\n",
                argv[0]);
        return 2;
    }
    pid = (pid_t)atoi(argv[1]);
    mod = argv[2];
    sym = argv[3];
    arch = (argc >= 5) ? atoi(argv[4]) : 0;

    /* 1. 解析符号 (本地 ELF 文件 = 目标进程的 lib) */
    if (ep_load_file(mod) != EP_OK) {
        fprintf(stderr, "cannot parse ELF: %s\n", mod);
        return 1;
    }
    if (ep_lookup(sym, &s) != EP_OK) {
        fprintf(stderr, "symbol not found: %s\n", sym);
        return 1;
    }
    printf("symbol %s: st_value=0x%llx\n", sym,
           (unsigned long long)s.st_value);

    /* 2. 找目标基址 */
    base = find_module_base(pid, mod);
    if (base == 0) {
        fprintf(stderr, "cannot find module %s in pid %d\n", mod, pid);
        return 1;
    }
    printf("module %s base=0x%llx\n", mod, (unsigned long long)base);

    /* 3. 构建补丁: 返回 0 */
    if (arch == 0) {
        uint32_t* w = (uint32_t*)patch;
        w[0] = AARCH64_MOVZ_X0_0;
        w[1] = AARCH64_RET;
        patch_len = 8;
    } else {
        patch[0] = 0x31; patch[1] = 0xC0; patch[2] = 0xC3; /* xor eax,eax; ret */
        patch_len = 3;
    }

    /* 4. ptrace 附加 + 写 */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) {
        perror("PTRACE_ATTACH");
        return 1;
    }
    waitpid(pid, NULL, 0);
    {
        uint64_t addr = base + (s.st_value - 0);
        int rc = write_mem(pid, addr, patch, patch_len);
        if (rc == 0) {
            printf("PATCHED 0x%llx (%zu bytes): %s -> return 0\n",
                   (unsigned long long)addr, patch_len, sym);
        } else {
            fprintf(stderr, "write failed (need root?)\n");
        }
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return (rc == 0) ? 0 : 1;
    }
}
