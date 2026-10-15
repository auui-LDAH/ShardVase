/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * patcher_jni.c — Android JNI + ptrace 内存补丁工具 (攻防演练用, 仅自有产物)
 *
 * 目标: libprot.so 的 nativeIsDebugged (TracerPid 检测) 等 JNI 导出函数。
 *
 * 两种模式:
 *   A. 同进程 patch (JNI 注入后改自己进程): 免 root, 改函数头 ret 0
 *   B. ptrace 附加 (root): ptrace(PTRACE_ATTACH/SEIZE) 附加目标进程写内存
 *
 * 构建: NDK (CMake) 或宿主编译 (Windows 仅验证语法)。
 */

/* `_GNU_SOURCE` 必须先于**任何**系统头: `process_vm_writev` (模式 B) 在 glibc 下
 * 仅于 `_GNU_SOURCE` 时由 <sys/uio.h> 声明。
 * 2026-10-06 用真实 Android NDK r28 (aarch64-linux-android21) 交叉编译时暴露 ——
 * 此前本文件从未在 Android/glibc 目标上编过, 两次所谓"宿主编译验证"实际只
 * 覆盖了 elfparse.c / elfdump.c。同型教训见 src/platform/prot_platform_linux.c:43-66。 */
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>

#include "elfparse/elfparse.h"  /* 符号解析 (同目录布局; 复制进 NDK 工程时保持) */

/* ---- process_vm_writev 的 API 23 门槛 (2026-10-06 真实 NDK r28 交叉编译暴露) ----
 * bionic 的 <sys/uio.h> 把它标为 `__INTRODUCED_IN(23)`, 而本项目 Android 侧
 * 既定下限是 **API 21** (docs/EXTENSION_PLAN.md「NDK r26+ / Clang 17 / API 21+」)。
 * 在 API 21/22 目标上直接调用 => `error: call to undeclared function`。
 * 该 **系统调用** 本身在 arm64 内核早已存在 (Linux 3.2+), 缺的只是 libc 声明,
 * 故低 API 级别改用 `syscall(__NR_process_vm_writev, ...)` 直呼, 保持下限不变。
 * 注: 宿主 (glibc) 编译不需要此分支 —— glibc 在 `_GNU_SOURCE` 下直接声明。 */
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

/* ---- ARM64 指令: mov w0, #0; ret  (等效 xor w0,w0; ret) ----
 *  mov w0, wzr  = 0x2F0000AA  (orr w0, wzr, wzr 的别名? 实际用 movz)
 *  稳妥: movz x0, #0 (0xD2800000) + ret (0xD65F03C0) = 8 字节
 */
#define AARCH64_MOVZ_X0_0 0xD2800000u  /* movz x0, #0 */
#define AARCH64_RET       0xD65F03C0u  /* ret */
#define AARCH64_NOP       0xD503201Fu

/* ---- x86_64 (模拟器/其他): xor eax,eax; ret ---- */
#define X86_64_XOR_EAX_EAX 0xC031u
#define X86_64_RET         0xC3u

typedef struct patch_spec {
    uint64_t target_va;   /* 目标符号链接时 VA */
    const char* sym_name;
    int arch;             /* 0=arm64, 1=x86_64 */
    uint8_t patch[16];    /* 补丁字节 */
    size_t patch_len;
} patch_spec;

/* 构建补丁: 使函数返回 0 (nativeIsDebugged -> 0 = 未调试) */
static void make_return_zero_patch(patch_spec* ps, int arch)
{
    ps->arch = arch;
    if (arch == 0) {
        uint32_t* w = (uint32_t*)ps->patch;
        w[0] = AARCH64_MOVZ_X0_0;
        w[1] = AARCH64_RET;
        ps->patch_len = 8;
    } else {
        ps->patch[0] = (uint8_t)(X86_64_XOR_EAX_EAX & 0xFF);
        ps->patch[1] = (uint8_t)(X86_64_XOR_EAX_EAX >> 8);
        ps->patch[2] = X86_64_RET;
        ps->patch_len = 3;
    }
}

/* 模式 A: 同进程 patch (JNI) —— 直接写自己的内存 */
static int patch_self(const patch_spec* ps, uint64_t runtime_base)
{
    uint64_t addr = runtime_base + (ps->target_va - 0x0); /* ELF ET_DYN: VA 是偏移 */
    uintptr_t page = (uintptr_t)addr & ~(uintptr_t)0xFFF;

    if (mprotect((void*)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return -1;
    }
    memcpy((void*)(uintptr_t)addr, ps->patch, ps->patch_len);
    __builtin___clear_cache((char*)(uintptr_t)addr,
                            (char*)(uintptr_t)(addr + ps->patch_len));
    /* 恢复原保护 (简化: 保持 RWX; 生产按原 flags) */
    return 0;
}

/* 模式 B: ptrace 附加写内存 (root) */
static int ptrace_write_mem(pid_t pid, uint64_t addr, const void* buf, size_t len)
{
    struct iovec local = { .iov_base = (void*)buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void*)(uintptr_t)addr, .iov_len = len };
    ssize_t n = prot_process_vm_writev(pid, &local, 1, &remote, 1, 0);
    return (n == (ssize_t)len) ? 0 : -1;
}

static int patch_remote(pid_t pid, const patch_spec* ps, uint64_t runtime_base)
{
    uint64_t addr = runtime_base + (ps->target_va - 0x0);
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) return -1;
    waitpid(pid, NULL, 0);
    /* 写内存 (ptrace POKEDATA 或 process_vm_writev; 用后者更简洁) */
    int rc = ptrace_write_mem(pid, addr, ps->patch, ps->patch_len);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return rc;
}

/* 解析目标进程模块基址 (简化: /proc/<pid>/maps 首个 .so) */
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

/* JNI: 同进程 patch nativeIsDebugged -> 返回 0 (模式 A) */
JNIEXPORT jint JNICALL
Java_com_prot_demo_Patcher_nativePatchSelf(JNIEnv* env, jobject thiz,
                                           jstring jmod_path, jstring jsym)
{
    const char* mod_path = (*env)->GetStringUTFChars(env, jmod_path, NULL);
    const char* sym = (*env)->GetStringUTFChars(env, jsym, NULL);
    ep_symbol s;
    patch_spec ps;
    uint64_t base = 0;
    int rc;

    (void)thiz;
    /* 加载自身 so 的符号表 */
    if (ep_load_file(mod_path) != EP_OK) {
        (*env)->ReleaseStringUTFChars(env, jmod_path, mod_path);
        (*env)->ReleaseStringUTFChars(env, jsym, sym);
        return -1;
    }
    if (ep_lookup(sym, &s) != EP_OK) {
        (*env)->ReleaseStringUTFChars(env, jmod_path, mod_path);
        (*env)->ReleaseStringUTFChars(env, jsym, sym);
        return -2;
    }
    /* 自身模块基址: 通过 dladdr 或 /proc/self/maps (简化: 用 base 0) */
    base = find_module_base(getpid(), NULL);
    make_return_zero_patch(&ps, 0); /* ARM64 假定; 生产按 CPU 架构 */
    ps.target_va = s.st_value;
    rc = patch_self(&ps, base ? base : 0);

    (*env)->ReleaseStringUTFChars(env, jmod_path, mod_path);
    (*env)->ReleaseStringUTFChars(env, jsym, sym);
    return rc;
}

/* JNI: ptrace 附加 patch 其他进程 (模式 B, 需 root) */
JNIEXPORT jint JNICALL
Java_com_prot_demo_Patcher_nativePatchRemote(JNIEnv* env, jobject thiz,
                                             jint jpid, jstring jmod,
                                             jstring jsym)
{
    const char* mod = (*env)->GetStringUTFChars(env, jmod, NULL);
    const char* sym = (*env)->GetStringUTFChars(env, jsym, NULL);
    pid_t pid = (pid_t)jpid;
    ep_symbol s;
    patch_spec ps;
    uint64_t base;
    int rc;

    (void)thiz;
    /* 目标进程内解析: 用本地文件 + 目标基址 (简化) */
    base = find_module_base(pid, mod);
    if (base == 0) {
        (*env)->ReleaseStringUTFChars(env, jmod, mod);
        (*env)->ReleaseStringUTFChars(env, jsym, sym);
        return -3;
    }
    if (ep_lookup(sym, &s) != EP_OK) {
        (*env)->ReleaseStringUTFChars(env, jmod, mod);
        (*env)->ReleaseStringUTFChars(env, jsym, sym);
        return -2;
    }
    make_return_zero_patch(&ps, 0);
    ps.target_va = s.st_value;
    rc = patch_remote(pid, &ps, base);

    (*env)->ReleaseStringUTFChars(env, jmod, mod);
    (*env)->ReleaseStringUTFChars(env, jsym, sym);
    return rc;
}
