/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * syscall.h — direct syscall 直调 (A6): 绕过 ntdll stub 入口的 inline hook
 *
 * 关键信息类查询 (NtQueryInformationProcess / NtQuerySystemInformation)
 * 在攻击者 hook 了 ntdll 导出入口时, 直接以 syscall 指令进入内核,
 * 不经过可能被改写的 stub 头部。
 *
 * 设计要点 (详见 docs/CONTRACT.md §6.3):
 *   - SSN 运行时从 ntdll 原始 stub 字节码中提取 (扫描 0F 05 前最近的
 *     B8 imm32), 不硬编码 (跨 Win10/11 版本稳定)。
 *   - 直调 stub (12 字节: mov r10,rcx; mov eax,SSN; syscall; ret) 在
 *     运行时生成于可执行内存 —— 无需 MASM, 二进制中无固定 syscall 代码。
 *   - 任何失败 (SSN 提取失败 / 内存分配失败) 返回 STATUS_UNSUCCESSFUL,
 *     调用方回退 GetProcAddress 路径, 不新增误报面。
 */
#ifndef PROT_SYSCALL_H
#define PROT_SYSCALL_H

/* ## C1（2026-09-25）: 移除 <windows.h> 依赖
 *
 * **为什么**: 本头文件原先 `#include <windows.h>` ->
 *   任何 include 它的 .c 都无法在 Linux 编译（**头文件层耦合**）。
 *
 * **修法**: 用**平台无关类型**替代（宽度在 Windows 上完全一致）:
 *   HANDLE -> void*      ULONG -> uint32_t
 *   PVOID  -> void*      PULONG -> uint32_t*
 *   LONG(NTSTATUS) -> int32_t
 * => 调用方（antidebug.c）**无需改动**（隐式转换兼容）。
 */
#include <stdint.h>

#include "protect/protdef.h"

/* windows.h 不提供 NTSTATUS (winternl.h 可选); 与 src/antidebug.c 同守卫 */
#ifdef __cplusplus
extern "C" {
#endif

/* ## NTSTATUS 的平台处理（2026-09-25，MSVC /WX 实测**两次**修正）
 *
 * ⚠️ **踩过的两个坑**（都由构建抓到）:
 *   ① `typedef int32_t NTSTATUS` 在 Windows 上**冲突** ——
 *      Windows 的 `NTSTATUS` 是 `LONG`（= `long`），`int32_t` 是 `int`；
 *      两者是不同的类型 -> MSVC **C4142** -> `/WX` 下失败。
 *   ② 加了守卫 `#if !defined(_WIN32) && !defined(NTSTATUS)`
 *      后又**漏了 Windows 侧的填充** —— 因为本头文件**已不 include
 *      windows.h**，故 `NTSTATUS` 在 Windows 上**根本未定义**
 *      -> `error C2061: 语法错误: 标识符 prot_sys_...`
 *
 * **正确做法（两侧都给定义）**:
 *   · Windows: 用 `LONG`（**与系统 NTSTATUS 完全同类型**，不冲突）
 *   · 其它平台: `int32_t`
 *   · 若调用方已 include windows.h（NTSTATUS 已定义）-> 不重定义
 */
#if !defined(NTSTATUS)
#  if defined(_WIN32)
typedef long NTSTATUS;      /* == Windows 的 LONG，同类型故无 C4142 */
#  else
typedef int32_t NTSTATUS;
#  endif
#endif

/* 直调 NtQueryInformationProcess (5 参数, x64 第 5 参在栈上)。
 * stub 可用 -> 直接 syscall; 不可用 -> 返回 STATUS_UNSUCCESSFUL (负值),
 * 由调用方回退 GetProcAddress 路径。 */
NTSTATUS prot_sys_nt_query_information_process(void* ProcessHandle,
                                               uint32_t ProcessInformationClass,
                                               void* ProcessInformation,
                                               uint32_t ProcessInformationLength,
                                               uint32_t* ReturnLength);

/* 直调 NtQuerySystemInformation (4 参数)。失败语义同上。 */
NTSTATUS prot_sys_nt_query_system_information(uint32_t SystemInformationClass,
                                              void* SystemInformation,
                                              uint32_t SystemInformationLength,
                                              uint32_t* ReturnLength);

/* 1 = 两个直调 stub 均可用; 0 = 至少一个不可用 (部分回退)。
 * 供 --selftest / 诊断输出。 */
uint32_t prot_sys_available(void);


#ifdef __cplusplus
}   /* extern "C" */
#endif
#endif /* PROT_SYSCALL_H */
