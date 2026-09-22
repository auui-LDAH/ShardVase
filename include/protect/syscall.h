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

#include <windows.h> /* HANDLE / ULONG / PVOID / PULONG / LONG */

#include "protect/protdef.h"

/* windows.h 不提供 NTSTATUS (winternl.h 可选); 与 src/antidebug.c 同守卫 */
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

/* 直调 NtQueryInformationProcess (5 参数, x64 第 5 参在栈上)。
 * stub 可用 -> 直接 syscall; 不可用 -> 返回 STATUS_UNSUCCESSFUL (负值),
 * 由调用方回退 GetProcAddress 路径。 */
NTSTATUS prot_sys_nt_query_information_process(HANDLE ProcessHandle,
                                               ULONG ProcessInformationClass,
                                               PVOID ProcessInformation,
                                               ULONG ProcessInformationLength,
                                               PULONG ReturnLength);

/* 直调 NtQuerySystemInformation (4 参数)。失败语义同上。 */
NTSTATUS prot_sys_nt_query_system_information(ULONG SystemInformationClass,
                                              PVOID SystemInformation,
                                              ULONG SystemInformationLength,
                                              PULONG ReturnLength);

/* 1 = 两个直调 stub 均可用; 0 = 至少一个不可用 (部分回退)。
 * 供 --selftest / 诊断输出。 */
uint32_t prot_sys_available(void);

#endif /* PROT_SYSCALL_H */
