/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * antidebug.h — 反调试: 检测调试器 / 分析环境
 *
 * 检测手段 (详见 docs/CONTRACT.md):
 *   PEB.BeingDebugged / PEB.NtGlobalFlag / ProcessDebugPort /
 *   ProcessDebugFlags / ProcessDebugObjectHandle / 硬件断点 /
 *   QPC+Sleep 计时 / 内核调试器标志
 */
#ifndef PROT_ANTIDEBUG_H
#define PROT_ANTIDEBUG_H

#include "protect/protdef.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct prot_antidebug_report {
    uint32_t peb_being_debugged;   /* PEB.BeingDebugged */
    uint32_t peb_nt_global_flag;   /* PEB.NtGlobalFlag 调试堆标志 (咨询项) */
    uint32_t debug_port;           /* ProcessDebugPort != 0 */
    uint32_t debug_flags;          /* ProcessDebugFlags != 1 */
    uint32_t debug_object;         /* ProcessDebugObjectHandle != NULL */
    uint32_t hardware_breakpoints; /* DR0-DR3 / DR7 硬件断点 */
    uint32_t timing_suspicious;    /* QPC+Sleep 计时异常 */
    uint32_t kernel_debugger;      /* 内核调试器标志 (咨询项) */
    uint32_t debug_heap_flags;     /* PEB.ProcessHeap Flags/ForceFlags 调试堆泄漏 (咨询项) */
    uint32_t int3_honey;           /* int3 VEH 蜜罐: 处理器未接管 → 有外部断点拦截 (咨询项) */
    uint32_t ppid_blacklist;       /* S5: 父进程为已知调试器名 (关键项) */
    uint32_t clock_drift_sec;      /* S5: 墙钟与 tick 源漂移 >250ms (咨询项) */
} prot_antidebug_report;

/* 执行全部检测并填充报告; 永不失败 (返回 PROT_OK) */
prot_status prot_antidebug_scan(prot_antidebug_report* out);

/* 任一「关键」检测项命中即返回非 0 (咨询项不计入) */
uint32_t prot_antidebug_detected(const prot_antidebug_report* rep);

/*
 * 关键项被命中时按策略处理:
 *   PROT_POLICY_EXIT     -> TerminateProcess(GetCurrentProcess(), PROT_EXIT_DEBUG_DETECTED)
 *   PROT_POLICY_FAKE     -> 置伪结果标志 (prot_antidebug_fake_active 返回 1)
 *   PROT_POLICY_CONTINUE -> 无操作
 */
prot_status prot_antidebug_apply_policy(prot_policy pol);

/* 查询 FAKE 标志 (demo 用它翻转校验结果) */
uint32_t prot_antidebug_fake_active(void);

/* ThreadHideFromDebugger; 若处于调试中可能导致进程被杀, 由调用方决定是否调用 */
prot_status prot_antidebug_hide_thread(void);

/*
 * R3.2-c: 判定多副本 + 交叉聚合
 *
 * prot_antidebug_detected_multi 是**契约入口** —— 宿主应调用它而不是
 * 任一副本: 它在同一输入上求全部副本的非短路多路 OR, 任一副本报 1 即
 * 返回 1。单点 patch 一个副本不再足够 (DRILL7 步骤 4 的补丁只让原实现
 * 失效, 其余副本仍然报告)。
 *
 * 三个副本 (r2/r3/r4) 与本体语义**逐位等价** (P1: 同一 7 关键位 OR,
 * 5 个咨询位不计入, NULL -> 0), 由 tools/replica_check.py 机械判据守护:
 * 差分等价 + map 地址互异 (抗 /OPT:ICF) + 改动其一必须被差分抓到。
 * 对外暴露副本是刻意的: 判据要能直接对它们做差分与打补丁。
 */
uint32_t prot_antidebug_detected_r2(const prot_antidebug_report* rep);
uint32_t prot_antidebug_detected_r3(const prot_antidebug_report* rep);
uint32_t prot_antidebug_detected_r4(const prot_antidebug_report* rep);
uint32_t prot_antidebug_detected_multi(const prot_antidebug_report* rep);


#ifdef __cplusplus
}   /* extern "C" */
#endif
#endif /* PROT_ANTIDEBUG_H */