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

#endif /* PROT_ANTIDEBUG_H */