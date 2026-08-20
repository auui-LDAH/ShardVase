/*
 * dbiguard.h — 反动态插桩/反 hook 检测 (N2, 咨询项)
 *
 * 检测项:
 *   inline_hooks      常用敏感 API 入口被改写 (Detours/恶意 hook) —— 与
 *                     A6 direct syscall 互补 (直调绕 hook, 本项做检测)
 *   frida_agent       已加载模块中含 frida-agent/gum 特征
 *   rx_rw_regions     PAGE_EXECUTE_READWRITE 可执行区异常增多 (插桩引擎特征)
 *   thread_count      线程数异常 (注入/插桩常见副作用)
 * 默认咨询项 (只报告); 策略由调用方决定 (CONTINUE/FAKE/EXIT)。
 */
#ifndef PROT_DBIGUARD_H
#define PROT_DBIGUARD_H

#include "protect/protdef.h"

typedef struct prot_dbiguard_report {
    uint32_t inline_hooks;  /* 敏感 API 入口被改写 (jmp 到非 ntdll 区) */
    uint32_t frida_agent;   /* 检测到 frida/gum 模块 */
    uint32_t rx_rw_regions; /* 可执行+可写区数量异常 */
    uint32_t thread_count;  /* 线程数异常 */
} prot_dbiguard_report;

/* 执行全部检测并填充报告; 永不失败 */
prot_status prot_dbiguard_scan(prot_dbiguard_report* out);

/* 任一检测项非 0 -> 返回 1 */
uint32_t prot_dbiguard_suspicious(const prot_dbiguard_report* rep);

#endif /* PROT_DBIGUARD_H */
