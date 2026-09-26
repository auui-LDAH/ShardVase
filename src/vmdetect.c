/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright (C) 2026 ShardVase contributors
 *
 * 本文件是 ShardVase 的一部分，以 AGPL-3.0 发布；
 * 商业授权见 LICENSE.md。
 */
/*
 * vmdetect.c — 虚拟机/沙箱检测 (M1, 咨询项)
 *
 * 对应契约 docs/ADVANCED.md §3。检测项:
 *   - CPUID hypervisor present bit (ECX bit31)
 *   - CPUID 0x40000000 厂商串 (Hyper-V/KVM/VMware/VBox/Xen/Parallels)
 *   - 虚拟化相关进程
 * 说明: 原计划的 VMware/VBox I/O 端口探测 (IN 指令 + VEH) 在真机实测触发
 * 异常分发层死循环 (风险不可控), 已移除 (ADVANCED.md §3.1 更新)。
 * 全部为咨询项: 只报告不触发策略 (合法用户可能跑在 VM 里)。
 */

#include <string.h>

#include "protect/vmdetect.h"
#include "protect/prot_compiler.h"  /* L6b: PROT_CPUID（跨平台 CPU 内建）*/
#include "protect/prot_platform.h"  /* L1: 平台抽象层 */
#include "protect/prot_noise.h"   /* W1.6 序言噪声 */

static void hv_vendor_id(char out[13])
{
    int regs[4] = { 0, 0, 0, 0 };
    PROT_CPUID(regs, 0x40000000);
    memcpy(out, &regs[1], 4);
    memcpy(out + 4, &regs[2], 4);
    memcpy(out + 8, &regs[3], 4);
    out[12] = '\0';
}

static uint32_t vendor_code(const char* v)
{
    if (strncmp(v, "Microsoft Hv", 12) == 0) return 1u;  /* Hyper-V */
    if (strncmp(v, "KVMKVMKVM", 9) == 0)         return 2u;  /* KVM */
    if (strncmp(v, "VMwareVMware", 12) == 0)     return 3u;
    if (strncmp(v, "VBoxVBoxVBox", 12) == 0)     return 4u;
    if (strncmp(v, "XenVMMXenVMM", 12) == 0)     return 5u;
    if (strncmp(v, "prl hyperv", 10) == 0)       return 6u;  /* Parallels */
    return 0u;
}

static int has_vm_process(void)
{
    static const char* const names[] = {
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
        "VBoxService.exe", "VBoxClient.exe", "vboxservice.exe",
        "qemu-ga.exe", "xenservices.exe", "xenbus.exe",
        "prl_tools.exe", "vmsrvc.exe", "vmcompute.exe",
    };
    static prot_proc_info procs[512];
    size_t total, i, j;
    int found = 0;

    /* L1（2026-09-23）: 改用**平台抽象层**，不再直接调 Toolhelp32。
     *
     * ## 为什么这是 L1 的接入点
     *   本模块此前用 `CreateToolhelp32Snapshot` + 宽字符 `_wcsicmp`
     *   —— 这是**平台特有**的做法（Linux 用 /proc 遍历）。
     *   改用 `prot_plat_enum_processes` 后:
     *     · 本函数**不再含平台 API**，跨平台时无需改动
     *     · 新增平台只需实现平台层，**不必碰本模块**
     *
     * ## 行为等价性
     *   平台层内部**仍调 Toolhelp32**（Windows 实现），
     *   故检测结果**完全一致**；只是比较改为 ASCII（进程名均 ASCII）。
     *   已实测: e2e / attacks / protcheck 全绿（见提交说明）。
     */
    total = prot_plat_enum_processes(procs,
                                     sizeof(procs) / sizeof(procs[0]));
    if (total == 0)
        return 0;

    for (i = 0; i < total && i < sizeof(procs) / sizeof(procs[0]); i++) {
        for (j = 0; j < sizeof(names) / sizeof(names[0]); j++) {
            /* ASCII 大小写不敏感比较（进程名为 ASCII） */
            const char* a = procs[i].name;
            const char* b = names[j];
            size_t k = 0;
            int same = 1;
            for (;; k++) {
                char ca = a[k], cb = b[k];
                if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
                if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
                if (ca != cb) { same = 0; break; }
                if (ca == '\0') break;
            }
            if (same) {
                found = 1;
                break;
            }
        }
        if (found)
            break;
    }
    return found;
}

prot_status prot_vmdetect_scan(prot_vmdetect_report* out)
{
    PROT_NOISE();   /* W1.6 序言噪声 */
    int regs[4] = { 0, 0, 0, 0 };
    char vendor[13] = { 0 };

    if (out == NULL)
        return PROT_OK;
    memset(out, 0, sizeof(*out));

    PROT_CPUID(regs, 1);
    out->cpu_hypervisor = ((uint32_t)regs[2] & 0x80000000u) ? 1u : 0u;

    if (out->cpu_hypervisor) {
        hv_vendor_id(vendor);
        out->hv_vendor = vendor_code(vendor);
    }

    out->vm_processes = has_vm_process() ? 1u : 0u;

    return PROT_OK;
}

uint32_t prot_vmdetect_suspicious(const prot_vmdetect_report* rep)
{
    PROT_NOISE();   /* W1.6 序言噪声 */
    if (rep == NULL)
        return 0u;
    return (rep->cpu_hypervisor || rep->hv_vendor ||
            rep->vm_processes) ? 1u : 0u;
}
