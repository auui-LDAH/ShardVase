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

#include <windows.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <string.h>

#include "protect/vmdetect.h"

static void hv_vendor_id(char out[13])
{
    int regs[4] = { 0, 0, 0, 0 };
    __cpuid(regs, 0x40000000);
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
    static const wchar_t* const names[] = {
        L"vmtoolsd.exe", L"vmwaretray.exe", L"vmwareuser.exe",
        L"VBoxService.exe", L"VBoxClient.exe", L"vboxservice.exe",
        L"qemu-ga.exe", L"xenservices.exe", L"xenbus.exe",
        L"prl_tools.exe", L"vmsrvc.exe", L"vmcompute.exe",
    };
    HANDLE snap;
    PROCESSENTRY32W pe;
    int found = 0;
    size_t i;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
                if (_wcsicmp(pe.szExeFile, names[i]) == 0) {
                    found = 1;
                    break;
                }
            }
        } while (!found && Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

prot_status prot_vmdetect_scan(prot_vmdetect_report* out)
{
    int regs[4] = { 0, 0, 0, 0 };
    char vendor[13] = { 0 };

    if (out == NULL)
        return PROT_OK;
    memset(out, 0, sizeof(*out));

    __cpuid(regs, 1);
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
    if (rep == NULL)
        return 0u;
    return (rep->cpu_hypervisor || rep->hv_vendor ||
            rep->vm_processes) ? 1u : 0u;
}
