/*
 * vmdetect.h — 虚拟机/沙箱检测 (咨询项, 只报告不触发策略)
 *
 * 检测项:
 *   cpu_hypervisor  CPUID.1:ECX bit31 (hypervisor present)
 *   hv_vendor       CPUID.0x40000000 厂商串 (Microsoft Hv / KVMKVMKVM /
 *                   VMwareVMware / VBoxVBoxVBox / XenVMMXenVMM / prl hyperv)
 *   vm_processes    虚拟化相关进程 (vmtoolsd/VBoxService/qemu-ga 等)
 *
 * 全部为咨询项: 报告但不触发退出/伪造策略 (合法用户可能跑在 VM 里,
 * 误杀成本高)。若需从严, 调用方自行决定策略。
 * (I/O 端口探测因真机异常分发死循环已移除, 见 docs/ADVANCED.md §3.1)
 */
#ifndef PROT_VMDETECT_H
#define PROT_VMDETECT_H

#include "protect/protdef.h"

typedef struct prot_vmdetect_report {
    uint32_t cpu_hypervisor; /* CPUID hypervisor present bit */
    uint32_t hv_vendor;      /* 0=none, 1=Microsoft(Hyper-V), 2=KVM,
                                3=VMware, 4=VirtualBox, 5=Xen, 6=Parallels */
    uint32_t vm_processes;   /* 检测到虚拟化相关进程 */
} prot_vmdetect_report;

/* 执行全部检测并填充报告; 永不失败 */
prot_status prot_vmdetect_scan(prot_vmdetect_report* out);

/* 任一检测项非 0 (即"疑似 VM") -> 返回 1 */
uint32_t prot_vmdetect_suspicious(const prot_vmdetect_report* rep);

#endif /* PROT_VMDETECT_H */
